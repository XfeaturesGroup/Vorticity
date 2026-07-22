// Ordered, append-only op-log for CRDT (Yjs/Automerge) multi-device sync. One ConvLogDO instance
// == one conversation. See docs/03-crypto-core.md §9 and docs/04-serverless-architecture.md DO
// catalog + Flow 4.
//
// ISOLATION (docs/02, docs/04): this DO is a blind sequencer. It knows only `seq`, an opaque
// encrypted blob, and a timestamp — never a conversation id as data (the DO's own name IS that
// id, same reasoning as QueueDO), never a device/account identifier, never plaintext. It assigns
// order; it does not and cannot merge CRDT state — that only ever happens on clients, which hold
// the decryption keys this DO never sees. Capability verification happens one layer up in the
// Messaging Worker, before a request reaches here (see index.ts).
//
// STORAGE: DO-local SQLite (`ctx.storage.sql`) is authoritative, same pattern as QueueDO. Unlike
// QueueDO there is no TTL/eviction here — a conversation's op-log is durable history, not a
// transient delivery queue, so entries are kept indefinitely (conversation-level deletion is a
// separate, out-of-scope concern).
//
// WEBSOCKET HIBERNATION (R22, 2026-07 — added this pass, was MISSING before): the DO catalog lists
// this class as hibernating and Flow 4 explicitly shows `L--)D2: push blob@n (WS)`, but the class had
// only `POST /append`/`GET /sync` — no WS fan-out existed at all, a real gap between docs and code,
// not just an implementation detail. `GET` with an `Upgrade: websocket` header now attaches a
// hibernatable socket (`ctx.acceptWebSocket`), flushes the backlog since an optional `?since_seq=`
// on connect (same "(re)connecting IS the sync-on-wake" property QueueDO's subscribe already has),
// and `handleAppend` fans each newly-assigned entry out to every currently attached device. No ack
// protocol here (unlike QueueDO): CRDT ops are idempotent to re-apply by design, so at-least-once
// delivery needs no dedup at this layer — a device just remembers its own last-seen `seq` and asks for
// `since_seq` on its next connect, same as `GET /sync` already did for the poll path.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { base64ToBuf, bufToBase64 } from "../base64";
import { bucketTimestamp } from "../bucketing";

// The `[key: string]: SqlStorageValue` index signature is required by
// `SqlStorage.exec<T extends Record<string, SqlStorageValue>>`.
interface LogEntryRow {
  seq: number;
  blob: ArrayBuffer;
  enqueued_at: number;
  [key: string]: SqlStorageValue;
}

interface WireEntry {
  seq: number;
  blob: string; // base64
  enqueuedAt: number;
}

const MAX_BATCH_SIZE = 500; // defensive cap on a single /append call, not a protocol limit

function rowToWire(row: LogEntryRow): WireEntry {
  return { seq: row.seq, blob: bufToBase64(row.blob), enqueuedAt: row.enqueued_at };
}

export class ConvLogDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ensureSchema();
  }

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS entries (
        seq         INTEGER PRIMARY KEY AUTOINCREMENT,
        blob        BLOB NOT NULL,
        enqueued_at INTEGER NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.headers.get("Upgrade") === "websocket") {
      return this.handleSubscribe(url);
    }

    switch (`${request.method} ${url.pathname}`) {
      case "POST /append":
        return this.handleAppend(request);
      case "GET /sync":
        return this.handleSync(url);
      default:
        return new Response("Not found", { status: 404 });
    }
  }

  // ── append ──────────────────────────────────────────────────────────────────────────────────

  private async handleAppend(request: Request): Promise<Response> {
    // Reading the JSON body is the first thing this handler does regardless of outcome (it's the
    // only way to know what to validate), so — unlike QueueDO's /push, which validated headers
    // before touching a separate binary body — there is no early-return-before-drain hazard here
    // by construction. Still verified live against `wrangler dev` (see docs/06 Phase 3) rather
    // than assumed safe.
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }

    const blobsB64 = (body as { blobs?: unknown }).blobs;
    if (!Array.isArray(blobsB64) || blobsB64.length === 0) {
      return new Response("body.blobs must be a non-empty array", { status: 400 });
    }
    if (blobsB64.length > MAX_BATCH_SIZE) {
      return new Response(`body.blobs exceeds max batch size of ${MAX_BATCH_SIZE}`, { status: 400 });
    }

    let blobs: ArrayBuffer[];
    try {
      blobs = blobsB64.map((b) => {
        if (typeof b !== "string") throw new Error("not a string");
        const buf = base64ToBuf(b);
        if (buf.byteLength === 0) throw new Error("empty blob");
        return buf;
      });
    } catch {
      return new Response("every entry in body.blobs must be a non-empty base64 string", { status: 400 });
    }

    // Bucketed at write time, not just when returned — see bucketing.ts's header comment for why
    // (the primary named adversary in docs/02 can read raw DO storage directly, so coarsening only
    // at response time would protect against nothing that adversary actually does). No size_bucket
    // here (unlike QueueDO/GroupDO): the original D1 schema for `conv_log` never had one — CRDT
    // op-log entries are a different shape/threat model than message ciphertexts, so this pass
    // doesn't invent a padding requirement the design never called for.
    const bucketedEnqueuedAt = bucketTimestamp(Date.now());
    const seqs: number[] = [];
    const inserted: LogEntryRow[] = [];
    // Sequential inserts preserve the caller's array order as the assigned seq order — required
    // so a client's own batch of ops lands in the log in the order it produced them.
    for (const blob of blobs) {
      const row = this.ctx.storage.sql
        .exec<LogEntryRow>(
          "INSERT INTO entries (blob, enqueued_at) VALUES (?, ?) RETURNING seq, blob, enqueued_at",
          blob,
          bucketedEnqueuedAt,
        )
        .one();
      seqs.push(row.seq);
      inserted.push(row);
    }

    // Flow 4: "L--)D2: push blob@n (WS)" — fan each newly-assigned entry out to every device
    // currently attached, in seq order, right after it's durably persisted above.
    for (const row of inserted) this.fanOut(row);

    return Response.json({ seqs }, { status: 201 });
  }

  // ── sync (multi-device delta pull — also used for the WS backlog-on-connect below) ─────────────

  private parseSinceSeq(url: URL): number | null {
    const sinceParam = url.searchParams.get("since_seq");
    const sinceSeq = sinceParam === null ? 0 : Number(sinceParam);
    if (!Number.isFinite(sinceSeq) || sinceSeq < 0 || !Number.isInteger(sinceSeq)) return null;
    return sinceSeq;
  }

  private handleSync(url: URL): Response {
    const sinceSeq = this.parseSinceSeq(url);
    if (sinceSeq === null) return new Response("since_seq must be a non-negative integer", { status: 400 });

    const rows = this.ctx.storage.sql
      .exec<LogEntryRow>("SELECT * FROM entries WHERE seq > ? ORDER BY seq ASC", sinceSeq)
      .toArray();

    return Response.json({ entries: rows.map(rowToWire) });
  }

  // ── subscribe (hibernatable WS, instant fan-out path — R22 addition, see file header) ──────────

  private handleSubscribe(url: URL): Response {
    const sinceSeq = this.parseSinceSeq(url) ?? 0; // malformed since_seq on a WS upgrade -> just start from 0 rather than fail the upgrade
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    this.ctx.acceptWebSocket(server);

    const backlog = this.ctx.storage.sql
      .exec<LogEntryRow>("SELECT * FROM entries WHERE seq > ? ORDER BY seq ASC", sinceSeq)
      .toArray();
    for (const row of backlog) server.send(JSON.stringify(rowToWire(row)));

    return new Response(null, { status: 101, webSocket: client });
  }

  /** Forward a freshly appended entry to every currently attached device, if any. */
  private fanOut(row: LogEntryRow): void {
    const payload = JSON.stringify(rowToWire(row));
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(payload);
      } catch {
        // A dead/closing socket shouldn't fail the append — the entry stays in durable history
        // regardless, and the device picks it up via since_seq on its next connect.
      }
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean): Promise<void> {
    // Same real bug QueueDO.ts found live: re-closing an already-closing/closed socket throws in
    // workerd, and this callback fires AFTER the close handshake already happened — so this must
    // tolerate that, not treat it as fatal. No other per-socket state to clean up (this DO doesn't
    // track who's subscribed, same isolation reasoning as QueueDO).
    try {
      ws.close(code, reason);
    } catch {
      // Already closed/closing — nothing left to acknowledge.
    }
  }

  override async webSocketError(_ws: WebSocket, _error: unknown): Promise<void> {
    // No-op: a device that drops mid-sync just reconnects with its own last-seen seq — CRDT ops are
    // idempotent to re-apply, so there's no lost-update risk from a dropped socket.
  }
}
