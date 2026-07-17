// Blind ordering service for group chats — the MLS (RFC 9420) Delivery Service role. One GroupDO
// instance == one group; it orders Commit/Application ciphertext and fans it out. See
// docs/03-crypto-core.md §5 and docs/04-serverless-architecture.md DO catalog + Flow 3/4.
//
// ISOLATION (docs/02, docs/04): this DO knows only `seq`, an opaque encrypted blob, an optional
// opaque `sender_queue_id` tag, and a timestamp — never a group id as data (the DO's own name IS
// that id), never a member identity, never plaintext, never MLS epoch semantics (it can't tell a
// Commit from an Application message — both are opaque blobs to it). A "group", from the server's
// point of view, is nothing more than a set of anonymous sockets listening to one DO. Capability
// verification happens one layer up in the Messaging Worker, before a request reaches here.
//
// `sender_queue_id` IS NOT AN IDENTITY: it is an opaque per-connection tag a client may attach to
// its own push/subscribe calls purely so the DO can skip echoing a member's own message back to
// their own live socket. It is never used to authenticate, never joined to anything, and carries
// no meaning beyond "sockets tagged with this string are the same submitter as this message."
//
// STORAGE: DO-local SQLite (`ctx.storage.sql`), same pattern as QueueDO/ConvLogDO. No TTL — like
// ConvLogDO this is an ordered durable log (members can be offline for a while and still catch up
// via /sync), not a transient delivery queue.
//
// WEBSOCKET HIBERNATION: same caveat as documented in QueueDO.ts — hibernation means the DO holds
// no in-memory state and accrues no duration cost while sockets sit idle; a `/push` is still a
// real (if brief) invocation that wakes the DO to write + fan out, then it can sleep again.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { base64ToBuf, bufToBase64 } from "../base64";

// Required by `SqlStorage.exec<T extends Record<string, SqlStorageValue>>`.
interface GroupEntryRow {
  seq: number;
  blob: ArrayBuffer;
  sender_queue_id: string | null;
  enqueued_at: number;
  [key: string]: SqlStorageValue;
}

interface WireEntry {
  type: "message";
  seq: number;
  blob: string; // base64
  senderQueueId: string | null;
  enqueuedAt: number;
}

const MAX_BATCH_SIZE = 500; // defensive cap on a single /push call, not a protocol limit

function rowToWire(row: GroupEntryRow): WireEntry {
  return {
    type: "message",
    seq: row.seq,
    blob: bufToBase64(row.blob),
    senderQueueId: row.sender_queue_id,
    enqueuedAt: row.enqueued_at,
  };
}

export class GroupDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ensureSchema();
  }

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS entries (
        seq             INTEGER PRIMARY KEY AUTOINCREMENT,
        blob            BLOB NOT NULL,
        sender_queue_id TEXT,
        enqueued_at     INTEGER NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") === "websocket") {
      return this.handleSubscribe(new URL(request.url));
    }

    const url = new URL(request.url);
    switch (`${request.method} ${url.pathname}`) {
      case "POST /push":
        return this.handlePush(request);
      case "GET /sync":
        return this.handleSync(url);
      default:
        return new Response("Not found", { status: 404 });
    }
  }

  // ── push (batch write + immediate live fan-out) ────────────────────────────────────────────

  private async handlePush(request: Request): Promise<Response> {
    // Read the JSON body first, unconditionally — it's the only way to know what to validate, so
    // there is no early-return-before-drain hazard here (see QueueDO.ts for the bug this avoids).
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

    const senderQueueId = (body as { senderQueueId?: unknown }).senderQueueId;
    if (senderQueueId !== undefined && (typeof senderQueueId !== "string" || senderQueueId.length === 0)) {
      return new Response("body.senderQueueId must be a non-empty string if present", { status: 400 });
    }
    const senderTag: string | null = (senderQueueId as string | undefined) ?? null;

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

    const now = Date.now();
    const seqs: number[] = [];
    for (const blob of blobs) {
      const row = this.ctx.storage.sql
        .exec<{ seq: number; [key: string]: SqlStorageValue }>(
          "INSERT INTO entries (blob, sender_queue_id, enqueued_at) VALUES (?, ?, ?) RETURNING seq",
          blob,
          senderTag,
          now,
        )
        .one();
      seqs.push(row.seq);
      this.fanOut({
        type: "message",
        seq: row.seq,
        blob: bufToBase64(blob),
        senderQueueId: senderTag,
        enqueuedAt: now,
      });
    }

    return Response.json({ seqs }, { status: 201 });
  }

  // ── sync (poll-based catch-up for offline members) ─────────────────────────────────────────

  private handleSync(url: URL): Response {
    const sinceSeq = this.parseSinceSeq(url);
    if (sinceSeq === null) {
      return new Response("since_seq must be a non-negative integer", { status: 400 });
    }

    const rows = this.ctx.storage.sql
      .exec<GroupEntryRow>("SELECT * FROM entries WHERE seq > ? ORDER BY seq ASC", sinceSeq)
      .toArray();

    return Response.json({ entries: rows.map(rowToWire) });
  }

  // ── subscribe (hibernatable WebSocket: connect-time catch-up + live fan-out) ────────────────

  private handleSubscribe(url: URL): Response {
    const sinceSeq = this.parseSinceSeq(url);
    if (sinceSeq === null) {
      return new Response("since_seq must be a non-negative integer", { status: 400 });
    }
    const senderQueueId = url.searchParams.get("sender_queue_id");

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    // Tagging lets fanOut() skip echoing a member's own live push back to their own socket (see
    // module doc — this tag is opaque and carries no identity). Untagged if none was supplied.
    this.ctx.acceptWebSocket(server, senderQueueId ? [senderQueueId] : []);

    const backlog = this.ctx.storage.sql
      .exec<GroupEntryRow>("SELECT * FROM entries WHERE seq > ? ORDER BY seq ASC", sinceSeq)
      .toArray();
    for (const row of backlog) {
      server.send(JSON.stringify(rowToWire(row)));
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(_ws: WebSocket, _message: string | ArrayBuffer): Promise<void> {
    // No client->server protocol over this socket (unlike QueueDO's ack frames): this is a
    // durable log with no eviction, so members only ever push via POST /push. Any inbound frame
    // (e.g. a keepalive ping some client sends) is intentionally ignored, not an error.
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean): Promise<void> {
    ws.close(code, reason);
  }

  override async webSocketError(_ws: WebSocket, _error: unknown): Promise<void> {
    // No-op: this DO holds no per-socket state to clean up (docs/04 isolation).
  }

  // ── helpers ─────────────────────────────────────────────────────────────────────────────────

  private parseSinceSeq(url: URL): number | null {
    const param = url.searchParams.get("since_seq");
    const sinceSeq = param === null ? 0 : Number(param);
    if (!Number.isFinite(sinceSeq) || sinceSeq < 0 || !Number.isInteger(sinceSeq)) return null;
    return sinceSeq;
  }

  /** Forward a freshly pushed entry to every attached socket except ones tagged as its own sender. */
  private fanOut(entry: WireEntry): void {
    const payload = JSON.stringify(entry);
    for (const ws of this.ctx.getWebSockets()) {
      if (entry.senderQueueId !== null && this.ctx.getTags(ws).includes(entry.senderQueueId)) {
        continue; // don't echo a member's own push back to their own live socket
      }
      try {
        ws.send(payload);
      } catch {
        // A dead/closing socket shouldn't fail the push — the entry is already durably stored.
      }
    }
  }
}
