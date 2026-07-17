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
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { base64ToBuf, bufToBase64 } from "../base64";

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

    const now = Date.now();
    const seqs: number[] = [];
    // Sequential inserts preserve the caller's array order as the assigned seq order — required
    // so a client's own batch of ops lands in the log in the order it produced them.
    for (const blob of blobs) {
      const row = this.ctx.storage.sql
        .exec<{ seq: number; [key: string]: SqlStorageValue }>(
          "INSERT INTO entries (blob, enqueued_at) VALUES (?, ?) RETURNING seq",
          blob,
          now,
        )
        .one();
      seqs.push(row.seq);
    }

    return Response.json({ seqs }, { status: 201 });
  }

  // ── sync (multi-device delta pull) ─────────────────────────────────────────────────────────

  private handleSync(url: URL): Response {
    const sinceParam = url.searchParams.get("since_seq");
    const sinceSeq = sinceParam === null ? 0 : Number(sinceParam);
    if (!Number.isFinite(sinceSeq) || sinceSeq < 0 || !Number.isInteger(sinceSeq)) {
      return new Response("since_seq must be a non-negative integer", { status: 400 });
    }

    const rows = this.ctx.storage.sql
      .exec<LogEntryRow>("SELECT * FROM entries WHERE seq > ? ORDER BY seq ASC", sinceSeq)
      .toArray();

    return Response.json({ entries: rows.map(rowToWire) });
  }
}
