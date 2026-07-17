// Pairwise unidirectional queue (SimpleX model). One QueueDO instance == one direction of one
// connection (A->B), addressed by a rotating opaque queue_id (the DO's own name/id — never
// stored as data inside the DO, since the instance itself IS that identity). Rotation to a new
// queue_id is a NEW DO instance by construction; this class has no rotation logic of its own.
// See docs/04-serverless-architecture.md DO catalog + Flow 3, and docs/03-crypto-core.md §7.
//
// ISOLATION (docs/02, docs/04): this DO knows only `seq`, `ciphertext`, `size_bucket`, and
// timestamps. No account/session identifier, no sender/recipient field, no capability check —
// that verification happens one layer up, in the Messaging Worker, before a request ever reaches
// here (see index.ts). This DO cannot tell who is pushing or who is subscribed.
//
// STORAGE: the DO's own SQLite storage (`ctx.storage.sql`) is authoritative/hot-path per docs/04
// ("DO SQLite is hot path; D1 is the durable mirror") — this class does not touch DB_MSG directly;
// mirroring to D1 (if ever needed for cross-region durability) is a separate concern, not part of
// the hot push/pull path.
//
// PHASE 5 TRANSPORT-SPIKE RELAY (webSocketMessage below): any JSON text frame that isn't the
// `{type:"ack",...}` protocol frame gets broadcast verbatim to every OTHER socket currently
// attached to this queue (see `relayToOthers`). This is NOT the real push/ack split described in
// the rest of this file — a real push is `POST /push` over HTTP with a ciphertext body, TTL, and
// size bucket, and gets persisted + fanned out via `fanOut()`. The relay path is unpersisted and
// exists solely so apps/web's `useChatWebSocket.ts` can exercise the local dev loop end-to-end
// (browser <-> `wrangler dev`) before the real capability bridge and push/ack reconciliation land.
// It's a deliberate, temporary widening of this DO's job, not an oversight — revisit once the real
// protocol is wired all the way through.
//
// WEBSOCKET HIBERNATION — what it actually buys us here (being precise, not oversold): while a
// subscriber's socket sits open with no traffic, the DO holds no in-memory JS state and accrues no
// duration billing (docs/04 "Cloudflare limits"). It is NOT possible to push a byte into an
// already-hibernated socket without *some* invocation of this DO — only the DO can call
// `ws.send()` on its own attached sockets. What actually happens: the sender's `push` call is
// itself a fresh invocation of this DO, which is what wakes it (if hibernating); on waking,
// `ctx.getWebSockets()` returns the still-attached socket exactly as before hibernation, so the
// DO can write the row and immediately forward it, then go back to sleep. The saving is *how
// little* the DO wakes for (one write + one send, not a resident process), not that it avoids
// waking altogether.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { bufToBase64 } from "../base64";

// The `[key: string]: SqlStorageValue` index signatures below are required by
// `SqlStorage.exec<T extends Record<string, SqlStorageValue>>` — every row shape passed as the
// generic parameter must structurally satisfy it.
interface QueueMessageRow {
  seq: number;
  ciphertext: ArrayBuffer;
  size_bucket: number;
  enqueued_at: number;
  expires_at: number;
  [key: string]: SqlStorageValue;
}

interface SeqRow {
  seq: number;
  [key: string]: SqlStorageValue;
}

interface MinExpiresRow {
  min_expires: number | null;
  [key: string]: SqlStorageValue;
}

interface WireMessage {
  type: "message";
  seq: number;
  ciphertext: string; // base64
  sizeBucket: number;
  enqueuedAt: number;
}

const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — a defensive cap, not a protocol limit
const DEFAULT_PULL_LIMIT = 100;

function rowToWire(row: QueueMessageRow): WireMessage {
  return {
    type: "message",
    seq: row.seq,
    ciphertext: bufToBase64(row.ciphertext),
    sizeBucket: row.size_bucket,
    enqueuedAt: row.enqueued_at,
  };
}

export class QueueDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ensureSchema();
  }

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        seq         INTEGER PRIMARY KEY AUTOINCREMENT,
        ciphertext  BLOB NOT NULL,
        size_bucket INTEGER NOT NULL,
        enqueued_at INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at);
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") === "websocket") {
      return this.handleSubscribe();
    }

    const url = new URL(request.url);
    switch (`${request.method} ${url.pathname}`) {
      case "POST /push":
        return this.handlePush(request);
      case "GET /pull":
        return this.handlePull(url);
      case "POST /ack":
        return this.handleAck(request);
      default:
        return new Response("Not found", { status: 404 });
    }
  }

  // ── push ────────────────────────────────────────────────────────────────────────────────────

  private async handlePush(request: Request): Promise<Response> {
    // Always drain the body FIRST, before any validation branch that might return early. An
    // unconsumed request body abandoned mid-flight (e.g. returning 400 on a bad header without
    // reading it) throws "Can't read from request stream after response has been sent" once this
    // Request has been forwarded through the Worker -> DO fetch() boundary — confirmed against a
    // live `wrangler dev` instance while validating this class.
    const ciphertext = await request.arrayBuffer();

    const ttlMs = Number(request.headers.get("X-Ttl-Ms"));
    const sizeBucket = Number(request.headers.get("X-Size-Bucket"));
    if (!Number.isFinite(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL_MS) {
      return new Response("invalid or missing X-Ttl-Ms", { status: 400 });
    }
    if (!Number.isFinite(sizeBucket) || sizeBucket < 0) {
      return new Response("invalid or missing X-Size-Bucket", { status: 400 });
    }
    if (ciphertext.byteLength === 0) {
      return new Response("empty ciphertext", { status: 400 });
    }

    const now = Date.now();
    const expiresAt = now + ttlMs;

    const row = this.ctx.storage.sql
      .exec<SeqRow>(
        `INSERT INTO messages (ciphertext, size_bucket, enqueued_at, expires_at)
         VALUES (?, ?, ?, ?)
         RETURNING seq`,
        ciphertext,
        sizeBucket,
        now,
        expiresAt,
      )
      .one();

    await this.scheduleEvictionNoLaterThan(expiresAt);
    this.fanOut({
      type: "message",
      seq: row.seq,
      ciphertext: bufToBase64(ciphertext),
      sizeBucket,
      enqueuedAt: now,
    });

    return Response.json({ seq: row.seq }, { status: 201 });
  }

  // ── pull (poll-based receive path) ─────────────────────────────────────────────────────────

  private handlePull(url: URL): Response {
    this.evictExpired();

    const limitParam = Number(url.searchParams.get("limit"));
    const limit = Number.isFinite(limitParam) && limitParam > 0 ? Math.min(limitParam, 500) : DEFAULT_PULL_LIMIT;

    const rows = this.ctx.storage.sql
      .exec<QueueMessageRow>("SELECT * FROM messages ORDER BY seq ASC LIMIT ?", limit)
      .toArray();

    return Response.json({ messages: rows.map(rowToWire) });
  }

  // ── ack (explicit delivery confirmation — TTL is only the backstop) ───────────────────────────

  private async handleAck(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const upToSeq = (body as { upToSeq?: unknown }).upToSeq;
    if (typeof upToSeq !== "number" || !Number.isInteger(upToSeq)) {
      return new Response("upToSeq must be an integer", { status: 400 });
    }

    this.ctx.storage.sql.exec("DELETE FROM messages WHERE seq <= ?", upToSeq);
    return new Response(null, { status: 204 });
  }

  // ── subscribe (hibernatable WebSocket, instant fan-out path) ───────────────────────────────────

  private handleSubscribe(): Response {
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    this.ctx.acceptWebSocket(server);

    // Catch-up: flush whatever is already buffered immediately on connect, same as a /pull would.
    this.evictExpired();
    const backlog = this.ctx.storage.sql.exec<QueueMessageRow>("SELECT * FROM messages ORDER BY seq ASC").toArray();
    for (const row of backlog) {
      server.send(JSON.stringify(rowToWire(row)));
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") return; // ack/relay protocol is JSON text frames only
    let parsed: unknown;
    try {
      parsed = JSON.parse(message);
    } catch {
      return; // malformed frame from an untrusted client — ignore, don't crash the socket
    }
    const obj = parsed as { type?: unknown; upToSeq?: unknown };
    if (obj.type === "ack" && typeof obj.upToSeq === "number" && Number.isInteger(obj.upToSeq)) {
      this.ctx.storage.sql.exec("DELETE FROM messages WHERE seq <= ?", obj.upToSeq);
      return;
    }

    // Phase 5 transport-spike relay (see file-header note): everything else — e.g. the plaintext
    // {type:"message",...} frames apps/web's useChatWebSocket.ts sends — gets broadcast as-is to
    // every OTHER socket on this queue. Unpersisted, best-effort, not the real push path.
    this.relayToOthers(ws, message);
  }

  /** Broadcasts a raw text frame to every attached socket except the one it came from. */
  private relayToOthers(sender: WebSocket, message: string): void {
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === sender) continue;
      try {
        ws.send(message);
      } catch {
        // A dead/closing socket shouldn't break the relay for everyone else.
      }
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    // Nothing to clean up: this DO holds no per-socket in-memory state (docs/04 isolation — it
    // doesn't know who was subscribed), and undelivered messages simply remain queued for the
    // next subscriber or /pull, evicted only by ack or TTL.
    //
    // REAL BUG found live (2026-07, Phase 5 E2E relay test): calling `ws.close()` here unconditionally
    // threw "Uncaught Error" on every single close — confirmed in `wrangler dev` logs, one exception
    // per connection teardown, regardless of which side initiated it. By the time this handler runs,
    // the close handshake this callback is reporting has already happened; re-closing an already-
    // closing/closed WebSocket throws in workerd. Left uncaught, this was firing on nearly every
    // reconnect/tab-switch during testing and is the likely cause of relayed messages going missing
    // (an uncaught exception here can tear down the DO's in-memory socket attachments mid-relay).
    // Same tolerance pattern as `relayToOthers`/`fanOut` below: a socket already gone shouldn't be
    // treated as fatal.
    try {
      ws.close(code, reason);
    } catch {
      // Already closed/closing — nothing left to acknowledge.
    }
  }

  override async webSocketError(_ws: WebSocket, _error: unknown): Promise<void> {
    // No-op: same reasoning as webSocketClose. TTL is the backstop for any lost push.
  }

  // ── eviction ────────────────────────────────────────────────────────────────────────────────

  private evictExpired(): void {
    this.ctx.storage.sql.exec("DELETE FROM messages WHERE expires_at <= ?", Date.now());
  }

  /** Ensure an alarm fires no later than `expiresAt`, without pushing an existing earlier alarm out. */
  private async scheduleEvictionNoLaterThan(expiresAt: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || expiresAt < current) {
      await this.ctx.storage.setAlarm(expiresAt);
    }
  }

  override async alarm(): Promise<void> {
    this.evictExpired();
    const next = this.ctx.storage.sql
      .exec<MinExpiresRow>("SELECT MIN(expires_at) AS min_expires FROM messages")
      .one();
    if (next.min_expires !== null) {
      await this.ctx.storage.setAlarm(next.min_expires);
    }
  }

  /** Forward a freshly pushed message to every currently attached subscriber, if any. */
  private fanOut(msg: WireMessage): void {
    const payload = JSON.stringify(msg);
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(payload);
      } catch {
        // A dead/closing socket shouldn't fail the push — the message stays queued regardless.
      }
    }
  }
}
