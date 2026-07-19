// Sharding key: the linking channel id itself (derived client-side from a random "linking secret" —
// see apps/web/src/lib/deviceLink.ts). One instance per link attempt, single-use, short-lived.
//
// WHAT THIS IS: a dumb, one-time, TTL'd dead-drop for the AEAD-SEALED device-linking payload
// (identity/KEM material, the local one-time-prekey pool, and a live ratchet-state export — see
// deviceLink.ts's header comment for the full payload shape and why it's transferred this way rather
// than through ConvLogDO). This DO never sees plaintext: `blob` is opaque ciphertext exactly like
// QueueDO's own message bodies, sealed under a key derived from the linking secret, which never
// crosses this DO or any other part of the server — only the two devices that both know the secret
// (because a human moved it between their own devices) can ever decrypt what's stored here.
//
// SINGLE-USE, SHORT-LIVED: `GET /take` deletes the row in the same call that reads it (same
// read-then-delete-is-race-free reasoning as PrekeyDO's one-time-prekey pop — a DO's execution is
// serialized per instance, so no separate connection can interleave). An alarm evicts an unclaimed
// blob after `TTL_MS` regardless, so an abandoned linking attempt doesn't leave sensitive ciphertext
// sitting around indefinitely.
//
// AUTH: both `/put` (the already-logged-in device generating the link) and `/take` (the device
// completing it) are gated by `requireCapability` one layer up in index.ts, same as every other
// conversation route — device linking transfers CHAT-level crypto state between a user's own
// devices, it does NOT bypass account-level authentication; the second device still needs its own
// real session capability (from its own real OAuth+ZK login) before it can reach this DO at all.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

const TTL_MS = 10 * 60 * 1000; // 10 minutes — generous enough for a human to move the code between devices, short enough not to linger

interface BlobRow {
  blob: string;
  [key: string]: SqlStorageValue;
}

export class DeviceLinkDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS link (
        id   INTEGER PRIMARY KEY CHECK (id = 0),
        blob TEXT NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    switch (`${request.method} ${url.pathname}`) {
      case "POST /put":
        return this.handlePut(request);
      case "GET /take":
        return this.handleTake();
      default:
        return new Response("Not found", { status: 404 });
    }
  }

  private async handlePut(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const blob = (body as { blob?: unknown }).blob;
    if (typeof blob !== "string" || blob.length === 0) {
      return new Response("blob (base64 ciphertext) is required", { status: 400 });
    }
    // Overwrite semantics (not append): only one pending link attempt makes sense per channel id —
    // a caller generating a fresh code always gets a fresh linkId (derived from a fresh random
    // secret), so a collision here would only happen if the SAME code were reused, which is already
    // a caller error this DO has no better answer for than "the newer put wins".
    this.ctx.storage.sql.exec(`INSERT INTO link (id, blob) VALUES (0, ?) ON CONFLICT(id) DO UPDATE SET blob = excluded.blob`, blob);
    await this.ctx.storage.setAlarm(Date.now() + TTL_MS);
    return Response.json({ ok: true }, { status: 201 });
  }

  private handleTake(): Response {
    const row = this.ctx.storage.sql.exec<BlobRow>("SELECT * FROM link WHERE id = 0").toArray()[0] ?? null;
    if (!row) {
      return new Response("no pending link for this code (already claimed, expired, or never created)", { status: 404 });
    }
    this.ctx.storage.sql.exec("DELETE FROM link WHERE id = 0");
    return Response.json({ blob: row.blob });
  }

  override async alarm(): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM link WHERE id = 0");
  }
}
