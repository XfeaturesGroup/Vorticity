// Sharding key: `${chatId}:${role}` — NOT the bare chat id (real bug found + fixed 2026-07, first
// live use: a chat id is SHARED by both parties of an ordinary 1:1 conversation — queueIds() derives
// both directions from it — while `role` ("responder"/"initiator") is per-party. Sharding on the bare
// chat id made the responder and the initiator, i.e. two DIFFERENT PEOPLE, not linked devices at all,
// race for the SAME lease the instant both had the chat open, and the loser was shown "active on
// another device" for a completely normal two-person conversation — this DO never learns which shape
// its own key has, so the fix lives entirely client-side (see lib/deviceLease.ts's header comment),
// this class just needs the corrected input.
//
// Prevents the real correctness hazard device-linking (docs/06) introduces: TWO of a user's own
// devices holding the SAME per-chat, per-role ratchet state and both independently sending/receiving
// would desync that shared state — not just against each other, but against the PEER too (the peer's
// own ratchet only ever expects ONE sender-direction chain advancing in order; two devices
// concurrently advancing "the same" chain corrupts it from the peer's side as well, a real bug
// affecting the other party, not just the linked user's own devices).
//
// WHAT THIS IS: a simple mutual-exclusion lease, renewed by heartbeat, held by at most one deviceId
// at a time. It does NOT gate messaging capability (that's `requireCapability`, unchanged) — it only
// answers "is it currently safe for THIS device to run a live ratchet session for this chat", which
// `useQueueTransport.ts` checks before mounting one. A device that fails to acquire falls back to a
// read-only view (chat history only, no live send/receive) rather than risking a silent desync.
//
// EXPIRY IS THE SAFETY NET, NOT AN EDGE CASE: a device that crashes, loses network, or has its tab
// closed without a clean `/release` leaves the lease to expire on its own after `LEASE_TTL_MS` of no
// renewal — a live-locked chat (nobody can ever acquire it again) would be worse than the desync risk
// this DO exists to prevent, so a stale lease must always be reclaimable, never permanent.
//
// ISOLATION: knows only an opaque `deviceId` string (client-generated, NOT identity material — same
// non-sensitivity as a device *label*, safe to keep in plain `localStorage` client-side, unlike every
// other per-device secret this project seals in the non-extractable vault) and timestamps. No
// account/session identifier, no capability check here either (one layer up in index.ts, same as
// every other DO in this catalog).
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

const LEASE_TTL_MS = 45 * 1000; // must outlive useQueueTransport.ts's heartbeat interval with margin

interface LeaseRow {
  holder: string;
  expires_at: number;
  [key: string]: SqlStorageValue;
}

export class DeviceLeaseDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS lease (
        id         INTEGER PRIMARY KEY CHECK (id = 0),
        holder     TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    switch (`${request.method} ${url.pathname}`) {
      case "POST /acquire":
        return this.handleAcquire(request);
      case "POST /release":
        return this.handleRelease(request);
      case "GET /status":
        return this.handleStatus();
      default:
        return new Response("Not found", { status: 404 });
    }
  }

  private currentLease(): LeaseRow | null {
    const row = this.ctx.storage.sql.exec<LeaseRow>("SELECT * FROM lease WHERE id = 0").toArray()[0] ?? null;
    if (row && row.expires_at <= Date.now()) return null; // expired — treated as absent, not deleted yet (next write cleans it up)
    return row;
  }

  private async handleAcquire(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const deviceId = (body as { deviceId?: unknown }).deviceId;
    if (typeof deviceId !== "string" || deviceId.length === 0) {
      return new Response("deviceId is required", { status: 400 });
    }

    const current = this.currentLease();
    if (current && current.holder !== deviceId) {
      return Response.json({ granted: false, holder: current.holder, expiresAt: current.expires_at }, { status: 409 });
    }

    // Either no live lease, or renewing our own — grant/extend.
    const expiresAt = Date.now() + LEASE_TTL_MS;
    this.ctx.storage.sql.exec(
      `INSERT INTO lease (id, holder, expires_at) VALUES (0, ?, ?)
       ON CONFLICT(id) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at`,
      deviceId,
      expiresAt,
    );
    await this.ctx.storage.setAlarm(expiresAt);
    return Response.json({ granted: true, expiresAt });
  }

  private async handleRelease(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const deviceId = (body as { deviceId?: unknown }).deviceId;
    // Only the current holder can release — a stale/foreign release request is a no-op, not an error:
    // it just means this caller no longer matters to the current lease state, which is already true.
    const current = this.currentLease();
    if (current && current.holder === deviceId) {
      this.ctx.storage.sql.exec("DELETE FROM lease WHERE id = 0");
    }
    return new Response(null, { status: 204 });
  }

  private handleStatus(): Response {
    const current = this.currentLease();
    return Response.json({ held: current !== null, holder: current?.holder ?? null, expiresAt: current?.expires_at ?? null });
  }

  override async alarm(): Promise<void> {
    const current = this.ctx.storage.sql.exec<LeaseRow>("SELECT * FROM lease WHERE id = 0").toArray()[0] ?? null;
    if (current && current.expires_at <= Date.now()) {
      this.ctx.storage.sql.exec("DELETE FROM lease WHERE id = 0");
    }
  }
}
