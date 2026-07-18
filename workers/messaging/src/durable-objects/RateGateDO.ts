// Sharding key: epoch bucket — one RateGateDO instance per epoch (docs/04 DO catalog), so counters
// reset naturally as new epochs roll in without any explicit TTL/cleanup logic. Purpose: rate limits for
// anything that must be gated BEFORE a session capability exists (nullifier + capability issuance per
// docs/03 §3, and — as of this pass — /membership/proof/:commitment, see MerkleTreeDO.ts's cost note).
// This is intentionally a generic "increment and check a named counter" primitive, not a
// proof-endpoint-specific mechanism: capability issuance rate limiting (still Phase-2 TODO) will reuse
// the exact same `/check` route with a different `key` prefix, not a second implementation.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

interface CountRow {
  count: number;
  [key: string]: SqlStorageValue;
}

export class RateGateDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS counters (
        key   TEXT PRIMARY KEY,
        count INTEGER NOT NULL
      );
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/check") return this.handleCheck(request);
    return new Response("Not found", { status: 404 });
  }

  // Atomically increments the counter for `key` and reports whether it's still within `limit`. DO
  // execution is single-threaded per instance, so this read-then-write is race-free without extra
  // locking — the same property every other DO in this codebase (MerkleTreeDO's nullifier spend,
  // QueueDO's seq counter) already relies on.
  private async handleCheck(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }
    const key = (body as { key?: unknown }).key;
    const limit = (body as { limit?: unknown }).limit;
    if (typeof key !== "string" || key.length === 0 || key.length > 256) {
      return new Response("key must be a non-empty string (max 256 chars)", { status: 400 });
    }
    if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1) {
      return new Response("limit must be a positive integer", { status: 400 });
    }

    const existing = this.ctx.storage.sql.exec<CountRow>("SELECT count FROM counters WHERE key = ?", key).toArray();
    const nextCount = (existing[0]?.count ?? 0) + 1;
    this.ctx.storage.sql.exec(
      "INSERT INTO counters (key, count) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET count = excluded.count",
      key,
      nextCount,
    );
    return Response.json({ allowed: nextCount <= limit, count: nextCount, limit });
  }
}
