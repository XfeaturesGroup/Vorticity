// Opt-in public @alias registry — Hashcash-gated, zero-knowledge to this DO. See
// docs/03-crypto-core.md §8 and docs/04-serverless-architecture.md Flows 5-6.
//
// ISOLATION (docs/02, docs/03 §8.1): the nickname itself NEVER reaches this DO. The client hashes
// it client-side into `lookup_key = H("vortic-alias-v1" || nickname)` and encrypts
// `{intro_queue_id, alias_pub, ...}` client-side into `record` under a key only derivable from the
// nickname (`HKDF(nickname)`) — this DO stores and serves opaque bytes on both sides. A full dump
// of this DO's storage yields no readable nickname->identity mapping without an offline dictionary
// grind against `lookup_key`, and even then the record decrypts to an intro-queue id, never an
// email/PPID/handle (see docs/03 §8.1's documented residual risk — that ceiling is accepted by
// design, not a bug here).
//
// Note vs. the original docs/04 schema sketch: that draft carried `alias_pub`/`pow_bits` as
// separate plaintext columns (needed for verifying signed update/revoke requests without
// decrypting `record` first). This pass only implements /register and /resolve — no update/revoke
// yet — so `alias_pub` stays bundled inside the encrypted `record` for now, which is *stronger*
// privacy than the original sketch. Reintroduce a plaintext `alias_pub` column only if/when
// signed-update support needs it.
//
// PROOF-OF-WORK (docs/03 §8.3): stamp = "ver:alg:bits:epoch:resource:salt:counter". A stamp is
// valid iff SHA-256(stamp) has >= the endpoint's required leading zero bits, `resource` matches
// the `lookup_key` being targeted (binds the stamp to this alias, not reusable elsewhere), and
// `epoch` is within +/-1 hour of now (bounds how long a precomputed stamp stays usable). Spent
// stamps are recorded in a single global set — a stamp minted for /register that happened to also
// clear /resolve's lower bit bar is still only spendable once, which is the correct semantics
// (each proof of work should buy exactly one action).
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { base64ToBuf, bufToBase64 } from "../base64";

const LOOKUP_KEY_RE = /^[0-9a-f]{64}$/; // SHA-256 digest, lowercase hex
const MAX_STAMP_LEN = 512; // defensive cap, not a protocol limit
const EPOCH_MS = 60 * 60 * 1000;
const EPOCH_TOLERANCE = 1; // stamp's epoch may be current +/- this many hours
const REGISTER_MIN_BITS = 24;
const RESOLVE_MIN_BITS = 20;

type PowVerdict = { ok: true; epoch: number } | { ok: false; reason: string };

/** Leading zero bits across a byte string, MSB-first — the Hashcash difficulty measure. */
function countLeadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    let b = byte;
    while ((b & 0x80) === 0) {
      bits++;
      b = (b << 1) & 0xff;
    }
    break;
  }
  return bits;
}

async function verifyPowStamp(stamp: string, expectedResource: string, minBits: number): Promise<PowVerdict> {
  if (stamp.length === 0 || stamp.length > MAX_STAMP_LEN) {
    return { ok: false, reason: "stamp length out of bounds" };
  }
  const parts = stamp.split(":");
  if (parts.length !== 7) {
    return { ok: false, reason: "malformed stamp: expected ver:alg:bits:epoch:resource:salt:counter" };
  }
  const [ver, alg, , epochStr, resource] = parts;
  if (ver !== "1") return { ok: false, reason: `unsupported stamp version: ${ver}` };
  if (alg !== "sha256") return { ok: false, reason: `unsupported stamp algorithm: ${alg}` };
  if (resource !== expectedResource) return { ok: false, reason: "stamp resource does not match target lookup_key" };

  const epoch = Number(epochStr);
  if (!Number.isInteger(epoch)) return { ok: false, reason: "invalid epoch field" };
  const currentEpoch = Math.floor(Date.now() / EPOCH_MS);
  if (Math.abs(epoch - currentEpoch) > EPOCH_TOLERANCE) {
    return { ok: false, reason: "stamp epoch outside acceptance window" };
  }

  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stamp));
  const actualBits = countLeadingZeroBits(new Uint8Array(digest));
  if (actualBits < minBits) {
    return { ok: false, reason: `insufficient PoW: ${actualBits} < ${minBits} leading zero bits` };
  }

  return { ok: true, epoch };
}

// Required by `SqlStorage.exec<T extends Record<string, SqlStorageValue>>`.
interface AliasRow {
  record: ArrayBuffer;
  [key: string]: SqlStorageValue;
}
interface StampRow {
  stamp: string;
  [key: string]: SqlStorageValue;
}
interface MinExpiresRow {
  min_expires: number | null;
  [key: string]: SqlStorageValue;
}

export class AliasDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ensureSchema();
  }

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS aliases (
        lookup_key TEXT PRIMARY KEY,
        record     BLOB NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pow_stamps (
        stamp      TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pow_stamps_expires_at ON pow_stamps(expires_at);
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/register") {
      return this.handleRegister(request);
    }

    const resolveMatch = url.pathname.match(/^\/resolve\/([^/]+)$/);
    if (request.method === "GET" && resolveMatch) {
      const rawKey = resolveMatch[1];
      if (rawKey) return this.handleResolve(request, decodeURIComponent(rawKey));
    }

    return new Response("Not found", { status: 404 });
  }

  // ── register ────────────────────────────────────────────────────────────────────────────────

  private async handleRegister(request: Request): Promise<Response> {
    // Read the JSON body first, unconditionally, before any validation branch can return early
    // (see QueueDO.ts for the body-drain bug this ordering avoids).
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }

    const lookupKey = (body as { lookup_key?: unknown }).lookup_key;
    const recordB64 = (body as { record?: unknown }).record;
    const powStamp = (body as { pow_stamp?: unknown }).pow_stamp;

    if (typeof lookupKey !== "string" || !LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex SHA-256 digest", { status: 400 });
    }
    if (typeof recordB64 !== "string" || recordB64.length === 0) {
      return new Response("record must be a non-empty base64 string", { status: 400 });
    }
    if (typeof powStamp !== "string") {
      return new Response("pow_stamp must be a string", { status: 400 });
    }

    let record: ArrayBuffer;
    try {
      record = base64ToBuf(recordB64);
      if (record.byteLength === 0) throw new Error("empty");
    } catch {
      return new Response("record is not valid base64", { status: 400 });
    }

    const pow = await verifyPowStamp(powStamp, lookupKey, REGISTER_MIN_BITS);
    if (!pow.ok) {
      return new Response(`PoW rejected: ${pow.reason}`, { status: 403 });
    }

    const spent = this.ctx.storage.sql.exec<StampRow>("SELECT stamp FROM pow_stamps WHERE stamp = ?", powStamp).toArray();
    if (spent.length > 0) {
      return new Response("pow_stamp already used (replay)", { status: 409 });
    }

    const existing = this.ctx.storage.sql
      .exec<{ lookup_key: string; [key: string]: SqlStorageValue }>(
        "SELECT lookup_key FROM aliases WHERE lookup_key = ?",
        lookupKey,
      )
      .toArray();
    if (existing.length > 0) {
      return new Response("alias already registered", { status: 409 });
    }

    const stampExpiresAt = (pow.epoch + EPOCH_TOLERANCE + 1) * EPOCH_MS;
    this.ctx.storage.sql.exec("INSERT INTO aliases (lookup_key, record, created_at) VALUES (?, ?, ?)", lookupKey, record, Date.now());
    this.ctx.storage.sql.exec("INSERT INTO pow_stamps (stamp, expires_at) VALUES (?, ?)", powStamp, stampExpiresAt);
    await this.scheduleStampSweepNoLaterThan(stampExpiresAt);

    return new Response(null, { status: 201 });
  }

  // ── resolve ─────────────────────────────────────────────────────────────────────────────────

  private async handleResolve(request: Request, lookupKey: string): Promise<Response> {
    if (!LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex SHA-256 digest", { status: 400 });
    }
    const powStamp = request.headers.get("X-PoW-Stamp");
    if (!powStamp) {
      return new Response("missing X-PoW-Stamp header", { status: 400 });
    }

    const pow = await verifyPowStamp(powStamp, lookupKey, RESOLVE_MIN_BITS);
    if (!pow.ok) {
      return new Response(`PoW rejected: ${pow.reason}`, { status: 403 });
    }

    const spent = this.ctx.storage.sql.exec<StampRow>("SELECT stamp FROM pow_stamps WHERE stamp = ?", powStamp).toArray();
    if (spent.length > 0) {
      return new Response("pow_stamp already used (replay)", { status: 409 });
    }

    const rows = this.ctx.storage.sql.exec<AliasRow>("SELECT record FROM aliases WHERE lookup_key = ?", lookupKey).toArray();

    // Spend the stamp regardless of hit/miss: a resolve attempt against a nonexistent alias still
    // cost the caller real work, and leaving a miss unspent would let it be retried for free —
    // exactly the scraping/enumeration cost this mechanism exists to impose (docs/03 §8.3).
    const stampExpiresAt = (pow.epoch + EPOCH_TOLERANCE + 1) * EPOCH_MS;
    this.ctx.storage.sql.exec("INSERT INTO pow_stamps (stamp, expires_at) VALUES (?, ?)", powStamp, stampExpiresAt);
    await this.scheduleStampSweepNoLaterThan(stampExpiresAt);

    const row = rows[0];
    if (!row) {
      return new Response("alias not found", { status: 404 });
    }
    return Response.json({ record: bufToBase64(row.record) });
  }

  // ── replay-set eviction (mirrors QueueDO's TTL-alarm pattern) ──────────────────────────────

  private async scheduleStampSweepNoLaterThan(expiresAt: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || expiresAt < current) {
      await this.ctx.storage.setAlarm(expiresAt);
    }
  }

  override async alarm(): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM pow_stamps WHERE expires_at <= ?", Date.now());
    const next = this.ctx.storage.sql.exec<MinExpiresRow>("SELECT MIN(expires_at) AS min_expires FROM pow_stamps").one();
    if (next.min_expires !== null) {
      await this.ctx.storage.setAlarm(next.min_expires);
    }
  }
}
