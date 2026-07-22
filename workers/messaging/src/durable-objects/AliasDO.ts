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
// decrypting `record` first).
//
// R18 (2026-07, "signed alias revoke" pass): `alias_pub` is now a plaintext column, populated at
// register time — the client sends it alongside the already-opaque `record` blob. No new privacy
// leak: `alias_pub` is a bare Ed25519 public key with no structural link to a nickname, an email,
// or a `DB_ENROLL` identity — the same property `record`'s bundled copy already had, just no longer
// requiring the nickname (hence `record`'s decryption key) to read it. This is what lets `/revoke`
// verify a signature (vortic-core's `alias_sig::verify`, via `alias-wasm.ts`) WITHOUT ever
// decrypting `record` — this DO still never learns the nickname. Update (replacing a record's
// contents) is NOT implemented here — see `alias.rs`'s module doc for why that's a deliberate,
// smaller scope for this pass.
//
// PROOF-OF-WORK (docs/03 §8.3): stamp = "ver:alg:bits:epoch:resource:salt:counter". A stamp is
// valid iff SHA-256(stamp) has >= the endpoint's required leading zero bits, `resource` matches
// the target being spent against (binds the stamp to this specific alias/introduce target, not
// reusable elsewhere), and `epoch` is within +/-1 hour of now (bounds how long a precomputed
// stamp stays usable). Spent stamps are recorded in a single global set — a stamp minted for
// /register that happened to also clear /resolve's lower bit bar is still only spendable once,
// which is the correct semantics (each proof of work should buy exactly one action).
// `verifyPowStamp`/`countLeadingZeroBits` moved to `../pow.ts` (2026-07, "alias contact
// establishment" pass) so the new `/introduce` write-path below reuses this exact,
// already-tested check rather than a second hand-rolled copy.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { base64ToBuf, bufToBase64 } from "../base64";
import { verifyPowStamp, stampExpiryFromEpoch } from "../pow";
import { verifyAliasOwnership, aliasRevokeMessage } from "../alias-wasm";
import { hexToBytes } from "../session";
import { namespaceAuthorityPubkeys } from "../namespace-authority-key";

const LOOKUP_KEY_RE = /^[0-9a-f]{64}$/; // SHA-256 digest, lowercase hex
const ALIAS_PUB_RE = /^[0-9a-f]{64}$/; // raw 32-byte Ed25519 public key, lowercase hex
const REGISTER_MIN_BITS = 24;

// R18 (2026-07, "reserved/verified namespaces" pass): closes the exact gap named "Not done" across
// three prior R18 progress notes in docs/06. A `lookup_key` in `reserved_namespaces` (added via
// `/reserve`, gated by an OFFLINE authority signature — see namespace-authority-key.ts / the
// namespace-authority.mts tool's header comment for the full design) cannot be claimed by ordinary
// PoW alone: `handleRegister` additionally requires a `registrant_sig` binding the SAME authority's
// approval to the SPECIFIC `alias_pub` attempting to register — so a reserved name is strictly
// HARDER to claim than an ordinary one (PoW AND an authority signature), never easier, and the
// ordinary (non-reserved) path is completely unchanged. Two domain-separated message prefixes so a
// signature for one action can never verify as the other (see the two builder functions below).
function reserveMessage(lookupKey: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode("vortic-reserve-v1:");
  const out = new Uint8Array(prefix.length + lookupKey.length);
  out.set(prefix, 0);
  out.set(lookupKey, prefix.length);
  return out;
}
function registrantMessage(lookupKey: Uint8Array, aliasPub: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode("vortic-registrant-v1:");
  const out = new Uint8Array(prefix.length + lookupKey.length + aliasPub.length);
  out.set(prefix, 0);
  out.set(lookupKey, prefix.length);
  out.set(aliasPub, prefix.length + lookupKey.length);
  return out;
}
/** Verifies `sig` over `message` against ANY currently-known authority key (supports rotation — see
 * namespace-authority-key.ts's header comment), not just a single hardcoded one. */
function verifyAgainstAnyAuthorityKey(message: Uint8Array, sig: Uint8Array): boolean {
  return namespaceAuthorityPubkeys().some((pk) => verifyAliasOwnership(pk, message, sig));
}

// R15/R16 (2026-07, "adaptive resolve difficulty" pass): resolve used to require a FLAT 20 bits no
// matter how many times a given lookup_key had already been resolved this epoch — the risk
// register's own R15 mitigation column ("adaptive/per-target difficulty") was still unimplemented.
// Real gap this closes: a flat cost lets a scraper hammer ONE known/guessed alias arbitrarily many
// times per epoch for the same per-attempt price. Reuses the exact `RateGateDO` "increment and
// check a counter" primitive the `/proof` and `/auth/session` rate limits already established
// (RateGateDO.ts's own header comment explicitly anticipated more callers of `/check`, not just
// those two) — but instead of hard-blocking at a limit, the running per-epoch attempt count for
// THIS lookup_key raises the required PoW bits, so cost scales smoothly with how hot a target is
// rather than falling off a cliff at some N+1th request.
const RESOLVE_BASE_BITS = 20;
const RESOLVE_ADAPTIVE_STEP = 5; // every this-many resolve attempts against one lookup_key this epoch...
const RESOLVE_ADAPTIVE_BITS_PER_STEP = 1; // ...adds this many required bits...
const RESOLVE_MAX_BITS = 28; // ...capped here (docs/03 §8.3's 18-26 bit range, +2 headroom for this cap)
// Flow 6 (docs/04): "write to intro queue" PoW, resource = the target intro_queue_id, not a
// lookup_key. Mid docs/03 §8.3's stated 20-24 bit write range, distinct from RESOLVE_BASE_BITS
// only as a difficulty choice — the two never collide on which stamp satisfies which endpoint
// since every stamp is resource-bound (a resolve-shaped stamp targets a lookup_key hex string, an
// introduce-shaped stamp targets an intro_queue_id — the two id-spaces don't overlap in practice).
const INTRODUCE_MIN_BITS = 22;
// A contact request sits in the recipient's inbox until they check it — long enough to be useful,
// short enough that an unclaimed request doesn't linger forever (same finite-lifetime philosophy
// as every other queued item in this app; QueueDO's own TTL is the precedent).
const INTRODUCE_TTL_MS = 3 * 24 * 60 * 60 * 1000;
const MAX_INTRO_QUEUE_ID_LEN = 256; // defensive cap, matches other opaque-id length checks in this codebase

// Epoch-bucketed RateGateDO stub, matching index.ts's own `rateGateStub` exactly (same formula —
// not required to be byte-identical across files since key prefixes never collide, but keeping the
// epoch definition consistent means "resets every epoch" means the same thing everywhere).
function rateGateStub(env: Env): DurableObjectStub {
  const epoch = Math.floor(Date.now() / 1000 / 3600);
  return env.RATE_GATE_DO.get(env.RATE_GATE_DO.idFromName(`epoch:${epoch}`));
}

/** K8: the single global KeyTransparencyDO instance, same "global" convention as this DO itself. */
function keyTransparencyStub(env: Env): DurableObjectStub {
  return env.KEY_TRANSPARENCY_DO.get(env.KEY_TRANSPARENCY_DO.idFromName("global"));
}

// K8: append one event to the public transparency log. AWAITED, not fire-and-forget (unlike
// MerkleTreeDO's D1 mirror `.catch(...)` pattern this deliberately does NOT copy): D1 there is a
// redundant COPY of state that's already authoritative in the DO itself, so a mirror failure only
// costs durability-in-depth. Here, if the log silently fell behind AliasDO's live table, the two
// would DISAGREE — exactly the equivocation gap K8 exists to make detectable, so it isn't optional.
// Still doesn't hard-fail the parent register/revoke on a log outage (logged loudly instead): a
// transparency-log subsystem being briefly down shouldn't block real alias operations, which don't
// depend on it for their OWN correctness. See this file's header comment for the honest scope note.
async function appendToTransparencyLog(env: Env, lookupKey: string, aliasPub: string, event: "register" | "revoke"): Promise<void> {
  try {
    const res = await keyTransparencyStub(env).fetch(
      new Request("https://do/append", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lookup_key: lookupKey, alias_pub: aliasPub, event }),
      }),
    );
    if (!res.ok) console.error(`[AliasDO] Key Transparency log append failed (${event}): HTTP ${res.status}`);
  } catch (err) {
    console.error(`[AliasDO] Key Transparency log append failed (${event}):`, err);
  }
}

// Required by `SqlStorage.exec<T extends Record<string, SqlStorageValue>>`.
interface AliasRow {
  record: ArrayBuffer;
  [key: string]: SqlStorageValue;
}
interface AliasPubRow {
  alias_pub: string;
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
        alias_pub  TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pow_stamps (
        stamp      TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pow_stamps_expires_at ON pow_stamps(expires_at);
      CREATE TABLE IF NOT EXISTS reserved_namespaces (
        lookup_key  TEXT PRIMARY KEY,
        reserved_at INTEGER NOT NULL
      );
    `);
    // R18 migration for DOs created before `alias_pub` existed: `CREATE TABLE IF NOT EXISTS` above
    // is a no-op against an already-existing table, so a pre-R18 instance needs the column added in
    // place. SQLite has no `ADD COLUMN IF NOT EXISTS`, so this is guarded by a try/catch — succeeds
    // once (adds the column, empty-string default for pre-existing rows, meaning those rows simply
    // can't be revoked until re-registered), then fails harmlessly with "duplicate column name" on
    // every subsequent DO wake-up.
    try {
      this.ctx.storage.sql.exec(`ALTER TABLE aliases ADD COLUMN alias_pub TEXT NOT NULL DEFAULT ''`);
    } catch {
      // column already exists — expected on every wake-up after the first
    }
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/register") {
      return this.handleRegister(request);
    }

    if (request.method === "POST" && url.pathname === "/revoke") {
      return this.handleRevoke(request);
    }

    if (request.method === "POST" && url.pathname === "/reserve") {
      return this.handleReserve(request);
    }

    const resolveMatch = url.pathname.match(/^\/resolve\/([^/]+)$/);
    if (request.method === "GET" && resolveMatch) {
      const rawKey = resolveMatch[1];
      if (rawKey) return this.handleResolve(request, decodeURIComponent(rawKey));
    }

    if (request.method === "POST" && url.pathname === "/introduce") {
      return this.handleIntroduce(request);
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
    const aliasPub = (body as { alias_pub?: unknown }).alias_pub;
    const registrantSigB64 = (body as { registrant_sig?: unknown }).registrant_sig;

    if (typeof lookupKey !== "string" || !LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex SHA-256 digest", { status: 400 });
    }
    if (typeof recordB64 !== "string" || recordB64.length === 0) {
      return new Response("record must be a non-empty base64 string", { status: 400 });
    }
    if (typeof powStamp !== "string") {
      return new Response("pow_stamp must be a string", { status: 400 });
    }
    // R18: plaintext ownership key, stored alongside the (still-opaque-to-this-DO) record — see the
    // header comment above for why this doesn't weaken the nickname-isolation property.
    if (typeof aliasPub !== "string" || !ALIAS_PUB_RE.test(aliasPub)) {
      return new Response("alias_pub must be a 64-char lowercase hex (32-byte) Ed25519 public key", { status: 400 });
    }

    // R18 (2026-07, "reserved/verified namespaces" pass): a reserved lookup_key additionally
    // requires a `registrant_sig` binding an authority approval to THIS specific alias_pub — checked
    // BEFORE the (more expensive) PoW verification below, cheap-check-first, same discipline as
    // every other gate in this codebase. Ordinary (non-reserved) names are completely unaffected —
    // this `SELECT` is the only new cost on that path, one indexed lookup.
    const reserved = this.ctx.storage.sql
      .exec<{ lookup_key: string; [key: string]: SqlStorageValue }>(
        "SELECT lookup_key FROM reserved_namespaces WHERE lookup_key = ?",
        lookupKey,
      )
      .toArray();
    if (reserved.length > 0) {
      if (typeof registrantSigB64 !== "string" || registrantSigB64.length === 0) {
        return new Response("this namespace is reserved: registrant_sig is required", { status: 403 });
      }
      let registrantSig: Uint8Array;
      try {
        registrantSig = new Uint8Array(base64ToBuf(registrantSigB64));
        if (registrantSig.byteLength !== 64) throw new Error("wrong length");
      } catch {
        return new Response("registrant_sig must be a valid base64-encoded 64-byte Ed25519 signature", { status: 400 });
      }
      const message = registrantMessage(hexToBytes(lookupKey), hexToBytes(aliasPub));
      const validRegistrant = verifyAgainstAnyAuthorityKey(message, registrantSig);
      console.log(`[Alias] reserved-namespace registrant signature valid -> ${validRegistrant} (lookup_key ${lookupKey.slice(0, 16)}…)`);
      if (!validRegistrant) {
        return new Response("registrant_sig verification failed against every known authority key", { status: 401 });
      }
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

    const stampExpiresAt = stampExpiryFromEpoch(pow.epoch);
    this.ctx.storage.sql.exec(
      "INSERT INTO aliases (lookup_key, record, alias_pub, created_at) VALUES (?, ?, ?, ?)",
      lookupKey,
      record,
      aliasPub,
      Date.now(),
    );
    this.ctx.storage.sql.exec("INSERT INTO pow_stamps (stamp, expires_at) VALUES (?, ?)", powStamp, stampExpiresAt);
    await this.scheduleStampSweepNoLaterThan(stampExpiresAt);

    await appendToTransparencyLog(this.env, lookupKey, aliasPub, "register");
    return new Response(null, { status: 201 });
  }

  // ── revoke (R18: signed ownership) ─────────────────────────────────────────────────────────
  // Frees a nickname so it can be registered again (by anyone, including a different owner) —
  // closes the "no signed update/revoke" gap R18 flagged: before this, a registered alias could
  // NEVER be freed, not even by its own legitimate owner. No PoW required here (unlike register):
  // the signature itself is the scarce proof — it can only be produced by whoever holds the
  // identity secret key `alias_pub` commits to, which is exactly as hard to forge as PoW is cheap
  // to buy, and cheaper for the legitimate owner than re-mining a stamp.

  private async handleRevoke(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }

    const lookupKey = (body as { lookup_key?: unknown }).lookup_key;
    const sigB64 = (body as { sig?: unknown }).sig;

    if (typeof lookupKey !== "string" || !LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex SHA-256 digest", { status: 400 });
    }
    if (typeof sigB64 !== "string" || sigB64.length === 0) {
      return new Response("sig must be a non-empty base64 string", { status: 400 });
    }

    let sig: Uint8Array;
    try {
      sig = new Uint8Array(base64ToBuf(sigB64));
      if (sig.byteLength !== 64) throw new Error("wrong length");
    } catch {
      return new Response("sig must be a valid base64-encoded 64-byte Ed25519 signature", { status: 400 });
    }

    const rows = this.ctx.storage.sql.exec<AliasPubRow>("SELECT alias_pub FROM aliases WHERE lookup_key = ?", lookupKey).toArray();
    const row = rows[0];
    if (!row || row.alias_pub.length === 0) {
      return new Response("alias not found", { status: 404 });
    }

    const message = aliasRevokeMessage(hexToBytes(lookupKey));
    const valid = verifyAliasOwnership(hexToBytes(row.alias_pub), message, sig);
    console.log(`[Alias] revoke signature valid -> ${valid} (lookup_key ${lookupKey.slice(0, 16)}…)`);
    if (!valid) {
      return new Response("signature verification failed", { status: 401 });
    }

    this.ctx.storage.sql.exec("DELETE FROM aliases WHERE lookup_key = ?", lookupKey);
    await appendToTransparencyLog(this.env, lookupKey, row.alias_pub, "revoke");
    return new Response(null, { status: 204 });
  }

  // ── reserve (R18: reserved/verified namespaces) ────────────────────────────────────────────
  // Adds `lookup_key` to the namespace-authority-gated set (see this file's header comment and
  // namespace-authority.mts). Deliberately requires NO PoW and NO pre-existing alias row — a
  // reservation exists to BLOCK ordinary registration ahead of time, so it must be attachable to a
  // name nobody has (or will ever be allowed to) register without the matching authorization. The
  // signature itself is the entire authorization, same "signature as capability" pattern `/revoke`
  // already established — this write path is idempotent (re-reserving an already-reserved name is a
  // harmless no-op, not an error) since two independent reserve calls for the same name are not a
  // conflict of any kind.
  private async handleReserve(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }

    const lookupKey = (body as { lookup_key?: unknown }).lookup_key;
    const reserveSigB64 = (body as { reserve_sig?: unknown }).reserve_sig;

    if (typeof lookupKey !== "string" || !LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex SHA-256 digest", { status: 400 });
    }
    if (typeof reserveSigB64 !== "string" || reserveSigB64.length === 0) {
      return new Response("reserve_sig must be a non-empty base64 string", { status: 400 });
    }

    let reserveSig: Uint8Array;
    try {
      reserveSig = new Uint8Array(base64ToBuf(reserveSigB64));
      if (reserveSig.byteLength !== 64) throw new Error("wrong length");
    } catch {
      return new Response("reserve_sig must be a valid base64-encoded 64-byte Ed25519 signature", { status: 400 });
    }

    const message = reserveMessage(hexToBytes(lookupKey));
    const valid = verifyAgainstAnyAuthorityKey(message, reserveSig);
    console.log(`[Alias] reserve signature valid -> ${valid} (lookup_key ${lookupKey.slice(0, 16)}…)`);
    if (!valid) {
      return new Response("reserve_sig verification failed against every known authority key", { status: 401 });
    }

    this.ctx.storage.sql.exec(
      "INSERT INTO reserved_namespaces (lookup_key, reserved_at) VALUES (?, ?) ON CONFLICT(lookup_key) DO NOTHING",
      lookupKey,
      Date.now(),
    );
    return new Response(null, { status: 204 });
  }

  // ── resolve ─────────────────────────────────────────────────────────────────────────────────

  // R15/R16: `limit` here is deliberately a sentinel that RateGateDO will never actually enforce
  // (this call exists to read back a running COUNT, not to hard-block) — the block-or-allow
  // decision stays entirely in `verifyPowStamp`'s bit-difficulty check below, matching this
  // endpoint's existing "spend real work even on a miss" philosophy rather than introducing a
  // second, differently-shaped rejection path.
  private async adaptiveResolveBits(lookupKey: string): Promise<number> {
    const res = await rateGateStub(this.env).fetch(
      new Request("https://do/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: `resolve:${lookupKey}`, limit: Number.MAX_SAFE_INTEGER }),
      }),
    );
    // RateGateDO unreachable: fail toward the MAX difficulty, not the base — falling back to the
    // cheapest price would make "make RateGateDO unreachable" a perverse incentive for an attacker.
    if (!res.ok) return RESOLVE_MAX_BITS;
    const { count } = (await res.json()) as { count: number };
    const extraSteps = Math.floor((count - 1) / RESOLVE_ADAPTIVE_STEP);
    return Math.min(RESOLVE_BASE_BITS + extraSteps * RESOLVE_ADAPTIVE_BITS_PER_STEP, RESOLVE_MAX_BITS);
  }

  private async handleResolve(request: Request, lookupKey: string): Promise<Response> {
    if (!LOOKUP_KEY_RE.test(lookupKey)) {
      return new Response("lookup_key must be a 64-char lowercase hex SHA-256 digest", { status: 400 });
    }
    const powStamp = request.headers.get("X-PoW-Stamp");
    if (!powStamp) {
      return new Response("missing X-PoW-Stamp header", { status: 400 });
    }

    // R15/R16: bump the per-lookup_key attempt counter FIRST (unconditionally — an under-difficulty
    // probe should still push the bar up, not get a free look at the old price) and derive this
    // attempt's required bits from the resulting count, before spending any real work verifying it.
    const requiredBits = await this.adaptiveResolveBits(lookupKey);

    const pow = await verifyPowStamp(powStamp, lookupKey, requiredBits);
    if (!pow.ok) {
      return new Response(`PoW rejected: ${pow.reason} (required ${requiredBits} bits this epoch for this alias)`, { status: 403 });
    }

    const spent = this.ctx.storage.sql.exec<StampRow>("SELECT stamp FROM pow_stamps WHERE stamp = ?", powStamp).toArray();
    if (spent.length > 0) {
      return new Response("pow_stamp already used (replay)", { status: 409 });
    }

    const rows = this.ctx.storage.sql.exec<AliasRow>("SELECT record FROM aliases WHERE lookup_key = ?", lookupKey).toArray();

    // Spend the stamp regardless of hit/miss: a resolve attempt against a nonexistent alias still
    // cost the caller real work, and leaving a miss unspent would let it be retried for free —
    // exactly the scraping/enumeration cost this mechanism exists to impose (docs/03 §8.3).
    const stampExpiresAt = stampExpiryFromEpoch(pow.epoch);
    this.ctx.storage.sql.exec("INSERT INTO pow_stamps (stamp, expires_at) VALUES (?, ?)", powStamp, stampExpiresAt);
    await this.scheduleStampSweepNoLaterThan(stampExpiresAt);

    const row = rows[0];
    if (!row) {
      return new Response("alias not found", { status: 404 });
    }
    return Response.json({ record: bufToBase64(row.record) });
  }

  // ── introduce (Flow 6: write a sealed contact request into the resolved intro queue) ──────────
  // The DO never decrypts `ciphertext` — it is opaque to this class exactly like a QueueDO
  // message body is opaque to QueueDO itself (same isolation property, one layer removed: this
  // pass adds a PoW-gated FORWARDING step in front of an ordinary push, not a new place that reads
  // plaintext). `introQueueId` arrives in the clear from the caller because the caller only got it
  // by successfully decrypting a `/resolve` record themselves — this DO already can't read that
  // record either, so it was never hiding `intro_queue_id` from a caller who legitimately resolved
  // the alias to begin with.

  private async handleIntroduce(request: Request): Promise<Response> {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400 });
    }

    const introQueueId = (body as { introQueueId?: unknown }).introQueueId;
    const ciphertextB64 = (body as { ciphertext?: unknown }).ciphertext;
    const powStamp = (body as { powStamp?: unknown }).powStamp;
    const sizeBucket = (body as { sizeBucket?: unknown }).sizeBucket;

    if (typeof introQueueId !== "string" || introQueueId.length === 0 || introQueueId.length > MAX_INTRO_QUEUE_ID_LEN) {
      return new Response(`introQueueId must be a non-empty string up to ${MAX_INTRO_QUEUE_ID_LEN} chars`, { status: 400 });
    }
    if (typeof ciphertextB64 !== "string" || ciphertextB64.length === 0) {
      return new Response("ciphertext must be a non-empty base64 string", { status: 400 });
    }
    if (typeof powStamp !== "string") {
      return new Response("powStamp must be a string", { status: 400 });
    }
    if (typeof sizeBucket !== "number" || !Number.isInteger(sizeBucket) || sizeBucket < 0) {
      return new Response("sizeBucket must be a non-negative integer", { status: 400 });
    }

    let ciphertext: ArrayBuffer;
    try {
      ciphertext = base64ToBuf(ciphertextB64);
      if (ciphertext.byteLength === 0) throw new Error("empty");
    } catch {
      return new Response("ciphertext is not valid base64", { status: 400 });
    }

    // Write-class PoW, resource = introQueueId (docs/04 Flow 6: "mint write PoW, resource =
    // intro_queue_id"), NOT the lookup_key — a caller only reaches this point after already
    // resolving the alias, so binding to the queue id (not the alias itself) is what actually
    // stops someone from grinding one stamp and spamming every queue they can enumerate.
    const pow = await verifyPowStamp(powStamp, introQueueId, INTRODUCE_MIN_BITS);
    if (!pow.ok) {
      return new Response(`PoW rejected: ${pow.reason}`, { status: 403 });
    }

    const spent = this.ctx.storage.sql.exec<StampRow>("SELECT stamp FROM pow_stamps WHERE stamp = ?", powStamp).toArray();
    if (spent.length > 0) {
      return new Response("pow_stamp already used (replay)", { status: 409 });
    }

    // Spend the stamp before forwarding — same "no free retry" reasoning `handleResolve` already
    // documents: a downstream QueueDO failure after a genuinely valid PoW is unlucky, not a refund.
    const stampExpiresAt = stampExpiryFromEpoch(pow.epoch);
    this.ctx.storage.sql.exec("INSERT INTO pow_stamps (stamp, expires_at) VALUES (?, ?)", powStamp, stampExpiresAt);
    await this.scheduleStampSweepNoLaterThan(stampExpiresAt);

    const stub = this.env.QUEUE_DO.get(this.env.QUEUE_DO.idFromName(introQueueId));
    const res = await stub.fetch(
      new Request("https://do/push", {
        method: "POST",
        headers: { "X-Ttl-Ms": String(INTRODUCE_TTL_MS), "X-Size-Bucket": String(sizeBucket) },
        body: ciphertext,
      }),
    );
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return new Response(text || `QueueDO push failed (${res.status})`, { status: res.status });
    }

    return new Response(null, { status: 201 });
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
