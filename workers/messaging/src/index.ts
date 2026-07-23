import { Router, error } from "itty-router";
import type { IRequest } from "itty-router";
import type { Env } from "./env";
import { corsHeaders, errorResp, jsonResp } from "./response";
import { bufToBase64, base64ToBuf } from "./base64";
import { verifyGroth16 } from "./zk-wasm";
import { verifyBlindSig } from "./blindsig-wasm";
import { CURRENT_ISSUER_PK_PEM } from "./issuer-keys";
import { VK_HEX, hexToBytes, buildPublicInputsBytes, mintCapability, verifyCapability } from "./session";
import { OhttpGateway, MEDIA_TYPE_KEY_CONFIG, MEDIA_TYPE_REQUEST, MEDIA_TYPE_RESPONSE, type BhttpRequest } from "@vorticity/ohttp";

export { MerkleTreeDO } from "./durable-objects/MerkleTreeDO";
export { QueueDO } from "./durable-objects/QueueDO";
export { GroupDO } from "./durable-objects/GroupDO";
export { ConvLogDO } from "./durable-objects/ConvLogDO";
export { PresenceDO } from "./durable-objects/PresenceDO";
export { PrekeyDO } from "./durable-objects/PrekeyDO";
export { DeviceLinkDO } from "./durable-objects/DeviceLinkDO";
export { DeviceLeaseDO } from "./durable-objects/DeviceLeaseDO";
export { AliasDO } from "./durable-objects/AliasDO";
export { RateGateDO } from "./durable-objects/RateGateDO";
export { KeyTransparencyDO } from "./durable-objects/KeyTransparencyDO";

const router = Router();

const HEX64_RE = /^[0-9a-f]{64}$/;

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The single global MerkleTreeDO instance (one accumulator for this pass, like AliasDO). */
function merkleStub(env: Env) {
  return env.MERKLE_TREE_DO.get(env.MERKLE_TREE_DO.idFromName("global"));
}

/** The single global KeyTransparencyDO instance (K8), same "global" convention as AliasDO/MerkleTreeDO. */
function keyTransparencyStub(env: Env) {
  return env.KEY_TRANSPARENCY_DO.get(env.KEY_TRANSPARENCY_DO.idFromName("global"));
}

// /membership/proof/:commitment (below) is necessarily unauthenticated — it's called BEFORE a session
// capability can exist, and MerkleTreeDO rebuilds the whole tree per call (see its header comment's cost
// note), so an unrate-limited caller could force repeated O(n) rebuilds against one commitment. RateGateDO
// is sharded by epoch bucket (docs/04 DO catalog) — one fresh counter set per epoch, so this needs no
// explicit reset/cleanup logic.
const PROOF_RATE_LIMIT_PER_EPOCH = 20;

// /transparency/consistency (below) recomputes MTH(...) from scratch over `second` leaves per call —
// materially more expensive than /transparency/proof/:seq's O(log n) cached-tree path — so it gets
// the same per-target rate-gate treatment as /membership/proof/:commitment above.
const CONSISTENCY_RATE_LIMIT_PER_EPOCH = 20;

// Capability-issuance rate limit (the "still-TODO" case RateGateDO's own header comment
// anticipated — see the "/proof rate limit" pass this reuses). Real gap it closes: today
// `coreAuthSession` below only checks the nullifier-spend table AFTER running the ~0.8s Groth16
// pairing verify (R1), so replaying the exact same (proof, nullifier) pair forces the Worker to
// redo the full expensive pairing check every single time before ever reaching the cheap
// spend-check that would reject it. Keyed per-claimed-nullifier (mirrors `proof:${commitment}`'s
// per-target keying) so one replayed/hammered attempt can't burn unlimited CPU, while distinct
// honest attempts (distinct nullifiers) are unaffected by each other's counters.
const SESSION_RATE_LIMIT_PER_EPOCH = 5;

// R12 cloud-backup pass (2026-07, docs/03 §11): opaque-ID-keyed E2EE state blobs in R2. Rate-gated
// PER BACKUP ID (not per capability — a capability's nullifier is itself real identity residue for
// the SESSION, and keying the limiter by it would let the host build a "how often does this session
// touch backups" profile; the backup ID is already the correct, purpose-built unlinkable key, same
// reasoning as `proof:${commitment}` above). PUT gets a materially lower budget than GET/DELETE: it
// is the only one of the three that costs real R2 storage/write-unit money per call, so it is the
// one worth bounding hardest against a stolen-capability churn/flood attempt; a legitimate client
// backs up on its own schedule (app close, periodic timer), not in a tight loop.
const BACKUP_PUT_RATE_LIMIT_PER_EPOCH = 10;
const BACKUP_GET_RATE_LIMIT_PER_EPOCH = 20;
const BACKUP_DELETE_RATE_LIMIT_PER_EPOCH = 5;
// 8 MiB: generous for "identity keys, ratchet state, message DB" (docs/03 §11) — this is NOT the
// media path (docs/03 §10, separate, still-unbuilt presigned-R2 flow for large files) — enforced
// BEFORE the R2 write, not just documented, so an oversized/malicious body can't buy free storage.
const BACKUP_MAX_BYTES = 8 * 1024 * 1024;

// Phase C media/attachments pass (2026-07): opaque-ID-keyed encrypted blobs in the already-bound
// `MEDIA` R2 bucket (docs/04), same "opaque ID doubles as a capability" reasoning as `backupR2Key`
// above, and the SAME deliberate choice as backup to proxy through the Worker rather than issue a
// presigned-direct-to-R2 URL — docs/03 §10's original sketch earmarked presigned/chunked upload for
// media specifically (unlike backup) because it assumed arbitrary-size file transfer, but this pass
// caps attachments at a bounded size (images/short clips/voice notes, not video/arbitrary files), at
// which point the SAME reasoning `backupR2Key` documents applies just as well: proxying keeps the
// capability + rate-limit gate as the single enforcement point, and — materially, for THIS app —
// going through the Worker means attachment upload/download can be OHTTP-wrapped like every other
// conversation route (R25), whereas a presigned direct-to-R2 PUT would bypass the Relay entirely and
// hand the real client IP straight to R2 at upload/download time, undermining the exact metadata
// protection this pass exists to preserve. True chunked/multipart streaming for large media (docs/03
// §10's original scope) remains future work if/when video or arbitrary-size files are ever supported.
const MEDIA_PUT_RATE_LIMIT_PER_EPOCH = 10;
const MEDIA_GET_RATE_LIMIT_PER_EPOCH = 30;
const MEDIA_MAX_BYTES = 20 * 1024 * 1024;

function rateGateStub(env: Env) {
  const epoch = Math.floor(Date.now() / 1000 / 3600);
  return env.RATE_GATE_DO.get(env.RATE_GATE_DO.idFromName(`epoch:${epoch}`));
}

// R25 (2026-07): the OHTTP Gateway role (RFC 9458 §4) — decapsulates HPKE-sealed requests that
// arrived via a separate Relay Worker (workers/ohttp-relay), which is the ONLY hop that ever sees a
// real client IP; this Worker, reached only through that Relay for the three routes below, sees the
// real request but never the caller's IP. See docs/04's OHTTP Relay topology and docs/06's R25 entry.
// One Gateway keypair per Worker isolate — cached module-level since `deriveKeyPair` does real HPKE
// key-derivation work and the isolate is reused across requests until Cloudflare recycles it.
const OHTTP_KEY_ID = 1;
let ohttpGatewaySingleton: OhttpGateway | null = null;
async function getOhttpGateway(env: Env): Promise<OhttpGateway> {
  if (!ohttpGatewaySingleton) {
    ohttpGatewaySingleton = await OhttpGateway.create(hexToBytes(env.OHTTP_GATEWAY_SEED), OHTTP_KEY_ID);
  }
  return ohttpGatewaySingleton;
}

// The session capability minted by /auth/session gates every conversation route. A browser can't set
// headers on `new WebSocket()`, so the /queue upgrade carries it as a `?cap=` query param; plain HTTP
// routes (/conv, /group) use `Authorization: Bearer <cap>`. Accept either everywhere for uniformity.
function extractCapability(request: IRequest): string | null {
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice("Bearer ".length);
  const cap = new URL(request.url).searchParams.get("cap");
  return cap && cap.length > 0 ? cap : null;
}

// Returns a 401 Response if the request lacks a valid capability, else null (proceed). CORS-aware so
// a rejected browser fetch reads a clean 401 instead of a phantom CORS error.
async function requireCapability(request: IRequest, env: Env): Promise<Response | null> {
  const origin = request.headers.get("Origin");
  const cap = extractCapability(request);
  if (!cap) return errorResp("Missing session capability", origin, 401);
  const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
  if (!verdict.valid) return errorResp(`Invalid session capability: ${verdict.reason}`, origin, 401);
  return null;
}

// Browser-facing airlock endpoints need CORS preflight (the /queue,/conv,/group routes below are
// same-origin/WS internal and don't).
router.options("*", (request: IRequest) => new Response(null, { headers: corsHeaders(request.headers.get("Origin")) }));

router.get("/health", () => Response.json({ ok: true, plane: "messaging" }));


// --- Core handlers below are plain functions over parsed input, NOT `Request`/`Response` — this is
// what lets the SAME logic be reached two ways: directly by the router (thin wrappers just below turn
// the real `Request` into `body`/`params` and the `CoreResult` back into a CORS-aware `Response`), and
// via the OHTTP Gateway dispatch (`handleGatewayRequest` further down), which has no real `Request` at
// all — only a decapsulated `BhttpRequest` it built itself from HPKE-sealed bytes, and no CORS to add
// (an OHTTP round trip through the Relay isn't a browser cross-origin fetch). Duplicating this logic
// per entry point was the alternative; sharing it means the two paths cannot drift apart.
interface CoreResult {
  status: number;
  body: unknown;
}

// Flow 1 (docs/04): redeem an Enrollment-issued RSABSSA token by inserting the client's Semaphore
// `commitment` into the membership accumulator; return the new Merkle root. Replaces the earlier
// "assumed valid" VOPRF-token placeholder — the redemption token is now REALLY verified: the client
// sends the unblinded `(msg, sig, msgRandomizer)` triple (see packages/vortic-core/src/blind_sig.rs),
// this Worker checks `Verify(pk_issuer, msg, msgRandomizer, sig)` using ONLY the issuer's PUBLIC key
// (issuer-keys.ts) — no secret ever crosses the plane boundary. Only on a valid signature do we
// compute `tokenNull = H(msg)` and hand it to MerkleTreeDO, which enforces the one-spend guard
// (`issuer_token_null`) before inserting the commitment (see MerkleTreeDO.ts's header comment).
async function coreMembershipInsert(env: Env, rawBody: unknown): Promise<CoreResult> {
  const body = rawBody as { msg?: unknown; sig?: unknown; msgRandomizer?: unknown; commitment?: unknown };
  if (typeof body.msg !== "string" || typeof body.sig !== "string" || typeof body.msgRandomizer !== "string") {
    return { status: 400, body: { error: "Missing msg, sig, or msgRandomizer (base64) — the RSABSSA redemption token" } };
  }
  if (typeof body.commitment !== "string" || !HEX64_RE.test(body.commitment)) {
    return { status: 400, body: { error: "commitment must be a 64-char lowercase hex (32-byte) value" } };
  }

  let msgBytes: Uint8Array, sigBytes: Uint8Array, randomizerBytes: Uint8Array;
  try {
    msgBytes = b64ToBytes(body.msg);
    sigBytes = b64ToBytes(body.sig);
    randomizerBytes = b64ToBytes(body.msgRandomizer);
  } catch {
    return { status: 400, body: { error: "msg, sig, and msgRandomizer must be valid base64" } };
  }

  const valid = verifyBlindSig(CURRENT_ISSUER_PK_PEM, msgBytes, randomizerBytes, sigBytes);
  console.log(`[Membership] blindsig_verify -> ${valid} (msg ${msgBytes.length}B, commitment ${body.commitment.slice(0, 16)}…)`);
  if (!valid) return { status: 401, body: { error: "Redemption token signature verification failed" } };

  const tokenNull = await sha256Hex(msgBytes);
  const res = await merkleStub(env).fetch(
    new Request("https://do/insert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ commitment: body.commitment, tokenNull }),
    }),
  );
  if (res.status === 409) return { status: 409, body: { error: "redemption token already spent — cannot insert twice" } };
  if (!res.ok) return { status: 502, body: { error: `MerkleTreeDO insert failed (${res.status})` } };
  return { status: 200, body: await res.json() };
}

// R23 follow-up (2026-07): a client needs its own Merkle proof (siblings path + leaf index) to build a
// real Semaphore witness for any tree beyond the trivial single-member case. Commitments are PUBLIC BY
// DESIGN in Semaphore (the proof is "I'm one of these known commitments", not "here's a secret list") —
// so, like `/membership/insert`'s root response, this deliberately carries no capability gate: it's
// called BEFORE a session capability can even exist (the client needs this proof to attempt
// /auth/session in the first place). Rate-limited PER COMMITMENT instead (see `rateGateStub` above) —
// this is an O(n) tree rebuild on MerkleTreeDO's side per call, and an unauthenticated caller who
// already knows one commitment (e.g. their own) could otherwise force unlimited rebuilds against it.
async function coreMembershipProof(env: Env, commitment: string | undefined): Promise<CoreResult> {
  if (!commitment || !HEX64_RE.test(commitment)) {
    return { status: 400, body: { error: "commitment must be a 64-char lowercase hex (32-byte) value" } };
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `proof:${commitment}`, limit: PROOF_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return { status: 502, body: { error: `Rate check failed (${rateRes.status})` } };
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Membership] proof rate limit hit for commitment ${commitment.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return { status: 429, body: { error: "Too many proof requests for this commitment this epoch — try again next epoch" } };
  }

  const res = await merkleStub(env).fetch(new Request(`https://do/proof/${commitment}`));
  if (res.status === 404) return { status: 404, body: { error: "commitment not found in the membership tree" } };
  if (!res.ok) return { status: 502, body: { error: `MerkleTreeDO proof lookup failed (${res.status})` } };
  return { status: 200, body: await res.json() };
}

// Flow 2 (docs/04): prove membership in zero knowledge -> mint a session capability. The client sends
// a REAL Groth16 proof (bytes) for the REAL Semaphore v4 circuit, plus the four values it commits to
// as public inputs: `merkleRoot`, `nullifier`, `message`, `scope` (see session.ts's header comment
// for why this order, and for the R21 "real circuit, test-only trusted setup" scope note). We run the
// REAL verifier in WASM (zk.rs via zk-wasm.ts) against public inputs BUILT FROM the caller's own
// values — no longer a fixed shared vector — and additionally check `merkleRoot` against
// MerkleTreeDO's actual CURRENT root before trusting it: a valid proof alone only proves "some root
// existed for which I have a witness", not that it's the current tree state (a stale replay would
// otherwise still verify). On success we spend the nullifier (one session per proof) and mint a
// signed capability, unchanged from before.
async function coreAuthSession(env: Env, rawBody: unknown): Promise<CoreResult> {
  const body = rawBody as { proof?: unknown; merkleRoot?: unknown; nullifier?: unknown; message?: unknown; scope?: unknown };
  if (typeof body.proof !== "string") return { status: 400, body: { error: "Missing proof (base64)" } };
  for (const [name, value] of Object.entries({
    merkleRoot: body.merkleRoot,
    nullifier: body.nullifier,
    message: body.message,
    scope: body.scope,
  })) {
    if (typeof value !== "string" || !HEX64_RE.test(value)) {
      return { status: 400, body: { error: `${name} must be a 64-char lowercase hex (32-byte) value` } };
    }
  }
  const { merkleRoot, nullifier, message, scope } = body as { merkleRoot: string; nullifier: string; message: string; scope: string };

  let proofBytes: Uint8Array;
  try {
    proofBytes = b64ToBytes(body.proof);
  } catch {
    return { status: 400, body: { error: "proof is not valid base64" } };
  }

  // Cheap check first, before the Groth16 pairing work: reject a stale/unrelated root outright.
  const rootRes = await merkleStub(env).fetch(new Request("https://do/root"));
  if (!rootRes.ok) return { status: 502, body: { error: `MerkleTreeDO root fetch failed (${rootRes.status})` } };
  const { merkleRoot: currentRoot } = (await rootRes.json()) as { merkleRoot: string };
  if (merkleRoot !== currentRoot) {
    console.log(`[Session] merkleRoot mismatch: claimed ${merkleRoot.slice(0, 16)}… vs current ${currentRoot.slice(0, 16)}…`);
    return { status: 409, body: { error: "merkleRoot does not match the current membership tree root" } };
  }

  // Second cheap check, still before the expensive pairing work: cap attempts per claimed
  // nullifier so a replayed/hammered (proof, nullifier) pair can't force unlimited re-verification.
  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `session:${nullifier}`, limit: SESSION_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return { status: 502, body: { error: `Rate check failed (${rateRes.status})` } };
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Session] auth/session rate limit hit for nullifier ${nullifier.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return { status: 429, body: { error: "Too many session attempts for this proof this epoch — try again next epoch" } };
  }

  let publicInputsBytes: Uint8Array;
  try {
    publicInputsBytes = buildPublicInputsBytes(merkleRoot, nullifier, message, scope);
  } catch (err) {
    return { status: 400, body: { error: `Invalid public inputs: ${(err as Error).message}` } };
  }

  const ok = verifyGroth16(hexToBytes(VK_HEX), proofBytes, publicInputsBytes);
  console.log(
    `[Session] zk_verify_groth16_bytes -> ${ok} (proof ${proofBytes.length}B, merkleRoot ${merkleRoot.slice(0, 16)}…, nullifier ${nullifier.slice(0, 16)}…)`,
  );
  if (!ok) return { status: 401, body: { error: "ZK proof verification failed" } };

  // One session per nullifier: spend it in the accumulator (rejects proof replay).
  const spendRes = await merkleStub(env).fetch(
    new Request("https://do/nullifier/spend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nullifier }),
    }),
  );
  if (spendRes.status === 409) {
    return { status: 409, body: { error: "nullifier already spent — a session was already issued for this proof" } };
  }
  if (!spendRes.ok) return { status: 502, body: { error: `nullifier spend failed (${spendRes.status})` } };

  const capability = await mintCapability(env.SESSION_SIGNING_KEY, nullifier);
  console.log(`[Session] Capability issued (nullifier ${nullifier.slice(0, 16)}…): ${capability.slice(0, 24)}…`);
  return { status: 200, body: { capability } };
}

// R12 cloud-backup pass (2026-07, docs/03 §11): "the same ciphertext blob may be stored in R2 keyed
// by an opaque backup ID; the server holds an unreadable blob." The client derives `backupId` from
// its own phrase-derived master key via HKDF (`vortic-core`'s `backup_derive_id`, domain-separated
// from the encryption key itself — see backup.rs's header comment) — this Worker never sees a
// phrase or a key, only a 32-byte value it cannot invert and a base64 AES-256-GCM ciphertext it
// cannot decrypt. Authorization is TWO independent factors, same "belt and suspenders" shape as
// AliasDO's capability+PoW gate: (1) a valid session capability (a real ZK-membership-proven
// session — ties storage cost to a real, Sybil-guarded account, not an anonymous crawler) AND
// (2) knowledge of the 256-bit backup ID itself (which requires the recovery phrase to compute) —
// neither alone is sufficient, and guessing a specific target's ID without their phrase is
// information-theoretically infeasible (2^256 space). Wire format follows this codebase's existing
// base64-in-JSON convention for opaque binary payloads (msg/sig/msgRandomizer, proof) rather than
// raw-bytes bodies, so the direct and OHTTP-dispatched paths below share byte-for-byte identical
// parsing — deliberately NOT the presigned-direct-to-R2 pattern docs/04 describes for the (still
// unbuilt) MEDIA path: that split exists to keep the Worker off the hot path for large files;
// backup blobs (identity/ratchet/message state, capped well below media sizes) don't need it, and
// funneling them through the Worker keeps the capability + rate-limit gate as the single point of
// enforcement instead of a second one at the storage layer.
function backupR2Key(backupId: string): string {
  return `backup/${backupId}`;
}

/** `generation` is a PUBLIC counter (see vortic-core's backup.rs "GENERATION KEYS" doc) — stored as
 * R2 custom metadata, not secret, just "how many times has this backup been rotated." */
function generationFromMetadata(customMetadata: Record<string, string> | undefined): number {
  const raw = customMetadata?.generation;
  const n = raw !== undefined ? Number(raw) : 0;
  return Number.isInteger(n) && n >= 0 ? n : 0;
}

// R12 key-rotation pass (2026-07-23): the generation counter must advance by exactly 1 per write —
// enforced via a REAL atomic compare-and-swap (R2's `onlyIf.etagMatches`), not read-then-write,
// so a malicious/compromised host cannot roll the counter back and replay a stale generation to a
// client that will re-derive that generation's key from nothing but the phrase (see backup.rs).
async function coreBackupPut(env: Env, backupId: string | undefined, rawBody: unknown): Promise<CoreResult> {
  if (!backupId || !HEX64_RE.test(backupId)) {
    return { status: 400, body: { error: "backupId must be a 64-char lowercase hex (32-byte) value" } };
  }
  const body = rawBody as { blob?: unknown; generation?: unknown };
  if (typeof body.blob !== "string") {
    return { status: 400, body: { error: "Missing blob (base64)" } };
  }
  if (typeof body.generation !== "number" || !Number.isInteger(body.generation) || body.generation < 0) {
    return { status: 400, body: { error: "generation must be a non-negative integer" } };
  }
  const generation = body.generation;
  let bytes: ArrayBuffer;
  try {
    bytes = base64ToBuf(body.blob);
  } catch {
    return { status: 400, body: { error: "blob is not valid base64" } };
  }
  if (bytes.byteLength === 0) {
    return { status: 400, body: { error: "blob must not be empty" } };
  }
  if (bytes.byteLength > BACKUP_MAX_BYTES) {
    return { status: 413, body: { error: `blob exceeds the ${BACKUP_MAX_BYTES}-byte backup size cap` } };
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `backup:put:${backupId}`, limit: BACKUP_PUT_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return { status: 502, body: { error: `Rate check failed (${rateRes.status})` } };
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Backup] PUT rate limit hit for ${backupId.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return { status: 429, body: { error: "Too many backup writes for this ID this epoch — try again next epoch" } };
  }

  const key = backupR2Key(backupId);
  const existing = await env.BACKUP.head(key);

  if (existing) {
    const currentGeneration = generationFromMetadata(existing.customMetadata);
    if (generation !== currentGeneration + 1) {
      return {
        status: 409,
        body: { error: `generation must advance by exactly 1 (current ${currentGeneration}, got ${generation})` },
      };
    }
    // Real CAS: `onlyIf.etagMatches` makes R2 itself reject the write (returns null, doesn't throw)
    // if the object changed since the `head()` above — closes the read-then-write race a naive
    // "check then put" would have, which matters here because a lost race would silently let a
    // stale generation number get accepted.
    const result = await env.BACKUP.put(key, bytes, {
      customMetadata: { generation: String(generation) },
      onlyIf: { etagMatches: existing.etag },
    });
    if (result === null) {
      return { status: 409, body: { error: "generation conflict — another write raced this one, refetch and retry" } };
    }
  } else {
    if (generation !== 0) {
      return { status: 409, body: { error: `first backup write must be generation 0, got ${generation}` } };
    }
    // First-ever write for this ID: no prior object/etag to CAS against, so this specific edge case
    // (bootstrap, not the repeated rotation path a real attacker would target) accepts a narrow
    // read-then-write race rather than an unverified "object must not exist" R2 conditional —
    // documented honestly, not silently assumed safe.
    await env.BACKUP.put(key, bytes, { customMetadata: { generation: "0" } });
  }

  console.log(`[Backup] PUT ${backupId.slice(0, 16)}… (${bytes.byteLength}B, generation ${generation})`);
  return { status: 200, body: { ok: true, size: bytes.byteLength, updatedAt: Date.now(), generation } };
}

async function coreBackupGet(env: Env, backupId: string | undefined): Promise<CoreResult> {
  if (!backupId || !HEX64_RE.test(backupId)) {
    return { status: 400, body: { error: "backupId must be a 64-char lowercase hex (32-byte) value" } };
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `backup:get:${backupId}`, limit: BACKUP_GET_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return { status: 502, body: { error: `Rate check failed (${rateRes.status})` } };
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Backup] GET rate limit hit for ${backupId.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return { status: 429, body: { error: "Too many backup reads for this ID this epoch — try again next epoch" } };
  }

  const object = await env.BACKUP.get(backupR2Key(backupId));
  if (!object) return { status: 404, body: { error: "no backup stored for this ID" } };
  const buf = await object.arrayBuffer();
  return {
    status: 200,
    body: {
      blob: bufToBase64(buf),
      size: buf.byteLength,
      updatedAt: object.uploaded.getTime(),
      generation: generationFromMetadata(object.customMetadata),
    },
  };
}

async function coreBackupDelete(env: Env, backupId: string | undefined): Promise<CoreResult> {
  if (!backupId || !HEX64_RE.test(backupId)) {
    return { status: 400, body: { error: "backupId must be a 64-char lowercase hex (32-byte) value" } };
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `backup:delete:${backupId}`, limit: BACKUP_DELETE_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return { status: 502, body: { error: `Rate check failed (${rateRes.status})` } };
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Backup] DELETE rate limit hit for ${backupId.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return { status: 429, body: { error: "Too many backup deletes for this ID this epoch — try again next epoch" } };
  }

  // Idempotent: R2 delete of a missing key is not an error, and returning a uniform 200 either way
  // avoids using the response to oracle whether a given (guessed) backup ID currently has data —
  // the rate limit above already bounds the guessing rate regardless.
  await env.BACKUP.delete(backupR2Key(backupId));
  console.log(`[Backup] DELETE ${backupId.slice(0, 16)}…`);
  return { status: 200, body: { ok: true } };
}

function mediaR2Key(mediaId: string): string {
  return `media/${mediaId}`;
}

// No generation/CAS dance here unlike backup — a mediaId is a freshly generated random 256-bit value
// per attachment, never reused or rotated, so it's write-once by convention. A bare overwrite on a
// repeat PUT (retry after a dropped response, say) is harmless: same id implies same client, and
// R2 objects are content-addressed by this key alone.
async function coreMediaPut(env: Env, mediaId: string | undefined, rawBody: unknown): Promise<CoreResult> {
  if (!mediaId || !HEX64_RE.test(mediaId)) {
    return { status: 400, body: { error: "mediaId must be a 64-char lowercase hex (32-byte) value" } };
  }
  const body = rawBody as { blob?: unknown };
  if (typeof body.blob !== "string") {
    return { status: 400, body: { error: "Missing blob (base64)" } };
  }
  let bytes: ArrayBuffer;
  try {
    bytes = base64ToBuf(body.blob);
  } catch {
    return { status: 400, body: { error: "blob is not valid base64" } };
  }
  if (bytes.byteLength === 0) {
    return { status: 400, body: { error: "blob must not be empty" } };
  }
  if (bytes.byteLength > MEDIA_MAX_BYTES) {
    return { status: 413, body: { error: `blob exceeds the ${MEDIA_MAX_BYTES}-byte media size cap` } };
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `media:put:${mediaId}`, limit: MEDIA_PUT_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return { status: 502, body: { error: `Rate check failed (${rateRes.status})` } };
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Media] PUT rate limit hit for ${mediaId.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return { status: 429, body: { error: "Too many media writes for this ID this epoch — try again next epoch" } };
  }

  await env.MEDIA.put(mediaR2Key(mediaId), bytes);
  console.log(`[Media] PUT ${mediaId.slice(0, 16)}… (${bytes.byteLength}B)`);
  return { status: 200, body: { ok: true, size: bytes.byteLength } };
}

async function coreMediaGet(env: Env, mediaId: string | undefined): Promise<CoreResult> {
  if (!mediaId || !HEX64_RE.test(mediaId)) {
    return { status: 400, body: { error: "mediaId must be a 64-char lowercase hex (32-byte) value" } };
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `media:get:${mediaId}`, limit: MEDIA_GET_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return { status: 502, body: { error: `Rate check failed (${rateRes.status})` } };
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Media] GET rate limit hit for ${mediaId.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return { status: 429, body: { error: "Too many media reads for this ID this epoch — try again next epoch" } };
  }

  const object = await env.MEDIA.get(mediaR2Key(mediaId));
  if (!object) return { status: 404, body: { error: "no media stored for this ID" } };
  const buf = await object.arrayBuffer();
  return { status: 200, body: { blob: bufToBase64(buf), size: buf.byteLength } };
}

router.post("/membership/insert", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  const result = await coreMembershipInsert(env, body);
  return jsonResp(result.body, origin, result.status);
});

router.get("/membership/proof/:commitment", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const result = await coreMembershipProof(env, request.params.commitment);
  return jsonResp(result.body, origin, result.status);
});

// K8: public, unauthenticated read routes for the append-only Key Transparency log — same openness
// reasoning as /membership/proof/:commitment (this is a PUBLIC AUDIT log by design; hiding it behind
// a capability would defeat the point of a transparency log anyone can independently check).
// Writes (`/append`) are internal-only, called by AliasDO on register/revoke, never routed here.
router.get("/transparency/root", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const res = await keyTransparencyStub(env).fetch(new Request("https://do/root"));
  return jsonResp(await res.json(), origin, res.status);
});
router.get("/transparency/latest/:lookupKey", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const res = await keyTransparencyStub(env).fetch(new Request(`https://do/latest/${request.params.lookupKey}`));
  const text = await res.text();
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return jsonResp(parsed, origin, res.status);
});
router.get("/transparency/proof/:seq", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const res = await keyTransparencyStub(env).fetch(new Request(`https://do/proof/${request.params.seq}`));
  const text = await res.text();
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return jsonResp(parsed, origin, res.status);
});
router.get("/transparency/sth", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const res = await keyTransparencyStub(env).fetch(new Request("https://do/sth"));
  return jsonResp(await res.json(), origin, res.status);
});
router.get("/transparency/consistency", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const url = new URL(request.url);
  const first = url.searchParams.get("first") ?? "";
  const second = url.searchParams.get("second") ?? "";
  if (!/^\d+$/.test(first) || !/^\d+$/.test(second)) {
    return errorResp("first and second query params must be positive integers", origin, 400);
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `consistency:${first}:${second}`, limit: CONSISTENCY_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return errorResp(`Rate check failed (${rateRes.status})`, origin, 502);
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Transparency] consistency rate limit hit for (${first},${second}) (${count}/${limit} this epoch)`);
    return errorResp("Too many consistency-proof requests for this (first,second) pair this epoch — try again next epoch", origin, 429);
  }

  const res = await keyTransparencyStub(env).fetch(new Request(`https://do/consistency?first=${first}&second=${second}`));
  const text = await res.text();
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return jsonResp(parsed, origin, res.status);
});

router.post("/auth/session", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  const result = await coreAuthSession(env, body);
  return jsonResp(result.body, origin, result.status);
});

// R12 cloud-backup direct routes — capability-gated like every other post-airlock route (see
// `coreBackupPut`/`Get`/`Delete`'s header comment above for the full two-factor design).
router.put("/backup/:backupId", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  const result = await coreBackupPut(env, request.params.backupId, body);
  return jsonResp(result.body, origin, result.status);
});
router.get("/backup/:backupId", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const result = await coreBackupGet(env, request.params.backupId);
  return jsonResp(result.body, origin, result.status);
});
router.delete("/backup/:backupId", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const result = await coreBackupDelete(env, request.params.backupId);
  return jsonResp(result.body, origin, result.status);
});

// Phase C media direct routes — capability-gated like backup above (see `coreMediaPut`/`Get`'s
// header comment for why this reuses backup's proxy-through-Worker shape rather than a presigned URL).
router.put("/media/:mediaId", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  const result = await coreMediaPut(env, request.params.mediaId, body);
  return jsonResp(result.body, origin, result.status);
});
router.get("/media/:mediaId", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const result = await coreMediaGet(env, request.params.mediaId);
  return jsonResp(result.body, origin, result.status);
});

function parseJsonBody(body: Uint8Array): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(new TextDecoder().decode(body)) };
  } catch {
    return { ok: false };
  }
}

function getBhttpHeader(headers: [string, string][], name: string): string | null {
  const lower = name.toLowerCase();
  for (const [k, v] of headers) if (k.toLowerCase() === lower) return v;
  return null;
}

// R25 follow-up (2026-07, same day): `POST /queue/:id/push` — the real 1:1 message SEND path
// (useQueueTransport.ts's `pushEnvelope`). Flagged in the first R25 pass as "not wired yet" and
// closed here once it became clear this is the highest-FREQUENCY OHTTP-eligible route in the whole
// app (fires per message, not once per session like the other three) — a real priority miss in the
// original pass, not a cosmetic one. `requireCapability`'s direct-route logic (reading `Authorization`
// off a real `IRequest`) doesn't apply here — there is no `IRequest`, only the decapsulated
// `BhttpRequest`'s own header list, so capability verification is re-expressed against that shape
// (same `verifyCapability` call, same HMAC check — not a parallel/weaker auth path).
async function coreQueuePush(env: Env, queueId: string, req: BhttpRequest): Promise<CoreResult> {
  const auth = getBhttpHeader(req.headers, "authorization");
  const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!cap) return { status: 401, body: { error: "Missing session capability" } };
  const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
  if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

  const doHeaders: Record<string, string> = {};
  const ttlMs = getBhttpHeader(req.headers, "x-ttl-ms");
  const sizeBucket = getBhttpHeader(req.headers, "x-size-bucket");
  if (ttlMs !== null) doHeaders["X-Ttl-Ms"] = ttlMs;
  if (sizeBucket !== null) doHeaders["X-Size-Bucket"] = sizeBucket;

  const stub = env.QUEUE_DO.get(env.QUEUE_DO.idFromName(queueId));
  const res = await stub.fetch(new Request("https://do/push", { method: "POST", headers: doHeaders, body: req.body }));
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { status: res.status, body: { error: text || `QueueDO push failed (${res.status})` } };
  }
  return { status: res.status, body: await res.json() };
}

// `GET /queue/:id/pull` — real bug found + fixed (2026-07, "alias contact establishment" pass,
// live-caught via the browser inbox: every poll logged `intro-queue pull failed: HTTP 404`). The
// direct (non-OHTTP) `/queue/:queueId/*` route already forwards ANY method including GET /pull —
// this gap was specific to the OHTTP-wrapped path, which only ever had a `push` case. Real chat
// messages never hit this: the live client receives via WS subscribe, not polling. But
// `apps/web/src/hooks/useAliasInbox.ts` (this same pass) DOES poll its own intro queue on a fixed
// ~15s cadence — exactly the "fires repeatedly, not one-time" shape every other OHTTP-wrapped route
// in this file was already wrapped for, and leaving it unwrapped would let the Messaging Worker
// correlate a real IP with "this device is checking its alias inbox" on every single poll. Same
// capability-check shape as `coreQueuePush` above.
async function coreQueuePull(env: Env, queueId: string, req: BhttpRequest): Promise<CoreResult> {
  const auth = getBhttpHeader(req.headers, "authorization");
  const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!cap) return { status: 401, body: { error: "Missing session capability" } };
  const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
  if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

  const stub = env.QUEUE_DO.get(env.QUEUE_DO.idFromName(queueId));
  const res = await stub.fetch(new Request("https://do/pull", { method: "GET" }));
  const text = await res.text().catch(() => "");
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return { status: res.status, body: parsed };
}

// PrekeyDO (rotation pass, docs/03 §4) — `POST /prekey/:chatId/publish`, `GET /prekey/:chatId/status`,
// `GET /prekey/:chatId/fetch`. Wrapped through OHTTP for the same reason `/queue/:id/push` is: these
// fire on roughly every chat mount / rotation interval, not just once per enrollment, so — like that
// route — a plain unwrapped fetch would leak the real client IP to the Messaging Worker on a call
// that isn't a one-time setup step. Same capability-verification-off-the-BhttpRequest-header-list
// shape as `coreQueuePush` above, not a parallel/weaker auth path.
async function corePrekeyRequest(env: Env, chatId: string, sub: "publish" | "status" | "fetch", req: BhttpRequest): Promise<CoreResult> {
  const auth = getBhttpHeader(req.headers, "authorization");
  const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!cap) return { status: 401, body: { error: "Missing session capability" } };
  const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
  if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

  const stub = env.PREKEY_DO.get(env.PREKEY_DO.idFromName(chatId));
  const method = sub === "publish" ? "POST" : "GET";
  const res = await stub.fetch(
    new Request(`https://do/${sub}`, {
      method,
      headers: method === "POST" ? { "Content-Type": "application/json" } : {},
      body: method === "POST" ? req.body : null,
    }),
  );
  const text = await res.text().catch(() => "");
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return { status: res.status, body: parsed };
}

// DeviceLeaseDO (device-linking pass) — `POST /device-lease/:leaseKey/acquire`, `POST .../release`,
// `GET .../status`, where `leaseKey` is `${chatId}:${role}` (see DeviceLeaseDO.ts's header comment
// for why it's not the bare chat id). Wrapped through OHTTP: this fires on a HEARTBEAT cadence (every
// ~15s per open chat, see useQueueTransport.ts) while a chat is open, so leaving it unwrapped would
// let the Messaging Worker correlate a real IP with "this device has chat X open right now"
// continuously — exactly the class of leak R25/R25-follow-up already prioritized wrapping for.
async function coreDeviceLeaseRequest(env: Env, leaseKey: string, sub: "acquire" | "release" | "status", req: BhttpRequest): Promise<CoreResult> {
  const auth = getBhttpHeader(req.headers, "authorization");
  const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!cap) return { status: 401, body: { error: "Missing session capability" } };
  const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
  if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

  const stub = env.DEVICE_LEASE_DO.get(env.DEVICE_LEASE_DO.idFromName(leaseKey));
  const method = sub === "status" ? "GET" : "POST";
  const res = await stub.fetch(
    new Request(`https://do/${sub}`, {
      method,
      headers: method === "POST" ? { "Content-Type": "application/json" } : {},
      body: method === "POST" ? req.body : null,
    }),
  );
  const text = await res.text().catch(() => "");
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return { status: res.status, body: parsed };
}

// DeviceLinkDO (device-linking pass) — `POST /device-link/:linkId/put`, `GET /device-link/:linkId/take`.
// Wrapped through OHTTP for an even stronger reason than the routes above: this payload is full
// private-key material for a chat, not ordinary message ciphertext — correlating "this real IP put/
// took a device-link blob" is a meaningful metadata leak this route deserves the same protection as
// any other anonymity-zone call. Same shape as `corePrekeyRequest`.
async function coreDeviceLinkRequest(env: Env, linkId: string, sub: "put" | "take", req: BhttpRequest): Promise<CoreResult> {
  const auth = getBhttpHeader(req.headers, "authorization");
  const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!cap) return { status: 401, body: { error: "Missing session capability" } };
  const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
  if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

  const stub = env.DEVICE_LINK_DO.get(env.DEVICE_LINK_DO.idFromName(linkId));
  const method = sub === "put" ? "POST" : "GET";
  const res = await stub.fetch(
    new Request(`https://do/${sub}`, {
      method,
      headers: method === "POST" ? { "Content-Type": "application/json" } : {},
      body: method === "POST" ? req.body : null,
    }),
  );
  const text = await res.text().catch(() => "");
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return { status: res.status, body: parsed };
}

// AliasDO (alias contact establishment pass, 2026-07; `/revoke` added R18, same day style) —
// `POST /alias/register`, `GET /alias/resolve/:lookupKey`, `POST /alias/introduce`,
// `POST /alias/revoke`. Wrapped through OHTTP for the same
// reason `/prekey/*`/`/device-link/*` are: a register/resolve/introduce call reveals "this real IP
// is claiming/looking up/contacting @nickname" — exactly the metadata docs/03 §8's privacy model
// (nickname discoverable, identity linkage never) exists to protect, so leaving these unwrapped
// would leak a real-IP<->nickname correlation the rest of the alias design goes out of its way to
// avoid. `subpath` is the AliasDO-relative path (`register`, `resolve/<key>`, or `introduce`);
// `method` is threaded through since resolve is a GET (with `X-PoW-Stamp` as a header, no body)
// while register/introduce are POST (JSON body).
async function coreAliasRequest(env: Env, subpath: string, method: "GET" | "POST", req: BhttpRequest): Promise<CoreResult> {
  const auth = getBhttpHeader(req.headers, "authorization");
  const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!cap) return { status: 401, body: { error: "Missing session capability" } };
  const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
  if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

  const stub = env.ALIAS_DO.get(env.ALIAS_DO.idFromName("global"));
  const headers: Record<string, string> = {};
  if (method === "POST") headers["Content-Type"] = "application/json";
  const powStamp = getBhttpHeader(req.headers, "x-pow-stamp");
  if (powStamp !== null) headers["X-PoW-Stamp"] = powStamp;

  const res = await stub.fetch(
    new Request(`https://do/${subpath}`, { method, headers, body: method === "POST" ? req.body : null }),
  );
  const text = await res.text().catch(() => "");
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  return { status: res.status, body: parsed };
}

// Dispatches a DECAPSULATED request (a `BhttpRequest` the Gateway itself constructed from HPKE-sealed
// bytes — never a real Cloudflare `Request`, so there is no `cf-connecting-ip`/`CF-Connecting-IP`
// header or any other IP-bearing field for these handlers to even reach for) to the SAME core logic
// the direct routes above use. See docs/06's R25 entry for which routes are NOT reachable here
// (WebSocket upgrades can't be tunneled through a single-shot request/response scheme like OHTTP at
// all — that's a structural limit, not a scope choice).
async function dispatchBhttpRequest(env: Env, req: BhttpRequest): Promise<CoreResult> {
  const proofMatch = /^\/membership\/proof\/([0-9a-f]{64})$/.exec(req.path);
  if (req.method === "GET" && proofMatch) {
    return coreMembershipProof(env, proofMatch[1]);
  }
  if (req.method === "POST" && req.path === "/membership/insert") {
    const parsed = parseJsonBody(req.body);
    if (!parsed.ok) return { status: 400, body: { error: "Invalid JSON body" } };
    return coreMembershipInsert(env, parsed.value);
  }
  if (req.method === "POST" && req.path === "/auth/session") {
    const parsed = parseJsonBody(req.body);
    if (!parsed.ok) return { status: 400, body: { error: "Invalid JSON body" } };
    return coreAuthSession(env, parsed.value);
  }
  const queuePushMatch = /^\/queue\/([^/]+)\/push$/.exec(req.path);
  if (req.method === "POST" && queuePushMatch) {
    return coreQueuePush(env, decodeURIComponent(queuePushMatch[1]!), req);
  }
  const queuePullMatch = /^\/queue\/([^/]+)\/pull$/.exec(req.path);
  if (req.method === "GET" && queuePullMatch) {
    return coreQueuePull(env, decodeURIComponent(queuePullMatch[1]!), req);
  }
  const prekeyMatch = /^\/prekey\/([^/]+)\/(publish|status|fetch)$/.exec(req.path);
  if (prekeyMatch) {
    const sub = prekeyMatch[2] as "publish" | "status" | "fetch";
    const expectedMethod = sub === "publish" ? "POST" : "GET";
    if (req.method === expectedMethod) {
      return corePrekeyRequest(env, decodeURIComponent(prekeyMatch[1]!), sub, req);
    }
  }
  const deviceLinkMatch = /^\/device-link\/([^/]+)\/(put|take)$/.exec(req.path);
  if (deviceLinkMatch) {
    const sub = deviceLinkMatch[2] as "put" | "take";
    const expectedMethod = sub === "put" ? "POST" : "GET";
    if (req.method === expectedMethod) {
      return coreDeviceLinkRequest(env, decodeURIComponent(deviceLinkMatch[1]!), sub, req);
    }
  }
  const deviceLeaseMatch = /^\/device-lease\/([^/]+)\/(acquire|release|status)$/.exec(req.path);
  if (deviceLeaseMatch) {
    const sub = deviceLeaseMatch[2] as "acquire" | "release" | "status";
    const expectedMethod = sub === "status" ? "GET" : "POST";
    if (req.method === expectedMethod) {
      return coreDeviceLeaseRequest(env, decodeURIComponent(deviceLeaseMatch[1]!), sub, req);
    }
  }
  if (req.method === "POST" && req.path === "/alias/register") {
    return coreAliasRequest(env, "register", "POST", req);
  }
  const aliasResolveMatch = /^\/alias\/resolve\/([^/]+)$/.exec(req.path);
  if (req.method === "GET" && aliasResolveMatch) {
    return coreAliasRequest(env, `resolve/${aliasResolveMatch[1]}`, "GET", req);
  }
  if (req.method === "POST" && req.path === "/alias/introduce") {
    return coreAliasRequest(env, "introduce", "POST", req);
  }
  if (req.method === "POST" && req.path === "/alias/revoke") {
    return coreAliasRequest(env, "revoke", "POST", req);
  }
  if (req.method === "POST" && req.path === "/alias/reserve") {
    return coreAliasRequest(env, "reserve", "POST", req);
  }
  // R12 cloud-backup OHTTP-wrapped path: "this real IP is uploading/fetching/deleting THIS backup
  // ID" is at least as sensitive as the alias-route metadata wrapped above (arguably more —
  // repeated GETs of the same ID directly fingerprint a returning device across sessions), so it
  // gets the same treatment. Capability check re-expressed against the BhttpRequest header list,
  // same shape (and same underlying `verifyCapability` call) as every other wrapped route above.
  const backupMatch = /^\/backup\/([0-9a-f]{64})$/.exec(req.path);
  if (backupMatch && (req.method === "PUT" || req.method === "GET" || req.method === "DELETE")) {
    const auth = getBhttpHeader(req.headers, "authorization");
    const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
    if (!cap) return { status: 401, body: { error: "Missing session capability" } };
    const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
    if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

    const backupId = backupMatch[1]!;
    if (req.method === "PUT") {
      const parsed = parseJsonBody(req.body);
      if (!parsed.ok) return { status: 400, body: { error: "Invalid JSON body" } };
      return coreBackupPut(env, backupId, parsed.value);
    }
    if (req.method === "GET") return coreBackupGet(env, backupId);
    return coreBackupDelete(env, backupId);
  }
  // Phase C media OHTTP-wrapped path — same capability re-check shape as the backup block above,
  // same rationale (an attachment upload/download's real IP is sensitive metadata too).
  const mediaMatch = /^\/media\/([0-9a-f]{64})$/.exec(req.path);
  if (mediaMatch && (req.method === "PUT" || req.method === "GET")) {
    const auth = getBhttpHeader(req.headers, "authorization");
    const cap = auth?.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
    if (!cap) return { status: 401, body: { error: "Missing session capability" } };
    const verdict = await verifyCapability(env.SESSION_SIGNING_KEY, cap);
    if (!verdict.valid) return { status: 401, body: { error: `Invalid session capability: ${verdict.reason}` } };

    const mediaId = mediaMatch[1]!;
    if (req.method === "PUT") {
      const parsed = parseJsonBody(req.body);
      if (!parsed.ok) return { status: 400, body: { error: "Invalid JSON body" } };
      return coreMediaPut(env, mediaId, parsed.value);
    }
    return coreMediaGet(env, mediaId);
  }
  return { status: 404, body: { error: "Not found (via OHTTP gateway)" } };
}

// RFC 9458 §3.2: publish the Gateway's Key Config so a Client can encapsulate against it. Public and
// unauthenticated by necessity — a Client needs this before it has any capability, same openness
// rationale as `/membership/proof/:commitment` above.
router.get("/ohttp/keys", async (_request: IRequest, env: Env) => {
  const gateway = await getOhttpGateway(env);
  return new Response(gateway.keyConfigBytes(), { headers: { "Content-Type": MEDIA_TYPE_KEY_CONFIG } });
});

// RFC 9458 §4: the Gateway endpoint itself. Reached only via workers/ohttp-relay in production — this
// Worker never needs to (and structurally cannot, from the decapsulated `BhttpRequest` shape alone)
// recover the original caller's IP from a request that arrives here.
router.post("/ohttp/gateway", async (request: IRequest, env: Env) => {
  const contentType = request.headers.get("Content-Type");
  if (contentType !== MEDIA_TYPE_REQUEST) {
    return new Response(`Content-Type must be ${MEDIA_TYPE_REQUEST}`, { status: 400 });
  }
  const gateway = await getOhttpGateway(env);
  const encapsulatedRequest = new Uint8Array(await request.arrayBuffer());

  let decapsulated: Awaited<ReturnType<OhttpGateway["decapsulateRequest"]>>;
  try {
    decapsulated = await gateway.decapsulateRequest(encapsulatedRequest);
  } catch (err) {
    console.warn("[OHTTP] decapsulation failed:", (err as Error).message);
    return new Response("Bad encapsulated request", { status: 400 });
  }

  const result = await dispatchBhttpRequest(env, decapsulated.request);
  const encapsulatedResponse = await decapsulated.encapsulateResponse({
    status: result.status,
    headers: [["content-type", "application/json"]],
    body: new TextEncoder().encode(JSON.stringify(result.body)),
  });
  return new Response(encapsulatedResponse, { headers: { "Content-Type": MEDIA_TYPE_RESPONSE } });
});

/**
 * Forward a request to a Durable Object stub addressed only by an opaque id — the DO itself never
 * learns anything about the caller beyond that id (see QueueDO.ts / ConvLogDO.ts). `prefix` is the
 * `/<mount>/<id>` segment to strip so the DO sees a path relative to its own root.
 */
// Real bug found + fixed 2026-07-19 (first genuine two-person live test): `id` here is itty-router's
// raw path param — confirmed via its own source (`IttyRouter.mjs`: params come straight from a regex
// match against `URL.pathname`, no decoding step) — which means it's still percent-encoded exactly as
// the client sent it. `coreQueuePush` and the rest of the OHTTP dispatch path (`dispatchBhttpRequest`
// above) already `decodeURIComponent` their own path captures. Every real queue name in this app is
// shaped `${chatId}:AtoB` / `${chatId}:BtoA` — the client always percent-encodes the `:` — so the
// direct WS-subscribe route (this function) and the OHTTP-wrapped push route were silently addressing
// TWO DIFFERENT Durable Object instances for the exact same logical queue: a push landed in the DO
// keyed by the decoded name, a WS subscribe attached to the DO keyed by the still-encoded name. Live
// messages were never lost or misdelivered — they were durably stored in a DO nothing was ever
// listening on. Fixed by decoding here too, so both paths derive the identical DO identity.
function forwardToDO(request: IRequest, ns: DurableObjectNamespace, id: string, prefix: string): Promise<Response> {
  const stub = ns.get(ns.idFromName(decodeURIComponent(id)));
  const forwardUrl = new URL(request.url);
  forwardUrl.pathname = forwardUrl.pathname.replace(prefix, "");
  return stub.fetch(new Request(forwardUrl, request as unknown as Request));
}

// Every conversation route below is gated by `requireCapability` — the session capability minted by
// /auth/session (HMAC over nullifier+expiry, verified here with SESSION_SIGNING_KEY). No valid
// capability -> 401 before the DO is ever reached.
//
// R25 (2026-07) honest scope note: the OHTTP Gateway (`/ohttp/keys`, `/ohttp/gateway` above) wraps
// four plain request/response routes — the three docs/04's Flow 1/2 diagrams draw through the Relay
// (/membership/insert, /membership/proof/:commitment, /auth/session) PLUS `/queue/:id/push` (the
// real message SEND path, wired in a same-day follow-up once it was pointed out that this is the
// HIGHEST-frequency OHTTP-eligible route in the app — fires per message, not once per session; see
// `coreQueuePush` above and docs/06's R25 entry). NOT wrapped, and structurally CANNOT be: WebSocket
// upgrades (`/queue/:id` subscribe, `/conv/:id`) — OHTTP is a single-shot HPKE-per-request/response
// scheme (RFC 9458), fundamentally incompatible with a persistent connection. A client's WS
// connection to RECEIVE messages is still made directly, so its IP is visible to Cloudflare's edge
// for that connection's lifetime — a real, documented residual gap (see docs/06's R25 entry), not
// silently claimed as covered.
//
// Mounted as `/queue/:queueId/*` (not `/q/...`) because apps/web's `useChatWebSocket.ts` hits this
// Worker directly (no `/ws` prefix) when running against a local `wrangler dev` instance — that
// prefix only exists in production's edge routing in front of `api.vort.xfeatures.net`, which maps
// its public `/ws/queue/*` path down to this Worker's `/queue/*`.
router.all("/queue/:queueId/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const queueId = request.params.queueId;
  if (!queueId) return error(400, "missing queueId");
  return forwardToDO(request, env.QUEUE_DO, queueId, `/queue/${queueId}`);
});

router.all("/conv/:convId/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const convId = request.params.convId;
  if (!convId) return error(400, "missing convId");
  return forwardToDO(request, env.CONV_LOG_DO, convId, `/conv/${convId}`);
});

router.all("/group/:groupId/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const groupId = request.params.groupId;
  if (!groupId) return error(400, "missing groupId");
  return forwardToDO(request, env.GROUP_DO, groupId, `/group/${groupId}`);
});

// PresenceDO (docs/04 DO catalog: "contact-scoped") — one instance per chat id, same capability gate
// as /queue and /conv. Unlike those, this route is WS-only (PresenceDO.fetch rejects anything that
// isn't an Upgrade); there is no push/pull HTTP surface to forward, but `forwardToDO`'s generic
// "strip the mount prefix, hand the rest to the DO" shape still applies unchanged.
router.all("/presence/:chatId/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const chatId = request.params.chatId;
  if (!chatId) return error(400, "missing chatId");
  return forwardToDO(request, env.PRESENCE_DO, chatId, `/presence/${chatId}`);
});

// PrekeyDO (rotation pass, docs/03 §4) — direct plain-HTTP path, same capability gate as /queue and
// /conv, coexisting with the OHTTP-wrapped path above (`corePrekeyRequest`/`dispatchBhttpRequest`)
// exactly the way `/queue/:queueId/push` has both a direct and an OHTTP-wrapped path — the client
// (useQueueTransport.ts) always goes through OHTTP for these in practice, but this direct route stays
// available the same way it does for every other conversation route, not removed just because a
// wrapped alternative exists.
router.all("/prekey/:chatId/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const chatId = request.params.chatId;
  if (!chatId) return error(400, "missing chatId");
  return forwardToDO(request, env.PREKEY_DO, chatId, `/prekey/${chatId}`);
});

// DeviceLinkDO (device-linking pass) — sharded by the linking channel id (derived client-side from a
// random secret, never sent to the server in the clear — see lib/deviceLink.ts). Capability-gated
// like every other conversation route: BOTH devices must already hold their own real session
// capability (see DeviceLinkDO.ts's header comment for why this doesn't bypass account auth).
router.all("/device-link/:linkId/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const linkId = request.params.linkId;
  if (!linkId) return error(400, "missing linkId");
  return forwardToDO(request, env.DEVICE_LINK_DO, linkId, `/device-link/${linkId}`);
});

// DeviceLeaseDO (device-linking pass) — sharded by `${chatId}:${role}`, NOT the bare chat id (real
// bug, see DeviceLeaseDO.ts's header comment: a chat id alone is shared by both parties of an
// ordinary 1:1 conversation, which made them race for the same lease). This route treats the segment
// as an opaque key either way — the client is what constructs it correctly (lib/deviceLease.ts).
// Capability-gated like every other conversation route.
router.all("/device-lease/:leaseKey/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  const leaseKey = request.params.leaseKey;
  if (!leaseKey) return error(400, "missing leaseKey");
  return forwardToDO(request, env.DEVICE_LEASE_DO, leaseKey, `/device-lease/${leaseKey}`);
});

// Unlike /q, /conv, /group (sharded per queue/conversation/group id), AliasDO is a single global
// instance for this pass — the namespace isn't large enough yet to need docs/04's documented
// H(nickname)-prefix sharding. Revisit if/when alias volume warrants splitting it.
//
// Real bug found + fixed (2026-07, "alias contact establishment" pass): this route forwarded to
// AliasDO with NO `requireCapability` check at all — every other conversation route in this file
// gates on it, and docs/03 §8.1 itself lists "a capability gate" as one of the accepted mitigations
// for the alias plane's low-entropy-nickname residual risk (§8.1: an attacker still needs "one
// enrolled account per actor" per §8.3's own economics argument — which was silently false as long
// as this route had no capability check at all). Fixed to match every other route below.
router.all("/alias/*", async (request: IRequest, env: Env) => {
  const denied = await requireCapability(request, env);
  if (denied) return denied;
  return forwardToDO(request, env.ALIAS_DO, "global", "/alias");
});

router.all("*", () => error(404, "Not found"));

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext): Promise<Response> => {
    try {
      return await router.fetch(request, env, ctx);
    } catch (err) {
      // Same lesson as workers/enrollment: any exception on a browser-facing route (/membership,
      // /auth) must still carry CORS headers, or the browser reports it as a misleading CORS block.
      console.error("Unhandled error in messaging Worker:", err);
      return errorResp(`Internal error: ${(err as Error).message}`, request.headers.get("Origin"), 500);
    }
  },
};
