import { Router, error } from "itty-router";
import type { IRequest } from "itty-router";
import type { Env } from "./env";
import { corsHeaders, errorResp, jsonResp } from "./response";
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

// /membership/proof/:commitment (below) is necessarily unauthenticated — it's called BEFORE a session
// capability can exist, and MerkleTreeDO rebuilds the whole tree per call (see its header comment's cost
// note), so an unrate-limited caller could force repeated O(n) rebuilds against one commitment. RateGateDO
// is sharded by epoch bucket (docs/04 DO catalog) — one fresh counter set per epoch, so this needs no
// explicit reset/cleanup logic.
const PROOF_RATE_LIMIT_PER_EPOCH = 20;

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
router.all("/alias/*", (request: IRequest, env: Env) => forwardToDO(request, env.ALIAS_DO, "global", "/alias"));

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
