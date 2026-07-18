import { Router, error } from "itty-router";
import type { IRequest } from "itty-router";
import type { Env } from "./env";
import { corsHeaders, errorResp, jsonResp } from "./response";
import { verifyGroth16 } from "./zk-wasm";
import { verifyBlindSig } from "./blindsig-wasm";
import { CURRENT_ISSUER_PK_PEM } from "./issuer-keys";
import { VK_HEX, hexToBytes, buildPublicInputsBytes, mintCapability, verifyCapability } from "./session";

export { MerkleTreeDO } from "./durable-objects/MerkleTreeDO";
export { QueueDO } from "./durable-objects/QueueDO";
export { GroupDO } from "./durable-objects/GroupDO";
export { ConvLogDO } from "./durable-objects/ConvLogDO";
export { PresenceDO } from "./durable-objects/PresenceDO";
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


// Flow 1 (docs/04): redeem an Enrollment-issued RSABSSA token by inserting the client's Semaphore
// `commitment` into the membership accumulator; return the new Merkle root. Replaces the earlier
// "assumed valid" VOPRF-token placeholder — the redemption token is now REALLY verified: the client
// sends the unblinded `(msg, sig, msgRandomizer)` triple (see packages/vortic-core/src/blind_sig.rs),
// this Worker checks `Verify(pk_issuer, msg, msgRandomizer, sig)` using ONLY the issuer's PUBLIC key
// (issuer-keys.ts) — no secret ever crosses the plane boundary. Only on a valid signature do we
// compute `tokenNull = H(msg)` and hand it to MerkleTreeDO, which enforces the one-spend guard
// (`issuer_token_null`) before inserting the commitment (see MerkleTreeDO.ts's header comment).
router.post("/membership/insert", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  let body: { msg?: unknown; sig?: unknown; msgRandomizer?: unknown; commitment?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  if (typeof body.msg !== "string" || typeof body.sig !== "string" || typeof body.msgRandomizer !== "string") {
    return errorResp("Missing msg, sig, or msgRandomizer (base64) — the RSABSSA redemption token", origin, 400);
  }
  if (typeof body.commitment !== "string" || !HEX64_RE.test(body.commitment)) {
    return errorResp("commitment must be a 64-char lowercase hex (32-byte) value", origin, 400);
  }

  let msgBytes: Uint8Array, sigBytes: Uint8Array, randomizerBytes: Uint8Array;
  try {
    msgBytes = b64ToBytes(body.msg);
    sigBytes = b64ToBytes(body.sig);
    randomizerBytes = b64ToBytes(body.msgRandomizer);
  } catch {
    return errorResp("msg, sig, and msgRandomizer must be valid base64", origin, 400);
  }

  const valid = verifyBlindSig(CURRENT_ISSUER_PK_PEM, msgBytes, randomizerBytes, sigBytes);
  console.log(`[Membership] blindsig_verify -> ${valid} (msg ${msgBytes.length}B, commitment ${body.commitment.slice(0, 16)}…)`);
  if (!valid) return errorResp("Redemption token signature verification failed", origin, 401);

  const tokenNull = await sha256Hex(msgBytes);
  const res = await merkleStub(env).fetch(
    new Request("https://do/insert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ commitment: body.commitment, tokenNull }),
    }),
  );
  if (res.status === 409) return errorResp("redemption token already spent — cannot insert twice", origin, 409);
  if (!res.ok) return errorResp(`MerkleTreeDO insert failed (${res.status})`, origin, 502);
  const inserted = (await res.json()) as { merkleRoot: string; size: number };
  return jsonResp(inserted, origin);
});

// R23 follow-up (2026-07): a client needs its own Merkle proof (siblings path + leaf index) to build a
// real Semaphore witness for any tree beyond the trivial single-member case. Commitments are PUBLIC BY
// DESIGN in Semaphore (the proof is "I'm one of these known commitments", not "here's a secret list") —
// so, like `/membership/insert`'s root response, this deliberately carries no capability gate: it's
// called BEFORE a session capability can even exist (the client needs this proof to attempt
// /auth/session in the first place). Rate-limited PER COMMITMENT instead (see `rateGateStub` above) —
// this is an O(n) tree rebuild on MerkleTreeDO's side per call, and an unauthenticated caller who
// already knows one commitment (e.g. their own) could otherwise force unlimited rebuilds against it.
router.get("/membership/proof/:commitment", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  const commitment = request.params.commitment;
  if (!commitment || !HEX64_RE.test(commitment)) {
    return errorResp("commitment must be a 64-char lowercase hex (32-byte) value", origin, 400);
  }

  const rateRes = await rateGateStub(env).fetch(
    new Request("https://do/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: `proof:${commitment}`, limit: PROOF_RATE_LIMIT_PER_EPOCH }),
    }),
  );
  if (!rateRes.ok) return errorResp(`Rate check failed (${rateRes.status})`, origin, 502);
  const { allowed, count, limit } = (await rateRes.json()) as { allowed: boolean; count: number; limit: number };
  if (!allowed) {
    console.log(`[Membership] proof rate limit hit for commitment ${commitment.slice(0, 16)}… (${count}/${limit} this epoch)`);
    return errorResp("Too many proof requests for this commitment this epoch — try again next epoch", origin, 429);
  }

  const res = await merkleStub(env).fetch(new Request(`https://do/proof/${commitment}`));
  if (res.status === 404) return errorResp("commitment not found in the membership tree", origin, 404);
  if (!res.ok) return errorResp(`MerkleTreeDO proof lookup failed (${res.status})`, origin, 502);
  const proof = (await res.json()) as { index: number; siblings: string[]; merkleRoot: string };
  return jsonResp(proof, origin);
});

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
router.post("/auth/session", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  let body: { proof?: unknown; merkleRoot?: unknown; nullifier?: unknown; message?: unknown; scope?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  if (typeof body.proof !== "string") return errorResp("Missing proof (base64)", origin, 400);
  for (const [name, value] of Object.entries({
    merkleRoot: body.merkleRoot,
    nullifier: body.nullifier,
    message: body.message,
    scope: body.scope,
  })) {
    if (typeof value !== "string" || !HEX64_RE.test(value)) {
      return errorResp(`${name} must be a 64-char lowercase hex (32-byte) value`, origin, 400);
    }
  }
  const { merkleRoot, nullifier, message, scope } = body as { merkleRoot: string; nullifier: string; message: string; scope: string };

  let proofBytes: Uint8Array;
  try {
    proofBytes = b64ToBytes(body.proof);
  } catch {
    return errorResp("proof is not valid base64", origin, 400);
  }

  // Cheap check first, before the Groth16 pairing work: reject a stale/unrelated root outright.
  const rootRes = await merkleStub(env).fetch(new Request("https://do/root"));
  if (!rootRes.ok) return errorResp(`MerkleTreeDO root fetch failed (${rootRes.status})`, origin, 502);
  const { merkleRoot: currentRoot } = (await rootRes.json()) as { merkleRoot: string };
  if (merkleRoot !== currentRoot) {
    console.log(`[Session] merkleRoot mismatch: claimed ${merkleRoot.slice(0, 16)}… vs current ${currentRoot.slice(0, 16)}…`);
    return errorResp("merkleRoot does not match the current membership tree root", origin, 409);
  }

  let publicInputsBytes: Uint8Array;
  try {
    publicInputsBytes = buildPublicInputsBytes(merkleRoot, nullifier, message, scope);
  } catch (err) {
    return errorResp(`Invalid public inputs: ${(err as Error).message}`, origin, 400);
  }

  const ok = verifyGroth16(hexToBytes(VK_HEX), proofBytes, publicInputsBytes);
  console.log(
    `[Session] zk_verify_groth16_bytes -> ${ok} (proof ${proofBytes.length}B, merkleRoot ${merkleRoot.slice(0, 16)}…, nullifier ${nullifier.slice(0, 16)}…)`,
  );
  if (!ok) return errorResp("ZK proof verification failed", origin, 401);

  // One session per nullifier: spend it in the accumulator (rejects proof replay).
  const spendRes = await merkleStub(env).fetch(
    new Request("https://do/nullifier/spend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nullifier }),
    }),
  );
  if (spendRes.status === 409) {
    return errorResp("nullifier already spent — a session was already issued for this proof", origin, 409);
  }
  if (!spendRes.ok) return errorResp(`nullifier spend failed (${spendRes.status})`, origin, 502);

  const capability = await mintCapability(env.SESSION_SIGNING_KEY, nullifier);
  console.log(`[Session] Capability issued (nullifier ${nullifier.slice(0, 16)}…): ${capability.slice(0, 24)}…`);
  return jsonResp({ capability }, origin);
});

/**
 * Forward a request to a Durable Object stub addressed only by an opaque id — the DO itself never
 * learns anything about the caller beyond that id (see QueueDO.ts / ConvLogDO.ts). `prefix` is the
 * `/<mount>/<id>` segment to strip so the DO sees a path relative to its own root.
 */
function forwardToDO(request: IRequest, ns: DurableObjectNamespace, id: string, prefix: string): Promise<Response> {
  const stub = ns.get(ns.idFromName(id));
  const forwardUrl = new URL(request.url);
  forwardUrl.pathname = forwardUrl.pathname.replace(prefix, "");
  return stub.fetch(new Request(forwardUrl, request as unknown as Request));
}

// Every conversation route below is gated by `requireCapability` — the session capability minted by
// /auth/session (HMAC over nullifier+expiry, verified here with SESSION_SIGNING_KEY). No valid
// capability -> 401 before the DO is ever reached. In production this Worker also sits behind an
// OHTTP relay so it never observes a client IP directly (see docs/03 §10, docs/04 topology).
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
