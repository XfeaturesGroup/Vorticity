import { Router, error } from "itty-router";
import type { IRequest } from "itty-router";
import type { Env } from "./env";
import { corsHeaders, errorResp, jsonResp } from "./response";
import { verifyGroth16 } from "./zk-wasm";
import { verifyBlindSig } from "./blindsig-wasm";
import { CURRENT_ISSUER_PK_PEM } from "./issuer-keys";
import { VK_HEX, PUBLIC_INPUTS_HEX, hexToBytes, mintCapability, verifyCapability } from "./session";

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

// Flow 2 (docs/04): prove membership in zero knowledge -> mint a session capability. The client sends
// a real Groth16 proof (bytes), the merkleRoot it's proving against, and a one-time nullifier. We run
// the REAL verifier in WASM (zk.rs via zk-wasm.ts); on `true`, we spend the nullifier (one session per
// proof) and mint a signed capability. See session.ts for the honest scope note on the fixed vector.
router.post("/auth/session", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  let body: { proof?: unknown; merkleRoot?: unknown; nullifier?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  if (typeof body.proof !== "string") return errorResp("Missing proof (base64)", origin, 400);
  if (typeof body.nullifier !== "string" || !HEX64_RE.test(body.nullifier)) {
    return errorResp("nullifier must be a 64-char lowercase hex (32-byte) value", origin, 400);
  }
  const merkleRoot = typeof body.merkleRoot === "string" ? body.merkleRoot : "n/a";

  let proofBytes: Uint8Array;
  try {
    proofBytes = b64ToBytes(body.proof);
  } catch {
    return errorResp("proof is not valid base64", origin, 400);
  }

  const ok = verifyGroth16(hexToBytes(VK_HEX), proofBytes, hexToBytes(PUBLIC_INPUTS_HEX));
  console.log(
    `[Session] zk_verify_groth16_bytes -> ${ok} (proof ${proofBytes.length}B, merkleRoot ${merkleRoot.slice(0, 16)}…, nullifier ${body.nullifier.slice(0, 16)}…)`,
  );
  if (!ok) return errorResp("ZK proof verification failed", origin, 401);

  // One session per nullifier: spend it in the accumulator (rejects proof replay).
  const spendRes = await merkleStub(env).fetch(
    new Request("https://do/nullifier/spend", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nullifier: body.nullifier }),
    }),
  );
  if (spendRes.status === 409) {
    return errorResp("nullifier already spent — a session was already issued for this proof", origin, 409);
  }
  if (!spendRes.ok) return errorResp(`nullifier spend failed (${spendRes.status})`, origin, 502);

  const capability = await mintCapability(env.SESSION_SIGNING_KEY, body.nullifier);
  console.log(`[Session] Capability issued (nullifier ${body.nullifier.slice(0, 16)}…): ${capability.slice(0, 24)}…`);
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
