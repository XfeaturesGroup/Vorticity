import { Router } from "itty-router";
import type { IRequest } from "itty-router";
import type { Env } from "./env";
import { corsHeaders, errorResp, jsonResp } from "./response";
import { computePpid } from "./ppid";
import { exchangeCodeForUserInfo } from "./oauth";
import { blindSign } from "./blindsig-wasm";
import { mintEnrollTicket, verifyEnrollTicket } from "./ticket";

const router = Router();

// R11 (docs/06): bounds how many redemption tickets ONE real Xfeatures account can ever be issued.
// enroll_count now increments 1:1 with ticket issuance (see /oauth/callback below), so this is a
// genuine lifetime cap on anonymous personas per account, not just a login counter. Deliberately
// generous (covers many devices/reinstalls over a long lifetime) — the point is bounding a
// botnet-driven flood through one compromised/rented OAuth account to double digits, not limiting
// ordinary multi-device use. A placeholder judgment call, not derived from usage data; revisit once
// real traffic patterns exist.
const ENROLL_QUOTA_MAX = 20;

// --- base64 <-> bytes for the RSABSSA wire (blinded message in, blind signature out) ---
function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

router.options("*", (request: IRequest) => new Response(null, { headers: corsHeaders(request.headers.get("Origin")) }));

router.get("/health", (request: IRequest) => jsonResp({ ok: true, plane: "enrollment" }, request.headers.get("Origin")));

// Real bug found via live testing (2026-07): this Worker used to hardcode `env.OAUTH_REDIRECT_URI`
// (the prod value) as the `redirect_uri` sent to the IDM's token endpoint, regardless of what the
// client actually used at its own /authorize redirect. Per RFC 6749 §4.1.3 the token endpoint must
// see the EXACT SAME redirect_uri used during authorization, or it rejects with `invalid_grant` —
// which is exactly what happened testing locally (`apps/web` sends `http://localhost:5173/
// auth/callback` to /authorize, but this Worker was sending `https://id.vort.xfeatures.net/
// oauth/callback` to the token endpoint — a guaranteed mismatch, nothing to do with OAuth scopes).
// Fix: the client now sends the redirect_uri it actually used in the request body, and this Worker
// validates it against a fixed allow-list before forwarding it to the IDM — never reflects an
// arbitrary caller-supplied value, same pattern as `corsHeaders`' origin allow-list.
function allowedRedirectUris(env: Env): string[] {
  return [env.OAUTH_REDIRECT_URI, "http://localhost:5173/auth/callback"];
}

// Step 1 of docs/04 Flow 1: OAuth2+PKCE -> real identity known here, transiently, in-memory only.
// Nothing but a PPID counter is ever written to DB_ENROLL.
router.post("/oauth/callback", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  let body: { code?: string; code_verifier?: string; redirect_uri?: string };
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  if (!body.code || !body.code_verifier || !body.redirect_uri) {
    return errorResp("Missing code, code_verifier, or redirect_uri", origin, 400);
  }
  if (!allowedRedirectUris(env).includes(body.redirect_uri)) {
    return errorResp("redirect_uri not allowed", origin, 400);
  }

  let userInfo;
  try {
    userInfo = await exchangeCodeForUserInfo(env, body.code, body.code_verifier, body.redirect_uri);
  } catch (err) {
    return errorResp(`IDM error: ${(err as Error).message}`, origin, 502);
  }

  if (!userInfo.email_verified) {
    return errorResp("Email must be verified with Xfeatures Account to enroll", origin, 403);
  }

  const ppid = await computePpid(userInfo.sub, env.PPID_HMAC_SECRET);
  const epoch = Math.floor(Date.now() / 1000 / 3600);

  // Sybil guard + quota (R11) — see docs/03 §2. `enroll_count` is a lifetime counter of tickets
  // issued to this ppid (incremented exactly once per ticket minted below); reject BEFORE the
  // upsert once the quota is hit, so a capped account can't keep bumping the counter forever.
  const existing = await env.DB_ENROLL.prepare("SELECT enroll_count FROM enroll_ppid WHERE ppid = ?")
    .bind(ppid)
    .first<{ enroll_count: number }>();

  if (existing && existing.enroll_count >= ENROLL_QUOTA_MAX) {
    return errorResp("Enrollment quota exceeded for this account", origin, 403);
  }

  // This upsert + the ticket mint below are the ONLY writes/effects this whole request makes.
  if (existing) {
    await env.DB_ENROLL.prepare("UPDATE enroll_ppid SET enroll_count = enroll_count + 1, last_epoch = ? WHERE ppid = ?")
      .bind(epoch, ppid)
      .run();
  } else {
    await env.DB_ENROLL.prepare(
      "INSERT INTO enroll_ppid (ppid, enroll_count, last_epoch, created_at) VALUES (?, 1, ?, ?)",
    )
      .bind(ppid, epoch, Math.floor(Date.now() / 1000))
      .run();
  }

  // Real bug found+fixed 2026-07-23: /token/issue used to accept ANY caller-supplied blinded
  // message with zero proof this OAuth exchange ever happened — an unauthenticated blind-signing
  // oracle that let anyone mint unlimited anonymous membership tokens, defeating R11/G8 entirely.
  // Mint a short-lived, single-use ticket bound to nothing but "this ppid passed the quota check
  // just now" (see ticket.ts) — /token/issue below requires and spends it.
  const ticket = await mintEnrollTicket(env.ENROLL_TICKET_SIGNING_KEY, ppid);
  return jsonResp({ enrolled: true, ticket }, origin);
});

// Step 2 of docs/04 Flow 1: the RSABSSA Plane Bridge (RFC 9474). Replaces the earlier VOPRF-based
// `/oprf/issue` — see packages/vortic-core/src/blind_sig.rs's module doc for exactly why: a VOPRF
// evaluation cannot be verified by a third party (Messaging) without either the OPRF secret `k` or
// some equivalent shared secret between the planes, which would violate the hard invariant that
// Messaging may know only a PUBLIC key about Enrollment. An RSA blind signature is a real signature,
// third-party-verifiable with nothing but the issuer's public key.
//
// The client blinds a random message client-side (`blindsig_blind`) and posts the blinded bytes
// here. This Worker signs them under `env.ISSUER_SIGNING_KEY_PEM` (the RSA-3072 secret key) via
// `blind_sig.rs`'s real RFC 9474 blind-sign operation, run through the `issuer-full` WASM build
// (see blindsig-wasm.ts — a DIFFERENT binary than the one workers/messaging loads, which cannot even
// compile this operation in). This endpoint deliberately does NOT re-run the sybil guard: that
// already happened in `/oauth/callback`'s `enroll_ppid` upsert above, in the same enrollment session
// — duplicating it here would be redundant, not additional safety (see docs/04 Flow 1). The Worker
// never sees the unblinded message; the client finalizes the signature locally (`blindsig_finalize`)
// into a `(msg, sig, msgRandomizer)` redemption token that Messaging can verify with nothing but the
// PUBLIC key (workers/messaging/src/issuer-keys.ts) — that token is what `/membership/insert` redeems.
router.post("/token/issue", async (request: IRequest, env: Env) => {
  const origin = request.headers.get("Origin");
  let body: { blinded?: string; ticket?: string };
  try {
    body = await request.json();
  } catch {
    return errorResp("Invalid JSON body", origin, 400);
  }
  if (!body.blinded) {
    return errorResp("Missing blinded message", origin, 400);
  }
  if (!body.ticket) {
    return errorResp("Missing enrollment ticket (call /oauth/callback first)", origin, 401);
  }

  const verdict = await verifyEnrollTicket(env.ENROLL_TICKET_SIGNING_KEY, body.ticket);
  if (!verdict.valid) {
    return errorResp(`Invalid enrollment ticket: ${verdict.reason}`, origin, 401);
  }

  // Single-use spend: rely on the D1 PRIMARY KEY constraint itself (not a check-then-insert), since
  // this Worker has no per-request serialization the way a Durable Object does — two concurrent
  // requests racing the same ticket must not both pass a SELECT-then-INSERT check. Plain INSERT
  // throwing on the second attempt is the atomic guarantee; catch and treat as "already spent".
  try {
    await env.DB_ENROLL.prepare("INSERT INTO spent_enroll_tickets (jti, spent_at) VALUES (?, ?)")
      .bind(verdict.payload.jti, Date.now())
      .run();
  } catch (err) {
    if ((err as Error).message.includes("UNIQUE constraint")) {
      return errorResp("Enrollment ticket already used", origin, 409);
    }
    throw err;
  }

  let blindedMsg: Uint8Array;
  try {
    blindedMsg = b64ToBytes(body.blinded);
  } catch {
    return errorResp("blinded is not valid base64", origin, 400);
  }

  let blindSig: Uint8Array;
  try {
    blindSig = blindSign(env.ISSUER_SIGNING_KEY_PEM, blindedMsg);
  } catch (err) {
    // Malformed blinded message (wrong length/out of range) or an unparsable key — bad input, not a 500.
    return errorResp(`blind-sign failed: ${(err as Error).message}`, origin, 400);
  }

  return jsonResp({ blindSig: bytesToB64(blindSig) }, origin);
});

router.all("*", (request: IRequest) => errorResp("Not found", request.headers.get("Origin"), 404));

// Real bug found via live testing (2026-07): itty-router's own `error()` fallback (previously used
// both for the 404 route above and as this top-level `.catch()`) builds a bare Response with NO
// CORS headers at all. Anything that throws before reaching one of this file's own `errorResp`/
// `jsonResp` calls — a malformed request body, an unexpected exception anywhere in a route handler
// — fell through to that bare response, and the browser reported it as a CORS failure ("No
// Access-Control-Allow-Origin header") that had nothing to do with the actual origin allow-list;
// the real symptom was just a response with no CORS header on it whatsoever. Every response this
// Worker returns, success or failure, expected or not, must carry a CORS header for the calling
// origin — so the top-level catch now builds one with `errorResp` instead of itty-router's helper.
export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext): Promise<Response> => {
    try {
      return await router.fetch(request, env, ctx);
    } catch (err) {
      // Genuinely unexpected — log it (this is a real error path worth seeing in `wrangler tail`/
      // prod logs), but still return a CORS-carrying response so the browser can read it.
      console.error("Unhandled error in enrollment Worker:", err);
      return errorResp(`Internal error: ${(err as Error).message}`, request.headers.get("Origin"), 500);
    }
  },
};
