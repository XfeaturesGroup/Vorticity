// Enrollment ticket: short-lived, single-use HMAC-signed proof that /oauth/callback's real OAuth
// exchange + PPID sybil-guard/quota check actually ran for THIS session, before /token/issue will
// blind-sign anything. Closes a real gap found 2026-07: /token/issue previously accepted any
// caller-supplied blinded message with zero linkage to a completed OAuth flow — an unauthenticated
// blind-signing oracle that let anyone mint unlimited anonymous membership tokens without ever
// holding a real Xfeatures account, defeating R11/G8 (Sybil resistance) entirely.
//
// Same b64url(payload).b64url(HMAC) shape as workers/messaging/src/session.ts's capability, kept
// fully independent: different signing key (env.ENROLL_TICKET_SIGNING_KEY, never leaves this
// Worker), different plane, minted and verified only within Enrollment. Messaging never sees this
// value — the client discards the ticket after redemption and only ever forwards the finalized
// RSABSSA (msg, sig, msgRandomizer) token onward, so this stays a plane-internal control, not a new
// cross-plane identity residue.
const TICKET_TTL_MS = 10 * 60 * 1000; // 10 min: generous for the real 3-step client flow (oauth -> blind -> issue), short enough that a leaked ticket can't be replayed long after the fact (also moot once spent — see single-use spend in index.ts).

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// Length-independent-leak constant-time compare (both inputs are fixed 32-byte HMACs here anyway) —
// same idiom as session.ts's timingSafeEqual, duplicated rather than shared across a plane boundary.
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export interface TicketPayload {
  ppid: string;
  jti: string;
  iat: number;
  exp: number;
}

/** Mint a ticket for a ppid that has already passed /oauth/callback's quota check this call. */
export async function mintEnrollTicket(signingKeyHex: string, ppid: string): Promise<string> {
  const now = Date.now();
  const jti = crypto.randomUUID();
  const payload: TicketPayload = { ppid, jti, iat: now, exp: now + TICKET_TTL_MS };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));

  const key = await crypto.subtle.importKey("raw", hexToBytes(signingKeyHex), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, payloadBytes));
  return `${b64url(payloadBytes)}.${b64url(sig)}`;
}

export type TicketVerdict = { valid: true; payload: TicketPayload } | { valid: false; reason: string };

/** Verify signature + expiry. Does NOT check single-use spend — that's index.ts's job (needs D1). */
export async function verifyEnrollTicket(signingKeyHex: string, ticket: string): Promise<TicketVerdict> {
  const dot = ticket.indexOf(".");
  if (dot < 0) return { valid: false, reason: "malformed ticket (no signature segment)" };
  const payloadSeg = ticket.slice(0, dot);
  const sigSeg = ticket.slice(dot + 1);

  let payloadBytes: Uint8Array;
  let sig: Uint8Array;
  try {
    payloadBytes = b64urlToBytes(payloadSeg);
    sig = b64urlToBytes(sigSeg);
  } catch {
    return { valid: false, reason: "ticket is not valid base64url" };
  }

  const key = await crypto.subtle.importKey("raw", hexToBytes(signingKeyHex), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, payloadBytes));
  if (!timingSafeEqual(sig, expected)) return { valid: false, reason: "bad signature" };

  let payload: TicketPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as TicketPayload;
  } catch {
    return { valid: false, reason: "ticket payload is not JSON" };
  }
  if (typeof payload.jti !== "string" || typeof payload.ppid !== "string") {
    return { valid: false, reason: "ticket payload malformed" };
  }
  if (typeof payload.exp !== "number" || Date.now() >= payload.exp) {
    return { valid: false, reason: "ticket expired" };
  }

  return { valid: true, payload };
}
