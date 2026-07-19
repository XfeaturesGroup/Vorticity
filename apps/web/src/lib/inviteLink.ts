// Contact-bootstrap invite link (docs/06 deploy-checklist, "closed alpha" pass, 2026-07). Minimal
// version, explicitly scoped: NO AliasDO, no PoW, no directory — that's a separate, larger system
// (docs/06's still-open "real per-user queue-id provisioning / Flow 5/6 contact establishment").
//
// What this actually does: generates a fresh, high-entropy, unguessable chat id (NOT one of the
// mock `chat-N` ids — those are low-entropy and would let anyone who saw one push/read on that
// pair's queues) and encodes it into a shareable URL. The link's own delivery channel (however the
// two people actually exchange it — chat, email, in person) is the trust anchor for this minimal
// version, same as it would be for a Signal/SimpleX-style invite: whoever holds the link can address
// this specific queue pair.
//
// Deliberately NOT embedded in the link: the PQXDH prekey bundle itself. It still flows exactly as
// before — over the queue's own channel, Ed25519-signed and verified by `RatchetSession.handshakeInitiate`
// (useQueueTransport.ts) — because embedding it a second time in the URL wouldn't add a real security
// property here: this app has no safety-number/verified-fingerprint UI to compare it against, so
// either path is equally first-use-trust (TOFU), and reusing the existing signed-bundle-over-the-queue
// flow unchanged avoids the sharper problem of needing to persist a generated identity/KEM keypair
// across a page navigation so it still matches what the link promised. A real out-of-band-authenticated
// invite (bundle embedded + a UI to compare it) is a reasonable future strengthening, not this pass.
const CHAT_ID_BYTES = 16;

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array | null {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  try {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** A fresh, unguessable chat id — becomes `${chatId}:AtoB` / `${chatId}:BtoA` via useQueueTransport's
 * existing `queueIds()`, exactly like a mock `chat-N` id does, just high-entropy instead of a fixed name. */
export function generateInviteChatId(): string {
  const raw = new Uint8Array(CHAT_ID_BYTES);
  crypto.getRandomValues(raw);
  return `inv-${toBase64Url(raw)}`;
}

const LABEL_MAX_LENGTH = 40;

/** Builds the shareable URL for the chat id above. Hash-based (`#/invite/<id>?from=<label>`), not a
 * server route — this is a pure client-side bootstrap, no server needs to know about invites at all.
 * `label` is a purely cosmetic, OPTIONAL, human-readable string the inviter can attach ("Пригласил:
 * X") — visible only to whoever already holds/opens this exact link, via this same client-side URL
 * parsing. NOT a public @alias (docs/03 §8's Flow 5/6 directory) — no discoverability, no server
 * storage, nothing resolvable without the link itself. Silently truncated to `LABEL_MAX_LENGTH`
 * rather than rejected, since it's cosmetic and a link should never fail to build over this. */
export function buildInviteUrl(chatId: string, label?: string): string {
  const base = `${location.origin}${location.pathname}#/invite/${encodeURIComponent(chatId)}`;
  const trimmed = label?.trim().slice(0, LABEL_MAX_LENGTH);
  return trimmed ? `${base}?from=${encodeURIComponent(trimmed)}` : base;
}

export interface ParsedInvite {
  chatId: string;
  /** The inviter's optional cosmetic label, already trimmed/length-capped — null if none was set. */
  label: string | null;
}

/** Reads a pending invite out of the current URL's hash, if any, without navigating. Returns null if
 * the hash isn't an invite link or the id fails the basic shape check (defends against a malformed/
 * truncated link silently becoming a garbage queue id rather than a clean "not an invite"). */
export function parseInviteFromLocation(): ParsedInvite | null {
  const match = /^#\/invite\/([^/?#]+)(?:\?(.*))?$/.exec(location.hash);
  if (!match) return null;
  const chatId = decodeURIComponent(match[1]!);
  if (!chatId.startsWith("inv-")) return null;
  if (!fromBase64Url(chatId.slice("inv-".length))) return null;
  const params = new URLSearchParams(match[2] ?? "");
  const rawLabel = params.get("from");
  const label = rawLabel ? rawLabel.trim().slice(0, LABEL_MAX_LENGTH) || null : null;
  return { chatId, label };
}

/** Clears the invite hash from the URL bar after it's been consumed, so a page refresh doesn't
 * re-trigger "join this invite" every time. */
export function clearInviteHash(): void {
  history.replaceState(null, "", location.pathname + location.search);
}

// Real bug found + fixed 2026-07-19 (first attempt at a genuine two-person invite test, not caught
// by any earlier pass): someone opening an invite link for the FIRST TIME, not yet authenticated,
// hits `AuthGuard` — which redirects to "/" via `<Navigate replace>`, and a full-path `Navigate`
// replaces the ENTIRE URL including the hash. The invite was silently gone before Chats.tsx ever
// got a chance to read it, and the subsequent OAuth round-trip (SecurityGate -> account.xfeatures.net
// -> AuthCallback -> /chats) has no memory of it either. Fixed the same way this codebase already
// solves "a value must survive a redirect chain": `sessionStorage`, single-use, same convention as
// `pkce.ts`'s `PKCE_VERIFIER_KEY` (tab-scoped, not `localStorage` — this is bootstrap data for the
// CURRENT tab's flow, not something that should linger across browser restarts).
const PENDING_INVITE_SESSION_KEY = "vorticity-pending-invite";

/** Called by AuthGuard right before it redirects an unauthenticated visitor away from a URL that
 * might carry a pending invite — captures it so it can be picked back up after login completes. */
export function stashPendingInviteFromCurrentLocation(): void {
  const invite = parseInviteFromLocation();
  if (!invite) return;
  sessionStorage.setItem(PENDING_INVITE_SESSION_KEY, JSON.stringify(invite));
}

/** Reads back and CONSUMES (single-use, like the PKCE verifier) an invite stashed by the function
 * above. Called by Chats.tsx after a successful login lands there with no invite hash of its own
 * (the login redirect chain doesn't carry one — this is how it survives that trip). */
export function takeStashedPendingInvite(): ParsedInvite | null {
  const raw = sessionStorage.getItem(PENDING_INVITE_SESSION_KEY);
  if (!raw) return null;
  sessionStorage.removeItem(PENDING_INVITE_SESSION_KEY);
  try {
    return JSON.parse(raw) as ParsedInvite;
  } catch {
    return null;
  }
}
