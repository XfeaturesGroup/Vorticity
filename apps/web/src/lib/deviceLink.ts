// Device-linking pass (2026-07): move a chat's full crypto state — persisted identity/KEM material,
// the local one-time-prekey pool, and the LIVE ratchet session — from one of a user's own devices to
// another. See docs/06's device-linking entry for the design decision this implements ("device
// linking": one shared per-chat identity/ratchet, not per-device Sesame-style keys) and
// workers/messaging/src/durable-objects/DeviceLinkDO.ts's header comment for the server side.
//
// WHY A SEPARATE SECRET-DERIVED CHANNEL, NOT JUST ohttpFetch TO A CHAT ROUTE: the receiving device
// does not yet know this chat exists (that is the entire point of linking it in) and, more
// fundamentally, this payload is orders of magnitude more sensitive than anything else this app ever
// puts on the wire — full private key material, not just ciphertext a peer is meant to read. It gets
// its own one-time dead-drop (DeviceLinkDO) and its own AEAD sealing, independent of the ratchet
// session itself (there is no ratchet session between "my two devices" to reuse).
//
// THE LINKING CODE **is a bearer credential to this chat's full private key material** for as long
// as the drop is unclaimed (DeviceLinkDO's `TTL_MS`, currently 10 minutes) — it must only ever be
// moved between a user's OWN devices, over a channel they control (shown on-screen + typed in, a
// private note-to-self, etc.), never forwarded through the chat itself or any third party. This is a
// materially different trust class from `lib/inviteLink.ts`'s invite links (those grant only the
// ability to START a NEW session as a stranger, not read an EXISTING one's full state) — said
// plainly so this distinction isn't lost by superficial code-shape similarity between the two files.
import { ohttpFetch } from "./ohttp";
import { sealToStore, unsealFromStore } from "./secureStore";
import { exportPoolEntries, importPoolEntries, type PoolEntry } from "./prekeys";
import type { Chat, ChatMessage, TransportRole } from "./chat";

const SECRET_BYTES = 32;

function bytesToB64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64UrlToBytes(s: string): Uint8Array | null {
  try {
    const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}
function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function generateLinkingSecret(): Uint8Array {
  const secret = new Uint8Array(SECRET_BYTES);
  crypto.getRandomValues(secret);
  return secret;
}

/** The shareable code — base64url of the raw secret. Move this between your OWN devices only (see
 * this file's header comment) — same "whoever holds the link can act" trust model as an invite link,
 * but for reading this chat's full state rather than just starting a new one. */
export function encodeLinkCode(secret: Uint8Array): string {
  return bytesToB64Url(secret);
}
export function decodeLinkCode(code: string): Uint8Array | null {
  const bytes = b64UrlToBytes(code.trim());
  return bytes && bytes.length === SECRET_BYTES ? bytes : null;
}

export function buildLinkUrl(secret: Uint8Array): string {
  return `${location.origin}${location.pathname}#/device-link/${encodeLinkCode(secret)}`;
}

/** Reads a pending device-link code out of the current URL's hash, same "parse without navigating"
 * convention as lib/inviteLink.ts's `parseInviteFromLocation` (kept as a separate function rather
 * than generalizing that one — the two hash shapes carry very differently-sensitive payloads and
 * this file's header comment is explicit about not blurring that distinction). */
export function parseLinkCodeFromLocation(): Uint8Array | null {
  const match = /^#\/device-link\/([^/?#]+)$/.exec(location.hash);
  if (!match) return null;
  return decodeLinkCode(decodeURIComponent(match[1]!));
}

/** One-way: the server-visible DO shard id, derived so that observing it (e.g. in the URL path of a
 * server-side request log) cannot be inverted back to the AEAD key below — SHA-256 has no known
 * preimage attack. */
async function linkIdFromSecret(secret: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", secret as BufferSource);
  return [...new Uint8Array(digest).slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function deriveAeadKey(secret: Uint8Array): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey("raw", secret as BufferSource, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode("vortic-device-link-v1") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(secret: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await deriveAeadKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext as BufferSource));
  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return out;
}

async function unseal(secret: Uint8Array, sealed: Uint8Array): Promise<Uint8Array | null> {
  if (sealed.length < 12) return null;
  const key = await deriveAeadKey(secret);
  const iv = sealed.slice(0, 12);
  const ciphertext = sealed.slice(12);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext as BufferSource));
  } catch {
    return null; // wrong secret, or tampered/corrupt blob
  }
}

/** Seals `payloadBytes` under a key derived from `secret` and drops it at DeviceLinkDO, keyed by the
 * one-way-derived linkId. `cap` is the PUBLISHING device's own session capability. */
export async function putLinkPayload(secret: Uint8Array, cap: string, payloadBytes: Uint8Array): Promise<void> {
  const linkId = await linkIdFromSecret(secret);
  const sealed = await seal(secret, payloadBytes);
  const res = await ohttpFetch(`/device-link/${encodeURIComponent(linkId)}/put`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify({ blob: bytesToB64(sealed) }),
  });
  if (!res.ok) throw new Error(`device-link put failed: HTTP ${res.status}`);
}

/** Fetches and unseals the payload for `secret`'s derived linkId, or `null` if there's nothing there
 * (not yet published, already claimed, expired, or the ciphertext failed to authenticate under this
 * secret — all treated the same by the caller: "linking hasn't succeeded yet / this code is invalid",
 * not distinguished further to avoid turning failure-mode differences into an oracle). `cap` is the
 * RECEIVING device's own session capability (see this file's header comment on why it needs one). */
export async function takeLinkPayload(secret: Uint8Array, cap: string): Promise<Uint8Array | null> {
  const linkId = await linkIdFromSecret(secret);
  const res = await ohttpFetch(`/device-link/${encodeURIComponent(linkId)}/take`, {
    method: "GET",
    headers: { Authorization: `Bearer ${cap}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`device-link take failed: HTTP ${res.status}`);
  const { blob } = (await res.json()) as { blob: string };
  return unseal(secret, b64ToBytes(blob));
}

// --- The actual transfer payload: everything a second device needs to continue this exact chat ---
// (identity/KEM material + one-time pool, ONLY meaningful for the responder role — an initiator has
// no persisted identity of its own, see useQueueTransport.ts's header comment — plus the live ratchet
// session, if one is established, and the chat's own metadata/history). See this file's header
// comment for the sensitivity of what this carries.

interface LinkPayload {
  chatId: string;
  alias: string;
  initials: string;
  role: TransportRole;
  presenceEnabled: boolean;
  messages: ChatMessage[];
  lastMessage: string;
  lastMessageAt: string;
  identitySeedB64: string | null;
  kemKeypairB64: string | null;
  kemRotatedAt: number | null;
  onetimePool: PoolEntry[] | null;
  ratchetStateB64: string | null;
  trustedPeerBundle: { verifyingKey: string; bundle: string } | null;
}

/** Gathers everything for `chat` into one payload, ready to `seal`+`putLinkPayload`. `ratchetState`/
 * `trustedPeerBundle` come from `useQueueTransport`'s `exportRatchetState`/`getTrustedPeerBundle` —
 * `deviceLink.ts` itself has no React/hook access, so the live session pieces are passed in rather
 * than re-derived here. Only meaningful to call from a device that currently holds this chat's
 * `hasLease` (exporting from a read-only device would hand over stale/absent live state). */
export async function buildLinkPayload(chat: Chat, ratchetState: Uint8Array | null, trustedPeerBundle: { verifyingKey: string; bundle: string } | null): Promise<Uint8Array> {
  let identitySeedB64: string | null = null;
  let kemKeypairB64: string | null = null;
  let kemRotatedAt: number | null = null;
  let onetimePool: PoolEntry[] | null = null;

  if (chat.role === "responder") {
    const [identitySeed, kemKeypair, rotatedAt] = await Promise.all([
      unsealFromStore(`ratchet-identity:${chat.id}`),
      unsealFromStore(`ratchet-kem:${chat.id}`),
      unsealFromStore(`ratchet-kem-rotated-at:${chat.id}`),
    ]);
    if (identitySeed) identitySeedB64 = bytesToB64(identitySeed);
    if (kemKeypair) kemKeypairB64 = bytesToB64(kemKeypair);
    if (rotatedAt) kemRotatedAt = Number(new TextDecoder().decode(rotatedAt));
    onetimePool = await exportPoolEntries(chat.id);
  }

  const payload: LinkPayload = {
    chatId: chat.id,
    alias: chat.alias,
    initials: chat.initials,
    role: chat.role,
    presenceEnabled: chat.presenceEnabled,
    messages: chat.messages,
    lastMessage: chat.lastMessage,
    lastMessageAt: chat.lastMessageAt,
    identitySeedB64,
    kemKeypairB64,
    kemRotatedAt,
    onetimePool,
    ratchetStateB64: ratchetState ? bytesToB64(ratchetState) : null,
    trustedPeerBundle,
  };
  return new TextEncoder().encode(JSON.stringify(payload));
}

/** The receiving device's half: writes everything back to local storage under the SAME chatId
 * (identity/KEM/pool via the exact same secureStore keys useQueueTransport.ts/lib/prekeys.ts already
 * use, so that hook's own logic picks them up with no special-casing) and stages the live ratchet
 * state at `ratchet-imported-state:${chatId}` for `useQueueTransport`'s lease-acquire effect to
 * hydrate on its next successful lease acquisition. Returns the `Chat` record to insert into the
 * local chat list — the caller (Chats.tsx) is responsible for actually adding it (and for deciding
 * what happens if a chat with this id already exists locally, e.g. re-linking after data loss). */
export async function applyLinkPayload(payloadBytes: Uint8Array): Promise<Chat> {
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as LinkPayload;

  const writes: Promise<void>[] = [];
  if (payload.identitySeedB64) writes.push(sealToStore(`ratchet-identity:${payload.chatId}`, b64ToBytes(payload.identitySeedB64)));
  if (payload.kemKeypairB64) writes.push(sealToStore(`ratchet-kem:${payload.chatId}`, b64ToBytes(payload.kemKeypairB64)));
  if (payload.kemRotatedAt !== null) {
    writes.push(sealToStore(`ratchet-kem-rotated-at:${payload.chatId}`, new TextEncoder().encode(String(payload.kemRotatedAt))));
  }
  if (payload.onetimePool) writes.push(importPoolEntries(payload.chatId, payload.onetimePool));
  if (payload.ratchetStateB64) {
    const importedState = { ratchetStateB64: payload.ratchetStateB64, trustedPeerBundle: payload.trustedPeerBundle };
    writes.push(sealToStore(`ratchet-imported-state:${payload.chatId}`, new TextEncoder().encode(JSON.stringify(importedState))));
  }
  await Promise.all(writes);

  return {
    id: payload.chatId,
    alias: payload.alias,
    initials: payload.initials,
    role: payload.role,
    online: false,
    unreadCount: 0,
    lastMessage: payload.lastMessage,
    lastMessageAt: payload.lastMessageAt,
    messages: payload.messages,
    presenceEnabled: payload.presenceEnabled,
  };
}
