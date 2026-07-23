// Client half of Flow 5/6 (docs/03 §8, docs/04) — opt-in public @alias registration + PoW-gated
// contact discovery/introduction. "Alias contact establishment" pass (2026-07): closes docs/06's
// long-standing "real per-user queue-id provisioning (Flow 5/6 contact establishment)" gap —
// `lib/inviteLink.ts`'s out-of-band URL is still there for a direct share, but this is the first
// real DISCOVERY path (look someone up by nickname, they approve) instead of requiring an
// out-of-band channel for every single contact. `AliasDO.ts` (`workers/messaging`) already existed,
// fully wired, from an earlier pass — what was missing was this client half plus the PoW miner
// (see `packages/vortic-core/src/pow.rs` and `apps/web/src/workers/powMiner.worker.ts`).
//
// Honest scope, said plainly (matching this codebase's own convention): this closes DISCOVERY, not
// the underlying `role` ("initiator"/"responder") stand-in `useQueueTransport.ts` still uses for
// queue provisioning itself — a resolved contact request still bootstraps a chat exactly like an
// invite link does (see `buildContactRequest`/`applyAcceptedRequest` below), just discovered via
// alias instead of an out-of-band URL. No signed update/revoke (`AliasDO.ts` doesn't verify a
// signature yet either — see its own header comment), no Key Transparency (K8) binding.
import { aliasDeriveRecordKey, aliasLookupKeyHex, identityVerifyingKey, initCrypto } from "@vorticity/vortic-core";
import { ohttpFetch } from "./ohttp";
import { sealToStore, unsealFromStore } from "./secureStore";
import { generateInviteChatId } from "./inviteLink";
import type { TransportRole } from "./chat";

// Must match workers/messaging/src/durable-objects/AliasDO.ts's own constants exactly — mining
// below these targets would just get a 403 back; mining above them only wastes time.
const REGISTER_MIN_BITS = 24;
const RESOLVE_MIN_BITS = 20;
const INTRODUCE_MIN_BITS = 22;

const NICKNAME_MIN_LENGTH = 3;
const NICKNAME_MAX_LENGTH = 32;
const NICKNAME_RE = /^[a-z0-9_]+$/;

export function isValidNickname(nickname: string): boolean {
  return nickname.length >= NICKNAME_MIN_LENGTH && nickname.length <= NICKNAME_MAX_LENGTH && NICKNAME_RE.test(nickname);
}

// --- base64 <-> bytes (same tiny per-file helpers this codebase already duplicates in every lib/*
// module that needs them — see lib/deviceLink.ts, lib/prekeys.ts) ---
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

// --- Record AEAD (rec_key is `aliasDeriveRecordKey(nickname)`'s raw 32 bytes directly — unlike
// lib/deviceLink.ts's HKDF-from-a-random-secret, the WASM export already IS the final derived key,
// so this just imports it) ---
async function importRecKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", rawKey as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function sealWithRecKey(rawKey: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await importRecKey(rawKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext as BufferSource));
  const out = new Uint8Array(iv.length + ciphertext.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  return out;
}

async function unsealWithRecKey(rawKey: Uint8Array, sealed: Uint8Array): Promise<Uint8Array | null> {
  if (sealed.length < 12) return null;
  const key = await importRecKey(rawKey);
  const iv = sealed.slice(0, 12);
  const ciphertext = sealed.slice(12);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext as BufferSource));
  } catch {
    return null; // wrong nickname/key, or tampered/corrupt blob
  }
}

// --- Padding: same size-bucket scheme useQueueTransport.ts's Sealed Sender++ padding uses, so a
// contact-request blob isn't distinguishable from an ordinary queue message by ciphertext length.
//
// REAL BUG found + fixed (2026-07, live use): `bucket` below used to be an ARRAY INDEX into a
// `SIZE_BUCKETS = [256, 512, ...]` table, but every server-side check (workers/messaging/src/
// bucketing.ts's `validateSizeBucket`) treats the value as a literal power-of-two EXPONENT — the
// exact same index-vs-exponent mismatch already found and fixed in useQueueTransport.ts's
// `padEnvelope` earlier this session, just never propagated to this file. This meant every real
// `/alias/introduce` contact-request send failed with a 400 ("ciphertext length N does not match
// declared size_bucket B") the instant the payload was non-trivially sized — i.e. always, since a
// real sealed contact-request payload never fits in the smallest bucket by coincidence at index 0.
const MIN_SIZE_BUCKET = 8; // 2^8 = 256 bytes
const MAX_SIZE_BUCKET = 24; // 2^24 = 16 MiB — mirrors bucketing.ts's ceiling

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function padHex(byteLen: number): string {
  const raw = new Uint8Array(byteLen);
  crypto.getRandomValues(raw);
  return Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, byteLen);
}

function padJson(obj: unknown): { bytes: Uint8Array; bucket: number } {
  const withoutPad = JSON.stringify({ ...(obj as object), pad: "" });
  const overhead = new TextEncoder().encode(withoutPad).length;
  let bucket = MIN_SIZE_BUCKET;
  while (overhead > 2 ** bucket && bucket < MAX_SIZE_BUCKET) bucket++;
  const targetSize = 2 ** bucket;
  if (overhead > targetSize) return { bytes: new TextEncoder().encode(withoutPad), bucket };
  const padded = JSON.stringify({ ...(obj as object), pad: padHex(targetSize - overhead) });
  return { bytes: new TextEncoder().encode(padded), bucket };
}

// --- PoW mining, off the main thread (apps/web/src/workers/powMiner.worker.ts) ---
function mineStamp(resource: string, minBits: number): Promise<string> {
  const worker = new Worker(new URL("../workers/powMiner.worker.ts", import.meta.url), { type: "module" });
  const requestId = crypto.randomUUID();
  const salt = padHex(16);
  const epoch = Math.floor(Date.now() / 3_600_000);
  return new Promise((resolve, reject) => {
    worker.onmessage = (event: MessageEvent<{ requestId: string; stamp: string } | { requestId: string; error: string }>) => {
      if (event.data.requestId !== requestId) return;
      worker.terminate();
      if ("stamp" in event.data) resolve(event.data.stamp);
      else reject(new Error(`PoW mining failed: ${event.data.error}`));
    };
    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(`PoW worker error: ${event.message}`));
    };
    worker.postMessage({ requestId, resource, minBits, epoch, salt });
  });
}

// --- Own registered alias (persisted in the vault, same primitive as everything else this app
// keeps across reloads — secureStore.ts's non-extractable AES-GCM vault) ---
const OWN_NICKNAME_KEY = "alias-own-nickname";
const OWN_SEED_KEY = "alias-own-seed";
const OWN_INTRO_QUEUE_KEY = "alias-own-intro-queue-id";

export interface OwnAlias {
  nickname: string;
  introQueueId: string;
}

/** Returns this device's registered alias, or `null` if none has been registered yet. */
export async function loadOwnAlias(): Promise<OwnAlias | null> {
  const [nicknameBytes, introQueueBytes] = await Promise.all([
    unsealFromStore(OWN_NICKNAME_KEY),
    unsealFromStore(OWN_INTRO_QUEUE_KEY),
  ]);
  if (!nicknameBytes || !introQueueBytes) return null;
  return { nickname: new TextDecoder().decode(nicknameBytes), introQueueId: new TextDecoder().decode(introQueueBytes) };
}

async function ownAliasSeed(): Promise<Uint8Array> {
  const existing = await unsealFromStore(OWN_SEED_KEY);
  if (existing) return existing;
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  await sealToStore(OWN_SEED_KEY, seed);
  return seed;
}

/** Registers `nickname` as this device's public alias, pointing it at a freshly generated
 * intro-queue id. Mines a real 24-bit PoW stamp (several seconds, runs off the main thread — see
 * `mineStamp`). Throws on any failure (including "already taken" — a 409 from `AliasDO`); callers
 * should surface that to the user rather than silently persisting a half-registered state. Only
 * succeeds once per device (no update/revoke yet, matching `AliasDO.ts`'s own current scope) —
 * callers should check `loadOwnAlias()` first. */
export async function registerAlias(nickname: string, cap: string): Promise<OwnAlias> {
  await initCrypto();
  const introQueueId = generateInviteChatId();
  const seed = await ownAliasSeed();
  const aliasPub = identityVerifyingKey(seed);
  const lookupKey = aliasLookupKeyHex(nickname);
  const recKey = aliasDeriveRecordKey(nickname);

  const recordPlain = new TextEncoder().encode(JSON.stringify({ introQueueId, aliasPub: bytesToB64(aliasPub), flags: 0 }));
  const sealedRecord = await sealWithRecKey(recKey, recordPlain);
  const stamp = await mineStamp(lookupKey, REGISTER_MIN_BITS);

  const res = await ohttpFetch("/alias/register", {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      lookup_key: lookupKey,
      record: bytesToB64(sealedRecord),
      pow_stamp: stamp,
      // R18 (AliasDO.ts): a plaintext top-level ownership key, required since the "signed alias
      // revoke" pass — this client was never updated to send it, so every registration attempt has
      // been failing with a 400 since that backend change landed. `record`'s own bundled base64
      // copy (above) is what stays opaque to the DO; this is the SAME key, just hex-encoded and
      // sent alongside, per AliasDO.ts's handleRegister.
      alias_pub: bytesToHex(aliasPub),
    }),
  });
  if (!res.ok) throw new Error(`alias register failed: HTTP ${res.status} ${await res.text().catch(() => "")}`);

  await Promise.all([
    sealToStore(OWN_NICKNAME_KEY, new TextEncoder().encode(nickname)),
    sealToStore(OWN_INTRO_QUEUE_KEY, new TextEncoder().encode(introQueueId)),
  ]);
  return { nickname, introQueueId };
}

export interface ResolvedAlias {
  introQueueId: string;
  aliasPub: Uint8Array;
  recKey: Uint8Array;
}

/** Looks up `nickname`, mining a real 20-bit PoW stamp bound to its `lookup_key`. Returns `null`
 * on a 404 (no such alias) — every other non-2xx is thrown, same "distinguish absence from
 * failure" convention `lib/deviceLink.ts`'s `takeLinkPayload` already uses. */
export async function resolveAlias(nickname: string, cap: string): Promise<ResolvedAlias | null> {
  await initCrypto();
  const lookupKey = aliasLookupKeyHex(nickname);
  const recKey = aliasDeriveRecordKey(nickname);
  const stamp = await mineStamp(lookupKey, RESOLVE_MIN_BITS);

  const res = await ohttpFetch(`/alias/resolve/${encodeURIComponent(lookupKey)}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${cap}`, "X-PoW-Stamp": stamp },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`alias resolve failed: HTTP ${res.status} ${await res.text().catch(() => "")}`);

  const { record } = (await res.json()) as { record: string };
  const plain = await unsealWithRecKey(recKey, b64ToBytes(record));
  if (!plain) return null; // shouldn't happen (we derived recKey from the same nickname the owner did), but never crash on a corrupt/foreign record
  const decoded = JSON.parse(new TextDecoder().decode(plain)) as { introQueueId: string; aliasPub: string };
  return { introQueueId: decoded.introQueueId, aliasPub: b64ToBytes(decoded.aliasPub), recKey };
}

// --- Contact requests: what actually flows through the resolved intro queue ---

interface ContactRequestPayload {
  type: "contact_request";
  proposedChatId: string;
  fromLabel: string | null;
}

/** Seals a proposal to start a NEW chat (a fresh `lib/inviteLink.ts`-shaped chat id — the SAME
 * bootstrap mechanism an invite link already uses downstream, just discovered via alias instead of
 * an out-of-band URL) and mines a real 22-bit PoW stamp bound to the target `introQueueId`, then
 * pushes it. `fromLabel` is a purely cosmetic, optional display hint for the recipient's inbox
 * card, same non-identity status as `lib/inviteLink.ts`'s own `label` param. The caller is
 * responsible for adding `proposedChatId` to its OWN chat list as role `"initiator"` — this
 * function only delivers the request, it doesn't touch local chat state (this module has no chat-
 * list access, same separation `lib/deviceLink.ts` already keeps). */
export async function sendContactRequest(resolved: ResolvedAlias, cap: string, fromLabel?: string): Promise<string> {
  const proposedChatId = generateInviteChatId();
  const payload: ContactRequestPayload = { type: "contact_request", proposedChatId, fromLabel: fromLabel?.trim().slice(0, 40) || null };
  const { bytes, bucket } = padJson(payload);
  const sealed = await sealWithRecKey(resolved.recKey, bytes);
  const stamp = await mineStamp(resolved.introQueueId, INTRODUCE_MIN_BITS);

  const res = await ohttpFetch("/alias/introduce", {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify({ introQueueId: resolved.introQueueId, ciphertext: bytesToB64(sealed), powStamp: stamp, sizeBucket: bucket }),
  });
  if (!res.ok) throw new Error(`contact request failed: HTTP ${res.status} ${await res.text().catch(() => "")}`);
  return proposedChatId;
}

export interface PendingContactRequest {
  seq: number;
  proposedChatId: string;
  fromLabel: string | null;
}

/** Pulls this device's own intro queue (its registered `introQueueId`) and decrypts every entry
 * with the OWNER's own rec_key (derivable locally — the owner already knows their own nickname).
 * `QueueDO`'s `/pull` does not remove anything (only `/ack` or TTL do, see this file's header
 * comment on why acking is deliberately NOT used here — its cumulative "everything <= seq"
 * semantics would risk dropping a still-pending, independent, lower-`seq` request alongside
 * whichever one was just handled); already-handled seqs are instead filtered out by the caller via
 * `alreadyHandledSeqs`, so a raw entry can linger in `QueueDO` until its TTL without resurfacing. */
export async function pullContactRequests(ownAlias: OwnAlias, cap: string, alreadyHandledSeqs: ReadonlySet<number>): Promise<PendingContactRequest[]> {
  await initCrypto(); // may be the first WASM-touching call this session if the user has no active chats yet
  const recKey = aliasDeriveRecordKey(ownAlias.nickname);
  const res = await ohttpFetch(`/queue/${encodeURIComponent(ownAlias.introQueueId)}/pull`, {
    method: "GET",
    headers: { Authorization: `Bearer ${cap}` },
  });
  if (!res.ok) throw new Error(`intro-queue pull failed: HTTP ${res.status}`);
  const { messages } = (await res.json()) as { messages: { seq: number; ciphertext: string }[] };

  const pending: PendingContactRequest[] = [];
  for (const msg of messages) {
    if (alreadyHandledSeqs.has(msg.seq)) continue;
    const plain = await unsealWithRecKey(recKey, b64ToBytes(msg.ciphertext));
    if (!plain) continue; // not a contact request sealed under our own alias — ignore, don't crash the inbox
    try {
      const decoded = JSON.parse(new TextDecoder().decode(plain)) as ContactRequestPayload;
      if (decoded.type !== "contact_request" || typeof decoded.proposedChatId !== "string") continue;
      pending.push({ seq: msg.seq, proposedChatId: decoded.proposedChatId, fromLabel: decoded.fromLabel ?? null });
    } catch {
      continue;
    }
  }
  return pending;
}

/** Builds the local `Chat` record for a proposed chat the OWNER just accepted from their inbox —
 * role `"responder"` (mirrors `Chats.tsx`'s `handleCreateInvite`: the owner is the one whose
 * `useQueueTransport` mount will publish the signed PQXDH prekey bundle onto this new chat's
 * queue, exactly like creating an invite link does). */
export function buildAcceptedChat(request: PendingContactRequest): { id: string; alias: string; initials: string; role: TransportRole } {
  const alias = request.fromLabel ? `Requested by: ${request.fromLabel}` : "New contact (via @alias)";
  return {
    id: request.proposedChatId,
    alias,
    initials: request.fromLabel ? request.fromLabel.slice(0, 2).toUpperCase() : "AL",
    role: "responder",
  };
}
