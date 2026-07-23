// First group-chat client pass (2026-07) — MLS via `MlsGroupSession` (X-Wing hybrid PQ ciphersuite,
// see packages/vortic-core/src/group.rs's module doc + docs/03 §5). `GroupDO` (workers/messaging) is
// a BLIND ordering/fan-out log for an already-known `groupId` — it has no roster, no create-group
// endpoint (a group is just a DO name), and deliberately does NOT deliver Welcome messages (those
// travel over a private 1:1 QueueDO channel — the exact infra 1:1 invites already use — see
// GroupDO.ts's own header comment). This file owns everything that isn't that blind log: creating a
// group, the invite/join key-package-then-Welcome exchange, producing/applying commits, and sealed
// local persistence of the live MLS session.
//
// SEALING DISCIPLINE: `MlsGroupSession.exportState()`'s own doc comment states this plainly — the
// exported bytes are "as sensitive as the session's full compromise" (all private key material +
// group ratchet-tree state) and the method performs NO sealing itself. Every place this file persists
// exported state goes through `lib/secureStore.ts`'s non-extractable AES-GCM vault, same as
// `RatchetSession`'s own exportState already does for 1:1 chats — never raw to localStorage/IndexedDB.
import { MlsGroupSession, initCrypto } from "@vorticity/vortic-core";
import { ohttpFetch } from "./ohttp";
import { sealToStore, unsealFromStore, clearFromStore } from "./secureStore";

const MESSAGING_API_URL = import.meta.env.DEV ? "http://localhost:8787" : "https://api.vort.xfeatures.net";

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
function toBase64Url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const GROUP_ID_BYTES = 16;
const IDENTITY_STORE_PREFIX = "group-identity:";
const STATE_STORE_PREFIX = "group-mls-state:";
const PENDING_STATE_STORE_PREFIX = "group-pending-state:";

/** A fresh, unguessable group id (the `GroupDO` instance name — see that class's header comment:
 * "a 'group', from the server's point of view, is nothing more than a set of anonymous sockets
 * listening to one DO", the name itself carries no meaning). */
export function generateGroupId(): string {
  const raw = new Uint8Array(GROUP_ID_BYTES);
  crypto.getRandomValues(raw);
  return `grp-${toBase64Url(raw)}`;
}

async function ownIdentitySeed(groupId: string): Promise<Uint8Array> {
  const key = IDENTITY_STORE_PREFIX + groupId;
  const existing = await unsealFromStore(key);
  if (existing) return existing;
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  await sealToStore(key, seed);
  return seed;
}

export async function saveGroupSession(groupId: string, session: MlsGroupSession): Promise<void> {
  await sealToStore(STATE_STORE_PREFIX + groupId, session.exportState());
}

export async function loadGroupSession(groupId: string): Promise<MlsGroupSession | null> {
  const bytes = await unsealFromStore(STATE_STORE_PREFIX + groupId);
  if (!bytes) return null;
  return MlsGroupSession.importState(bytes);
}

/** Removes ALL local state for a group (own identity, live session, any in-flight pending-join
 * state) — mirrors Chats.tsx's handleDeleteChat's crypto-state cleanup for 1:1 chats. LOCAL-DEVICE
 * ONLY: does not remove this device from the group server-side (GroupDO has no such concept), does
 * not notify other members. */
export async function deleteGroupState(groupId: string): Promise<void> {
  await Promise.all(
    [IDENTITY_STORE_PREFIX + groupId, STATE_STORE_PREFIX + groupId, PENDING_STATE_STORE_PREFIX + groupId].map((key) =>
      clearFromStore(key).catch(() => {}),
    ),
  );
}

/** Creates a brand-new group with the caller as its sole member (epoch 0). */
export async function createGroup(): Promise<{ groupId: string; session: MlsGroupSession }> {
  await initCrypto();
  const groupId = generateGroupId();
  const seed = await ownIdentitySeed(groupId);
  const session = MlsGroupSession.createGroup(seed);
  await saveGroupSession(groupId, session);
  return { groupId, session };
}

// --- Padding: same power-of-two size-bucket convention as useQueueTransport.ts's padEnvelope /
// workers/messaging/src/bucketing.ts's validateSizeBucket — an exponent, not an array index. ---
function padToBucket(bytes: Uint8Array): { bytes: Uint8Array; bucket: number } {
  let bucket = 8;
  while (bytes.byteLength > 2 ** bucket && bucket < 24) bucket++;
  const target = 2 ** bucket;
  if (bytes.byteLength >= target) return { bytes, bucket };
  const padded = new Uint8Array(target);
  padded.set(bytes);
  crypto.getRandomValues(padded.subarray(bytes.byteLength)); // random pad, not zeros
  return { bytes: padded, bucket };
}

/** Pushes one blob onto the REAL group log (`GroupDO`) — commits and application messages are
 * indistinguishable opaque blobs to it (see GroupDO.ts's header comment), so this is used for both.
 * `senderQueueId`, if given, is GroupDO's anti-echo tag (an opaque per-connection tag, not an
 * identity — same convention QueueDO/ConvLogDO already use): a live WS subscribed with the SAME tag
 * is excluded from this push's fan-out, so a sender doesn't see their own message echoed back. */
export async function pushToGroupLog(groupId: string, cap: string, blobBytes: Uint8Array, senderQueueId?: string): Promise<number> {
  const { bytes, bucket } = padToBucket(blobBytes);
  // NOTE: unlike /queue/:id/push, /group/:id/push has no OHTTP-wrapped path yet (a real, documented
  // gap — see GroupDO.ts's own header comment) — plain fetch is the only option today, inherited
  // deliberately rather than silently worked around in this pass.
  const res = await fetch(`${MESSAGING_API_URL}/group/${encodeURIComponent(groupId)}/push`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      blobs: [{ blob: bytesToB64(bytes), sizeBucket: bucket }],
      ...(senderQueueId ? { senderQueueId } : {}),
    }),
  });
  if (!res.ok) throw new Error(`group push failed: HTTP ${res.status} ${await res.text().catch(() => "")}`);
  const { seqs } = (await res.json()) as { seqs: number[] };
  return seqs[0]!;
}

// --- Invite / join exchange -------------------------------------------------------------------
// A temporary pairwise QueueDO channel (the SAME per-message infra 1:1 chats use, just for a one-shot
// handshake instead of an ongoing conversation) — `${inviteId}:toCreator` carries the prospective
// member's KeyPackage, `${inviteId}:toInvitee` carries the resulting Welcome back. Neither leg needs
// its own encryption layer on top: a KeyPackage is public-by-design (meant to be published so others
// can add you) and a Welcome is already HPKE-encrypted to the specific joiner's init key by MLS
// itself — QueueDO's opaque-blob storage is exactly the right primitive here, unmodified.

const INVITE_TTL_MS = 24 * 60 * 60 * 1000; // 24h — generous for "someone opens the link later"

function inviteQueueId(inviteId: string, direction: "toCreator" | "toInvitee"): string {
  return `group-invite-${inviteId}-${direction}`;
}

async function pushToQueue(queueId: string, cap: string, rawBytes: Uint8Array): Promise<void> {
  const { bytes, bucket } = padToBucket(rawBytes);
  const res = await ohttpFetch(`/queue/${encodeURIComponent(queueId)}/push`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "X-Ttl-Ms": String(INVITE_TTL_MS), "X-Size-Bucket": String(bucket) },
    body: bytes,
  });
  if (!res.ok) throw new Error(`invite queue push failed: HTTP ${res.status}`);
}

interface QueuePullMessage {
  seq: number;
  ciphertext: string;
  sizeBucket: number;
}

async function pullFromQueue(queueId: string, cap: string): Promise<QueuePullMessage[]> {
  const res = await ohttpFetch(`/queue/${encodeURIComponent(queueId)}/pull`, {
    method: "GET",
    headers: { Authorization: `Bearer ${cap}` },
  });
  if (!res.ok) throw new Error(`invite queue pull failed: HTTP ${res.status}`);
  const { messages } = (await res.json()) as { messages: QueuePullMessage[] };
  return messages;
}

export function generateInviteId(): string {
  const raw = new Uint8Array(GROUP_ID_BYTES);
  crypto.getRandomValues(raw);
  return toBase64Url(raw);
}

export function buildGroupInviteUrl(groupId: string, inviteId: string, groupName?: string): string {
  const base = `${location.origin}${location.pathname}#/group-invite/${encodeURIComponent(groupId)}/${encodeURIComponent(inviteId)}`;
  const trimmed = groupName?.trim().slice(0, 60);
  return trimmed ? `${base}?name=${encodeURIComponent(trimmed)}` : base;
}

export interface ParsedGroupInvite {
  groupId: string;
  inviteId: string;
  groupName: string | null;
}

export function parseGroupInviteFromLocation(): ParsedGroupInvite | null {
  const match = /^#\/group-invite\/([^/?#]+)\/([^/?#]+)(?:\?(.*))?$/.exec(location.hash);
  if (!match) return null;
  const groupId = decodeURIComponent(match[1]!);
  const inviteId = decodeURIComponent(match[2]!);
  if (!groupId.startsWith("grp-")) return null;
  const params = new URLSearchParams(match[3] ?? "");
  const rawName = params.get("name");
  return { groupId, inviteId, groupName: rawName ? decodeURIComponent(rawName).trim().slice(0, 60) || null : null };
}

export function clearGroupInviteHash(): void {
  history.replaceState(null, "", location.pathname + location.search);
}

/** Invitee side, step 1: generates this device's own KeyPackage for the target group and sends it
 * to whoever holds the invite link. The returned `pendingState` MUST be kept (sealed under
 * `groupId`, done here) until `completeJoinFromWelcome` below consumes it — it holds the private
 * signer material the eventual Welcome decrypts against. */
export async function requestToJoinGroup(groupId: string, inviteId: string, cap: string): Promise<void> {
  await initCrypto();
  const seed = await ownIdentitySeed(groupId);
  const [pendingStateBytes, keyPackageBytes] = MlsGroupSession.generateKeyPackage(seed) as [Uint8Array, Uint8Array];
  await sealToStore(PENDING_STATE_STORE_PREFIX + groupId, pendingStateBytes);
  await pushToQueue(inviteQueueId(inviteId, "toCreator"), cap, keyPackageBytes);
}

/** Invitee side, step 2: polls for the Welcome the creator sends back once they've processed this
 * device's KeyPackage. Returns `null` if it hasn't arrived yet (caller polls again) — never throws
 * for "not yet", only for a real transport failure. */
export async function pollForWelcome(groupId: string, inviteId: string, cap: string): Promise<MlsGroupSession | null> {
  const messages = await pullFromQueue(inviteQueueId(inviteId, "toInvitee"), cap);
  if (messages.length === 0) return null;
  const pendingStateBytes = await unsealFromStore(PENDING_STATE_STORE_PREFIX + groupId);
  if (!pendingStateBytes) throw new Error("no pending join state found for this group — was requestToJoinGroup called first?");
  const welcomeBytes = b64ToBytes(messages[0]!.ciphertext);
  const session = MlsGroupSession.joinFromWelcome(pendingStateBytes, welcomeBytes);
  await saveGroupSession(groupId, session);
  await clearFromStore(PENDING_STATE_STORE_PREFIX + groupId);
  return session;
}

/** Creator side: checks the invite's inbound leg for a prospective member's KeyPackage; if present,
 * adds them (real MLS commit, merged into THIS device's session immediately), pushes the commit to
 * the real group log so every other current member processes it too, and sends the Welcome back to
 * the joiner over the same invite channel. Returns `true` once a member was actually added (caller
 * can then stop polling this invite). */
export async function checkAndProcessJoinRequest(
  groupId: string,
  inviteId: string,
  cap: string,
  session: MlsGroupSession,
  senderQueueId?: string,
): Promise<boolean> {
  const messages = await pullFromQueue(inviteQueueId(inviteId, "toCreator"), cap);
  if (messages.length === 0) return false;
  const keyPackageBytes = b64ToBytes(messages[0]!.ciphertext);
  const [commitBytes, welcomeBytes] = session.addMember(keyPackageBytes) as [Uint8Array, Uint8Array];
  await saveGroupSession(groupId, session);
  // `addMember` already merged this commit into `session` synchronously (see group.rs's own doc) —
  // tagged with this device's own anti-echo id so its live WS (if subscribed) doesn't receive the
  // SAME commit back and try to re-apply it.
  await pushToGroupLog(groupId, cap, commitBytes, senderQueueId);
  await pushToQueue(inviteQueueId(inviteId, "toInvitee"), cap, welcomeBytes);
  return true;
}
