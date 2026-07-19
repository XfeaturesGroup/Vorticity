// Client half of the PrekeyDO rotation pass (2026-07, docs/03 §4 + workers/messaging/src/
// durable-objects/PrekeyDO.ts). Two responsibilities, deliberately kept in one small module rather
// than folded into useQueueTransport.ts: talking to PrekeyDO over HTTP, and persisting the
// RESPONDER's local one-time-prekey pool (the private halves PrekeyDO never sees).
//
// WHY A LOCAL POOL AT ALL: PrekeyDO stores only PUBLIC one-time-prekey bytes — the matching private
// keys must live somewhere so the responder can later decapsulate whichever one an initiator's
// `session_init` envelope references. Sealed via lib/secureStore.ts's non-extractable vault, same
// primitive the persisted ratchet identity already uses. Single-use by construction: `consumeFromPool`
// removes an entry the moment it's used, mirroring PrekeyDO's own atomic pop-on-fetch server-side.
//
// HONEST GAP, still real for an UNLINKED device (device-linking pass, docs/06, only closes it for
// devices that went through the linking flow): this pool is otherwise LOCAL-DEVICE-ONLY. If local
// storage is ever lost (device wipe) while PrekeyDO server-side still remembers having handed out a
// since-orphaned one-time prekey's public half to some initiator, that ONE specific handshake attempt
// fails to decapsulate — a rare edge case, not reconciled automatically. `exportPoolEntries`/
// `importPoolEntries` below are lib/deviceLink.ts's hook into this pool for a device that WAS linked.
import { kemGenerateKeypair, kemPublicKeyFromKeypair } from "@vorticity/vortic-core";
import { ohttpFetch } from "./ohttp";
import { sealToStore, unsealFromStore } from "./secureStore";

export const ONETIME_POOL_TARGET_SIZE = 20;
export const ONETIME_REPLENISH_THRESHOLD = 5;
export const SIGNED_PREKEY_ROTATE_AFTER_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface PoolEntry {
  id: string;
  keypairB64: string;
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

const poolStoreKey = (chatId: string) => `onetime-pool:${chatId}`;

async function loadPool(chatId: string): Promise<PoolEntry[]> {
  const bytes = await unsealFromStore(poolStoreKey(chatId));
  if (!bytes) return [];
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return Array.isArray(parsed) ? (parsed as PoolEntry[]) : [];
  } catch {
    return [];
  }
}

async function savePool(chatId: string, pool: PoolEntry[]): Promise<void> {
  await sealToStore(poolStoreKey(chatId), new TextEncoder().encode(JSON.stringify(pool)));
}

/** Device-linking pass: the raw pool entries (id + private keypair bytes, base64), for
 * lib/deviceLink.ts to bundle into a transfer payload. Exposed as `PoolEntry[]` (not re-encoded) so
 * the receiving device's `importPoolEntries` below can store them back verbatim. */
export async function exportPoolEntries(chatId: string): Promise<PoolEntry[]> {
  return loadPool(chatId);
}

/** The other half — REPLACES this device's local pool for `chatId` with the linked device's exact
 * pool (not merged/appended): the receiving device has no pool of its own yet for a chat it's only
 * just learning about via linking, so there is nothing meaningful to merge with. */
export async function importPoolEntries(chatId: string, entries: PoolEntry[]): Promise<void> {
  await savePool(chatId, entries);
}

/** Removes and returns the keypair bytes for `id`, or `null` if this device never had it (lost
 * storage, or a stale/forged id) — the caller (useQueueTransport.ts) must treat that as "cannot
 * decapsulate this handshake", not retry the same id. */
export async function consumeFromPool(chatId: string, id: string): Promise<Uint8Array | null> {
  const pool = await loadPool(chatId);
  const idx = pool.findIndex((e) => e.id === id);
  if (idx === -1) return null;
  const [entry] = pool.splice(idx, 1);
  await savePool(chatId, pool);
  return b64ToBytes(entry!.keypairB64);
}

/** Generates enough fresh one-time keypairs to bring the pool up to `ONETIME_POOL_TARGET_SIZE`,
 * given the server already reports `serverCount` outstanding — persists the new keypairs locally
 * (appended, existing entries untouched) and returns `"id:base64(pubkey)"` pairs ready for
 * `publishBundle`'s `onetimePubKeys`. Returns `[]` if the pool is already at/above target (no churn
 * for its own sake). */
export async function topUpPool(chatId: string, serverCount: number): Promise<string[]> {
  const need = ONETIME_POOL_TARGET_SIZE - serverCount;
  if (need <= 0) return [];
  const pool = await loadPool(chatId);
  const fresh: PoolEntry[] = [];
  const wireEntries: string[] = [];
  for (let i = 0; i < need; i++) {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    const keypair = kemGenerateKeypair(seed);
    const id = crypto.randomUUID();
    fresh.push({ id, keypairB64: bytesToB64(keypair) });
    wireEntries.push(`${id}:${bytesToB64(kemPublicKeyFromKeypair(keypair))}`);
  }
  await savePool(chatId, [...pool, ...fresh]);
  return wireEntries;
}

// --- PrekeyDO HTTP client (always via OHTTP — see ../hooks/useQueueTransport.ts's header comment on
// why /queue/:id/push goes through the Relay; prekey publish/fetch fire on a comparable, non-one-time
// cadence — every chat mount and every rotation/replenish check — so the same reasoning applies). ---

export interface PrekeyStatus {
  hasBundle: boolean;
  rotatedAt: number | null;
  onetimeCount: number;
}

export async function fetchStatus(chatId: string, cap: string): Promise<PrekeyStatus> {
  const res = await ohttpFetch(`/prekey/${encodeURIComponent(chatId)}/status`, {
    method: "GET",
    headers: { Authorization: `Bearer ${cap}` },
  });
  if (!res.ok) throw new Error(`prekey status fetch failed: HTTP ${res.status}`);
  return (await res.json()) as PrekeyStatus;
}

export interface PublishedBundle {
  verifyingKey: string; // base64
  signedPrekeyPub: string; // base64
  signedPrekeySig: string; // base64
  onetimePubKeys?: string[]; // "id:base64(pubkey)" pairs, additive only
}

export async function publishBundle(chatId: string, cap: string, bundle: PublishedBundle): Promise<{ onetimeCount: number }> {
  const res = await ohttpFetch(`/prekey/${encodeURIComponent(chatId)}/publish`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify(bundle),
  });
  if (!res.ok) throw new Error(`prekey publish failed: HTTP ${res.status}`);
  return (await res.json()) as { onetimeCount: number };
}

export interface FetchedBundle {
  verifyingKey: string;
  signedPrekeyPub: string;
  signedPrekeySig: string;
  onetimePrekey: { id: string; pubKey: string } | null;
}

/** Returns `null` on a 404 (responder hasn't published for this chat yet — the caller should fall
 * back to passively waiting for the queue-pushed `prekey_offer`, same as before this pass). */
export async function fetchAndPopBundle(chatId: string, cap: string): Promise<FetchedBundle | null> {
  const res = await ohttpFetch(`/prekey/${encodeURIComponent(chatId)}/fetch`, {
    method: "GET",
    headers: { Authorization: `Bearer ${cap}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`prekey fetch failed: HTTP ${res.status}`);
  return (await res.json()) as FetchedBundle;
}
