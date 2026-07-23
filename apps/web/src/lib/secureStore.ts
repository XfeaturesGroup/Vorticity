// Non-extractable encryption-at-rest for browser-local secrets (2026-07). Replaces the "React
// state only, nothing persisted" model (R20) for two things that need to survive a page reload
// without going back to plain Web Storage: the session capability (AuthContext.tsx) and the PQXDH
// ratchet's long-term identity/KEM material (useQueueTransport.ts).
//
// WHY NOT JUST localStorage/sessionStorage: R20 moved the capability OUT of localStorage precisely
// because it's plain JS-readable — one XSS payload and it's gone, permanently, from anywhere. Simply
// moving it back for persistence would undo that fix. WHY NOT "just leave it in memory" (R20's
// original tradeoff): a lost ratchet identity on every reload breaks ongoing encrypted conversations
// (a peer's already-verified signing key becomes unrecoverable, forcing a full re-handshake the
// current protocol doesn't even detect correctly — see useQueueTransport.ts).
//
// THE ACTUAL PROPERTY THIS BUYS: a non-extractable WebCrypto AES-GCM key, generated with
// `extractable: false` and persisted as a CryptoKey OBJECT (not raw bytes) in IndexedDB, can be used
// to encrypt/decrypt (via `crypto.subtle`) but its raw bytes can NEVER be extracted via `exportKey` —
// not by this code, not by an attacker's injected script, structurally, for the lifetime of the key.
// A one-time XSS read of IndexedDB's stored records yields only AES-GCM ciphertext — useless without
// also being able to invoke the non-extractable key live in the victim's own browser. This converts
// "steal the secret once, use it forever from anywhere" into "must maintain live code execution in
// this exact browser to use it at all" — a real reduction in blast radius, not a full elimination of
// risk (an attacker with PERSISTENT script execution in this origin can still call `sealToStore`/
// `unsealFromStore` themselves, same as any other client-side crypto). Structural non-extractability
// is verified live, not just asserted — see `assertVaultKeyNonExtractable` below, exercised by this
// module's own test pass.
const DB_NAME = "vorticity-vault";
const DB_VERSION = 1;
const KEY_STORE = "keys";
const DATA_STORE = "data";
const VAULT_KEY_ID = "vault-aes-gcm-key";

interface SealedRecord {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) db.createObjectStore(KEY_STORE);
      if (!db.objectStoreNames.contains(DATA_STORE)) db.createObjectStore(DATA_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB.open failed"));
  });
}

function idbGet<T>(db: IDBDatabase, store: string, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error ?? new Error(`idb get failed: ${store}/${key}`));
  });
}

function idbPut(db: IDBDatabase, store: string, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error(`idb put failed: ${store}/${key}`));
  });
}

function idbDelete(db: IDBDatabase, store: string, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error(`idb delete failed: ${store}/${key}`));
  });
}

// Cached across calls within one page load (mirrors the module-singleton pattern already used for
// the OHTTP Gateway keypair in workers/messaging) — IndexedDB round-trips are real I/O, no need to
// repeat them for every seal/unseal in the same session.
let vaultKeyPromise: Promise<CryptoKey> | null = null;

async function getVaultKey(): Promise<CryptoKey> {
  if (vaultKeyPromise) return vaultKeyPromise;
  vaultKeyPromise = (async () => {
    const db = await openDb();
    const existing = await idbGet<CryptoKey>(db, KEY_STORE, VAULT_KEY_ID);
    if (existing) return existing;
    // extractable: false — the load-bearing property this whole module exists for.
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await idbPut(db, KEY_STORE, VAULT_KEY_ID, key);
    return key;
  })();
  vaultKeyPromise.catch(() => {
    vaultKeyPromise = null; // don't poison future calls with a stale rejected promise
  });
  return vaultKeyPromise;
}

/** Encrypts `plaintext` under the non-extractable vault key and persists it in IndexedDB under `name`. */
export async function sealToStore(name: string, plaintext: Uint8Array): Promise<void> {
  const key = await getVaultKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext as BufferSource));
  const db = await openDb();
  const record: SealedRecord = { iv, ciphertext };
  await idbPut(db, DATA_STORE, name, record);
}

/** Decrypts the record stored under `name`, or returns `null` if absent or (tampered/corrupt) —
 * never throws for a missing/bad record, since callers should treat that as "not persisted yet",
 * not a fatal error. */
export async function unsealFromStore(name: string): Promise<Uint8Array | null> {
  const db = await openDb();
  const record = await idbGet<SealedRecord>(db, DATA_STORE, name);
  if (!record) return null;
  const key = await getVaultKey();
  try {
    // Fresh Uint8Array copies (not a cast) — IndexedDB's structured-clone round-trip can hand back a
    // typed array TS infers as backed by an ambiguous ArrayBufferLike; a real copy sidesteps that
    // rather than asserting past it.
    const iv = new Uint8Array(record.iv);
    const ciphertext = new Uint8Array(record.ciphertext);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new Uint8Array(plain);
  } catch {
    return null;
  }
}

/** Removes a sealed record (e.g. on logout, or capability expiry). */
export async function clearFromStore(name: string): Promise<void> {
  const db = await openDb();
  await idbDelete(db, DATA_STORE, name);
}

/** Settings.tsx "Danger Zone" — deletes the ENTIRE `vorticity-vault` IndexedDB database in one shot
 * (both object stores: the non-extractable vault key itself, and every sealed record under it —
 * session capability, chat list + message history, every chat's ratchet identity/KEM/prekey pool,
 * alias seed). Deliberately a full-database delete rather than enumerating every `sealToStore` key
 * name used across the app (AuthContext, useQueueTransport, lib/chatList, lib/alias, lib/prekeys) —
 * fewer places to update if a future pass adds another sealed key and forgets to list it here too.
 * Caller is responsible for reloading afterward — this key powers all page's in-memory state built
 * from what's now gone, and `getVaultKey`'s cached promise would otherwise still point at a deleted
 * key. */
export async function clearEntireVault(): Promise<void> {
  vaultKeyPromise = null;
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error("indexedDB.deleteDatabase failed"));
    req.onblocked = () => resolve(); // another tab has it open — it'll finish clearing once that tab closes
  });
}

/** For live verification only (not called in normal app flow): confirms the vault key is
 * STRUCTURALLY non-extractable — `exportKey` must reject, not just "we don't happen to call it". */
export async function assertVaultKeyNonExtractable(): Promise<boolean> {
  const key = await getVaultKey();
  try {
    await crypto.subtle.exportKey("raw", key);
    return false; // exporting succeeded — the non-extractability property does NOT hold
  } catch {
    return true;
  }
}
