// Phase C media/attachments (2026-07). Client half of workers/messaging's coreMediaPut/coreMediaGet
// — see that file's header comment for the server-side design (proxy-through-Worker, OHTTP-wrapped,
// bounded to MEDIA_MAX_BYTES, deliberately NOT the presigned-direct-to-R2 pattern docs/03 §10
// originally sketched for media). Each attachment gets a FRESH random 32-byte content key, unrelated
// to the ratchet session — same Signal/Telegram pattern already documented on `AttachmentMeta`
// (lib/chat.ts): the server only ever custodies the encrypted blob at `mediaId`, the decryption key
// travels ONLY inside the ratchet-encrypted `MessagePayload` itself.
import { decryptMessage, encryptMessage } from "@vorticity/vortic-core";
import { ohttpFetch } from "./ohttp";
import type { AttachmentMeta } from "./chat";

export const MEDIA_MAX_BYTES = 20 * 1024 * 1024;

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
function randomHex64(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function readErrorBody(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string };
    return body.error ? ` — ${body.error}` : "";
  } catch {
    return "";
  }
}

/** Encrypts + uploads `file` under a fresh random key, returning the `AttachmentMeta` to embed in a
 * `text`-kind `MessagePayload` (the key travels there, not with the upload). */
export async function uploadAttachment(file: File, cap: string): Promise<AttachmentMeta> {
  if (file.size > MEDIA_MAX_BYTES) {
    throw new Error(`"${file.name}" is too large — attachments are capped at ${Math.floor(MEDIA_MAX_BYTES / (1024 * 1024))} MiB`);
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  // `encryptMessage`'s plaintext argument is a UTF-8 string (same convention the ratchet itself
  // uses) — base64-encode the raw file bytes first so arbitrary binary content survives intact.
  // Its return value is ALREADY base64(nonce||ciphertext||tag) — that's exactly the wire shape
  // `coreMediaPut`'s `blob` field expects, no further encoding needed.
  const payload = encryptMessage(key, bytesToB64(bytes));
  const mediaId = randomHex64();

  const res = await ohttpFetch(`/media/${mediaId}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify({ blob: payload }),
  });
  if (!res.ok) throw new Error(`media upload failed: HTTP ${res.status}${await readErrorBody(res)}`);

  return { mediaId, key: bytesToB64(key), mime: file.type || "application/octet-stream", name: file.name, size: file.size };
}

/** Downloads + decrypts an attachment back to a `Blob`, given the `AttachmentMeta` that arrived
 * inside a decrypted `MessagePayload`. */
export async function downloadAttachment(meta: AttachmentMeta, cap: string): Promise<Blob> {
  const res = await ohttpFetch(`/media/${meta.mediaId}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${cap}` },
  });
  if (!res.ok) throw new Error(`media download failed: HTTP ${res.status}${await readErrorBody(res)}`);
  const { blob: payload } = (await res.json()) as { blob: string };
  const key = b64ToBytes(meta.key);
  const bytes = b64ToBytes(decryptMessage(key, payload));
  return new Blob([bytes.buffer as ArrayBuffer], { type: meta.mime });
}

// Module-scope, in-memory-only cache: repeated renders of the same message (re-renders, scrolling
// back into view) shouldn't redundantly re-download/re-decrypt the same attachment. Deliberately not
// persisted and object URLs are never revoked — acceptable at this app's current chat/attachment
// scale (an alpha, not a media-heavy app); revisit if that stops being true.
const objectUrlCache = new Map<string, Promise<string>>();

export function getAttachmentObjectUrl(meta: AttachmentMeta, cap: string): Promise<string> {
  const cached = objectUrlCache.get(meta.mediaId);
  if (cached) return cached;
  const promise = downloadAttachment(meta, cap).then((blob) => URL.createObjectURL(blob));
  objectUrlCache.set(meta.mediaId, promise);
  promise.catch(() => objectUrlCache.delete(meta.mediaId));
  return promise;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
