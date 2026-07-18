// Shared HPKE ciphersuite + RFC 9458 constants, used identically by both client.ts and gateway.ts.
// Ciphersuite choice: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM — this is RFC 9180's
// "recommended" suite and RFC 9458's own worked example, and X25519 matches this codebase's existing
// convention everywhere else (kem.rs, ratchet.rs). `@hpke/core` ships DHKEM-X25519 directly (not a
// separate package) — confirmed by reading its actual `mod.d.ts` before depending on it, not assumed.
import { Aes128Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";

export const KEM_ID = 0x0020; // DHKEM(X25519, HKDF-SHA256), RFC 9180 registry
export const KDF_ID = 0x0001; // HKDF-SHA256
export const AEAD_ID = 0x0001; // AES-128-GCM

export const MEDIA_TYPE_KEY_CONFIG = "application/ohttp-keys";
export const MEDIA_TYPE_REQUEST = "message/ohttp-req";
export const MEDIA_TYPE_RESPONSE = "message/ohttp-res";

export function newSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
}

/** hdr = key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2) — RFC 9458 §4.1, shared by request encap
 * (as a prefix of the encapsulated request) and as part of the HPKE `info` binding on both sides. */
export function encodeHeader(keyId: number): Uint8Array {
  const out = new Uint8Array(7);
  const view = new DataView(out.buffer);
  view.setUint8(0, keyId);
  view.setUint16(1, KEM_ID);
  view.setUint16(3, KDF_ID);
  view.setUint16(5, AEAD_ID);
  return out;
}

export function decodeHeader(bytes: Uint8Array): { keyId: number; kemId: number; kdfId: number; aeadId: number } {
  if (bytes.length < 7) throw new Error("ohttp: encapsulated request shorter than the 7-byte header");
  const view = new DataView(bytes.buffer, bytes.byteOffset, 7);
  return { keyId: view.getUint8(0), kemId: view.getUint16(1), kdfId: view.getUint16(3), aeadId: view.getUint16(5) };
}

const REQUEST_LABEL = new TextEncoder().encode("message/bhttp request");
const RESPONSE_EXPORT_CONTEXT = new TextEncoder().encode("message/bhttp response");
const KEY_LABEL = new TextEncoder().encode("key");
const NONCE_LABEL = new TextEncoder().encode("nonce");

/** `info = "message/bhttp request" || 0x00 || hdr` — RFC 9458 §4.3. */
export function buildRequestInfo(hdr: Uint8Array): Uint8Array {
  const out = new Uint8Array(REQUEST_LABEL.length + 1 + hdr.length);
  out.set(REQUEST_LABEL, 0);
  out[REQUEST_LABEL.length] = 0x00;
  out.set(hdr, REQUEST_LABEL.length + 1);
  return out;
}

/**
 * RFC 5869 HKDF-Extract = HMAC-Hash(salt, IKM), called directly via WebCrypto rather than
 * `suite.kdf.extract()`: that method artificially rejects any `salt` whose length isn't exactly the
 * hash size (`@hpke/common`'s `hkdf.js` — a narrowing of RFC 5869 to match RFC 9180's own *internal*
 * usage pattern, not a requirement of Extract itself, since RFC 5869's salt may be any length). RFC
 * 9458 §4.4's `salt = concat(enc, response_nonce)` is 48 bytes for our suite (32-byte X25519 `enc` +
 * 16-byte `response_nonce`), so the library's own method cannot be used here — confirmed by a failing
 * round-trip test before working around it, not assumed in advance. `suite.kdf.expand()` has no such
 * restriction and is reused unmodified below.
 */
async function hkdfExtractSha256(salt: Uint8Array, ikm: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("raw", salt.buffer as ArrayBuffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, ikm);
}

/**
 * RFC 9458 §4.4's response-key derivation, identical on both the sealing (Gateway) and opening
 * (Client) side — both start from an HPKE context's `.export()` (which the HPKE key schedule
 * guarantees is identical for a Sender and its matching Recipient) plus the same `enc` and
 * `response_nonce`, so this one function is correct to share rather than reimplement per side.
 */
export async function deriveResponseKeyNonce(
  suite: CipherSuite,
  exportSecret: ArrayBuffer,
  enc: ArrayBuffer,
  responseNonce: Uint8Array,
): Promise<{ key: ArrayBuffer; nonce: ArrayBuffer }> {
  const salt = new Uint8Array(enc.byteLength + responseNonce.length);
  salt.set(new Uint8Array(enc), 0);
  salt.set(responseNonce, enc.byteLength);
  const prk = await hkdfExtractSha256(salt, exportSecret);
  const key = await suite.kdf.expand(prk, KEY_LABEL, suite.aead.keySize);
  const nonce = await suite.kdf.expand(prk, NONCE_LABEL, suite.aead.nonceSize);
  return { key, nonce };
}

export function responseExportLength(suite: CipherSuite): number {
  return Math.max(suite.aead.nonceSize, suite.aead.keySize);
}

export { RESPONSE_EXPORT_CONTEXT };
