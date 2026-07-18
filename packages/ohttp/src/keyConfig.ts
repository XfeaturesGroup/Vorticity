// RFC 9458 §3.1 — the Gateway's published Key Configuration. Published at a Gateway-chosen URL
// (`GET /ohttp/keys` in this codebase — see workers/messaging) with media type
// `application/ohttp-keys`; a Client fetches it before it can encapsulate anything.
//
// Wire format (all fixed-width big-endian, NOT QUIC varints — those are a Binary-HTTP-only encoding,
// this structure is plain TLS presentation-language per the RFC):
//   Key Identifier (1 byte)
//   HPKE KEM ID    (2 bytes)
//   HPKE Public Key (Npk bytes — 32 for X25519)
//   Symmetric Algorithms Length (2 bytes, byte length of what follows)
//   Symmetric Algorithms[] { KDF ID (2 bytes), AEAD ID (2 bytes) }
import { AEAD_ID, KDF_ID, KEM_ID } from "./hpkeSuite.js";

export interface KeyConfig {
  keyId: number;
  kemId: number;
  publicKey: Uint8Array;
  /** (kdfId, aeadId) pairs the Gateway supports for this key. This codebase's Gateway only ever
   * offers exactly one — (HKDF-SHA256, AES-128-GCM) — but decode accepts more for spec conformance. */
  algorithms: { kdfId: number; aeadId: number }[];
}

export function encodeKeyConfig(keyId: number, publicKey: Uint8Array): Uint8Array {
  const algBytes = 4; // one (kdfId, aeadId) pair
  const out = new Uint8Array(1 + 2 + publicKey.length + 2 + algBytes);
  const view = new DataView(out.buffer);
  let offset = 0;
  view.setUint8(offset, keyId);
  offset += 1;
  view.setUint16(offset, KEM_ID);
  offset += 2;
  out.set(publicKey, offset);
  offset += publicKey.length;
  view.setUint16(offset, algBytes);
  offset += 2;
  view.setUint16(offset, KDF_ID);
  offset += 2;
  view.setUint16(offset, AEAD_ID);
  offset += 2;
  return out;
}

/** X25519 public keys are always 32 bytes — the only KEM this package's Gateway/Client support, so
 * this length is fixed rather than looked up from a KEM registry table we'd otherwise need to carry. */
const X25519_PUBLIC_KEY_LEN = 32;

export function decodeKeyConfig(bytes: Uint8Array): KeyConfig {
  if (bytes.length < 1 + 2 + X25519_PUBLIC_KEY_LEN + 2) {
    throw new Error("ohttp: key config shorter than the minimum fixed-field length");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  let offset = 0;
  const keyId = view.getUint8(offset);
  offset += 1;
  const kemId = view.getUint16(offset);
  offset += 2;
  if (kemId !== KEM_ID) {
    throw new Error(`ohttp: key config declares kem_id 0x${kemId.toString(16)}, this package only supports 0x${KEM_ID.toString(16)} (X25519)`);
  }
  const publicKey = bytes.slice(offset, offset + X25519_PUBLIC_KEY_LEN);
  offset += X25519_PUBLIC_KEY_LEN;
  const algLen = view.getUint16(offset);
  offset += 2;
  if (offset + algLen > bytes.length) throw new Error("ohttp: key config truncated in the symmetric-algorithms list");
  const algorithms: { kdfId: number; aeadId: number }[] = [];
  const algEnd = offset + algLen;
  while (offset < algEnd) {
    const kdfId = view.getUint16(offset);
    offset += 2;
    const aeadId = view.getUint16(offset);
    offset += 2;
    algorithms.push({ kdfId, aeadId });
  }
  if (offset !== algEnd) throw new Error("ohttp: symmetric-algorithms length is not a multiple of 4 bytes");
  return { keyId, kemId, publicKey, algorithms };
}
