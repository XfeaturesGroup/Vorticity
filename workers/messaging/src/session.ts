// Session capability issuance for the ZK airlock (Flow 2, docs/04). After /auth/session verifies a
// client's Groth16 membership proof, this mints a short-lived signed capability the client presents
// to reach /queue, /conv, /group routes.
//
// THE VERIFICATION KEY (R21-continued, 2026-07): real Semaphore v4, REAL multi-party ceremony —
// upgraded from the local single-party test setup of the initial R21 pass. `VK_HEX` below is
// converted directly from `semaphore-20.json`, part of the official `@zk-kit/semaphore-artifacts`
// npm package (v4.13.0, published by PSE, downloaded via unpkg and sha256-verified against the hash
// npm itself reports for that exact file). That package distributes the output of "Semaphore V4
// Ceremony 1" — a real Groth16 Phase 2 MPC ceremony with 300-400+ independent contributors, finalized
// 2024-09-05 (attestation: gist.github.com/NicoSerranoP/10b09d0539cb87445fee2d3d98cda96a; a second
// contributor's attestation, gist.github.com/hw010101/cccbdf986150b96d706b935668693a0e, confirms the
// ceremony covered all 32 circuits `semaphorev4-1`..`semaphorev4-32` — one per supported LeanIMT tree
// depth 1..32 — of which `semaphorev4-20` is ours). As long as one contributor destroyed their
// randomness, the toxic waste is unrecoverable: the real MPC trust assumption, not a single-operator
// one. See docs/06's R21-continued entry for what was and wasn't independently re-verified (file
// integrity: yes, structural circuit-shape match: yes, full 300+-contribution transcript replay: no —
// that's a separate, heavier audit this pass did not attempt).
// The verifier itself (`zk_verify_groth16_bytes`, packages/vortic-core/src/zk.rs) is STILL UNCHANGED
// from the original mock-circuit pass — only this VK changed, again. See `zk_test.rs`'s
// `official_ceremony_semaphore_v4_vector_verifies` test for this exact VK validated natively against a
// proof generated with the OFFICIAL semaphore-20.wasm/zkey (not a local recompile).
//
// PUBLIC INPUTS remain dynamic, per-request: circom convention (circuit OUTPUTS first, then declared-
// public INPUTS) gives order `[merkleRoot, nullifier, message, scope]`. `buildPublicInputsBytes` below
// builds this from what the caller actually sent, and `index.ts`'s `/auth/session` additionally checks
// the caller's claimed `merkleRoot` against MerkleTreeDO's real CURRENT root before trusting it — a
// valid proof alone only proves "some root existed for which I have a witness"; checking it's the
// CURRENT root rejects a replayed proof against a stale (now-superseded) tree state.
export const VK_HEX =
  "245229d9b076b3c0e8a4d70bde8c1cccffa08a9fae7557b165b3b0dbd653e2c7253ec85988dbb84e46e94b5efa3373b47a000b4ac6c86b2d4b798d274a1823022424bcc1f60a5472685fd50705b2809626e170120acaf441e133a2bd5e61d24407090a82e8fabbd39299be24705b92cf208ee8b3487f6f2b39ff27978a29a1db2b86859fd3d55c9d150fb3f0aeba798826493dd73d357ab0f9fdaced9fc818290ae1135cffdaf227c5dc266740607aa930bc3bd92ddc2b135086d9da2dfd3e2a1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c212c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b1673e455967762f96f57b413424631198e09e7bb1bb06844068fe44f307a8d591230a42b5aa82168743e9817923ea3ebd1d3a55ef1bd91a89eacc55663a026402e92f89b6bd8472ef679fa5d617805180e6e0605423cac37fc15f281939770a7061d9c5b1f377adc54722ccaf3601332ebc07660fec4d89b5c8213031f0aa8b72d3c9778d5cb3ab0bfe4b296e2ed90ed19619b8b353c1043b40e03b568a049a417276cb455cc5d461db37b0b4f6b34f1bb429a76968726205617095e1d39b92d09dae1c6d2e4114c5439c81baa28594cc0ab76e7f32c25c4f780c9e9d6e46a5a0a23d3bedfe1b14bff3eec36492bb9329f56ddbf7f5e1f122838e96dcfe98c4613a1149cf273a308c777146d7f4be2160aac12980d97661fad18cf682b7c5e242b74aaa132494d280ca444d5d2a99cd2bd426ff82d443e2b44b8441733bd450d29b8403a3843d4a77b6c70539d8965e57af369d6f32feab13450f3fa985aed18142569f4ef08c2a1947dcb6e99b5ac52cdd5876c50f02bd6afd62fc810a755110f47bd52a43c690f658374e9f7c2bc4285c641c7116a4ccd2c94f684cbeb7f2a17a29f16b646ebe94c4b2e2c4bc375cd7b002111dd55c4d212e9360cec88c188";

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Build the 128-byte public-input vector `merkleRoot || nullifier || message || scope` (each a
 * 32-byte big-endian BN254 field element, hex-encoded on the wire) in the exact order the real
 * Semaphore v4 circuit's `publicSignals` output uses (see this file's header comment). Throws if any
 * value isn't valid 32-byte hex — the caller (index.ts) should treat that as a 400, not a verify
 * failure, since it's a malformed request rather than a wrong-but-well-formed proof.
 */
export function buildPublicInputsBytes(merkleRoot: string, nullifier: string, message: string, scope: string): Uint8Array {
  const parts = [merkleRoot, nullifier, message, scope].map((hex) => {
    const bytes = hexToBytes(hex);
    if (bytes.length !== 32) throw new Error(`expected a 32-byte hex value, got ${bytes.length} bytes`);
    return bytes;
  });
  const out = new Uint8Array(128);
  parts.forEach((bytes, i) => out.set(bytes, i * 32));
  return out;
}

const CAPABILITY_TTL_MS = 60 * 60 * 1000; // 1h session

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

// Length-independent-leak constant-time compare (both inputs are fixed 32-byte HMACs here anyway).
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Mint a capability = `base64url(payloadJson).base64url(HMAC-SHA256(payloadJson))`. The payload binds
 * the spent nullifier and an expiry; the Messaging Plane can later verify the HMAC with the same key
 * to authorise /queue etc. without any identity lookup. `signingKeyHex` is env.SESSION_SIGNING_KEY.
 */
export async function mintCapability(signingKeyHex: string, nullifier: string): Promise<string> {
  const now = Date.now();
  const payload = JSON.stringify({ nullifier, iat: now, exp: now + CAPABILITY_TTL_MS, plane: "messaging" });
  const payloadBytes = new TextEncoder().encode(payload);

  const key = await crypto.subtle.importKey("raw", hexToBytes(signingKeyHex), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, payloadBytes));
  return `${b64url(payloadBytes)}.${b64url(sig)}`;
}

export interface CapabilityPayload {
  nullifier: string;
  iat: number;
  exp: number;
  plane: string;
}

export type CapabilityVerdict =
  | { valid: true; payload: CapabilityPayload }
  | { valid: false; reason: string };

/**
 * Verify a capability minted by `mintCapability`: recompute the HMAC over the payload segment and
 * compare in constant time (a wrong/forged signature is rejected), then check the expiry. This is
 * how the Messaging Plane authorises /queue, /conv, /group without any identity lookup — it trusts
 * only its own signature over the session's nullifier + expiry.
 */
export async function verifyCapability(signingKeyHex: string, capability: string): Promise<CapabilityVerdict> {
  const dot = capability.indexOf(".");
  if (dot < 0) return { valid: false, reason: "malformed capability (no signature segment)" };
  const payloadSeg = capability.slice(0, dot);
  const sigSeg = capability.slice(dot + 1);

  let payloadBytes: Uint8Array;
  let sig: Uint8Array;
  try {
    payloadBytes = b64urlToBytes(payloadSeg);
    sig = b64urlToBytes(sigSeg);
  } catch {
    return { valid: false, reason: "capability is not valid base64url" };
  }

  const key = await crypto.subtle.importKey("raw", hexToBytes(signingKeyHex), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, payloadBytes));
  if (!timingSafeEqual(sig, expected)) return { valid: false, reason: "bad signature" };

  let payload: CapabilityPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as CapabilityPayload;
  } catch {
    return { valid: false, reason: "capability payload is not JSON" };
  }
  if (typeof payload.exp !== "number" || Date.now() >= payload.exp) {
    return { valid: false, reason: "capability expired" };
  }
  if (payload.plane !== "messaging") return { valid: false, reason: "capability not for this plane" };

  return { valid: true, payload };
}
