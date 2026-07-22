// Loads the vortic-core WASM (edge profile) so `pow.ts` can verify Argon2id-hardened PoW stamps for
// real (memory-hard hashing isn't reasonable to hand-roll in pure JS/WebCrypto, unlike the SHA-256
// mode, which stays a plain `crypto.subtle.digest` call — no reason to pay a WASM call for a hash
// WebCrypto already does natively and fast). Same `pkg/msg` bundle (edge-verify-only,
// `wasm-pack --target web --features edge-verify-only`) `zk-wasm.ts`/`blindsig-wasm.ts` already load
// — `initSync` is idempotent (confirmed safe to call from multiple loaders importing the same
// module, see docs/06's "Key Transparency consistency proofs" pass note) and ES module caching means
// this only instantiates the WASM once per Worker isolate regardless of how many loader files import
// it. `pow_verify` (packages/vortic-core/src/pow.rs) is UNCONDITIONAL — present in this edge-only
// profile, confirmed via the generated `.d.ts` — matching this crate's "verification is edge-safe"
// precedent for every other primitive (Groth16, blind-sig, alias-sig).
import wasmModule from "../../../packages/vortic-core/pkg/msg/vortic_core_bg.wasm";
import { initSync, pow_verify } from "../../../packages/vortic-core/pkg/msg/vortic_core.js";

initSync({ module: wasmModule });

/**
 * Verifies a full PoW stamp (`ver:alg:bits:epoch:resource:salt:counter`) under WHICHEVER `alg` it
 * declares, computing a REAL Argon2id digest via WASM when `alg === "argon2id"` (a plain SHA-256
 * stamp also verifies correctly here, but `pow.ts` never routes one to this function — see that
 * file's dispatch). Returns false (never throws) on any malformed input — same hardened-for-
 * untrusted-input contract as every other WASM boundary in this Worker.
 */
export function verifyPowStampWasm(stamp: string, expectedResource: string, minBits: number): boolean {
  return pow_verify(stamp, expectedResource, minBits);
}
