// Loads the vortic-core WASM (edge profile) into the Messaging Worker so /auth/session can run the
// REAL Groth16/BN254 verifier (src/zk.rs) over a client-supplied proof — no snarkjs, no trusting the
// client. Same wiring as workers/enrollment/src/oprf-wasm.ts: import the `pkg/msg` bundle built with
// `wasm-pack --target web --features edge-verify-only` (packages/vortic-core `build:msg`), which
// contains ONLY the verify-only surface (zk_verify + oprf_evaluate) — no ml-kem, no decryption, no
// Groth16 *prover* — so docs/03 invariant #4 (the edge holds no decryption key, only verifies) holds
// at the binary level.
//
// `.wasm` is imported as a `WebAssembly.Module` and instantiated synchronously at module load via
// `initSync` — no top-level await, no network fetch.
import wasmModule from "../../../packages/vortic-core/pkg/msg/vortic_core_bg.wasm";
import { initSync, zk_verify_groth16_bytes } from "../../../packages/vortic-core/pkg/msg/vortic_core.js";

initSync({ module: wasmModule });

/**
 * Verify a Groth16/BN254 proof against a verifying key and public inputs, all in zk.rs's big-endian
 * byte contract (VK 768B, proof 256B, inputs = 32B * nPublic). Returns false (never throws) on any
 * malformed/failing input — the Rust verifier is hardened for untrusted bytes.
 */
export function verifyGroth16(vk: Uint8Array, proof: Uint8Array, publicInputs: Uint8Array): boolean {
  return zk_verify_groth16_bytes(vk, proof, publicInputs);
}
