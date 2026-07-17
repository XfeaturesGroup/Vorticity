// Loads the vortic-core WASM verify-only profile into the Messaging Worker so `/membership/insert`
// can run the REAL RSA blind-signature verification (src/blind_sig.rs, RFC 9474 RSABSSA) over a
// client-presented redemption token — no shared secret with Enrollment, ever (see blind_sig.rs's
// module doc, and issuer-keys.ts's header comment, for the full rationale).
//
// We import the SAME `pkg/msg` bundle zk-wasm.ts already loads (`wasm-pack --target web --features
// edge-verify-only`, packages/vortic-core `build:msg`) — that profile does NOT enable `issuer-full`,
// so `blindsig_sign` (which needs the issuer's SECRET key) is not merely unreachable here, it was
// never compiled into this binary at all (confirmed via `pkg/msg/vortic_core.d.ts`, which has no
// `blindsig_sign` export — unlike `pkg/issuer/vortic_core.d.ts`, which workers/enrollment loads).
// `initSync` only runs once per isolate regardless of how many modules call it (idempotent within
// wasm-bindgen's own glue code), so it's safe for both zk-wasm.ts and this file to each `initSync`
// against the same `pkg/msg` bundle.
import wasmModule from "../../../packages/vortic-core/pkg/msg/vortic_core_bg.wasm";
import { initSync, blindsig_verify } from "../../../packages/vortic-core/pkg/msg/vortic_core.js";

initSync({ module: wasmModule });

/**
 * Verify a redemption token `(msg, msgRandomizer, sig)` against the issuer's PUBLIC key. Never
 * throws — malformed input (wrong-length randomizer, unparsable PEM, bad signature) all verify
 * `false`, matching this crate's other untrusted-input verifiers (`zk_verify_groth16_bytes`).
 */
export function verifyBlindSig(pkPem: string, msg: Uint8Array, msgRandomizer: Uint8Array, sig: Uint8Array): boolean {
  return blindsig_verify(pkPem, msg, msgRandomizer, sig);
}
