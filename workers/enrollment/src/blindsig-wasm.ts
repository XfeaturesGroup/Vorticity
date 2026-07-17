// Loads the vortic-core WASM ISSUER profile into the Enrollment Worker so `/token/issue` can run the
// REAL RSA blind-signature operation (src/blind_sig.rs, RFC 9474 RSABSSA) — no shared secret with
// Messaging, ever (see blind_sig.rs's module doc for the full rationale).
//
// We import `pkg/issuer` — built with `wasm-pack --target web --features edge-verify-only,issuer-full`
// (packages/vortic-core `build:issuer`). That is a DIFFERENT WASM binary than the one
// `workers/messaging` loads (`pkg/msg`, `edge-verify-only` WITHOUT `issuer-full`): `pkg/issuer`
// exports `blindsig_sign` (needs `env.ISSUER_SIGNING_KEY_PEM`); `pkg/msg` does not even compile that
// function in (verified via `pkg/msg/vortic_core.d.ts` — no `blindsig_sign` export exists there).
//
// `.wasm` is imported as a `WebAssembly.Module` and instantiated synchronously at module load via
// `initSync` — no top-level await, no network fetch. Same pattern as this Worker's old
// oprf-wasm.ts (removed — see index.ts's `/token/issue`, which replaces `/oprf/issue`).
import wasmModule from "../../../packages/vortic-core/pkg/issuer/vortic_core_bg.wasm";
import { initSync, blindsig_sign } from "../../../packages/vortic-core/pkg/issuer/vortic_core.js";

initSync({ module: wasmModule });

/**
 * Sign a client's blinded message under the issuer's RSA-3072 secret key. The issuer never sees the
 * unblinded message — that's the entire point of RSABSSA (see blind_sig.rs). Throws on a malformed
 * blinded message or an unparsable `skPem`.
 */
export function blindSign(skPem: string, blindedMsg: Uint8Array): Uint8Array {
  return blindsig_sign(skPem, blindedMsg);
}
