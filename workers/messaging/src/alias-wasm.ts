// Loads the vortic-core WASM verify-only profile into the Messaging Worker so `AliasDO`'s /revoke
// route can check a real Ed25519 signature (src/alias_sig.rs, R18) against the plaintext
// `alias_pub` column it stores at registration time — no secret key ever touches this Worker
// (`alias_sign_action`, the secret-key half, isn't even compiled into this bundle — confirmed via
// `pkg/msg/vortic_core.d.ts`, same check `blindsig-wasm.ts` already documents for its own primitive).
//
// Same `pkg/msg` bundle zk-wasm.ts/blindsig-wasm.ts already load; `initSync` is idempotent across
// however many of these loader modules call it in the same isolate.
import wasmModule from "../../../packages/vortic-core/pkg/msg/vortic_core_bg.wasm";
import { initSync, alias_verify_action, alias_revoke_message } from "../../../packages/vortic-core/pkg/msg/vortic_core.js";

initSync({ module: wasmModule });

/**
 * Verify an Ed25519 signature over `message` against a raw 32-byte public key. Never throws —
 * malformed input (wrong-length key/sig, degenerate/small-order key) all verify `false` (uses
 * `verify_strict`, not the plain cofactored `verify` — see alias_sig.rs's header comment for the
 * real malleability bug this avoided).
 */
export function verifyAliasOwnership(pubkey: Uint8Array, message: Uint8Array, sig: Uint8Array): boolean {
  return alias_verify_action(pubkey, message, sig);
}

/**
 * The exact canonical byte message a revoke signature must cover for the given `lookup_key` (32
 * bytes). Built via the SAME Rust function (`alias::revoke_message`) the client signs against —
 * reused, not re-derived by hand in TS, so the two sides can never drift on the byte format.
 */
export function aliasRevokeMessage(lookupKey: Uint8Array): Uint8Array {
  return alias_revoke_message(lookupKey);
}
