//! Opt-in public @alias records. See docs/03-crypto-core.md §8.
//!
//! `lookup_key`/`derive_record_key` are pure functions of the nickname and can run anywhere
//! (client to register/resolve, edge never needs the nickname itself — it only ever sees
//! `lookup_key` and ciphertext, per docs/04 `AliasDO`).
//!
//! Implemented for real (2026-07, "alias contact establishment" pass) — closes the Phase-0
//! `todo!()` stubs. `AliasDO.ts` (`workers/messaging`) already existed and is fully wired
//! (register/resolve, PoW-gated) from an earlier pass; what was missing was the CLIENT half that
//! derives these two values in the first place. See `pow.rs` in this same crate for the other
//! missing piece (a real Hashcash miner) this pass also closes.

use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

#[cfg(feature = "client-full")]
use crate::util::hkdf_sha256;

/// `H("vortic-alias-v1" || nickname)` — what `AliasDO` indexes on (docs/03 §8.1). Domain-separated
/// via string concatenation (not a distinct HKDF `info` field) to match the docs' literal notation
/// exactly, and because this is a single plain hash, not a key derivation — no need for HKDF's
/// extract/expand structure here at all, unlike `derive_record_key` below.
pub fn lookup_key(nickname: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vortic-alias-v1");
    hasher.update(nickname.as_bytes());
    hasher.finalize().into()
}

/// `HKDF("vortic-alias-enc" || nickname)` — symmetric AEAD key for the alias record, derivable by
/// anyone who knows the nickname (the registering owner, and anyone who later looks it up), and by
/// no one else — `AliasDO` itself never learns the nickname, only `lookup_key` and the resulting
/// ciphertext (docs/03 §8.1's residual-risk note). Concrete assignment within docs' looser prose
/// spec: `ikm = nickname` (the actual secret entropy — matches "derivable only if you know the
/// nickname"), `salt = ""`, `info = "vortic-alias-enc"` (domain separation) — the same HKDF shape
/// `apps/web/src/lib/deviceLink.ts`'s `deriveAeadKey` already uses for an analogous "shared secret
/// string -> AES-GCM key" derivation, just with a different domain string and IKM source.
#[cfg(feature = "client-full")]
pub fn derive_record_key(nickname: &str) -> [u8; 32] {
    let okm = hkdf_sha256(nickname.as_bytes(), &[], b"vortic-alias-enc", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

// No dedicated `AliasOwnershipKey` type here (the Phase-0 skeleton's TODO): `alias_pub` IS
// `ratchet::identity_verifying_key(seed)`'s output — the same long-term identity key that signs
// PQXDH prekey bundles, not a second parallel keypair. Sign/verify for ownership actions live in
// `alias_sig.rs` (kept separate from this module so `verify` stays reachable from `edge-verify-only`
// builds — `ratchet.rs` itself is `client-full`-only per lib.rs, since it also holds ratchet
// decrypt state that must never link into the edge binary).
//
// R18 (2026-07, "signed alias revoke" pass): `AliasDO.ts` now stores `alias_pub` as a plaintext
// column (populated at register time) and verifies a signature over `revoke_message` below before
// deleting a row — closing the "no signed update/revoke" gap this comment used to flag. Update
// (replacing a record's contents in place) is deliberately NOT implemented in this pass — revoke +
// re-register (a fresh PoW stamp) covers the same outcome and keeps the change smaller; add it
// later by reusing this exact signature mechanism with a different domain-separated message.

/// Canonical message signed to authorize revoking a registered alias (R18). Domain-separated and
/// bound to the exact `lookup_key` being revoked — not reusable against a different alias. No
/// separate nonce/timestamp is needed: `AliasDO` verifies against whatever `alias_pub` is CURRENTLY
/// stored for that `lookup_key`, so a captured signature only ever authorizes revoking the same
/// (lookup_key, alias_pub) pairing it was made under — replaying it after a successful revoke just
/// 404s (row gone), and replaying it after a DIFFERENT owner re-registers the same nickname fails
/// the pubkey check outright (the new row's `alias_pub` differs).
pub fn revoke_message(lookup_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = b"vortic-alias-revoke-v1".to_vec();
    msg.extend_from_slice(lookup_key);
    msg
}

#[wasm_bindgen]
pub fn alias_revoke_message(lookup_key: &[u8]) -> Vec<u8> {
    let Ok(key) = <[u8; 32]>::try_from(lookup_key) else {
        return Vec::new();
    };
    revoke_message(&key)
}

#[wasm_bindgen]
pub fn alias_lookup_key(nickname: &str) -> Vec<u8> {
    lookup_key(nickname).to_vec()
}

#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn alias_derive_record_key(nickname: &str) -> Vec<u8> {
    derive_record_key(nickname).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_key_is_deterministic_32_bytes_and_nickname_sensitive() {
        let a = lookup_key("nightowl_42");
        let b = lookup_key("nightowl_42");
        let c = lookup_key("nightowl_43");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, c);
    }

    #[cfg(feature = "client-full")]
    #[test]
    fn record_key_is_deterministic_and_independent_from_lookup_key() {
        let rec_a = derive_record_key("nightowl_42");
        let rec_b = derive_record_key("nightowl_42");
        assert_eq!(rec_a, rec_b);
        // Two different domain-separated derivations from the same nickname must not collide —
        // if they did, `lookup_key` would double as an oracle for `derive_record_key`, defeating
        // the whole "the DO holds lookup_key -> ciphertext but cannot read the ciphertext" design.
        assert_ne!(rec_a, lookup_key("nightowl_42"));
    }

    #[test]
    fn revoke_message_is_deterministic_and_lookup_key_sensitive() {
        let key_a = lookup_key("nightowl_42");
        let key_b = lookup_key("nightowl_43");
        assert_eq!(revoke_message(&key_a), revoke_message(&key_a));
        assert_ne!(revoke_message(&key_a), revoke_message(&key_b));
        assert!(revoke_message(&key_a).starts_with(b"vortic-alias-revoke-v1"));
    }

    #[test]
    fn lookup_key_matches_a_known_test_vector() {
        // Cross-check against a value independently computed via Node's `crypto.createHash` over
        // the literal byte concatenation `"vortic-alias-v1" + "nightowl_42"` — proves this isn't
        // just internally self-consistent but matches what a JS-side implementation (e.g. a
        // future edge-side sanity check) would independently compute for the same input.
        let digest = lookup_key("nightowl_42");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "79b29f66c2cf5b0c3c5b6310405ef6459ff7b45e3a176636622d1b8ba896481c");
    }
}
