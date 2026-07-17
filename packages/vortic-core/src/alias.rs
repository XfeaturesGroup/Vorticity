//! Opt-in public @alias records. See docs/03-crypto-core.md §8.
//!
//! `lookup_key`/`derive_record_key` are pure functions of the nickname and can run anywhere
//! (client to register/resolve, edge never needs the nickname itself — it only ever sees
//! `lookup_key` and ciphertext, per docs/04 `AliasDO`).

pub fn lookup_key(/* nickname: &str */) -> [u8; 32] {
    todo!("Phase 3: H(\"vortic-alias-v1\" || nickname)")
}

#[cfg(feature = "client-full")]
pub fn derive_record_key(/* nickname: &str */) -> [u8; 32] {
    todo!("Phase 3: HKDF(\"vortic-alias-enc\" || nickname) — client-only, edge never derives this")
}

#[cfg(feature = "client-full")]
pub struct AliasOwnershipKey; // TODO(Phase 3): Ed25519 alias_key, included in E2EE backups
