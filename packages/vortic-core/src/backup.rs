//! Local-first E2EE backups: BIP39 recovery phrase → Argon2id → AES-256-GCM.
//! See docs/03-crypto-core.md §11. Client-side only.

#[cfg(feature = "client-full")]
pub fn derive_backup_key(/* phrase: &str */) -> [u8; 32] {
    todo!("Phase 1: BIP39 seed -> Argon2id(m=256MiB, t=3, p=1) -> master backup key")
}

#[cfg(feature = "client-full")]
pub fn export(/* state: &[u8], key: &[u8; 32] */) -> Vec<u8> {
    todo!("Phase 1: AES-256-GCM encrypt full local state for export")
}
