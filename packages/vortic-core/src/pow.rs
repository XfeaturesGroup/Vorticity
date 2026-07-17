//! Hashcash-family Proof-of-Work stamps (anti-scrape/anti-spam on the alias plane).
//! See docs/03-crypto-core.md §8.3. `mint` is client-only (expensive by design); `verify` must
//! be cheap enough to run on `edge-verify-only` per message/request (docs/06 — PoW is the cost
//! inverse of ZK: expensive to mint, ~free to check).

#[cfg(feature = "client-full")]
pub fn mint(/* resource: &[u8], epoch: u64, difficulty_bits: u8 */) -> Vec<u8> {
    todo!("Phase 3: SHA-256 Hashcash baseline; Argon2id hardened option under load")
}

pub fn verify(/* stamp: &[u8], resource: &[u8], epoch: u64, difficulty_bits: u8 */) -> bool {
    todo!("Phase 3: single hash + leading-zero-bit check — must be edge-cheap")
}
