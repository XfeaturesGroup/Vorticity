//! MLS (RFC 9420) wrapper around `mls-rs`/OpenMLS for group messaging with PCS at scale.
//! See docs/03-crypto-core.md §5. Client-side only — `GroupDO` on the edge only orders
//! ciphertext (see docs/04), it never calls into this module.

#[cfg(feature = "client-full")]
pub struct GroupState; // TODO(Phase 1): wrap mls-rs group state, epoch tracking

#[cfg(feature = "client-full")]
impl GroupState {
    pub fn create(/* ciphersuite: CipherSuite */) -> Self {
        todo!("Phase 1: mls-rs group creation, hybrid PQ ciphersuite when available")
    }
}
