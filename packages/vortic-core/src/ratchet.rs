//! Triple Ratchet (Double Ratchet + Sparse Post-Quantum Ratchet), Signal SPQR-style.
//! See docs/03-crypto-core.md §4. Client-side only.

#[cfg(feature = "client-full")]
pub struct RatchetState; // TODO(Phase 1): root key, chain keys, PQ re-mix schedule

#[cfg(feature = "client-full")]
impl RatchetState {
    pub fn init_from_pqxdh(/* shared_secret: &[u8] */) -> Self {
        todo!("Phase 1: derive initial root/chain keys from PQXDH output")
    }
}
