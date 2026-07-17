//! Linkable ring signatures (bLSAG, Ristretto255) for anonymous group authorship with
//! per-epoch spam-linkability. See docs/03-crypto-core.md §5 ("Anonymous authorship").
//! Sign = client-side. Verify = both client and edge (edge never learns the signer).

pub struct RingSignature; // TODO(Phase 1): bLSAG over curve25519-dalek Ristretto255

#[cfg(feature = "client-full")]
pub fn sign(/* message: &[u8], ring: &[PublicKey], secret: &Scalar */) -> RingSignature {
    todo!("Phase 1: bLSAG sign, tag keyed by H(group || epoch)")
}

pub fn verify(/* sig: &RingSignature, message: &[u8], ring: &[PublicKey] */) -> bool {
    todo!("Phase 1: bLSAG verify — available on both client-full and edge-verify-only builds")
}
