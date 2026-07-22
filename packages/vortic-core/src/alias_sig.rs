//! Ed25519 sign/verify for alias-ownership actions (R18: signed alias revoke). See
//! docs/03-crypto-core.md §8 and the risk register's R18 row ("Nickname squatting / impersonation").
//!
//! Unconditionally compiled (no feature gate): `verify` needs no secret and must run on the edge —
//! `AliasDO` (workers/messaging) checks a revoke request's signature against the plaintext
//! `alias_pub` column it stores at registration time, without ever holding (or needing) the owner's
//! signing key. This is the same "verification is edge-safe" reasoning `zk.rs`/`blind_sig.rs`
//! already apply — see docs/03 crypto invariant #4.
//!
//! Deliberately reuses the SAME long-term identity key `ratchet.rs` derives for PQXDH prekey-bundle
//! signing (`hkdf(seed, "vortic-identity-v1", "ed25519-seed")`), not a second parallel keypair — the
//! `alias.rs` module doc already anticipated this ("reuses ratchet::identity_verifying_key... instead
//! of inventing a parallel Ed25519 keypair type"). `sign` is `client-full`-gated (needs the seed);
//! `verify` is not gated at all — it's the whole point of this module.

use ed25519_dalek::{Signature, VerifyingKey};
use wasm_bindgen::prelude::*;

#[cfg(feature = "client-full")]
use ed25519_dalek::{Signer, SigningKey};
#[cfg(feature = "client-full")]
use crate::util::hkdf_sha256;

#[cfg(feature = "client-full")]
fn identity_signing_key(seed: &[u8]) -> SigningKey {
    let okm = hkdf_sha256(seed, b"vortic-identity-v1", b"ed25519-seed", 32);
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&okm);
    SigningKey::from_bytes(&sk_bytes)
}

/// Sign an arbitrary message with the caller's long-term identity key. Client-only (needs the
/// seed) — used to authorize alias-ownership actions such as revoke (see `alias::revoke_message`
/// for the canonical message this signs over).
#[cfg(feature = "client-full")]
pub fn sign(seed: &[u8], message: &[u8]) -> [u8; 64] {
    identity_signing_key(seed).sign(message).to_bytes()
}

/// Verify an Ed25519 signature against a raw 32-byte public key. No secret involved — safe on the
/// edge. Returns `false` (never panics/traps) on a malformed key or signature, matching this
/// crate's untrusted-input-hardening convention (see `zk.rs`'s header comment for the same rule).
///
/// Uses `verify_strict`, not the plain cofactored `verify` — a REAL bug caught by this module's own
/// negative test, not assumed in advance: `alias_pub` here is CLIENT-SUPPLIED at registration (the
/// server never derives it), so an attacker can register a row with a degenerate key of their own
/// choosing. With plain (cofactored) `verify`, an all-zero 32-byte "public key" paired with an
/// all-zero 64-byte "signature" verified as valid for ANY message — the well-known Ed25519
/// identity-point/zero-signature malleability, not a hand-rolled math error (`s·B = 0 = R + k·A`
/// trivially holds when `A = R = s = 0`, independent of the message or `k`). A legitimately derived
/// `identity_verifying_key(seed)` can never BE the identity point (RFC 8032 scalar clamping makes
/// the signing scalar non-zero), so this only ever rejects deliberately-degenerate input, never a
/// real key. `verify_strict` is ed25519-dalek's own documented mitigation for exactly this class of
/// signature malleability — reused, not reimplemented, per this crate's standing rule against
/// hand-rolling primitives of this kind.
pub fn verify(pubkey: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(message, &signature).is_ok()
}

#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn alias_sign_action(seed: &[u8], message: &[u8]) -> Vec<u8> {
    sign(seed, message).to_vec()
}

/// wasm-bindgen boundary: bounds-checks lengths itself (never trusts the caller) before touching
/// the fixed-size crypto types above — same defensive shape as `zk_verify_groth16_bytes`.
#[wasm_bindgen]
pub fn alias_verify_action(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(s) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    verify(&pk, message, &s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "client-full")]
    #[test]
    fn sign_then_verify_round_trips() {
        let seed = [7u8; 32];
        let msg = b"vortic-alias-revoke-v1\x00\x01\x02";
        let sig = sign(&seed, msg);
        let pubkey_vec = crate::ratchet::identity_verifying_key(&seed);
        let pubkey: [u8; 32] = pubkey_vec.try_into().unwrap();
        assert!(verify(&pubkey, msg, &sig));
    }

    #[cfg(feature = "client-full")]
    #[test]
    fn tampered_message_rejected() {
        let seed = [7u8; 32];
        let sig = sign(&seed, b"revoke:aaa");
        let pubkey_vec = crate::ratchet::identity_verifying_key(&seed);
        let pubkey: [u8; 32] = pubkey_vec.try_into().unwrap();
        assert!(!verify(&pubkey, b"revoke:bbb", &sig));
    }

    #[cfg(feature = "client-full")]
    #[test]
    fn wrong_key_rejected() {
        let seed_a = [7u8; 32];
        let seed_b = [8u8; 32];
        let msg = b"revoke:aaa";
        let sig = sign(&seed_a, msg);
        let wrong_pubkey_vec = crate::ratchet::identity_verifying_key(&seed_b);
        let wrong_pubkey: [u8; 32] = wrong_pubkey_vec.try_into().unwrap();
        assert!(!verify(&wrong_pubkey, msg, &sig));
    }

    #[test]
    fn malformed_pubkey_or_sig_bytes_rejected_not_panicking() {
        assert!(!verify(&[0u8; 32], b"msg", &[0u8; 64]));
    }
}
