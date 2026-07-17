//! VOPRF blind enrollment (Ristretto255), basic wrapper. See docs/03-crypto-core.md §2.
//!
//! Three distinct roles, each compiled for a different target — do not conflate them:
//!   - `blind` / `unblind` : the enrolling CLIENT. client-full only.
//!   - `evaluate`          : the Enrollment Worker, which holds the OPRF key `k`. Intentionally
//!                           NOT gated by client-full/edge-verify-only — it belongs to neither
//!                           profile; it is wired only into `workers/enrollment`'s build, never
//!                           `workers/messaging`'s. Safe to always-compile: `evaluate` needs the
//!                           secret `oprf_key`, which the Messaging Plane never holds — the
//!                           function is inert without it, and it performs no decryption. See
//!                           docs/04 plane-isolation.
//!
//! Scope note: this is the point-arithmetic core of a blind evaluation (blind → evaluate →
//! unblind), matching what docs/03 §2 calls the "basic wrapper". The DLEQ proof that makes the
//! server's evaluation *verifiable* (so a client can detect a misbehaving evaluator) is deferred
//! to the Phase 2 spike per docs/06 — noted below rather than implemented now, to keep this pass
//! focused.
//!
//! No internal randomness: `blind` takes 32 bytes of caller-supplied entropy (the client sources
//! this from `crypto.getRandomValues` in JS) rather than reading OS randomness itself, so this
//! crate never needs a `getrandom` WASM backend.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use wasm_bindgen::prelude::*;

/// Hash-to-group via the standard "hash to 64 uniform bytes, map with Elligator2" construction
/// that curve25519-dalek exposes directly (`RistrettoPoint::from_uniform_bytes`). Only `blind`
/// (client-full) calls this; `evaluate` operates on an already-blinded point.
#[cfg(feature = "client-full")]
fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"vortic-oprf-v1");
    hasher.update(input);
    let digest: [u8; 64] = hasher.finalize().into();
    RistrettoPoint::from_uniform_bytes(&digest)
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

/// Client: blind(x) = r * H(x). Returns (blinded point, blinding factor `r`) — both 32 bytes.
/// `entropy` must be fresh, secret randomness from the caller (never reused across calls).
#[cfg(feature = "client-full")]
pub fn blind(seed: &[u8], entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let point = hash_to_group(seed);
    let r = scalar_from_bytes(entropy);
    let blinded = r * point;
    (blinded.compress().to_bytes(), *entropy)
}

/// Enrollment Worker only (see module doc). Z = k * B.
pub fn evaluate(blinded: &[u8; 32], oprf_key: &[u8; 32]) -> Option<[u8; 32]> {
    let b = CompressedRistretto(*blinded).decompress()?;
    let k = scalar_from_bytes(oprf_key);
    Some((k * b).compress().to_bytes())
}

// --- DLEQ (Chaum-Pedersen NIZK) making `evaluate` verifiable -------------------------------------
//
// Proves, in zero knowledge, that the same secret scalar `k` relates the public key `K = k·G` and the
// evaluation `Z = k·B` — i.e. the Enrollment Worker evaluated honestly with its committed key, and did
// not swap in a different key to deanonymise a specific client. Standard Chaum-Pedersen over Ristretto:
//   commit:    A1 = t·G,  A2 = t·B         (t = caller-supplied nonce; no internal RNG, as elsewhere)
//   challenge: c  = H(G, K, B, Z, A1, A2)  (Fiat-Shamir, SHA-512 -> scalar)
//   response:  s  = t + c·k
// Verifier recomputes A1' = s·G − c·K, A2' = s·B − c·Z and checks c == H(G, K, B, Z, A1', A2').
// This closes the DLEQ gap the module doc / docs/06 previously deferred.

fn dleq_challenge(
    big_k: &RistrettoPoint,
    b: &RistrettoPoint,
    z: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    let g = RISTRETTO_BASEPOINT_POINT;
    let mut h = Sha512::new();
    h.update(b"vortic-oprf-dleq-v1");
    h.update(g.compress().as_bytes());
    h.update(big_k.compress().as_bytes());
    h.update(b.compress().as_bytes());
    h.update(z.compress().as_bytes());
    h.update(a1.compress().as_bytes());
    h.update(a2.compress().as_bytes());
    let digest: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&digest)
}

/// Enrollment Worker: evaluate `Z = k·B` AND produce a DLEQ proof. Returns
/// `(Z, K, c, s)` — the evaluation, the public key `K = k·G`, and the (challenge, response) scalars.
/// `nonce` is 32 bytes of fresh caller-supplied randomness (the proof's blinding factor `t`).
pub fn evaluate_with_dleq(
    blinded: &[u8; 32],
    oprf_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Option<([u8; 32], [u8; 32], [u8; 32], [u8; 32])> {
    let b = CompressedRistretto(*blinded).decompress()?;
    let k = scalar_from_bytes(oprf_key);
    let g = RISTRETTO_BASEPOINT_POINT;

    let z = k * b;
    let big_k = k * g;

    let t = scalar_from_bytes(nonce);
    let a1 = t * g;
    let a2 = t * b;
    let c = dleq_challenge(&big_k, &b, &z, &a1, &a2);
    let s = t + c * k;

    Some((z.compress().to_bytes(), big_k.compress().to_bytes(), c.to_bytes(), s.to_bytes()))
}

/// Client: verify a DLEQ proof `(c, s)` for `Z = k·B` under public key `K`. Returns true iff honest.
pub fn verify_dleq(blinded: &[u8; 32], z: &[u8; 32], big_k: &[u8; 32], c: &[u8; 32], s: &[u8; 32]) -> bool {
    let (b, z, big_k) = match (
        CompressedRistretto(*blinded).decompress(),
        CompressedRistretto(*z).decompress(),
        CompressedRistretto(*big_k).decompress(),
    ) {
        (Some(b), Some(z), Some(k)) => (b, z, k),
        _ => return false,
    };
    let c_scalar = scalar_from_bytes(c);
    let s_scalar = scalar_from_bytes(s);
    let g = RISTRETTO_BASEPOINT_POINT;

    // A1' = s·G − c·K,  A2' = s·B − c·Z
    let a1 = s_scalar * g - c_scalar * big_k;
    let a2 = s_scalar * b - c_scalar * z;
    let c_recomputed = dleq_challenge(&big_k, &b, &z, &a1, &a2);
    c_recomputed == c_scalar
}

/// Client: unblind(Z, r) = r^-1 * Z, recovering the token `k * H(x)`.
#[cfg(feature = "client-full")]
pub fn unblind(evaluated: &[u8; 32], blinding_factor: &[u8; 32]) -> Option<[u8; 32]> {
    let z = CompressedRistretto(*evaluated).decompress()?;
    let r = scalar_from_bytes(blinding_factor);
    let r_inv = r.invert();
    Some((r_inv * z).compress().to_bytes())
}

// TODO(Phase 2 spike): DLEQ proof so the client can verify `evaluate` was computed honestly with
// the committed `oprf_key`, per docs/06's Phase 2 entry. Also Phase 2: alias.rs's lookup_key/
// derive_record_key and pow.rs build on the same curve25519-dalek dependency already in scope.

// --- wasm-bindgen exports. blind/unblind: client-full only. evaluate: unconditional (see
// module doc — it's Enrollment-Worker-only by deployment, not by feature gate). ---

#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn oprf_blind(seed: &[u8], entropy: &[u8]) -> Vec<u8> {
    let entropy_arr: [u8; 32] = entropy.try_into().expect("entropy must be exactly 32 bytes");
    let (blinded, r) = blind(seed, &entropy_arr);
    let mut out = blinded.to_vec();
    out.extend_from_slice(&r);
    out
}

#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn oprf_unblind(evaluated: &[u8], blinding_factor: &[u8]) -> Vec<u8> {
    let evaluated_arr: [u8; 32] = evaluated.try_into().expect("evaluated must be 32 bytes");
    let r_arr: [u8; 32] = blinding_factor.try_into().expect("blinding_factor must be 32 bytes");
    unblind(&evaluated_arr, &r_arr).expect("invalid point").to_vec()
}

#[wasm_bindgen]
pub fn oprf_evaluate(blinded: &[u8], oprf_key: &[u8]) -> Vec<u8> {
    let blinded_arr: [u8; 32] = blinded.try_into().expect("blinded must be 32 bytes");
    let key_arr: [u8; 32] = oprf_key.try_into().expect("oprf_key must be 32 bytes");
    evaluate(&blinded_arr, &key_arr).expect("invalid point").to_vec()
}

/// Enrollment Worker export: evaluate + DLEQ. Returns Z(32) || K(32) || c(32) || s(32) = 128 bytes.
#[wasm_bindgen]
pub fn oprf_evaluate_with_dleq(blinded: &[u8], oprf_key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let blinded_arr: [u8; 32] = blinded.try_into().expect("blinded must be 32 bytes");
    let key_arr: [u8; 32] = oprf_key.try_into().expect("oprf_key must be 32 bytes");
    let nonce_arr: [u8; 32] = nonce.try_into().expect("nonce must be 32 bytes");
    let (z, k, c, s) = evaluate_with_dleq(&blinded_arr, &key_arr, &nonce_arr).expect("invalid point");
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&z);
    out.extend_from_slice(&k);
    out.extend_from_slice(&c);
    out.extend_from_slice(&s);
    out
}

/// Client export: verify the DLEQ proof. Inputs are the 32-byte blinded point, then Z || K || c || s.
#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn oprf_verify_dleq(blinded: &[u8], proof: &[u8]) -> bool {
    let blinded_arr: [u8; 32] = match blinded.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    if proof.len() != 128 {
        return false;
    }
    let z: [u8; 32] = proof[0..32].try_into().unwrap();
    let k: [u8; 32] = proof[32..64].try_into().unwrap();
    let c: [u8; 32] = proof[64..96].try_into().unwrap();
    let s: [u8; 32] = proof[96..128].try_into().unwrap();
    verify_dleq(&blinded_arr, &z, &k, &c, &s)
}

#[cfg(all(test, feature = "client-full"))]
mod tests {
    use super::*;

    #[test]
    fn blind_evaluate_unblind_recovers_direct_evaluation() {
        let seed = b"user-identity-seed";
        let entropy = [7u8; 32];
        let oprf_key = [42u8; 32];

        let (blinded, r) = blind(seed, &entropy);
        let evaluated = evaluate(&blinded, &oprf_key).expect("valid point");
        let token = unblind(&evaluated, &r).expect("valid point");

        // Token must equal a direct (unblinded) evaluation of H(seed) under the same key —
        // this is the VOPRF correctness property: blind/evaluate/unblind == evaluate(H(x), k).
        let direct = evaluate(&hash_to_group(seed).compress().to_bytes(), &oprf_key).expect("valid point");
        assert_eq!(token, direct);
    }

    #[test]
    fn dleq_proof_verifies_and_catches_a_dishonest_evaluator() {
        let (blinded, _r) = blind(b"identity", &[7u8; 32]);
        let oprf_key = [42u8; 32];
        let nonce = [13u8; 32];

        let (z, k, c, s) = evaluate_with_dleq(&blinded, &oprf_key, &nonce).expect("valid point");
        // Honest proof verifies.
        assert!(verify_dleq(&blinded, &z, &k, &c, &s));

        // Z produced under a DIFFERENT key (a deanonymising evaluator) must fail against the
        // committed public key K.
        let z_evil = evaluate(&blinded, &[99u8; 32]).expect("valid point");
        assert!(!verify_dleq(&blinded, &z_evil, &k, &c, &s));

        // Tampered response scalar fails.
        let mut s_bad = s;
        s_bad[0] ^= 0x01;
        assert!(!verify_dleq(&blinded, &z, &k, &c, &s_bad));
    }
}
