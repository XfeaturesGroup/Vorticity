//! Hybrid KEM: ML-KEM-768 (FIPS 203) + X25519, combined via HKDF-SHA256 into one root key.
//! See docs/03-crypto-core.md §4 (PQXDH handshake). Client-side only — the edge never holds a
//! KEM decapsulation key.
//!
//! No internal randomness: every function takes a caller-supplied 32-byte seed (sourced from
//! `crypto.getRandomValues` in JS) and expands it deterministically via HKDF — both ML-KEM
//! (`from_seed`/`encapsulate_deterministic`) and X25519 (`StaticSecret::from(bytes)`) support
//! fully deterministic construction natively, so no RNG trait plumbing or `getrandom` WASM
//! backend is needed at all. See oprf.rs's module doc for the same design choice.

use kem::{Decapsulate, Key, KeyExport, KeyInit};
use ml_kem::{B32, DecapsulationKey, EncapsulationKey, MlKem768, Seed};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::util::hkdf_sha256;

/// FIPS 203 ML-KEM-768 fixed sizes — used to pack/unpack the WASM byte boundary without a
/// length-prefix framing scheme. Note: the `ml-kem` crate's canonical `KeyInit`/`KeyExport`
/// serialization of a decapsulation key is the 64-byte *seed* (its documented "preferred
/// serialization"), not the 2400-byte FIPS 203 "expanded" private key — so DK_LEN is 64, and
/// reconstructing from it re-derives the expanded key deterministically on `new()`.
pub const ML_KEM_768_EK_LEN: usize = 1184;
pub const ML_KEM_768_DK_LEN: usize = 64;
pub const ML_KEM_768_CT_LEN: usize = 1088;

pub struct HybridPublicKey {
    pub ml_kem_ek: Vec<u8>,
    pub x25519_pk: [u8; 32],
}

pub struct HybridKeyPair {
    ml_kem_dk: Vec<u8>,
    x25519_sk: [u8; 32],
    pub public: HybridPublicKey,
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        self.ml_kem_dk.zeroize();
        self.x25519_sk.zeroize();
    }
}

pub struct HybridCiphertext {
    pub ml_kem_ct: Vec<u8>,
    pub x25519_ephemeral_pk: [u8; 32],
}

fn arr64(bytes: &[u8]) -> [u8; 64] {
    bytes.try_into().expect("expected 64 bytes")
}
fn arr32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("expected 32 bytes")
}

/// Deterministic keypair generation from a caller-supplied 32-byte seed.
pub fn generate_keypair(seed: &[u8; 32]) -> HybridKeyPair {
    let ml_kem_seed_bytes = arr64(&hkdf_sha256(seed, b"vortic-kem-v1", b"ml-kem-seed", 64));
    let dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(ml_kem_seed_bytes));
    let ek = dk.encapsulation_key().clone();

    let x25519_seed_bytes = arr32(&hkdf_sha256(seed, b"vortic-kem-v1", b"x25519-seed", 32));
    let x25519_sk = StaticSecret::from(x25519_seed_bytes);
    let x25519_pk = X25519Public::from(&x25519_sk);

    HybridKeyPair {
        ml_kem_dk: dk.to_bytes().as_slice().to_vec(),
        x25519_sk: x25519_sk.to_bytes(),
        public: HybridPublicKey {
            ml_kem_ek: ek.to_bytes().as_slice().to_vec(),
            x25519_pk: x25519_pk.to_bytes(),
        },
    }
}

/// Encapsulate to a peer's hybrid public key. Returns the ciphertext to send and the resulting
/// 32-byte root key (breaking either the classical or PQ leg alone does not recover it).
pub fn encapsulate(seed: &[u8; 32], peer: &HybridPublicKey) -> (HybridCiphertext, [u8; 32]) {
    let ek_key: Key<EncapsulationKey<MlKem768>> = Key::<EncapsulationKey<MlKem768>>::from(
        <[u8; ML_KEM_768_EK_LEN]>::try_from(peer.ml_kem_ek.as_slice()).expect("bad ek length"),
    );
    let ek = EncapsulationKey::<MlKem768>::new(&ek_key).expect("invalid ek");

    let m = B32::from(arr32(&hkdf_sha256(seed, b"vortic-kem-v1", b"ml-kem-encap-m", 32)));
    let (ml_kem_ct, ml_kem_ss) = ek.encapsulate_deterministic(&m);

    let ephemeral_seed = arr32(&hkdf_sha256(seed, b"vortic-kem-v1", b"x25519-ephemeral", 32));
    let ephemeral_sk = StaticSecret::from(ephemeral_seed);
    let ephemeral_pk = X25519Public::from(&ephemeral_sk);
    let peer_x25519_pk = X25519Public::from(peer.x25519_pk);
    let x25519_ss = ephemeral_sk.diffie_hellman(&peer_x25519_pk);

    let root_key = combine(ml_kem_ss.as_slice(), x25519_ss.as_bytes());

    (
        HybridCiphertext {
            ml_kem_ct: ml_kem_ct.as_slice().to_vec(),
            x25519_ephemeral_pk: ephemeral_pk.to_bytes(),
        },
        root_key,
    )
}

/// Decapsulate using this keypair's private material. Returns the same 32-byte root key.
pub fn decapsulate(keypair: &HybridKeyPair, ct: &HybridCiphertext) -> [u8; 32] {
    let dk_key: Key<DecapsulationKey<MlKem768>> = Key::<DecapsulationKey<MlKem768>>::from(
        <[u8; ML_KEM_768_DK_LEN]>::try_from(keypair.ml_kem_dk.as_slice()).expect("bad dk length"),
    );
    let dk = DecapsulationKey::<MlKem768>::new(&dk_key); // KeyInit::new — re-derives the expanded key from the seed

    let ct_arr = ml_kem::Ciphertext::<MlKem768>::from(
        <[u8; ML_KEM_768_CT_LEN]>::try_from(ct.ml_kem_ct.as_slice()).expect("bad ct length"),
    );
    let ml_kem_ss = dk.decapsulate(&ct_arr);

    let my_sk = StaticSecret::from(keypair.x25519_sk);
    let their_pk = X25519Public::from(ct.x25519_ephemeral_pk);
    let x25519_ss = my_sk.diffie_hellman(&their_pk);

    combine(ml_kem_ss.as_slice(), x25519_ss.as_bytes())
}

fn combine(ml_kem_ss: &[u8], x25519_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ml_kem_ss.len() + x25519_ss.len());
    ikm.extend_from_slice(ml_kem_ss);
    ikm.extend_from_slice(x25519_ss);
    let okm = hkdf_sha256(&ikm, b"vortic-pqxdh-v1", b"root-key", 32);
    arr32(&okm)
}

// --- Fixed-size (de)serialization for the WASM boundary. A nicer typed JS wrapper is Phase 4
// work; this pass only needs a stable, simple byte layout. ---

impl HybridPublicKey {
    /// Layout: ml_kem_ek(1184) || x25519_pk(32).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ML_KEM_768_EK_LEN + 32);
        out.extend_from_slice(&self.ml_kem_ek);
        out.extend_from_slice(&self.x25519_pk);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), ML_KEM_768_EK_LEN + 32, "bad hybrid public key length");
        HybridPublicKey {
            ml_kem_ek: bytes[..ML_KEM_768_EK_LEN].to_vec(),
            x25519_pk: arr32(&bytes[ML_KEM_768_EK_LEN..]),
        }
    }
}

impl HybridKeyPair {
    /// Layout: ml_kem_ek(1184) || x25519_pk(32) || ml_kem_dk(2400) || x25519_sk(32).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.public.to_bytes();
        out.extend_from_slice(&self.ml_kem_dk);
        out.extend_from_slice(&self.x25519_sk);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let pub_len = ML_KEM_768_EK_LEN + 32;
        assert_eq!(bytes.len(), pub_len + ML_KEM_768_DK_LEN + 32, "bad hybrid keypair length");
        HybridKeyPair {
            public: HybridPublicKey::from_bytes(&bytes[..pub_len]),
            ml_kem_dk: bytes[pub_len..pub_len + ML_KEM_768_DK_LEN].to_vec(),
            x25519_sk: arr32(&bytes[pub_len + ML_KEM_768_DK_LEN..]),
        }
    }
}

impl HybridCiphertext {
    /// Layout: ml_kem_ct(1088) || x25519_ephemeral_pk(32).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ML_KEM_768_CT_LEN + 32);
        out.extend_from_slice(&self.ml_kem_ct);
        out.extend_from_slice(&self.x25519_ephemeral_pk);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), ML_KEM_768_CT_LEN + 32, "bad hybrid ciphertext length");
        HybridCiphertext {
            ml_kem_ct: bytes[..ML_KEM_768_CT_LEN].to_vec(),
            x25519_ephemeral_pk: arr32(&bytes[ML_KEM_768_CT_LEN..]),
        }
    }
}

// --- wasm-bindgen exports (client-full only — this whole module is feature-gated in lib.rs) ---

#[wasm_bindgen]
pub fn kem_generate_keypair(seed: &[u8]) -> Vec<u8> {
    generate_keypair(&arr32(seed)).to_bytes()
}

#[wasm_bindgen]
pub fn kem_public_key_from_keypair(keypair_bytes: &[u8]) -> Vec<u8> {
    keypair_bytes[..ML_KEM_768_EK_LEN + 32].to_vec()
}

#[wasm_bindgen]
pub fn kem_encapsulate(seed: &[u8], peer_public_bytes: &[u8]) -> Vec<u8> {
    let peer = HybridPublicKey::from_bytes(peer_public_bytes);
    let (ct, root_key) = encapsulate(&arr32(seed), &peer);
    let mut out = ct.to_bytes();
    out.extend_from_slice(&root_key);
    out
}

#[wasm_bindgen]
pub fn kem_decapsulate(keypair_bytes: &[u8], ct_bytes: &[u8]) -> Vec<u8> {
    let keypair = HybridKeyPair::from_bytes(keypair_bytes);
    let ct = HybridCiphertext::from_bytes(ct_bytes);
    decapsulate(&keypair, &ct).to_vec()
}

// --- Plain X25519 Diffie-Hellman (Phase-1 "dynamic key exchange") ---------------------------------
//
// Separate from the hybrid KEM above: this is the SYMMETRIC ephemeral-DH handshake the chat transport
// uses to replace symmetric.rs's hardcoded demo key. Both peers generate a keypair, swap public keys
// over the wire, and each computes `DH(my_secret, their_public)` — X25519 is symmetric, so both arrive
// at the same shared point. The raw DH output is then run through HKDF-SHA256 into a clean 32-byte key
// suitable for ChaCha20-Poly1305 (never use a raw DH output directly as a cipher key). This is NOT
// forward-secret on its own (no ratchet yet) and NOT authenticated (no signed prekeys — a MITM on the
// first exchange is undetected); it is the honest "get a real shared secret onto the wire" step, with
// the hybrid PQ KEM + Triple Ratchet + prekey signing still tracked as later Phase-2/ratchet work.

/// Derive an X25519 keypair from a caller-supplied 32-byte secret (JS sources it from
/// `crypto.getRandomValues`). Layout of the returned buffer: `secret(32) || public(32)`.
#[wasm_bindgen]
pub fn x25519_generate_keypair(secret_bytes: &[u8]) -> Vec<u8> {
    let sk = StaticSecret::from(arr32(secret_bytes));
    let pk = X25519Public::from(&sk);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&sk.to_bytes());
    out.extend_from_slice(pk.as_bytes());
    out
}

/// Compute the shared ChaCha20-Poly1305 key from this peer's X25519 secret and the other peer's
/// X25519 public key. Returns the 32-byte HKDF-SHA256 output of the raw DH secret (domain-separated
/// so this key is distinct from any other use of the same DH point).
#[wasm_bindgen]
pub fn x25519_derive_shared(my_secret: &[u8], their_public: &[u8]) -> Vec<u8> {
    let sk = StaticSecret::from(arr32(my_secret));
    let pk = X25519Public::from(arr32(their_public));
    let shared = sk.diffie_hellman(&pk);
    hkdf_sha256(shared.as_bytes(), b"vortic-x25519-dh-v1", b"chat-key", 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_both_sides_agree_and_kdf_is_applied() {
        // Alice and Bob each generate a keypair, swap publics, derive — must match.
        let alice = x25519_generate_keypair(&[7u8; 32]);
        let bob = x25519_generate_keypair(&[9u8; 32]);
        let (alice_sk, alice_pk) = alice.split_at(32);
        let (bob_sk, bob_pk) = bob.split_at(32);

        let k_alice = x25519_derive_shared(alice_sk, bob_pk);
        let k_bob = x25519_derive_shared(bob_sk, alice_pk);
        assert_eq!(k_alice, k_bob);
        assert_eq!(k_alice.len(), 32);

        // The returned key is the HKDF output, not the raw DH secret — different keypairs differ.
        let carol = x25519_generate_keypair(&[11u8; 32]);
        let (_carol_sk, carol_pk) = carol.split_at(32);
        assert_ne!(x25519_derive_shared(alice_sk, carol_pk), k_alice);
    }

    #[test]
    fn encapsulate_decapsulate_agree_on_root_key() {
        let alice = generate_keypair(&[1u8; 32]);
        let (ct, root_key_sender) = encapsulate(&[2u8; 32], &alice.public);
        let root_key_receiver = decapsulate(&alice, &ct);
        assert_eq!(root_key_sender, root_key_receiver);
    }

    #[test]
    fn keypair_roundtrips_through_bytes() {
        let kp = generate_keypair(&[3u8; 32]);
        let bytes = kp.to_bytes();
        let restored = HybridKeyPair::from_bytes(&bytes);
        let (ct, ss1) = encapsulate(&[4u8; 32], &restored.public);
        let ss2 = decapsulate(&restored, &ct);
        assert_eq!(ss1, ss2);
    }
}
