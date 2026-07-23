//! Triple Ratchet (Double Ratchet + Sparse Post-Quantum Ratchet), Signal SPQR-style, with an
//! authenticated PQXDH-style handshake. See docs/03-crypto-core.md §4. Client-side only (this whole
//! module is `client-full`-gated at `lib.rs`, so `edge-verify-only` never links any ratchet/decrypt
//! code — crypto invariant #4).
//!
//! HANDSHAKE (PQXDH-style): a responder ("Bob") publishes a hybrid KEM prekey bundle (ML-KEM-768 +
//! X25519, `kem::HybridPublicKey`) *signed* by his long-term Ed25519 identity key. An initiator
//! ("Alice") verifies that signature before doing anything else — this is what makes the handshake
//! *authenticated* rather than bare DH: a MITM without Bob's identity signing key cannot forge a
//! bundle that verifies. (What is *not* solved here, same as Signal's own TOFU model: verifying that
//! a given `verifying_key` really belongs to the expected peer the first time — that is a separate,
//! out-of-band identity-verification/safety-number UX problem, not a cryptographic one.) The
//! resulting hybrid shared secret seeds the Double Ratchet's root key exactly like X3DH seeds
//! Signal's.
//!
//! DOUBLE RATCHET: standard Signal algorithm — a symmetric-key ratchet (HKDF hash chain) advances
//! every message for forward secrecy (each message key is derived one-way and discarded), and a
//! DH ratchet (fresh X25519 keypair each time the conversation's sender direction flips) re-injects
//! new randomness into the root key for post-compromise security (an attacker who steals the full
//! state at time T is shut out again after the next DH ratchet turn in either direction).
//!
//! SPARSE PQ RATCHET: every [`PQ_REMIX_EVERY_N_TURNS`] DH ratchet turns, a party offers a *fresh*
//! ML-KEM-768 keypair in its header (`pq_ek`); the peer encapsulates to it and attaches the
//! ciphertext (`pq_ct`) to its own next new-chain message, since ML-KEM has no symmetric "both sides
//! compute the same point" shortcut — one side must encapsulate to the other's public key. Both
//! sides fold the resulting ML-KEM shared secret into that *specific* chain's key material at the
//! exact `n == 0` message where the ciphertext travels (see `ratchet_encrypt`/`ratchet_decrypt`) —
//! **not** into `state.rk`. An earlier version of this module tried to defer the mix to each side's
//! own *next* DH ratchet turn and fold it into the shared root key there; that broke under
//! alternating-sender traffic (confirmed by a failing test, kept as
//! `sparse_pq_ratchet_actually_remixes_after_enough_turns`) because an asynchronous offer/response
//! can't be relied on to land on a turn-for-turn-paired `kdf_rk` call on both sides, and `state.rk`
//! is a purely local value that only ever needs to match the peer's at those specific paired
//! call-sites — mixing it anywhere else desyncs every later turn. Mixing into the chain key instead
//! is safe because it happens within processing of the *one shared wire message* carrying the
//! ciphertext, so both sides are provably operating on the same starting value (that's exactly what
//! the matching `mk` on both ends proves). The resulting property is real but scoped: it strengthens
//! the messages of the chain segment the remix landed in specifically, on top of whatever the DH
//! ratchet's own already-proven per-turn PCS already provides — not a permanent fold into the root
//! for every future chain. Tuning that into a full root-level "PQ PCS" (matching docs/03's phrasing
//! literally) needs a different synchronization primitive; documented as a known simplification, not
//! silently glossed over.
//!
//! `PQ_REMIX_EVERY_N_TURNS = 3` is a small constant chosen for this pass's testability (few messages
//! needed to observe a remix live) — docs/03 only requires "periodic", not a specific cadence; tuning
//! this for production traffic patterns is separate, later work.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::kem::{self, HybridCiphertext, HybridKeyPair, HybridPublicKey, MlKemKeyPair};
use crate::util::hkdf_sha256;

const MAX_SKIP: u32 = 25;
const PQ_REMIX_EVERY_N_TURNS: u32 = 3;

fn arr32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("expected 32 bytes")
}

// ================================ Identity (long-term Ed25519) =====================================

struct IdentityKeyPair {
    signing: SigningKey,
    verifying: [u8; 32],
}

/// Deterministic from a caller-supplied 32-byte seed — same convention as every other client-full
/// key-generation function in this crate (kem.rs, symmetric.rs's callers).
fn identity_generate(seed: &[u8; 32]) -> IdentityKeyPair {
    let sk_bytes = arr32(&hkdf_sha256(seed, b"vortic-identity-v1", b"ed25519-seed", 32));
    let signing = SigningKey::from_bytes(&sk_bytes);
    let verifying = signing.verifying_key().to_bytes();
    IdentityKeyPair { signing, verifying }
}

fn identity_sign(id: &IdentityKeyPair, msg: &[u8]) -> [u8; 64] {
    id.signing.sign(msg).to_bytes()
}

fn identity_verify(verifying_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(verifying_key) else {
        return false;
    };
    let sig = Signature::from_bytes(sig);
    vk.verify(msg, &sig).is_ok()
}

/// The prekey bundle IS the hybrid KEM public key (`kem::HybridPublicKey::to_bytes()`), signed by
/// the publisher's long-term identity key. Binding the signature to those exact bytes means a
/// tampered ML-KEM or X25519 leg (e.g. a MITM substituting their own X25519 key while keeping the
/// real ML-KEM key, to downgrade to a classically-breakable exchange) is caught by signature
/// verification just as much as a wholesale substitution would be.
fn bundle_sign(id: &IdentityKeyPair, hybrid_public: &HybridPublicKey) -> [u8; 64] {
    identity_sign(id, &hybrid_public.to_bytes())
}

fn bundle_verify(verifying_key: &[u8; 32], hybrid_public: &HybridPublicKey, sig: &[u8; 64]) -> bool {
    identity_verify(verifying_key, &hybrid_public.to_bytes(), sig)
}

// ================================ Double + Sparse-PQ Ratchet core ===================================

struct RatchetHeader {
    dh_pub: [u8; 32],
    pn: u32,
    n: u32,
    pq_ek: Option<Vec<u8>>,
    pq_ct: Option<Vec<u8>>,
}

impl RatchetHeader {
    /// Layout: dh_pub(32) || pn(4 LE) || n(4 LE) || flags(1) || [pq_ek_len(2 LE) || pq_ek] || [pq_ct_len(2 LE) || pq_ct].
    /// This exact byte range is bound into the AEAD as associated data (see `aead_encrypt`/`aead_decrypt`
    /// below), so a MITM cannot flip `dh_pub`/`n`/the PQ offer fields without the auth tag failing —
    /// headers are authenticated even though they are not themselves encrypted.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.extend_from_slice(&self.dh_pub);
        out.extend_from_slice(&self.pn.to_le_bytes());
        out.extend_from_slice(&self.n.to_le_bytes());
        let mut flags = 0u8;
        if self.pq_ek.is_some() {
            flags |= 0b01;
        }
        if self.pq_ct.is_some() {
            flags |= 0b10;
        }
        out.push(flags);
        if let Some(ref ek) = self.pq_ek {
            out.extend_from_slice(&(ek.len() as u16).to_le_bytes());
            out.extend_from_slice(ek);
        }
        if let Some(ref ct) = self.pq_ct {
            out.extend_from_slice(&(ct.len() as u16).to_le_bytes());
            out.extend_from_slice(ct);
        }
        out
    }
}

/// Splits a wire message into `(header, header_bytes, ciphertext)`. `header_bytes` is the exact
/// slice consumed (not a re-serialization), so it is byte-identical to what the sender used as AAD.
fn parse_wire(wire: &[u8]) -> Result<(RatchetHeader, &[u8], &[u8]), String> {
    if wire.len() < 32 + 4 + 4 + 1 {
        return Err("wire message too short for a ratchet header".to_string());
    }
    let dh_pub = arr32(&wire[0..32]);
    let pn = u32::from_le_bytes(wire[32..36].try_into().unwrap());
    let n = u32::from_le_bytes(wire[36..40].try_into().unwrap());
    let flags = wire[40];
    let mut offset = 41usize;

    let mut pq_ek = None;
    if flags & 0b01 != 0 {
        if wire.len() < offset + 2 {
            return Err("truncated pq_ek length".to_string());
        }
        let len = u16::from_le_bytes(wire[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if wire.len() < offset + len {
            return Err("truncated pq_ek".to_string());
        }
        pq_ek = Some(wire[offset..offset + len].to_vec());
        offset += len;
    }
    let mut pq_ct = None;
    if flags & 0b10 != 0 {
        if wire.len() < offset + 2 {
            return Err("truncated pq_ct length".to_string());
        }
        let len = u16::from_le_bytes(wire[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if wire.len() < offset + len {
            return Err("truncated pq_ct".to_string());
        }
        pq_ct = Some(wire[offset..offset + len].to_vec());
        offset += len;
    }

    let header = RatchetHeader { dh_pub, pn, n, pq_ek, pq_ct };
    Ok((header, &wire[..offset], &wire[offset..]))
}

/// `key` here is always a one-time message key (each derived once via `kdf_ck`, used for exactly one
/// message, then discarded) — a fixed all-zero nonce is safe under that discipline (key uniqueness
/// substitutes for nonce uniqueness), unlike `symmetric.rs`'s long-lived session key, which needs a
/// fresh random nonce per call. The header is authenticated (AAD) but not encrypted: routing/replay
/// bookkeeping (`dh_pub`/`pn`/`n`) must be readable before the receiver knows which message key to try.
fn aead_encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .expect("chacha20poly1305 encrypt with a fresh one-time key cannot fail")
}

fn aead_decrypt(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| "decryption failed (bad tag, wrong key, or tampered header)".to_string())
}

/// `KDF_RK` — advances the root key using a DH output. `rk` is used as the HKDF salt and `dh_out` as
/// the IKM, matching the Double Ratchet spec's own KDF_RK(rk, dh_out) convention. The Sparse PQ
/// Ratchet does NOT thread its ML-KEM secret through here (see `mix_pq_secret` below and its call
/// sites) — an earlier version of this function tried to fold a deferred `pending_pq_ss` into
/// whichever side's *next* DH-ratchet-turn happened to run first, but that requires the two peers'
/// `kdf_rk` calls to consume the exact same optional PQ input at the exact same turn, which an
/// asynchronous offer/response (the offer and its answering ciphertext arrive in different messages,
/// not necessarily paired turn-for-turn) cannot guarantee — it produced real, observed key mismatches
/// under alternating-sender traffic. `mix_pq_secret` instead mixes the PQ secret in in a place both
/// sides reach *within the same shared message* (see `ratchet_encrypt`/`ratchet_decrypt`'s `n == 0`
/// handling), which is trivially symmetric since it's the same wire message on both ends.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let okm = hkdf_sha256(dh_out, rk, b"vortic-ratchet-root-v1", 64);
    (arr32(&okm[..32]), arr32(&okm[32..]))
}

/// `KDF_CK` — advances a chain key one step, deriving both the next chain key and this step's
/// message key. The Double Ratchet spec explicitly permits HKDF in place of the reference HMAC
/// construction; using `hkdf_sha256(ck, ..., info, 32)` with `ck` as IKM is exactly that substitution
/// (HKDF-Expand is itself HMAC-keyed by the PRK), reusing this crate's one existing KDF primitive
/// instead of adding a second HMAC dependency for no cryptographic gain.
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let new_ck = arr32(&hkdf_sha256(ck, b"vortic-ratchet-chain-v1", b"chain", 32));
    let mk = arr32(&hkdf_sha256(ck, b"vortic-ratchet-chain-v1", b"message", 32));
    (new_ck, mk)
}

/// The Sparse PQ Ratchet's actual mixing step: a one-way fold of a fresh ML-KEM shared secret into a
/// CHAIN key (never `state.rk` — see this module's doc comment for why that specifically doesn't
/// work). Applied identically by both peers on the exact same wire message (see the `header.n == 0`
/// blocks in `ratchet_encrypt`/`ratchet_decrypt`), so — unlike routing it through `kdf_rk`'s per-side
/// turn-pairing — no cross-message synchronization is required for the two sides to land on the same
/// output.
fn mix_pq_secret(key: &[u8; 32], pq_ss: &[u8; 32]) -> [u8; 32] {
    arr32(&hkdf_sha256(pq_ss, key, b"vortic-sparse-pq-mix-v1", 32))
}

fn dh_generate(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let secret_bytes = arr32(&hkdf_sha256(seed, b"vortic-ratchet-dh-v1", b"x25519-seed", 32));
    let sk = StaticSecret::from(secret_bytes);
    let pk = X25519Public::from(&sk);
    (sk.to_bytes(), pk.to_bytes())
}

fn dh(my_priv: &[u8; 32], their_pub: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*my_priv);
    let pk = X25519Public::from(*their_pub);
    sk.diffie_hellman(&pk).to_bytes()
}

/// The 96 bytes of fresh entropy `encrypt`/`decrypt` always take as input (same "caller always
/// supplies real randomness, crate never touches an RNG for key generation" convention as kem.rs).
/// Each 32-byte lane is *conditionally* consumed — most calls use none of them (no ratchet turn, no
/// PQ event on that call) — but the caller cannot know in advance which case applies, so it always
/// draws fresh bytes via `crypto.getRandomValues`, same as e.g. `kem_generate_keypair`'s seed.
struct Entropy {
    dh: [u8; 32],
    pq_kp: [u8; 32],
    pq_encap: [u8; 32],
}

impl Entropy {
    fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 96 {
            return Err(format!("entropy must be 96 bytes, got {}", b.len()));
        }
        Ok(Entropy { dh: arr32(&b[0..32]), pq_kp: arr32(&b[32..64]), pq_encap: arr32(&b[64..96]) })
    }
}

pub struct RatchetState {
    dhs_priv: [u8; 32],
    dhs_pub: [u8; 32],
    dhr_pub: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
    dh_ratchet_turns: u32,
    pq_remix_count: u32,
    /// Our own most recently offered (not-yet-answered) ML-KEM keypair — cleared once the peer's
    /// matching `pq_ct` arrives.
    pq_pending_offer: Option<MlKemKeyPair>,
    /// The peer's most recently offered (not-yet-answered) ML-KEM public key — cleared once we
    /// encapsulate to it and attach the resulting ciphertext to our own next new-chain message.
    pq_peer_offer_ek: Option<Vec<u8>>,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.dhs_priv.zeroize();
        self.rk.zeroize();
        if let Some(ref mut ck) = self.cks {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.ckr {
            ck.zeroize();
        }
        for (_, mut k) in self.skipped.drain() {
            k.zeroize();
        }
    }
}

fn ratchet_init_alice(root_key: [u8; 32], bob_dh_pub: [u8; 32], dh_seed: &[u8; 32]) -> RatchetState {
    let (my_priv, my_pub) = dh_generate(dh_seed);
    let dh_out = dh(&my_priv, &bob_dh_pub);
    let (rk, cks) = kdf_rk(&root_key, &dh_out);
    RatchetState {
        dhs_priv: my_priv,
        dhs_pub: my_pub,
        dhr_pub: Some(bob_dh_pub),
        rk,
        cks: Some(cks),
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        skipped: HashMap::new(),
        dh_ratchet_turns: 1,
        pq_remix_count: 0,
        pq_pending_offer: None,
        pq_peer_offer_ek: None,
    }
}

fn ratchet_init_bob(root_key: [u8; 32], my_dh_priv: [u8; 32], my_dh_pub: [u8; 32]) -> RatchetState {
    RatchetState {
        dhs_priv: my_dh_priv,
        dhs_pub: my_dh_pub,
        dhr_pub: None,
        rk: root_key,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        skipped: HashMap::new(),
        dh_ratchet_turns: 0,
        pq_remix_count: 0,
        pq_pending_offer: None,
        pq_peer_offer_ek: None,
    }
}

// ============================ State export/import (device-linking pass) ===========================
//
// Serializes the ENTIRE live `RatchetState` — every private key, chain key, and cached skipped-
// message key currently held — to a flat byte blob, and back. This is the mechanism a second device
// of the SAME identity uses to pick up an already-established 1:1 session: this project's design is
// "one shared ratchet, whichever device currently holds it is live" (see docs/06's device-linking
// entry for why this was chosen over a per-device Sesame-style fan-out), so linking a device means
// literally handing it this exact state, not deriving a fresh one.
//
// **THE EXPORTED BLOB IS MAXIMALLY SENSITIVE — equivalent to full compromise of this specific
// session if it leaks.** It contains the current sending/receiving chain keys and, if a DH ratchet
// turn is due, the raw private key for it. This module does not transport, seal, or persist the
// blob anywhere — it only converts to/from bytes; the caller (apps/web's device-linking flow) is
// responsible for sealing it under a real AEAD key derived from an out-of-band-authenticated linking
// secret before it ever leaves the exporting device's memory, and for ensuring only ONE device is
// ever "live" at a time afterward (a lease mechanism, not this crate's concern — two devices
// simultaneously advancing the SAME ratchet state would desync it exactly like two independent
// sessions racing, this module has no way to detect or prevent that misuse from the state shape
// alone).
//
// FIXED LAYOUT (not a generic serde format — this crate's existing convention throughout kem.rs/
// ratchet.rs's other `to_bytes`/`from_bytes` pairs, kept consistent rather than pulling in a
// serialization crate for one more struct):
//   flags(1) — bit0 dhr_pub present, bit1 cks present, bit2 ckr present, bit3 pq_pending_offer
//              present, bit4 pq_peer_offer_ek present
//   dhs_priv(32) dhs_pub(32) [dhr_pub(32)] rk(32) [cks(32)] [ckr(32)]
//   ns(4 LE) nr(4 LE) pn(4 LE) dh_ratchet_turns(4 LE) pq_remix_count(4 LE)
//   skipped_count(4 LE), then skipped_count × [dh_pub(32) n(4 LE) mk(32)]  (68 bytes each)
//   [pq_pending_offer: MlKemKeyPair::to_bytes(), 1248 bytes, if flag]
//   [pq_peer_offer_ek: 1184 bytes, if flag]
//   pending_handshake_ct_len(4 LE), then that many bytes (usually 0 — see RatchetSession's own doc:
//   normally already taken/None by the time a session is worth linking a second device into, but
//   included for full fidelity rather than assuming that timing)
fn serialize_ratchet_state(state: &RatchetState, pending_handshake_ct: &Option<Vec<u8>>) -> Vec<u8> {
    let mut flags = 0u8;
    if state.dhr_pub.is_some() {
        flags |= 0b00001;
    }
    if state.cks.is_some() {
        flags |= 0b00010;
    }
    if state.ckr.is_some() {
        flags |= 0b00100;
    }
    if state.pq_pending_offer.is_some() {
        flags |= 0b01000;
    }
    if state.pq_peer_offer_ek.is_some() {
        flags |= 0b10000;
    }

    let mut out = Vec::new();
    out.push(flags);
    out.extend_from_slice(&state.dhs_priv);
    out.extend_from_slice(&state.dhs_pub);
    if let Some(v) = state.dhr_pub {
        out.extend_from_slice(&v);
    }
    out.extend_from_slice(&state.rk);
    if let Some(v) = state.cks {
        out.extend_from_slice(&v);
    }
    if let Some(v) = state.ckr {
        out.extend_from_slice(&v);
    }
    out.extend_from_slice(&state.ns.to_le_bytes());
    out.extend_from_slice(&state.nr.to_le_bytes());
    out.extend_from_slice(&state.pn.to_le_bytes());
    out.extend_from_slice(&state.dh_ratchet_turns.to_le_bytes());
    out.extend_from_slice(&state.pq_remix_count.to_le_bytes());

    out.extend_from_slice(&(state.skipped.len() as u32).to_le_bytes());
    for ((dh_pub, n), mk) in &state.skipped {
        out.extend_from_slice(dh_pub);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(mk);
    }

    if let Some(ref kp) = state.pq_pending_offer {
        out.extend_from_slice(&kp.to_bytes());
    }
    if let Some(ref ek) = state.pq_peer_offer_ek {
        out.extend_from_slice(ek);
    }

    let ct = pending_handshake_ct.as_deref().unwrap_or(&[]);
    out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
    out.extend_from_slice(ct);

    out
}

fn deserialize_ratchet_state(bytes: &[u8]) -> Result<(RatchetState, Option<Vec<u8>>), String> {
    let mut pos = 0usize;
    let need = |pos: usize, n: usize, what: &str| -> Result<(), String> {
        if bytes.len() < pos + n {
            return Err(format!("truncated ratchet state (need {n} more bytes for {what})"));
        }
        Ok(())
    };

    need(pos, 1, "flags")?;
    let flags = bytes[pos];
    pos += 1;

    need(pos, 32, "dhs_priv")?;
    let dhs_priv = arr32(&bytes[pos..pos + 32]);
    pos += 32;
    need(pos, 32, "dhs_pub")?;
    let dhs_pub = arr32(&bytes[pos..pos + 32]);
    pos += 32;

    let dhr_pub = if flags & 0b00001 != 0 {
        need(pos, 32, "dhr_pub")?;
        let v = arr32(&bytes[pos..pos + 32]);
        pos += 32;
        Some(v)
    } else {
        None
    };

    need(pos, 32, "rk")?;
    let rk = arr32(&bytes[pos..pos + 32]);
    pos += 32;

    let cks = if flags & 0b00010 != 0 {
        need(pos, 32, "cks")?;
        let v = arr32(&bytes[pos..pos + 32]);
        pos += 32;
        Some(v)
    } else {
        None
    };
    let ckr = if flags & 0b00100 != 0 {
        need(pos, 32, "ckr")?;
        let v = arr32(&bytes[pos..pos + 32]);
        pos += 32;
        Some(v)
    } else {
        None
    };

    need(pos, 20, "ns/nr/pn/dh_ratchet_turns/pq_remix_count")?;
    let ns = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let nr = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let pn = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let dh_ratchet_turns = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let pq_remix_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;

    need(pos, 4, "skipped_count")?;
    let skipped_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut skipped = HashMap::with_capacity(skipped_count);
    for _ in 0..skipped_count {
        need(pos, 68, "a skipped-key entry")?;
        let dh_pub = arr32(&bytes[pos..pos + 32]);
        pos += 32;
        let n = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let mk = arr32(&bytes[pos..pos + 32]);
        pos += 32;
        skipped.insert((dh_pub, n), mk);
    }

    let pq_pending_offer = if flags & 0b01000 != 0 {
        need(pos, 1248, "pq_pending_offer")?;
        let v = MlKemKeyPair::from_bytes(&bytes[pos..pos + 1248]);
        pos += 1248;
        Some(v)
    } else {
        None
    };
    let pq_peer_offer_ek = if flags & 0b10000 != 0 {
        need(pos, kem::ML_KEM_768_EK_LEN, "pq_peer_offer_ek")?;
        let v = bytes[pos..pos + kem::ML_KEM_768_EK_LEN].to_vec();
        pos += kem::ML_KEM_768_EK_LEN;
        Some(v)
    } else {
        None
    };

    need(pos, 4, "pending_handshake_ct_len")?;
    let ct_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    need(pos, ct_len, "pending_handshake_ct")?;
    let pending_handshake_ct = if ct_len > 0 { Some(bytes[pos..pos + ct_len].to_vec()) } else { None };

    let state = RatchetState {
        dhs_priv,
        dhs_pub,
        dhr_pub,
        rk,
        cks,
        ckr,
        ns,
        nr,
        pn,
        skipped,
        dh_ratchet_turns,
        pq_remix_count,
        pq_pending_offer,
        pq_peer_offer_ek,
    };
    Ok((state, pending_handshake_ct))
}

fn skip_message_keys_to(state: &mut RatchetState, until: u32) -> Result<(), String> {
    let Some(ckr) = state.ckr else { return Ok(()) }; // Bob before his first receive: nothing to skip
    if until.saturating_sub(state.nr) > MAX_SKIP {
        return Err("too many skipped messages in one chain (possible DoS / lost messages)".to_string());
    }
    let mut ckr = ckr;
    while state.nr < until {
        let (new_ck, mk) = kdf_ck(&ckr);
        ckr = new_ck;
        state.skipped.insert((state.dhr_pub.expect("ckr implies dhr_pub is set"), state.nr), mk);
        state.nr += 1;
    }
    state.ckr = Some(ckr);
    Ok(())
}

/// A full DH ratchet turn: derive the closing receiving chain from the peer's new public key, then
/// generate a fresh DH keypair of our own and derive a new sending chain — the two-step structure
/// ("receive-turn" then "send-turn") that gives the Double Ratchet its self-healing property in both
/// directions. Sparse-PQ-Ratchet mixing does NOT happen here (see `mix_pq_secret`'s doc comment for
/// why) — it happens in `ratchet_encrypt`/`ratchet_decrypt` at each chain's `n == 0` message instead.
fn dh_ratchet_step(state: &mut RatchetState, new_dhr_pub: [u8; 32], seeds: &Entropy) {
    state.pn = state.ns;
    state.ns = 0;
    state.nr = 0;
    state.dhr_pub = Some(new_dhr_pub);

    let dh_out_recv = dh(&state.dhs_priv, &new_dhr_pub);
    let (rk1, ckr) = kdf_rk(&state.rk, &dh_out_recv);
    state.rk = rk1;
    state.ckr = Some(ckr);

    let (new_priv, new_pub) = dh_generate(&seeds.dh);
    state.dhs_priv = new_priv;
    state.dhs_pub = new_pub;
    let dh_out_send = dh(&state.dhs_priv, &new_dhr_pub);
    let (rk2, cks) = kdf_rk(&state.rk, &dh_out_send);
    state.rk = rk2;
    state.cks = Some(cks);

    state.dh_ratchet_turns += 1;
}

/// REAL BUG found live (2026-07-23, via an actual two-party browser test, not a unit test): this used
/// to `.expect()` the responder's sending chain, which panics (an `unreachable` wasm trap, surfacing
/// in a browser as a confusing "recursive use of an object detected" — wasm-bindgen's `&mut self`
/// borrow flag is left stuck set once a panic unwinds mid-call, poisoning the `RatchetSession` for
/// every later call too, not just this one). The underlying constraint IS real Double Ratchet
/// protocol behavior, not a crypto bug: the responder ("Bob") has no sending chain key until he's
/// decrypted the initiator's first message (which carries her new DH public key and triggers his
/// first DH-ratchet turn) — there is no key material to derive one from before that. But a real,
/// everyday user action (the person who created an invite typing a message before the other side has
/// joined) hit exactly this path, crashing the whole encryption module instead of getting a clean,
/// recoverable "can't send yet" result. Returns `Err` now; the `#[wasm_bindgen]` wrapper
/// (`encrypt_message`) already had a `Result` return type, so no signature-shape change reaches JS.
fn ratchet_encrypt(state: &mut RatchetState, plaintext: &[u8], seeds: &Entropy) -> Result<Vec<u8>, String> {
    let Some(mut cks) = state.cks else {
        return Err(
            "cannot send yet — must receive at least one message from the other side first (the \
             responder has no sending chain until then; this is a real Double Ratchet protocol \
             constraint, not a transient failure)"
                .to_string(),
        );
    };
    let n = state.ns;
    state.ns += 1;

    // Sparse PQ Ratchet mixing is confined to each chain's very first message (`n == 0`) — see
    // `mix_pq_secret`'s doc comment for why this specific synchronization point (rather than a
    // DH-ratchet-turn boundary) is what makes it symmetric between both peers. Deliberately mixes
    // into the CHAIN key only, not `state.rk` — an earlier version also folded it into `state.rk`
    // directly here, which broke: `state.rk` is a purely local value whose bitwise snapshots are
    // never meant to be compared across peers (only specific *paired* `kdf_rk` derivations are), so
    // mixing it asymmetrically (each side touching its own already-divergent local copy) desynced
    // every later DH ratchet turn's root-key salt. Chain-key mixing has no such hazard: `cks`/`ckr`
    // here are, by construction, the exact same value on both sides at this point (that's what the
    // matching `mk` below proves), so applying the identical fold to both is safe.
    let mut pq_ct_response = None;
    if n == 0 {
        if let Some(peer_ek) = state.pq_peer_offer_ek.take() {
            let (ct, pq_ss) = kem::ml_kem_encapsulate(&seeds.pq_encap, &peer_ek);
            pq_ct_response = Some(ct);
            cks = mix_pq_secret(&cks, &pq_ss);
            state.pq_remix_count += 1;
        }
    }

    let mut pq_ek_offer = None;
    if n == 0
        && state.pq_pending_offer.is_none()
        && state.dh_ratchet_turns > 0
        && state.dh_ratchet_turns % PQ_REMIX_EVERY_N_TURNS == 0
    {
        let kp = kem::ml_kem_generate_keypair(&seeds.pq_kp);
        pq_ek_offer = Some(kp.ek.clone());
        state.pq_pending_offer = Some(kp);
    }

    let (new_ck, mk) = kdf_ck(&cks);
    state.cks = Some(new_ck);

    let header = RatchetHeader { dh_pub: state.dhs_pub, pn: state.pn, n, pq_ek: pq_ek_offer, pq_ct: pq_ct_response };
    let header_bytes = header.to_bytes();
    let ciphertext = aead_encrypt(&mk, &header_bytes, plaintext);

    let mut wire = header_bytes;
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}

fn ratchet_decrypt(state: &mut RatchetState, wire: &[u8], seeds: &Entropy) -> Result<Vec<u8>, String> {
    let (header, header_bytes, ciphertext) = parse_wire(wire)?;

    if let Some(mk) = state.skipped.remove(&(header.dh_pub, header.n)) {
        return aead_decrypt(&mk, header_bytes, ciphertext);
    }

    if state.dhr_pub == Some(header.dh_pub) && header.n < state.nr {
        return Err(
            "message key for this sequence number was already consumed and is not cached — old keys \
             cannot be recovered by design (forward secrecy)"
                .to_string(),
        );
    }

    if state.dhr_pub != Some(header.dh_pub) {
        if state.ckr.is_some() {
            skip_message_keys_to(state, header.pn)?;
        }
        dh_ratchet_step(state, header.dh_pub, seeds);
    }
    skip_message_keys_to(state, header.n)?;

    let mut ckr = state.ckr.expect("dh_ratchet_step always establishes a receiving chain");

    // Symmetric counterpart of `ratchet_encrypt`'s `n == 0` block, operating on the SAME wire
    // message: whichever side sent it may have folded a Sparse-PQ-Ratchet secret in before deriving
    // this message's key, so we must do the identical fold before deriving ours.
    if header.n == 0 {
        if let Some(ek) = &header.pq_ek {
            state.pq_peer_offer_ek = Some(ek.clone());
        }
        if let Some(ct) = &header.pq_ct {
            if let Some(kp) = state.pq_pending_offer.take() {
                let pq_ss = kem::ml_kem_decapsulate(&kp, ct);
                ckr = mix_pq_secret(&ckr, &pq_ss);
                state.pq_remix_count += 1;
            }
        }
    }

    let (new_ck, mk) = kdf_ck(&ckr);
    state.ckr = Some(new_ck);
    state.nr = header.n + 1;

    aead_decrypt(&mk, header_bytes, ciphertext)
}

// ============================== wasm-bindgen surface (client-full only) ============================

#[wasm_bindgen]
pub fn identity_verifying_key(seed: &[u8]) -> Vec<u8> {
    identity_generate(&arr32(seed)).verifying.to_vec()
}

/// Sign a hybrid KEM prekey bundle (`kem_generate_keypair`'s public-key half, i.e. the first
/// `ML_KEM_768_EK_LEN + 32` bytes of its output) with a long-term identity key derived from `seed`.
#[wasm_bindgen]
pub fn identity_sign_bundle(seed: &[u8], hybrid_public_bytes: &[u8]) -> Vec<u8> {
    let id = identity_generate(&arr32(seed));
    let hp = HybridPublicKey::from_bytes(hybrid_public_bytes);
    bundle_sign(&id, &hp).to_vec()
}

#[wasm_bindgen]
pub fn identity_verify_bundle(verifying_key: &[u8], hybrid_public_bytes: &[u8], sig: &[u8]) -> bool {
    let hp = HybridPublicKey::from_bytes(hybrid_public_bytes);
    let Ok(sig_arr): Result<[u8; 64], _> = sig.try_into() else { return false };
    let Ok(vk_arr): Result<[u8; 32], _> = verifying_key.try_into() else { return false };
    bundle_verify(&vk_arr, &hp, &sig_arr)
}

/// One party's live ratchet session. Opaque to JS beyond `encryptMessage`/`decryptMessage` — all
/// state (root/chain keys, skipped-message cache, pending Sparse-PQ offers) lives inside the WASM
/// linear memory behind this handle, never serialized out to JS except as wire bytes.
#[wasm_bindgen]
pub struct RatchetSession {
    state: RatchetState,
    pending_handshake_ct: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl RatchetSession {
    /// Alice's side of the handshake. Verifies Bob's signed prekey bundle FIRST — a bad/missing
    /// signature is refused outright, which is what makes this "PQXDH-style" rather than bare DH: an
    /// attacker without Bob's identity signing key cannot get this call to succeed with a substituted
    /// bundle. On success, does the hybrid ML-KEM+X25519 encapsulation and initializes the ratchet as
    /// the initiator. The resulting session's `takeHandshakeCiphertext()` must be sent to Bob as (or
    /// alongside) the very first message.
    #[wasm_bindgen(js_name = handshakeInitiate)]
    pub fn handshake_initiate(
        kem_seed: &[u8],
        dh_seed: &[u8],
        peer_verifying_key: &[u8],
        peer_bundle_bytes: &[u8],
        peer_bundle_sig: &[u8],
    ) -> Result<RatchetSession, JsError> {
        let vk_arr: [u8; 32] = peer_verifying_key
            .try_into()
            .map_err(|_| JsError::new("peer_verifying_key must be 32 bytes"))?;
        let sig_arr: [u8; 64] = peer_bundle_sig
            .try_into()
            .map_err(|_| JsError::new("peer_bundle_sig must be 64 bytes"))?;
        let peer_hp = HybridPublicKey::from_bytes(peer_bundle_bytes);
        if !bundle_verify(&vk_arr, &peer_hp, &sig_arr) {
            return Err(JsError::new(
                "peer prekey bundle signature is invalid — refusing to establish a session (possible MITM)",
            ));
        }
        let (ct, root_key) = kem::encapsulate(&arr32(kem_seed), &peer_hp);
        let bob_dh_pub = peer_hp.x25519_pk;
        let state = ratchet_init_alice(root_key, bob_dh_pub, &arr32(dh_seed));
        Ok(RatchetSession { state, pending_handshake_ct: Some(ct.to_bytes()) })
    }

    /// Bob's side. `my_hybrid_keypair_bytes` is his own `kem_generate_keypair` output (the same
    /// keypair whose public half he published, signed, as his prekey bundle) — its X25519 leg doubles
    /// as his initial Double Ratchet key, exactly like Signal reusing the signed prekey.
    #[wasm_bindgen(js_name = handshakeRespond)]
    pub fn handshake_respond(my_hybrid_keypair_bytes: &[u8], handshake_ct_bytes: &[u8]) -> RatchetSession {
        let kp = HybridKeyPair::from_bytes(my_hybrid_keypair_bytes);
        let ct = HybridCiphertext::from_bytes(handshake_ct_bytes);
        let root_key = kem::decapsulate(&kp, &ct);
        let my_dh_priv = kp.x25519_secret();
        let my_dh_pub = kp.public.x25519_pk;
        let state = ratchet_init_bob(root_key, my_dh_priv, my_dh_pub);
        RatchetSession { state, pending_handshake_ct: None }
    }

    /// Alice's side, WITH a one-time prekey (docs/03 §4's full X3DH-style bundle: identity + signed
    /// prekey + one-time prekeys). Strictly stronger than `handshakeInitiate` above: the final root
    /// key folds in a SECOND independent hybrid encapsulation, this one against a prekey PrekeyDO
    /// deletes after this single fetch — so recovering this session's root key later requires BOTH
    /// the signed prekey's private key AND the one-time prekey's (already-discarded) private key, not
    /// either alone. Same signature-verification gate as `handshakeInitiate` (unchanged — the identity
    /// key signs only the signed prekey, matching real X3DH; one-time prekeys ride on that same
    /// authenticated channel rather than being individually signed). `peer_onetime_bytes` empty means
    /// "PrekeyDO's pool was empty" — real X3DH tolerates this; use `handshakeInitiate` instead in that
    /// case rather than calling this with an empty slice (kept as two functions, not one with a
    /// sometimes-empty argument, to make that caller-side branch explicit rather than silently baked
    /// into this one's control flow).
    #[wasm_bindgen(js_name = handshakeInitiateWithOnetime)]
    pub fn handshake_initiate_with_onetime(
        kem_seed: &[u8],
        onetime_kem_seed: &[u8],
        dh_seed: &[u8],
        peer_verifying_key: &[u8],
        peer_bundle_bytes: &[u8],
        peer_bundle_sig: &[u8],
        peer_onetime_bytes: &[u8],
    ) -> Result<RatchetSession, JsError> {
        let vk_arr: [u8; 32] = peer_verifying_key
            .try_into()
            .map_err(|_| JsError::new("peer_verifying_key must be 32 bytes"))?;
        let sig_arr: [u8; 64] = peer_bundle_sig
            .try_into()
            .map_err(|_| JsError::new("peer_bundle_sig must be 64 bytes"))?;
        let peer_hp = HybridPublicKey::from_bytes(peer_bundle_bytes);
        if !bundle_verify(&vk_arr, &peer_hp, &sig_arr) {
            return Err(JsError::new(
                "peer prekey bundle signature is invalid — refusing to establish a session (possible MITM)",
            ));
        }
        let peer_onetime_hp = HybridPublicKey::from_bytes(peer_onetime_bytes);

        let (signed_ct, signed_root) = kem::encapsulate(&arr32(kem_seed), &peer_hp);
        let (onetime_ct, onetime_root) = kem::encapsulate(&arr32(onetime_kem_seed), &peer_onetime_hp);
        let root_key = kem::combine_with_onetime(&signed_root, &onetime_root);

        let bob_dh_pub = peer_hp.x25519_pk;
        let state = ratchet_init_alice(root_key, bob_dh_pub, &arr32(dh_seed));
        // Fixed-length concatenation (both ciphertexts are always ML_KEM_768_CT_LEN + 32 bytes), not a
        // length-prefixed framing — `handshakeRespondWithOnetime` below knows the exact split point.
        let mut ct_bytes = signed_ct.to_bytes();
        ct_bytes.extend_from_slice(&onetime_ct.to_bytes());
        Ok(RatchetSession { state, pending_handshake_ct: Some(ct_bytes) })
    }

    /// Bob's side, WITH a one-time prekey. `my_onetime_keypair_bytes` must be the SPECIFIC one-time
    /// keypair whose public half PrekeyDO handed out to this particular initiator (looked up by the
    /// id the initiator's `session_init` envelope references — see useQueueTransport.ts) — using the
    /// wrong one-time keypair fails to decapsulate to the same root key Alice derived, same as using
    /// the wrong signed-prekey keypair would. Callers MUST discard/never reuse this one-time keypair
    /// after this call succeeds (PrekeyDO already deletes the public half server-side on fetch; this
    /// is the client-side half of that same single-use guarantee).
    #[wasm_bindgen(js_name = handshakeRespondWithOnetime)]
    pub fn handshake_respond_with_onetime(
        my_hybrid_keypair_bytes: &[u8],
        my_onetime_keypair_bytes: &[u8],
        handshake_ct_bytes: &[u8],
    ) -> Result<RatchetSession, JsError> {
        let ct_pair_len = 2 * (kem::ML_KEM_768_CT_LEN + 32);
        if handshake_ct_bytes.len() != ct_pair_len {
            return Err(JsError::new(&format!(
                "handshake_ct_bytes must be {ct_pair_len} bytes (signed-prekey ct || one-time-prekey ct), got {}",
                handshake_ct_bytes.len()
            )));
        }
        let (signed_ct_bytes, onetime_ct_bytes) = handshake_ct_bytes.split_at(kem::ML_KEM_768_CT_LEN + 32);

        let kp = HybridKeyPair::from_bytes(my_hybrid_keypair_bytes);
        let onetime_kp = HybridKeyPair::from_bytes(my_onetime_keypair_bytes);
        let signed_root = kem::decapsulate(&kp, &HybridCiphertext::from_bytes(signed_ct_bytes));
        let onetime_root = kem::decapsulate(&onetime_kp, &HybridCiphertext::from_bytes(onetime_ct_bytes));
        let root_key = kem::combine_with_onetime(&signed_root, &onetime_root);

        let my_dh_priv = kp.x25519_secret();
        let my_dh_pub = kp.public.x25519_pk;
        let state = ratchet_init_bob(root_key, my_dh_priv, my_dh_pub);
        Ok(RatchetSession { state, pending_handshake_ct: None })
    }

    /// Alice only: the hybrid KEM ciphertext to deliver to Bob alongside her first ratchet message.
    /// Returns an empty vec once already taken (or on a Bob-side session, which never has one).
    #[wasm_bindgen(js_name = takeHandshakeCiphertext)]
    pub fn take_handshake_ciphertext(&mut self) -> Vec<u8> {
        self.pending_handshake_ct.take().unwrap_or_default()
    }

    /// How many times the Sparse PQ Ratchet has actually folded a fresh ML-KEM shared secret into the
    /// root key so far — a live-testable, non-cosmetic signal that the PQ remix path really ran.
    #[wasm_bindgen(js_name = pqRemixCount)]
    pub fn pq_remix_count(&self) -> u32 {
        self.state.pq_remix_count
    }

    /// Encrypt one message. `entropy` must be 96 fresh random bytes (`crypto.getRandomValues`); most
    /// of it goes unused on any given call (only consumed on a DH-ratchet-turn send or a Sparse-PQ
    /// offer), but which case applies isn't knowable to the caller in advance.
    #[wasm_bindgen(js_name = encryptMessage)]
    pub fn encrypt_message(&mut self, plaintext: &str, entropy: &[u8]) -> Result<Vec<u8>, JsError> {
        let seeds = Entropy::from_bytes(entropy).map_err(|e| JsError::new(&e))?;
        ratchet_encrypt(&mut self.state, plaintext.as_bytes(), &seeds).map_err(|e| JsError::new(&e))
    }

    /// Decrypt one wire message. Same 96-byte entropy contract as `encryptMessage` (consumed only if
    /// this call happens to trigger a DH ratchet turn or must encapsulate to a peer's Sparse-PQ
    /// offer). Returns an `Err` — never partial/garbage plaintext — on a bad tag, a tampered header,
    /// too many skipped messages, or a replayed/already-consumed sequence number.
    #[wasm_bindgen(js_name = decryptMessage)]
    pub fn decrypt_message(&mut self, wire: &[u8], entropy: &[u8]) -> Result<String, JsError> {
        let seeds = Entropy::from_bytes(entropy).map_err(|e| JsError::new(&e))?;
        let plaintext = ratchet_decrypt(&mut self.state, wire, &seeds).map_err(|e| JsError::new(&e))?;
        String::from_utf8(plaintext).map_err(|_| JsError::new("decrypted bytes are not valid UTF-8"))
    }

    /// Device-linking pass: serialize the ENTIRE live session state to bytes — see this file's
    /// "State export/import" module doc for the exact layout and, more importantly, the load-bearing
    /// warning that the result is as sensitive as this session's full compromise. The caller MUST
    /// seal this under a real AEAD key before it leaves device memory; this method itself performs
    /// no sealing, no transport, and no persistence — it only converts state to bytes.
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Vec<u8> {
        serialize_ratchet_state(&self.state, &self.pending_handshake_ct)
    }

    /// The other half of `exportState` — reconstructs a live session from a previously exported blob.
    /// Errors on a truncated/malformed blob rather than silently producing a partially-initialized
    /// session. Callers are responsible for the same "only one device live at a time" discipline
    /// `exportState`'s doc comment describes; this constructor has no way to enforce it.
    #[wasm_bindgen(js_name = importState)]
    pub fn import_state(bytes: &[u8]) -> Result<RatchetSession, JsError> {
        let (state, pending_handshake_ct) = deserialize_ratchet_state(bytes).map_err(|e| JsError::new(&e))?;
        Ok(RatchetSession { state, pending_handshake_ct })
    }
}

// Tests exercise the inner (non-`#[wasm_bindgen]`) functions directly, not the `RatchetSession`
// adapter — same convention as symmetric.rs's test module: constructing a `JsError` panics on a
// native (non-wasm) target, so any test path that would hit an adapter's error branch (e.g. the
// forward-secrecy test, which *expects* a decrypt failure) can't run through the wasm-bindgen surface
// off-wasm. The inner fns hold all the real logic; the adapters only translate `String` -> `JsError`.
#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn entropy(tag: u8) -> Entropy {
        Entropy::from_bytes(&vec![tag; 96]).unwrap()
    }

    fn encrypt(state: &mut RatchetState, plaintext: &str, tag: u8) -> Vec<u8> {
        ratchet_encrypt(state, plaintext.as_bytes(), &entropy(tag)).expect("test call sites always send after a sending chain exists")
    }

    fn decrypt(state: &mut RatchetState, wire: &[u8], tag: u8) -> Result<String, String> {
        let bytes = ratchet_decrypt(state, wire, &entropy(tag))?;
        Ok(String::from_utf8(bytes).unwrap())
    }

    /// Runs a full handshake and returns (alice, bob) states ready to exchange messages.
    fn setup() -> (RatchetState, RatchetState) {
        let bob_kem_keypair = kem::generate_keypair(&seed(1));
        let bob_identity = identity_generate(&seed(2));
        let sig = bundle_sign(&bob_identity, &bob_kem_keypair.public);
        assert!(bundle_verify(&bob_identity.verifying, &bob_kem_keypair.public, &sig), "own signature must verify");

        let (ct, alice_root_key) = kem::encapsulate(&seed(3), &bob_kem_keypair.public);
        let alice = ratchet_init_alice(alice_root_key, bob_kem_keypair.public.x25519_pk, &seed(4));

        let bob_root_key = kem::decapsulate(&bob_kem_keypair, &ct);
        assert_eq!(alice_root_key, bob_root_key, "both sides must derive the same PQXDH root key");
        let bob = ratchet_init_bob(bob_root_key, bob_kem_keypair.x25519_secret(), bob_kem_keypair.public.x25519_pk);

        (alice, bob)
    }

    #[test]
    fn handshake_rejects_bad_signature() {
        let bob_kem_keypair = kem::generate_keypair(&seed(1));
        let real_bob_identity = identity_generate(&seed(2));
        // Signed by a DIFFERENT identity than the one Alice thinks she's talking to.
        let wrong_sig = bundle_sign(&identity_generate(&seed(99)), &bob_kem_keypair.public);
        assert!(
            !bundle_verify(&real_bob_identity.verifying, &bob_kem_keypair.public, &wrong_sig),
            "a bundle signed by the wrong identity key must be rejected"
        );
    }

    #[test]
    fn messages_round_trip_both_directions() {
        let (mut alice, mut bob) = setup();

        let wire1 = encrypt(&mut alice, "hello bob", 10);
        assert_eq!(decrypt(&mut bob, &wire1, 11).unwrap(), "hello bob");

        let wire2 = encrypt(&mut bob, "hello alice", 12);
        assert_eq!(decrypt(&mut alice, &wire2, 13).unwrap(), "hello alice");

        let wire3 = encrypt(&mut alice, "second message", 14);
        assert_eq!(decrypt(&mut bob, &wire3, 15).unwrap(), "second message");
    }

    /// Real bug found live (2026-07-23, two-party browser test — see this function's neighbor
    /// `ratchet_encrypt`'s own doc comment for the full story): the responder trying to send before
    /// ever receiving a message used to PANIC (`unreachable` wasm trap, "poisoning" the whole
    /// `RatchetSession` object for every later call — confirmed by an isolated Node repro before this
    /// fix). A completely ordinary user action (the person who creates an invite typing a message
    /// while waiting for the other side to join) hit this every single time. Must now be a clean,
    /// recoverable `Err`, not a crash.
    #[test]
    fn responder_sending_before_receiving_anything_is_a_clean_error_not_a_panic() {
        let (mut alice, mut bob) = setup();
        let result = ratchet_encrypt(&mut bob, b"bob trying to speak first", &entropy(5));
        assert!(result.is_err(), "Bob has no sending chain yet — must be Err, not a crash or a bogus Ok");

        // The SAME session must still work normally afterward — a rejected send must not leave the
        // state corrupted for a later, legitimate exchange (this is exactly the "poisoned object"
        // failure mode the panic version had; a clean Err must not have that effect at all).
        // Nothing to reset here since `bob` was never mutated on the error path.
        let wire = encrypt(&mut alice, "alice speaks first, as the protocol requires", 6);
        assert_eq!(decrypt(&mut bob, &wire, 7).unwrap(), "alice speaks first, as the protocol requires");
        let reply = encrypt(&mut bob, "now bob can reply", 8);
        assert_eq!(decrypt(&mut alice, &reply, 9).unwrap(), "now bob can reply");
    }

    #[test]
    fn each_message_ciphertext_is_distinct_even_for_identical_plaintext() {
        let (mut alice, mut bob) = setup();
        let wire1 = encrypt(&mut alice, "same text", 20);
        decrypt(&mut bob, &wire1, 21).unwrap();
        let wire2 = encrypt(&mut bob, "reply", 22);
        decrypt(&mut alice, &wire2, 23).unwrap();
        let wire3 = encrypt(&mut alice, "same text", 24);
        // Different message key each time (chain ratchet) -> different ciphertext despite identical
        // plaintext and despite reusing the fixed all-zero AEAD nonce.
        assert_ne!(wire1, wire3);
    }

    #[test]
    fn forward_secrecy_old_message_key_is_gone_after_it_is_consumed() {
        let (mut alice, mut bob) = setup();
        let wire1 = encrypt(&mut alice, "secret one", 30);
        decrypt(&mut bob, &wire1, 31).unwrap(); // consumes message 0's key, advances nr
        let wire2 = encrypt(&mut alice, "secret two", 32);
        decrypt(&mut bob, &wire2, 33).unwrap();

        // Replaying the FIRST captured ciphertext against Bob's now-advanced state must fail — the
        // key that decrypted it is gone, not re-derivable from the current chain state.
        let replay = decrypt(&mut bob, &wire1, 34);
        assert!(replay.is_err(), "a consumed message key must not be recoverable from later ratchet state");
    }

    #[test]
    fn out_of_order_delivery_still_decrypts_via_skipped_key_cache() {
        let (mut alice, mut bob) = setup();
        let wire1 = encrypt(&mut alice, "first", 40);
        let wire2 = encrypt(&mut alice, "second", 41);
        // Bob receives message 2 before message 1 (network reordering).
        assert_eq!(decrypt(&mut bob, &wire2, 42).unwrap(), "second");
        assert_eq!(decrypt(&mut bob, &wire1, 43).unwrap(), "first");
    }

    #[test]
    fn sparse_pq_ratchet_actually_remixes_after_enough_turns() {
        let (mut alice, mut bob) = setup();
        assert_eq!(alice.pq_remix_count, 0);
        assert_eq!(bob.pq_remix_count, 0);

        // Alternate senders to force repeated DH ratchet turns (a turn happens each time the sender
        // direction flips) until PQ_REMIX_EVERY_N_TURNS is crossed on at least one side.
        for i in 0..14u8 {
            if i % 2 == 0 {
                let wire = encrypt(&mut alice, "ping", 50 + i);
                decrypt(&mut bob, &wire, 80 + i).unwrap_or_else(|e| panic!("i={i} bob decrypt failed: {e}"));
            } else {
                let wire = encrypt(&mut bob, "pong", 50 + i);
                decrypt(&mut alice, &wire, 80 + i).unwrap_or_else(|e| panic!("i={i} alice decrypt failed: {e}"));
            }
        }

        assert!(
            alice.pq_remix_count > 0 || bob.pq_remix_count > 0,
            "expected at least one Sparse PQ Ratchet remix after 14 alternating turns"
        );
    }

    // ============================ State export/import (device-linking pass) =========================

    #[test]
    fn exported_state_round_trips_and_a_linked_device_continues_the_conversation() {
        let (mut alice, mut bob) = setup();
        // Exchange a couple of messages first so the exported state isn't the trivial just-initialized
        // case — advances chain keys, ns/nr, and forces a DH ratchet turn (sender flips).
        let wire1 = encrypt(&mut alice, "before linking", 90);
        assert_eq!(decrypt(&mut bob, &wire1, 91).unwrap(), "before linking");
        let wire2 = encrypt(&mut bob, "reply before linking", 92);
        assert_eq!(decrypt(&mut alice, &wire2, 93).unwrap(), "reply before linking");

        // "Link a second device": export Bob's live state, reconstruct it into a fresh RatchetState —
        // this is exactly what apps/web's device-linking transfer does, minus the AEAD sealing around
        // the blob (out of this crate's scope, see this module's own doc comment).
        let exported = serialize_ratchet_state(&bob, &None);
        let (mut bob_linked_device, pending_ct) = deserialize_ratchet_state(&exported).expect("a freshly exported blob must deserialize");
        assert!(pending_ct.is_none(), "an established session (past the handshake) has no pending handshake ciphertext to carry");

        // The linked device must be able to CONTINUE the conversation — decrypt a new message from
        // Alice, and have Alice successfully decrypt a message the linked device sends back. This is
        // the real correctness bar: not just "the bytes round-trip", but "the ratchet still agrees".
        let wire3 = encrypt(&mut alice, "after linking, does the new device see this?", 94);
        assert_eq!(decrypt(&mut bob_linked_device, &wire3, 95).unwrap(), "after linking, does the new device see this?");
        let wire4 = encrypt(&mut bob_linked_device, "yes, the linked device replies", 96);
        assert_eq!(decrypt(&mut alice, &wire4, 97).unwrap(), "yes, the linked device replies");
    }

    #[test]
    fn exported_state_preserves_skipped_keys_and_pending_pq_offer() {
        let (mut alice, mut bob) = setup();
        // Force an out-of-order skipped-key entry AND enough alternating turns to populate a pending
        // Sparse-PQ offer on one side, so the export covers BOTH optional/variable-length parts of the
        // layout, not just the always-present fields the test above already exercises.
        let wire_a = encrypt(&mut alice, "skip me first", 100);
        let wire_b = encrypt(&mut alice, "arrives first", 101);
        assert_eq!(decrypt(&mut bob, &wire_b, 102).unwrap(), "arrives first"); // bob now has a skipped-key cache entry for wire_a's seq

        for i in 0..7u8 {
            if i % 2 == 0 {
                let w = encrypt(&mut bob, "ping", 110 + i);
                decrypt(&mut alice, &w, 130 + i).unwrap();
            } else {
                let w = encrypt(&mut alice, "pong", 110 + i);
                decrypt(&mut bob, &w, 130 + i).unwrap();
            }
        }
        assert!(!bob.skipped.is_empty(), "precondition: bob must have at least one cached skipped key before export");

        let exported = serialize_ratchet_state(&bob, &None);
        let (bob_linked_device, _) = deserialize_ratchet_state(&exported).expect("must deserialize");
        assert_eq!(bob_linked_device.skipped, bob.skipped, "the skipped-key cache must survive export/import exactly");
        assert_eq!(bob_linked_device.pq_remix_count, bob.pq_remix_count);
        assert_eq!(bob_linked_device.pq_pending_offer.is_some(), bob.pq_pending_offer.is_some());
        assert_eq!(bob_linked_device.pq_peer_offer_ek, bob.pq_peer_offer_ek);

        // The originally-skipped message must still decrypt correctly on the linked device, proving
        // the skipped-key cache isn't just byte-identical but actually functional after import.
        let mut bob_linked_device = bob_linked_device;
        let seeds = entropy(140);
        let recovered = ratchet_decrypt(&mut bob_linked_device, &wire_a, &seeds).expect("the linked device must still recover the skipped message");
        assert_eq!(String::from_utf8(recovered).unwrap(), "skip me first");
    }

    #[test]
    fn deserialize_rejects_truncated_state() {
        let (_, bob) = setup();
        let exported = serialize_ratchet_state(&bob, &None);
        for cut in [0usize, 1, 32, 65, 100] {
            assert!(
                deserialize_ratchet_state(&exported[..cut]).is_err(),
                "truncating to {cut} bytes must be rejected, not silently accepted or panic"
            );
        }
    }

    // ============================ One-time-prekey handshake (rotation pass) =========================
    // Same convention as `setup()` above and for the same reason, not just "JsError panics off-wasm":
    // `#[wasm_bindgen]`-annotated items generally can't be called on a native target at all (confirmed
    // empirically while writing this test — an adapter-level attempt panics with wasm-bindgen's own
    // "cannot call wasm-bindgen imported functions on non-wasm targets", even for a call that never
    // reaches an error branch). `handshakeInitiateWithOnetime`/`handshakeRespondWithOnetime`'s adapter
    // layer is thin glue over the logic this test already exercises directly (concatenate/split two
    // fixed-length ciphertexts) — real coverage of the compiled WASM adapter itself happens via a
    // Node script against the actual built `pkg/client` output, not a native `cargo test`, matching
    // how `handshake_initiate`/`handshake_respond` themselves have never had a native adapter-level
    // test either.

    #[test]
    fn onetime_prekey_handshake_both_sides_agree_and_the_mix_is_load_bearing() {
        let bob_kem_keypair = kem::generate_keypair(&seed(1));
        let bob_onetime_keypair = kem::generate_keypair(&seed(50));
        let bob_identity = identity_generate(&seed(2));
        let sig = bundle_sign(&bob_identity, &bob_kem_keypair.public);
        assert!(bundle_verify(&bob_identity.verifying, &bob_kem_keypair.public, &sig));

        // Alice encapsulates to BOTH the signed prekey and the one-time prekey, combines the two
        // resulting root keys — this is exactly what `handshakeInitiateWithOnetime` does internally.
        let (signed_ct, alice_signed_root) = kem::encapsulate(&seed(3), &bob_kem_keypair.public);
        let (onetime_ct, alice_onetime_root) = kem::encapsulate(&seed(51), &bob_onetime_keypair.public);
        let alice_root = kem::combine_with_onetime(&alice_signed_root, &alice_onetime_root);

        let bob_signed_root = kem::decapsulate(&bob_kem_keypair, &signed_ct);
        let bob_onetime_root = kem::decapsulate(&bob_onetime_keypair, &onetime_ct);
        let bob_root = kem::combine_with_onetime(&bob_signed_root, &bob_onetime_root);

        assert_eq!(alice_root, bob_root, "both sides must derive the same one-time-strengthened root key");
        // Load-bearing, not cosmetic: the one-time-prekey mix must actually CHANGE the root key
        // relative to the signed-prekey-only path — otherwise it would add no real security property.
        assert_ne!(alice_root, alice_signed_root, "mixing the one-time prekey must change the resulting root key");

        let mut alice_state = ratchet_init_alice(alice_root, bob_kem_keypair.public.x25519_pk, &seed(4));
        let mut bob_state = ratchet_init_bob(bob_root, bob_kem_keypair.x25519_secret(), bob_kem_keypair.public.x25519_pk);
        let wire = encrypt(&mut alice_state, "onetime-strengthened hello", 60);
        assert_eq!(decrypt(&mut bob_state, &wire, 61).unwrap(), "onetime-strengthened hello");
    }
}
