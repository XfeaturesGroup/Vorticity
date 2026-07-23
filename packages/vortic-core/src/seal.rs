//! Sealed Sender++ envelope: sender field encrypted to recipient, padded to a power-of-two bucket.
//! See docs/03-crypto-core.md §6, point 1 ("sender field encrypted to recipient — server sees no
//! `from`") and point 4 ("constant-size envelopes via length padding to power-of-two buckets").
//! Client-side only.
//!
//! WHY A SEPARATE ENVELOPE KEY, NOT THE RATCHET SESSION KEY (`ratchet.rs`): the ratchet only exists
//! once a session is established, but docs/03 §6 point 3 requires receipts to be sent as
//! *independent* sealed messages, and the very first contact message needs sealing before any
//! ratchet session exists. So `seal()` derives its own single-message key via a fresh ephemeral
//! X25519 DH to the recipient's long-term X25519 public key (the same primitive `kem.rs` already
//! exports — reused directly, not reimplemented), fully decoupled from ratchet state. This means an
//! observer who somehow separated the envelope from its ratchet-encrypted payload learns nothing
//! about which ratchet session (if any) it belongs to — the two encryption layers are independent by
//! design, not just by accident.
//!
//! No internal randomness, same discipline as `kem.rs`/`oprf.rs`: every function takes a
//! caller-supplied 32-byte seed for the ephemeral key, sourced from `crypto.getRandomValues` in JS.
//!
//! Wire format of the returned envelope:
//! ```text
//! ephemeral_x25519_pub (32 bytes)
//! nonce                (12 bytes)
//! ciphertext           (padded_plaintext_len + 16-byte Poly1305 tag) — ALWAYS exactly 2^bucket total
//!                        bytes for the envelope as a whole, for the smallest bucket that fits
//! ```
//! Inside the AEAD plaintext (before padding is stripped):
//! ```text
//! real_content_len : u16 BE  (2 bytes)  — length of everything below, NOT counting the zero pad
//! sender_cert_len  : u16 BE  (2 bytes)
//! sender_cert      : sender_cert_len bytes
//! plaintext        : remaining real_content_len - 2 - sender_cert_len bytes
//! zero padding      : out to the chosen bucket size
//! ```
//! An explicit length prefix (not "trim trailing zero bytes") is required for correctness: real
//! plaintext is free to end in `0x00` bytes itself.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use wasm_bindgen::prelude::*;

use crate::kem::{x25519_derive_shared, x25519_generate_keypair};

const EPHEMERAL_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = EPHEMERAL_PUB_LEN + NONCE_LEN; // envelope bytes before the AEAD ciphertext
const LEN_PREFIX_LEN: usize = 2; // u16 BE
const MAX_SIZE_BUCKET: u32 = 24; // 2^24 = 16 MiB — mirrors workers/messaging/src/bucketing.ts's own
                                  // cap; kept as a plain literal since a Rust crate cannot import a
                                  // TS constant, but the two are meant to describe the SAME ceiling.

/// Smallest `b` with `len <= 2^b` (and `len > 2^(b-1)` whenever `b > 0`) — same convention as
/// `bucketing.ts`'s `validateSizeBucket`, so a future caller that wires this into the Worker-side
/// size-bucket header gets byte-identical bucket numbers on both ends without any conversion step.
fn size_bucket_for(len: usize) -> u32 {
    if len <= 1 {
        return 0;
    }
    (usize::BITS - (len - 1).leading_zeros()).min(MAX_SIZE_BUCKET)
}

fn u16_be(n: usize) -> [u8; 2] {
    (n as u16).to_be_bytes()
}

/// Encrypt `plaintext` for `recipient_x25519_pub`, sealing `sender_cert` inside the same
/// authenticated envelope so only the recipient — never the server — learns who sent it. Returns
/// `Err` only for malformed key material (wrong slice lengths) or content too large for
/// `MAX_SIZE_BUCKET` — never partial output.
pub fn seal(
    ephemeral_seed: &[u8; 32],
    sender_cert: &[u8],
    plaintext: &[u8],
    recipient_x25519_pub: &[u8; 32],
) -> Result<Vec<u8>, String> {
    if sender_cert.len() > u16::MAX as usize || plaintext.len() > u16::MAX as usize {
        return Err("sender_cert or plaintext too long to length-prefix as u16".to_string());
    }

    let real_content_len = LEN_PREFIX_LEN + sender_cert.len() + plaintext.len();
    let total_envelope_len = HEADER_LEN + LEN_PREFIX_LEN + real_content_len + TAG_LEN;
    let bucket = size_bucket_for(total_envelope_len);
    if bucket > MAX_SIZE_BUCKET {
        return Err(format!("content too large for the {MAX_SIZE_BUCKET}-bucket ceiling"));
    }
    let target_envelope_len = 1usize << bucket;
    let target_plaintext_len = target_envelope_len - HEADER_LEN - TAG_LEN;
    let pad_len = target_plaintext_len - LEN_PREFIX_LEN - real_content_len;

    let mut padded_plaintext = Vec::with_capacity(target_plaintext_len);
    padded_plaintext.extend_from_slice(&u16_be(real_content_len));
    padded_plaintext.extend_from_slice(&u16_be(sender_cert.len()));
    padded_plaintext.extend_from_slice(sender_cert);
    padded_plaintext.extend_from_slice(plaintext);
    padded_plaintext.resize(padded_plaintext.len() + pad_len, 0u8);
    debug_assert_eq!(padded_plaintext.len(), target_plaintext_len);

    let ephemeral_keypair = x25519_generate_keypair(ephemeral_seed);
    let (ephemeral_secret, ephemeral_pub) = ephemeral_keypair.split_at(32);
    let shared_key = x25519_derive_shared(ephemeral_secret, recipient_x25519_pub);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce RNG failed: {e}"))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), padded_plaintext.as_slice())
        .map_err(|_| "seal encryption failed".to_string())?;

    let mut envelope = Vec::with_capacity(target_envelope_len);
    envelope.extend_from_slice(ephemeral_pub);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    debug_assert_eq!(envelope.len(), target_envelope_len);
    Ok(envelope)
}

/// Recover `(sender_cert, plaintext)` from an envelope `seal()` produced, using this recipient's
/// X25519 secret. Rejects a truncated envelope, a wrong recipient key, and any tampering (Poly1305
/// tag failure) — never returns partial or garbage output.
pub fn unseal(envelope: &[u8], recipient_x25519_secret: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err("envelope too short to contain a header + AEAD tag".to_string());
    }
    let (ephemeral_pub, rest) = envelope.split_at(EPHEMERAL_PUB_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let shared_key = x25519_derive_shared(recipient_x25519_secret, ephemeral_pub);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared_key));
    let padded_plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| "unseal failed (bad tag, wrong recipient key, or truncated envelope)".to_string())?;

    if padded_plaintext.len() < LEN_PREFIX_LEN {
        return Err("decrypted envelope shorter than its own length prefix".to_string());
    }
    let real_content_len = u16::from_be_bytes([padded_plaintext[0], padded_plaintext[1]]) as usize;
    let real_content = padded_plaintext
        .get(LEN_PREFIX_LEN..LEN_PREFIX_LEN + real_content_len)
        .ok_or_else(|| "real_content_len exceeds the decrypted envelope (corrupt padding)".to_string())?;

    if real_content.len() < LEN_PREFIX_LEN {
        return Err("real content shorter than its own sender_cert length prefix".to_string());
    }
    let sender_cert_len = u16::from_be_bytes([real_content[0], real_content[1]]) as usize;
    let after_prefix = &real_content[LEN_PREFIX_LEN..];
    if sender_cert_len > after_prefix.len() {
        return Err("sender_cert_len exceeds the real content (corrupt padding)".to_string());
    }
    let (sender_cert, plaintext) = after_prefix.split_at(sender_cert_len);
    Ok((sender_cert.to_vec(), plaintext.to_vec()))
}

// --- wasm-bindgen exports. This whole module is declared `#[cfg(feature = "client-full")]` in
// lib.rs (matching kem.rs, whose x25519_generate_keypair/x25519_derive_shared this module calls
// directly), so nothing below needs its own redundant cfg gate. ---

#[wasm_bindgen]
pub fn seal_message(ephemeral_seed: &[u8], sender_cert: &[u8], plaintext: &[u8], recipient_x25519_pub: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed: [u8; 32] = ephemeral_seed.try_into().map_err(|_| JsError::new("ephemeral_seed must be 32 bytes"))?;
    let recipient: [u8; 32] = recipient_x25519_pub.try_into().map_err(|_| JsError::new("recipient_x25519_pub must be 32 bytes"))?;
    seal(&seed, sender_cert, plaintext, &recipient).map_err(|e| JsError::new(&e))
}

#[wasm_bindgen]
pub fn unseal_message(envelope: &[u8], recipient_x25519_secret: &[u8]) -> Result<Vec<u8>, JsError> {
    let secret: [u8; 32] = recipient_x25519_secret
        .try_into()
        .map_err(|_| JsError::new("recipient_x25519_secret must be 32 bytes"))?;
    let (sender_cert, plaintext) = unseal(envelope, &secret).map_err(|e| JsError::new(&e))?;
    // Pack as sender_cert_len(u16 BE) || sender_cert || plaintext for the JS side to split — same
    // length-prefix idiom as the internal wire format, so JS needs no separate parsing convention.
    let mut out = Vec::with_capacity(2 + sender_cert.len() + plaintext.len());
    out.extend_from_slice(&u16_be(sender_cert.len()));
    out.extend_from_slice(&sender_cert);
    out.extend_from_slice(&plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECIPIENT_SEED: [u8; 32] = [42u8; 32];
    const EPHEMERAL_SEED: [u8; 32] = [7u8; 32];

    fn recipient_keys() -> ([u8; 32], [u8; 32]) {
        let kp = x25519_generate_keypair(&RECIPIENT_SEED);
        let (sk, pk) = kp.split_at(32);
        (sk.try_into().unwrap(), pk.try_into().unwrap())
    }

    #[test]
    fn round_trips_sender_cert_and_plaintext() {
        let (recipient_sk, recipient_pk) = recipient_keys();
        let envelope = seal(&EPHEMERAL_SEED, b"alice-cert-v1", b"hello sealed world", &recipient_pk).unwrap();
        let (sender_cert, plaintext) = unseal(&envelope, &recipient_sk).unwrap();
        assert_eq!(sender_cert, b"alice-cert-v1");
        assert_eq!(plaintext, b"hello sealed world");
    }

    #[test]
    fn envelope_length_is_always_exactly_a_power_of_two() {
        let (_recipient_sk, recipient_pk) = recipient_keys();
        for (cert, msg) in [
            (b"c".as_slice(), b"m".as_slice()),
            (b"a-longer-cert".as_slice(), b"a somewhat longer plaintext message".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            let envelope = seal(&EPHEMERAL_SEED, cert, msg, &recipient_pk).unwrap();
            let len = envelope.len();
            assert_eq!(len & (len - 1), 0, "envelope length {len} is not a power of two");
        }
    }

    #[test]
    fn different_plaintexts_of_different_length_can_share_a_bucket_indistinguishably() {
        // The whole point of point 4 (docs/03 §6): a passive observer of envelope SIZE alone must
        // not learn real content length beyond which bucket it landed in.
        let (_recipient_sk, recipient_pk) = recipient_keys();
        let short = seal(&EPHEMERAL_SEED, b"cert", b"hi", &recipient_pk).unwrap();
        let longer = seal(&EPHEMERAL_SEED, b"cert", b"a longer message but same bucket", &recipient_pk).unwrap();
        assert_eq!(short.len(), longer.len());
    }

    #[test]
    fn wrong_recipient_key_is_rejected() {
        let (_recipient_sk, recipient_pk) = recipient_keys();
        let envelope = seal(&EPHEMERAL_SEED, b"cert", b"secret", &recipient_pk).unwrap();
        let wrong_kp = x25519_generate_keypair(&[99u8; 32]);
        let (wrong_sk, _) = wrong_kp.split_at(32);
        assert!(unseal(&envelope, &wrong_sk.try_into().unwrap()).is_err());
    }

    #[test]
    fn tampering_is_rejected() {
        let (recipient_sk, recipient_pk) = recipient_keys();
        let mut envelope = seal(&EPHEMERAL_SEED, b"cert", b"secret", &recipient_pk).unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        assert!(unseal(&envelope, &recipient_sk).is_err());
    }

    #[test]
    fn truncated_envelope_is_rejected() {
        let (recipient_sk, recipient_pk) = recipient_keys();
        let envelope = seal(&EPHEMERAL_SEED, b"cert", b"secret", &recipient_pk).unwrap();
        assert!(unseal(&envelope[..HEADER_LEN + TAG_LEN - 1], &recipient_sk).is_err());
    }

    #[test]
    fn empty_sender_cert_and_plaintext_round_trip() {
        let (recipient_sk, recipient_pk) = recipient_keys();
        let envelope = seal(&EPHEMERAL_SEED, b"", b"", &recipient_pk).unwrap();
        let (sender_cert, plaintext) = unseal(&envelope, &recipient_sk).unwrap();
        assert!(sender_cert.is_empty());
        assert!(plaintext.is_empty());
    }

    #[test]
    fn size_bucket_matches_bucketing_ts_convention() {
        assert_eq!(size_bucket_for(1), 0);
        assert_eq!(size_bucket_for(2), 1);
        assert_eq!(size_bucket_for(3), 2);
        assert_eq!(size_bucket_for(4), 2);
        assert_eq!(size_bucket_for(5), 3);
        assert_eq!(size_bucket_for(64), 6);
        assert_eq!(size_bucket_for(65), 7);
    }
}
