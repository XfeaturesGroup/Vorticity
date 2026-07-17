//! Phase-1 real symmetric AEAD, exposed to JS via `wasm-bindgen`.
//!
//! This replaces the Phase-5 transport spike's reversible-XOR `mockCrypto.ts`. The mock proved the
//! *wire contract* ("only ciphertext crosses the socket"); this proves it for real: authenticated
//! encryption with ChaCha20-Poly1305 (RFC 8439), a fresh random 96-bit nonce per message, and a
//! 128-bit Poly1305 tag that makes tampering detectable (`decrypt_message` returns an error rather
//! than garbage on any bit-flip, wrong key, or truncation).
//!
//! KEY SOURCE: the 32-byte key is now a CALLER-SUPPLIED argument, not a hardcoded constant. The chat
//! transport derives it per-conversation from an X25519 Diffie-Hellman handshake (`kem.rs`'s
//! `x25519_generate_keypair`/`x25519_derive_shared`). What is still missing on top of this: post-
//! quantum hybrid (the ML-KEM leg of `kem.rs`), forward secrecy / a ratchet (`ratchet.rs`), and
//! prekey authentication (an unauthenticated DH is MITM-able on first contact) — all later work.
//!
//! Wire format (base64 of): nonce(12) || ciphertext(len) || tag(16). Self-framing — `decrypt_message`
//! splits the 12-byte nonce off the front and lets the AEAD verify the trailing tag.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use wasm_bindgen::prelude::*;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Encrypt a UTF-8 string under a 32-byte key, returning base64(`nonce || ciphertext || tag`).
///
/// A fresh random nonce is drawn per call (nonce reuse under a fixed key is catastrophic for any
/// AEAD), so calling this twice on identical plaintext yields different outputs — that is correct
/// and expected. Thin `#[wasm_bindgen]` adapter over [`encrypt_inner`]; the real work is in the
/// inner fn so it stays unit-testable on native targets (constructing a `JsError` panics off-wasm).
#[wasm_bindgen]
pub fn encrypt_message(key: &[u8], plaintext: &str) -> Result<String, JsError> {
    encrypt_inner(key, plaintext).map_err(|e| JsError::new(&e))
}

/// Decrypt base64(`nonce || ciphertext || tag`) under a 32-byte key back to the original string.
///
/// Returns an error (never partial/garbage plaintext) on a wrong-length key, malformed base64, a
/// too-short frame, a failed Poly1305 tag verification (tampering, wrong key), or non-UTF-8 output.
#[wasm_bindgen]
pub fn decrypt_message(key: &[u8], payload_b64: &str) -> Result<String, JsError> {
    decrypt_inner(key, payload_b64).map_err(|e| JsError::new(&e))
}

fn cipher_from_key(key: &[u8]) -> Result<ChaCha20Poly1305, String> {
    if key.len() != KEY_LEN {
        return Err(format!("key must be {KEY_LEN} bytes, got {}", key.len()));
    }
    Ok(ChaCha20Poly1305::new(Key::from_slice(key)))
}

fn encrypt_inner(key: &[u8], plaintext: &str) -> Result<String, String> {
    let cipher = cipher_from_key(key)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce RNG failed: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "encryption failed".to_string())?;

    let mut framed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    framed.extend_from_slice(&nonce_bytes);
    framed.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(framed))
}

fn decrypt_inner(key: &[u8], payload_b64: &str) -> Result<String, String> {
    let cipher = cipher_from_key(key)?;

    let framed = STANDARD
        .decode(payload_b64)
        .map_err(|_| "payload is not valid base64".to_string())?;
    if framed.len() < NONCE_LEN {
        return Err("payload too short to contain a nonce".to_string());
    }
    let (nonce_bytes, ciphertext) = framed.split_at(NONCE_LEN);

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| "decryption failed (bad tag, wrong key, or truncated)".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "decrypted bytes are not valid UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests target the inner fns, not the `#[wasm_bindgen]` adapters: constructing a `JsError`
    // panics on a native (non-wasm) target, so testing the adapters' error path off-wasm is
    // impossible. The inner fns hold all the real logic; the adapters only map `String` -> `JsError`.

    const K1: [u8; 32] = [1u8; 32];
    const K2: [u8; 32] = [2u8; 32];

    #[test]
    fn round_trips() {
        let ct = encrypt_inner(&K1, "hello vorticity").unwrap();
        assert_eq!(decrypt_inner(&K1, &ct).unwrap(), "hello vorticity");
    }

    #[test]
    fn nonce_is_fresh_each_call() {
        // Same plaintext + key, different ciphertext — proves the nonce is not fixed.
        assert_ne!(encrypt_inner(&K1, "dup").unwrap(), encrypt_inner(&K1, "dup").unwrap());
    }

    #[test]
    fn wrong_key_is_rejected() {
        // Encrypt under K1, try to decrypt under K2 — Poly1305 tag verification must fail.
        let ct = encrypt_inner(&K1, "secret").unwrap();
        assert!(decrypt_inner(&K2, &ct).is_err());
    }

    #[test]
    fn tamper_is_rejected() {
        let ct = encrypt_inner(&K1, "integrity").unwrap();
        let mut raw = STANDARD.decode(&ct).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01; // flip a bit in the Poly1305 tag
        assert!(decrypt_inner(&K1, &STANDARD.encode(raw)).is_err());
    }

    #[test]
    fn wrong_length_key_is_rejected() {
        assert!(encrypt_inner(&[0u8; 16], "x").is_err());
        assert!(decrypt_inner(&[0u8; 16], "AAAAAAAAAAAAAAAA").is_err());
    }

    #[test]
    fn wrong_length_payload_is_rejected() {
        assert!(decrypt_inner(&K1, &STANDARD.encode([0u8; 4])).is_err()); // shorter than a nonce
        assert!(decrypt_inner(&K1, "not base64!!!").is_err());
    }
}
