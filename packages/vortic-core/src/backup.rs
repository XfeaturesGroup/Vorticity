//! Local-first E2EE backups: BIP39 recovery phrase → Argon2id → AES-256-GCM. See
//! docs/03-crypto-core.md §11 and the risk register's R12 row ("Key-loss / recovery"). Client-side
//! only (`client-full`-gated at `lib.rs`) — the edge never sees a phrase, a derived key, or
//! plaintext state.
//!
//! PIPELINE (per docs/03 §11, followed literally):
//! `entropy (32 bytes, caller-supplied)` → BIP39 → `24-word phrase` → BIP39 `to_seed` (RFC-standard
//! PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase) → `64-byte seed` → Argon2id(m=256MiB, t=3,
//! p=1) → `32-byte master backup key` → AES-256-GCM(state).
//!
//! ENTROPY SOURCE: same "seed-threaded, no internal RNG" convention as `kem.rs`/`ratchet.rs` —
//! `generate_mnemonic` takes 32 bytes of caller-supplied entropy (the JS side draws these from
//! `crypto.getRandomValues`) rather than calling an OS RNG itself. 32 bytes of entropy is exactly
//! what BIP39 needs for a 24-word phrase (256 bits, the maximum BIP39 supports).
//!
//! WHY A FIXED ARGON2ID SALT IS THE RIGHT CHOICE HERE, NOT AN OVERSIGHT: Argon2's salt exists to
//! stop precomputation attacks across MANY users sharing a low-entropy input (e.g. short human
//! passwords). The "password" Argon2id stretches here is never that — it's the 64-byte BIP39 seed,
//! which is itself already a PBKDF2-HMAC-SHA512 stretch of 256 bits of real entropy. Deriving the
//! SAME master key from the SAME phrase every time (required for restore to work at all) means the
//! salt CANNOT be random — it must be a fixed, domain-separated constant, same pattern this crate's
//! HKDF call sites already use for `info` strings. `zeroize`d generously below since intermediate
//! seed/key material is genuinely sensitive.
//!
//! HONEST GAP, STATED PLAINLY (not verified in this pass): Argon2id at m=256MiB is real memory
//! pressure inside a WASM linear memory — this module's tests run it natively (`cargo test`), which
//! is fast and unconstrained; actual browser/mobile WASM behavior at this memory cost (docs/06 R6,
//! "WASM size/perf on mobile") was NOT live-verified here — that needs `apps/web` wiring + a real
//! browser run, out of this pass's scope (crate-only, per the task's own boundary).
//!
//! GENERATION KEYS (R12 rotation pass, 2026-07): the master key above is, by necessity, STATIC —
//! recovery must work from the phrase alone, with no other client-side state, so it can never
//! change. Real forward/backward secrecy for the backup CIPHERTEXT instead comes from a per-
//! generation data key, independently derived from the master key and a PUBLIC generation counter
//! `n` (the Worker already tracks `n` as a plain integer alongside the R2 object — it is not secret,
//! merely "how many times has this been rotated"):
//!   `gen_key[n] = HKDF(master_key, salt="vortic-backup-gen-v1", info=be32(n))`
//! This is deliberately an INDEXED derivation, not a hash chain (`gen_key[n+1] = H(gen_key[n])`): a
//! chain would let anyone who recovers ONE generation's key trivially walk forward to derive every
//! later one, which is exactly backwards from what rotation is supposed to buy. With indexed HKDF,
//! `gen_key[n]` for different `n` are cryptographically independent given only the master key is
//! secret — compromising one generation's key (e.g. a memory-scraping event on a device, without
//! ever obtaining the phrase itself) reveals nothing about any other generation, past or future.
//! Recovery still needs nothing but the phrase: fetch the current `n` from the server (public,
//! not sensitive) and re-derive `gen_key[n]` from `M` — no rotation counter needs to survive on the
//! client between a compromise and a later recovery.
//! AAD BINDING: `export_generation`/`import_generation` additionally bind `(backup_id, n)` into the
//! AEAD's associated data. This is defense-in-depth on top of the key derivation itself (which
//! already makes cross-generation/cross-account replay fail via a wrong key) — it turns any
//! accidental or adversarial generation/backup_id mismatch into an immediate, explicit AEAD tag
//! failure rather than relying solely on key derivation to have been done correctly upstream.
//! HONEST LIMIT: none of this defends against a compromise of the phrase/master key itself (full
//! root of trust, as always), nor against a malicious server replaying a stale `(ciphertext, n)`
//! pair specifically during RECOVERY on a device with no local memory of the last-seen `n` — that
//! specific rollback is undetectable without client-side state, which the recovery contract
//! explicitly excludes. Documented, not silently assumed away.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bip39::Mnemonic;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const ENTROPY_LEN: usize = 32; // 256 bits -> 24-word BIP39 phrase
const ARGON2_SALT: &[u8] = b"vortic-backup-v1-argon2id-fixed-salt"; // see module doc for why fixed
const ARGON2_M_COST_KIB: u32 = 256 * 1024; // 256 MiB, per docs/03 §11
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Generate a 24-word BIP39 recovery phrase from 32 bytes of caller-supplied entropy.
fn generate_mnemonic_inner(entropy: &[u8]) -> Result<String, String> {
    if entropy.len() != ENTROPY_LEN {
        return Err(format!("entropy must be {ENTROPY_LEN} bytes, got {}", entropy.len()));
    }
    let mnemonic = Mnemonic::from_entropy(entropy).map_err(|e| format!("invalid entropy: {e}"))?;
    Ok(mnemonic.to_string())
}

/// Stretch a BIP39 phrase into a 32-byte master backup key: parse+validate the phrase (rejects a
/// typo'd word or bad checksum outright, before ever touching Argon2id), take the standard 64-byte
/// BIP39 seed, then Argon2id-stretch it under the fixed domain-separated salt (see module doc).
fn derive_backup_key_inner(phrase: &str) -> Result<[u8; 32], String> {
    let mnemonic = Mnemonic::parse_normalized(phrase).map_err(|e| format!("invalid recovery phrase: {e}"))?;
    let mut seed = mnemonic.to_seed_normalized("");

    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|e| format!("invalid Argon2id params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    let result = argon2.hash_password_into(&seed, ARGON2_SALT, &mut key);
    seed.zeroize();
    result.map_err(|e| format!("Argon2id derivation failed: {e}"))?;
    Ok(key)
}

/// Derive the opaque 32-byte cloud-backup slot ID from the master backup key (docs/03 §11: "the
/// same ciphertext blob may be stored in R2 keyed by an opaque backup ID; the server holds an
/// unreadable blob"). Domain-separated via HKDF from the encryption key itself — the server-facing
/// ID and the client-only decryption key must never be the same value or derivable from one
/// another without this step, or leaking/logging the ID (which the Worker necessarily sees and can
/// log) would narrow the search space for the key it's supposed to be independent of. Deterministic
/// from the phrase alone (no caller-supplied salt) so a restore ("re-enroll + phrase") can recompute
/// the same slot ID without storing anything locally beyond the phrase.
fn derive_backup_id_inner(key: &[u8]) -> Result<[u8; 32], String> {
    if key.len() != KEY_LEN {
        return Err(format!("key must be {KEY_LEN} bytes, got {}", key.len()));
    }
    let id = crate::util::hkdf_sha256(key, &[], b"vortic-backup-id-v1", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&id);
    Ok(out)
}

fn cipher_from_key(key: &[u8]) -> Result<Aes256Gcm, String> {
    if key.len() != KEY_LEN {
        return Err(format!("key must be {KEY_LEN} bytes, got {}", key.len()));
    }
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
}

const GENERATION_KEY_SALT: &[u8] = b"vortic-backup-gen-v1";

/// Derive generation `n`'s independent AEAD key from the (phrase-derived, static) master key — see
/// the module doc's "GENERATION KEYS" section for why this is an indexed HKDF call, not a chain.
fn derive_generation_key_inner(master_key: &[u8], generation: u32) -> Result<[u8; 32], String> {
    if master_key.len() != KEY_LEN {
        return Err(format!("master_key must be {KEY_LEN} bytes, got {}", master_key.len()));
    }
    let okm = crate::util::hkdf_sha256(master_key, GENERATION_KEY_SALT, &generation.to_be_bytes(), KEY_LEN);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&okm);
    Ok(out)
}

/// `backup_id || generation` — bound into the AEAD's associated data by both
/// `export_generation_inner`/`import_generation_inner` below.
fn generation_aad(backup_id: &[u8], generation: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(backup_id.len() + 4);
    aad.extend_from_slice(backup_id);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

/// Encrypt local state under generation `n`'s data key, with `(backup_id, n)` bound as AAD. Same
/// wire shape as the non-generational `export_inner` (base64 of `nonce || ciphertext || tag`) — the
/// AAD is not on the wire, both sides recompute it from context they already have.
fn export_generation_inner(state: &[u8], gen_key: &[u8], backup_id: &[u8], generation: u32) -> Result<String, String> {
    let cipher = cipher_from_key(gen_key)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce RNG failed: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = generation_aad(backup_id, generation);

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: state, aad: &aad })
        .map_err(|_| "encryption failed".to_string())?;

    let mut framed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    framed.extend_from_slice(&nonce_bytes);
    framed.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(framed))
}

/// Decrypt a blob `export_generation_inner` produced. Fails (never partial output) on a wrong key,
/// a wrong `generation` or `backup_id` (AAD mismatch), tampering, or truncation.
fn import_generation_inner(blob_b64: &str, gen_key: &[u8], backup_id: &[u8], generation: u32) -> Result<Vec<u8>, String> {
    let cipher = cipher_from_key(gen_key)?;

    let framed = STANDARD.decode(blob_b64).map_err(|_| "payload is not valid base64".to_string())?;
    if framed.len() < NONCE_LEN {
        return Err("payload too short to contain a nonce".to_string());
    }
    let (nonce_bytes, ciphertext) = framed.split_at(NONCE_LEN);
    let aad = generation_aad(backup_id, generation);

    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), aes_gcm::aead::Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| "decryption failed (bad tag, wrong key/generation/backup_id, or truncated)".to_string())
}

// ── wasm-bindgen boundary ──────────────────────────────────────────────────────────────────────
// Thin adapters over the inner fns, matching symmetric.rs's convention: constructing a `JsError`
// panics off-wasm, so the real logic (and its tests) live in the native-testable inner fns above.

#[wasm_bindgen]
pub fn backup_generate_mnemonic(entropy: &[u8]) -> Result<String, JsError> {
    generate_mnemonic_inner(entropy).map_err(|e| JsError::new(&e))
}

#[wasm_bindgen]
pub fn backup_derive_key(phrase: &str) -> Result<Vec<u8>, JsError> {
    derive_backup_key_inner(phrase).map(|k| k.to_vec()).map_err(|e| JsError::new(&e))
}

/// Derive the opaque cloud-backup slot ID (hex-encoded, 64 chars) from the master backup key
/// returned by `backup_derive_key`. See `derive_backup_id_inner`'s doc for why this is a distinct
/// HKDF-derived value, not the key itself or a substring of it.
#[wasm_bindgen]
pub fn backup_derive_id(key: &[u8]) -> Result<String, JsError> {
    derive_backup_id_inner(key)
        .map(|id| id.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .map_err(|e| JsError::new(&e))
}

/// Derive generation `n`'s independent AEAD data key from the master backup key. See the module
/// doc's "GENERATION KEYS" section: `n` is a PUBLIC counter (the Worker tracks/serves it, no
/// secrecy needed) and different generations' keys are cryptographically independent of each other.
#[wasm_bindgen]
pub fn backup_derive_generation_key(master_key: &[u8], generation: u32) -> Result<Vec<u8>, JsError> {
    derive_generation_key_inner(master_key, generation).map(|k| k.to_vec()).map_err(|e| JsError::new(&e))
}

/// Encrypt local state under generation `n`, binding `(backup_id, n)` as AEAD associated data —
/// see `export_generation_inner`'s doc.
#[wasm_bindgen]
pub fn backup_export_generation(state: &[u8], gen_key: &[u8], backup_id: &[u8], generation: u32) -> Result<String, JsError> {
    export_generation_inner(state, gen_key, backup_id, generation).map_err(|e| JsError::new(&e))
}

/// Decrypt a blob `backup_export_generation` produced. Fails on wrong key, wrong `generation`/
/// `backup_id` (AAD mismatch), tampering, or truncation — see `import_generation_inner`'s doc.
#[wasm_bindgen]
pub fn backup_import_generation(blob_b64: &str, gen_key: &[u8], backup_id: &[u8], generation: u32) -> Result<Vec<u8>, JsError> {
    import_generation_inner(blob_b64, gen_key, backup_id, generation).map_err(|e| JsError::new(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY_A: [u8; 32] = [7u8; 32];
    const ENTROPY_B: [u8; 32] = [9u8; 32];

    #[test]
    fn mnemonic_is_24_words_and_deterministic_from_entropy() {
        let a = generate_mnemonic_inner(&ENTROPY_A).unwrap();
        let b = generate_mnemonic_inner(&ENTROPY_A).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.split_whitespace().count(), 24);

        let c = generate_mnemonic_inner(&ENTROPY_B).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn generate_mnemonic_rejects_wrong_length_entropy() {
        assert!(generate_mnemonic_inner(&[0u8; 16]).is_err());
        assert!(generate_mnemonic_inner(&[0u8; 33]).is_err());
    }

    #[test]
    fn derive_backup_key_is_deterministic_and_phrase_sensitive() {
        let phrase_a = generate_mnemonic_inner(&ENTROPY_A).unwrap();
        let phrase_b = generate_mnemonic_inner(&ENTROPY_B).unwrap();

        let key_a1 = derive_backup_key_inner(&phrase_a).unwrap();
        let key_a2 = derive_backup_key_inner(&phrase_a).unwrap();
        let key_b = derive_backup_key_inner(&phrase_b).unwrap();

        assert_eq!(key_a1, key_a2);
        assert_ne!(key_a1, key_b);
        assert_eq!(key_a1.len(), 32);
    }

    #[test]
    fn derive_backup_key_rejects_invalid_phrase() {
        assert!(derive_backup_key_inner("not a valid bip39 phrase at all").is_err());

        // A real 24-word phrase with the last word's checksum-relevant bits flipped by swapping
        // it for a different, still-in-wordlist word — breaks the BIP39 checksum, not just parsing.
        let mut phrase = generate_mnemonic_inner(&ENTROPY_A).unwrap();
        let swap_from = if phrase.ends_with("abandon") { "abandon" } else { "zoo" };
        let swap_to = if swap_from == "abandon" { "zoo" } else { "abandon" };
        if phrase.ends_with(swap_from) {
            let cut = phrase.len() - swap_from.len();
            phrase.truncate(cut);
            phrase.push_str(swap_to);
        } else {
            phrase.push_str(" zoo"); // 25 words: definitely invalid either way
        }
        assert!(derive_backup_key_inner(&phrase).is_err());
    }

    const BACKUP_ID: [u8; 32] = [1u8; 32];

    #[test]
    fn export_then_import_round_trips_binary_state() {
        let master = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen_key = derive_generation_key_inner(&master, 0).unwrap();
        let state = b"\x00\x01\xffnot-utf8-safe-binary-state\x02";
        let blob = export_generation_inner(state, &gen_key, &BACKUP_ID, 0).unwrap();
        assert_eq!(import_generation_inner(&blob, &gen_key, &BACKUP_ID, 0).unwrap(), state);
    }

    #[test]
    fn import_rejects_wrong_key_derived_from_a_different_phrase() {
        let master_a = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let master_b = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_B).unwrap()).unwrap();
        let key_a = derive_generation_key_inner(&master_a, 0).unwrap();
        let key_b = derive_generation_key_inner(&master_b, 0).unwrap();
        let blob = export_generation_inner(b"secret state", &key_a, &BACKUP_ID, 0).unwrap();
        assert!(import_generation_inner(&blob, &key_b, &BACKUP_ID, 0).is_err());
    }

    #[test]
    fn import_rejects_tampered_ciphertext() {
        let master = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen_key = derive_generation_key_inner(&master, 0).unwrap();
        let blob = export_generation_inner(b"integrity-check", &gen_key, &BACKUP_ID, 0).unwrap();
        let mut raw = STANDARD.decode(&blob).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01; // flip a bit in the GCM tag
        assert!(import_generation_inner(&STANDARD.encode(raw), &gen_key, &BACKUP_ID, 0).is_err());
    }

    #[test]
    fn export_nonce_is_fresh_each_call() {
        let master = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen_key = derive_generation_key_inner(&master, 0).unwrap();
        assert_ne!(
            export_generation_inner(b"same state", &gen_key, &BACKUP_ID, 0).unwrap(),
            export_generation_inner(b"same state", &gen_key, &BACKUP_ID, 0).unwrap()
        );
    }

    #[test]
    fn wrong_length_key_is_rejected() {
        assert!(export_generation_inner(b"x", &[0u8; 16], &BACKUP_ID, 0).is_err());
        assert!(import_generation_inner("AAAAAAAAAAAAAAAA", &[0u8; 16], &BACKUP_ID, 0).is_err());
    }

    #[test]
    fn generation_keys_are_independent_not_a_chain() {
        // The whole point of indexed HKDF over a hash chain: knowing gen_key[5] must not help
        // derive gen_key[6] or gen_key[4] — a real memory-scraping compromise of one generation's
        // key (without the phrase itself) must not expose any other generation.
        let master = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen4 = derive_generation_key_inner(&master, 4).unwrap();
        let gen5 = derive_generation_key_inner(&master, 5).unwrap();
        let gen6 = derive_generation_key_inner(&master, 6).unwrap();
        assert_ne!(gen4, gen5);
        assert_ne!(gen5, gen6);
        assert_ne!(gen4, gen6);
        // Not merely "different" — confirm gen6 isn't reachable by hashing gen5 forward (the
        // hash-chain shape this design deliberately avoids). A single SHA-256 of gen5 landing on
        // gen6 would be an absurd coincidence; this is a sanity guard against ever "simplifying"
        // derive_generation_key_inner into a chain by accident.
        use sha2::{Digest, Sha256};
        let hashed_gen5 = Sha256::digest(gen5);
        assert_ne!(hashed_gen5.as_slice(), gen6.as_slice());
    }

    #[test]
    fn recovery_needs_only_the_master_key_and_the_public_generation_number() {
        // Simulates the real recovery contract: nothing but the phrase (-> master key) plus a
        // generation number told to the client by the (untrusted) server is needed to decrypt.
        let master = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen_key_write = derive_generation_key_inner(&master, 7).unwrap();
        let blob = export_generation_inner(b"rotated state", &gen_key_write, &BACKUP_ID, 7).unwrap();

        // "Recovery": re-derive the master key from the phrase again (independent computation),
        // learn generation=7 from "the server", re-derive gen_key[7] fresh, decrypt.
        let master_recovered = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen_key_recovered = derive_generation_key_inner(&master_recovered, 7).unwrap();
        assert_eq!(
            import_generation_inner(&blob, &gen_key_recovered, &BACKUP_ID, 7).unwrap(),
            b"rotated state"
        );
    }

    #[test]
    fn aad_binds_generation_number_even_with_the_correct_key_hypothetically_reused() {
        // Real generations always have distinct keys (proven above), so this test constructs the
        // narrower, specific property AAD adds on top of that: given the SAME gen_key (as if it
        // were, hypothetically, reused across generations by a future bug), decrypting while
        // CLAIMING the wrong generation number must still fail — the AAD mismatch alone catches it,
        // independent of whether the key derivation happened to differ.
        let master = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen_key = derive_generation_key_inner(&master, 3).unwrap();
        let blob = export_generation_inner(b"gen-3 state", &gen_key, &BACKUP_ID, 3).unwrap();
        assert!(import_generation_inner(&blob, &gen_key, &BACKUP_ID, 4).is_err());
    }

    #[test]
    fn aad_binds_backup_id_too() {
        let master = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let gen_key = derive_generation_key_inner(&master, 0).unwrap();
        let blob = export_generation_inner(b"state", &gen_key, &BACKUP_ID, 0).unwrap();
        let other_backup_id = [2u8; 32];
        assert!(import_generation_inner(&blob, &gen_key, &other_backup_id, 0).is_err());
    }

    #[test]
    fn derive_generation_key_rejects_wrong_length_master_key() {
        assert!(derive_generation_key_inner(&[0u8; 16], 0).is_err());
        assert!(derive_generation_key_inner(&[0u8; 33], 0).is_err());
    }

    #[test]
    fn backup_id_is_deterministic_and_key_sensitive() {
        let key_a = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let key_b = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_B).unwrap()).unwrap();

        let id_a1 = derive_backup_id_inner(&key_a).unwrap();
        let id_a2 = derive_backup_id_inner(&key_a).unwrap();
        let id_b = derive_backup_id_inner(&key_b).unwrap();

        assert_eq!(id_a1, id_a2);
        assert_ne!(id_a1, id_b);
        assert_eq!(id_a1.len(), 32);
    }

    #[test]
    fn backup_id_is_domain_separated_from_the_encryption_key_itself() {
        // The whole point of HKDF-deriving the ID is that it must not equal (or trivially reveal)
        // the master key the server must never see. Guard against a copy-paste regression that
        // accidentally returns `key` unchanged.
        let key = derive_backup_key_inner(&generate_mnemonic_inner(&ENTROPY_A).unwrap()).unwrap();
        let id = derive_backup_id_inner(&key).unwrap();
        assert_ne!(id.to_vec(), key.to_vec());
    }

    #[test]
    fn backup_id_rejects_wrong_length_key() {
        assert!(derive_backup_id_inner(&[0u8; 16]).is_err());
        assert!(derive_backup_id_inner(&[0u8; 33]).is_err());
    }
}
