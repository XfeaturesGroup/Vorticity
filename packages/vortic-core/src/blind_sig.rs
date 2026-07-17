//! RSA Blind Signatures (RFC 9474, "RSABSSA") — the Plane Bridge redemption-token mechanism.
//!
//! WHY THIS REPLACES VOPRF FOR THE ENROLLMENT<->MESSAGING BRIDGE (see `oprf.rs`, still present and
//! unit-tested but no longer wired into the redemption flow): a VOPRF evaluation is not, by
//! construction, third-party verifiable — checking it requires the evaluator's own secret key `k`
//! (`oprf::evaluate`'s DLEQ proof lets the *client* who requested the evaluation confirm the Worker
//! used its committed key, but it gives a THIRD party, i.e. the Messaging Plane, no way to verify a
//! redeemed token without also holding `k` or some equivalent shared secret). Any scheme where
//! Messaging "verifies" a VOPRF token therefore smuggles in a shared secret between the planes under
//! a different name — which is exactly the invariant this bridge must not violate (see below).
//! RSA blind signatures solve this by construction: the issuer's signature is a REAL signature over
//! an (unblinded) message, verifiable with nothing but the issuer's PUBLIC key via ordinary
//! RSASSA-PSS verification. Messaging holds only `pk_issuer`; the private key `sk_issuer` never
//! leaves the Enrollment Plane.
//!
//! HARD INVARIANT (do not weaken silently): the Messaging Plane's WASM build must never even
//! *compile* the secret-key-consuming operation (`blindsig_sign`), not merely "not call it". That is
//! why this crate has a THIRD Cargo feature, `issuer-full`, additive and orthogonal to `client-full`/
//! `edge-verify-only` (see Cargo.toml) — only `workers/enrollment`'s WASM build enables it. This is
//! deliberately stricter than the pre-existing `oprf::evaluate` precedent (that function is
//! unconditional in both profiles, accepting a secret key as a plain argument) because RSA blind
//! signing is the actual "hold and use a private key" operation this bridge exists to isolate.
//!
//! Parameters: **RSA-3072**, **SHA-384**, **PSS** (salt length = hash output length), **Randomized**
//! message preparation (RFC 9474 §4's documented "primary"/recommended combination — the crate's own
//! `BlindRsaSha384PSSRandomized` type alias). Uses the pure-Rust `blind-rsa-signatures` crate (RFC
//! 9474-conformant, ships the RFC's own Appendix test vectors) rather than hand-rolling PSS padding
//! or the RSA blinding math — see `zk_test.rs`'s and `oprf.rs`'s doc comments for why this project
//! treats "reimplementing padding/blinding by hand" as the highest-risk place to introduce a subtle
//! bug in exactly this class of primitive.
//!
//! Wire contract (fixed sizes for a 3072-bit modulus, `MODULUS_BYTES = 384`):
//!   - Blinded message / blind signature / final signature: `384` bytes each.
//!   - Message randomizer: `32` bytes (Randomized mode always prepends this).
//!   - `blindsig_blind`'s packed "blinding state" (client-local only, never sent over the wire):
//!     `blind_message(384) || secret(384) || msg_randomizer(32)` = `800` bytes.
//!
//! Protocol roles (mirrors the crate's own doc example):
//!   1. **Client** (`client-full`): `blindsig_blind(pk_pem, msg)` -> blinding state to keep locally.
//!   2. **Issuer** (`issuer-full`, Enrollment Plane only): `blindsig_sign(sk_pem, blinded_msg)`.
//!   3. **Client**: `blindsig_finalize(pk_pem, blinding_state, blind_sig, msg)` -> final `(msg, sig,
//!      msg_randomizer)` triple — THIS is the redemption token presented to Messaging.
//!   4. **Verifier** (unconditional, both `client-full` and `edge-verify-only`; this is what
//!      Messaging actually calls): `blindsig_verify(pk_pem, msg, msg_randomizer, sig)`.

use blind_rsa_signatures::{DefaultRng, MessageRandomizer, PSS, PublicKey, Randomized, Sha384, Signature};
#[cfg(feature = "client-full")]
use blind_rsa_signatures::{BlindMessage, BlindSignature, BlindingResult, Secret};
#[cfg(feature = "issuer-full")]
use blind_rsa_signatures::{KeyPair, SecretKey};
use wasm_bindgen::prelude::*;

type BRsaPk = PublicKey<Sha384, PSS, Randomized>;
#[cfg(feature = "issuer-full")]
type BRsaSk = SecretKey<Sha384, PSS, Randomized>;

/// RSA-3072 (see module doc). Fixes the byte lengths below — every function validates against them.
pub const MODULUS_BITS: usize = 3072;
pub const MODULUS_BYTES: usize = MODULUS_BITS / 8; // 384
const RANDOMIZER_LEN: usize = 32;
#[cfg(feature = "client-full")]
const BLINDING_STATE_LEN: usize = MODULUS_BYTES * 2 + RANDOMIZER_LEN; // 800

fn parse_pk(pk_pem: &str) -> Result<BRsaPk, String> {
    BRsaPk::from_pem(pk_pem).map_err(|e| format!("invalid issuer public key: {e}"))
}

#[cfg(feature = "issuer-full")]
fn parse_sk(sk_pem: &str) -> Result<BRsaSk, String> {
    BRsaSk::from_pem(sk_pem).map_err(|e| format!("invalid issuer secret key: {e}"))
}

// --- Verifier: unconditional (both profiles) — needs only the issuer's PUBLIC key. This is the
// only operation the Messaging Plane ever calls. ---

fn verify_inner(pk_pem: &str, msg: &[u8], msg_randomizer: &[u8], sig: &[u8]) -> Result<bool, String> {
    let pk = parse_pk(pk_pem)?;
    if msg_randomizer.len() != RANDOMIZER_LEN {
        return Err(format!("msg_randomizer must be {RANDOMIZER_LEN} bytes"));
    }
    let randomizer_arr: [u8; RANDOMIZER_LEN] = msg_randomizer.try_into().expect("length checked above");
    let randomizer = MessageRandomizer(randomizer_arr);
    let signature = Signature(sig.to_vec());
    Ok(pk.verify(&signature, Some(randomizer), msg).is_ok())
}

/// Verify a redemption token `(msg, msg_randomizer, sig)` against the issuer's public key. Never
/// throws — malformed input (wrong-length randomizer, unparsable PEM, bad signature) all verify
/// `false`, matching this crate's other untrusted-input verifiers (`zk_verify_groth16_bytes`).
#[wasm_bindgen]
pub fn blindsig_verify(pk_pem: &str, msg: &[u8], msg_randomizer: &[u8], sig: &[u8]) -> bool {
    verify_inner(pk_pem, msg, msg_randomizer, sig).unwrap_or(false)
}

// --- Client: blind + finalize (client-full only) — needs only the issuer's PUBLIC key plus local
// randomness; never sees or needs the secret key. ---

#[cfg(feature = "client-full")]
fn blind_inner(pk_pem: &str, msg: &[u8]) -> Result<Vec<u8>, String> {
    let pk = parse_pk(pk_pem)?;
    let mut rng = DefaultRng;
    let result = pk.blind(&mut rng, msg).map_err(|e| format!("blind failed: {e}"))?;
    let randomizer = result
        .msg_randomizer
        .ok_or_else(|| "internal error: expected Randomized mode to produce a randomizer".to_string())?;

    if result.blind_message.0.len() != MODULUS_BYTES || result.secret.0.len() != MODULUS_BYTES {
        return Err("internal error: blind output did not match the expected modulus size".to_string());
    }
    let mut state = Vec::with_capacity(BLINDING_STATE_LEN);
    state.extend_from_slice(&result.blind_message.0);
    state.extend_from_slice(&result.secret.0);
    state.extend_from_slice(&randomizer.0);
    Ok(state)
}

/// Blind `msg` for the issuer's public key. Returns an opaque 800-byte "blinding state" the client
/// must keep locally (never send it anywhere) and pass back into `blindsig_finalize` once the issuer
/// replies. The first `MODULUS_BYTES` of that state are the actual blinded message to send to the
/// issuer — see `js/crypto.ts` for the unpacking.
#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn blindsig_blind(pk_pem: &str, msg: &[u8]) -> Result<Vec<u8>, JsError> {
    blind_inner(pk_pem, msg).map_err(|e| JsError::new(&e))
}

#[cfg(feature = "client-full")]
fn unpack_blinding_state(state: &[u8]) -> Result<(Vec<u8>, Vec<u8>, [u8; RANDOMIZER_LEN]), String> {
    if state.len() != BLINDING_STATE_LEN {
        return Err(format!("blinding state must be {BLINDING_STATE_LEN} bytes"));
    }
    let blind_message = state[..MODULUS_BYTES].to_vec();
    let secret = state[MODULUS_BYTES..MODULUS_BYTES * 2].to_vec();
    let randomizer: [u8; RANDOMIZER_LEN] = state[MODULUS_BYTES * 2..].try_into().expect("length checked above");
    Ok((blind_message, secret, randomizer))
}

#[cfg(feature = "client-full")]
fn finalize_inner(pk_pem: &str, blinding_state: &[u8], blind_sig: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let pk = parse_pk(pk_pem)?;
    let (blind_message, secret, randomizer) = unpack_blinding_state(blinding_state)?;
    let result = BlindingResult {
        blind_message: BlindMessage(blind_message),
        secret: Secret(secret),
        msg_randomizer: Some(MessageRandomizer(randomizer)),
    };
    let blind_sig = BlindSignature(blind_sig.to_vec());
    // `finalize` also re-verifies the unblinded signature internally before returning it, so a
    // malformed/incorrect blind signature from a dishonest issuer surfaces here as an error, not a
    // signature the client would only discover was invalid later at the Messaging Plane.
    let sig = pk.finalize(&blind_sig, &result, msg).map_err(|e| format!("finalize failed: {e}"))?;
    Ok(sig.0)
}

/// Unblind the issuer's `blind_sig` into the final, real RSA-PSS signature over `msg` — the
/// redemption token's third field (alongside `msg` and the randomizer already known from `blind`).
/// Also verifies the result before returning it, so a dishonest issuer's bad signature is caught
/// here rather than silently accepted and rejected only later by Messaging.
#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn blindsig_finalize(pk_pem: &str, blinding_state: &[u8], blind_sig: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsError> {
    finalize_inner(pk_pem, blinding_state, blind_sig, msg).map_err(|e| JsError::new(&e))
}

// --- Issuer: blind-sign (issuer-full only — Enrollment Plane exclusively). Needs the SECRET key.
// This module is the only place in the crate that imports `SecretKey`; excluding `issuer-full`
// excludes this whole code path from compilation, not just from being called. ---

#[cfg(feature = "issuer-full")]
fn sign_inner(sk_pem: &str, blinded_msg: &[u8]) -> Result<Vec<u8>, String> {
    let sk = parse_sk(sk_pem)?;
    let blind_sig = sk.blind_sign(blinded_msg).map_err(|e| format!("blind_sign failed: {e}"))?;
    Ok(blind_sig.0)
}

/// Sign a client's blinded message under the issuer's secret key. The issuer never sees the
/// unblinded `msg` — that is the entire point of the construction (see module doc).
#[cfg(feature = "issuer-full")]
#[wasm_bindgen]
pub fn blindsig_sign(sk_pem: &str, blinded_msg: &[u8]) -> Result<Vec<u8>, JsError> {
    sign_inner(sk_pem, blinded_msg).map_err(|e| JsError::new(&e))
}

/// Generate a fresh issuer keypair (PEM-encoded sk, pk). NOT exposed via `wasm-bindgen` — RSA-3072
/// key generation is a one-time, offline operation (see `examples/rsabssa_keygen.rs`), never
/// something a live Worker request should do. `issuer-full`-gated for the same reason `blindsig_sign`
/// is: this touches `SecretKey` construction.
#[cfg(feature = "issuer-full")]
pub fn generate_keypair_pem() -> Result<(String, String), String> {
    let kp = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, MODULUS_BITS)
        .map_err(|e| format!("keygen failed: {e}"))?;
    let sk_pem = kp.sk.to_pem().map_err(|e| format!("sk PEM encode failed: {e}"))?;
    let pk_pem = kp.pk.to_pem().map_err(|e| format!("pk PEM encode failed: {e}"))?;
    Ok((sk_pem, pk_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- RFC 9474 Appendix conformance: verify against the RFC's OWN official test vector -------
    //
    // These constants are the first vector ("RSABSSA-SHA384-PSS-Randomized") from the RFC 9474
    // Appendix, taken from the `blind-rsa-signatures` crate's own shipped
    // `tests/test_vectors_rfc9474.json` (that crate is the reference implementation this module
    // wraps; its test vectors ARE the RFC's). This is a genuine RFC conformance check for
    // `blindsig_verify` specifically — the one operation the Messaging Plane actually calls — not a
    // hand-copied/re-derived vector. The vector's own key size differs from this module's
    // MODULUS_BITS=3072 production choice; that's fine, `verify()` accepts any 2048-4096 bit modulus.
    #[cfg(feature = "issuer-full")] // needs SecretKey::new to reconstruct the vector's raw (n,e,d,p,q)
    #[test]
    fn rfc9474_official_vector_verifies() {
        use blind_rsa_signatures::reexports::rsa::{BoxedUint, RsaPrivateKey};

        fn hex_uint(s: &str) -> BoxedUint {
            let clean = s.strip_prefix("0x").unwrap_or(s);
            BoxedUint::from_str_radix_vartime(clean, 16).expect("valid hex in test vector")
        }
        fn hex_bytes(s: &str) -> Vec<u8> {
            hex_uint(s).to_be_bytes().to_vec()
        }

        let p = hex_uint("0xe1f4d7a34802e27c7392a3cea32a262a34dc3691bd87f3f310dc75673488930559c120fd0410194fb8a0da55bd0b81227e843fdca6692ae80e5a5d414116d4803fca7d8c30eaaae57e44a1816ebb5c5b0606c536246c7f11985d731684150b63c9a3ad9e41b04c0b5b27cb188a692c84696b742a80d3cd00ab891f2457443dadfeba6d6daf108602be26d7071803c67105a5426838e6889d77e8474b29244cefaf418e381b312048b457d73419213063c60ee7b0d81820165864fef93523c9635c22210956e53a8d96322493ffc58d845368e2416e078e5bcb5d2fd68ae6acfa54f9627c42e84a9d3f2774017e32ebca06308a12ecc290c7cd1156dcccfb2311");
        let q = hex_uint("0xc601a9caea66dc3835827b539db9df6f6f5ae77244692780cd334a006ab353c806426b60718c05245650821d39445d3ab591ed10a7339f15d83fe13f6a3dfb20b9452c6a9b42eaa62a68c970df3cadb2139f804ad8223d56108dfde30ba7d367e9b0a7a80c4fdba2fd9dde6661fc73fc2947569d2029f2870fc02d8325acf28c9afa19ecf962daa7916e21afad09eb62fe9f1cf91b77dc879b7974b490d3ebd2e95426057f35d0a3c9f45f79ac727ab81a519a8b9285932d9b2e5ccd347e59f3f32ad9ca359115e7da008ab7406707bd0e8e185a5ed8758b5ba266e8828f8d863ae133846304a2936ad7bc7c9803879d2fc4a28e69291d73dbd799f8bc238385");
        let n = hex_uint("0xaec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5");
        let e = hex_uint("0x010001");
        let d = hex_uint("0x0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051");

        let inner = RsaPrivateKey::from_components(n, e, d, vec![p, q]).expect("valid RFC vector key components");
        let sk = BRsaSk::new(inner);
        let pk = sk.public_key().expect("derive public key");
        let pk_pem = pk.to_pem().expect("encode pk to PEM");

        let msg = hex_bytes("8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d");
        let msg_randomizer = hex_bytes("8417e699b219d583fb6216ae0c53ca0e9723442d02f1d1a34295527e7d929e8b");
        let sig = hex_bytes("191e941c57510e22d29afad257de5ca436d2316221fe870c7cb75205a6c071c2735aed0bc24c37f3d5bd960ab97a829a508f966bbaed7a82645e65eadaf24ab5e6d9421392c5b15b7f9b640d34fec512846a3100b80f75ef51064602118c1a77d28d938f6efc22041d60159a518d3de7c4d840c9c68109672d743d299d8d2577ef60c19ab463c716b3fa75fa56f5735349d414a44df12bf0dd44aa3e10822a651ed4cb0eb6f47c9bd0ef14a034a7ac2451e30434d513eb22e68b7587a8de9b4e63a059d05c8b22c7c51e2cfee2d8bef511412e93c859a13726d87c57d1bc4c2e68ab121562f839c3a3d233e87ed63c69b7e57525367753fbebcc2a9805a2802659f5888b2c69115bf865559f10d906c09d048a0d71bfee4b33857393ec2b69e451433496d02c9a7910abb954317720bbde9e69108eafc3e90bad3d5ca4066d7b1e49013fa04e948104a1dd82b12509ecb146e948c54bd8bfb5e6d18127cd1f7a93c3cf9f2d869d5a78878c03fe808a0d799e910be6f26d18db61c485b303631d3568368fc41986d08a95ea6ac0592240c19d7b22416b9c82ae6241e211dd5610d0baaa9823158f9c32b66318f5529491b7eeadcaa71898a63bac9d95f4aa548d5e97568d744fc429104e32edd9c87519892a198a30d333d427739ffb9607b092e910ae37771abf2adb9f63bc058bf58062ad456cb934679795bbdfcdfad5e0f2");

        assert!(
            verify_inner(&pk_pem, &msg, &msg_randomizer, &sig).unwrap(),
            "blindsig_verify rejected the official RFC 9474 test vector"
        );

        // Negative control: a bit-flipped signature must be rejected by the exact same verify path.
        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0x01;
        assert!(!verify_inner(&pk_pem, &msg, &msg_randomizer, &bad_sig).unwrap());
    }

    // --- Full protocol round trip through THIS module's own wrapper, fresh key (not the RFC vector,
    // since blind()/blind_sign() use DefaultRng — real randomness — and can't reproduce the vector's
    // fixed blinded_msg/blind_sig bytes). Proves blind -> sign -> finalize -> verify is internally
    // consistent end to end, i.e. the actual live protocol path this bridge uses. ---
    #[cfg(all(feature = "client-full", feature = "issuer-full"))]
    #[test]
    fn full_round_trip_with_fresh_key() {
        let (sk_pem, pk_pem) = generate_keypair_pem().expect("keygen");
        let msg = b"redemption-token-identity-seed";

        let blinding_state = blind_inner(&pk_pem, msg).expect("blind");
        let blinded_msg = &blinding_state[..MODULUS_BYTES];
        let blind_sig = sign_inner(&sk_pem, blinded_msg).expect("blind_sign");
        let sig = finalize_inner(&pk_pem, &blinding_state, &blind_sig, msg).expect("finalize");

        let randomizer = &blinding_state[MODULUS_BYTES * 2..];
        assert!(verify_inner(&pk_pem, msg, randomizer, &sig).unwrap(), "round-trip signature failed to verify");
    }

    #[cfg(all(feature = "client-full", feature = "issuer-full"))]
    #[test]
    fn tampered_message_is_rejected() {
        let (sk_pem, pk_pem) = generate_keypair_pem().expect("keygen");
        let msg = b"original-message";

        let blinding_state = blind_inner(&pk_pem, msg).expect("blind");
        let blind_sig = sign_inner(&sk_pem, &blinding_state[..MODULUS_BYTES]).expect("blind_sign");
        let sig = finalize_inner(&pk_pem, &blinding_state, &blind_sig, msg).expect("finalize");
        let randomizer = &blinding_state[MODULUS_BYTES * 2..];

        // The signature is bound to "original-message" — verifying against different bytes must fail.
        assert!(!verify_inner(&pk_pem, b"different-message", randomizer, &sig).unwrap());
    }

    #[cfg(all(feature = "client-full", feature = "issuer-full"))]
    #[test]
    fn wrong_key_is_rejected() {
        let (_sk1, pk1) = generate_keypair_pem().expect("keygen 1");
        let (sk2, _pk2) = generate_keypair_pem().expect("keygen 2");
        let msg = b"identity-seed";

        // Blind/finalize under key 1's public key, but have key 2 (a DIFFERENT issuer) sign it.
        let blinding_state = blind_inner(&pk1, msg).expect("blind");
        let blind_sig = sign_inner(&sk2, &blinding_state[..MODULUS_BYTES]);
        // A blind signature produced under the wrong key either fails outright or, if it happens to
        // decrypt without a hard error (different modulus size could still panic-guard elsewhere),
        // must not finalize+verify successfully. Assert the failure surfaces at one of these stages.
        if let Ok(blind_sig) = blind_sig {
            let finalize_result = finalize_inner(&pk1, &blinding_state, &blind_sig, msg);
            assert!(finalize_result.is_err(), "finalize should reject a signature from the wrong issuer key");
        }
    }
}
