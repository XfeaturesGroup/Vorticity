//! Hashcash-family Proof-of-Work stamps (anti-scrape/anti-spam on the alias plane).
//! See docs/03-crypto-core.md §8.3. `mint` is client-only (expensive by design); `verify` must
//! be cheap enough to run on `edge-verify-only` per message/request (docs/06 — PoW is the cost
//! inverse of ZK: expensive to mint, ~free to check).
//!
//! Implemented for real (2026-07, "alias contact establishment" pass) — closes the Phase-0
//! `todo!()` stubs. **Why a real synchronous Rust/WASM miner, not a TS loop calling
//! `crypto.subtle.digest` per iteration:** the required difficulty (18-26 leading zero bits per
//! docs/03 §8.3) needs on the order of 2^18 to 2^26 average hash attempts. `SubtleCrypto.digest`
//! is async — each call round-trips through a Promise, and that per-call dispatch overhead (not
//! the hash itself) dominates at millions of iterations, making a real register-class mint
//! (24-26 bits) take minutes rather than the "~a few seconds" docs/03 targets. A synchronous
//! tight loop compiled to WASM has no such per-iteration async overhead — this is exactly the
//! class of primitive `packages/vortic-core` already exists for.
//!
//! `AliasDO.ts` (`workers/messaging`) already has its own independent, already-tested JS
//! `verifyPowStamp` (from the original "AliasDO" pass) — this module's `verify` is NOT wired into
//! that Worker; verification is cheap enough server-side that there's no performance reason to
//! swap a working, live-tested implementation for a WASM call, and doing so would be unrelated
//! risk for this pass. `verify` here exists to close the crate's own Phase-0 TODO and to give the
//! Rust test suite (below) a same-language round-trip check against `mint` — a real correctness
//! cross-check, just not the one actually gating requests in production. It also deliberately
//! does NOT check epoch freshness/replay — that's server-side policy (`AliasDO.ts`'s
//! `pow_stamps` table), not a property of the stamp itself.

use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// Leading zero bits across a byte string, MSB-first — the Hashcash difficulty measure. Mirrors
/// `workers/messaging/src/durable-objects/AliasDO.ts`'s `countLeadingZeroBits` byte-for-byte (see
/// this module's tests for a cross-check against that same algorithm's known outputs).
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0u32;
    for &byte in bytes {
        if byte == 0 {
            bits += 8;
            continue;
        }
        bits += byte.leading_zeros();
        break;
    }
    bits
}

/// `ver:alg:bits:epoch:resource:salt:counter` — matches `AliasDO.ts`'s `verifyPowStamp` grammar
/// exactly (7 colon-separated fields, `ver="1"`, `alg="sha256"`). `bits` is a client-declared
/// label only — like the server, nothing here trusts it; the actual difficulty is whatever
/// `leading_zero_bits` measures on the real digest.
#[cfg(feature = "client-full")]
fn stamp_string(resource: &str, min_bits: u32, epoch: u32, salt: &str, counter: u32) -> String {
    format!("1:sha256:{min_bits}:{epoch}:{resource}:{salt}:{counter}")
}

/// Mints a stamp for `resource` meeting `min_bits`, at the given `epoch` (caller-supplied —
/// `AliasDO.ts` defines `epoch = floor(unix_ms / 3_600_000)`; this module has no clock of its
/// own, matching this crate's existing convention of taking entropy/time as parameters rather
/// than reaching for a platform clock). `salt` should be caller-supplied random bytes (hex-ish is
/// fine, it's opaque to this function) so two mints for the same resource/epoch don't collide on
/// `counter` alone. Loops until found — bounded in practice by `min_bits` (2^26 worst case at the
/// top of docs/03's stated range), not literally unbounded.
#[cfg(feature = "client-full")]
pub fn mint(resource: &str, min_bits: u32, epoch: u32, salt: &str) -> String {
    let mut counter: u32 = 0;
    loop {
        let stamp = stamp_string(resource, min_bits, epoch, salt, counter);
        let digest = Sha256::digest(stamp.as_bytes());
        if leading_zero_bits(&digest) >= min_bits {
            return stamp;
        }
        counter += 1;
    }
}

/// Checks that `stamp` is well-formed, targets `expected_resource`, and its SHA-256 digest has at
/// least `min_bits` leading zero bits. Does NOT check epoch freshness or replay (see module doc)
/// — a caller enforcing full server-side policy needs those checks on top of this.
pub fn verify(stamp: &str, expected_resource: &str, min_bits: u32) -> bool {
    let parts: Vec<&str> = stamp.split(':').collect();
    if parts.len() != 7 {
        return false;
    }
    if parts[0] != "1" || parts[1] != "sha256" {
        return false;
    }
    if parts[4] != expected_resource {
        return false;
    }
    let digest = Sha256::digest(stamp.as_bytes());
    leading_zero_bits(&digest) >= min_bits
}

#[cfg(feature = "client-full")]
#[wasm_bindgen]
pub fn pow_mint(resource: &str, min_bits: u32, epoch: u32, salt: &str) -> String {
    mint(resource, min_bits, epoch, salt)
}

#[wasm_bindgen]
pub fn pow_verify(stamp: &str, expected_resource: &str, min_bits: u32) -> bool {
    verify(stamp, expected_resource, min_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_known_values() {
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8); // first byte all-zero (+8), second byte is nonzero so it stops the count there (its own leading zeros are 0)
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x0f]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x00]), 24);
    }

    #[cfg(feature = "client-full")]
    #[test]
    fn mint_then_verify_round_trips_at_a_real_difficulty() {
        // 16 bits keeps the test fast (avg 65536 attempts) while still exercising the real loop,
        // not a trivial 0-bit no-op.
        let stamp = mint("lookup-key-abc123", 16, 486_123, "test-salt");
        assert!(verify(&stamp, "lookup-key-abc123", 16));
    }

    #[cfg(feature = "client-full")]
    #[test]
    fn verify_rejects_wrong_resource_and_insufficient_bits() {
        let stamp = mint("resource-a", 16, 1, "salt");
        assert!(!verify(&stamp, "resource-b", 16), "resource mismatch must be rejected");
        assert!(verify(&stamp, "resource-a", 15), "one bit below the mined target must still pass");
        // `mint` guarantees AT LEAST `min_bits`, not exactly — the actual digest can (and often
        // does) clear a higher bar by chance, so asserting against `min_bits + 1` here would be
        // flaky. Instead: measure the stamp's real bit count and confirm one bit ABOVE THAT is
        // correctly rejected — a precise, non-flaky version of the same property.
        let digest = Sha256::digest(stamp.as_bytes());
        let actual_bits = leading_zero_bits(&digest);
        assert!(!verify(&stamp, "resource-a", actual_bits + 1), "one bit above the stamp's real difficulty must be rejected");
    }

    #[test]
    fn verify_rejects_malformed_stamps() {
        assert!(!verify("not:enough:fields", "r", 1));
        assert!(!verify("2:sha256:16:1:r:salt:0", "r", 1), "wrong version");
        assert!(!verify("1:md5:16:1:r:salt:0", "r", 1), "wrong algorithm");
    }
}
