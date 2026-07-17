//! Shared primitives: HKDF-SHA256, constant-time compare. Available on both build profiles —
//! every module above composes from these.

use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-SHA256 (RFC 5869). Used everywhere key material is derived (docs/03: hybrid root key,
/// alias record keys, backup keys). `out_len` may be up to 255*32 bytes per RFC 5869.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256: requested output length exceeds RFC 5869 limit");
    okm
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_is_deterministic_and_length_correct() {
        let a = hkdf_sha256(b"ikm", b"salt", b"info", 32);
        let b = hkdf_sha256(b"ikm", b"salt", b"info", 32);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
