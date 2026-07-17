//! Sealed Sender++ envelope: sender field encrypted to recipient, padded/delayed/decoupled
//! receipts. See docs/03-crypto-core.md §6. Client-side only.

#[cfg(feature = "client-full")]
pub fn seal(/* sender_cert: &[u8], plaintext: &[u8], recipient_key: &PublicKey */) -> Vec<u8> {
    todo!("Phase 3: encrypt sender field to recipient, pad envelope to power-of-two bucket")
}

#[cfg(feature = "client-full")]
pub fn unseal(/* envelope: &[u8], recipient_key: &PrivateKey */) -> (Vec<u8> /* sender_cert */, Vec<u8> /* plaintext */) {
    todo!("Phase 3")
}
