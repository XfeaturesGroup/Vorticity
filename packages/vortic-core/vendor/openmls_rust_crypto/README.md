# `openmls_rust_crypto` — vendored, minimally patched (X-Wing wiring)

This is a **local fork of `openmls_rust_crypto` v0.5.1** (MIT license, upstream:
<https://github.com/openmls/openmls/tree/main/openmls_rust_crypto>), vendored ONLY to fix one
specific gap: v0.5.1's `provider.rs` has a literal `unimplemented!("XWingKemDraft6 is not supported
by the RustCrypto provider.")` in `kem_mode()` — even though the underlying `hpke-rs-rust-crypto`
crate (already a real dependency of this very crate) fully implements the X-Wing KEM primitive
(`hpke-rs-rust-crypto`'s `pq_kem.rs`, `KemAlgorithm::XWingDraft06`). The gap is a missing match arm
in the GLUE between two layers of the same provider stack, not a missing cryptographic primitive —
confirmed by reading both crates' source before writing this patch, same discipline `group.rs`'s
own module doc already documents for why the PQ ciphersuite was originally deferred.

## The patch (`src/provider.rs`), exactly two changes from upstream v0.5.1

1. `kem_mode()`: `HpkeKemType::XWingKemDraft6 => hpke_types::KemAlgorithm::XWingDraft06` instead of
   `unimplemented!()`.
2. `supports()` / `supported_ciphersuites()`: added
   `Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` to both.

Nothing else changed. Every other function in `provider.rs` (`hpke_seal`/`hpke_open`/
`hpke_setup_sender_and_export`/`hpke_setup_receiver_and_export`/`derive_hpke_keypair`) was already
written generically against `Hpke<HpkeRustCrypto>` parameterized by `kem_mode()`'s output — none of
that logic needed to change for X-Wing to work; it only needed `kem_mode()` to stop panicking.

## Why vendor instead of a Cargo `[patch]` pointing at a git fork

No public git fork with this fix exists yet to point at. Vendoring the full (tiny) crate source
locally with the patch applied, then using Cargo's `[patch.crates-io]` to substitute it in-tree, is
the standard way to unblock on a small upstream gap while waiting for a real fix, without forking
the whole `openmls` monorepo.

## When to remove this vendor directory

The moment `openmls_rust_crypto` ships a released version with `XWingKemDraft6` wired (check its
CHANGELOG.md / the `unimplemented!()` in `provider.rs`), delete this directory, remove the
`[patch.crates-io]` entry in `packages/vortic-core/Cargo.toml`, and bump the real dependency version.
This is a maintenance liability by nature (a locally-frozen fork of a security-sensitive dependency
that won't receive upstream fixes automatically) — flagged here so it isn't forgotten, not swept
under a comment nobody re-reads.
