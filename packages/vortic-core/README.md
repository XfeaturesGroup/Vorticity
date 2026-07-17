# vortic-core

Single Rust source tree, THREE WASM outputs (a third, `issuer-full`, added 2026-07 for the RSABSSA
Plane Bridge — see docs/03 §2, docs/06's "Plane Bridge" entry):

- `pnpm run build:client` → `pkg/client` (`client-full`): proving, encryption, decryption,
  ratchet/MLS state, plus the RSABSSA client ops (`blind_sig::blindsig_blind`/`blindsig_finalize`).
  Consumed by `apps/web` and `apps/mobile`.
- `pnpm run build:msg` → `pkg/msg` (`edge-verify-only`): only verify-shaped ops compile in —
  `zk.rs`'s Groth16 verify, `oprf::evaluate`, `blind_sig::blindsig_verify`. Consumed by
  `workers/messaging`. This is the crate-level enforcement of docs/03's crypto invariant #4 — *the
  edge never holds a decryption key* — as a build-time guarantee, not just a code-review rule.
- `pnpm run build:issuer` → `pkg/issuer` (`edge-verify-only` + `issuer-full`): everything `pkg/msg`
  has, PLUS `blind_sig::blindsig_sign` (needs the RSABSSA issuer's secret key). Consumed by
  `workers/enrollment` only. `issuer-full` is a deliberately stricter isolation than the
  `oprf::evaluate` precedent above: `blindsig_sign` isn't just unreachable from `pkg/msg`, it was
  never compiled into that binary — verified via each profile's generated `.d.ts` export list.

`oprf::evaluate` belongs to neither `client-full` nor `edge-verify-only` specifically: it's
Enrollment-Plane-only code (needs the OPRF secret key as an argument) that happens to be safe to
also compile into `pkg/msg` since Messaging never calls it with a real key — same reasoning as
`zk_verify_groth16_bytes`. (No longer wired into the live enrollment<->messaging bridge — see
`blind_sig.rs` below — but still real, tested code, not deleted.)

## Build prerequisite

Requires `wasm-pack` (`cargo install wasm-pack`) and the `wasm32-unknown-unknown` target
(`rustup target add wasm32-unknown-unknown`). `apps/web` imports the generated `pkg/client/` bundle
directly, so `pnpm run build:client` (or the full `pnpm run build`) must run at least once before the
web app can start; the `pkg/` directory is a build artifact and is git-ignored.

## Status

`src/symmetric.rs` is **real**: ChaCha20-Poly1305 authenticated encryption exposed to JS as
`encrypt_message`/`decrypt_message`, keyed by a real X25519 Diffie-Hellman handshake (`kem.rs`'s
`x25519_generate_keypair`/`x25519_derive_shared` — no hardcoded key). `src/blind_sig.rs` is **real**:
RSA Blind Signatures (RFC 9474 RSABSSA, RSA-3072), the enrollment<->messaging Plane Bridge (see
docs/03 §2) — passes the RFC's own official Appendix test vector. `zk.rs`/`oprf.rs`/`kem.rs` are also
real byte-in/byte-out WASM exports (`oprf.rs`'s VOPRF primitives remain implemented/tested but are no
longer wired into the live redemption bridge, superseded by `blind_sig.rs`). `cargo test --features
client-full,issuer-full` — 21/21. Remaining stubs: PQXDH session framing, Triple Ratchet, MLS, ring
sigs, backup — per docs/06-roadmap-and-risks.md.
