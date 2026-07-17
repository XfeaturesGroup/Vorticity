//! Groth16 verifier for Semaphore v4 (BN254 / alt_bn128). See docs/03-crypto-core.md §3 and
//! docs/06 R1.
//!
//! This module is compiled into BOTH build profiles (`client-full` and `edge-verify-only`) — it
//! is pure *verification*: it deserializes a proof + verifying key + public inputs, runs the
//! Groth16 pairing check, and returns a bool. It holds no secret, decrypts nothing, and cannot
//! prove — so it is safe on the edge and satisfies docs/03 crypto invariant #4. The `prove` side
//! (witness generation + proof creation) stays client-only and is out of scope for this pass
//! (Semaphore proofs are generated in-browser by snarkjs/rapidsnark; this crate never proves).
//!
//! WHY THIS EXISTS: snarkjs's pure-WASM Groth16 verify costs ~0.75–0.9 s CPU (docs/06 R1). A
//! Groth16 verify is only 3 pairings; this hand-linked arkworks (BN254) verifier does exactly
//! that and nothing else, targeting the sub-100 ms budget so it can run once per session inside a
//! Worker to mint a capability. Benchmark on a real Worker isolate is the remaining Phase 2 step.
//!
//! ── BYTE-LAYOUT CONTRACT (the WASM boundary) ──────────────────────────────────────────────────
//! All field coordinates are 32-byte BIG-ENDIAN, reduced mod the relevant field. This is the
//! representation a browser trivially produces from snarkjs decimal strings via
//! `BigInt(s)` → 32-byte BE. We deliberately do NOT use arkworks' `CanonicalSerialize` wire format
//! (it carries compression/infinity flags and little-endian limbs that JS can't cheaply emit).
//!
//!   Fq  (G1 base field)  = 32 BE bytes
//!   Fq2 (G2 base field)  = c0(32 BE) || c1(32 BE), where the element is c0 + c1·u
//!   G1  point            = x:Fq(32) || y:Fq(32)                       = 64 bytes
//!   G2  point            = x:Fq2(64) || y:Fq2(64)                     = 128 bytes
//!   Proof                = A:G1(64) || B:G2(128) || C:G1(64)          = 256 bytes
//!   VerifyingKey         = alpha_g1:G1(64) || beta_g2:G2(128)
//!                          || gamma_g2:G2(128) || delta_g2:G2(128)
//!                          || IC[(nPublic+1)]:G1 each 64             = 448 + 64·(nPublic+1)
//!   PublicInputs         = nPublic × Fr(32 BE), in the circuit's signal order
//!                          (Semaphore v4: merkleRoot, nullifierHash, signalHash, externalNullifier)
//!
//! ── snarkjs → bytes mapping (do this in the Worker / client glue) ─────────────────────────────
//! proof.json  pi_a = [a_x, a_y, "1"]                       → A  = be32(a_x) || be32(a_y)
//! proof.json  pi_b = [[b_x_c0,b_x_c1],[b_y_c0,b_y_c1],..]  → B  = be32(b_x_c0)||be32(b_x_c1)
//!                                                                 ||be32(b_y_c0)||be32(b_y_c1)
//! proof.json  pi_c = [c_x, c_y, "1"]                       → C  = be32(c_x) || be32(c_y)
//! verification_key.json  vk_alpha_1 / vk_beta_2 / vk_gamma_2 / vk_delta_2 / IC → same field order.
//!
//! ⚠ G2 COORDINATE ORDER — the one thing to validate against a real Semaphore vector: snarkjs's
//! raw proof.json stores Fq2 as [c0, c1] matching the math here (Fq2::new(c0, c1)). The BYTE SWAP
//! to [c1, c0] happens ONLY inside snarkjs's `exportSolidityCallData` for the EVM precompile — do
//! NOT apply that swap when producing bytes for THIS verifier. Since tests are deferred (this is a
//! spike), the first integration task in Phase 2 is to confirm accept/reject against one real
//! Semaphore v4 proof + its verification key.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use wasm_bindgen::prelude::*;

const FQ: usize = 32; // one big-endian field coordinate
const G1_LEN: usize = 2 * FQ; // 64
const G2_LEN: usize = 4 * FQ; // 128
const PROOF_LEN: usize = G1_LEN + G2_LEN + G1_LEN; // 256
const VK_FIXED_LEN: usize = G1_LEN + 3 * G2_LEN; // alpha_g1 + beta/gamma/delta g2 = 448

// ── coordinate → field ────────────────────────────────────────────────────────────────────────

#[inline]
fn fq(b: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(b)
}

#[inline]
fn fr(b: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

/// Build a G1 point from 64 bytes and validate it. Returns `None` (→ verification fails) for any
/// off-curve or wrong-subgroup point rather than panicking — the input is attacker-controlled.
fn g1(b: &[u8]) -> Option<G1Affine> {
    let p = G1Affine::new_unchecked(fq(&b[0..FQ]), fq(&b[FQ..2 * FQ]));
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

/// Build a G2 point from 128 bytes (x = c0||c1, y = c0||c1) and validate it.
fn g2(b: &[u8]) -> Option<G2Affine> {
    let x = Fq2::new(fq(&b[0..FQ]), fq(&b[FQ..2 * FQ]));
    let y = Fq2::new(fq(&b[2 * FQ..3 * FQ]), fq(&b[3 * FQ..4 * FQ]));
    let p = G2Affine::new_unchecked(x, y);
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

// ── structure parsing ─────────────────────────────────────────────────────────────────────────

fn parse_proof(b: &[u8]) -> Option<Proof<Bn254>> {
    if b.len() != PROOF_LEN {
        return None;
    }
    Some(Proof {
        a: g1(&b[0..G1_LEN])?,
        b: g2(&b[G1_LEN..G1_LEN + G2_LEN])?,
        c: g1(&b[G1_LEN + G2_LEN..PROOF_LEN])?,
    })
}

fn parse_vk(b: &[u8], n_public: usize) -> Option<VerifyingKey<Bn254>> {
    let ic_count = n_public + 1;
    if b.len() != VK_FIXED_LEN + ic_count * G1_LEN {
        return None;
    }
    let mut o = 0;
    let take_g1 = |o: &mut usize| -> Option<G1Affine> {
        let p = g1(&b[*o..*o + G1_LEN])?;
        *o += G1_LEN;
        Some(p)
    };
    let take_g2 = |o: &mut usize| -> Option<G2Affine> {
        let p = g2(&b[*o..*o + G2_LEN])?;
        *o += G2_LEN;
        Some(p)
    };

    let alpha_g1 = take_g1(&mut o)?;
    let beta_g2 = take_g2(&mut o)?;
    let gamma_g2 = take_g2(&mut o)?;
    let delta_g2 = take_g2(&mut o)?;

    let mut gamma_abc_g1 = Vec::with_capacity(ic_count);
    for _ in 0..ic_count {
        gamma_abc_g1.push(take_g1(&mut o)?);
    }

    Some(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

// ── core verify (Rust-native, both profiles) ──────────────────────────────────────────────────

/// Verify a Groth16/BN254 proof. `public_inputs` is a flat big-endian buffer of `nPublic × 32`
/// bytes; `nPublic` is inferred from its length and must equal `IC.len() - 1` in `vk`.
/// Returns `false` on any malformed input, invalid point, length mismatch, or failed pairing —
/// never panics.
pub fn verify_groth16_bn254(vk_bytes: &[u8], proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> bool {
    if public_inputs_bytes.len() % FQ != 0 {
        return false;
    }
    let n_public = public_inputs_bytes.len() / FQ;

    let vk = match parse_vk(vk_bytes, n_public) {
        Some(v) => v,
        None => return false,
    };
    let proof = match parse_proof(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    let inputs: Vec<Fr> = public_inputs_bytes.chunks_exact(FQ).map(fr).collect();

    let pvk = prepare_verifying_key(&vk);
    Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs).unwrap_or(false)
}

// ── hex helper (dependency-free) ──────────────────────────────────────────────────────────────

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in bytes.chunks_exact(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Some(out)
}

// ── wasm-bindgen boundary (called by workers/messaging from TS) ───────────────────────────────

/// Verify from raw byte buffers (JS passes `Uint8Array`s). See the byte-layout contract above.
#[wasm_bindgen]
pub fn zk_verify_groth16_bytes(vk: &[u8], proof: &[u8], public_inputs: &[u8]) -> bool {
    verify_groth16_bn254(vk, proof, public_inputs)
}

/// Verify from hex strings (each is the concatenated big-endian blob for vk / proof / inputs),
/// convenient to lift straight out of a JSON request body. `0x` prefix optional. Any malformed
/// hex → `false`.
#[wasm_bindgen]
pub fn zk_verify_groth16_hex(vk_hex: &str, proof_hex: &str, public_inputs_hex: &str) -> bool {
    let (vk, proof, inputs) = match (
        hex_to_bytes(vk_hex),
        hex_to_bytes(proof_hex),
        hex_to_bytes(public_inputs_hex),
    ) {
        (Some(v), Some(p), Some(i)) => (v, p, i),
        _ => return false,
    };
    verify_groth16_bn254(&vk, &proof, &inputs)
}

// ── prover side (client-only, out of scope this pass) ─────────────────────────────────────────

/// Placeholder for the client-side Semaphore identity + Groth16 proving path. In practice the
/// browser generates Semaphore proofs with snarkjs/rapidsnark (WASM); if we ever move proving into
/// this crate it links here, gated to `client-full` so it can never reach an edge Worker build.
#[cfg(feature = "client-full")]
pub fn prove_placeholder() {
    // TODO(Phase 2+): witness generation + Groth16 prove, client-only.
}
