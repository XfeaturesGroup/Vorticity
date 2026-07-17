//! Integration test for the Groth16/BN254 verifier (`zk.rs`) — the Phase 2 ZKP-spike validation.
//!
//! WHAT THIS PROVES: we generate a *real* Groth16/BN254 proof with arkworks (real trusted setup,
//! real prover), then serialize the verifying key, proof, and public inputs into `zk.rs`'s exact
//! big-endian byte contract and run them through the public `zk_verify_groth16_bytes` boundary.
//! That end-to-end exercises the real curve, the real 3-pairing verify, and — the whole point of
//! the user's concern — the crate's serialization/parse pipeline: G1/G2 point reconstruction,
//! the **G2 Fq2 [c0, c1] coordinate order**, big-endian field encoding, the VK/proof/IC offsets,
//! and the **public-input ordering** (merkleRoot, nullifierHash, signalHash, externalNullifier).
//!
//! WHAT THIS DOES NOT PROVE: this is not Semaphore's actual circuit (Poseidon/LeanIMT over a
//! ceremony-produced key) — it's a structurally-equivalent mock (4 public inputs in Semaphore's
//! order, nPublic=4). Confirming byte-compat against a genuine snarkjs-produced Semaphore v4
//! proof still requires the snarkjs toolchain and is the remaining Phase 2 item (docs/06). Because
//! arkworks and snarkjs share the Fq2 = c0 + c1·u convention, the [c0, c1] order validated here is
//! the same one snarkjs's raw proof.json uses (the swap to [c1, c0] lives only in snarkjs's
//! Solidity export). The `g2_coordinate_order_is_load_bearing` case makes that ordering explicit:
//! swapping c0/c1 must cause rejection.

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, Variable};
use ark_relations::lc;
use ark_snark::SNARK;
// Use a concrete StdRng from arkworks' OWN re-exported rand (`ark_std::rand`) — this is the exact
// rand crate ark-snark's `R: RngCore + CryptoRng` bound refers to, so both bounds are satisfied
// unambiguously. (`ark_std::test_rng()` returns an opaque `impl rand::Rng` that doesn't carry
// `CryptoRng`, and the KEM deps pull a second rand_core version — hence the explicit type here.)
use ark_std::rand::{rngs::StdRng, SeedableRng};

use ark_groth16::Groth16;

use crate::zk::zk_verify_groth16_bytes;

const N_PUBLIC: usize = 4; // Semaphore v4: merkleRoot, nullifierHash, signalHash, externalNullifier

/// Mock circuit, structurally equivalent to Semaphore's instance shape: 4 public inputs, in the
/// documented signal order. One real R1CS multiplication ties `merkle_root = a * b` (so the proof
/// is only valid for the exact public `merkle_root` — a bit-flip on it must break verification);
/// the other three public signals are wired into trivially-satisfiable `x * 1 = x` constraints so
/// they each get a real IC entry, exactly as all four Semaphore signals do.
#[derive(Clone)]
struct MockSemaphoreCircuit {
    // witnesses
    a: Option<Fr>,
    b: Option<Fr>,
    // public inputs, in Semaphore v4 order
    merkle_root: Option<Fr>, // == a * b
    nullifier_hash: Option<Fr>,
    signal_hash: Option<Fr>,
    external_nullifier: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MockSemaphoreCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        let a = cs.new_witness_variable(|| self.a.ok_or(ark_relations::gr1cs::SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(ark_relations::gr1cs::SynthesisError::AssignmentMissing))?;

        // Public-input allocation order === Groth16 public-input index order === the order the
        // verifier must receive them in.
        let root = cs.new_input_variable(|| self.merkle_root.ok_or(ark_relations::gr1cs::SynthesisError::AssignmentMissing))?;
        let nullifier =
            cs.new_input_variable(|| self.nullifier_hash.ok_or(ark_relations::gr1cs::SynthesisError::AssignmentMissing))?;
        let signal =
            cs.new_input_variable(|| self.signal_hash.ok_or(ark_relations::gr1cs::SynthesisError::AssignmentMissing))?;
        let ext =
            cs.new_input_variable(|| self.external_nullifier.ok_or(ark_relations::gr1cs::SynthesisError::AssignmentMissing))?;

        // a * b = merkle_root
        cs.enforce_r1cs_constraint(|| lc![a], || lc![b], || lc![root])?;
        // wire the other three public signals in (always satisfiable): x * 1 = x
        cs.enforce_r1cs_constraint(|| lc![nullifier], || lc![Variable::One], || lc![nullifier])?;
        cs.enforce_r1cs_constraint(|| lc![signal], || lc![Variable::One], || lc![signal])?;
        cs.enforce_r1cs_constraint(|| lc![ext], || lc![Variable::One], || lc![ext])?;
        Ok(())
    }
}

// ── serialize arkworks types into zk.rs's big-endian byte contract ─────────────────────────────

fn fq_be(f: &Fq) -> [u8; 32] {
    let v = f.into_bigint().to_bytes_be(); // BN254 BigInt<4> → 32 bytes
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v); // left-pad defensively
    out
}
fn fr_be(f: &Fr) -> [u8; 32] {
    let v = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}
fn g1_be(p: &G1Affine) -> Vec<u8> {
    [fq_be(&p.x), fq_be(&p.y)].concat()
}
fn g2_be(p: &G2Affine) -> Vec<u8> {
    // x = c0 + c1·u, y = c0 + c1·u → serialize c0 then c1 (the contract in zk.rs).
    [fq_be(&p.x.c0), fq_be(&p.x.c1), fq_be(&p.y.c0), fq_be(&p.y.c1)].concat()
}

fn build_vector() -> (Vec<u8>, Vec<u8>, Vec<u8>, ark_groth16::VerifyingKey<Bn254>, ark_groth16::Proof<Bn254>, Vec<Fr>) {
    let mut rng = StdRng::seed_from_u64(0xF00D_BEEF_u64);

    // Concrete assignment: a, b arbitrary; merkle_root = a*b; the other signals are mock hashes.
    let a = Fr::from_be_bytes_mod_order(&[0x11; 32]);
    let b = Fr::from_be_bytes_mod_order(&[0x22; 32]);
    let merkle_root = a * b;
    let nullifier_hash = Fr::from_be_bytes_mod_order(&[0xAB; 32]);
    let signal_hash = Fr::from_be_bytes_mod_order(&[0xCD; 32]);
    let external_nullifier = Fr::from_be_bytes_mod_order(&[0xEF; 32]);

    // Setup reads only structure (witness/input closures are not evaluated in setup mode), so
    // None assignments are fine here.
    let setup_circuit = MockSemaphoreCircuit {
        a: None,
        b: None,
        merkle_root: None,
        nullifier_hash: None,
        signal_hash: None,
        external_nullifier: None,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).expect("setup");

    let prove_circuit = MockSemaphoreCircuit {
        a: Some(a),
        b: Some(b),
        merkle_root: Some(merkle_root),
        nullifier_hash: Some(nullifier_hash),
        signal_hash: Some(signal_hash),
        external_nullifier: Some(external_nullifier),
    };
    let proof = Groth16::<Bn254>::prove(&pk, prove_circuit, &mut rng).expect("prove");

    let public_inputs = vec![merkle_root, nullifier_hash, signal_hash, external_nullifier];
    assert_eq!(public_inputs.len(), N_PUBLIC);

    // Serialize into the byte contract.
    let mut vk_bytes = Vec::new();
    vk_bytes.extend(g1_be(&vk.alpha_g1));
    vk_bytes.extend(g2_be(&vk.beta_g2));
    vk_bytes.extend(g2_be(&vk.gamma_g2));
    vk_bytes.extend(g2_be(&vk.delta_g2));
    assert_eq!(vk.gamma_abc_g1.len(), N_PUBLIC + 1, "IC must have nPublic+1 points");
    for ic in &vk.gamma_abc_g1 {
        vk_bytes.extend(g1_be(ic));
    }

    let mut proof_bytes = Vec::new();
    proof_bytes.extend(g1_be(&proof.a));
    proof_bytes.extend(g2_be(&proof.b));
    proof_bytes.extend(g1_be(&proof.c));
    assert_eq!(proof_bytes.len(), 256);

    let inputs_bytes: Vec<u8> = public_inputs.iter().flat_map(|f| fr_be(f)).collect();
    assert_eq!(inputs_bytes.len(), N_PUBLIC * 32);

    (vk_bytes, proof_bytes, inputs_bytes, vk, proof, public_inputs)
}

#[test]
fn accept_valid_semaphore_shaped_proof() {
    let (vk_bytes, proof_bytes, inputs_bytes, vk, proof, public_inputs) = build_vector();

    // Sanity: arkworks' own verify agrees the proof is valid (independent of our serialization).
    assert!(
        Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap(),
        "arkworks-native verify rejected a proof it just produced"
    );

    // The real assertion: our verifier, fed the serialized byte contract, ACCEPTS.
    assert!(
        zk_verify_groth16_bytes(&vk_bytes, &proof_bytes, &inputs_bytes),
        "zk_verify_groth16_bytes rejected a valid proof — serialization/parse mismatch"
    );
}

#[test]
fn reject_tampered_public_input() {
    let (vk_bytes, proof_bytes, mut inputs_bytes, ..) = build_vector();
    // Flip the least-significant bit of merkleRoot (input 0). The proof was bound to a*b, so the
    // pairing check must now fail — this exercises rejection through the full verify, not just a
    // parse error.
    inputs_bytes[31] ^= 1;
    assert!(
        !zk_verify_groth16_bytes(&vk_bytes, &proof_bytes, &inputs_bytes),
        "verifier accepted a proof against tampered public inputs"
    );
}

#[test]
fn reject_tampered_proof_bit() {
    let (vk_bytes, mut proof_bytes, inputs_bytes, ..) = build_vector();
    let last = proof_bytes.len() - 1;
    proof_bytes[last] ^= 1; // flip one bit of C.y
    assert!(
        !zk_verify_groth16_bytes(&vk_bytes, &proof_bytes, &inputs_bytes),
        "verifier accepted a proof with a flipped bit"
    );
}

#[test]
fn g2_coordinate_order_is_load_bearing() {
    // Take the valid proof and swap the c0/c1 halves of every Fq2 in the G2 point B. If our
    // parser's [c0, c1] convention were wrong (or if a caller applied snarkjs's Solidity-export
    // [c1, c0] swap), the proof would be built this way — and it MUST be rejected. Proves the
    // ordering is exactly the one that verifies, not the swapped one.
    let (vk_bytes, proof_bytes, inputs_bytes, ..) = build_vector();
    let mut swapped = proof_bytes.clone();
    // Proof layout: A[0..64] || B[64..192] || C[192..256]; B = xc0|xc1|yc0|yc1, each 32 bytes.
    let b = &proof_bytes[64..192];
    let xc0 = &b[0..32];
    let xc1 = &b[32..64];
    let yc0 = &b[64..96];
    let yc1 = &b[96..128];
    let mut b_swapped = Vec::with_capacity(128);
    b_swapped.extend_from_slice(xc1);
    b_swapped.extend_from_slice(xc0);
    b_swapped.extend_from_slice(yc1);
    b_swapped.extend_from_slice(yc0);
    swapped[64..192].copy_from_slice(&b_swapped);

    assert!(
        !zk_verify_groth16_bytes(&vk_bytes, &swapped, &inputs_bytes),
        "verifier accepted a proof with swapped G2 [c1, c0] ordering — ordering is not being enforced"
    );
}
