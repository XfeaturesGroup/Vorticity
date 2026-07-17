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

// ── Real Semaphore v4 vector (R21, 2026-07) ──────────────────────────────────────────────────────
//
// Everything above this point uses `build_vector()`'s structurally-equivalent MOCK circuit (4 public
// inputs in Semaphore's order, one real R1CS multiplication) — it validates our byte-contract/parser
// pipeline but is NOT Semaphore's real circuit. This test closes that gap: the vk/proof/public-inputs
// below come from the REAL, OFFICIAL `@semaphore-protocol/circuits` v4 template
// (github.com/semaphore-protocol/semaphore/packages/circuits/src/semaphore.circom, unmodified,
// MAX_DEPTH=20), compiled with the real `circom 2.2.3` compiler and a REAL Groth16 setup
// (snarkjs: powersoftau + circuit-specific setup + contribution) — NOT PSE's production ceremony
// (this is a local, test-only trusted setup; see docs/06's R21 entry for why that's the honest scope
// for proving OUR verifier/pipeline is correct, as opposed to attesting to mainnet-ceremony security).
//
// Public signal order, confirmed empirically from snarkjs's own `publicSignals` output (circom
// convention: circuit OUTPUTS first, then declared-public INPUTS): `[merkleRoot, nullifier, message,
// scope]` — same POSITIONS as the mock's `[merkleRoot, nullifierHash, signalHash, externalNullifier]`
// (nPublic=4 either way), different names/semantics per the real v4 circuit
// (`nullifier = Poseidon2(scope, secret)`, no separate "signalHash"/"externalNullifier" hashing step
// inside the circuit itself — the real circuit takes `message`/`scope` directly).
//
// The witness/proof were generated for: a 2-leaf LeanIMT (Poseidon2) with the proving identity's
// commitment at index 0, `message=1337`, `scope=42`. `merkleRoot`/`nullifier` are therefore real,
// self-consistent values from that real tree/identity — not placeholders.
#[test]
fn real_semaphore_v4_vector_verifies() {
    let vk_hex = "15c77a2b333b2c35ce275aa66ff61002be4735273f54815f7bbed68c6b9ad3380ba3c527a60ae53284d7e37c04ed7fa09ac6ed8d4be9a0f8583b2e695a02ae17147f6fb673c131967c834c212e540c2ddf599ee4c45eb1c9c10aab0010a1a4372e036a0f1ca05bee9f52e23f24d9ed001fdd318ff145ce1c35f0af1d984e70401586f27e93fa19fef2f57d6c52b51c03449f38807b8ca8e5a000f6e854b3faa508683c375bdd137e988a37ef3bc749470bfaed628e91d8fbd5e312c4e02ea63f1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c212c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b1b2462f3d634bd394f6430f6c339be0070cb20983e2c5e088bd67fcbcae7758a0fe99b19c95af9ca373a0da5af51d72c977575acd3fb3bd566acd3743e90a039176d46b5d204461a2b5b62dfcf667732466fcdb2259e02dea037d37f9c0b1c9e02fc8ed514d75adb617303897fcbf682d76bdcc3e4954061505bbd452e8a4c6a2905e2777a5edc1f484fc81c65bd648be9ce82cbcf95bf559032874cfd6e972423d3f68cdb15f32646e82991f530ab386ebd316ab5ae7987ee7b3caaf5a44bf5045450d36221e211d55ffeb733d8a2859850121ee482fda46b3ad4ac1624d76e0d51a07f44e1251cb8746f5cb20dcfb7ff89b914365f09ef84e2041be23f5eb6047807142b0dcf739e0a59d1ae00c45b87acc8ecb9b407dd87d8666fd1729eb302749f0b5e1674460c68c4700b516f841f5de20201e2dc3bb5c8c2529b961f4e2ac9e93f129c60becde1cff8818dafcbb3b3382362db0ee62bb1fd0478382cf128dd11dabf4256ccd5f792c6b85fea3c6a6719b37567f93249fea0f3329c19640900bef55f144a994bec0b36e2f7ee093a2eebda437e1088be5ffddc11f34aed2e263857e1de8c40f1848743799056ad0f6117d874f298ba389e37e7623a24fa";
    let proof_hex = "101aadebcb6f0a53ed7f7fe43f0b3191fb9f2aaa57a6b82d20ffc2dc8fc2697410171627f5ccb3fc89df24b37c6402840b064c8ee732e34d87e494516c67d38f01543a3fe26b0b5f526911ecb3cf947fc2d81ae1f7d617249536e62a9517a22f08f73be286ea958303b70d2972e81c0f89e5f03f83cc26ba4d2c32315a836a50058cb0dc9f02e4ea3e44f3f41705a84274326be88e6bd1c622edb3a0c14344a912f1f872ae7c25d2bba4e0a046f425e16ffaca1e9b01c7c502720d40d92b23a0198736b0e4d3d8d59e1ce23e59df3a6f28cadccbbaa092619d6da36b0a7f92ce20cd54c926bb0258e18faa026da400705665ba6515b5c13606a4e02c5448b9d5";
    let inputs_hex = "05f43fb3c09152b01a54d1ea36275f238caa23194b42c43e081217da0ce4c40a2ee795c84e3c7ccb04063c2b052192e1218f865faf09c0390647d50ffba979580000000000000000000000000000000000000000000000000000000000000539000000000000000000000000000000000000000000000000000000000000002a";

    let hex_bytes = |s: &str| -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let vk = hex_bytes(vk_hex);
    let proof = hex_bytes(proof_hex);
    let inputs = hex_bytes(inputs_hex);
    assert_eq!(vk.len(), 768);
    assert_eq!(proof.len(), 256);
    assert_eq!(inputs.len(), 128);

    assert!(
        zk_verify_groth16_bytes(&vk, &proof, &inputs),
        "verifier rejected a real, valid Semaphore v4 proof from the official circuit"
    );

    // Negative control: tamper the last input (scope) — must reject, same as the mock vector's test.
    let mut tampered = inputs.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        !zk_verify_groth16_bytes(&vk, &proof, &tampered),
        "verifier accepted a real Semaphore v4 proof against a tampered public input"
    );
}

// ── Official PSE trusted-setup ceremony vector (R21-continued, 2026-07) ─────────────────────────────
//
// The vector above (`real_semaphore_v4_vector_verifies`) used a LOCAL, single-party test-only Groth16
// setup — legitimate for proving our verifier/pipeline is byte-compatible with a real circuit, but
// explicitly NOT something to trust in production (the toxic waste from a single-party setup is known
// to that one party). This test replaces that concern: the VK below is converted directly from
// `semaphore-20.json`, part of the official `@zk-kit/semaphore-artifacts@4.13.0` npm package
// (downloaded from unpkg, sha256-verified against the hash npm itself reports for that exact file —
// see docs/06's R21-continued entry). That package ships the output of "Semaphore V4 Ceremony 1", a
// real multi-party Groth16 Phase 2 ceremony run by PSE with 300-400+ independent contributors,
// finalized 2024-09-05 (attestation: gist.github.com/NicoSerranoP/10b09d0539cb87445fee2d3d98cda96a,
// contributor attestations confirm circuit `semaphorev4-20` was one of the 32 circuits — one per
// supported tree depth 1..32 — covered by that ceremony). As long as at least one of those hundreds of
// contributors destroyed their randomness, the toxic waste is unrecoverable — the standard trust
// assumption for a real MPC trusted setup, unlike the single-party vector above.
//
// The witness/proof were generated with the OFFICIAL semaphore-20.wasm/zkey (not a locally recompiled
// circuit) via snarkjs, driven directly (not through `@semaphore-protocol/proof@4.11.1`'s
// `generateProof()`, which was found to build a stale `merkleProofIndices` (plural, per-level bit
// array) witness input that this circuit's actual ABI rejects — the real circuit takes a single scalar
// `merkleProofIndex`, confirmed by direct probing against the downloaded wasm). A real 2-leaf LeanIMT
// (Poseidon2) tree, two real `@semaphore-protocol/identity` identities, `message=20260718`,
// `scope=1784326405067`. `snarkjs.groth16.verify()` against the official `semaphore-20.json` VK
// confirmed `true` before this vector was ever handed to arkworks.
#[test]
fn official_ceremony_semaphore_v4_vector_verifies() {
    let vk_hex = "245229d9b076b3c0e8a4d70bde8c1cccffa08a9fae7557b165b3b0dbd653e2c7253ec85988dbb84e46e94b5efa3373b47a000b4ac6c86b2d4b798d274a1823022424bcc1f60a5472685fd50705b2809626e170120acaf441e133a2bd5e61d24407090a82e8fabbd39299be24705b92cf208ee8b3487f6f2b39ff27978a29a1db2b86859fd3d55c9d150fb3f0aeba798826493dd73d357ab0f9fdaced9fc818290ae1135cffdaf227c5dc266740607aa930bc3bd92ddc2b135086d9da2dfd3e2a1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c212c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b1673e455967762f96f57b413424631198e09e7bb1bb06844068fe44f307a8d591230a42b5aa82168743e9817923ea3ebd1d3a55ef1bd91a89eacc55663a026402e92f89b6bd8472ef679fa5d617805180e6e0605423cac37fc15f281939770a7061d9c5b1f377adc54722ccaf3601332ebc07660fec4d89b5c8213031f0aa8b72d3c9778d5cb3ab0bfe4b296e2ed90ed19619b8b353c1043b40e03b568a049a417276cb455cc5d461db37b0b4f6b34f1bb429a76968726205617095e1d39b92d09dae1c6d2e4114c5439c81baa28594cc0ab76e7f32c25c4f780c9e9d6e46a5a0a23d3bedfe1b14bff3eec36492bb9329f56ddbf7f5e1f122838e96dcfe98c4613a1149cf273a308c777146d7f4be2160aac12980d97661fad18cf682b7c5e242b74aaa132494d280ca444d5d2a99cd2bd426ff82d443e2b44b8441733bd450d29b8403a3843d4a77b6c70539d8965e57af369d6f32feab13450f3fa985aed18142569f4ef08c2a1947dcb6e99b5ac52cdd5876c50f02bd6afd62fc810a755110f47bd52a43c690f658374e9f7c2bc4285c641c7116a4ccd2c94f684cbeb7f2a17a29f16b646ebe94c4b2e2c4bc375cd7b002111dd55c4d212e9360cec88c188";
    let proof_hex = "23234ac83feaa93c31fd8235397511cd53d3cb2bae46213d9cf1c70ea4ef5fe30cf42499488dbb7c5661cb32108bdd6ce5bdeafc26437c56b493202cdb3eb1121991bd8512e55196bec979f1f23b8a14b91c77e3be197c041f970761e93bdd3e2b7026e30f09f97b3e2236365bbc27bdc2ffd53056153e5baffec3d1cf720acf244495ffbb7a7efc21a9be735ab29fa8186362bc74fcd8a6cd7ef4aebf6c520b29fd99918f35bee4e05e86d4e957a1bdc24ff1249810b750863c7d9dbf87523b081c9a31a6d74747613595ffd76259a33fc7360ad690ad53d9029010ea1e3e961ce8ea0ab7ad7b34aaa9c100db08e0144959a3ffe9b4ad795dbe3334811b320d";
    let inputs_hex = "0f2be177d0a8efab19f3bb5b849581d2a73f8330e7b412f6c6e9674d445bddad06e5af06125a35bbe35d2808003821de26ad391038cc6a00301db0416d4c5d6e000000000000000000000000000000000000000000000000000000000135276e0000000000000000000000000000000000000000000000000000019f72243bcb";

    let hex_bytes = |s: &str| -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let vk = hex_bytes(vk_hex);
    let proof = hex_bytes(proof_hex);
    let inputs = hex_bytes(inputs_hex);
    assert_eq!(vk.len(), 768);
    assert_eq!(proof.len(), 256);
    assert_eq!(inputs.len(), 128);

    assert!(
        zk_verify_groth16_bytes(&vk, &proof, &inputs),
        "verifier rejected a real, valid Semaphore v4 proof from the OFFICIAL PSE ceremony circuit"
    );

    let mut tampered = inputs.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        !zk_verify_groth16_bytes(&vk, &proof, &tampered),
        "verifier accepted an official-ceremony Semaphore v4 proof against a tampered public input"
    );
}
