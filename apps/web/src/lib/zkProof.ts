// Real client-side Semaphore v4 proving (R23, 2026-07). Generates the Groth16 proof AuthCallback.tsx's
// step 5 sends to /auth/session, replacing the retired fixed mock-proof vector.
//
// ARTIFACTS: `public/zk/semaphore-20.{wasm,zkey,json}` are the OFFICIAL PSE ceremony artifacts for
// tree depth 20 (matching MerkleTreeDO's MAX_DEPTH) — the exact same files validated server-side in
// the "R21-continued" pass (`@zk-kit/semaphore-artifacts@4.13.0`, sha256-verified against npm's own
// reported hash; see docs/06's R21-continued entry for ceremony provenance). Copied here verbatim, not
// re-downloaded or re-derived.
//
// WITNESS ABI: `snarkjs.groth16.fullProve` is driven directly with the real circuit's actual signal
// names (`secret`, `merkleProofLength`, `merkleProofIndex` — singular scalar — `merkleProofSiblings`,
// `message`, `scope`), NOT through `@semaphore-protocol/proof`'s `generateProof()`, which was found
// (server-side, same pass) to build a stale `merkleProofIndices` (plural array, v3-era) witness input
// that this circuit's real ABI rejects. See docs/06 R21-continued for the full finding.
//
// REAL MERKLE PATH (R23 follow-up, 2026-07): the caller's own Merkle proof (siblings + index) comes
// from the Worker's `GET /membership/proof/:commitment` (backed by `MerkleTreeDO`'s new `/proof/`
// route) — fetched by AuthCallback.tsx, not this module, matching the existing separation of "network
// calls live in AuthCallback.tsx, crypto lives here". `proveMembershipSession` below works for a tree of
// ANY size, not just the earlier sole-member special case (that trivial-tree-only restriction is gone —
// see docs/06's R23 entry for the history).
import { Identity } from "@semaphore-protocol/identity";
import * as snarkjs from "snarkjs";

export { Identity };

const FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const MAX_DEPTH = 20;

function fieldToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}
function fieldToBytes(n: bigint): Uint8Array {
  const hex = fieldToHex(n);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/// `H(label)` reduced into the BN254 scalar field — used for `scope`/`message`, matching docs/03 §3's
/// `scope = H(epoch)` ("one anonymous session per member per epoch"). `message` has no other
/// established meaning yet in this codebase, so it's a fixed domain-separated constant for now.
async function hashToField(label: string): Promise<bigint> {
  const bytes = new TextEncoder().encode(label);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  let n = 0n;
  for (const b of digest) n = (n << 8n) | BigInt(b);
  return n % FR_MODULUS;
}

export interface SemaphoreSessionProof {
  proofBytes: Uint8Array;
  merkleRoot: string; // hex64, the circuit's own output — must equal MerkleTreeDO's current root
  nullifier: string; // hex64
  message: string; // hex64
  scope: string; // hex64
}

/// The shape `GET /membership/proof/:commitment` returns — `siblings` are hex64 field elements,
/// ordered leaf-to-root, one per actual tree level (NOT pre-padded to MAX_DEPTH; this module pads).
export interface MerkleProofResponse {
  index: number;
  siblings: string[];
  merkleRoot: string;
}

/**
 * Generate a real Groth16 Semaphore v4 proof for `identity`, given its real Merkle proof (`merkleProof`,
 * as returned by `GET /membership/proof/:commitment` — fetched by the caller, not here). Works for a
 * tree of any size: `merkleProof.siblings` may be shorter than `MAX_DEPTH` (LeanIMT's actual depth grows
 * with leaf count), padded with zeros for the unused levels — the circuit's own `merkleProofLength`
 * signal tells it how many of the `MAX_DEPTH` siblings slots are real.
 */
export async function proveMembershipSession(identity: Identity, merkleProof: MerkleProofResponse): Promise<SemaphoreSessionProof> {
  if (merkleProof.siblings.length > MAX_DEPTH) {
    throw new Error(`Merkle proof has ${merkleProof.siblings.length} siblings, more than this circuit's MAX_DEPTH (${MAX_DEPTH}).`);
  }

  const epoch = Math.floor(Date.now() / 1000 / 3600);
  const scope = await hashToField(`vorticity-epoch:${epoch}`);
  const message = await hashToField("vorticity-auth-session");
  const merkleProofSiblings = merkleProof.siblings.map((hex) => BigInt(`0x${hex}`));
  while (merkleProofSiblings.length < MAX_DEPTH) merkleProofSiblings.push(0n);

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      secret: identity.secretScalar,
      merkleProofLength: merkleProof.siblings.length,
      merkleProofIndex: merkleProof.index,
      merkleProofSiblings,
      message,
      scope,
    },
    "/zk/semaphore-20.wasm",
    "/zk/semaphore-20.zkey",
  );

  const g1ToBytes = (p: string[]): Uint8Array => concatBytes(fieldToBytes(BigInt(p[0]!)), fieldToBytes(BigInt(p[1]!)));
  const g2ToBytes = (p: string[][]): Uint8Array =>
    concatBytes(
      fieldToBytes(BigInt(p[0]![0]!)),
      fieldToBytes(BigInt(p[0]![1]!)),
      fieldToBytes(BigInt(p[1]![0]!)),
      fieldToBytes(BigInt(p[1]![1]!)),
    );
  const proofBytes = concatBytes(g1ToBytes(proof.pi_a), g2ToBytes(proof.pi_b), g1ToBytes(proof.pi_c));

  // circom convention: circuit OUTPUTS first, then declared-public INPUTS — [merkleRoot, nullifier, message, scope].
  if (publicSignals.length !== 4) throw new Error(`expected 4 public signals from the circuit, got ${publicSignals.length}`);
  const [merkleRoot, nullifier, messageOut, scopeOut] = publicSignals.map((s: string) => fieldToHex(BigInt(s)));

  return { proofBytes, merkleRoot: merkleRoot!, nullifier: nullifier!, message: messageOut!, scope: scopeOut! };
}
