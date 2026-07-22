// The concrete hash function KeyTransparencyDO's LeanIMT uses, extracted out of that file so it has
// exactly ONE definition shared by (1) the live DO and (2) `scripts/kt-monitor.mts` — an independent
// auditor verifying a consistency proof MUST combine sibling hashes the identical way the log itself
// does, or every proof would spuriously fail. Plain SHA-256, not Poseidon2: this log is never read
// inside a ZK circuit (unlike MerkleTreeDO's Semaphore accumulator), so there is no reason to pay for
// circuit-compatible field arithmetic here.
import { createHash } from "node:crypto";

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Combines two 256-bit node values the same way KeyTransparencyDO's LeanIMT does: SHA-256 over the
 * big-endian hex concatenation. Passed as the `Combine` callback to merkleConsistency.ts's
 * algorithm-agnostic `mth`/`consistencyProof`/`verifyConsistency`. */
export function ktCombine(a: bigint, b: bigint): bigint {
  const aHex = a.toString(16).padStart(64, "0");
  const bHex = b.toString(16).padStart(64, "0");
  const bytes = Buffer.from(aHex + bHex, "hex");
  return BigInt("0x" + sha256Hex(bytes));
}

export function fieldToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

export function hexToField(hex: string): bigint {
  return BigInt("0x" + hex);
}
