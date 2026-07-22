// RFC 6962-style Merkle consistency proofs (docs/06 "Key Transparency (K8)" — the explicitly-named
// residual gap: the append-only log + inclusion proofs already prove "this entry is IN the current
// tree", but not that an EARLIER published root is a genuine append-only prefix of a LATER one. A
// single operator controlling the only copy of the log could otherwise fork it for one victim
// without this piece — see KeyTransparencyDO.ts's own header comment for the full threat model.
//
// Deliberately independent of any live LeanIMT instance's internal node matrix. Reading
// `@zk-kit/lean-imt`'s actual `insert()` source (not assumed) shows it MUTATES `_nodes[level][index]`
// in place: a "carried up unchanged" lone node (no right sibling yet) gets OVERWRITTEN once a later
// insertion gives it a real sibling. Concretely, for leaves L0..L3 inserted one at a time,
// `_nodes[1][1]` is L2 right after the 3rd insert, then becomes hash(L2,L3) after the 4th — so a live
// tree's CURRENT node matrix cannot answer "what was the subtree hash when the tree had only m
// leaves" for arbitrary past m; that would silently return today's value, not history's. This module
// always recomputes MTH(...) from the raw ordered leaf-hash list for whatever exact prefix size is
// asked for for exactly this reason — recomputation is O(n) per call, acceptable since a consistency
// proof is an occasional audit operation, not a hot path (same "correctness first, perf later if ever
// needed" precedent as this codebase's original R21 Merkle pass before its own incremental-cache
// follow-up).
//
// SHAPE EQUIVALENCE (verified, not assumed — see this module's own test suite): `LeanIMT.insert()`'s
// "no right child yet -> carry the left child's value up unchanged" rule, applied level-by-level, is
// the SAME tree shape as RFC 6962 §2.1.2's recursive "split D[n] at the largest power of two k < n"
// definition, for every n — confirmed by an exhaustive cross-check (this module's `mth()` against an
// independently-built `LeanIMT` over the same prefix, for every prefix size). That equivalence is what
// makes a proof built by this module valid against KeyTransparencyDO's real LeanIMT roots.
//
// HONEST SCOPE, a real finding from this module's own adversarial testing, not assumed in advance:
// `verifyConsistency` authenticates that root_m's CONTENT is a genuine append-only prefix of root_n's
// content. It does NOT independently authenticate the numeric size label attached to root_n — a
// brute-force test deliberately fed the real proof/root for an actual n=37 tree back in under a
// claimed n=36 and it verified, because the algorithm's recursive right-hand subtree hash is opaque
// (its internal leaf count is never re-derived, only its aggregate value used) and the claimed n
// only changes it, if it does at all, in the small window where the two candidate n's don't yet
// share a "largest power of two below n" split boundary. This is not a bug: real Certificate
// Transparency deployments bind (tree_size, root_hash) together via a Signed Tree Head — a signature,
// a mechanism entirely separate from the Merkle-consistency math — precisely because the math alone
// was never meant to authenticate the size label. What the math DOES guarantee, and what this
// module's own fork test (two trees sharing a prefix then diverging) confirms live: a proof built
// against one tree's root can never verify against a genuinely DIFFERENT root claimed for the same
// (m, n) — i.e., real equivocation (the K8 threat model) is caught. Binding the (size, root) pair
// itself to a signature is separate, not-yet-built work (same "no independent monitors/gossip" gap
// KeyTransparencyDO's own header comment already names) — callers of this module must obtain the
// (n, root) pairs they compare from a source they already trust for that pairing (e.g. their own
// earlier `/root` fetch), not from an unauthenticated claim made in the same request as the proof.

export type Combine = (a: bigint, b: bigint) => bigint;

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle Tree Hash of leaves[0:n) per RFC 6962 §2.1.1 — recomputed from scratch, no external state. */
export function mth(combine: Combine, leaves: bigint[]): bigint {
  const n = leaves.length;
  if (n === 0) throw new RangeError("mth: cannot hash an empty leaf list");
  if (n === 1) return leaves[0]!; // length===1 just checked — index 0 always exists
  const k = largestPowerOfTwoBelow(n);
  return combine(mth(combine, leaves.slice(0, k)), mth(combine, leaves.slice(k, n)));
}

function subProof(combine: Combine, m: number, leaves: bigint[], haveRootOfSmall: boolean): bigint[] {
  const n = leaves.length;
  if (m === n) {
    return haveRootOfSmall ? [] : [mth(combine, leaves)];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    return [...subProof(combine, m, leaves.slice(0, k), haveRootOfSmall), mth(combine, leaves.slice(k, n))];
  }
  return [...subProof(combine, m - k, leaves.slice(k, n), false), mth(combine, leaves.slice(0, k))];
}

/**
 * RFC 6962 PROOF(m, D[n]): the ordered subtree hashes that let a verifier confirm root(D[0:m]) is a
 * genuine append-only prefix of root(D[n]). Requires 0 < m < n (m == n is trivial/empty by
 * definition; m == 0 is meaningless — there is no root to be consistent with).
 */
export function consistencyProof(combine: Combine, m: number, leaves: bigint[]): bigint[] {
  const n = leaves.length;
  if (!Number.isInteger(m) || m <= 0 || m >= n) {
    throw new RangeError(`consistencyProof: requires 0 < m < n (got m=${m}, n=${n})`);
  }
  return subProof(combine, m, leaves, true);
}

/**
 * Verifies a consistency proof between an earlier root (size m) and a later root (size n), per RFC
 * 6962 §2.1.2's standard iterative verification algorithm. Returns false (never throws) on any
 * malformed input — this function's whole point is to be safe to run against untrusted/adversarial
 * proof bytes from an unauthenticated route.
 */
export function verifyConsistency(
  combine: Combine,
  m: number,
  n: number,
  rootM: bigint,
  rootN: bigint,
  proof: bigint[],
): boolean {
  if (!Number.isInteger(m) || !Number.isInteger(n) || m <= 0 || n <= 0 || m > n) return false;
  if (m === n) return proof.length === 0 && rootM === rootN;

  let node = m - 1;
  let lastNode = n - 1;
  while (node % 2 === 1) {
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }

  let idx = 0;
  let fr: bigint;
  let sr: bigint;
  if (node > 0) {
    if (proof.length === 0) return false;
    fr = proof[0]!; // length checked just above
    sr = proof[0]!;
    idx = 1;
  } else {
    fr = rootM;
    sr = rootM;
  }

  while (node > 0) {
    if (node % 2 === 1) {
      if (idx >= proof.length) return false;
      const p = proof[idx]!; // idx < proof.length just checked
      fr = combine(p, fr);
      sr = combine(p, sr);
      idx += 1;
    } else if (node < lastNode) {
      if (idx >= proof.length) return false;
      sr = combine(sr, proof[idx]!); // idx < proof.length just checked
      idx += 1;
    }
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }
  while (lastNode > 0) {
    if (idx >= proof.length) return false;
    sr = combine(sr, proof[idx]!); // idx < proof.length just checked
    idx += 1;
    lastNode = Math.floor(lastNode / 2);
  }

  return fr === rootM && sr === rootN && idx === proof.length;
}
