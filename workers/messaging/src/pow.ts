// Hashcash-family PoW stamp verification (docs/03-crypto-core.md §8.3), extracted from
// AliasDO.ts (2026-07, "alias contact establishment" pass) so `index.ts`'s new
// `POST /alias/introduce` write-path (AliasDO.ts's own `handleIntroduce`) can reuse the SAME
// already-tested verification logic instead of a second hand-rolled copy — a security-critical
// check like this should have exactly one implementation, not two that could drift apart.
//
// Deliberately still plain TS, not the crate's new `pow.rs`/`pow_verify` WASM export (see that
// module's doc comment): verification is a single hash, cheap enough that there's no performance
// reason to swap a working, already-live-tested implementation for a WASM call, and doing so here
// would be unrelated risk for the pass that added it.
//
// `stamp = ver:alg:bits:epoch:resource:salt:counter`. A stamp is valid iff SHA-256(stamp) has >=
// the caller's required leading zero bits, `resource` matches the target being spent against
// (binds the stamp so it can't be replayed against a different resource), and `epoch` is within
// the caller's tolerance window (bounds how long a precomputed stamp stays usable).
export const MAX_STAMP_LEN = 512; // defensive cap, not a protocol limit
export const EPOCH_MS = 60 * 60 * 1000;
export const EPOCH_TOLERANCE = 1; // stamp's epoch may be current +/- this many hours

export type PowVerdict = { ok: true; epoch: number } | { ok: false; reason: string };

/** Leading zero bits across a byte string, MSB-first — the Hashcash difficulty measure. */
export function countLeadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    let b = byte;
    while ((b & 0x80) === 0) {
      bits++;
      b = (b << 1) & 0xff;
    }
    break;
  }
  return bits;
}

export async function verifyPowStamp(stamp: string, expectedResource: string, minBits: number): Promise<PowVerdict> {
  if (stamp.length === 0 || stamp.length > MAX_STAMP_LEN) {
    return { ok: false, reason: "stamp length out of bounds" };
  }
  const parts = stamp.split(":");
  if (parts.length !== 7) {
    return { ok: false, reason: "malformed stamp: expected ver:alg:bits:epoch:resource:salt:counter" };
  }
  const [ver, alg, , epochStr, resource] = parts;
  if (ver !== "1") return { ok: false, reason: `unsupported stamp version: ${ver}` };
  if (alg !== "sha256") return { ok: false, reason: `unsupported stamp algorithm: ${alg}` };
  if (resource !== expectedResource) return { ok: false, reason: "stamp resource does not match target lookup_key" };

  const epoch = Number(epochStr);
  if (!Number.isInteger(epoch)) return { ok: false, reason: "invalid epoch field" };
  const currentEpoch = Math.floor(Date.now() / EPOCH_MS);
  if (Math.abs(epoch - currentEpoch) > EPOCH_TOLERANCE) {
    return { ok: false, reason: "stamp epoch outside acceptance window" };
  }

  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stamp));
  const actualBits = countLeadingZeroBits(new Uint8Array(digest));
  if (actualBits < minBits) {
    return { ok: false, reason: `insufficient PoW: ${actualBits} < ${minBits} leading zero bits` };
  }

  return { ok: true, epoch };
}

/** `(epoch + tolerance + 1 whole epoch)` — the point after which a stamp minted at `epoch` can no
 * longer pass the freshness check above, so a replay-set entry for it is safe to evict. Shared by
 * every caller that records spent stamps (AliasDO's register/resolve/introduce) so the eviction
 * horizon always matches the acceptance window it's protecting. */
export function stampExpiryFromEpoch(epoch: number): number {
  return (epoch + EPOCH_TOLERANCE + 1) * EPOCH_MS;
}
