// Hashcash-family PoW stamp verification (docs/03-crypto-core.md §8.3), extracted from
// AliasDO.ts (2026-07, "alias contact establishment" pass) so `index.ts`'s new
// `POST /alias/introduce` write-path (AliasDO.ts's own `handleIntroduce`) can reuse the SAME
// already-tested verification logic instead of a second hand-rolled copy — a security-critical
// check like this should have exactly one implementation, not two that could drift apart.
//
// `stamp = ver:alg:bits:epoch:resource:salt:counter`. A stamp is valid iff Hpow(stamp) has >= the
// caller's required leading zero bits, `resource` matches the target being spent against (binds the
// stamp so it can't be replayed against a different resource), and `epoch` is within the caller's
// tolerance window (bounds how long a precomputed stamp stays usable).
//
// TWO `Hpow` OPTIONS (2026-07, "wire Argon2id PoW into AliasDO" pass — R16 progress): docs/03 §8.3
// names both a SHA-256 baseline and an Argon2id-hardened mode; `pow.rs` (packages/vortic-core) has
// implemented Argon2id since the "Argon2id hardened PoW" pass, but this file — the one actually
// gating live requests — only ever accepted `alg === "sha256"` until now (a real, previously-
// disclosed gap: R16's own risk-register row named this file by path as still not wired). SHA-256
// stays plain `crypto.subtle.digest` — a single fast hash, no reason to pay a WASM call for it.
// Argon2id is delegated to REAL WASM (`pow-wasm.ts` -> `pow.rs`'s `pow_verify`, edge-safe, present
// in the `pkg/msg` build profile) — memory-hard hashing isn't reasonable to hand-roll in pure JS.
//
// CALLERS STILL PASS ONE NUMBER, not two: `minBits` is the SHA-256-EQUIVALENT difficulty for the
// action being gated. An Argon2id stamp's actual required bits is derived from it via
// `argonEquivalentBits` — see that function's doc for the real measured cost ratio this is based on
// — so every existing call site (AliasDO's register/resolve/introduce) needed zero changes to gain
// Argon2id support; only a client choosing to mint under the alternate `alg` needed to change.
import { verifyPowStampWasm } from "./pow-wasm";

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

// Real measured relative cost, on this project's own dev machine, not assumed: a live 24-bit SHA-256
// alias-registration mint (workers/messaging's own production stamp grammar) took 9,583,205 tries in
// 11.468s = ~1.197µs/attempt; `pow.rs`'s own timing test measured a single Argon2id(m=4MiB,t=1,p=1)
// call at ~2.6824ms/attempt (native release build — the WASM build this Worker actually runs is
// plausibly somewhat slower again, an honest gap not remeasured in-Worker this pass, same class of
// gap backup.rs's Argon2id docs disclose for its own WASM-vs-native timing). Ratio ≈ 2240x, so for an
// Argon2id stamp to cost an honest client roughly the SAME expected wall-clock time as the SHA-256
// target it's offered as an alternative to, its bit target must be lower by log2(2240) ≈ 11 bits —
// fewer average attempts needed, each one ~2240x more expensive. A derived number, not a guess;
// re-measure and update this constant if the crate's Argon2id params or this file's dispatch cost
// ever change materially.
export const ARGON2ID_BIT_DISCOUNT = 11;

/** The Argon2id-equivalent difficulty for an action whose SHA-256 baseline is `sha256Bits` — see
 * `ARGON2ID_BIT_DISCOUNT`'s doc for the real measurement this is derived from. Clamped to >= 1 so a
 * very low SHA-256 baseline never derives a meaningless-or-negative Argon2id target. */
export function argonEquivalentBits(sha256Bits: number): number {
  return Math.max(1, sha256Bits - ARGON2ID_BIT_DISCOUNT);
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
  if (alg !== "sha256" && alg !== "argon2id") return { ok: false, reason: `unsupported stamp algorithm: ${alg}` };
  if (resource !== expectedResource) return { ok: false, reason: "stamp resource does not match target lookup_key" };

  const epoch = Number(epochStr);
  if (!Number.isInteger(epoch)) return { ok: false, reason: "invalid epoch field" };
  const currentEpoch = Math.floor(Date.now() / EPOCH_MS);
  if (Math.abs(epoch - currentEpoch) > EPOCH_TOLERANCE) {
    return { ok: false, reason: "stamp epoch outside acceptance window" };
  }

  if (alg === "argon2id") {
    const requiredBits = argonEquivalentBits(minBits);
    // pow_verify re-checks version/resource/digest itself (belt-and-suspenders with the checks
    // above, cheap) and never throws on malformed input — see pow-wasm.ts's doc.
    if (!verifyPowStampWasm(stamp, expectedResource, requiredBits)) {
      return { ok: false, reason: `insufficient PoW: argon2id digest below ${requiredBits} leading zero bits` };
    }
    return { ok: true, epoch };
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
