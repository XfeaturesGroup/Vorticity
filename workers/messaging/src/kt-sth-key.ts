// KeyTransparencyDO's Signed Tree Head (STH) public key — see sth.ts and docs/06's "Signed Tree
// Head" pass. Closes the residual gap the "Key Transparency consistency proofs" pass's own header
// comment named: a consistency proof authenticates that an older root's CONTENT is a genuine prefix
// of a newer root's content, but never independently authenticated the numeric SIZE label attached to
// that newer root. Real Certificate Transparency binds `(tree_size, root_hash)` together via exactly
// this kind of signature — a mechanism entirely separate from the Merkle-consistency math, which is
// why it lives in its own module rather than being folded into merkleConsistency.ts.
//
// Public keys are, by definition, safe to commit — same reasoning as issuer-keys.ts's
// CURRENT_ISSUER_PK_PEM. The matching PRIVATE key lives only in `env.KT_STH_SIGNING_KEY_PEM`
// (`.dev.vars` locally, `wrangler secret put` in prod) and never appears here.
//
// KEY ROTATION: keyed by `kid`, same lookup-table shape as issuer-keys.ts, for the same reason — a
// future rotation adds a new entry and starts signing under it while old-but-not-yet-expired STHs
// signed under a prior `kid` can still be looked up and verified.
export const CURRENT_KT_STH_KID = "kt-sth-2026-07-v1";

export const KT_STH_KEYS: Record<string, string> = {
  [CURRENT_KT_STH_KID]: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEArMp4wlHNj1w31e+Pw58cB5WonwTRBjiAGX2XRT/3Qp8=
-----END PUBLIC KEY-----`,
};

/** The public key this pass verifies Signed Tree Heads against today. */
export const CURRENT_KT_STH_PK_PEM = KT_STH_KEYS[CURRENT_KT_STH_KID]!;
