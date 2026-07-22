// Public key for R18's reserved/verified namespace authority — see
// workers/messaging/scripts/namespace-authority.mts's header comment for the full design and
// AliasDO.ts's reserve/register handlers for how it's used. Public keys are, by definition, safe to
// commit — same reasoning as issuer-keys.ts's CURRENT_ISSUER_PK_PEM / kt-sth-key.ts's
// CURRENT_KT_STH_PK_PEM. Unlike those two, there is deliberately NO matching private-key entry
// anywhere in this Worker's env (`.dev.vars`, `wrangler secret put`, etc.): the authority signs
// reservations and registrant authorizations OFFLINE, rarely, on an operator's own machine via
// `namespace-authority.mts` — it never signs live per-request, so there is no live secret for this
// Worker to hold in the first place.
//
// Encoded as raw 32-byte hex (NOT PEM) — matches `alias_pub`'s own on-the-wire convention and the
// `alias_verify_action`/`verifyAliasOwnership` WASM boundary's expected input shape directly, unlike
// the STH/issuer keys (which go through `node:crypto`'s PEM-based Ed25519/RSA APIs instead).
//
// KEY ROTATION: keyed by `kid`, same lookup-table shape as issuer-keys.ts/kt-sth-key.ts — a future
// rotation adds a new entry and starts granting reservations under it while namespaces already
// reserved/authorized under a prior `kid` keep verifying against that entry (this Worker checks a
// reservation/authorization against ALL known keys, not just the current one — see AliasDO.ts).
export const CURRENT_NAMESPACE_AUTHORITY_KID = "ns-authority-2026-07-v1";

export const NAMESPACE_AUTHORITY_KEYS: Record<string, string> = {
  [CURRENT_NAMESPACE_AUTHORITY_KID]: "6882baaffbf73083c786b0be1f9d058d3cf03bf4ea2849fabb9949df2fcc0b32",
};

/** All known authority public keys, as raw bytes, for verifying against any not-yet-rotated-out key. */
export function namespaceAuthorityPubkeys(): Uint8Array[] {
  return Object.values(NAMESPACE_AUTHORITY_KEYS).map((hex) => new Uint8Array(Buffer.from(hex, "hex")));
}
