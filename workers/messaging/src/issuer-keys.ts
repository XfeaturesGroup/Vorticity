// The Enrollment Plane's RSABSSA issuer public key(s) — see packages/vortic-core/src/blind_sig.rs
// and docs/03-crypto-core.md §2. THIS IS THE ONLY THING THE MESSAGING PLANE IS ALLOWED TO KNOW ABOUT
// THE ENROLLMENT PLANE: a public key. Not `k`, not any shared HMAC/signing secret, nothing else — see
// this file's callers in index.ts, which never import anything from workers/enrollment or read any
// env var named like a secret. The matching PRIVATE key lives only in workers/enrollment's
// `env.ISSUER_SIGNING_KEY_PEM` (`.dev.vars` locally, `wrangler secret put` in prod) and never reaches
// this Worker in any form.
//
// Public keys are, by definition, safe to commit — there is no secrecy requirement here, unlike
// SESSION_SIGNING_KEY (this Worker's own HMAC key, which IS a secret — see session.ts/.dev.vars).
//
// KEY ROTATION: keyed by `kid` (key id) so a future key rotation can add a new entry here and start
// issuing tokens signed by it, while still accepting redemption of tokens signed under an
// old-but-not-yet-expired `kid` — the same pattern JWKS/JWT key rotation uses. There is only one key
// today (`CURRENT_KID` points at it); the wire doesn't carry a `kid` yet since there's nothing to
// disambiguate, but the lookup-table shape means adding that later doesn't require restructuring this
// file, only adding an entry and threading `kid` through the client<->Worker request body.
export const CURRENT_KID = "issuer-2026-07-v1";

export const ISSUER_KEYS: Record<string, string> = {
  [CURRENT_KID]: `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAx4y5rvt5VbDL9kz+fZP0
jBhxdRjpgu3JEhtFeCHMbd3jrEAl7u7VIEj5QR0UobbVMphbpvMMdIMcHguA4QMY
IjjYwOdpggESo2P52E2/JvWjbK3IZ7qODhe3xp4nT2JbGVqF1R9tj4j8Xmq1/ilh
mVO1Uvfu2uYA+3q5LPCemc9mFlAdnydJrlLi6EDa4W7Z7wZjKtcuu16htmxub6zI
/2V+J+XdFamRp7AkNOP6keGg79oqXdg/FvPUJ+cdLrlza4N2CjZwDHAkX2d2gi2R
Tpynw3qz40xXmcHrDUL045c0DCxdig8SM68lreARfzhlS2F/UCa3uGQHH+Isku5/
nW/SYfcAyOyV725mfJBt8oOypFbQYtHDFVUxM4vt8VtLKw+JNO2oGyuFhXxOIcpo
uszlZjhwLgkCwWq9B/9V6LpEhnEaaQ2FXEsyj3d6SCguZkLyio3vs/nqiVHi2ypU
mzP/yG/mi6k7iPNGzkpLejbGPlUHjfzPg5bwl/bbZeq3AgMBAAE=
-----END PUBLIC KEY-----`,
};

/** The public key this Worker verifies redemption tokens against today. */
export const CURRENT_ISSUER_PK_PEM = ISSUER_KEYS[CURRENT_KID]!;
