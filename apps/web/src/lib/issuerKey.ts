// The Enrollment Plane's RSABSSA issuer PUBLIC key (RFC 9474, see packages/vortic-core/src/
// blind_sig.rs). Public by design — safe to ship in the client bundle, same value as the constant
// workers/messaging/src/issuer-keys.ts hardcodes (kid "issuer-2026-07-v1"). The client blinds
// against this key; only the Enrollment Worker holds the matching PRIVATE key
// (env.ISSUER_SIGNING_KEY_PEM), which never reaches this codebase or the Messaging Plane.
export const ISSUER_KID = "issuer-2026-07-v1";

export const ISSUER_PK_PEM = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAx4y5rvt5VbDL9kz+fZP0
jBhxdRjpgu3JEhtFeCHMbd3jrEAl7u7VIEj5QR0UobbVMphbpvMMdIMcHguA4QMY
IjjYwOdpggESo2P52E2/JvWjbK3IZ7qODhe3xp4nT2JbGVqF1R9tj4j8Xmq1/ilh
mVO1Uvfu2uYA+3q5LPCemc9mFlAdnydJrlLi6EDa4W7Z7wZjKtcuu16htmxub6zI
/2V+J+XdFamRp7AkNOP6keGg79oqXdg/FvPUJ+cdLrlza4N2CjZwDHAkX2d2gi2R
Tpynw3qz40xXmcHrDUL045c0DCxdig8SM68lreARfzhlS2F/UCa3uGQHH+Isku5/
nW/SYfcAyOyV725mfJBt8oOypFbQYtHDFVUxM4vt8VtLKw+JNO2oGyuFhXxOIcpo
uszlZjhwLgkCwWq9B/9V6LpEhnEaaQ2FXEsyj3d6SCguZkLyio3vs/nqiVHi2ypU
mzP/yG/mi6k7iPNGzkpLejbGPlUHjfzPg5bwl/bbZeq3AgMBAAE=
-----END PUBLIC KEY-----`;
