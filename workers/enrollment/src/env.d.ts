export interface Env {
  DB_ENROLL: D1Database;
  /** API host — token exchange + userinfo. NOT the browser authorize host (see wrangler.toml). */
  IDM_API_URL: string;
  OAUTH_CLIENT_ID: string;
  OAUTH_REDIRECT_URI: string;
  /** Set via `wrangler secret put OAUTH_CLIENT_SECRET` — never committed. */
  OAUTH_CLIENT_SECRET: string;
  /** Set via `wrangler secret put PPID_HMAC_SECRET` — never committed, never rotated casually
   * (rotating it invalidates every existing PPID's sybil-guard history). */
  PPID_HMAC_SECRET: string;
  /** RSA-3072 PRIVATE key (PKCS#8 PEM) for the RSABSSA Plane Bridge issuer — see
   * packages/vortic-core/src/blind_sig.rs. Local dev: `.dev.vars` (gitignored, see
   * `.dev.vars.example`). Prod: `wrangler secret put ISSUER_SIGNING_KEY_PEM`. NEVER in
   * wrangler.toml [vars] — this is the entire bridge's secret. The matching PUBLIC key is hardcoded
   * (not secret) in workers/messaging/src/issuer-keys.ts; Messaging never sees this value. */
  ISSUER_SIGNING_KEY_PEM: string;
  /** HMAC-SHA256 key (hex) for the enrollment ticket (ticket.ts) — proves /oauth/callback's OAuth
   * exchange + quota check actually ran before /token/issue will blind-sign anything. Set via
   * `wrangler secret put ENROLL_TICKET_SIGNING_KEY`; local dev in `.dev.vars`. Independent of
   * PPID_HMAC_SECRET (different purpose: this signs a bearer-style ticket, that hashes an identity)
   * and of messaging's SESSION_SIGNING_KEY (different plane). NEVER in wrangler.toml [vars]. */
  ENROLL_TICKET_SIGNING_KEY: string;
}
