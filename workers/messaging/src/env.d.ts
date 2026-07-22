export interface Env {
  DB_MSG: D1Database;
  MEDIA: R2Bucket;
  MERKLE_TREE_DO: DurableObjectNamespace;
  QUEUE_DO: DurableObjectNamespace;
  GROUP_DO: DurableObjectNamespace;
  CONV_LOG_DO: DurableObjectNamespace;
  PRESENCE_DO: DurableObjectNamespace;
  PREKEY_DO: DurableObjectNamespace;
  DEVICE_LINK_DO: DurableObjectNamespace;
  DEVICE_LEASE_DO: DurableObjectNamespace;
  ALIAS_DO: DurableObjectNamespace;
  RATE_GATE_DO: DurableObjectNamespace;
  KEY_TRANSPARENCY_DO: DurableObjectNamespace;
  /** 32-byte HMAC key (hex) for signing session capabilities issued by /auth/session. Local dev uses
   * a demo value in wrangler.toml [vars]; prod sets it via `wrangler secret put SESSION_SIGNING_KEY`. */
  SESSION_SIGNING_KEY: string;
  /** 32-byte seed (hex) this Worker's OHTTP Gateway role derives its HPKE (X25519) keypair from — see
   * ohttp-gateway.ts / GET /ohttp/keys. Local dev: `.dev.vars`; prod: `wrangler secret put`. */
  OHTTP_GATEWAY_SEED: string;
  /** Ed25519 PKCS8 PEM — KeyTransparencyDO's Signed Tree Head signing key (see sth.ts). The matching
   * PUBLIC key is committed in src/kt-sth-key.ts (safe to commit; this private half is not). Local
   * dev: `.dev.vars`; prod: `wrangler secret put`. */
  KT_STH_SIGNING_KEY_PEM: string;
}
