export interface Env {
  DB_MSG: D1Database;
  MEDIA: R2Bucket;
  MERKLE_TREE_DO: DurableObjectNamespace;
  QUEUE_DO: DurableObjectNamespace;
  GROUP_DO: DurableObjectNamespace;
  CONV_LOG_DO: DurableObjectNamespace;
  PRESENCE_DO: DurableObjectNamespace;
  ALIAS_DO: DurableObjectNamespace;
  RATE_GATE_DO: DurableObjectNamespace;
  /** 32-byte HMAC key (hex) for signing session capabilities issued by /auth/session. Local dev uses
   * a demo value in wrangler.toml [vars]; prod sets it via `wrangler secret put SESSION_SIGNING_KEY`. */
  SESSION_SIGNING_KEY: string;
}
