-- DB_MSG — durable mirror of the Messaging Plane's Durable Object state. See
-- docs/04-serverless-architecture.md "D1 schema (zero PII)". No column in this file may hold
-- PII or a cross-plane join key back to DB_ENROLL — enforced by scripts/schema-lint.mjs.

CREATE TABLE merkle_nodes (
  group_id TEXT NOT NULL,
  idx      INTEGER NOT NULL,
  level    INTEGER NOT NULL,
  hash     TEXT NOT NULL,
  PRIMARY KEY (group_id, level, idx)
);

CREATE TABLE group_roots (
  group_id   TEXT NOT NULL,
  root       TEXT NOT NULL,
  epoch      INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, epoch)
);

CREATE TABLE nullifiers (
  external_nullifier TEXT NOT NULL,
  nullifier_hash     TEXT NOT NULL,
  epoch              INTEGER NOT NULL,
  PRIMARY KEY (external_nullifier, nullifier_hash)
);

CREATE TABLE queues (
  queue_id   TEXT PRIMARY KEY,   -- rotating opaque 128-bit id
  created_at INTEGER NOT NULL,
  rotates_at INTEGER NOT NULL
);

CREATE TABLE queue_messages (
  queue_id    TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  ciphertext  BLOB NOT NULL,
  size_bucket INTEGER NOT NULL,
  enqueued_at INTEGER NOT NULL,
  ttl         INTEGER NOT NULL,
  PRIMARY KEY (queue_id, seq)
);

CREATE TABLE prekeys (
  bundle_id TEXT PRIMARY KEY,
  bundle    BLOB NOT NULL,
  kind      TEXT NOT NULL,
  consumed  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE conv_log (
  conv_id     TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  blob        BLOB NOT NULL,
  enqueued_at INTEGER NOT NULL,
  PRIMARY KEY (conv_id, seq)
);

CREATE TABLE blobs_meta (
  blob_id     TEXT PRIMARY KEY,
  size_bucket INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  ttl         INTEGER NOT NULL
);

-- Opt-in public @alias records (docs/03 §8, docs/05 K13). Keyed by hash; value is AEAD
-- ciphertext only derivable by someone who already knows the nickname. A plaintext `nickname`
-- column here is exactly what schema-lint's forbidden-column check rejects.
CREATE TABLE aliases (
  lookup_key       TEXT PRIMARY KEY,  -- H("vortic-alias-v1" || nickname)
  record           BLOB NOT NULL,     -- AEAD(HKDF(nickname), {intro_queue_id, alias_pub, flags, pow_bits})
  alias_pub        TEXT NOT NULL,
  pow_bits         INTEGER NOT NULL,
  registered_epoch INTEGER NOT NULL
);

CREATE TABLE pow_stamps (
  stamp_hash TEXT NOT NULL,
  epoch      INTEGER NOT NULL,
  kind       TEXT NOT NULL,  -- 'resolve' | 'write' | 'register'
  PRIMARY KEY (stamp_hash, epoch)
);
