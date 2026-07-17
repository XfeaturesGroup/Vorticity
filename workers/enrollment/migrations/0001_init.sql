-- DB_ENROLL — see docs/04-serverless-architecture.md "D1 schema (zero PII)".
-- The only identity residue permitted anywhere in Vorticity lives in THIS table, as a one-way
-- HMAC. No email column may ever be added here or anywhere else in the system — enforced by
-- scripts/schema-lint.mjs, which fails CI on sight of one.

CREATE TABLE enroll_ppid (
  ppid          TEXT PRIMARY KEY,        -- HMAC(secret, oauth_sub); irreversible
  enroll_count  INTEGER NOT NULL DEFAULT 0,
  last_epoch    INTEGER NOT NULL,
  created_at    INTEGER NOT NULL
);

-- Spent blind tokens, keyed by the token's own nullifier hash — NOT by ppid, so a redeemed
-- token cannot be joined back to the account that produced it.
CREATE TABLE spent_tokens (
  token_null    TEXT PRIMARY KEY,
  spent_at      INTEGER NOT NULL
);
