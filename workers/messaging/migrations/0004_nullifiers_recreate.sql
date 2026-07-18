-- Migration 0004: Recreate nullifiers table to match DO schema
-- The original table had `external_nullifier`, `nullifier_hash`, `epoch` which were from a pre-implementation design.
-- Semaphore v4 nullifier = Poseidon2(scope, secret) inherently encodes the epoch/scope, so the canonical shape
-- is simply the nullifier hash and the spend timestamp.

DROP TABLE IF EXISTS nullifiers;

CREATE TABLE nullifiers (
  nullifier TEXT PRIMARY KEY,
  spent_at  INTEGER NOT NULL
);
