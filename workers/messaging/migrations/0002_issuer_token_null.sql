-- Plane Bridge (RSABSSA, 2026-07): the redemption-token replay guard, correctly placed in DB_MSG
-- this time — see workers/enrollment/migrations/0002_drop_spent_tokens.sql for the bug this fixes
-- (the same table used to live in DB_ENROLL as `spent_tokens`, contradicting docs/04 Flow 1's own
-- diagram, which has always shown this check happening in the Messaging plane).
--
-- `token_null` = SHA-256(msg) where `msg` is the RSABSSA-signed redemption message (see
-- packages/vortic-core/src/blind_sig.rs, workers/messaging/src/durable-objects/MerkleTreeDO.ts). It
-- is NOT derived from or linkable to the enrolling account's PPID, the Semaphore commitment, or any
-- other identity residue — it is opaque, matching docs/02's "Opaque routing IDs" data class.
--
-- NOTE: MerkleTreeDO is the authoritative, live enforcement point for this table today (its own
-- local SQLite mirrors this exact shape) — same as the pre-existing `commitments`/`nullifiers`
-- tables, which were never actually mirrored to this D1 database either. This migration documents
-- the schema (so schema-lint scans it and the docs/code stay in sync) rather than claiming a D1
-- mirror is wired; see MerkleTreeDO.ts's header comment for the honest scope note.
CREATE TABLE issuer_token_null (
  token_null TEXT PRIMARY KEY,
  spent_at   INTEGER NOT NULL
);
