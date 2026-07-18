-- Migration 0003: Mirror commitments table from MerkleTreeDO
CREATE TABLE IF NOT EXISTS commitments (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  commitment TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL
);
