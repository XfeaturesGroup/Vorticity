-- Single-use spend set for enrollment tickets (ticket.ts). Keyed by the ticket's own `jti`, NOT by
-- ppid — mirrors spent_tokens/nullifiers' own "key by the token's identifier, not the account"
-- convention elsewhere in this project, so a spent ticket can't be joined back to a specific ppid
-- by anyone reading this table alone (the ppid still lives in the ticket's signed payload, which
-- never touches D1 — only the jti is ever persisted here).
CREATE TABLE spent_enroll_tickets (
  jti       TEXT PRIMARY KEY,
  spent_at  INTEGER NOT NULL
);
