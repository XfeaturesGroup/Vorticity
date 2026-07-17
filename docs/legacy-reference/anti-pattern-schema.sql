-- Extracted from the deleted legacy backend/schema.sql — kept ONLY as a labelled anti-pattern.
-- DO NOT reuse any of this. It is the exact linkage graph docs/02 (threat model) forbids:
-- Users.email is stored directly, and Sessions/Posts/Chats/Messages/Friends/UserKeys all carry
-- a plaintext user_id FK straight back to that email row. This is precisely what "DB_MSG must
-- have zero PII and zero join-key back to DB_ENROLL" (docs/04) exists to prevent.
--
-- Kept for one purpose: it makes a ready-made negative test fixture for the `schema-lint` CI
-- check (docs/06 Phase 0 exit gate — "CI blocks a deliberately-planted email column"). See
-- scripts/schema-lint.mjs's test fixtures.

CREATE TABLE Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT,
    email TEXT UNIQUE,                  -- ← forbidden column, forbidden table shape
    bio TEXT,
    avatar_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,           -- ← forbidden: session linkable to the email row above
    token TEXT UNIQUE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);

CREATE TABLE Messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,         -- ← forbidden: message content linkable to identity
    content TEXT NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES Users(id) ON DELETE CASCADE
);

-- (Posts/Likes/Comments/Friends/Chats/UserKeys/PostViews omitted — same shape, same problem:
--  every table's identity anchor is Users.id, one hop from Users.email.)
