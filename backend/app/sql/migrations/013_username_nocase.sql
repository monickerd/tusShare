-- Make username lookups and uniqueness constraints case-insensitive.
-- The old case-sensitive index is replaced with a COLLATE NOCASE unique index.
-- The inline UNIQUE constraint on the column remains but is superseded by the
-- stricter NOCASE index (inserting 'Alice' when 'alice' exists will now fail).

DROP INDEX IF EXISTS idx_users_username;
CREATE UNIQUE INDEX idx_users_username_nocase ON users (username COLLATE NOCASE);
