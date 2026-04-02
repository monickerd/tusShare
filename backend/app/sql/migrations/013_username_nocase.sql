-- 013_username_nocase.sql — Username case-insensitivity.
--
-- In PostgreSQL this is a no-op: the username column is already CITEXT (set in
-- 001_initial.sql), which provides case-insensitive storage and comparison at
-- the column level without any additional index or collation.
-- The migration is recorded so the migration runner does not error on existing
-- SQLite-originated migration history.
SELECT 1;
