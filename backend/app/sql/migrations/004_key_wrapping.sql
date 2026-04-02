-- 004_key_wrapping.sql — E2E encryption key wrapping model
--
-- Decouples the masterKey from the user's password so that password
-- changes don't invalidate encrypted files.

ALTER TABLE users ADD COLUMN wrapped_master_key     TEXT;
ALTER TABLE users ADD COLUMN wrapped_master_key_iv  TEXT;
ALTER TABLE users ADD COLUMN recovery_key_wrapped   TEXT;
ALTER TABLE users ADD COLUMN recovery_key_iv        TEXT;
ALTER TABLE users ADD COLUMN recovery_key_hash      TEXT;
