-- 004_key_wrapping.sql — E2E encryption key wrapping model
--
-- Decouples the masterKey from the user's password so that password
-- changes don't invalidate encrypted files.
--
-- wrapped_master_key:    masterKey encrypted (wrapped) under the
--                        password-derived KEK (AES-256-GCM).
-- wrapped_master_key_iv: IV used for the KEK→masterKey wrapping.
-- recovery_key_wrapped:  masterKey wrapped under a one-time recovery key.
-- recovery_key_iv:       IV for the recovery key wrapping.
-- recovery_key_hash:     SHA-256 hash of the raw recovery key (for
--                        server-side verification before attempting unwrap).

ALTER TABLE users ADD COLUMN wrapped_master_key     TEXT;
ALTER TABLE users ADD COLUMN wrapped_master_key_iv  TEXT;
ALTER TABLE users ADD COLUMN recovery_key_wrapped   TEXT;
ALTER TABLE users ADD COLUMN recovery_key_iv        TEXT;
ALTER TABLE users ADD COLUMN recovery_key_hash      TEXT;
