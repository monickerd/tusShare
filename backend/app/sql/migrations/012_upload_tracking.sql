-- Track when each upload last received a chunk.
--
-- updated_at is set on every successful PATCH. expires_at is now a sliding
-- window reset on each chunk, so an actively-uploading large file will never
-- be swept by the cleanup task. A truly abandoned upload expires
-- TUS_UPLOAD_EXPIRY_HOURS after its last chunk arrived.
--
-- Existing rows inherit created_at so they are not immediately expired.

ALTER TABLE tus_uploads ADD COLUMN updated_at TEXT;

UPDATE tus_uploads SET updated_at = created_at;
