-- 012_upload_tracking.sql — Track when each upload last received a chunk.
--
-- updated_at is set on every successful PATCH. expires_at is a sliding
-- window reset on each chunk, so actively-uploading large files never expire.

ALTER TABLE tus_uploads ADD COLUMN updated_at TIMESTAMPTZ;

UPDATE tus_uploads SET updated_at = created_at;
