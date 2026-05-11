-- Migration 015 — Add last_modified_ms to files table
--
-- Stores the browser File.lastModified timestamp (ms since epoch) supplied
-- by the client at upload time.  Used by the client-side conflict modal to
-- detect whether a newly uploaded file is identical to an existing one
-- (same size AND same lastModified → treat as identical copy).
--
-- NULL for files uploaded before this migration ships (safe fallback:
-- the client treats NULL as "different" and shows the full comparison modal).

ALTER TABLE files ADD COLUMN last_modified_ms INTEGER;
