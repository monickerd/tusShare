-- 006_sharing_v2.sql — Fix short_links schema: add created_by
--
-- The wordlist.py insert helper references a created_by column that was
-- accidentally omitted from the 002_shares.sql definition.  Added here as
-- a nullable FK so existing rows (if any) remain valid.

ALTER TABLE short_links ADD COLUMN created_by TEXT REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX idx_shortlinks_creator ON short_links(created_by);
