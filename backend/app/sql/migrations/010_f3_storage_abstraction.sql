-- 010_f3_storage_abstraction.sql — Phase F3: Storage abstraction layer
--
-- Changes:
--   • storage_volumes: named provider backends (local, s3, azure, gcs, b2)
--   • file_storage_locations: many-to-many files↔volumes (replicas, mirrors,
--     tiering); replaces the implicit single-volume assumption
--   • files: last_accessed_at for tiering age decisions
--   • tus_uploads: part_tags for provider-native multipart etag tracking
--   • Seed: default local volume + backfill all existing files

-------------------------------------------------
-- STORAGE VOLUMES
-- config_enc: AES-GCM encrypted JSON for provider credentials
--   local  → {"files_dir": "...", "uploads_dir": "..."}
--   s3     → {"endpoint_url": "...", "bucket": "...",
--              "access_key_id": "...", "secret_access_key": "...", "region": "..."}
-- tier: hot = primary/fast, warm = nearline, cold = archive/cheap
-- priority: read preference among replicas for a given file (lower = preferred)
-- is_default: exactly one volume should have is_default=1; used for new uploads
-------------------------------------------------
CREATE TABLE storage_volumes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    provider    TEXT NOT NULL CHECK (provider IN ('local', 's3', 'azure', 'gcs', 'b2')),
    config_enc  TEXT,
    tier        TEXT NOT NULL DEFAULT 'hot' CHECK (tier IN ('hot', 'warm', 'cold')),
    is_default  INTEGER NOT NULL DEFAULT 0,
    priority    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_storage_volumes_default ON storage_volumes(is_default);

-------------------------------------------------
-- FILE STORAGE LOCATIONS
-- One row per (file, volume) pair. A file with two mirror volumes has two rows.
-- is_primary: 1 for the authoritative write target; 0 for async replicas.
-- migration_state:
--   idle      = stored and verified
--   migrating = copy in progress (tier move or initial async replica)
--   failed    = last migration attempt failed; reconciliation will retry
-- migration_started_at: set when migration_state transitions to 'migrating';
--   used to detect stalled migrations (anything migrating for >1h is suspect).
-------------------------------------------------
CREATE TABLE file_storage_locations (
    file_id              TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    volume_id            TEXT NOT NULL REFERENCES storage_volumes(id),
    is_primary           INTEGER NOT NULL DEFAULT 1,
    migration_state      TEXT NOT NULL DEFAULT 'idle'
                             CHECK (migration_state IN ('idle', 'migrating', 'failed')),
    migration_started_at TIMESTAMPTZ,
    stored_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified        TIMESTAMPTZ,
    PRIMARY KEY (file_id, volume_id)
);

CREATE INDEX idx_fsl_volume          ON file_storage_locations(volume_id);
CREATE INDEX idx_fsl_migration_state ON file_storage_locations(migration_state)
    WHERE migration_state != 'idle';

-------------------------------------------------
-- EXTEND files
-- last_accessed_at: updated on every successful download.
--   NULL = never downloaded (or pre-F3 row not yet touched).
--   Used by the StorageManager tiering background task.
-------------------------------------------------
ALTER TABLE files ADD COLUMN last_accessed_at TIMESTAMPTZ DEFAULT NULL;

-------------------------------------------------
-- EXTEND tus_uploads
-- part_tags: JSON array of provider etags, one per completed part.
--   Required for S3-compatible multipart finalization
--   (CompleteMultipartUpload requires the ordered etag list).
--   NULL for local-provider uploads which don't use multipart.
-------------------------------------------------
ALTER TABLE tus_uploads ADD COLUMN part_tags TEXT DEFAULT NULL;

-------------------------------------------------
-- SEED: default local volume
-- Uses the well-known ID 'local-default' so the application can reference it
-- at startup before any admin configuration has been applied.
-------------------------------------------------
INSERT INTO storage_volumes (id, name, provider, tier, is_default, priority)
VALUES ('local-default', 'Local (default)', 'local', 'hot', 1, 0)
ON CONFLICT (id) DO NOTHING;

-------------------------------------------------
-- BACKFILL: register all existing files on the default local volume
-- All pre-F3 files are assumed to live on the local filesystem.
-------------------------------------------------
INSERT INTO file_storage_locations (file_id, volume_id, is_primary, migration_state, stored_at)
SELECT id, 'local-default', 1, 'idle', created_at
FROM   files
ON CONFLICT (file_id, volume_id) DO NOTHING;

-------------------------------------------------
-- ADMIN SETTINGS SEEDS (tiering policy defaults — all disabled)
-------------------------------------------------
INSERT INTO admin_settings (key, value) VALUES ('storage_tiering_enabled',     '0') ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_hot_to_warm_days',    '')  ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_warm_to_cold_days',   '')  ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_warm_volume_id',      '')  ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_cold_volume_id',      '')  ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_auto_warm_on_read',   '0') ON CONFLICT (key) DO NOTHING;
