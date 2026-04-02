-- 002_files_folders.sql — File storage: folders, files, chunks, permissions, uploads

-------------------------------------------------
-- FOLDERS
-------------------------------------------------
CREATE TABLE folders (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
    parent_id   TEXT REFERENCES folders(id) ON DELETE CASCADE,
    owner_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_shared   INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_folders_parent ON folders(parent_id);
CREATE INDEX idx_folders_owner  ON folders(owner_id);
CREATE UNIQUE INDEX idx_folders_unique_name ON folders(parent_id, owner_id, name);

-------------------------------------------------
-- FILES
-------------------------------------------------
CREATE TABLE files (
    id                  TEXT PRIMARY KEY,
    original_name       TEXT NOT NULL,
    sanitized_name      TEXT NOT NULL,
    storage_key         TEXT NOT NULL UNIQUE,
    folder_id           TEXT REFERENCES folders(id) ON DELETE SET NULL,
    owner_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mime_type           TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes          BIGINT NOT NULL DEFAULT 0,
    encrypted_size      BIGINT NOT NULL DEFAULT 0,
    chunk_size          BIGINT NOT NULL DEFAULT 5242880,
    total_chunks        INTEGER NOT NULL DEFAULT 0,
    encrypted_file_key  TEXT NOT NULL,
    key_iv              TEXT NOT NULL,
    checksum_sha256     TEXT,
    upload_complete     INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_files_folder      ON files(folder_id);
CREATE INDEX idx_files_owner       ON files(owner_id);
CREATE INDEX idx_files_storage_key ON files(storage_key);

-------------------------------------------------
-- FILE CHUNKS (per-chunk IVs for streaming decryption)
-------------------------------------------------
CREATE TABLE file_chunks (
    id          TEXT PRIMARY KEY,
    file_id     TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    iv          TEXT NOT NULL,
    size_bytes  BIGINT NOT NULL,
    "offset"    BIGINT NOT NULL,
    UNIQUE(file_id, chunk_index)
);

CREATE INDEX idx_chunks_file ON file_chunks(file_id);

-------------------------------------------------
-- PERMISSIONS
-------------------------------------------------
CREATE TABLE permissions (
    id            TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id   TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission    TEXT NOT NULL CHECK(permission IN ('read', 'write', 'admin')),
    recursive     INTEGER NOT NULL DEFAULT 0,
    granted_by    TEXT NOT NULL REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_perm_resource ON permissions(resource_type, resource_id);
CREATE INDEX idx_perm_user     ON permissions(user_id);
CREATE UNIQUE INDEX idx_perm_unique ON permissions(resource_type, resource_id, user_id);

-------------------------------------------------
-- TUS UPLOADS (in-progress chunked uploads)
-- updated_at tracks the last chunk received so actively-uploading files
-- never expire, while stalled uploads can be cleaned up.
-------------------------------------------------
CREATE TABLE tus_uploads (
    id              TEXT PRIMARY KEY,
    file_id         TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    total_size      BIGINT NOT NULL,
    current_offset  BIGINT NOT NULL DEFAULT 0,
    next_chunk      INTEGER NOT NULL DEFAULT 0,
    metadata_json   TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tus_user    ON tus_uploads(user_id);
CREATE INDEX idx_tus_expires ON tus_uploads(expires_at);
