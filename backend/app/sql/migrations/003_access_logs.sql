-- 003_access_logs.sql — Access logging, admin settings, bandwidth tracking

-------------------------------------------------
-- ACCESS LOGS
-------------------------------------------------
CREATE TABLE access_logs (
    id          TEXT PRIMARY KEY,
    file_id     TEXT,
    user_id     TEXT,
    share_id    TEXT,
    ip_address  TEXT NOT NULL,
    user_agent  TEXT,
    action      TEXT NOT NULL CHECK(action IN ('view', 'download', 'upload', 'delete', 'share')),
    timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_alog_file      ON access_logs(file_id);
CREATE INDEX idx_alog_user      ON access_logs(user_id);
CREATE INDEX idx_alog_share     ON access_logs(share_id);
CREATE INDEX idx_alog_timestamp ON access_logs(timestamp);

-------------------------------------------------
-- ADMIN SETTINGS (key-value store)
-------------------------------------------------
CREATE TABLE admin_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO admin_settings (key, value) VALUES
    ('open_registration',      'false'),
    ('global_max_file_size',   '10737418240'),
    ('global_bandwidth_limit', '0'),
    ('disk_warning_threshold', '90'),
    ('default_chunk_size',     '5242880');

-------------------------------------------------
-- BANDWIDTH LOG
-------------------------------------------------
CREATE TABLE bandwidth_log (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    bytes       INTEGER NOT NULL,
    direction   TEXT NOT NULL CHECK(direction IN ('upload', 'download')),
    timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_bwlog_user      ON bandwidth_log(user_id);
CREATE INDEX idx_bwlog_timestamp ON bandwidth_log(timestamp);
