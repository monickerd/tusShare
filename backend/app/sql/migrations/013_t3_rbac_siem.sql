-- 013_t3_rbac_siem.sql — T3 security fixes + SIEM event filter profiles
--
-- Changes:
--   • siem_destinations: add filter_profile + filter_custom_json columns
--     Existing destinations default to 'recommended' (preserves prior behavior
--     of forwarding all events, since no filtering existed before).

ALTER TABLE siem_destinations
    ADD COLUMN filter_profile TEXT NOT NULL DEFAULT 'recommended'
        CHECK (filter_profile IN ('high_security', 'recommended', 'relaxed', 'custom'));

-- JSON blob for 'custom' profile: {"event_type_globs": [...], "min_severity": "info"}
ALTER TABLE siem_destinations
    ADD COLUMN filter_custom_json TEXT;
