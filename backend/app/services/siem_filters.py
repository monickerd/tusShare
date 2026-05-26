"""SIEM event filter profiles.

Each SIEM destination carries a filter_profile that controls which events are
forwarded to it.  The internal event bus and security_events DB table always
capture everything; filtering is applied only at the per-destination forwarding
layer so the pull API and SSE stream are never affected.

Profiles
--------
high_security  All events, all severities.  For SOC SIEMs that want full
               telemetry including file downloads, uploads, and shares.
recommended    Auth, admin, policy/role changes, and destructive file ops.
               Good default for most compliance and monitoring use cases.
relaxed        Critical-severity events only — lockouts, emergency revocations,
               and major auth failures.
custom         Admin-supplied JSON: {"event_type_globs": [...], "min_severity": "info"}
               Glob patterns follow fnmatch syntax (e.g. "auth.*", "file.*").
"""

from __future__ import annotations

import fnmatch
import json
import logging

from app.schemas.security_event import SecurityEvent

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

PROFILE_PRESETS: dict[str, dict] = {
    "high_security": {
        "label": "High Security",
        "description": "All events including file downloads, uploads, and shares.",
        "event_type_globs": ["*"],
        "min_severity": "info",
    },
    "recommended": {
        "label": "Recommended",
        "description": "Auth, admin actions, policy/role changes, and destructive file ops.",
        "event_type_globs": [
            "auth.*",
            "admin.*",
            "policy.*",
            "file.delete",
            "file.move",
            "share.*",
            "team.*",
        ],
        "min_severity": "info",
    },
    "relaxed": {
        "label": "Relaxed",
        "description": "Critical severity only — lockouts, emergency revocations, auth failures.",
        "event_type_globs": ["*"],
        "min_severity": "critical",
    },
}

# Exported for the admin API to surface preset metadata to the UI.
PROFILE_META: list[dict] = [
    {
        "id": profile_id,
        "label": meta["label"],
        "description": meta["description"],
        "globs": meta["event_type_globs"],
        "min_severity": meta["min_severity"],
    }
    for profile_id, meta in PROFILE_PRESETS.items()
] + [
    {
        "id": "custom",
        "label": "Custom",
        "description": "Define your own event type glob patterns and minimum severity.",
        "globs": None,
        "min_severity": None,
    }
]


def _severity_gte(sev: str, minimum: str) -> bool:
    return _SEVERITY_ORDER.get(sev, 0) >= _SEVERITY_ORDER.get(minimum, 0)


def _parse_custom(raw: str | None) -> tuple[list[str], str]:
    """Parse filter_custom_json. Returns (globs, min_severity) with safe defaults."""
    try:
        config = json.loads(raw or "")
    except (ValueError, TypeError):
        return ["*"], "info"
    globs = config.get("event_type_globs")
    if not isinstance(globs, list) or not globs:
        globs = ["*"]
    min_sev = config.get("min_severity", "info")
    if min_sev not in _SEVERITY_ORDER:
        min_sev = "info"
    return globs, min_sev


def matches_destination_filter(dest: dict, event: SecurityEvent) -> bool:
    """Return True if *event* should be forwarded to this SIEM destination."""
    profile = dest.get("filter_profile") or "recommended"

    if profile == "custom":
        globs, min_sev = _parse_custom(dest.get("filter_custom_json"))
    else:
        preset = PROFILE_PRESETS.get(profile)
        if preset is None:
            logger.warning("siem_filters: unknown profile %r, defaulting to recommended", profile)
            preset = PROFILE_PRESETS["recommended"]
        globs = preset["event_type_globs"]
        min_sev = preset["min_severity"]

    if not _severity_gte(event.severity, min_sev):
        return False
    return any(fnmatch.fnmatch(event.event_type, g) for g in globs)
