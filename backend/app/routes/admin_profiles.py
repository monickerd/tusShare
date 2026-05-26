"""Security profile routes.

Manages built-in security profiles, export/import, and first-run wizard state.

Endpoints:
  GET  /admin/settings/profiles       — list built-in profiles (no step-up)
  GET  /admin/settings/export         — download current settings as JSON attachment
  POST /admin/settings/apply-profile  — apply a built-in profile (replace or merge)
  POST /admin/settings/import         — import a profile JSON (replace or merge)

All mutation/export endpoints require server_admin (role tier ≤ 1) + step-up.
Step-up action key: admin.settings.security.*
"""

from __future__ import annotations

import json as _json
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

import app.sensitive_config as sensitive_config
from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.auth.stepup import verify_step_up_token
from app.database import Database, get_db
from app.middleware.stepup import require_step_up
from app.models.role import admin_best_tier
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import event_bus
from app.util.db import get_admin_setting

router = APIRouter()

_STEPUP_ACTION = "admin.settings.security.*"
_ERR_MODE_REPLACE_OR_MERGE = "mode must be 'replace' or 'merge'"

# ---------------------------------------------------------------------------
# Built-in profile definitions
# ---------------------------------------------------------------------------

_PROFILES: dict[str, dict] = {
    "high_security": {
        "name": "High Security",
        "description": (
            "Mandatory escrow coverage; link shares and folder shares blocked; "
            "all security settings locked at tier 1 (server_admin only)."
        ),
        "admin_settings": {
            "escrow_require_coverage": {"value": "1", "is_locked": True, "locked_min_tier": 1},
            "notify_escrow_on_revocation": {"value": "1", "is_locked": True, "locked_min_tier": 1},
            # Cap link share expiry at 30 days even though link shares are blocked by
            # role flags and the sharing rule below — belt-and-suspenders.
            "link_share_max_expiry_days": {"value": "30", "is_locked": True, "locked_min_tier": 1},
        },
        "role_flag_overrides": {
            "role_user": {
                "shares_link_create": {"value": "0", "is_locked": True, "locked_min_tier": 1},
                "shares_user_create": {"value": "1", "is_locked": True, "locked_min_tier": 1},
                # upload_grant requires shares_link_create; keep consistent with the '0' above
                "shares_upload_grant_create": {"value": "0", "is_locked": True, "locked_min_tier": 1},
                "shares_folder_create": {"value": "0", "is_locked": True, "locked_min_tier": 1},
            },
        },
        "sharing_rules": [
            {
                "name": "Block link shares (high security)",
                "description": "Belt-and-suspenders: deny link share creation regardless of role flags.",
                "is_active": True,
                "priority": 1,
                "subject": "sender",
                "applies_to_share_type": "link",
                "effect": "deny",
                "is_locked": True,
                "locked_min_tier": 1,
                "conditions": [
                    {
                        "attribute_path": "internal.username",
                        "operator": "matches_re",
                        "value": ".*",
                        "block_on_missing_attribute": False,
                    }
                ],
            }
        ],
    },
    "recommended": {
        "name": "Recommended",
        "description": (
            "Sensible defaults for most deployments. All sharing enabled; "
            "escrow encouraged but not enforced; settings locked at tier 2 (org_admin)."
        ),
        "admin_settings": {
            "escrow_require_coverage": {"value": "0", "is_locked": True, "locked_min_tier": 2},
            "notify_escrow_on_revocation": {"value": "1", "is_locked": True, "locked_min_tier": 2},
            "link_share_max_expiry_days": {"value": "365", "is_locked": True, "locked_min_tier": 2},
        },
        "role_flag_overrides": {
            "role_user": {
                "shares_link_create": {"value": "1", "is_locked": True, "locked_min_tier": 2},
                "shares_user_create": {"value": "1", "is_locked": True, "locked_min_tier": 2},
                "shares_upload_grant_create": {"value": "1", "is_locked": True, "locked_min_tier": 2},
                "shares_folder_create": {"value": "1", "is_locked": True, "locked_min_tier": 2},
            },
        },
        "sharing_rules": [],
    },
    "open": {
        "name": "Open",
        "description": (
            "All sharing on; no restrictions; no locks. "
            "Intended for dev, internal tooling, or environments with a separate policy layer."
        ),
        "admin_settings": {
            "escrow_require_coverage": {"value": "0", "is_locked": False, "locked_min_tier": None},
            "notify_escrow_on_revocation": {"value": "0", "is_locked": False, "locked_min_tier": None},
            "link_share_max_expiry_days": {"value": "0", "is_locked": False, "locked_min_tier": None},
        },
        "role_flag_overrides": {
            "role_user": {
                "shares_link_create": {"value": "1", "is_locked": False, "locked_min_tier": None},
                "shares_user_create": {"value": "1", "is_locked": False, "locked_min_tier": None},
                "shares_upload_grant_create": {"value": "1", "is_locked": False, "locked_min_tier": None},
                "shares_folder_create": {"value": "1", "is_locked": False, "locked_min_tier": None},
            },
        },
        "sharing_rules": [],
    },
}

# ---------------------------------------------------------------------------
# Permission helper
# ---------------------------------------------------------------------------


def _require_server_admin(admin: AuthenticatedUser) -> None:
    if admin_best_tier(admin.roles) > 1:
        raise HTTPException(  # NOSONAR — helper; 403 documented in callers
            status_code=403,
            detail="Only server_admin may manage security profiles",
        )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ApplyProfileRequest(BaseModel):
    profile: str
    mode: str = "replace"
    confirm: bool = False
    confirmation_text: str = ""
    decisions: dict[str, str] = {}
    mark_first_run: bool = False  # set first_run_completed='1' after applying


class ImportProfileRequest(BaseModel):
    profile_json: dict
    mode: str = "replace"
    confirm: bool = False
    confirmation_text: str = ""
    decisions: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Internal: read current state
# ---------------------------------------------------------------------------

_PROFILE_ADMIN_SETTING_KEYS = [
    "escrow_require_coverage",
    "notify_escrow_on_revocation",
    "link_share_max_expiry_days",
]

_PROFILE_SHARING_FLAGS = [
    "shares_link_create",
    "shares_user_create",
    "shares_upload_grant_create",
    "shares_folder_create",
]


async def _read_current(db) -> dict:
    """Read the current profile-managed settings from the DB."""
    placeholders = ",".join("?" * len(_PROFILE_ADMIN_SETTING_KEYS))
    cursor = await db.execute(
        f"SELECT key, value, is_locked, locked_min_tier FROM admin_settings WHERE key IN ({placeholders})",
        _PROFILE_ADMIN_SETTING_KEYS,
    )
    admin_settings = {
        r["key"]: {
            "value": r["value"],
            "is_locked": bool(r["is_locked"]),
            "locked_min_tier": r["locked_min_tier"],
        }
        for r in await cursor.fetchall()
    }

    placeholders = ",".join("?" * len(_PROFILE_SHARING_FLAGS))
    cursor = await db.execute(
        f"SELECT flag, value, is_locked, locked_min_tier FROM role_permissions "
        f"WHERE role_id = 'role_user' AND flag IN ({placeholders})",
        _PROFILE_SHARING_FLAGS,
    )
    role_flags = {
        r["flag"]: {
            "value": r["value"],
            "is_locked": bool(r["is_locked"]),
            "locked_min_tier": r["locked_min_tier"],
        }
        for r in await cursor.fetchall()
    }

    cursor = await db.execute(
        "SELECT id, name, description, is_active, priority, subject, "
        "applies_to_share_type, effect, is_locked, locked_min_tier "
        "FROM sharing_rules ORDER BY priority"
    )
    rules_raw = await cursor.fetchall()
    sharing_rules = []
    for rule in rules_raw:
        cursor2 = await db.execute(
            "SELECT attribute_path, operator, value, block_on_missing_attribute "
            "FROM sharing_rule_conditions WHERE rule_id = ?",
            (rule["id"],),
        )
        conditions = [
            {
                "attribute_path": c["attribute_path"],
                "operator": c["operator"],
                "value": c["value"],
                "block_on_missing_attribute": bool(c["block_on_missing_attribute"]),
            }
            for c in await cursor2.fetchall()
        ]
        sharing_rules.append(
            {
                "name": rule["name"],
                "description": rule["description"],
                "is_active": bool(rule["is_active"]),
                "priority": rule["priority"],
                "subject": rule["subject"],
                "applies_to_share_type": rule["applies_to_share_type"],
                "effect": rule["effect"],
                "is_locked": bool(rule["is_locked"]),
                "locked_min_tier": rule["locked_min_tier"],
                "conditions": conditions,
            }
        )

    return {
        "admin_settings": admin_settings,
        "role_flag_overrides": {"role_user": role_flags},
        "sharing_rules": sharing_rules,
    }


# ---------------------------------------------------------------------------
# Internal: diff computation
# ---------------------------------------------------------------------------


def _compute_diff(current: dict, profile: dict) -> list[dict]:
    """Return per-item diffs between current state and proposed profile."""
    diff = []

    for key, proposed in profile.get("admin_settings", {}).items():
        cur = current["admin_settings"].get(key)
        diff.append(
            {
                "type": "admin_setting",
                "key": f"admin_setting.{key}",
                "label": key,
                "current": cur,
                "proposed": proposed,
                "changed": cur != proposed,
            }
        )

    for role_id, flags in profile.get("role_flag_overrides", {}).items():
        role_cur = current.get("role_flag_overrides", {}).get(role_id, {})
        for flag, proposed in flags.items():
            cur = role_cur.get(flag)
            diff.append(
                {
                    "type": "role_flag",
                    "key": f"role_flag.{role_id}.{flag}",
                    "label": f"{role_id} / {flag}",
                    "role_id": role_id,
                    "flag": flag,
                    "current": cur,
                    "proposed": proposed,
                    "changed": cur != proposed,
                }
            )

    cur_rules = {r["name"]: r for r in current.get("sharing_rules", [])}
    for rule in profile.get("sharing_rules", []):
        cur = cur_rules.get(rule["name"])
        _summary_keys = (
            "is_active",
            "priority",
            "subject",
            "applies_to_share_type",
            "effect",
            "is_locked",
            "locked_min_tier",
            "conditions",
        )
        cur_summary = None if cur is None else {k: cur.get(k) for k in _summary_keys}
        proposed_summary = {k: rule.get(k) for k in _summary_keys}
        diff.append(
            {
                "type": "sharing_rule",
                "key": f"sharing_rule.{rule['name']}",
                "label": f"sharing rule: {rule['name']}",
                "current": cur_summary,
                "proposed": proposed_summary,
                "changed": cur_summary != proposed_summary,
            }
        )

    return diff


# ---------------------------------------------------------------------------
# Internal: apply helpers
# ---------------------------------------------------------------------------


async def _upsert_admin_setting(db, key: str, setting: dict) -> None:
    await db.execute(
        "INSERT INTO admin_settings (key, value, is_locked, locked_min_tier) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT (key) DO UPDATE SET "
        "value = excluded.value, is_locked = excluded.is_locked, "
        "locked_min_tier = excluded.locked_min_tier",
        (key, setting["value"], setting["is_locked"], setting["locked_min_tier"]),
    )


async def _upsert_role_flag(db, role_id: str, flag: str, fu: dict) -> None:
    await db.execute(
        "INSERT INTO role_permissions (role_id, flag, value, is_locked, locked_min_tier) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (role_id, flag) DO UPDATE SET "
        "value = excluded.value, is_locked = excluded.is_locked, "
        "locked_min_tier = excluded.locked_min_tier",
        (role_id, flag, fu["value"], fu["is_locked"], fu.get("locked_min_tier")),
    )


async def _insert_rule(db, rule: dict, admin_id: str, admin_tier: int) -> None:
    rule_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO sharing_rules "
        "(id, name, description, is_active, priority, subject, "
        "applies_to_share_type, effect, is_locked, locked_min_tier, "
        "created_by, created_by_tier) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            rule_id,
            rule["name"],
            rule.get("description", ""),
            rule.get("is_active", True),
            rule.get("priority", 100),
            rule["subject"],
            rule.get("applies_to_share_type"),
            rule.get("effect", "deny"),
            rule.get("is_locked", False),
            rule.get("locked_min_tier"),
            admin_id,
            admin_tier,
        ),
    )
    for cond in rule.get("conditions", []):
        await db.execute(
            "INSERT INTO sharing_rule_conditions "
            "(id, rule_id, attribute_path, operator, value, block_on_missing_attribute) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                rule_id,
                cond["attribute_path"],
                cond["operator"],
                cond.get("value"),
                cond.get("block_on_missing_attribute", True),
            ),
        )


async def _apply_replace(db, profile: dict, admin_id: str, admin_tier: int) -> None:
    """Wipe all sharing rules then atomically apply the profile."""
    for key, setting in profile.get("admin_settings", {}).items():
        await _upsert_admin_setting(db, key, setting)

    for role_id, flags in profile.get("role_flag_overrides", {}).items():
        for flag, fu in flags.items():
            await _upsert_role_flag(db, role_id, flag, fu)

    await db.execute("DELETE FROM sharing_rules")
    for rule in profile.get("sharing_rules", []):
        await _insert_rule(db, rule, admin_id, admin_tier)


async def _apply_merge(db, profile: dict, decisions: dict, admin_id: str, admin_tier: int) -> None:
    """Apply only items where decisions[key] == 'proposed' (default when absent)."""
    for key, setting in profile.get("admin_settings", {}).items():
        if decisions.get(f"admin_setting.{key}", "proposed") == "proposed":
            await _upsert_admin_setting(db, key, setting)

    for role_id, flags in profile.get("role_flag_overrides", {}).items():
        for flag, fu in flags.items():
            if decisions.get(f"role_flag.{role_id}.{flag}", "proposed") == "proposed":
                await _upsert_role_flag(db, role_id, flag, fu)

    for rule in profile.get("sharing_rules", []):
        if decisions.get(f"sharing_rule.{rule['name']}", "proposed") == "proposed":
            await db.execute("DELETE FROM sharing_rules WHERE name = ?", (rule["name"],))
            await _insert_rule(db, rule, admin_id, admin_tier)


def _validate_role_flag_overrides(overrides: dict) -> None:
    for role_id, flags in overrides.items():
        if not isinstance(flags, dict):
            raise HTTPException(  # NOSONAR
                status_code=400,
                detail=f"role_flag_overrides.{role_id} must be a dict of flags",
            )
        for flag, fu in flags.items():
            if not isinstance(fu, dict) or "value" not in fu:
                raise HTTPException(  # NOSONAR
                    status_code=400,
                    detail=f"role_flag_overrides.{role_id}.{flag} must be an object with a 'value' field",
                )


def _validate_profile_structure(profile_json: dict) -> None:
    """Raise 400 on structural problems in an imported profile JSON."""
    allowed_keys = {"_warnings", "_meta", "admin_settings", "role_flag_overrides", "sharing_rules"}
    unknown = set(profile_json.keys()) - allowed_keys
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown profile keys: {sorted(unknown)}")  # NOSONAR

    for key, setting in profile_json.get("admin_settings", {}).items():
        if not isinstance(setting, dict) or "value" not in setting:
            raise HTTPException(  # NOSONAR
                status_code=400,
                detail=f"admin_settings.{key} must be an object with a 'value' field",
            )

    _validate_role_flag_overrides(profile_json.get("role_flag_overrides", {}))

    for i, rule in enumerate(profile_json.get("sharing_rules", [])):
        if not isinstance(rule, dict) or "name" not in rule or "subject" not in rule:
            raise HTTPException(  # NOSONAR
                status_code=400,
                detail=f"sharing_rules[{i}] is missing required fields (name, subject)",
            )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/settings/profiles")
async def list_profiles(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
):
    """List available built-in profile names and descriptions."""
    _require_server_admin(admin)
    return {
        "profiles": [{"id": pid, "name": p["name"], "description": p["description"]} for pid, p in _PROFILES.items()]
    }


@router.get("/settings/export")
async def export_settings(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    _: Annotated[None, Depends(require_step_up(_STEPUP_ACTION))],
    db: Annotated[Database, Depends(get_db)],
):
    """Download current profile-managed settings as a JSON attachment."""
    _require_server_admin(admin)

    current = await _read_current(db)
    warnings: list[str] = []

    # Check for user IDs in escrow defaults — strip and warn
    escrow_raw = await get_admin_setting(db, "escrow_default_user_ids")
    if escrow_raw is not None:
        try:
            user_ids = _json.loads(escrow_raw or "[]")
        except Exception:
            user_ids = []
        if user_ids:
            warnings.append(
                f"STRIPPED: {len(user_ids)} direct user ID assignment(s) in "
                "escrow defaults (escrow_default_user_ids) removed — user IDs are "
                "instance-specific. Re-configure escrow agents after import."
            )

    from app.config import settings as _app_settings

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    export = {
        "_warnings": warnings,
        "_meta": {
            "format_version": "1",
            "profile_name": f"Custom Export — {date_str}",
            "exported_at": now_str,
            "exported_from_app_version": getattr(_app_settings, "APP_VERSION", "unknown"),
            "exported_by_tier": admin_best_tier(admin.roles),
        },
        "admin_settings": current["admin_settings"],
        "role_flag_overrides": current["role_flag_overrides"],
        "sharing_rules": current["sharing_rules"],
    }

    event_bus.emit(
        SecurityEvent(
            event_type="admin.settings.profile_exported",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username),
            detail={"exported_by_tier": admin_best_tier(admin.roles)},
        )
    )

    return Response(
        content=_json.dumps(export, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="filexfer-profile-{date_str}.json"',
        },
    )


@router.post(
    "/settings/apply-profile", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}}
)
async def apply_profile(
    body: ApplyProfileRequest,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Apply a built-in security profile.

    Without confirm=True: returns a diff preview (no changes made).
    With confirm=True and (for replace mode) confirmation_text='REPLACE':
      applies the profile atomically and emits a SIEM event.

    Step-up is bypassed during the first-run wizard (mark_first_run=True before
    first_run_completed is set).  All post-setup calls require step-up as normal.
    """
    _require_server_admin(admin)

    # Determine whether step-up must be enforced.
    # During first-run setup the admin has just bootstrapped and has no active
    # session key to complete OPAQUE step-up, so we skip it.
    # first_run_completed is pre-seeded as '0' by schema.sql, so treat both
    # NULL and '0' as "wizard not yet finished" to bypass step-up.
    is_wizard_call = (await get_admin_setting(db, "first_run_completed")) not in ("1",)

    if not is_wizard_call and sensitive_config.is_sensitive(_STEPUP_ACTION):
        token = request.headers.get("X-Step-Up-Token", "")
        if not token:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "step_up_required",
                    "action": _STEPUP_ACTION,
                    "challenge_type": sensitive_config.get_challenge_type(_STEPUP_ACTION),
                },
            )
        if not verify_step_up_token(token, admin.id, _STEPUP_ACTION, session_id=admin.session_id):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "step_up_invalid",
                    "action": _STEPUP_ACTION,
                    "challenge_type": sensitive_config.get_challenge_type(_STEPUP_ACTION),
                },
            )

    if body.profile not in _PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown profile '{body.profile}'. Valid: {list(_PROFILES)}",
        )
    if body.mode not in ("replace", "merge"):
        raise HTTPException(status_code=400, detail=_ERR_MODE_REPLACE_OR_MERGE)

    profile = _PROFILES[body.profile]
    current = await _read_current(db)
    diff = _compute_diff(current, profile)

    if not body.confirm:
        return {"diff": diff, "profile": body.profile, "mode": body.mode}

    if body.mode == "replace" and body.confirmation_text != "REPLACE":
        raise HTTPException(
            status_code=400,
            detail="Replace mode requires confirmation_text = 'REPLACE'",
        )

    admin_id = admin.id
    tier = admin_best_tier(admin.roles)

    if body.mode == "replace":
        await _apply_replace(db, profile, admin_id, tier)
    else:
        await _apply_merge(db, profile, body.decisions, admin_id, tier)

    if body.mark_first_run:
        await db.execute(
            "INSERT INTO admin_settings (key, value) VALUES ('first_run_completed', '1') "
            "ON CONFLICT (key) DO UPDATE SET value = '1'",
        )

    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type="admin.settings.profile_applied",
            severity="high",
            outcome="success",
            actor=EventActor(user_id=admin_id, username=admin.username),
            detail={
                "profile": body.profile,
                "mode": body.mode,
                "items_changed": sum(1 for d in diff if d["changed"]),
            },
        )
    )

    return {"message": "Profile applied", "profile": body.profile, "mode": body.mode}


@router.post("/settings/import", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}})
async def import_profile(
    body: ImportProfileRequest,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Import a profile JSON.

    Without confirm=True: validates structure and returns a diff preview.
    With confirm=True and (for replace mode) confirmation_text='REPLACE':
      applies the profile atomically and emits a SIEM event.

    Step-up is bypassed during the first-run wizard (same logic as apply_profile).
    """
    _require_server_admin(admin)

    is_wizard_call = (await get_admin_setting(db, "first_run_completed")) not in ("1",)
    if not is_wizard_call and sensitive_config.is_sensitive(_STEPUP_ACTION):
        token = request.headers.get("X-Step-Up-Token", "")
        if not token:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "step_up_required",
                    "action": _STEPUP_ACTION,
                    "challenge_type": sensitive_config.get_challenge_type(_STEPUP_ACTION),
                },
            )
        if not verify_step_up_token(token, admin.id, _STEPUP_ACTION, session_id=admin.session_id):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "step_up_invalid",
                    "action": _STEPUP_ACTION,
                    "challenge_type": sensitive_config.get_challenge_type(_STEPUP_ACTION),
                },
            )

    if body.mode not in ("replace", "merge"):
        raise HTTPException(status_code=400, detail=_ERR_MODE_REPLACE_OR_MERGE)

    _validate_profile_structure(body.profile_json)

    current = await _read_current(db)
    diff = _compute_diff(current, body.profile_json)

    if not body.confirm:
        return {
            "diff": diff,
            "mode": body.mode,
            "warnings": body.profile_json.get("_warnings", []),
        }

    if body.mode == "replace" and body.confirmation_text != "REPLACE":
        raise HTTPException(
            status_code=400,
            detail="Replace mode requires confirmation_text = 'REPLACE'",
        )

    admin_id = admin.id
    tier = admin_best_tier(admin.roles)

    if body.mode == "replace":
        await _apply_replace(db, body.profile_json, admin_id, tier)
    else:
        await _apply_merge(db, body.profile_json, body.decisions, admin_id, tier)

    await db.commit()

    severity = "critical" if body.mode == "replace" else "high"
    event_bus.emit(
        SecurityEvent(
            event_type="admin.settings.profile_imported",
            severity=severity,
            outcome="success",
            actor=EventActor(user_id=admin_id, username=admin.username),
            detail={
                "mode": body.mode,
                "items_changed": sum(1 for d in diff if d["changed"]),
            },
        )
    )

    return {"message": "Profile imported", "mode": body.mode}


# ---------------------------------------------------------------------------
# Full export / import (multi-category)
# ---------------------------------------------------------------------------

# Admin settings keys that are safe to export (credentials excluded)
_FULL_EXPORT_SETTING_KEYS = [
    "open_registration",
    "global_max_file_size",
    "global_bandwidth_limit",
    "disk_warning_threshold",
    "default_chunk_size",
    "mfa_enforcement",
    "mfa_allowed_methods",
    "mfa_oidc_exempt",
    "notify_escrow_on_revocation",
    "escrow_require_coverage",
    "allow_user_delete_own_account",
    "can_delete_owned_shared",
    "allow_multi_team_owner",
    "copy_boundary",
    "audit_retention_days",
    "regex_match_timeout_ms",
    "av_scan_endpoint",
    "av_require_clean",
    "av_scan_retry_attempts",
    "trash_enabled",
    "trash_retention_days",
]

_ALL_CATEGORIES = frozenset(
    [
        "security_profile",
        "roles",
        "admin_settings",
        "policies",
        "policy_fields",
        "siem",
        "notifications",
        "storage",
    ]
)


class FullImportRequest(BaseModel):
    data: dict
    categories: list[str] = []
    mode: str = "replace"


async def _read_roles_for_export(db) -> list[dict]:
    cursor = await db.execute("SELECT id, name, description, is_system FROM roles ORDER BY is_system DESC, id")
    roles = []
    for rr in await cursor.fetchall():
        cursor2 = await db.execute(
            "SELECT flag, value, is_locked, locked_min_tier FROM role_permissions WHERE role_id = ?",
            (rr["id"],),
        )
        perms = {
            r["flag"]: {
                "value": r["value"],
                "is_locked": bool(r["is_locked"]),
                "locked_min_tier": r["locked_min_tier"],
            }
            for r in await cursor2.fetchall()
        }
        roles.append(
            {
                "id": rr["id"],
                "name": rr["name"],
                "description": rr["description"] or "",
                "is_system": bool(rr["is_system"]),
                "permissions": perms,
            }
        )
    return roles


async def _read_policies_for_export(db) -> list[dict]:
    cursor = await db.execute(
        "SELECT id, name, scope_type, escrow_enabled FROM policies WHERE scope_type = 'org' ORDER BY name"
    )
    policies = []
    for pr in await cursor.fetchall():
        cursor2 = await db.execute(
            "SELECT field, operator, value, block_on_missing_attribute "
            "FROM policy_conditions WHERE policy_id = ? ORDER BY field",
            (pr["id"],),
        )
        conditions = [
            {
                "field": c["field"],
                "operator": c["operator"],
                "value": c["value"],
                "block_on_missing_attribute": bool(c["block_on_missing_attribute"]),
            }
            for c in await cursor2.fetchall()
        ]
        policies.append(
            {
                "name": pr["name"],
                "escrow_enabled": pr["escrow_enabled"],
                "conditions": conditions,
            }
        )
    return policies


async def _full_read(db, categories: set) -> tuple[dict, list[str]]:
    out: dict = {}
    warnings: list[str] = []

    if "security_profile" in categories:
        out["security_profile"] = await _read_current(db)

    if "roles" in categories:
        out["roles"] = await _read_roles_for_export(db)

    if "admin_settings" in categories:
        placeholders = ",".join("?" * len(_FULL_EXPORT_SETTING_KEYS))
        cursor = await db.execute(
            f"SELECT key, value FROM admin_settings WHERE key IN ({placeholders})",
            _FULL_EXPORT_SETTING_KEYS,
        )
        out["admin_settings"] = {r["key"]: r["value"] for r in await cursor.fetchall()}

    if "policies" in categories:
        out["policies"] = await _read_policies_for_export(db)
        warnings.append(
            "NOTE: policy effects (team membership, folder ACL, escrow overrides) "
            "are NOT exported because they reference instance-specific user/team IDs."
        )

    if "policy_fields" in categories:
        cursor = await db.execute(
            "SELECT name, display_label, source FROM policy_field_definitions WHERE source != 'internal' ORDER BY name"
        )
        out["policy_fields"] = [
            {"name": r["name"], "display_label": r["display_label"], "source": r["source"]}
            for r in await cursor.fetchall()
        ]

    if "siem" in categories:
        cursor = await db.execute(
            "SELECT id, name, type, is_active, host, port, protocol, "
            "syslog_format, facility, url, batch_size, filter_profile "
            "FROM siem_destinations ORDER BY created_at ASC"
        )
        out["siem"] = [dict(r) for r in await cursor.fetchall()]
        if out["siem"]:
            warnings.append(
                "SIEM destination signing secrets (secret_enc) are NOT exported. "
                "Re-configure shared secrets after import."
            )

    if "notifications" in categories:
        cursor = await db.execute(
            "SELECT id, name, endpoint_url, event_filter, batch_size, batch_interval_s, enabled "
            "FROM notification_channels ORDER BY created_at ASC"
        )
        out["notifications"] = [dict(r) for r in await cursor.fetchall()]
        if out["notifications"]:
            warnings.append(
                "Notification channel signing secrets are NOT exported. Re-configure shared secrets after import."
            )

    if "storage" in categories:
        cursor = await db.execute(
            "SELECT id, name, provider, tier, is_default, priority FROM storage_volumes ORDER BY priority ASC, name ASC"
        )
        out["storage"] = [dict(r) for r in await cursor.fetchall()]
        if out["storage"]:
            warnings.append(
                "Storage volume credentials (access keys, secrets) are NOT exported. "
                "Re-configure provider credentials after import. Storage volumes are "
                "always merged on import — existing volumes with files are never deleted."
            )

    return out, warnings


@router.get("/settings/full-export", responses={400: {"description": "Bad Request"}})
async def full_export_settings(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    _: Annotated[None, Depends(require_step_up(_STEPUP_ACTION))],
    db: Annotated[Database, Depends(get_db)],
    categories: str = "security_profile,roles,admin_settings,policies,policy_fields,siem,notifications,storage",
):
    """Export multiple configuration categories as a single JSON file."""
    _require_server_admin(admin)

    requested = {c.strip() for c in categories.split(",") if c.strip()}
    unknown = requested - _ALL_CATEGORIES
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown export categories: {sorted(unknown)}. Valid: {sorted(_ALL_CATEGORIES)}",
        )

    data, warnings = await _full_read(db, requested)

    from app.config import settings as _app_settings

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    export = {
        "_warnings": warnings,
        "_meta": {
            "format_version": "2",
            "exported_at": now_str,
            "exported_by_tier": admin_best_tier(admin.roles),
            "categories": sorted(requested),
            "exported_from_app_version": getattr(_app_settings, "APP_VERSION", "unknown"),
        },
        **data,
    }

    event_bus.emit(
        SecurityEvent(
            event_type="admin.settings.full_exported",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username),
            detail={"categories": sorted(requested), "tier": admin_best_tier(admin.roles)},
        )
    )

    return Response(
        content=_json.dumps(export, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="filexfer-export-{date_str}.json"',
        },
    )


async def _import_security_profile(db, data: dict, replace: bool, admin_id: str, tier: int) -> int:
    sp = data["security_profile"]
    _validate_profile_structure(sp)
    if replace:
        await _apply_replace(db, sp, admin_id, tier)
    else:
        await _apply_merge(db, sp, {}, admin_id, tier)
    return (
        len(sp.get("admin_settings", {}))
        + sum(len(v) for v in sp.get("role_flag_overrides", {}).values())
        + len(sp.get("sharing_rules", []))
    )


async def _delete_unreferenced_roles(db, export_ids: set) -> None:
    cursor = await db.execute(
        "SELECT id FROM roles WHERE is_system = 0 AND id NOT IN "
        f"({','.join('?' * len(export_ids)) if export_ids else 'NULL'})",
        list(export_ids) if export_ids else [],
    )
    for row in await cursor.fetchall():
        await db.execute("DELETE FROM roles WHERE id = ?", (row["id"],))


async def _upsert_role_permissions(db, rid: str, permissions: dict) -> None:
    for flag, fu in permissions.items():
        if not isinstance(fu, dict) or "value" not in fu:
            continue
        await db.execute(
            "INSERT INTO role_permissions (role_id, flag, value, is_locked, locked_min_tier) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (role_id, flag) DO UPDATE SET "
            "value = excluded.value, is_locked = excluded.is_locked, "
            "locked_min_tier = excluded.locked_min_tier",
            (rid, flag, fu["value"], bool(fu.get("is_locked", False)), fu.get("locked_min_tier")),
        )


async def _import_roles(db, data: dict, replace: bool) -> int:
    roles_list = data["roles"]
    if not isinstance(roles_list, list):
        raise HTTPException(status_code=400, detail="data.roles must be a list")
    count = 0
    if replace:
        export_ids = {r["id"] for r in roles_list if isinstance(r, dict) and "id" in r}
        await _delete_unreferenced_roles(db, export_ids)
    for role in roles_list:
        if not isinstance(role, dict) or "id" not in role or "name" not in role:
            continue
        rid = role["id"]
        await db.execute(
            "INSERT INTO roles (id, name, description, is_system) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (id) DO UPDATE SET name = excluded.name, "
            "description = excluded.description",
            (rid, role["name"], role.get("description", ""), 1 if role.get("is_system") else 0),
        )
        await _upsert_role_permissions(db, rid, role.get("permissions") or {})
        count += 1
    return count


async def _import_admin_settings(db, data: dict) -> int:
    from app.routes.admin import _SETTINGS_VALIDATORS

    settings_dict = data["admin_settings"]
    if not isinstance(settings_dict, dict):
        raise HTTPException(status_code=400, detail="data.admin_settings must be a dict")
    count = 0
    for key, value in settings_dict.items():
        if key not in _SETTINGS_VALIDATORS:
            continue
        if not _SETTINGS_VALIDATORS[key](str(value)):
            continue
        await db.execute(
            "INSERT INTO admin_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        count += 1
    return count


async def _upsert_policy_conditions(db, policy_id: str, conditions: list) -> None:
    for cond in conditions:
        if not isinstance(cond, dict) or "field" not in cond:
            continue
        await db.execute(
            "INSERT INTO policy_conditions "
            "(id, policy_id, field, operator, value, block_on_missing_attribute) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (
                str(uuid.uuid4()),
                policy_id,
                cond["field"],
                cond.get("operator", "="),
                cond.get("value"),
                1 if cond.get("block_on_missing_attribute", True) else 0,
            ),
        )


async def _import_policies(db, data: dict, replace: bool, admin_id: str) -> int:
    policies_list = data["policies"]
    if not isinstance(policies_list, list):
        raise HTTPException(status_code=400, detail="data.policies must be a list")
    if replace:
        await db.execute(
            "DELETE FROM policies WHERE scope_type = 'org' AND id NOT IN "
            "(SELECT DISTINCT policy_id FROM policy_effects)"
        )
    count = 0
    for pol in policies_list:
        if not isinstance(pol, dict) or "name" not in pol:
            continue
        pol_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO policies (id, name, scope_type, escrow_enabled, created_by) "
            "VALUES (?, ?, 'org', ?, ?) "
            "ON CONFLICT DO NOTHING",
            (pol_id, pol["name"], pol.get("escrow_enabled"), admin_id),
        )
        cursor = await db.execute(
            "SELECT id FROM policies WHERE name = ? AND scope_type = 'org'",
            (pol["name"],),
        )
        row = await cursor.fetchone()
        if row is None:
            continue
        await _upsert_policy_conditions(db, row["id"], pol.get("conditions") or [])
        count += 1
    return count


async def _import_policy_fields(db, data: dict) -> int:
    fields_list = data["policy_fields"]
    if not isinstance(fields_list, list):
        raise HTTPException(status_code=400, detail="data.policy_fields must be a list")
    count = 0
    for f in fields_list:
        if not isinstance(f, dict) or "name" not in f or "source" not in f:
            continue
        if f["source"] == "internal":
            continue
        await db.execute(
            "INSERT INTO policy_field_definitions (name, display_label, source) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT (name) DO UPDATE SET display_label = excluded.display_label, "
            "source = excluded.source",
            (f["name"], f.get("display_label", f["name"]), f["source"]),
        )
        count += 1
    return count


async def _import_siem(db, data: dict, replace: bool) -> int:
    siem_list = data["siem"]
    if not isinstance(siem_list, list):
        raise HTTPException(status_code=400, detail="data.siem must be a list")
    if replace:
        await db.execute("DELETE FROM siem_destinations")
    count = 0
    for dest in siem_list:
        if not isinstance(dest, dict) or "name" not in dest or "type" not in dest:
            continue
        dest_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO siem_destinations "
            "(id, name, type, is_active, host, port, protocol, syslog_format, "
            "facility, url, secret_enc, batch_size, filter_profile) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?) "
            "ON CONFLICT DO NOTHING",
            (
                dest_id,
                dest["name"],
                dest["type"],
                1 if dest.get("is_active", True) else 0,
                dest.get("host"),
                dest.get("port"),
                dest.get("protocol"),
                dest.get("syslog_format"),
                dest.get("facility"),
                dest.get("url"),
                dest.get("batch_size"),
                dest.get("filter_profile"),
            ),
        )
        count += 1
    return count


async def _import_notifications(db, data: dict, replace: bool) -> int:
    notif_list = data["notifications"]
    if not isinstance(notif_list, list):
        raise HTTPException(status_code=400, detail="data.notifications must be a list")
    if replace:
        await db.execute("DELETE FROM notification_channels")
    count = 0
    for ch in notif_list:
        if not isinstance(ch, dict) or "name" not in ch or "endpoint_url" not in ch:
            continue
        ch_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO notification_channels "
            "(id, name, endpoint_url, secret_enc, event_filter, "
            "batch_size, batch_interval_s, enabled, created_at) "
            "VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (
                ch_id,
                ch["name"],
                ch["endpoint_url"],
                ch.get("event_filter", "[]"),
                ch.get("batch_size"),
                ch.get("batch_interval_s"),
                1 if ch.get("enabled", True) else 0,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        count += 1
    return count


async def _import_storage(db, data: dict) -> int:
    storage_list = data["storage"]
    if not isinstance(storage_list, list):
        raise HTTPException(status_code=400, detail="data.storage must be a list")
    valid_providers = {"local", "s3", "b2", "azure", "gcs"}
    count = 0
    for vol in storage_list:
        if not isinstance(vol, dict) or "name" not in vol or "provider" not in vol:
            continue
        if vol["provider"] not in valid_providers:
            continue
        vol_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO storage_volumes (id, name, provider, config_enc, tier, is_default, priority) "
            "VALUES (?, ?, ?, NULL, ?, 0, ?) "
            "ON CONFLICT (name) DO NOTHING",
            (
                vol_id,
                vol["name"],
                vol["provider"],
                vol.get("tier", "hot"),
                vol.get("priority", 0),
            ),
        )
        count += 1
    return count


def _enforce_step_up_import(request: Request, admin: AuthenticatedUser) -> None:
    if not sensitive_config.is_sensitive(_STEPUP_ACTION):
        return
    token = request.headers.get("X-Step-Up-Token", "")
    if not token:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "step_up_required",
                "action": _STEPUP_ACTION,
                "challenge_type": sensitive_config.get_challenge_type(_STEPUP_ACTION),
            },
        )
    if not verify_step_up_token(token, admin.id, _STEPUP_ACTION, session_id=admin.session_id):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "step_up_invalid",
                "action": _STEPUP_ACTION,
                "challenge_type": sensitive_config.get_challenge_type(_STEPUP_ACTION),
            },
        )


@router.post(
    "/settings/full-import", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}}
)
async def full_import_settings(
    body: FullImportRequest,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Import one or more configuration categories from a full-export JSON."""
    _require_server_admin(admin)
    _enforce_step_up_import(request, admin)

    if body.mode not in ("replace", "merge"):
        raise HTTPException(status_code=400, detail=_ERR_MODE_REPLACE_OR_MERGE)

    requested = set(body.categories)
    unknown = requested - _ALL_CATEGORIES
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown import categories: {sorted(unknown)}",
        )

    admin_id = admin.id
    tier = admin_best_tier(admin.roles)
    data = body.data
    replace = body.mode == "replace"
    items_applied: dict[str, int] = {}

    _dispatch = {
        "security_profile": lambda: _import_security_profile(db, data, replace, admin_id, tier),
        "roles": lambda: _import_roles(db, data, replace),
        "admin_settings": lambda: _import_admin_settings(db, data),
        "policies": lambda: _import_policies(db, data, replace, admin_id),
        "policy_fields": lambda: _import_policy_fields(db, data),
        "siem": lambda: _import_siem(db, data, replace),
        "notifications": lambda: _import_notifications(db, data, replace),
        "storage": lambda: _import_storage(db, data),
    }
    for cat in requested:
        if cat in data and cat in _dispatch:
            items_applied[cat] = await _dispatch[cat]()

    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type="admin.settings.full_imported",
            severity="critical" if replace else "high",
            outcome="success",
            actor=EventActor(user_id=admin_id, username=admin.username),
            detail={"mode": body.mode, "categories": sorted(requested), "items": items_applied},
        )
    )

    return {"message": "Import applied", "mode": body.mode, "items_applied": items_applied}
