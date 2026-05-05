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

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

import app.sensitive_config as sensitive_config
from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.auth.stepup import verify_step_up_token
from app.database import get_db
from app.middleware.stepup import require_step_up
from app.models.role import admin_best_tier
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import event_bus
from app.util.db import get_admin_setting

router = APIRouter()

_STEPUP_ACTION = "admin.settings.security.*"

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
            "escrow_require_coverage":     {"value": "1", "is_locked": True,  "locked_min_tier": 1},
            "notify_escrow_on_revocation": {"value": "1", "is_locked": True,  "locked_min_tier": 1},
        },
        "role_flag_overrides": {
            "role_user": {
                "can_create_link_shares":   {"value": "0", "is_locked": True, "locked_min_tier": 1},
                "can_create_user_shares":   {"value": "1", "is_locked": True, "locked_min_tier": 1},
                "can_create_upload_grants": {"value": "1", "is_locked": True, "locked_min_tier": 1},
                "can_share_folders":        {"value": "0", "is_locked": True, "locked_min_tier": 1},
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
            "escrow_require_coverage":     {"value": "0", "is_locked": True,  "locked_min_tier": 2},
            "notify_escrow_on_revocation": {"value": "0", "is_locked": True,  "locked_min_tier": 2},
        },
        "role_flag_overrides": {
            "role_user": {
                "can_create_link_shares":   {"value": "1", "is_locked": True, "locked_min_tier": 2},
                "can_create_user_shares":   {"value": "1", "is_locked": True, "locked_min_tier": 2},
                "can_create_upload_grants": {"value": "1", "is_locked": True, "locked_min_tier": 2},
                "can_share_folders":        {"value": "1", "is_locked": True, "locked_min_tier": 2},
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
            "escrow_require_coverage":     {"value": "0", "is_locked": False, "locked_min_tier": None},
            "notify_escrow_on_revocation": {"value": "0", "is_locked": False, "locked_min_tier": None},
        },
        "role_flag_overrides": {
            "role_user": {
                "can_create_link_shares":   {"value": "1", "is_locked": False, "locked_min_tier": None},
                "can_create_user_shares":   {"value": "1", "is_locked": False, "locked_min_tier": None},
                "can_create_upload_grants": {"value": "1", "is_locked": False, "locked_min_tier": None},
                "can_share_folders":        {"value": "1", "is_locked": False, "locked_min_tier": None},
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
        raise HTTPException(
            status_code=403,
            detail="Only server_admin may manage security profiles",
        )

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ApplyProfileRequest(BaseModel):
    profile:           str
    mode:              str = "replace"
    confirm:           bool = False
    confirmation_text: str = ""
    decisions:         dict[str, str] = {}
    mark_first_run:    bool = False  # set first_run_completed='1' after applying


class ImportProfileRequest(BaseModel):
    profile_json:      dict
    mode:              str = "replace"
    confirm:           bool = False
    confirmation_text: str = ""
    decisions:         dict[str, str] = {}

# ---------------------------------------------------------------------------
# Internal: read current state
# ---------------------------------------------------------------------------

_PROFILE_ADMIN_SETTING_KEYS = [
    "escrow_require_coverage",
    "notify_escrow_on_revocation",
]

_PROFILE_SHARING_FLAGS = [
    "can_create_link_shares",
    "can_create_user_shares",
    "can_create_upload_grants",
    "can_share_folders",
]


async def _read_current(db) -> dict:
    """Read the current profile-managed settings from the DB."""
    placeholders = ",".join("?" * len(_PROFILE_ADMIN_SETTING_KEYS))
    cursor = await db.execute(
        f"SELECT key, value, is_locked, locked_min_tier FROM admin_settings "
        f"WHERE key IN ({placeholders})",
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
        sharing_rules.append({
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
        })

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
        diff.append({
            "type":    "admin_setting",
            "key":     f"admin_setting.{key}",
            "label":   key,
            "current": cur,
            "proposed": proposed,
            "changed": cur != proposed,
        })

    for role_id, flags in profile.get("role_flag_overrides", {}).items():
        role_cur = current.get("role_flag_overrides", {}).get(role_id, {})
        for flag, proposed in flags.items():
            cur = role_cur.get(flag)
            diff.append({
                "type":    "role_flag",
                "key":     f"role_flag.{role_id}.{flag}",
                "label":   f"{role_id} / {flag}",
                "role_id": role_id,
                "flag":    flag,
                "current": cur,
                "proposed": proposed,
                "changed": cur != proposed,
            })

    cur_rules = {r["name"]: r for r in current.get("sharing_rules", [])}
    for rule in profile.get("sharing_rules", []):
        cur = cur_rules.get(rule["name"])
        _summary_keys = (
            "is_active", "priority", "subject", "applies_to_share_type",
            "effect", "is_locked", "locked_min_tier", "conditions",
        )
        cur_summary = (
            None if cur is None
            else {k: cur.get(k) for k in _summary_keys}
        )
        proposed_summary = {k: rule.get(k) for k in _summary_keys}
        diff.append({
            "type":    "sharing_rule",
            "key":     f"sharing_rule.{rule['name']}",
            "label":   f"sharing rule: {rule['name']}",
            "current": cur_summary,
            "proposed": proposed_summary,
            "changed": cur_summary != proposed_summary,
        })

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
            rule_id, rule["name"], rule.get("description", ""),
            rule.get("is_active", True), rule.get("priority", 100),
            rule["subject"], rule.get("applies_to_share_type"),
            rule.get("effect", "deny"),
            rule.get("is_locked", False), rule.get("locked_min_tier"),
            admin_id, admin_tier,
        ),
    )
    for cond in rule.get("conditions", []):
        await db.execute(
            "INSERT INTO sharing_rule_conditions "
            "(id, rule_id, attribute_path, operator, value, block_on_missing_attribute) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()), rule_id,
                cond["attribute_path"], cond["operator"],
                cond.get("value"), cond.get("block_on_missing_attribute", True),
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


async def _apply_merge(
    db, profile: dict, decisions: dict, admin_id: str, admin_tier: int
) -> None:
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


def _validate_profile_structure(profile_json: dict) -> None:
    """Raise 400 on structural problems in an imported profile JSON."""
    allowed_keys = {"_warnings", "_meta", "admin_settings", "role_flag_overrides", "sharing_rules"}
    unknown = set(profile_json.keys()) - allowed_keys
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown profile keys: {sorted(unknown)}")

    for key, setting in profile_json.get("admin_settings", {}).items():
        if not isinstance(setting, dict) or "value" not in setting:
            raise HTTPException(
                status_code=400,
                detail=f"admin_settings.{key} must be an object with a 'value' field",
            )

    for role_id, flags in profile_json.get("role_flag_overrides", {}).items():
        if not isinstance(flags, dict):
            raise HTTPException(
                status_code=400,
                detail=f"role_flag_overrides.{role_id} must be a dict of flags",
            )
        for flag, fu in flags.items():
            if not isinstance(fu, dict) or "value" not in fu:
                raise HTTPException(
                    status_code=400,
                    detail=f"role_flag_overrides.{role_id}.{flag} must be an object with a 'value' field",
                )

    for i, rule in enumerate(profile_json.get("sharing_rules", [])):
        if not isinstance(rule, dict) or "name" not in rule or "subject" not in rule:
            raise HTTPException(
                status_code=400,
                detail=f"sharing_rules[{i}] is missing required fields (name, subject)",
            )

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/settings/profiles")
async def list_profiles(
    admin: AuthenticatedUser = Depends(require_admin),
):
    """List available built-in profile names and descriptions."""
    _require_server_admin(admin)
    return {
        "profiles": [
            {"id": pid, "name": p["name"], "description": p["description"]}
            for pid, p in _PROFILES.items()
        ]
    }


@router.get("/settings/export")
async def export_settings(
    admin: AuthenticatedUser = Depends(require_admin),
    _: None = Depends(require_step_up(_STEPUP_ACTION)),
    db=Depends(get_db),
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
            "format_version":           "1",
            "profile_name":             f"Custom Export — {date_str}",
            "exported_at":              now_str,
            "exported_from_app_version": getattr(_app_settings, "APP_VERSION", "unknown"),
            "exported_by_tier":         admin_best_tier(admin.roles),
        },
        "admin_settings":     current["admin_settings"],
        "role_flag_overrides": current["role_flag_overrides"],
        "sharing_rules":       current["sharing_rules"],
    }

    event_bus.emit(SecurityEvent(
        event_type="admin.settings.profile_exported",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=admin.id),
        detail={"exported_by_tier": admin_best_tier(admin.roles)},
    ))

    return Response(
        content=_json.dumps(export, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="filexfer-profile-{date_str}.json"',
        },
    )


@router.post("/settings/apply-profile")
async def apply_profile(
    body: ApplyProfileRequest,
    request: Request,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
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
    is_wizard_call = (await get_admin_setting(db, "first_run_completed")) is None

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
        if not verify_step_up_token(token, admin.id, _STEPUP_ACTION,
                                    session_id=admin.session_id):
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
        raise HTTPException(status_code=400, detail="mode must be 'replace' or 'merge'")

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

    admin_id  = admin.id
    tier      = admin_best_tier(admin.roles)

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

    event_bus.emit(SecurityEvent(
        event_type="admin.settings.profile_applied",
        severity="high",
        outcome="success",
        actor=EventActor(user_id=admin_id),
        detail={
            "profile": body.profile,
            "mode":    body.mode,
            "items_changed": sum(1 for d in diff if d["changed"]),
        },
    ))

    return {"message": "Profile applied", "profile": body.profile, "mode": body.mode}


@router.post("/settings/import")
async def import_profile(
    body: ImportProfileRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    _: None = Depends(require_step_up(_STEPUP_ACTION)),
    db=Depends(get_db),
):
    """Import a profile JSON.

    Without confirm=True: validates structure and returns a diff preview.
    With confirm=True and (for replace mode) confirmation_text='REPLACE':
      applies the profile atomically and emits a SIEM event.
    """
    _require_server_admin(admin)

    if body.mode not in ("replace", "merge"):
        raise HTTPException(status_code=400, detail="mode must be 'replace' or 'merge'")

    _validate_profile_structure(body.profile_json)

    current = await _read_current(db)
    diff    = _compute_diff(current, body.profile_json)

    if not body.confirm:
        return {
            "diff":     diff,
            "mode":     body.mode,
            "warnings": body.profile_json.get("_warnings", []),
        }

    if body.mode == "replace" and body.confirmation_text != "REPLACE":
        raise HTTPException(
            status_code=400,
            detail="Replace mode requires confirmation_text = 'REPLACE'",
        )

    admin_id = admin.id
    tier     = admin_best_tier(admin.roles)

    if body.mode == "replace":
        await _apply_replace(db, body.profile_json, admin_id, tier)
    else:
        await _apply_merge(db, body.profile_json, body.decisions, admin_id, tier)

    await db.commit()

    severity = "critical" if body.mode == "replace" else "high"
    event_bus.emit(SecurityEvent(
        event_type="admin.settings.profile_imported",
        severity=severity,
        outcome="success",
        actor=EventActor(user_id=admin_id),
        detail={
            "mode":          body.mode,
            "items_changed": sum(1 for d in diff if d["changed"]),
        },
    ))

    return {"message": "Profile imported", "mode": body.mode}
