"""Admin settings, disk usage, and invite management routes."""

import asyncio
import hashlib
import json as _json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

import app.storage.manager as storage
from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.config import settings
from app.database import Database, get_db
from app.models.role import FLAG_ORG_SETTINGS_MANAGE, FLAG_USERS_INVITE_MANAGE, admin_best_tier
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import event_bus, live_settings, sse_broker
from app.util.db import check_admin_setting_lock, get_admin_setting
from app.validation.sanitizers import validate_uuid
from app.wordlist import insert_invite_short_link_with_unique_slug

_bg_tasks: set = set()

router = APIRouter()

_THEME_JSON = "theme.json"
_THEME_JSON_TMP = ".json.tmp"

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


# Allowed admin setting keys and their validators
def _valid_mfa_allowed_methods(v: str) -> bool:
    """Validate mfa_allowed_methods — must be a JSON array of known method strings."""
    import json as _json

    try:
        methods = _json.loads(v)
        if not isinstance(methods, list):
            return False
        allowed = {"totp", "webauthn", "email_otp"}
        return all(isinstance(m, str) and m in allowed for m in methods)
    except Exception:
        return False


_SETTINGS_VALIDATORS = {
    "open_registration": lambda v: v in ("true", "false"),
    "global_max_file_size": lambda v: v.isdigit() and int(v) >= 0,
    "global_bandwidth_limit": lambda v: v.isdigit() and int(v) >= 0,
    "disk_warning_threshold": lambda v: v.isdigit() and 0 <= int(v) <= 100,
    "default_chunk_size": lambda v: v.isdigit() and int(v) >= 65536,
    # MFA enforcement policy
    "mfa_enforcement": lambda v: v in ("off", "optional", "required"),
    "mfa_allowed_methods": _valid_mfa_allowed_methods,
    "mfa_oidc_exempt": lambda v: v in ("0", "1"),
    # Emergency revocation
    "notify_escrow_on_revocation": lambda v: v in ("0", "1"),
    # Escrow coverage enforcement
    "escrow_require_coverage": lambda v: v in ("0", "1"),
    # Self-service account deletion
    "allow_user_delete_own_account": lambda v: v in ("true", "false"),
    "can_delete_owned_shared": lambda v: v in ("true", "false"),
    # Multi-owner teams
    "allow_multi_team_owner": lambda v: v in ("true", "false"),
    # File copy policy
    "copy_boundary": lambda v: v in ("any", "same_team", "disabled"),
    # Audit retention
    "audit_retention_days": lambda v: v.isdigit() and 1 <= int(v) <= 3650,
    # Antivirus / server-side scanning
    # av_scan_endpoint and av_scan_secret: allow any non-empty or empty string
    "av_scan_endpoint": lambda v: len(v) <= 2048,
    "av_scan_secret": lambda v: len(v) <= 512,
    "av_require_clean": lambda v: v in ("true", "false"),
    "av_scan_retry_attempts": lambda v: v.isdigit() and 1 <= int(v) <= 10,
    # First-run wizard completion flag (set by the profile wizard after first profile selection)
    "first_run_completed": lambda v: v in ("0", "1"),
    # Trash / soft-delete
    "trash_enabled": lambda v: v in ("true", "false"),
    "trash_retention_days": lambda v: v.isdigit() and 1 <= int(v) <= 3650,
    # Rate limits (Phase 1)
    "anon_share_upload_rate_limit": lambda v: v.isdigit() and 1 <= int(v) <= 1000,
    "rate_limit_login": lambda v: v.isdigit() and 1 <= int(v) <= 1000,
    "rate_limit_api": lambda v: v.isdigit() and 1 <= int(v) <= 10000,
    "rate_limit_share_create": lambda v: v.isdigit() and 1 <= int(v) <= 1000,
    "rate_limit_upload": lambda v: v.isdigit() and 1 <= int(v) <= 10000,
    "rate_limit_management": lambda v: v.isdigit() and 1 <= int(v) <= 10000,
    "rate_limit_error_threshold": lambda v: v.isdigit() and 0 <= int(v) <= 100,
    "rate_limit_error_window": lambda v: v.isdigit() and 1 <= int(v) <= 3600,
    "rate_limit_escalated_max": lambda v: v.isdigit() and 1 <= int(v) <= 1000,
    "rate_limit_escalated_window": lambda v: v.isdigit() and 1 <= int(v) <= 60,
    "rate_limit_escalated_duration": lambda v: v.isdigit() and 1 <= int(v) <= 86400,
    # Session & auth policy (Phase 2)
    "access_token_expire_minutes": lambda v: v.isdigit() and 1 <= int(v) <= 60,
    "refresh_token_expire_days": lambda v: v.isdigit() and 1 <= int(v) <= 365,
    "session_idle_timeout_minutes": lambda v: v.isdigit() and 1 <= int(v) <= 1440,
    "share_session_expire_hours": lambda v: v.isdigit() and 1 <= int(v) <= 168,
    "public_device_refresh_minutes": lambda v: v.isdigit() and 1 <= int(v) <= 1440,
    "mfa_pending_token_ttl": lambda v: v.isdigit() and 10 <= int(v) <= 600,
    "step_up_window_seconds": lambda v: v.isdigit() and 0 <= int(v) <= 86400,
    "step_up_max_failures": lambda v: v.isdigit() and 1 <= int(v) <= 20,
    # Operational tuning (Phase 3)
    "tus_upload_expiry_hours": lambda v: v.isdigit() and 1 <= int(v) <= 168,
    "upload_evict_stride_mb": lambda v: v.isdigit() and 0 <= int(v) <= 256,
    "webauthn_rp_name": lambda v: 1 <= len(v.strip()) <= 128,
    "allow_http_idp": lambda v: v in ("true", "false"),
}


# Keys whose current values are communicated to clients (via user_response_dict and SSE).
_CLIENT_RELEVANT_SETTINGS = {"rate_limit_upload", "step_up_window_seconds"}


class UpdateSettingsRequest(BaseModel):
    settings: dict[str, str]


class UpdateSettingLocksRequest(BaseModel):
    locks: dict[str, dict]  # key → {is_locked: bool, locked_min_tier: int | None}


@router.get("/settings")
async def get_settings(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get all admin settings including lock metadata."""
    cursor = await db.execute("SELECT key, value, is_locked, locked_min_tier FROM admin_settings")
    rows = await cursor.fetchall()
    return {
        "settings": {
            row["key"]: {
                "value": row["value"],
                "is_locked": bool(row["is_locked"]),
                "locked_min_tier": row["locked_min_tier"],
            }
            for row in rows
        }
    }


@router.put("/settings", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}})
async def update_settings(
    body: UpdateSettingsRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Update admin settings. Locked settings require the caller's tier ≤ locked_min_tier."""
    for key, value in body.settings.items():
        if key not in _SETTINGS_VALIDATORS:
            raise HTTPException(status_code=400, detail=f"Unknown setting: {key}")
        if not _SETTINGS_VALIDATORS[key](value):
            raise HTTPException(status_code=400, detail=f"Invalid value for {key}: {value}")

    admin_tier = admin_best_tier(admin.roles)

    # Fetch current lock state for all keys being modified in one query.
    keys_list = list(body.settings.keys())
    placeholders = ", ".join("?" * len(keys_list))
    cursor = await db.execute(
        f"SELECT key, is_locked, locked_min_tier FROM admin_settings WHERE key IN ({placeholders})",
        tuple(keys_list),
    )
    lock_rows = {row["key"]: row for row in await cursor.fetchall()}
    for key in keys_list:
        check_admin_setting_lock(lock_rows.get(key), admin_tier)

    await db.execute("BEGIN")
    try:
        for key, value in body.settings.items():
            await db.execute(
                "INSERT INTO admin_settings (key, value) VALUES (?, ?)"
                " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
                (key, value),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    live_settings.update_many(body.settings)

    event_bus.emit(
        SecurityEvent(
            event_type="admin.policy.changed",
            severity="warning",
            outcome="success",
            actor=EventActor(user_id=str(admin.id), username=admin.username),
            detail={"keys_changed": list(body.settings.keys())},
        )
    )

    if any(k in _CLIENT_RELEVANT_SETTINGS for k in body.settings):
        sse_broker.publish(
            "broadcast",
            {
                "type": "config_changed",
                "config": {
                    "upload_rate_limit": live_settings.get_int("rate_limit_upload", settings.RATE_LIMIT_UPLOAD),
                    "step_up_window_seconds": live_settings.get_int(
                        "step_up_window_seconds", settings.STEP_UP_WINDOW_SECONDS
                    ),
                },
            },
        )

    return {"message": "Settings updated"}


def _validate_single_lock(key: str, lock_spec: dict, admin_tier: int) -> None:
    if key not in _SETTINGS_VALIDATORS:
        raise HTTPException(status_code=400, detail=f"Unknown setting: {key}")
    new_locked = bool(lock_spec.get("is_locked", False))
    new_min_tier = lock_spec.get("locked_min_tier")
    if new_locked and new_min_tier is not None:
        if not isinstance(new_min_tier, int) or new_min_tier < 1:
            raise HTTPException(status_code=400, detail=f"locked_min_tier must be a positive integer for {key}")
        if new_min_tier < admin_tier:
            raise HTTPException(
                status_code=403,
                detail=f"Cannot lock {key} at tier {new_min_tier} — that would exclude your own tier ({admin_tier})",
            )


@router.put("/settings/locks", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}})
async def update_setting_locks(
    body: UpdateSettingLocksRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Set or clear lock state on admin settings.

    Only admins holding org_settings_manage may call this endpoint.
    An admin can only lock a setting at a tier ≥ their own (they cannot lock
    out themselves or anyone more privileged).
    """
    if not admin.has_flag(FLAG_ORG_SETTINGS_MANAGE):
        raise HTTPException(status_code=403, detail="org_settings_manage required")

    admin_tier = admin_best_tier(admin.roles)

    for key, lock_spec in body.locks.items():
        _validate_single_lock(key, lock_spec, admin_tier)

    await db.execute("BEGIN")
    try:
        for key, lock_spec in body.locks.items():
            new_locked = bool(lock_spec.get("is_locked", False))
            new_min_tier = lock_spec.get("locked_min_tier")
            await db.execute(
                "INSERT INTO admin_settings (key, value, is_locked, locked_min_tier) "
                "VALUES (?, COALESCE((SELECT value FROM admin_settings WHERE key = ?), ''), ?, ?) "
                "ON CONFLICT (key) DO UPDATE SET is_locked = EXCLUDED.is_locked, "
                "locked_min_tier = EXCLUDED.locked_min_tier, updated_at = NOW()",
                (key, key, new_locked, new_min_tier),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    return {"message": "Locks updated"}


# ---------------------------------------------------------------------------
# Disk usage
# ---------------------------------------------------------------------------


@router.get("/disk-usage")
async def get_disk_usage(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get disk usage breakdown: per-user stats + filesystem totals."""
    cursor = await db.execute("SELECT id, username, disk_used, disk_quota FROM users ORDER BY disk_used DESC")
    users = [
        {
            "id": row["id"],
            "username": row["username"],
            "disk_used": row["disk_used"],
            "disk_quota": row["disk_quota"],
        }
        for row in await cursor.fetchall()
    ]

    cursor = await db.execute("SELECT SUM(disk_used) as total FROM users")
    total_used = (await cursor.fetchone())["total"] or 0

    try:
        usage = await storage.get_manager().get_usage_summary()
        fs_total = usage.get("total_capacity_bytes") or 0
        fs_free = max(0, fs_total - (usage.get("total_used_bytes") or 0))
    except Exception:
        fs_total = 0
        fs_free = 0

    thr_val = await get_admin_setting(db, "disk_warning_threshold")
    threshold_pct = int(thr_val) if thr_val is not None else settings.DISK_WARNING_THRESHOLD

    usage_pct = ((fs_total - fs_free) / fs_total * 100) if fs_total > 0 else 0
    warning = usage_pct >= threshold_pct

    return {
        "total_used_bytes": total_used,
        "filesystem_total": fs_total,
        "filesystem_free": fs_free,
        "usage_percent": round(usage_pct, 1),
        "warning_threshold": threshold_pct,
        "warning": warning,
        "users": users,
    }


# ---------------------------------------------------------------------------
# Hardware capability scan
# ---------------------------------------------------------------------------


@router.get("/hw-scan")
async def get_hw_scan(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
):
    """Run a hardware capability scan and return tuning recommendations.

    Probes PBKDF2 throughput, CPU/RAM, and local-volume disk space.
    The scan takes 1–3 s and runs in a thread to avoid blocking the event loop.
    """
    from app.util import hw_scan

    local_volumes = storage.get_manager().local_volumes()
    result = await asyncio.to_thread(hw_scan.run_scan, local_volumes)
    return result


# ---------------------------------------------------------------------------
# Invites
# ---------------------------------------------------------------------------

_INVITE_EXPIRE_HOURS = 24
_INVITE_TOKEN_BYTES = 16  # 128-bit = 22 URL-safe base64 chars


@router.post("/invites", responses={403: {"description": "Forbidden"}})
async def create_invite(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create a single-use registration invite (24-hour expiry).

    The raw token is returned once. The server stores only its SHA-256 hash.
    """
    if not admin.has_flag(FLAG_USERS_INVITE_MANAGE):
        raise HTTPException(status_code=403, detail="users_invite_manage permission required")
    raw_token = secrets.token_urlsafe(_INVITE_TOKEN_BYTES)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invite_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=_INVITE_EXPIRE_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")

    await db.execute(
        "INSERT INTO invites (id, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?)",
        (invite_id, token_hash, admin.id, expires_at),
    )
    await db.commit()

    return {
        "id": invite_id,
        "token": raw_token,
        "expires_at": expires_at,
    }


@router.get("/invites")
async def list_invites(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all invites (pending and used), most recent first."""
    cursor = await db.execute(
        """
        SELECT i.id, i.created_by, i.expires_at, i.used_at, i.used_by_ip,
               i.used_by_user_id, u.username AS used_by_username, i.created_at
        FROM invites i
        LEFT JOIN users u ON u.id = i.used_by_user_id
        ORDER BY i.created_at DESC
        """
    )
    rows = await cursor.fetchall()
    return {
        "invites": [
            {
                "id": row["id"],
                "created_by": row["created_by"],
                "expires_at": row["expires_at"],
                "used_at": row["used_at"],
                "used_by_ip": row["used_by_ip"],
                "used_by_user_id": row["used_by_user_id"],
                "used_by_username": row["used_by_username"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


@router.delete("/invites/{invite_id}", responses={404: {"description": "Not Found"}})
async def revoke_invite(
    invite_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Revoke a pending (unused) invite."""
    invite_id = validate_uuid(invite_id)

    result = await db.execute(
        "DELETE FROM invites WHERE id = ? AND used_at IS NULL",
        (invite_id,),
    )
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Invite not found or already used")

    return {"message": "Invite revoked"}


# ---------------------------------------------------------------------------
# Theme hot-reload
# ---------------------------------------------------------------------------


@router.post("/theme/reload")
async def reload_theme(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
):
    """Hot-reload DATA_DIR/theme.json without restarting the server.

    Re-reads and validates theme.json, injects updated CSS variable overrides
    into index.html.  The next page load will pick up the new theme.
    """
    from pathlib import Path as _Path

    from app.util.theme import get_theme_config, inject_theme

    frontend_dir = _Path(__file__).parent.parent.parent / "frontend"
    inject_theme(frontend_dir, settings.DATA_DIR)

    config = get_theme_config()
    return {
        "message": "Theme reloaded",
        "brand_name": config.get("brand_name"),
        "has_logo": "logo_path" in config,
        "color_overrides": len(config.get("colors", {})),
    }


class UpdateThemeRequest(BaseModel):
    brand_name: str | None = None
    ui: dict[str, bool] | None = None


@router.patch("/theme", responses={400: {"description": "Bad Request"}, 500: {"description": "Internal Server Error"}})
async def update_theme(
    body: UpdateThemeRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
):
    """Update theme.json brand_name and/or ui flags and hot-reload.

    Reads existing theme.json, merges supplied fields, writes atomically,
    then triggers an in-process reload so the change is live immediately.
    """
    from pathlib import Path as _Path

    from app.util.theme import (
        _BRAND_NAME_MAX,
        _UI_FLAG_DEFAULTS,
        inject_theme,
        load_theme,
    )

    path = settings.DATA_DIR / _THEME_JSON
    existing: dict = {}
    if path.exists():
        try:
            existing = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    if body.brand_name is not None:
        if not (1 <= len(body.brand_name) <= _BRAND_NAME_MAX):
            raise HTTPException(
                status_code=400,
                detail=f"brand_name must be 1–{_BRAND_NAME_MAX} chars",
            )
        existing["brand_name"] = body.brand_name

    if body.ui is not None:
        ui_block = existing.get("ui", {})
        for key, val in body.ui.items():
            if key not in _UI_FLAG_DEFAULTS:
                raise HTTPException(status_code=400, detail=f"Unknown ui flag: {key!r}")
            ui_block[key] = bool(val)
        existing["ui"] = ui_block

    tmp = path.with_suffix(_THEME_JSON_TMP)
    try:
        tmp.write_text(_json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write theme.json: {exc}")

    frontend_dir = _Path(__file__).parent.parent.parent / "frontend"
    inject_theme(frontend_dir, settings.DATA_DIR)
    config = load_theme(settings.DATA_DIR)

    return {
        "message": "Theme updated",
        "brand_name": config.get("brand_name"),
        "has_logo": "logo_path" in config,
        "color_overrides": len(config.get("colors", {})),
    }


_LOGO_MAX_BYTES = 2 * 1024 * 1024  # 2 MB
# SVG excluded: it is XML text without a binary magic signature and can contain
# embedded scripts that execute when served from the app's origin.
_LOGO_ALLOWED_MIME: frozenset[str] = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
    }
)

_FAVICON_MAX_BYTES = 256 * 1024  # 256 KB
_FAVICON_ALLOWED_MIME: frozenset[str] = frozenset(
    {
        "image/png",
        "image/x-icon",
        "image/vnd.microsoft.icon",
    }
)


@router.post(
    "/theme/logo",
    responses={
        400: {"description": "Bad Request"},
        413: {"description": "413"},
        500: {"description": "Internal Server Error"},
    },
)
async def upload_theme_logo(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    file: Annotated[UploadFile, File(...)],
):
    """Upload an org logo to DATA_DIR and wire it into theme.json.

    Filename is sanitised; only image MIME types are accepted.  Triggers a
    hot-reload after saving.
    """
    import re as _re
    from pathlib import Path as _Path

    import filetype as _filetype

    from app.util.theme import (
        _LOGO_FILENAME_RE,
        inject_theme,
        load_theme,
    )

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    # Sanitise filename to prevent path traversal
    safe_name = _re.sub(r"[^a-zA-Z0-9._-]", "_", file.filename)
    if not _LOGO_FILENAME_RE.match(safe_name):
        raise HTTPException(status_code=400, detail="Invalid logo filename")

    data = await file.read(_LOGO_MAX_BYTES + 1)
    if len(data) > _LOGO_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Logo must be ≤ 2 MB")

    # Verify actual content type via magic bytes (extension alone is not trusted)
    detected = _filetype.guess(data[:512])
    if detected is None or detected.mime not in _LOGO_ALLOWED_MIME:
        raise HTTPException(
            status_code=400,
            detail="Logo must be PNG, JPEG, GIF, or WebP (SVG is not accepted)",
        )

    dest = settings.DATA_DIR / safe_name
    try:
        dest.write_bytes(data)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save logo: {exc}")

    # Write logo_path into theme.json
    path = settings.DATA_DIR / _THEME_JSON
    existing: dict = {}
    if path.exists():
        try:
            existing = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing["logo_path"] = safe_name

    tmp = path.with_suffix(_THEME_JSON_TMP)
    try:
        tmp.write_text(_json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update theme.json: {exc}")

    frontend_dir = _Path(__file__).parent.parent.parent / "frontend"
    inject_theme(frontend_dir, settings.DATA_DIR)
    load_theme(settings.DATA_DIR)

    return {"message": "Logo uploaded", "logo_path": safe_name, "logo_url": "/api/v1/theme/logo"}


@router.post(
    "/theme/favicon",
    responses={
        400: {"description": "Bad Request"},
        413: {"description": "413"},
        500: {"description": "Internal Server Error"},
    },
)
async def upload_theme_favicon(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    file: Annotated[UploadFile, File(...)],
):
    """Upload an org favicon to DATA_DIR and wire it into theme.json.

    Accepts PNG, ICO, and SVG.  Max 256 KB.  Triggers a hot-reload after saving.
    """
    import re as _re
    from pathlib import Path as _Path

    import filetype as _filetype

    from app.util.theme import _LOGO_FILENAME_RE, inject_theme, load_theme

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    safe_name = _re.sub(r"[^a-zA-Z0-9._-]", "_", file.filename)
    if not _LOGO_FILENAME_RE.match(safe_name):
        raise HTTPException(status_code=400, detail="Invalid favicon filename")

    data = await file.read(_FAVICON_MAX_BYTES + 1)
    if len(data) > _FAVICON_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Favicon must be ≤ 256 KB")

    detected = _filetype.guess(data[:512])
    if detected is None or detected.mime not in _FAVICON_ALLOWED_MIME:
        raise HTTPException(
            status_code=400,
            detail="Favicon must be PNG or ICO (SVG is not accepted)",
        )

    dest = settings.DATA_DIR / safe_name
    try:
        dest.write_bytes(data)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save favicon: {exc}")

    path = settings.DATA_DIR / _THEME_JSON
    existing: dict = {}
    if path.exists():
        try:
            existing = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing["favicon_path"] = safe_name

    tmp = path.with_suffix(_THEME_JSON_TMP)
    try:
        tmp.write_text(_json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update theme.json: {exc}")

    frontend_dir = _Path(__file__).parent.parent.parent / "frontend"
    inject_theme(frontend_dir, settings.DATA_DIR)
    load_theme(settings.DATA_DIR)

    return {"message": "Favicon uploaded", "favicon_path": safe_name, "favicon_url": "/api/v1/theme/favicon"}


class CreateInviteShortLinkRequest(BaseModel):
    token: str
    expires_at: str


@router.post(
    "/invites/{invite_id}/short-link", responses={404: {"description": "Not Found"}, 503: {"description": "503"}}
)
async def create_invite_short_link(
    invite_id: str,
    body: CreateInviteShortLinkRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Generate a memorable 3-word short link for an existing pending invite.

    The raw token is stored temporarily in invite_short_links so that the slug
    can redirect to /register/<token>.  The row is deleted automatically when
    the invite is used or revoked (ON DELETE CASCADE).
    """
    invite_id = validate_uuid(invite_id)

    # Verify the invite exists, is pending, and the supplied token matches
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    cursor = await db.execute(
        "SELECT id, expires_at FROM invites WHERE id = ? AND token_hash = ? AND used_at IS NULL",
        (invite_id, token_hash),
    )
    invite = await cursor.fetchone()
    if invite is None:
        raise HTTPException(status_code=404, detail="Invite not found or already used")

    link_id = str(uuid.uuid4())
    try:
        slug = await insert_invite_short_link_with_unique_slug(
            db,
            link_id=link_id,
            invite_id=invite_id,
            token=body.token,
            expires_at=body.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {"slug": slug, "link_id": link_id, "expires_at": body.expires_at}


# ---------------------------------------------------------------------------
# Antivirus / server-side scanning
# ---------------------------------------------------------------------------


@router.get("/files/av-status")
async def get_av_status(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return per-status counts of files for the AV status dashboard."""
    cursor = await db.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE av_scan_status IS NULL)         AS null_count,
            COUNT(*) FILTER (WHERE av_scan_status = 'pending')     AS pending_count,
            COUNT(*) FILTER (WHERE av_scan_status = 'clean')       AS clean_count,
            COUNT(*) FILTER (WHERE av_scan_status = 'infected')    AS infected_count,
            COUNT(*) FILTER (WHERE av_scan_status = 'error')       AS error_count
        FROM files WHERE upload_complete = 1
        """
    )
    row = await cursor.fetchone()
    return {
        "null": row["null_count"] or 0,
        "pending": row["pending_count"] or 0,
        "clean": row["clean_count"] or 0,
        "infected": row["infected_count"] or 0,
        "error": row["error_count"] or 0,
    }


@router.post("/files/av-rescan", responses={501: {"description": "501"}})
async def bulk_av_rescan(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Queue background AV scan tasks for all null/error-status files.

    Returns 501 when TUSSHARE_ESCROW_PRIVATE_KEY is not configured (no-op
    would silently do nothing, which is worse than a clear error).
    """
    from app.services.av_scanner import get_escrow_public_key_b64

    if get_escrow_public_key_b64() is None:
        raise HTTPException(
            status_code=501,
            detail="TUSSHARE_ESCROW_PRIVATE_KEY is not configured; server-side AV scanning is unavailable",
        )

    cursor = await db.execute(
        "SELECT id FROM files WHERE upload_complete = 1   AND (av_scan_status IS NULL OR av_scan_status = 'error')"
    )
    rows = await cursor.fetchall()
    queued = 0
    for row in rows:
        _t = asyncio.create_task(_bg_scan(row["id"]))
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)
        queued += 1

    return {"queued": queued}


async def _bg_scan(file_id: str) -> None:
    from app.database import db_session
    from app.services.av_scanner import scan_file

    try:
        async with db_session() as _db:
            await scan_file(_db, file_id)
    except Exception as exc:
        import logging

        logging.getLogger(__name__).warning("Bulk rescan failed for file %s: %s", file_id, exc)
