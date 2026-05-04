"""Admin settings, disk usage, and invite management routes."""

import asyncio
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import json as _json
import mimetypes

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.config import settings
from app.models.role import FLAG_MANAGE_INVITES
from app.database import get_db
import app.storage.manager as storage
from app.validation.sanitizers import validate_uuid
from app.wordlist import insert_invite_short_link_with_unique_slug

router = APIRouter()

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
    "open_registration":      lambda v: v in ("true", "false"),
    "global_max_file_size":   lambda v: v.isdigit() and int(v) >= 0,
    "global_bandwidth_limit": lambda v: v.isdigit() and int(v) >= 0,
    "disk_warning_threshold": lambda v: v.isdigit() and 0 <= int(v) <= 100,
    "default_chunk_size":     lambda v: v.isdigit() and int(v) >= 65536,
    # MFA enforcement policy
    "mfa_enforcement":        lambda v: v in ("off", "optional", "required"),
    "mfa_allowed_methods":    _valid_mfa_allowed_methods,
    "mfa_oidc_exempt":        lambda v: v in ("0", "1"),
    # Emergency revocation
    "notify_escrow_on_revocation": lambda v: v in ("0", "1"),
    # Self-service account deletion
    "allow_user_delete_own_account": lambda v: v in ("true", "false"),
    "can_delete_owned_shared":       lambda v: v in ("true", "false"),
    # Multi-owner teams
    "allow_multi_team_owner":        lambda v: v in ("true", "false"),
    # File copy policy
    "copy_boundary":                 lambda v: v in ("any", "same_team", "disabled"),
    # Audit retention
    "audit_retention_days":   lambda v: v.isdigit() and 1 <= int(v) <= 3650,
    # Antivirus / server-side scanning
    # av_scan_endpoint and av_scan_secret: allow any non-empty or empty string
    "av_scan_endpoint":       lambda v: len(v) <= 2048,
    "av_scan_secret":         lambda v: len(v) <= 512,
    "av_require_clean":       lambda v: v in ("true", "false"),
    "av_scan_retry_attempts": lambda v: v.isdigit() and 1 <= int(v) <= 10,
    # First-run wizard completion flag (set by the profile wizard after first profile selection)
    "first_run_completed":    lambda v: v in ("0", "1"),
    # Trash / soft-delete
    "trash_enabled":          lambda v: v in ("true", "false"),
    "trash_retention_days":   lambda v: v.isdigit() and 1 <= int(v) <= 3650,
}


class UpdateSettingsRequest(BaseModel):
    settings: dict[str, str]


@router.get("/settings")
async def get_settings(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Get all admin settings."""
    cursor = await db.execute("SELECT key, value FROM admin_settings")
    rows = await cursor.fetchall()
    return {"settings": {row["key"]: row["value"] for row in rows}}


@router.put("/settings")
async def update_settings(
    body: UpdateSettingsRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Update admin settings. All updates are applied atomically."""
    for key, value in body.settings.items():
        if key not in _SETTINGS_VALIDATORS:
            raise HTTPException(status_code=400, detail=f"Unknown setting: {key}")
        if not _SETTINGS_VALIDATORS[key](value):
            raise HTTPException(status_code=400, detail=f"Invalid value for {key}: {value}")

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

    return {"message": "Settings updated"}


# ---------------------------------------------------------------------------
# Disk usage
# ---------------------------------------------------------------------------

@router.get("/disk-usage")
async def get_disk_usage(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Get disk usage breakdown: per-user stats + filesystem totals."""
    cursor = await db.execute(
        "SELECT id, username, disk_used, disk_quota FROM users ORDER BY disk_used DESC"
    )
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
        fs_free  = max(0, fs_total - (usage.get("total_used_bytes") or 0))
    except Exception:
        fs_total = 0
        fs_free  = 0

    cursor = await db.execute(
        "SELECT value FROM admin_settings WHERE key = 'disk_warning_threshold'"
    )
    threshold_row = await cursor.fetchone()
    threshold_pct = int(threshold_row["value"]) if threshold_row else settings.DISK_WARNING_THRESHOLD

    usage_pct = ((fs_total - fs_free) / fs_total * 100) if fs_total > 0 else 0
    warning   = usage_pct >= threshold_pct

    return {
        "total_used_bytes":  total_used,
        "filesystem_total":  fs_total,
        "filesystem_free":   fs_free,
        "usage_percent":     round(usage_pct, 1),
        "warning_threshold": threshold_pct,
        "warning":           warning,
        "users":             users,
    }


# ---------------------------------------------------------------------------
# Hardware capability scan
# ---------------------------------------------------------------------------

@router.get("/hw-scan")
async def get_hw_scan(
    admin: AuthenticatedUser = Depends(require_admin),
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

_INVITE_EXPIRE_HOURS  = 24
_INVITE_TOKEN_BYTES   = 16   # 128-bit = 22 URL-safe base64 chars


@router.post("/invites")
async def create_invite(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Create a single-use registration invite (24-hour expiry).

    The raw token is returned once. The server stores only its SHA-256 hash.
    """
    if not admin.has_flag(FLAG_MANAGE_INVITES):
        raise HTTPException(status_code=403, detail="can_manage_invites permission required")
    raw_token  = secrets.token_urlsafe(_INVITE_TOKEN_BYTES)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invite_id  = str(uuid.uuid4())
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=_INVITE_EXPIRE_HOURS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    await db.execute(
        "INSERT INTO invites (id, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?)",
        (invite_id, token_hash, admin.id, expires_at),
    )
    await db.commit()

    return {
        "id":         invite_id,
        "token":      raw_token,
        "expires_at": expires_at,
    }


@router.get("/invites")
async def list_invites(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
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
                "id":                row["id"],
                "created_by":        row["created_by"],
                "expires_at":        row["expires_at"],
                "used_at":           row["used_at"],
                "used_by_ip":        row["used_by_ip"],
                "used_by_user_id":   row["used_by_user_id"],
                "used_by_username":  row["used_by_username"],
                "created_at":        row["created_at"],
            }
            for row in rows
        ]
    }


@router.delete("/invites/{invite_id}")
async def revoke_invite(
    invite_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
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
    admin: AuthenticatedUser = Depends(require_admin),
):
    """Hot-reload DATA_DIR/theme.json without restarting the server.

    Re-reads and validates theme.json, injects updated CSS variable overrides
    into index.html.  The next page load will pick up the new theme.
    """
    from pathlib import Path as _Path
    from app.util.theme import inject_theme, get_theme_config

    frontend_dir = _Path(__file__).parent.parent.parent / "frontend"
    inject_theme(frontend_dir, settings.DATA_DIR)

    config = get_theme_config()
    return {
        "message":         "Theme reloaded",
        "brand_name":      config.get("brand_name"),
        "has_logo":        "logo_path" in config,
        "color_overrides": len(config.get("colors", {})),
    }


class UpdateThemeRequest(BaseModel):
    brand_name: str | None = None
    ui: dict[str, bool] | None = None


@router.patch("/theme")
async def update_theme(
    body: UpdateThemeRequest,
    admin: AuthenticatedUser = Depends(require_admin),
):
    """Update theme.json brand_name and/or ui flags and hot-reload.

    Reads existing theme.json, merges supplied fields, writes atomically,
    then triggers an in-process reload so the change is live immediately.
    """
    from pathlib import Path as _Path
    from app.util.theme import (
        inject_theme, load_theme, _BRAND_NAME_MAX, _UI_FLAG_DEFAULTS,
    )

    path = settings.DATA_DIR / "theme.json"
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

    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.write_text(_json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write theme.json: {exc}")

    frontend_dir = _Path(__file__).parent.parent.parent / "frontend"
    inject_theme(frontend_dir, settings.DATA_DIR)
    config = load_theme(settings.DATA_DIR)

    return {
        "message":         "Theme updated",
        "brand_name":      config.get("brand_name"),
        "has_logo":        "logo_path" in config,
        "color_overrides": len(config.get("colors", {})),
    }


_LOGO_MAX_BYTES = 2 * 1024 * 1024  # 2 MB
_LOGO_ALLOWED_MIME: frozenset[str] = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/svg+xml", "image/webp",
})


@router.post("/theme/logo")
async def upload_theme_logo(
    file: UploadFile = File(...),
    admin: AuthenticatedUser = Depends(require_admin),
):
    """Upload an org logo to DATA_DIR and wire it into theme.json.

    Filename is sanitised; only image MIME types are accepted.  Triggers a
    hot-reload after saving.
    """
    import re as _re
    from pathlib import Path as _Path
    from app.util.theme import (
        inject_theme, load_theme, _LOGO_FILENAME_RE, _BRAND_NAME_MAX,
        _UI_FLAG_DEFAULTS,
    )

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    content_type, _ = mimetypes.guess_type(file.filename)
    if content_type not in _LOGO_ALLOWED_MIME:
        raise HTTPException(
            status_code=400,
            detail="Logo must be PNG, JPEG, GIF, SVG, or WebP",
        )

    # Sanitise filename to prevent path traversal
    safe_name = _re.sub(r"[^a-zA-Z0-9._-]", "_", file.filename)
    if not _LOGO_FILENAME_RE.match(safe_name):
        raise HTTPException(status_code=400, detail="Invalid logo filename")

    data = await file.read(_LOGO_MAX_BYTES + 1)
    if len(data) > _LOGO_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Logo must be ≤ 2 MB")

    dest = settings.DATA_DIR / safe_name
    try:
        dest.write_bytes(data)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save logo: {exc}")

    # Write logo_path into theme.json
    path = settings.DATA_DIR / "theme.json"
    existing: dict = {}
    if path.exists():
        try:
            existing = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing["logo_path"] = safe_name

    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.write_text(_json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update theme.json: {exc}")

    frontend_dir = _Path(__file__).parent.parent.parent / "frontend"
    inject_theme(frontend_dir, settings.DATA_DIR)
    load_theme(settings.DATA_DIR)

    return {"message": "Logo uploaded", "logo_path": safe_name, "logo_url": "/api/v1/theme/logo"}


class CreateInviteShortLinkRequest(BaseModel):
    token: str
    expires_at: str


@router.post("/invites/{invite_id}/short-link")
async def create_invite_short_link(
    invite_id: str,
    body: CreateInviteShortLinkRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
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
        "SELECT id, expires_at FROM invites "
        "WHERE id = ? AND token_hash = ? AND used_at IS NULL",
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
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
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
        "null":     row["null_count"]     or 0,
        "pending":  row["pending_count"]  or 0,
        "clean":    row["clean_count"]    or 0,
        "infected": row["infected_count"] or 0,
        "error":    row["error_count"]    or 0,
    }


@router.post("/files/av-rescan")
async def bulk_av_rescan(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Queue background AV scan tasks for all null/error-status files.

    Returns 501 when TUSSHARE_ESCROW_PRIVATE_KEY is not configured (no-op
    would silently do nothing, which is worse than a clear error).
    """
    from app.services.av_scanner import get_escrow_public_key_b64, scan_file
    if get_escrow_public_key_b64() is None:
        raise HTTPException(
            status_code=501,
            detail="TUSSHARE_ESCROW_PRIVATE_KEY is not configured; server-side AV scanning is unavailable",
        )

    cursor = await db.execute(
        "SELECT id FROM files "
        "WHERE upload_complete = 1 "
        "  AND (av_scan_status IS NULL OR av_scan_status = 'error')"
    )
    rows = await cursor.fetchall()
    queued = 0
    for row in rows:
        asyncio.create_task(_bg_scan(row["id"]))
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
