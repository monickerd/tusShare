"""Admin settings, disk usage, and invite management routes."""

import asyncio
import hashlib
import secrets
import shutil
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.config import settings
from app.database import get_db
from app.validation.sanitizers import validate_uuid
from app.wordlist import insert_invite_short_link_with_unique_slug

router = APIRouter()

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

# Allowed admin setting keys and their validators
_SETTINGS_VALIDATORS = {
    "open_registration":      lambda v: v in ("true", "false"),
    "global_max_file_size":   lambda v: v.isdigit() and int(v) >= 0,
    "global_bandwidth_limit": lambda v: v.isdigit() and int(v) >= 0,
    "disk_warning_threshold": lambda v: v.isdigit() and 0 <= int(v) <= 100,
    "default_chunk_size":     lambda v: v.isdigit() and int(v) >= 1_048_576,
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
                "UPDATE admin_settings SET value = ?, updated_at = NOW() WHERE key = ?",
                (value, key),
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
        disk = await asyncio.to_thread(shutil.disk_usage, str(settings.DATA_DIR))
        fs_total = disk.total
        fs_free  = disk.free
    except OSError:
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
        "SELECT id, created_by, expires_at, used_at, used_by_ip, created_at "
        "FROM invites ORDER BY created_at DESC"
    )
    rows = await cursor.fetchall()
    return {
        "invites": [
            {
                "id":          row["id"],
                "created_by":  row["created_by"],
                "expires_at":  row["expires_at"],
                "used_at":     row["used_at"],
                "used_by_ip":  row["used_by_ip"],
                "created_at":  row["created_at"],
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
