"""Share management and public access routes.

Includes:
- /api/v1/shares/*              — authenticated share CRUD
- /s/{token}                    — public share resolution
- /s/{token}/files/{id}/chunks  — chunk manifest for shared file (public)
- /s/{token}/files/{id}/content — stream shared file (public)
- /l/{slug}                     — short link resolution (public)
"""

import asyncio
import logging
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.auth.dependencies import get_optional_user, require_user_role
from app.auth.interface import AuthenticatedUser
from app.auth.jwt import create_share_session_token, verify_share_session_token
from app.database import Database, db_session, get_db
import app.storage.manager as storage
from app.middleware.rate_limit import check_management_rate_limit, _counter
from app.models.file import FileChunk
from app.validation.sanitizers import (
    sanitize_filename,
    sanitize_username,
    validate_base64,
    validate_share_token,
    validate_short_slug,
    validate_uuid,
)
from app.config import settings
from app.routes._access import check_data_permission, is_in_shared_tree, is_team_folder_member, _team_level_for_user
from app.conf.teams import TEAM_ROLE_SUPERVISOR, TEAM_ROLE_OWNER
from app.util.http import content_disposition, parse_range_header
from app.util.db import get_admin_setting
from app.services.sharing_rules import check_sharing_flags, evaluate_sharing_rules
from app.services import event_bus
from app.schemas.security_event import EventActor, SecurityEvent
from app.wordlist import insert_short_link_with_unique_slug
from typing import Annotated


_UTC_OFFSET = "+00:00"
_ERR_SHARE_NOT_FOUND = "Share not found or expired"
_ERR_SHARE_NOT_FOUND_SIMPLE = "Share not found"
_ERR_ACCESS_DENIED = "Access denied"
_SQL_GET_SHARE_BY_ID = "SELECT * FROM shares WHERE id = ?"

_bg_tasks: set = set()

logger = logging.getLogger(__name__)

router = APIRouter()

# Maximum number of files in one share
_SHARE_MAX_ITEMS = 100


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class _ShareItemIn(BaseModel):
    resource_type: str
    resource_id: str
    encrypted_file_key: str
    key_iv: str
    # KEM fields for user-type shares (NULL for link shares)
    ephemeral_x25519_pub: str | None = None
    kem_ciphertext: str | None = None

    @field_validator("resource_type")
    @classmethod
    def validate_rtype(cls, v: str) -> str:
        if v != "file":
            raise ValueError("resource_type must be 'file'")
        return v

    @field_validator("resource_id")
    @classmethod
    def validate_rid(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("encrypted_file_key", "key_iv")
    @classmethod
    def validate_blobs(cls, v: str) -> str:
        return validate_base64(v)

    @field_validator("ephemeral_x25519_pub")
    @classmethod
    def validate_x25519(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=60)
        return v

    @field_validator("kem_ciphertext")
    @classmethod
    def validate_kem(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=1500)
        return v


_SHARE_UPLOAD_DEFAULT_BUDGET = 100 * 1024 * 1024   # 100 MB


class CreateShareRequest(BaseModel):
    items: list[_ShareItemIn]
    share_type: str = "link"
    recipient_username: str | None = None
    expires_at: str | None = None
    max_downloads: int | None = None
    allow_upload: bool = False
    upload_max_bytes: int | None = None   # None → server chooses (min of default and available quota)
    target_folder_id: str | None = None
    client_token: str | None = None

    @field_validator("client_token")
    @classmethod
    def validate_client_token(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                return validate_share_token(v)
            except ValueError as exc:
                raise ValueError(str(exc))
        return v

    @field_validator("share_type")
    @classmethod
    def validate_share_type(cls, v: str) -> str:
        if v not in ("link", "user"):
            raise ValueError("share_type must be 'link' or 'user'")
        return v

    @field_validator("recipient_username")
    @classmethod
    def validate_recipient(cls, v: str | None) -> str | None:
        if v is not None:
            return sanitize_username(v)
        return v

    @field_validator("items")
    @classmethod
    def validate_items(cls, v: list) -> list:
        if len(v) > _SHARE_MAX_ITEMS:
            raise ValueError(f"Share cannot contain more than {_SHARE_MAX_ITEMS} files")
        return v

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                dt = datetime.fromisoformat(v.replace("Z", _UTC_OFFSET))
                if dt <= datetime.now(timezone.utc):
                    raise ValueError("expires_at must be in the future")
            except ValueError as exc:
                raise ValueError(str(exc))
        return v

    @field_validator("max_downloads")
    @classmethod
    def validate_max_downloads(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 10_000):
            raise ValueError("max_downloads must be 1–10000")
        return v

    @field_validator("target_folder_id")
    @classmethod
    def validate_target_folder(cls, v: str | None) -> str | None:
        if v is not None:
            return validate_uuid(v)
        return v


class UpdateShareRequest(BaseModel):
    is_active: bool | None = None
    expires_at: str | None = None
    max_downloads: int | None = None

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                datetime.fromisoformat(v.replace("Z", _UTC_OFFSET))
            except ValueError as exc:
                raise ValueError(f"Invalid expires_at: {exc}")
        return v

    @field_validator("max_downloads")
    @classmethod
    def validate_max_downloads(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 10_000):
            raise ValueError("max_downloads must be 1–10000")
        return v


class CreateShortLinkRequest(BaseModel):
    expires_at: str
    share_key: str  # AES share key (base64url) — stored server-side for root-level redirect

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: str) -> str:
        try:
            dt = datetime.fromisoformat(v.replace("Z", _UTC_OFFSET))
            if dt <= datetime.now(timezone.utc):
                raise ValueError("expires_at must be in the future")
        except ValueError as exc:
            raise ValueError(str(exc))
        return v

    @field_validator("share_key")
    @classmethod
    def validate_share_key(cls, v: str) -> str:
        return validate_base64(v, max_length=64)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

async def _get_share_for_owner(db, share_id: str, user: AuthenticatedUser):
    """Fetch a share by ID, verifying the requester is the owner or an admin."""
    cursor = await db.execute(_SQL_GET_SHARE_BY_ID, (share_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SHARE_NOT_FOUND_SIMPLE)
    if row["created_by"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)
    return row


async def _get_share_for_manage(db, share_id: str, user: AuthenticatedUser):
    """Fetch a share by ID, verifying the requester may manage it (owner, admin, or team supervisor+)."""
    cursor = await db.execute(_SQL_GET_SHARE_BY_ID, (share_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SHARE_NOT_FOUND_SIMPLE)
    if not await _can_manage_share(db, row, user):
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)
    return row


async def _get_folder_team_id(db, folder_id: str) -> str | None:
    """Return the team_id if folder_id is a team folder root, else None."""
    if not folder_id:
        return None
    cursor = await db.execute("SELECT team_id FROM team_folders WHERE folder_id = ?", (folder_id,))
    row = await cursor.fetchone()
    return row["team_id"] if row else None


async def _can_manage_share(db, share: dict, user: AuthenticatedUser) -> bool:
    """True if user may update or delete this share.

    Allowed when the user is:
    - the share creator, OR
    - a global admin, OR
    - a member with write or admin level in the team that owns the share's target folder
      (i.e. supervisors and owners, not read-only members).
    """
    if share["created_by"] == user.id or user.is_admin:
        return True
    if share["target_folder_id"]:
        team_id = await _get_folder_team_id(db, share["target_folder_id"])
        if team_id:
            level = await _team_level_for_user(db, team_id, user.id)
            if level in ("admin", "write"):
                return True
    return False


async def _get_active_share_by_token(db, token: str):
    """Fetch an active, non-expired share by its token. Raises 404 otherwise."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = await db.execute(
        "SELECT * FROM shares WHERE token = ? AND is_active = 1 "
        "AND (expires_at IS NULL OR expires_at > ?)",
        (token, now),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SHARE_NOT_FOUND)
    return row


async def _get_items_with_files(
    db, share_id: str, folder_id: str | None = None
) -> list[dict]:
    """Return share items joined with file metadata for file-type items.

    Returns the share-item encrypted_file_key (re-encrypted with shareKey),
    never the file's original key (encrypted with the owner's masterKey).

    When folder_id is given (folder shares) the query is driven from the
    files table so that deletions are reflected immediately and only files
    that currently exist are returned.
    """
    if folder_id:
        cursor = await db.execute(
            """
            SELECT si.id          AS item_id,
                   'file'         AS resource_type,
                   f.id           AS resource_id,
                   si.encrypted_file_key,
                   si.key_iv,
                   si.ephemeral_x25519_pub,
                   si.kem_ciphertext,
                   f.original_name,
                   f.size_bytes,
                   f.mime_type,
                   f.total_chunks
            FROM files f
            JOIN share_items si
                ON si.share_id = ?
               AND si.resource_type = 'file'
               AND si.resource_id = f.id
            WHERE f.folder_id = ?
              AND f.upload_complete = 1
              AND f.deleted_at IS NULL
            """,
            (share_id, folder_id),
        )
    else:
        cursor = await db.execute(
            """
            SELECT si.id          AS item_id,
                   si.resource_type,
                   si.resource_id,
                   si.encrypted_file_key,
                   si.key_iv,
                   si.ephemeral_x25519_pub,
                   si.kem_ciphertext,
                   f.original_name,
                   f.size_bytes,
                   f.mime_type,
                   f.total_chunks
            FROM share_items si
            JOIN files f
                ON si.resource_type = 'file'
               AND si.resource_id = f.id
               AND f.upload_complete = 1
            WHERE si.share_id = ?
            """,
            (share_id,),
        )
    rows = await cursor.fetchall()
    return [
        {
            "item_id": r["item_id"],
            "resource_type": r["resource_type"],
            "resource_id": r["resource_id"],
            "encrypted_file_key": r["encrypted_file_key"],
            "key_iv": r["key_iv"],
            "ephemeral_x25519_pub": r["ephemeral_x25519_pub"],
            "kem_ciphertext": r["kem_ciphertext"],
            "file_name": r["original_name"],
            "size_bytes": r["size_bytes"],
            "mime_type": r["mime_type"],
            "total_chunks": r["total_chunks"],
        }
        for r in rows
    ]


async def _verify_file_in_share(db, share_id: str, file_id: str) -> None:
    """Raise 403 if the file is not included in the share."""
    cursor = await db.execute(
        "SELECT id FROM share_items "
        "WHERE share_id = ? AND resource_type = 'file' AND resource_id = ?",
        (share_id, file_id),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=403, detail="File not in share")


async def _verify_creator_still_has_access(
    db,
    share_id: str,
    creator_id: str,
) -> None:
    """Raise 404 if the share creator no longer has access to any file in the share.

    Called at every share resolution. This enforces that moving a file out of a
    team folder invalidates share links created by team members who no longer have
    access — e.g., if a file is moved from a shared folder to a private location,
    existing share links from non-owner team members stop resolving immediately.

    File owners always retain access to their own files regardless of location.
    """
    cursor = await db.execute(
        "SELECT resource_id FROM share_items "
        "WHERE share_id = ? AND resource_type = 'file'",
        (share_id,),
    )
    file_ids = [r["resource_id"] for r in await cursor.fetchall()]

    for file_id in file_ids:
        cursor = await db.execute(
            "SELECT owner_id, folder_id FROM files WHERE id = ? AND upload_complete = 1",
            (file_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Shared file no longer exists")
        if row["owner_id"] == creator_id:
            continue  # Owner always has access to their own file
        # Non-owner creator: use the full Phase 1 ACL chain (respects explicit denies)
        has_access = await check_data_permission(db, "file", file_id, creator_id, "read")
        if not has_access:
            raise HTTPException(
                status_code=404,
                detail="Share is no longer available",
            )


async def _log_share_access(
    db,
    request: Request,
    user_id: str | None,
    share_id: str,
    file_id: str | None,
    username: str | None = None,
    auth_method: str | None = None,
    action: str = "download",
) -> None:
    """Log a share access event. Best-effort — never raises."""
    try:
        ip = _get_share_client_ip(request)[:64]
        ua = (request.headers.get("User-Agent") or "")[:512]
        actor_username = username if user_id else "external"
        log_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO access_logs
                (id, file_id, user_id, actor_username, actor_auth_method,
                 share_id, ip_address, user_agent, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (log_id, file_id, user_id, actor_username, auth_method, share_id, ip, ua, action),
        )
        await db.commit()
    except Exception:
        logger.warning("Failed to write share access log for share %s", share_id)


def _get_share_client_ip(request: Request) -> str:
    """Extract the canonical client IP for share session token binding."""
    ip = (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get(settings.TRUSTED_IP_HEADER, "")
        or (request.client.host if request.client else "unknown")
    )
    return ip.split(",")[0].strip() or "unknown"


def _require_share_access(
    request: Request,
    share_id: str,
    user: AuthenticatedUser | None,
) -> None:
    """Require either an authenticated session OR a valid share session token.

    Authenticated users (cookie JWT) always pass through. Anonymous clients must
    present the short-lived share_session_token issued by the resolve endpoint,
    which is bound to their IP hash + User-Agent hash.
    """
    if user is not None:
        return

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        client_ip = _get_share_client_ip(request)
        user_agent = (request.headers.get("User-Agent") or "")[:512]
        if verify_share_session_token(token, share_id, client_ip, user_agent):
            return

    raise HTTPException(
        status_code=401,
        detail="A valid share session token is required. Re-open the share link to obtain one.",
    )


# ---------------------------------------------------------------------------
# Authenticated share management
# ---------------------------------------------------------------------------

@router.get("/api/v1/shares/received")
async def list_received_shares(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    """List active user shares sent directly to the current user.

    Returns only 'user' type shares where target_user_id = current user.
    Each item includes the KEM fields needed to unwrap the file key.
    """
    cursor = await db.execute(
        "SELECT * FROM shares "
        "WHERE target_user_id = ? AND share_type = 'user' AND is_active = 1 "
        "AND (expires_at IS NULL OR expires_at > NOW()) "
        "ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (user.id, limit, offset),
    )
    shares = await cursor.fetchall()

    count_cursor = await db.execute(
        "SELECT COUNT(*) FROM shares "
        "WHERE target_user_id = ? AND share_type = 'user' AND is_active = 1 "
        "AND (expires_at IS NULL OR expires_at > NOW())",
        (user.id,),
    )
    total = (await count_cursor.fetchone())[0]

    result = []
    for s in shares:
        items = await _get_items_with_files(db, s["id"])
        # Look up sender username
        sender_cursor = await db.execute(
            "SELECT username FROM users WHERE id = ?", (s["created_by"],)
        )
        sender_row = await sender_cursor.fetchone()
        result.append({
            "id": s["id"],
            "token": s["token"],
            "share_type": s["share_type"],
            "sender_username": sender_row["username"] if sender_row else None,
            "expires_at": s["expires_at"],
            "created_at": s["created_at"],
            "files": items,
        })

    return {"shares": result, "total": total, "offset": offset, "limit": limit}


class _CheckSharesRequest(BaseModel):
    resource_ids: list[str]

    @field_validator("resource_ids")
    @classmethod
    def validate_ids(cls, v: list[str]) -> list[str]:
        if len(v) > 100:
            raise ValueError("Too many IDs (max 100)")
        return [validate_uuid(r) for r in v]


@router.post("/api/v1/shares/active-for-items")
async def check_active_shares_for_items(
    body: _CheckSharesRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
):
    """Return which of the given resource IDs have at least one active share (by any user).

    Used by the move modal to warn before moving items with live share links.
    """
    if not body.resource_ids:
        return {"ids_with_shares": []}

    placeholders = ",".join(["?" for _ in body.resource_ids])
    cursor = await db.execute(
        f"SELECT DISTINCT si.resource_id "
        f"FROM share_items si "
        f"JOIN shares s ON s.id = si.share_id "
        f"WHERE si.resource_id IN ({placeholders}) "
        f"AND s.is_active = 1",
        tuple(body.resource_ids),
    )
    rows = await cursor.fetchall()
    return {"ids_with_shares": [r["resource_id"] for r in rows]}


@router.get("/api/v1/shares")
async def list_shares(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    """List all active and inactive shares created by the current user."""
    cursor = await db.execute(
        "SELECT * FROM shares WHERE created_by = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (user.id, limit, offset),
    )
    shares = await cursor.fetchall()

    count_cursor = await db.execute(
        "SELECT COUNT(*) FROM shares WHERE created_by = ?", (user.id,)
    )
    total = (await count_cursor.fetchone())[0]

    result = []
    for s in shares:
        items = await _get_items_with_files(db, s["id"])
        sl_cursor = await db.execute(
            "SELECT slug, expires_at FROM short_links WHERE share_id = ?", (s["id"],)
        )
        short_links = [
            {"slug": r["slug"], "expires_at": r["expires_at"]}
            for r in await sl_cursor.fetchall()
        ]
        result.append({
            "id": s["id"],
            "token": s["token"],
            "share_type": s["share_type"],
            "expires_at": s["expires_at"],
            "is_active": bool(s["is_active"]),
            "has_password": s["password_hash"] is not None,
            "max_downloads": s["max_downloads"],
            "download_count": s["download_count"],
            "allow_upload": bool(s["allow_upload"]),
            "target_folder_id": s["target_folder_id"],
            "created_at": s["created_at"],
            "items": items,
            "short_links": short_links,
        })

    return {"shares": result, "total": total, "offset": offset, "limit": limit}


async def _resolve_share_recipient(db: Database, body: "CreateShareRequest") -> str | None:
    """Validate a user-type share and return the recipient's user_id."""
    if body.share_type != "user":
        return None
    if not body.recipient_username:
        raise HTTPException(status_code=400, detail="recipient_username is required for user shares")
    cursor = await db.execute(
        "SELECT id, x25519_public_key FROM users WHERE username = ? AND is_active = 1",
        (body.recipient_username,),
    )
    recipient_row = await cursor.fetchone()
    if recipient_row is None:
        raise HTTPException(status_code=404, detail="Recipient user not found")
    if recipient_row["x25519_public_key"] is None:
        raise HTTPException(status_code=422, detail="Recipient has not set up sharing keys yet")
    for item in body.items:
        if not item.ephemeral_x25519_pub or not item.kem_ciphertext:
            raise HTTPException(
                status_code=422,
                detail="ephemeral_x25519_pub and kem_ciphertext are required for user shares",
            )
    return recipient_row["id"]


async def _verify_share_items_access(db: Database, user: AuthenticatedUser, items: list) -> None:
    """Verify every file in the share exists, is complete, and the requester may share it."""
    for item in items:
        cursor = await db.execute(
            "SELECT id, folder_id, owner_id FROM files WHERE id = ? AND upload_complete = 1",
            (item.resource_id,),
        )
        file_row = await cursor.fetchone()
        if file_row is None:
            raise HTTPException(status_code=404, detail=f"File not found or upload incomplete: {item.resource_id}")
        if file_row["owner_id"] != user.id and not user.is_admin:
            has_access = False
            if file_row["folder_id"]:
                has_access = (
                    await is_in_shared_tree(db, file_row["folder_id"])
                    or await is_team_folder_member(db, file_row["folder_id"], user.id)
                )
            if not has_access:
                raise HTTPException(status_code=404, detail=f"File not found or access denied: {item.resource_id}")


async def _resolve_upload_folder(
    db: Database, body: "CreateShareRequest", user: AuthenticatedUser
) -> tuple[str | None, bool, int]:
    """Validate upload folder and compute per-share budget. Returns (folder_id, allow_upload, upload_max_bytes)."""
    if not (body.share_type == "link" and body.allow_upload):
        return None, False, 0
    if not body.target_folder_id:
        raise HTTPException(status_code=400, detail="target_folder_id is required when allow_upload is true")
    cursor = await db.execute(
        "SELECT id FROM folders WHERE id = ? AND owner_id = ?",
        (body.target_folder_id, user.id),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Target folder not found")

    # Compute available quota for this creator
    cursor = await db.execute(
        "SELECT disk_quota, disk_used FROM users WHERE id = ?", (user.id,)
    )
    u = await cursor.fetchone()
    if u and u["disk_quota"] is not None:
        available = max(0, u["disk_quota"] - u["disk_used"])
    else:
        available = _SHARE_UPLOAD_DEFAULT_BUDGET

    # Client may request a smaller budget; hard cap at available quota
    requested = body.upload_max_bytes if body.upload_max_bytes is not None else _SHARE_UPLOAD_DEFAULT_BUDGET
    if requested <= 0:
        raise HTTPException(status_code=400, detail="upload_max_bytes must be positive")
    budget = min(requested, available, _SHARE_UPLOAD_DEFAULT_BUDGET)
    if budget == 0:
        raise HTTPException(status_code=400, detail="No upload quota available for this share")
    return body.target_folder_id, True, budget


async def _insert_share_transaction(
    db: Database, request: Request, share_id: str, token: str,
    body: "CreateShareRequest", user: AuthenticatedUser,
    recipient_user_id: str | None, target_folder_id: str | None, allow_upload: bool,
    key_type: str | None = None, upload_max_bytes: int = _SHARE_UPLOAD_DEFAULT_BUDGET,
) -> None:
    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            INSERT INTO shares
                (id, token, created_by, share_type, target_user_id, expires_at,
                 max_downloads, allow_upload, target_folder_id, key_type, upload_max_bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (share_id, token, user.id, body.share_type, recipient_user_id,
             body.expires_at, body.max_downloads, 1 if allow_upload else 0,
             target_folder_id, key_type, upload_max_bytes),
        )
        for item in body.items:
            await db.execute(
                """
                INSERT INTO share_items
                    (id, share_id, resource_type, resource_id,
                     encrypted_file_key, key_iv, ephemeral_x25519_pub, kem_ciphertext)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), share_id, item.resource_type, item.resource_id,
                 item.encrypted_file_key, item.key_iv, item.ephemeral_x25519_pub, item.kem_ciphertext),
            )
        ip = (
            request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Real-IP")
            or (request.client.host if request.client else "unknown")
        )[:64]
        await db.execute(
            "INSERT INTO access_logs "
            "    (id, file_id, user_id, actor_auth_method, share_id, ip_address, user_agent, action) "
            "VALUES (?, NULL, ?, ?, ?, ?, ?, 'share')",
            (str(uuid.uuid4()), user.id, user.auth_method, share_id, ip,
             (request.headers.get("User-Agent") or "")[:512]),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise


@router.post("/api/v1/shares", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}, 422: {"description": "Unprocessable Entity"}})
async def create_share(
    body: CreateShareRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
):
    """Create a link or user share containing one or more files.

    Link shares: each item carries the file's key re-encrypted with a
    client-generated shareKey. The shareKey lives only in the URL fragment —
    never sent to the server.

    User shares: each item carries the file's key wrapped via hybrid
    X25519 + ML-KEM-768 KEM for the recipient. The ephemeral X25519 public key
    and ML-KEM-768 ciphertext are stored so the recipient can re-derive the
    wrapping key to decrypt the file key.
    """
    check_sharing_flags(
        actor=user,
        share_type=body.share_type,
        allow_upload=body.allow_upload,
        has_items=bool(body.items),
        target_folder_id=body.target_folder_id,
    )

    if not body.items and not (body.allow_upload and body.target_folder_id):
        raise HTTPException(
            status_code=400,
            detail="Share must contain at least one file, or be an upload-only folder share",
        )

    recipient_user_id = await _resolve_share_recipient(db, body)
    await evaluate_sharing_rules(db, user, recipient_user_id, body.share_type, actor_ip=_get_share_client_ip(request))
    await _verify_share_items_access(db, user, body.items)

    share_id = str(uuid.uuid4())
    token = body.client_token if body.client_token else secrets.token_urlsafe(32)
    key_type = "hkdf-v1" if body.client_token else None
    target_folder_id, allow_upload, upload_max_bytes = await _resolve_upload_folder(db, body, user)

    await _insert_share_transaction(db, request, share_id, token, body, user, recipient_user_id, target_folder_id, allow_upload, key_type, upload_max_bytes)

    cursor = await db.execute("SELECT created_at FROM shares WHERE id = ?", (share_id,))
    row = await cursor.fetchone()
    return {
        "share_id":   share_id,
        "id":         share_id,
        "share_type": body.share_type,
        "token":      token,
        "created_at": row["created_at"],
    }


@router.get("/api/v1/shares/{share_id}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def get_share(
    share_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
):
    """Get a single share with its items and short links."""
    share_id = validate_uuid(share_id)
    share = await _get_share_for_owner(db, share_id, user)

    items = await _get_items_with_files(db, share_id)
    sl_cursor = await db.execute(
        "SELECT slug, expires_at FROM short_links WHERE share_id = ?", (share_id,)
    )
    short_links = [
        {"slug": r["slug"], "expires_at": r["expires_at"]}
        for r in await sl_cursor.fetchall()
    ]

    return {
        "share": {
            "id": share["id"],
            "token": share["token"],
            "share_type": share["share_type"],
            "expires_at": share["expires_at"],
            "is_active": bool(share["is_active"]),
            "has_password": share["password_hash"] is not None,
            "max_downloads": share["max_downloads"],
            "download_count": share["download_count"],
            "allow_upload": bool(share["allow_upload"]),
            "target_folder_id": share["target_folder_id"],
            "created_at": share["created_at"],
            "items": items,
            "short_links": short_links,
        }
    }


@router.put("/api/v1/shares/{share_id}", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def update_share(
    share_id: str,
    body: UpdateShareRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
):
    """Update share settings (active state, expiry, download limit)."""
    share_id = validate_uuid(share_id)
    await _get_share_for_manage(db, share_id, user)

    updates: list[str] = []
    params: list = []
    if body.is_active is not None:
        updates.append("is_active = ?")
        params.append(1 if body.is_active else 0)
    if body.expires_at is not None:
        updates.append("expires_at = ?")
        params.append(body.expires_at)
    if body.max_downloads is not None:
        updates.append("max_downloads = ?")
        params.append(body.max_downloads)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(share_id)
    await db.execute(
        f"UPDATE shares SET {', '.join(updates)} WHERE id = ?", params
    )
    await db.commit()
    event_bus.emit(SecurityEvent(
        event_type="file.share.updated",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=user.id, username=user.username, ip=_get_share_client_ip(request)),
        detail={"share_id": share_id, "fields_changed": [u.split(" =")[0] for u in updates]},
    ))
    return {"message": "Share updated"}


@router.delete("/api/v1/shares/{share_id}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def delete_share(
    share_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
):
    """Delete a share and all its items/short links.

    Access log rows retain a NULL share_id reference (ON DELETE SET NULL).
    """
    share_id = validate_uuid(share_id)
    await _get_share_for_manage(db, share_id, user)
    await db.execute("DELETE FROM shares WHERE id = ?", (share_id,))
    await db.commit()
    event_bus.emit(SecurityEvent(
        event_type="file.share.deleted",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=user.id, username=user.username, ip=_get_share_client_ip(request)),
        detail={"share_id": share_id},
    ))
    return {"message": "Share deleted"}


@router.get("/api/v1/folders/{folder_id}/shares", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def get_folder_shares(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return all active link shares targeting this folder, with enough detail for the share banner.

    Accessible by the folder owner or any team member of the containing team.
    Each entry includes a can_manage flag indicating whether the requesting user
    may update or delete that share (own share, global admin, or team supervisor+).
    """
    folder_id = validate_uuid(folder_id)

    folder_cursor = await db.execute("SELECT id, owner_id FROM folders WHERE id = ?", (folder_id,))
    folder = await folder_cursor.fetchone()
    if folder is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    team_id = await _get_folder_team_id(db, folder_id)
    is_member = team_id and await _team_level_for_user(db, team_id, user.id) is not None

    if folder["owner_id"] != user.id and not is_member and not user.is_admin:
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    now = datetime.now(timezone.utc).isoformat()
    cursor = await db.execute(
        """
        SELECT s.id, s.token, s.key_type, s.created_by, s.created_at, s.expires_at,
               s.is_active, s.allow_upload,
               u.username AS creator_username,
               sl.slug    AS short_link_slug
        FROM shares s
        JOIN users u ON u.id = s.created_by
        LEFT JOIN short_links sl ON sl.share_id = s.id
        WHERE s.target_folder_id = ?
          AND s.share_type = 'link'
          AND s.is_active = 1
          AND (s.expires_at IS NULL OR s.expires_at > ?)
        ORDER BY s.created_at DESC
        """,
        (folder_id, now),
    )
    rows = await cursor.fetchall()

    result = []
    for r in rows:
        can_manage = r["created_by"] == user.id or user.is_admin
        if not can_manage and team_id:
            level = await _team_level_for_user(db, team_id, user.id)
            can_manage = level == "admin"
        result.append({
            "share_id":        r["id"],
            "token":           r["token"],
            "key_type":        r["key_type"],
            "creator_username": r["creator_username"],
            "created_at":      r["created_at"],
            "expires_at":      r["expires_at"],
            "allow_upload":    bool(r["allow_upload"]),
            "short_link_slug": r["short_link_slug"],
            "can_manage":      can_manage,
        })
    return result


class _ShareItemsRequest(BaseModel):
    items: list[_ShareItemIn]

    @field_validator("items")
    @classmethod
    def validate_items(cls, v: list) -> list:
        if not v:
            raise ValueError("items must not be empty")
        if len(v) > _SHARE_MAX_ITEMS:
            raise ValueError(f"Cannot add more than {_SHARE_MAX_ITEMS} items at once")
        return v


@router.post("/api/v1/shares/{share_id}/items", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def add_share_items(
    share_id: str,
    body: _ShareItemsRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Add new items (file key entries) to an existing link share.

    Used by the auto-keying flow when the owner uploads new files to a shared
    folder: the client derives the share key, wraps the new file key, and posts
    the share_items row here so recipients can decrypt the file.

    Idempotent: ON CONFLICT DO NOTHING, so duplicate posts are safe.
    """
    from app.routes.files import check_file_access
    share_id = validate_uuid(share_id)
    await _get_share_for_manage(db, share_id, user)

    # Verify requester has read access to every file before any insert
    for item in body.items:
        cursor = await db.execute(
            "SELECT id, owner_id, folder_id FROM files WHERE id = ? AND deleted_at IS NULL",
            (item.resource_id,),
        )
        file_row = await cursor.fetchone()
        if file_row is None:
            raise HTTPException(status_code=403, detail=f"No access to file {item.resource_id}")
        await check_file_access(db, file_row, user)

    for item in body.items:
        await db.execute(
            """
            INSERT INTO share_items
                (id, share_id, resource_type, resource_id, encrypted_file_key, key_iv)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (share_id, resource_type, resource_id) DO NOTHING
            """,
            (str(uuid.uuid4()), share_id, item.resource_type, item.resource_id,
             item.encrypted_file_key, item.key_iv),
        )
    await db.commit()
    return {"added": len(body.items)}


@router.post("/api/v1/shares/{share_id}/short-link", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 503: {"description": "503"}})
async def create_short_link(
    share_id: str,
    body: CreateShortLinkRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_management_rate_limit)],
):
    """Generate a memorable 3-word slug short link for an existing share."""
    share_id = validate_uuid(share_id)
    share = await _get_share_for_owner(db, share_id, user)

    if not share["is_active"]:
        raise HTTPException(
            status_code=400,
            detail="Cannot create a short link for an inactive share",
        )

    link_id = str(uuid.uuid4())
    try:
        slug = await insert_short_link_with_unique_slug(
            db,
            link_id=link_id,
            share_id=share_id,
            created_by=user.id,
            expires_at=body.expires_at,
            share_key=body.share_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {"slug": slug, "link_id": link_id, "expires_at": body.expires_at}


# ---------------------------------------------------------------------------
# Public share access (no authentication required)
# ---------------------------------------------------------------------------

@router.get("/api/v1/s/{token}", responses={404: {"description": "Not Found"}})
async def resolve_share(
    token: str,
    request: Request,
    user: Annotated[AuthenticatedUser | None, Depends(get_optional_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Resolve a share token.

    Returns share metadata and the list of files with their shareKey-encrypted
    file keys.  The shareKey itself is never sent to the server — it lives in
    the URL fragment on the client side.

    Also issues a short-lived share_session_token bound to the client's IP and
    User-Agent. This token must be presented as Authorization: Bearer on the
    chunk manifest and file content endpoints.
    """
    try:
        token = validate_share_token(token)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_SHARE_NOT_FOUND)

    try:
        share = await _get_active_share_by_token(db, token)

        # User-type shares are gated on the intended recipient being authenticated.
        if share["share_type"] == "user" and share["target_user_id"] is not None:
            if user is None or user.id != share["target_user_id"]:
                raise HTTPException(status_code=404, detail=_ERR_SHARE_NOT_FOUND)

        await _verify_creator_still_has_access(db, share["id"], share["created_by"])
        items = await _get_items_with_files(db, share["id"], share["target_folder_id"])

        client_ip = _get_share_client_ip(request)
        user_agent = (request.headers.get("User-Agent") or "")[:512]
        # Authenticated recipients don't need a share_session_token — their session cookie
        # passes _require_share_access. Unauthenticated link shares still get one.
        session_token = None if (share["share_type"] == "user" and user is not None) else \
            create_share_session_token(share["id"], client_ip, user_agent)

        await _log_share_access(
            db, request,
            user.id if user else None, share["id"], None,
            username=user.username if user else None,
            auth_method=user.auth_method if user else None,
            action="view",
        )
        return {
            "share_id": share["id"],
            "share_type": share["share_type"],
            "expires_at": share["expires_at"],
            "has_password": share["password_hash"] is not None,
            "max_downloads": share["max_downloads"],
            "download_count": share["download_count"],
            "allow_upload": bool(share["allow_upload"]),
            "target_folder_id": share["target_folder_id"],
            "files": items,
            "share_session_token": session_token,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("resolve_share internal error for token %s: %s", token[:8], exc)  # NOSONAR — server-side audit log; values are Pydantic-validated
        raise


@router.get("/s/{token}/files/{file_id}/chunks", responses={400: {"description": "Bad Request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def get_shared_file_chunks(
    token: str,
    file_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser | None, Depends(get_optional_user)],
    db: Annotated[Database, Depends(get_db)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
):
    """Return the chunk manifest for a file inside a share.

    The manifest carries per-chunk IVs for client-side AES-GCM decryption.
    The encrypted_file_key in the share items (encrypted with shareKey) is
    already returned by GET /s/{token} and is not repeated here.

    Requires either an authenticated session or a valid share_session_token
    (issued by GET /s/{token}) presented as Authorization: Bearer.
    """
    try:
        token = validate_share_token(token)
        file_id = validate_uuid(file_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    share = await _get_active_share_by_token(db, token)
    await _verify_creator_still_has_access(db, share["id"], share["created_by"])
    _require_share_access(request, share["id"], user)
    await _verify_file_in_share(db, share["id"], file_id)

    cursor = await db.execute(
        "SELECT * FROM files WHERE id = ? AND upload_complete = 1 AND deleted_at IS NULL", (file_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    cursor = await db.execute(
        "SELECT * FROM file_chunks "
        "WHERE file_id = ? ORDER BY chunk_index LIMIT ? OFFSET ?",
        (file_id, limit, offset),
    )
    chunks = [FileChunk.from_row(r).to_dict() for r in await cursor.fetchall()]

    return {
        "file_id": file_id,
        "original_name": row["original_name"],
        "mime_type": row["mime_type"],
        "size_bytes": row["size_bytes"],
        "chunk_size": row["chunk_size"],
        "total_chunks": row["total_chunks"],
        "chunks": chunks,
        "offset": offset,
        "limit": limit,
    }


async def _load_shared_file_row(db, file_id: str) -> dict:
    """Fetch and validate a file for shared download. Raises 404/409/422."""
    cursor = await db.execute(
        "SELECT id, storage_key, sanitized_name, encrypted_size, upload_complete "
        "FROM files WHERE id = ? AND deleted_at IS NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")
    if not row["upload_complete"]:
        raise HTTPException(status_code=409, detail="File upload is not complete")
    if row["encrypted_size"] <= 0:
        raise HTTPException(status_code=422, detail="File has no content")
    return row


async def _enforce_download_limit(
    db: Database, share: dict, user: AuthenticatedUser | None,
    range_header: str, start: int, content_length: int,
) -> None:
    """Atomically increment download_count for non-owner requests that cross the minimum size."""
    is_owner = user is not None and user.id == share["created_by"]
    if is_owner or share["max_downloads"] is None:
        return
    counts_as_download = not range_header or (start == 0 and content_length > _DOWNLOAD_COUNT_MIN_BYTES)
    if not counts_as_download:
        return
    result = await db.execute(
        "UPDATE shares SET download_count = download_count + 1 "
        "WHERE id = ? AND download_count < max_downloads",
        (share["id"],),
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=410, detail="Download limit reached for this share")


@router.get("/s/{token}/files/{file_id}/content", responses={400: {"description": "Bad Request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}, 410: {"description": "Gone"}, 422: {"description": "Unprocessable Entity"}, 503: {"description": "503"}})
async def download_shared_file(
    token: str,
    file_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser | None, Depends(get_optional_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Stream an encrypted file from a share (public, no auth required).

    Supports HTTP Range requests for chunked client-side decryption.

    If the share has a max_downloads limit:
    - The share owner (if authenticated) bypasses the counter.
    - All other requesters atomically increment download_count on first chunk.
    - Returns 410 Gone when the limit is exhausted.
    """
    try:
        token = validate_share_token(token)
        file_id = validate_uuid(file_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    share = await _get_active_share_by_token(db, token)
    await _verify_creator_still_has_access(db, share["id"], share["created_by"])
    _require_share_access(request, share["id"], user)
    await _verify_file_in_share(db, share["id"], file_id)

    row = await _load_shared_file_row(db, file_id)
    storage_key = row["storage_key"]
    encrypted_size: int = row["encrypted_size"]

    blob_exists = await storage.get_manager().exists(db, file_id, storage_key)
    if not blob_exists:
        logger.error("Blob missing for shared file %s (storage_key=%s)", file_id, storage_key)  # NOSONAR — server-side audit log; values are Pydantic-validated
        raise HTTPException(status_code=503, detail="File data is temporarily unavailable")

    # --- Parse Range header ---
    range_header = request.headers.get("Range", "").strip()
    start, end = 0, encrypted_size - 1
    if range_header:
        result = parse_range_header(range_header, encrypted_size)
        if isinstance(result, Response):
            return result
        start, end = result
    content_length = end - start + 1
    status_code = 206 if range_header else 200

    await _enforce_download_limit(db, share, user, range_header, start, content_length)

    # --- Access log on first chunk ---
    if not range_header or start == 0:
        await _log_share_access(db, request, user.id if user else None, share["id"], file_id,
                                username=user.username if user else None,
                                auth_method=user.auth_method if user else None)

    # --- Content-Disposition ---
    disposition = content_disposition(row["sanitized_name"] or "download")

    resp_headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(content_length),
        "Content-Disposition": disposition,
        "Cache-Control": "no-store",
    }
    if status_code == 206:
        resp_headers["Content-Range"] = f"bytes {start}-{end}/{encrypted_size}"

    stream = await storage.get_manager().read_stream(db, file_id, storage_key, start, end)
    return StreamingResponse(
        stream,
        status_code=status_code,
        media_type="application/octet-stream",
        headers=resp_headers,
    )


@router.get("/api/v1/l/{slug}", responses={404: {"description": "Not Found"}})
async def resolve_short_link(
    slug: str,
    request: Request,
    db: Annotated[Database, Depends(get_db)],
):
    """Resolve a memorable short link slug to its share data.

    Returns the same payload as GET /s/{token}, plus the token itself so the
    client can build download URLs using the /s/{token}/files/... endpoints.

    Also issues a share_session_token for the resolved share (same semantics as
    GET /s/{token}) so the client can immediately access chunk/content endpoints.
    """
    try:
        slug = validate_short_slug(slug)
    except ValueError:
        raise HTTPException(status_code=404, detail="Short link not found or expired")

    now = datetime.now(timezone.utc).isoformat()

    # Check invite short links first (they have no share_key complexity)
    invite_cursor = await db.execute(
        "SELECT token FROM invite_short_links WHERE slug = ? AND expires_at > ?",
        (slug, now),
    )
    invite_row = await invite_cursor.fetchone()
    if invite_row is not None:
        return {"type": "invite", "token": invite_row["token"]}

    cursor = await db.execute(
        "SELECT share_id FROM short_links WHERE slug = ? AND expires_at > ?",
        (slug, now),
    )
    link_row = await cursor.fetchone()
    if link_row is None:
        raise HTTPException(status_code=404, detail="Short link not found or expired")

    share_cursor = await db.execute(
        "SELECT * FROM shares WHERE id = ? AND is_active = 1 "
        "AND (expires_at IS NULL OR expires_at > ?)",
        (link_row["share_id"], now),
    )
    share = await share_cursor.fetchone()
    if share is None:
        raise HTTPException(status_code=404, detail=_ERR_SHARE_NOT_FOUND)

    items = await _get_items_with_files(db, share["id"], share["target_folder_id"])

    client_ip = _get_share_client_ip(request)
    user_agent = (request.headers.get("User-Agent") or "")[:512]
    session_token = create_share_session_token(share["id"], client_ip, user_agent)

    await _log_share_access(db, request, None, share["id"], None, action="view")
    return {
        "share_id": share["id"],
        "token": share["token"],
        "share_type": share["share_type"],
        "expires_at": share["expires_at"],
        "has_password": share["password_hash"] is not None,
        "max_downloads": share["max_downloads"],
        "download_count": share["download_count"],
        "files": items,
        "share_session_token": session_token,
    }


# ---------------------------------------------------------------------------
# Upload to share (anonymous — requires share_session_token + allow_upload)
# ---------------------------------------------------------------------------

# Minimum bytes for a ranged download to count against max_downloads
_DOWNLOAD_COUNT_MIN_BYTES = 1024


@router.post("/s/{share_id}/upload", responses={400: {"description": "Bad Request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 413: {"description": "413"}, 422: {"description": "Unprocessable Entity"}, 429: {"description": "Too Many Requests"}})
async def upload_to_share(
    share_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser | None, Depends(get_optional_user)],
    db: Annotated[Database, Depends(get_db)],
    file: Annotated[UploadFile, File()],
    file_name: Annotated[str, Form()],
    encrypted_file_key: Annotated[str, Form()],
    key_iv: Annotated[str, Form()],
    chunk_iv: Annotated[str, Form()],
    size_bytes: Annotated[int, Form()],
):
    """Accept an encrypted file uploaded by a share-link visitor.

    The client must:
    1. Generate a fresh AES file key.
    2. Encrypt the file into a single chunk using that key.
    3. Wrap the file key with the share key (AES-GCM key wrap).
    4. POST the encrypted blob + wrapped-key metadata here.

    The file is stored under the share's target folder, owned by the share
    creator. The owner can decrypt it using the share key.
    Requires the share to have allow_upload=1 and a target_folder_id.
    """
    share_id = validate_uuid(share_id)
    _require_share_access(request, share_id, user)

    _rl_raw = await get_admin_setting(db, "anon_share_upload_rate_limit")
    _rl = int(_rl_raw) if (_rl_raw and _rl_raw.isdigit()) else 20
    if not await _counter.is_allowed(f"share_upload:{share_id}", _rl, 60):
        raise HTTPException(status_code=429, detail="Too many uploads to this share. Please try again later.")

    now = datetime.now(timezone.utc).isoformat()
    cursor = await db.execute(
        "SELECT * FROM shares WHERE id = ? AND is_active = 1 "
        "AND (expires_at IS NULL OR expires_at > ?)",
        (share_id, now),
    )
    share = await cursor.fetchone()
    if share is None:
        raise HTTPException(status_code=404, detail=_ERR_SHARE_NOT_FOUND)

    if not share["allow_upload"]:
        raise HTTPException(status_code=403, detail="This share does not allow uploads")

    if not share["target_folder_id"]:
        raise HTTPException(status_code=400, detail="Share has no target folder")

    # Validate form fields
    try:
        safe_name = sanitize_filename(file_name).name
        encrypted_file_key = validate_base64(encrypted_file_key)
        key_iv = validate_base64(key_iv)
        chunk_iv = validate_base64(chunk_iv)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if size_bytes < 0:
        raise HTTPException(status_code=422, detail="Invalid size_bytes")

    upload_max = share["upload_max_bytes"]
    already_used = share["total_uploaded_bytes"]

    # Early rejection: client-declared size already exceeds remaining budget
    if already_used + size_bytes > upload_max:
        raise HTTPException(
            status_code=413,
            detail=f"Upload would exceed this share's upload budget of {upload_max // (1024 * 1024)} MB",
        )

    # Read upload — enforce remaining budget; read at most (budget_left + 1) bytes
    budget_left = upload_max - already_used
    content = await file.read(budget_left + 1)
    if len(content) > budget_left:
        raise HTTPException(
            status_code=413,
            detail=f"Upload would exceed this share's upload budget of {upload_max // (1024 * 1024)} MB",
        )
    encrypted_size = len(content)

    file_id = str(uuid.uuid4())
    storage_key = secrets.token_urlsafe(32)

    chunk_id = str(uuid.uuid4())
    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            INSERT INTO files
                (id, original_name, sanitized_name, storage_key, folder_id, owner_id,
                 mime_type, size_bytes, encrypted_size, chunk_size, total_chunks,
                 encrypted_file_key, key_iv, upload_complete)
            VALUES (?, ?, ?, ?, ?, ?, 'application/octet-stream', ?, ?, ?, 1, ?, ?, 1)
            """,
            (
                file_id, safe_name, safe_name, storage_key,
                share["target_folder_id"], share["created_by"],
                size_bytes, encrypted_size, encrypted_size,
                encrypted_file_key, key_iv,
            ),
        )
        # Write blob after the files row exists so the file_storage_locations FK is satisfied
        await storage.get_manager().write_blob(db, file_id, storage_key, content)
        await db.execute(
            "INSERT INTO file_chunks (id, file_id, chunk_index, iv, size_bytes, \"offset\") "
            "VALUES (?, ?, 0, ?, ?, 0)",
            (chunk_id, file_id, chunk_iv, encrypted_size),
        )
        await db.execute(
            "INSERT INTO share_items (id, share_id, resource_type, resource_id, encrypted_file_key, key_iv) "
            "VALUES (?, ?, 'file', ?, ?, ?)",
            (str(uuid.uuid4()), share_id, file_id, encrypted_file_key, key_iv),
        )
        # Secondary guard: check creator's absolute disk quota
        cursor = await db.execute(
            "SELECT disk_quota, disk_used FROM users WHERE id = ?",
            (share["created_by"],),
        )
        creator = await cursor.fetchone()
        if creator and creator["disk_quota"] is not None:
            if creator["disk_used"] + encrypted_size > creator["disk_quota"]:
                raise HTTPException(status_code=413, detail="Share creator's disk quota exceeded")

        await db.execute(
            "UPDATE users SET disk_used = disk_used + ? WHERE id = ?",
            (encrypted_size, share["created_by"]),
        )
        # Atomically claim budget; fail if a concurrent upload already consumed it
        cursor = await db.execute(
            "UPDATE shares SET total_uploaded_bytes = total_uploaded_bytes + ? "
            "WHERE id = ? AND total_uploaded_bytes + ? <= upload_max_bytes "
            "RETURNING total_uploaded_bytes",
            (encrypted_size, share_id, encrypted_size),
        )
        if await cursor.fetchone() is None:
            raise HTTPException(
                status_code=413,
                detail=f"Upload would exceed this share's upload budget of {upload_max // (1024 * 1024)} MB",
            )
        log_id = str(uuid.uuid4())
        ip = (
            request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Real-IP")
            or (request.client.host if request.client else "unknown")
        )[:64]
        ua = (request.headers.get("User-Agent") or "")[:512]
        await db.execute(
            "INSERT INTO access_logs "
            "    (id, file_id, user_id, actor_auth_method, share_id, ip_address, user_agent, action) "
            "VALUES (?, ?, NULL, NULL, ?, ?, ?, 'upload')",
            (log_id, file_id, share_id, ip, ua),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        async def _bg_delete(fid: str, key: str) -> None:
            try:
                async with db_session() as _db:
                    await storage.get_manager().delete_blob(_db, fid, key)
            except Exception:
                pass
        _t = asyncio.create_task(_bg_delete(file_id, storage_key))
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)
        raise

    return {"file_id": file_id, "file_name": safe_name, "size_bytes": size_bytes}
