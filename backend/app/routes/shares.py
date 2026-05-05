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
from app.database import db_session, get_db
import app.storage.manager as storage
from app.middleware.rate_limit import check_management_rate_limit
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
from app.routes._access import is_in_shared_tree, is_team_folder_member
from app.util.http import content_disposition, parse_range_header
from app.services.sharing_rules import check_sharing_flags, evaluate_sharing_rules
from app.wordlist import insert_short_link_with_unique_slug

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


class CreateShareRequest(BaseModel):
    items: list[_ShareItemIn]
    share_type: str = "link"
    recipient_username: str | None = None
    expires_at: str | None = None
    max_downloads: int | None = None
    allow_upload: bool = False
    target_folder_id: str | None = None

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
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
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
                datetime.fromisoformat(v.replace("Z", "+00:00"))
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
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
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
    cursor = await db.execute("SELECT * FROM shares WHERE id = ?", (share_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Share not found")
    if row["created_by"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")
    return row


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
        raise HTTPException(status_code=404, detail="Share not found or expired")
    return row


async def _get_items_with_files(db, share_id: str) -> list[dict]:
    """Return share items joined with file metadata for file-type items.

    Returns the share-item encrypted_file_key (re-encrypted with shareKey),
    never the file's original key (encrypted with the owner's masterKey).
    """
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
        LEFT JOIN files f
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
        # Non-owner creator: check whether they still have team/shared access
        has_access = False
        if row["folder_id"]:
            has_access = (
                await is_in_shared_tree(db, row["folder_id"])
                or await is_team_folder_member(db, row["folder_id"], creator_id)
            )
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
) -> None:
    """Log a share download event. Best-effort — never raises."""
    try:
        ip = _get_share_client_ip(request)[:64]
        ua = (request.headers.get("User-Agent") or "")[:512]
        actor_username = username if user_id else "external"
        log_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO access_logs
                (id, file_id, user_id, actor_username, share_id, ip_address, user_agent, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'download')
            """,
            (log_id, file_id, user_id, actor_username, share_id, ip, ua),
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


async def _require_share_access(
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
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    _rl=Depends(check_management_rate_limit),
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
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    _rl=Depends(check_management_rate_limit),
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
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    _rl=Depends(check_management_rate_limit),
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


@router.post("/api/v1/shares")
async def create_share(
    body: CreateShareRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    _rl=Depends(check_management_rate_limit),
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
    # Layer 1: behavioral flag check (fast, synchronous)
    check_sharing_flags(
        actor=user,
        share_type=body.share_type,
        allow_upload=body.allow_upload,
        has_items=bool(body.items),
        target_folder_id=body.target_folder_id,
    )

    # Empty item list is only valid for upload-only folder shares
    if not body.items:
        if not (body.allow_upload and body.target_folder_id):
            raise HTTPException(
                status_code=400,
                detail="Share must contain at least one file, or be an upload-only folder share",
            )

    # Validate user shares have a recipient
    if body.share_type == "user":
        if not body.recipient_username:
            raise HTTPException(
                status_code=400,
                detail="recipient_username is required for user shares",
            )
        # Resolve recipient user ID and verify they have PQ keys
        cursor = await db.execute(
            "SELECT id, x25519_public_key FROM users "
            "WHERE username = ? AND is_active = 1",
            (body.recipient_username,),
        )
        recipient_row = await cursor.fetchone()
        if recipient_row is None:
            raise HTTPException(status_code=404, detail="Recipient user not found")
        if recipient_row["x25519_public_key"] is None:
            raise HTTPException(
                status_code=422,
                detail="Recipient has not set up sharing keys yet",
            )
        # Validate all items include KEM fields
        for item in body.items:
            if not item.ephemeral_x25519_pub or not item.kem_ciphertext:
                raise HTTPException(
                    status_code=422,
                    detail="ephemeral_x25519_pub and kem_ciphertext are required for user shares",
                )
        recipient_user_id = recipient_row["id"]
    else:
        recipient_user_id = None

    # Layer 2: identity-scoped sharing rules (evaluated after recipient is resolved)
    await evaluate_sharing_rules(db, user, recipient_user_id, body.share_type, actor_ip=_get_share_client_ip(request))

    # Verify every referenced file exists, is complete, and the requester has access.
    # Owners and admins can always share their files. Team members may share any file
    # currently in a team folder they belong to (the file key was distributed to them
    # via the team key exchange at upload time).
    for item in body.items:
        cursor = await db.execute(
            "SELECT id, folder_id, owner_id FROM files WHERE id = ? AND upload_complete = 1",
            (item.resource_id,),
        )
        file_row = await cursor.fetchone()
        if file_row is None:
            raise HTTPException(
                status_code=404,
                detail=f"File not found or upload incomplete: {item.resource_id}",
            )
        if file_row["owner_id"] != user.id and not user.is_admin:
            has_access = False
            if file_row["folder_id"]:
                has_access = (
                    await is_in_shared_tree(db, file_row["folder_id"])
                    or await is_team_folder_member(db, file_row["folder_id"], user.id)
                )
            if not has_access:
                raise HTTPException(
                    status_code=404,
                    detail=f"File not found or access denied: {item.resource_id}",
                )

    share_id = str(uuid.uuid4())
    # token = 43-char base64url of 32 random bytes (128-bit entropy in path component)
    token = secrets.token_urlsafe(32)

    # allow_upload only valid for link shares (not user shares) and requires a folder
    target_folder_id = None
    allow_upload = False
    if body.share_type == "link" and body.allow_upload:
        if not body.target_folder_id:
            raise HTTPException(
                status_code=400,
                detail="target_folder_id is required when allow_upload is true",
            )
        # Verify the folder exists and belongs to the requesting user
        cursor = await db.execute(
            "SELECT id FROM folders WHERE id = ? AND owner_id = ?",
            (body.target_folder_id, user.id),
        )
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Target folder not found")
        target_folder_id = body.target_folder_id
        allow_upload = True

    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            INSERT INTO shares
                (id, token, created_by, share_type, target_user_id, expires_at,
                 max_downloads, allow_upload, target_folder_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (share_id, token, user.id, body.share_type, recipient_user_id,
             body.expires_at, body.max_downloads,
             1 if allow_upload else 0, target_folder_id),
        )

        for item in body.items:
            item_id = str(uuid.uuid4())
            await db.execute(
                """
                INSERT INTO share_items
                    (id, share_id, resource_type, resource_id,
                     encrypted_file_key, key_iv,
                     ephemeral_x25519_pub, kem_ciphertext)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_id, share_id,
                    item.resource_type, item.resource_id,
                    item.encrypted_file_key, item.key_iv,
                    item.ephemeral_x25519_pub, item.kem_ciphertext,
                ),
            )

        # Log share creation in access_logs
        log_id = str(uuid.uuid4())
        ip = (
            request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Real-IP")
            or (request.client.host if request.client else "unknown")
        )[:64]
        ua = (request.headers.get("User-Agent") or "")[:512]
        await db.execute(
            """
            INSERT INTO access_logs
                (id, file_id, user_id, share_id, ip_address, user_agent, action)
            VALUES (?, NULL, ?, ?, ?, ?, 'share')
            """,
            (log_id, user.id, share_id, ip, ua),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    cursor = await db.execute("SELECT created_at FROM shares WHERE id = ?", (share_id,))
    row = await cursor.fetchone()
    return {
        "share_id":   share_id,
        "id":         share_id,
        "share_type": body.share_type,
        "token":      token,
        "created_at": row["created_at"],
    }


@router.get("/api/v1/shares/{share_id}")
async def get_share(
    share_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    _rl=Depends(check_management_rate_limit),
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


@router.put("/api/v1/shares/{share_id}")
async def update_share(
    share_id: str,
    body: UpdateShareRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    _rl=Depends(check_management_rate_limit),
):
    """Update share settings (active state, expiry, download limit)."""
    share_id = validate_uuid(share_id)
    await _get_share_for_owner(db, share_id, user)

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
    return {"message": "Share updated"}


@router.delete("/api/v1/shares/{share_id}")
async def delete_share(
    share_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    _rl=Depends(check_management_rate_limit),
):
    """Delete a share and all its items/short links.

    Access log rows retain a NULL share_id reference (ON DELETE SET NULL).
    """
    share_id = validate_uuid(share_id)
    await _get_share_for_owner(db, share_id, user)
    await db.execute("DELETE FROM shares WHERE id = ?", (share_id,))
    await db.commit()
    return {"message": "Share deleted"}


@router.post("/api/v1/shares/{share_id}/short-link")
async def create_short_link(
    share_id: str,
    body: CreateShortLinkRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    _rl=Depends(check_management_rate_limit),
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

@router.get("/api/v1/s/{token}")
async def resolve_share(
    token: str,
    request: Request,
    user: AuthenticatedUser | None = Depends(get_optional_user),
    db=Depends(get_db),
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
        raise HTTPException(status_code=404, detail="Share not found or expired")

    try:
        share = await _get_active_share_by_token(db, token)

        # User-type shares are gated on the intended recipient being authenticated.
        if share["share_type"] == "user" and share["target_user_id"] is not None:
            if user is None or user.id != share["target_user_id"]:
                raise HTTPException(status_code=404, detail="Share not found or expired")

        await _verify_creator_still_has_access(db, share["id"], share["created_by"])
        items = await _get_items_with_files(db, share["id"])

        client_ip = _get_share_client_ip(request)
        user_agent = (request.headers.get("User-Agent") or "")[:512]
        # Authenticated recipients don't need a share_session_token — their session cookie
        # passes _require_share_access. Unauthenticated link shares still get one.
        session_token = None if (share["share_type"] == "user" and user is not None) else \
            create_share_session_token(share["id"], client_ip, user_agent)

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
        logger.exception("resolve_share internal error for token %s: %s", token[:8], exc)
        raise


@router.get("/s/{token}/files/{file_id}/chunks")
async def get_shared_file_chunks(
    token: str,
    file_id: str,
    request: Request,
    user: AuthenticatedUser | None = Depends(get_optional_user),
    db=Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5000),
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
    await _require_share_access(request, share["id"], user)
    await _verify_file_in_share(db, share["id"], file_id)

    cursor = await db.execute(
        "SELECT * FROM files WHERE id = ? AND upload_complete = 1", (file_id,)
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


@router.get("/s/{token}/files/{file_id}/content")
async def download_shared_file(
    token: str,
    file_id: str,
    request: Request,
    user: AuthenticatedUser | None = Depends(get_optional_user),
    db=Depends(get_db),
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
    await _require_share_access(request, share["id"], user)
    await _verify_file_in_share(db, share["id"], file_id)

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

    storage_key = row["storage_key"]
    encrypted_size: int = row["encrypted_size"]

    if encrypted_size <= 0:
        raise HTTPException(status_code=422, detail="File has no content")

    blob_exists = await storage.get_manager().exists(db, file_id, storage_key)
    if not blob_exists:
        logger.error("Blob missing for shared file %s (storage_key=%s)", file_id, storage_key)
        raise HTTPException(status_code=503, detail="File data is temporarily unavailable")

    # --- Parse Range header ---
    range_header = request.headers.get("Range", "").strip()
    start = 0
    end = encrypted_size - 1

    if range_header:
        result = parse_range_header(range_header, encrypted_size)
        if isinstance(result, Response):
            return result
        start, end = result

    content_length = end - start + 1
    status_code = 206 if range_header else 200

    # --- max_downloads: atomic increment on first chunk for non-owners ---
    is_owner = user is not None and user.id == share["created_by"]
    if (
        not is_owner
        and share["max_downloads"] is not None
        and (not range_header or start == 0)
    ):
        result = await db.execute(
            "UPDATE shares SET download_count = download_count + 1 "
            "WHERE id = ? AND download_count < max_downloads",
            (share["id"],),
        )
        await db.commit()
        if result.rowcount == 0:
            raise HTTPException(
                status_code=410,
                detail="Download limit reached for this share",
            )

    # --- Access log on first chunk ---
    if not range_header or start == 0:
        user_id = user.id if user else None
        await _log_share_access(db, request, user_id, share["id"], file_id, username=user.username if user else None)

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


@router.get("/api/v1/l/{slug}")
async def resolve_short_link(
    slug: str,
    request: Request,
    db=Depends(get_db),
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
        raise HTTPException(status_code=404, detail="Share not found or expired")

    items = await _get_items_with_files(db, share["id"])

    client_ip = _get_share_client_ip(request)
    user_agent = (request.headers.get("User-Agent") or "")[:512]
    session_token = create_share_session_token(share["id"], client_ip, user_agent)

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

# Maximum encrypted size accepted for share uploads (100 MB)
_SHARE_UPLOAD_MAX_BYTES = 100 * 1024 * 1024


@router.post("/s/{share_id}/upload")
async def upload_to_share(
    share_id: str,
    request: Request,
    file: UploadFile = File(...),
    file_name: str = Form(...),
    encrypted_file_key: str = Form(...),
    key_iv: str = Form(...),
    chunk_iv: str = Form(...),
    size_bytes: int = Form(...),
    user: AuthenticatedUser | None = Depends(get_optional_user),
    db=Depends(get_db),
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
    await _require_share_access(request, share_id, user)

    now = datetime.now(timezone.utc).isoformat()
    cursor = await db.execute(
        "SELECT * FROM shares WHERE id = ? AND is_active = 1 "
        "AND (expires_at IS NULL OR expires_at > ?)",
        (share_id, now),
    )
    share = await cursor.fetchone()
    if share is None:
        raise HTTPException(status_code=404, detail="Share not found or expired")

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

    # Read upload — enforce size limit before touching disk
    content = await file.read(_SHARE_UPLOAD_MAX_BYTES + 1)
    if len(content) > _SHARE_UPLOAD_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds the {_SHARE_UPLOAD_MAX_BYTES // (1024 * 1024)} MB limit",
        )
    encrypted_size = len(content)

    file_id = str(uuid.uuid4())
    storage_key = secrets.token_urlsafe(32)

    # Write blob first so we can roll back on DB failure
    await storage.get_manager().write_blob(db, file_id, storage_key, content)

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
        await db.execute(
            "INSERT INTO file_chunks (id, file_id, chunk_index, iv, size_bytes, \"offset\") "
            "VALUES (?, ?, 0, ?, ?, 0)",
            (chunk_id, file_id, chunk_iv, encrypted_size),
        )
        await db.execute(
            "UPDATE users SET disk_used = disk_used + ? WHERE id = ?",
            (encrypted_size, share["created_by"]),
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
            "    (id, file_id, user_id, share_id, ip_address, user_agent, action) "
            "VALUES (?, ?, NULL, ?, ?, ?, 'share_upload')",
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
        asyncio.create_task(_bg_delete(file_id, storage_key))
        raise

    return {"file_id": file_id, "file_name": safe_name, "size_bytes": size_bytes}
