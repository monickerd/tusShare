"""File metadata and content routes.

Content serving (with Range support) and access logging implemented in
Phase 4. Encrypted bytes are served verbatim — the server never decrypts.
"""

import asyncio
import logging
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.auth.dependencies import get_current_user, get_optional_user, require_user_role
from app.auth.interface import AuthenticatedUser
from app.config import settings
from app.database import get_db
from app.middleware.bandwidth import check_bandwidth
from app.models.file import File, FileChunk
from app.routes._access import is_in_shared_tree
from app.validation.sanitizers import SanitizedFilename, sanitize_filename, validate_uuid

logger = logging.getLogger(__name__)


async def check_file_access(db, file_row, user: AuthenticatedUser) -> None:
    """Verify user has access to a file. Raises 403 if denied.

    Shared helper used by get_file_metadata, get_file_chunks, etc.
    Full permission-tree check will replace this in Phase 6.
    """
    if file_row["owner_id"] == user.id or user.is_admin:
        return
    if file_row["folder_id"] and await is_in_shared_tree(db, file_row["folder_id"]):
        return
    raise HTTPException(status_code=403, detail="Access denied")

router = APIRouter()


class UpdateFileRequest(BaseModel):
    original_name: str | None = None
    folder_id: str | None = None

    @field_validator("original_name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            return sanitize_filename(v).name
        return v

    @field_validator("folder_id")
    @classmethod
    def validate_folder_id(cls, v: str | None) -> str | None:
        if v is not None:
            return validate_uuid(v)
        return v


@router.get("/{file_id}")
async def get_file_metadata(
    file_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Get file metadata (not content)."""
    file_id = validate_uuid(file_id)

    cursor = await db.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    file = File.from_row(row)
    await check_file_access(db, row, user)
    return {"file": file.to_dict()}


@router.put("/{file_id}")
async def update_file(
    file_id: str,
    body: UpdateFileRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Update file metadata (rename, move)."""
    file_id = validate_uuid(file_id)

    cursor = await db.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    updates = []
    params = []
    removed_chars: list[str] = []
    if body.original_name is not None:
        updates.append("original_name = ?")
        params.append(body.original_name)
        sanitized = sanitize_filename(body.original_name)
        updates.append("sanitized_name = ?")
        params.append(sanitized.name)
        removed_chars = sanitized.removed_chars
    if body.folder_id is not None:
        # Verify the target folder exists and is owned by this user.
        # Without this check, a user could move their file into another user's folder,
        # making it appear in that user's folder listing (since listing queries by folder_id).
        target_cursor = await db.execute(
            "SELECT owner_id FROM folders WHERE id = ?", (body.folder_id,)
        )
        target_folder = await target_cursor.fetchone()
        if target_folder is None:
            raise HTTPException(status_code=404, detail="Target folder not found")
        if target_folder["owner_id"] != user.id and not user.is_admin:
            raise HTTPException(status_code=403, detail="Access denied to target folder")
        updates.append("folder_id = ?")
        params.append(body.folder_id)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
    params.append(file_id)

    await db.execute(
        f"UPDATE files SET {', '.join(updates)} WHERE id = ?",
        params,
    )
    await db.commit()

    result = {"message": "File updated"}
    if removed_chars:
        result["removed_chars"] = removed_chars
    return result


@router.delete("/{file_id}")
async def delete_file(
    file_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Delete a file (metadata and blob).

    DB mutations (quota update + row delete) are atomic in a single transaction.
    Disk blob removal happens AFTER the commit in a thread to avoid blocking
    the event loop. If the blob unlink fails, it's logged but doesn't roll back
    the DB — a background cleanup job can catch orphans later.
    """
    file_id = validate_uuid(file_id)

    cursor = await db.execute(
        "SELECT id, storage_key, owner_id, encrypted_size FROM files WHERE id = ?",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    storage_key = row["storage_key"]
    # Defense-in-depth: validate storage_key is a UUID before using in path
    validate_uuid(storage_key)
    encrypted_size = row["encrypted_size"]
    owner_id = row["owner_id"]

    # Atomic: update quota + delete record in one transaction
    await db.execute("BEGIN IMMEDIATE")
    try:
        await db.execute(
            "UPDATE users SET disk_used = MAX(0, disk_used - ?) WHERE id = ?",
            (encrypted_size, owner_id),
        )
        await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
    except Exception:
        await db.execute("ROLLBACK")
        raise

    # Disk cleanup after commit — non-blocking, best-effort
    blob_path = settings.FILES_DIR / storage_key

    def _unlink_blob():
        try:
            blob_path.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Failed to delete blob %s: %s", storage_key, exc)

    await asyncio.to_thread(_unlink_blob)

    return {"message": "File deleted"}


async def _log_download(
    db,
    request: Request,
    user: AuthenticatedUser,
    file_id: str,
) -> None:
    """Insert a 'download' access log entry. Best-effort — never raises.

    IP precedence: CF-Connecting-IP (Cloudflare) > X-Real-IP (nginx) >
    socket peer address.  All values are truncated before DB insert.
    """
    try:
        ip = (
            request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Real-IP")
            or (request.client.host if request.client else "unknown")
        )
        ip = ip[:64]
        ua = (request.headers.get("User-Agent") or "")[:512]
        log_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO access_logs
                (id, file_id, user_id, share_id, ip_address, user_agent, action)
            VALUES (?, ?, ?, NULL, ?, ?, 'download')
            """,
            (log_id, file_id, user.id, ip, ua),
        )
        await db.commit()
    except Exception:
        logger.warning("Failed to write access log for file %s", file_id)


@router.get("/{file_id}/content")
async def get_file_content(
    file_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Stream encrypted file bytes with HTTP Range support.

    The server never decrypts.  Clients fetch one encrypted chunk at a
    time via ``Range: bytes=<offset>-<offset+size-1>``, then decrypt
    using the per-chunk IV returned by GET /{file_id}/chunks.

    An access log entry is written on the first request for a file
    (Range start == 0, or no Range header).
    """
    file_id = validate_uuid(file_id)

    cursor = await db.execute(
        "SELECT id, storage_key, owner_id, folder_id, sanitized_name, "
        "encrypted_size, upload_complete FROM files WHERE id = ?",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    if not row["upload_complete"]:
        raise HTTPException(status_code=409, detail="File upload is not complete")

    await check_file_access(db, row, user)

    storage_key = row["storage_key"]
    validate_uuid(storage_key)  # defense-in-depth: must be a UUID before path join
    blob_path = settings.FILES_DIR / storage_key
    encrypted_size: int = row["encrypted_size"]

    if encrypted_size <= 0:
        raise HTTPException(status_code=422, detail="File has no content")

    # Verify blob exists on disk before committing to stream
    blob_exists = await asyncio.to_thread(blob_path.exists)
    if not blob_exists:
        logger.error(
            "Blob missing for file %s (storage_key=%s)", file_id, storage_key
        )
        raise HTTPException(status_code=503, detail="File data is temporarily unavailable")

    # --- Parse Range header ---
    range_header = request.headers.get("Range", "").strip()
    start = 0
    end = encrypted_size - 1

    if range_header:
        if not range_header.startswith("bytes="):
            raise HTTPException(status_code=400, detail="Only bytes ranges are supported")
        spec = range_header[6:]  # strip "bytes="
        parts = spec.split("-", 1)
        try:
            if parts[0] == "" and len(parts) == 2 and parts[1]:
                # Suffix range: bytes=-N  →  last N bytes
                suffix = int(parts[1])
                start = max(0, encrypted_size - suffix)
                end = encrypted_size - 1
            else:
                start = int(parts[0]) if parts[0] else 0
                end = int(parts[1]) if (len(parts) > 1 and parts[1]) else encrypted_size - 1
        except (ValueError, OverflowError):
            raise HTTPException(status_code=400, detail="Invalid Range header")

        if start < 0 or end < start or start >= encrypted_size:
            return Response(
                status_code=416,
                headers={"Content-Range": f"bytes */{encrypted_size}"},
            )
        end = min(end, encrypted_size - 1)

    content_length = end - start + 1
    status_code = 206 if range_header else 200

    # --- Bandwidth enforcement (checked before streaming begins) ---
    await check_bandwidth(db, user.id, content_length)

    # --- Access log (once per file download, not once per chunk request) ---
    if not range_header or start == 0:
        await _log_download(db, request, user, file_id)

    # --- Content-Disposition: RFC 5987 UTF-8 encoded filename ---
    safe_name = row["sanitized_name"] or "download"
    encoded_name = urllib.parse.quote(safe_name, safe="")
    disposition = f"attachment; filename*=UTF-8''{encoded_name}"

    resp_headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(content_length),
        "Content-Disposition": disposition,
        "Cache-Control": "no-store",
    }
    if status_code == 206:
        resp_headers["Content-Range"] = f"bytes {start}-{end}/{encrypted_size}"

    # --- Stream the requested byte range ---
    async def _stream():
        READ_SIZE = 256 * 1024  # 256 KB read buffer

        def _read_slice(pos: int, size: int) -> bytes:
            with open(blob_path, "rb") as f:
                f.seek(pos)
                return f.read(size)

        pos = start
        remaining = content_length
        while remaining > 0:
            to_read = min(READ_SIZE, remaining)
            data = await asyncio.to_thread(_read_slice, pos, to_read)
            if not data:
                break
            yield data
            pos += len(data)
            remaining -= len(data)

    return StreamingResponse(
        _stream(),
        status_code=status_code,
        media_type="application/octet-stream",
        headers=resp_headers,
    )


@router.get("/{file_id}/chunks")
async def get_file_chunks(
    file_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5000),
):
    """Return chunk manifest for client-side decryption.

    Paginated: use offset/limit for files with many chunks.
    """
    file_id = validate_uuid(file_id)

    cursor = await db.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    await check_file_access(db, row, user)

    cursor = await db.execute(
        "SELECT * FROM file_chunks WHERE file_id = ? ORDER BY chunk_index LIMIT ? OFFSET ?",
        (file_id, limit, offset),
    )
    chunks = [FileChunk.from_row(r).to_dict() for r in await cursor.fetchall()]

    return {
        "file_id": file_id,
        "original_name": row["original_name"],
        "mime_type": row["mime_type"],
        "size_bytes": row["size_bytes"],          # plaintext file size for integrity check
        "encrypted_file_key": row["encrypted_file_key"],
        "key_iv": row["key_iv"],
        "chunk_size": row["chunk_size"],
        "total_chunks": row["total_chunks"],
        "chunks": chunks,
        "offset": offset,
        "limit": limit,
    }
