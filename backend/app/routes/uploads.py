"""tus protocol upload routes.

Implements the tus v1.0.0 subset: POST (create), HEAD (resume check),
PATCH (send chunk), DELETE (abort).

Each chunk is received as raw encrypted bytes with its AES-GCM IV in the
X-Chunk-IV header. The server stores bytes verbatim — it never decrypts.
"""

import asyncio
import base64
import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.auth.dependencies import require_user_role
from app.routes._access import check_data_permission, copy_folder_permissions
from app.auth.interface import AuthenticatedUser
from app.config import settings
from app.database import Database, get_db
from app.middleware.bandwidth import check_bandwidth
from app.middleware.rate_limit import check_upload_rate_limit
from app.services import live_settings, sse_broker, event_bus
from app.schemas.security_event import SecurityEvent
import app.storage.manager as storage
from app.util.db import get_admin_setting
from app.validation.sanitizers import sanitize_filename, validate_base64, validate_uuid
from typing import Annotated

_bg_tasks: set = set()

logger = logging.getLogger(__name__)

router = APIRouter()

_TUS_VERSION        = "1.0.0"
_CONTENT_TYPE_PATCH = "application/offset+octet-stream"
_ERR_UPLOAD_NOT_FOUND = "Upload not found"
_SQL_DELETE_UPLOAD    = "DELETE FROM tus_uploads WHERE id = ?"
# Maximum single-chunk body: chunkSize (default 5 MB) + AES-GCM tag (16 B) + headroom
_MAX_CHUNK_BYTES = 21 * 1024 * 1024  # 21 MB


def _parse_size_params(meta: dict) -> tuple[int, int, "int | None"]:
    """Parse chunk_size, original_size, and last_modified_ms from upload metadata.

    Raises HTTPException(400) on invalid or out-of-range values.
    """
    try:
        chunk_size = int(meta["chunk_size"])
        original_size = int(meta["original_size"])
    except (ValueError, OverflowError):
        raise HTTPException(status_code=400, detail="chunk_size and original_size must be integers")

    last_modified_ms_raw = meta.get("last_modified_ms")
    try:
        last_modified_ms: int | None = int(last_modified_ms_raw) if last_modified_ms_raw else None
        if last_modified_ms is not None and last_modified_ms <= 0:
            raise ValueError("non-positive")
    except (ValueError, OverflowError):
        raise HTTPException(status_code=400, detail="last_modified_ms must be a positive integer if provided")

    if not (1 <= chunk_size <= _MAX_CHUNK_BYTES - 16):
        raise HTTPException(status_code=400, detail="chunk_size out of range")

    if original_size <= 0:
        raise HTTPException(status_code=400, detail="original_size must be positive")

    return chunk_size, original_size, last_modified_ms


def _tus_headers(extra: dict | None = None) -> dict:
    h = {"Tus-Resumable": _TUS_VERSION, "Tus-Version": _TUS_VERSION}
    if extra:
        h.update(extra)
    return h


def _parse_upload_metadata(raw: str) -> dict[str, str]:
    """Parse tus Upload-Metadata header.

    Format: ``key base64val, key2 base64val2``
    Values are UTF-8 decoded from their base64 representation.
    """
    result: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        pieces = part.split(" ", 1)
        key = pieces[0].strip()
        if len(pieces) == 2:
            try:
                val = base64.b64decode(pieces[1].strip()).decode("utf-8")
            except Exception:
                raise ValueError(f"Invalid base64 value for metadata key '{key}'")
        else:
            val = ""
        result[key] = val
    return result


# ---------------------------------------------------------------------------
# create_upload helpers
# ---------------------------------------------------------------------------

def _validate_metadata_fields(meta: dict) -> tuple:
    """Check required fields and validate escrow key encoding. Returns (escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv)."""
    for field in ("filename", "filetype", "encrypted_file_key", "key_iv", "chunk_size", "original_size"):
        if field not in meta:
            raise HTTPException(status_code=400, detail=f"Missing metadata field: {field}")
    escrow_ephemeral_pk: str | None = meta.get("escrow_ephemeral_pk") or None
    escrow_encrypted_key: str | None = meta.get("escrow_encrypted_key") or None
    escrow_key_iv: str | None = meta.get("escrow_key_iv") or None
    if escrow_ephemeral_pk and escrow_encrypted_key and escrow_key_iv:
        try:
            validate_base64(escrow_ephemeral_pk)
            validate_base64(escrow_encrypted_key)
            validate_base64(escrow_key_iv)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid escrow key field encoding")
    return escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv


async def _check_folder_access(db, user_id: str, folder_id_raw: str | None) -> str | None:
    """Validate folder UUID and write access. Returns validated folder_id or None."""
    if not folder_id_raw:
        return None
    try:
        folder_id = validate_uuid(folder_id_raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid folder_id in metadata")
    cursor = await db.execute(
        "SELECT id, owner_id FROM folders WHERE id = ?",
        (folder_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Folder not found")
    if row["owner_id"] == user_id:
        return folder_id
    allowed = await check_data_permission(db, "folder", folder_id, user_id, "write")
    if not allowed:
        raise HTTPException(status_code=403, detail="Folder access denied")  # NOSONAR
    return folder_id


async def _emit_quota_status_event(db, user_id: str, disk_used: int, disk_quota: int) -> None:
    """Emit an op_bus event for quota warning or ok status."""
    try:
        from app.services import op_bus
        from app.schemas.op_event import OperationalEvent
        warn_val = await get_admin_setting(db, "upload_quota_warn_pct")
        warn_pct = int(warn_val) if warn_val else 90
        used_pct = disk_used / disk_quota * 100
        if used_pct >= warn_pct:
            op_bus.emit(OperationalEvent(
                event_type="upload.quota.warning",
                severity="warning", source="upload",
                data={
                    "user_id":     user_id,
                    "used_bytes":  disk_used,
                    "quota_bytes": disk_quota,
                    "used_pct":    round(used_pct, 1),
                    "catch_up":    False,
                },
            ))
        else:
            op_bus.emit(OperationalEvent(
                event_type="upload.quota.ok",
                severity="info", source="upload",
                data={"user_id": user_id},
            ))
    except Exception:
        pass


async def _enforce_upload_quotas(db, user_id: str, total_encrypted_size: int) -> None:
    """Fetch user row and enforce global/personal size limits and disk quota."""
    cursor = await db.execute(
        "SELECT disk_used, disk_quota, max_file_size FROM users WHERE id = ?",
        (user_id,),
    )
    user_row = await cursor.fetchone()
    if user_row is None:
        raise HTTPException(status_code=404, detail="User not found")

    gmax_val = await get_admin_setting(db, "global_max_file_size")
    global_max = int(gmax_val) if gmax_val is not None else settings.GLOBAL_MAX_FILE_SIZE
    if global_max > 0 and total_encrypted_size > global_max:
        raise HTTPException(status_code=413, detail="File exceeds the server's maximum allowed size")
    if user_row["max_file_size"] is not None and total_encrypted_size > user_row["max_file_size"]:
        raise HTTPException(status_code=413, detail="File exceeds the maximum allowed size")

    if user_row["disk_quota"] is not None:
        if user_row["disk_used"] + total_encrypted_size > user_row["disk_quota"]:
            raise HTTPException(status_code=413, detail="Storage quota exceeded")
        await _emit_quota_status_event(db, user_id, user_row["disk_used"], user_row["disk_quota"])


def _parse_create_upload_headers(request: Request) -> tuple[int, str]:
    """Validate POST /uploads Tus headers. Returns (total_encrypted_size, metadata_raw)."""
    if request.headers.get("Tus-Resumable", "") != _TUS_VERSION:
        raise HTTPException(status_code=400, detail="Unsupported Tus-Resumable version")
    upload_length_raw = request.headers.get("Upload-Length", "")
    if not upload_length_raw.isdigit():
        raise HTTPException(status_code=400, detail="Upload-Length header required")
    total_encrypted_size = int(upload_length_raw)
    if total_encrypted_size <= 0:
        raise HTTPException(status_code=400, detail="Upload-Length must be positive")
    metadata_raw = request.headers.get("Upload-Metadata", "")
    if not metadata_raw:
        raise HTTPException(status_code=400, detail="Upload-Metadata header required")
    return total_encrypted_size, metadata_raw


# ---------------------------------------------------------------------------
# POST /uploads  — create a new upload
# ---------------------------------------------------------------------------

@router.post("", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}, 413: {"description": "413"}})
async def create_upload(
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    _rl: Annotated[None, Depends(check_upload_rate_limit)],
):
    """Create a new tus upload. Returns 201 with Location header."""

    total_encrypted_size, metadata_raw = _parse_create_upload_headers(request)

    try:
        meta = _parse_upload_metadata(metadata_raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # --- Validate required metadata fields and escrow encoding ---
    escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv = _validate_metadata_fields(meta)

    try:
        sanitized = sanitize_filename(meta["filename"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    original_name = meta["filename"]
    sanitized_name = sanitized.name
    mime_type = (meta["filetype"] or "application/octet-stream")[:256]

    try:
        encrypted_file_key = validate_base64(meta["encrypted_file_key"])
        key_iv = validate_base64(meta["key_iv"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    chunk_size, original_size, last_modified_ms = _parse_size_params(meta)

    # Enforce admin-configured chunk size.  Clients fetch the current value from
    # /auth/public-settings on startup; a mismatch means the setting changed since
    # the client last loaded — tell the client to refresh and retry.
    cs_val = await get_admin_setting(db, "default_chunk_size")
    admin_chunk_size = int(cs_val) if cs_val is not None else settings.DEFAULT_CHUNK_SIZE
    if chunk_size != admin_chunk_size:
        raise HTTPException(
            status_code=400,
            detail="invalid chunk_size, please refresh and try again",
        )

    folder_id = await _check_folder_access(db, user.id, meta.get("folder_id") or None)
    await _enforce_upload_quotas(db, user.id, total_encrypted_size)

    total_chunks = (original_size + chunk_size - 1) // chunk_size

    # --- Create file + tus_upload records atomically ---
    file_id = str(uuid.uuid4())
    storage_key = str(uuid.uuid4())
    upload_id = str(uuid.uuid4())
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=live_settings.get_int("tus_upload_expiry_hours", settings.TUS_UPLOAD_EXPIRY_HOURS))
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            INSERT INTO files (
                id, original_name, sanitized_name, storage_key, folder_id, owner_id,
                mime_type, size_bytes, encrypted_size, chunk_size, total_chunks,
                encrypted_file_key, key_iv, upload_complete,
                escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv,
                last_modified_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (
                file_id, original_name, sanitized_name, storage_key, folder_id, user.id,
                mime_type, original_size, total_encrypted_size, chunk_size, total_chunks,
                encrypted_file_key, key_iv,
                escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv,
                last_modified_ms,
            ),
        )
        # Inherit recursive permissions from the parent folder (personal root = no-inherit)
        if folder_id:
            await copy_folder_permissions(db, folder_id, "file", file_id)
        await db.execute(
            """
            INSERT INTO tus_uploads
                (id, file_id, user_id, total_size, current_offset, next_chunk,
                 expires_at, part_tags)
            VALUES (?, ?, ?, ?, 0, 0, ?, '[]')
            """,
            (upload_id, file_id, user.id, total_encrypted_size, expires_at),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    await storage.get_manager().begin_upload(upload_id)

    return Response(
        status_code=201,
        headers=_tus_headers({
            "Location": f"/api/v1/uploads/{upload_id}",
            "Upload-Offset": "0",
        }),
    )


# ---------------------------------------------------------------------------
# HEAD /uploads/{upload_id}  — resume check
# ---------------------------------------------------------------------------

@router.head("/{upload_id}", responses={404: {"description": "Not Found"}})
async def head_upload(
    upload_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return current Upload-Offset and Upload-Length for a pending upload."""
    try:
        upload_id = validate_uuid(upload_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_UPLOAD_NOT_FOUND)

    cursor = await db.execute(
        "SELECT current_offset, total_size FROM tus_uploads WHERE id = ? AND user_id = ?",
        (upload_id, user.id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_UPLOAD_NOT_FOUND)

    return Response(
        status_code=200,
        headers=_tus_headers({
            "Upload-Offset": str(row["current_offset"]),
            "Upload-Length": str(row["total_size"]),
            "Cache-Control": "no-store",
        }),
    )


# ---------------------------------------------------------------------------
# patch_upload helpers
# ---------------------------------------------------------------------------

async def _read_and_verify_chunk(
    request: Request, upload_id: str, chunk_index: int, client_offset: int
) -> bytes:
    """Read request body and verify the X-Chunk-Hash header. Raises 400 on any mismatch."""
    chunk_data = await request.body()
    if not chunk_data:
        raise HTTPException(status_code=400, detail="Empty chunk body")
    if len(chunk_data) > _MAX_CHUNK_BYTES:
        raise HTTPException(status_code=413, detail="Chunk body too large")
    chunk_hash_header = request.headers.get("X-Chunk-Hash", "")
    if not chunk_hash_header:
        raise HTTPException(status_code=400, detail="X-Chunk-Hash header required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", chunk_hash_header):
        raise HTTPException(status_code=400, detail="Invalid X-Chunk-Hash format (expected sha256:<64 hex chars>)")
    expected_hex = chunk_hash_header[7:]
    actual_hex = await asyncio.to_thread(lambda: hashlib.sha256(chunk_data).hexdigest())
    if actual_hex != expected_hex:
        logger.warning(  # NOSONAR — server-side audit log; values are Pydantic-validated
            "Chunk hash mismatch for upload %s chunk %d at offset %d "
            "(expected=%s actual=%s size=%d)",
            upload_id, chunk_index, client_offset,
            expected_hex, actual_hex, len(chunk_data),
        )
        raise HTTPException(status_code=400, detail="Chunk integrity check failed: hash mismatch")
    return chunk_data


async def _record_chunk_in_db(
    db, upload_id: str, file_id: str, chunk_index: int, chunk_iv_b64: str,
    chunk_size: int, client_offset: int, new_offset: int, etag
) -> None:
    chunk_id = str(uuid.uuid4())
    new_expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=live_settings.get_int("tus_upload_expiry_hours", settings.TUS_UPLOAD_EXPIRY_HOURS))
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    chunk_now = datetime.now(timezone.utc).isoformat()
    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            INSERT INTO file_chunks (id, file_id, chunk_index, iv, size_bytes, "offset")
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (chunk_id, file_id, chunk_index, chunk_iv_b64, chunk_size, client_offset),
        )
        if etag is not None:
            await db.execute(
                "UPDATE tus_uploads "
                "SET current_offset = ?, next_chunk = ?, expires_at = ?, updated_at = ?, "
                "    part_tags = (COALESCE(part_tags::jsonb, '[]'::jsonb) || jsonb_build_array(?::text))::text "
                "WHERE id = ?",
                (new_offset, chunk_index + 1, new_expires_at, chunk_now, etag, upload_id),
            )
        else:
            await db.execute(
                "UPDATE tus_uploads "
                "SET current_offset = ?, next_chunk = ?, expires_at = ?, updated_at = ? "
                "WHERE id = ?",
                (new_offset, chunk_index + 1, new_expires_at, chunk_now, upload_id),
            )
        await db.commit()
    except Exception as _phase1_exc:
        logger.error("Phase 1 DB update failed for upload %s: %s", upload_id, _phase1_exc)  # NOSONAR — server-side audit log; values are Pydantic-validated
        await db.rollback()
        raise


async def _finalize_completed_upload(
    db, upload_id: str, file_id: str, storage_key: str,
    new_offset: int, chunk_index: int, user_id: str, file_row
) -> None:
    tags_cursor = await db.execute(
        "SELECT part_tags FROM tus_uploads WHERE id = ?", (upload_id,)
    )
    tags_row = await tags_cursor.fetchone()
    part_tags: list[str] = json.loads(tags_row["part_tags"] or "[]") if tags_row else []

    try:
        actual_size = await storage.get_manager().finalize_upload(
            db, upload_id, file_id, storage_key, part_tags
        )
    except Exception as exc:
        logger.error("Upload finalization failed for %s: %s", upload_id, exc)  # NOSONAR — server-side audit log; values are Pydantic-validated
        raise HTTPException(status_code=500, detail="Upload finalization failed")

    if actual_size != new_offset:
        logger.error(
            "Blob size mismatch for file %s: expected %d bytes, got %d",
            file_id, new_offset, actual_size,
        )
        await storage.get_manager().abort_upload(upload_id)
        raise HTTPException(status_code=500, detail="Upload finalization failed: size mismatch")

    await db.execute("BEGIN")
    try:
        count_cursor = await db.execute(
            "SELECT COUNT(*) FROM file_chunks WHERE file_id = ?", (file_id,)
        )
        count_row = await count_cursor.fetchone()
        expected_chunks = chunk_index + 1
        if count_row[0] != expected_chunks:
            await db.rollback()
            logger.error(
                "Chunk count mismatch for file %s: expected %d, got %d",
                file_id, expected_chunks, count_row[0],
            )
            raise HTTPException(
                status_code=500,
                detail="Upload finalization failed: chunk count mismatch",
            )
        await db.execute(
            "UPDATE files SET upload_complete = 1, encrypted_size = ?, updated_at = NOW() "
            "WHERE id = ?",
            (new_offset, file_id),
        )
        await db.execute(
            "UPDATE users SET disk_used = disk_used + ? WHERE id = ?",
            (new_offset, user_id),
        )
        await db.execute(_SQL_DELETE_UPLOAD, (upload_id,))
        await db.commit()
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise

    event_bus.emit(SecurityEvent(
        event_type="file.upload.completed",
        severity="info",
        outcome="success",
        user_id=user_id,
        detail={"file_id": file_id, "size": new_offset},
    ))

    _topic = file_row["folder_id"] or f"root:{file_row['owner_id']}"
    sse_broker.publish(_topic, {"type": "change"})

    _t = asyncio.create_task(_maybe_scan_file(file_id))
    _bg_tasks.add(_t)
    _t.add_done_callback(_bg_tasks.discard)


# ---------------------------------------------------------------------------
# PATCH /uploads/{upload_id}  — send a chunk
# ---------------------------------------------------------------------------

def _parse_patch_upload_headers(request: Request, upload_id_raw: str) -> tuple[str, int, str]:
    """Validate PATCH /uploads/{id} headers. Returns (upload_id, client_offset, chunk_iv_b64)."""
    try:
        upload_id = validate_uuid(upload_id_raw)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_UPLOAD_NOT_FOUND)
    if request.headers.get("Tus-Resumable", "") != _TUS_VERSION:
        raise HTTPException(status_code=400, detail="Unsupported Tus-Resumable version")
    if request.headers.get("Content-Type", "") != _CONTENT_TYPE_PATCH:
        raise HTTPException(status_code=415, detail=f"Content-Type must be {_CONTENT_TYPE_PATCH}")
    offset_raw = request.headers.get("Upload-Offset", "")
    if not offset_raw.isdigit():
        raise HTTPException(status_code=400, detail="Upload-Offset header required")
    chunk_iv_b64 = request.headers.get("X-Chunk-IV", "")
    if not chunk_iv_b64:
        raise HTTPException(status_code=400, detail="X-Chunk-IV header required")
    try:
        validate_base64(chunk_iv_b64)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid X-Chunk-IV header")
    return upload_id, int(offset_raw), chunk_iv_b64


@router.patch("/{upload_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}, 410: {"description": "Gone"}, 413: {"description": "413"}, 415: {"description": "415"}, 423: {"description": "423"}, 500: {"description": "Internal Server Error"}})
async def patch_upload(
    upload_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Receive one encrypted chunk and append it to the upload."""
    upload_id, client_offset, chunk_iv_b64 = _parse_patch_upload_headers(request, upload_id)

    # --- Fetch and validate upload record ---
    cursor = await db.execute(
        "SELECT id, file_id, user_id, total_size, current_offset, next_chunk, expires_at "
        "FROM tus_uploads WHERE id = ? AND user_id = ?",
        (upload_id, user.id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_UPLOAD_NOT_FOUND)

    now_iso = datetime.now(timezone.utc).isoformat()
    if row["expires_at"] < now_iso:
        raise HTTPException(status_code=410, detail="Upload has expired")

    if client_offset != row["current_offset"]:
        raise HTTPException(
            status_code=409,
            detail=f"Offset conflict: server is at {row['current_offset']}",
        )

    # --- Read and verify chunk body (hash validated in helper) ---
    chunk_data = await _read_and_verify_chunk(request, upload_id, row["next_chunk"], client_offset)
    chunk_size = len(chunk_data)

    new_offset = client_offset + chunk_size
    if new_offset > row["total_size"]:
        raise HTTPException(status_code=400, detail="Chunk extends beyond Upload-Length")

    # --- Fetch file record (storage_key, transfer lock, chunk geometry) ---
    cursor = await db.execute(
        "SELECT id, storage_key, folder_id, owner_id, transfer_locked_at, chunk_size "
        "FROM files WHERE id = ?",
        (row["file_id"],),
    )
    file_row = await cursor.fetchone()
    if file_row is None:
        raise HTTPException(status_code=500, detail="File record missing for upload")

    if file_row["transfer_locked_at"] is not None:
        raise HTTPException(status_code=423, detail="File is transfer-locked by an administrator")

    storage_key = file_row["storage_key"]
    chunk_index = row["next_chunk"]
    is_complete = new_offset == row["total_size"]

    # Validate per-chunk body size against the chunk_size stored when the upload was
    # created (not the current admin setting, which may change mid-upload).
    # Each encrypted chunk = plaintext + 16-byte AES-GCM tag.
    expected_enc_size = file_row["chunk_size"] + 16
    if not is_complete and chunk_size != expected_enc_size:
        raise HTTPException(
            status_code=400,
            detail=f"Unexpected chunk size: expected {expected_enc_size} bytes",
        )

    # --- Bandwidth enforcement (checked before disk write) ---
    await check_bandwidth(db, user.id, chunk_size)

    # --- Write chunk via storage manager (provider handles seek/multipart internally) ---
    try:
        etag = await storage.get_manager().write_chunk(
            upload_id, chunk_index + 1, client_offset, chunk_data
        )
    except Exception as exc:
        logger.error("Failed to write chunk for upload %s: %s", upload_id, exc)  # NOSONAR — server-side audit log; values are Pydantic-validated
        raise HTTPException(status_code=500, detail="Chunk write failed")

    # --- Phase 1 DB update: record this chunk and advance the tus offset ---
    await _record_chunk_in_db(
        db, upload_id, row["file_id"], chunk_index, chunk_iv_b64,
        chunk_size, client_offset, new_offset, etag,
    )

    # --- If complete, finalize via storage manager then commit Phase 2 ---
    if is_complete:
        await _finalize_completed_upload(
            db, upload_id, row["file_id"], storage_key,
            new_offset, chunk_index, user.id, file_row,
        )

    extra_headers: dict = {"Upload-Offset": str(new_offset)}
    if is_complete:
        extra_headers["X-File-ID"] = row["file_id"]

    return Response(
        status_code=204,
        headers=_tus_headers(extra_headers),
    )


# ---------------------------------------------------------------------------
# DELETE /uploads/{upload_id}  — abort
# ---------------------------------------------------------------------------

@router.delete("/{upload_id}", responses={404: {"description": "Not Found"}})
async def abort_upload(
    upload_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Abort an upload: delete the tus record, incomplete file record, and staging blob."""
    try:
        upload_id = validate_uuid(upload_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_UPLOAD_NOT_FOUND)

    cursor = await db.execute(
        "SELECT tus_uploads.file_id "
        "FROM tus_uploads "
        "WHERE tus_uploads.id = ? AND tus_uploads.user_id = ?",
        (upload_id, user.id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_UPLOAD_NOT_FOUND)

    file_id = row["file_id"]

    await db.execute("BEGIN")
    try:
        # Deleting the file cascades to file_chunks via FK; tus_uploads also FKs to files.
        await db.execute(_SQL_DELETE_UPLOAD, (upload_id,))
        await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    await storage.get_manager().abort_upload(upload_id)
    return Response(status_code=204, headers=_tus_headers())


# ---------------------------------------------------------------------------
# Escrow public key endpoint
# ---------------------------------------------------------------------------

@router.get("/escrow-key", responses={404: {"description": "Not Found"}})
async def get_escrow_public_key(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
):
    """Return the server's escrow ECDH public key (SPKI, base64).

    Returns 404 when TUSSHARE_ESCROW_PRIVATE_KEY is not configured.
    Clients use this to decide whether to include escrow key fields on upload.
    """
    from app.services.av_scanner import get_escrow_public_key_b64
    pub_b64 = get_escrow_public_key_b64()
    if pub_b64 is None:
        raise HTTPException(status_code=404, detail="Escrow key not configured")
    return {"escrow_public_key": pub_b64}


@router.get("/pending")
async def list_pending_uploads(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db:   Annotated[Database, Depends(get_db)],
):
    """Return all incomplete tus uploads owned by the current user.

    Used by the client Transfers tab to surface interrupted uploads from any
    folder so the user can navigate back and resume without having to remember
    which folder the upload was started in.
    """
    result = await db.execute(
        """
        SELECT tu.id            AS upload_id,
               f.original_name,
               f.size_bytes,
               f.encrypted_file_key,
               f.key_iv,
               f.folder_id,
               tu.current_offset,
               tu.total_size,
               tu.expires_at
          FROM tus_uploads tu
          JOIN files f ON tu.file_id = f.id
         WHERE tu.user_id = ?
         ORDER BY tu.created_at DESC
        """,
        (user.id,),
    )
    rows = await result.fetchall()
    return {"pending_uploads": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _maybe_scan_file(file_id: str) -> None:
    """Background task: run AV scan if configured. Errors are logged, not raised."""
    try:
        from app.database import db_session
        from app.services.av_scanner import scan_file
        async with db_session() as _db:
            await scan_file(_db, file_id)
    except Exception as exc:
        logger.warning("Background AV scan failed for file %s: %s", file_id, exc)


# ---------------------------------------------------------------------------
# Background cleanup task
# ---------------------------------------------------------------------------

async def _cleanup_expired_uploads(db) -> int:
    """Delete tus_uploads whose expires_at has passed, plus their file records
    and staging blobs.  expires_at is now a sliding window (reset on every
    successful PATCH), so only truly abandoned uploads are removed.

    Returns the number of uploads deleted.
    """
    now = datetime.now(timezone.utc).isoformat()
    cursor = await db.execute(
        "SELECT id AS upload_id, file_id FROM tus_uploads WHERE expires_at < ?",
        (now,),
    )
    rows = await cursor.fetchall()
    if not rows:
        return 0

    count = 0
    for row in rows:
        upload_id = row["upload_id"]
        file_id   = row["file_id"]
        try:
            await db.execute("BEGIN")
            await db.execute(_SQL_DELETE_UPLOAD, (upload_id,))
            await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
            await db.commit()
        except Exception:
            await db.rollback()
            logger.exception("Failed to clean up expired upload %s", upload_id)
            continue

        try:
            await storage.get_manager().abort_upload(upload_id)
        except Exception as exc:
            logger.warning("Could not delete staging blob for upload %s: %s", upload_id, exc)

        count += 1

    if count > 0:
        logger.info("Cleaned up %d expired upload(s)", count)
    return count


async def run_upload_cleanup(db_factory, interval: float = 3600.0) -> None:
    """Periodic background task — removes expired incomplete uploads.

    Runs every `interval` seconds (default 1 hour).  db_factory is an async
    context manager factory (e.g. db_session from app.database).
    """
    while True:
        await asyncio.sleep(interval)
        try:
            async with db_factory() as db:
                await _cleanup_expired_uploads(db)
        except Exception:
            logger.exception("Upload cleanup task failed")
