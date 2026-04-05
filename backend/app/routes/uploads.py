"""tus protocol upload routes.

Implements the tus v1.0.0 subset: POST (create), HEAD (resume check),
PATCH (send chunk), DELETE (abort).

Each chunk is received as raw encrypted bytes with its AES-GCM IV in the
X-Chunk-IV header. The server stores bytes verbatim — it never decrypts.
"""

import asyncio
import base64
import hashlib
import logging
import os
import re
import shutil
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.config import settings
from app.database import get_db
from app.middleware.bandwidth import check_bandwidth
from app.services import sse_broker
from app.validation.sanitizers import sanitize_filename, validate_base64, validate_uuid

logger = logging.getLogger(__name__)

router = APIRouter()

_TUS_VERSION = "1.0.0"
_CONTENT_TYPE_PATCH = "application/offset+octet-stream"
# Maximum single-chunk body: chunkSize (default 5 MB) + AES-GCM tag (16 B) + headroom
_MAX_CHUNK_BYTES = 21 * 1024 * 1024  # 21 MB

# ---------------------------------------------------------------------------
# Page-cache eviction — stride-based
# ---------------------------------------------------------------------------
# On every completed chunk the PATCH handler checks whether the upload has
# crossed another _EVICT_STRIDE boundary.  When it has, the staging blob is
# fdatasync'd (flushing dirty pages to storage so they become evictable) and
# posix_fadvise(DONTNEED) is called for all bytes written so far.  This caps
# page-cache consumption to roughly _EVICT_STRIDE per concurrent upload
# regardless of file size — important on network volumes where fdatasync per
# chunk would add one storage round-trip per 5 MB instead of one per 32 MB.
#
# _evict_offsets tracks {upload_id → bytes evicted so far} in process memory.
# The dict is intentionally process-local: if the server restarts mid-upload
# the worst case is one stride's worth of stale pages that the kernel reclaims
# naturally under memory pressure.  Redis is the right home for this state once
# the server goes multi-worker (Phase F).
#
# The stride itself is read from settings at first use so that the configured
# value is always current (including test overrides).  0 = disabled.
_evict_offsets: dict[str, int] = {}


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


def _write_chunk_at(path, offset: int, data: bytes) -> None:
    """Write *data* at *offset*, truncating any stale bytes beyond the new end.

    Idempotent: re-sending the same chunk at the same offset overwrites
    identically, so a DB-rollback-then-retry scenario is safe.

    Page-cache eviction is handled separately by _stride_evict, called by
    the PATCH handler after every _EVICT_STRIDE bytes written.
    """
    mode = "r+b" if path.exists() else "wb"
    with open(path, mode) as f:
        f.seek(offset)
        f.write(data)
        f.truncate()


def _stride_evict(path, up_to: int) -> None:
    """fdatasync the staging blob then advise the OS to evict pages [0, up_to).

    fdatasync first: POSIX_FADV_DONTNEED only evicts *clean* pages.  Calling
    it on dirty pages is a no-op on Linux, so without the sync step the hint
    would be silently ignored and cache would keep growing.  Opening r+b is
    required because fdatasync needs a writable file descriptor.
    """
    try:
        with open(path, "r+b") as f:
            os.fdatasync(f.fileno())
            os.posix_fadvise(f.fileno(), 0, up_to, os.POSIX_FADV_DONTNEED)
    except (AttributeError, OSError):
        pass  # not available (Windows/macOS/some BSDs) or unsupported filesystem


# ---------------------------------------------------------------------------
# POST /uploads  — create a new upload
# ---------------------------------------------------------------------------

@router.post("")
async def create_upload(
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Create a new tus upload. Returns 201 with Location header."""

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

    try:
        meta = _parse_upload_metadata(metadata_raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # --- Validate required metadata fields ---
    for field in ("filename", "filetype", "encrypted_file_key", "key_iv",
                  "chunk_size", "original_size"):
        if field not in meta:
            raise HTTPException(status_code=400, detail=f"Missing metadata field: {field}")

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

    try:
        chunk_size = int(meta["chunk_size"])
        original_size = int(meta["original_size"])
    except (ValueError, OverflowError):
        raise HTTPException(status_code=400, detail="chunk_size and original_size must be integers")

    if not (1 <= chunk_size <= _MAX_CHUNK_BYTES - 16):
        raise HTTPException(status_code=400, detail="chunk_size out of range")
    if original_size <= 0:
        raise HTTPException(status_code=400, detail="original_size must be positive")

    folder_id: str | None = meta.get("folder_id") or None
    if folder_id:
        try:
            folder_id = validate_uuid(folder_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid folder_id in metadata")
        cursor = await db.execute(
            "SELECT id FROM folders WHERE id = ? AND owner_id = ?",
            (folder_id, user.id),
        )
        if not await cursor.fetchone():
            raise HTTPException(status_code=404, detail="Folder not found")

    # --- Quota / size limit enforcement ---
    cursor = await db.execute(
        "SELECT disk_used, disk_quota, max_file_size FROM users WHERE id = ?",
        (user.id,),
    )
    user_row = await cursor.fetchone()
    if user_row is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Global max file size (admin setting; 0 = no limit)
    cursor = await db.execute(
        "SELECT value FROM admin_settings WHERE key = 'global_max_file_size'"
    )
    setting_row = await cursor.fetchone()
    global_max = int(setting_row["value"]) if setting_row else settings.GLOBAL_MAX_FILE_SIZE

    if global_max > 0 and total_encrypted_size > global_max:
        raise HTTPException(status_code=413, detail="File exceeds the server's maximum allowed size")

    if user_row["max_file_size"] is not None and total_encrypted_size > user_row["max_file_size"]:
        raise HTTPException(status_code=413, detail="File exceeds the maximum allowed size")

    if user_row["disk_quota"] is not None:
        if user_row["disk_used"] + total_encrypted_size > user_row["disk_quota"]:
            raise HTTPException(status_code=413, detail="Storage quota exceeded")

    total_chunks = (original_size + chunk_size - 1) // chunk_size

    # --- Create file + tus_upload records atomically ---
    file_id = str(uuid.uuid4())
    storage_key = str(uuid.uuid4())
    upload_id = str(uuid.uuid4())
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=settings.TUS_UPLOAD_EXPIRY_HOURS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            INSERT INTO files (
                id, original_name, sanitized_name, storage_key, folder_id, owner_id,
                mime_type, size_bytes, encrypted_size, chunk_size, total_chunks,
                encrypted_file_key, key_iv, upload_complete
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                file_id, original_name, sanitized_name, storage_key, folder_id, user.id,
                mime_type, original_size, total_encrypted_size, chunk_size, total_chunks,
                encrypted_file_key, key_iv,
            ),
        )
        await db.execute(
            """
            INSERT INTO tus_uploads
                (id, file_id, user_id, total_size, current_offset, next_chunk, expires_at)
            VALUES (?, ?, ?, ?, 0, 0, ?)
            """,
            (upload_id, file_id, user.id, total_encrypted_size, expires_at),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

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

@router.head("/{upload_id}")
async def head_upload(
    upload_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Return current Upload-Offset and Upload-Length for a pending upload."""
    try:
        upload_id = validate_uuid(upload_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Upload not found")

    cursor = await db.execute(
        "SELECT current_offset, total_size FROM tus_uploads WHERE id = ? AND user_id = ?",
        (upload_id, user.id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    return Response(
        status_code=200,
        headers=_tus_headers({
            "Upload-Offset": str(row["current_offset"]),
            "Upload-Length": str(row["total_size"]),
            "Cache-Control": "no-store",
        }),
    )


# ---------------------------------------------------------------------------
# PATCH /uploads/{upload_id}  — send a chunk
# ---------------------------------------------------------------------------

@router.patch("/{upload_id}")
async def patch_upload(
    upload_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Receive one encrypted chunk and append it to the upload."""
    try:
        upload_id = validate_uuid(upload_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Upload not found")

    if request.headers.get("Tus-Resumable", "") != _TUS_VERSION:
        raise HTTPException(status_code=400, detail="Unsupported Tus-Resumable version")

    if request.headers.get("Content-Type", "") != _CONTENT_TYPE_PATCH:
        raise HTTPException(
            status_code=415,
            detail=f"Content-Type must be {_CONTENT_TYPE_PATCH}",
        )

    offset_raw = request.headers.get("Upload-Offset", "")
    if not offset_raw.isdigit():
        raise HTTPException(status_code=400, detail="Upload-Offset header required")
    client_offset = int(offset_raw)

    chunk_iv_b64 = request.headers.get("X-Chunk-IV", "")
    if not chunk_iv_b64:
        raise HTTPException(status_code=400, detail="X-Chunk-IV header required")
    try:
        validate_base64(chunk_iv_b64)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid X-Chunk-IV header")

    # --- Fetch and validate upload record ---
    cursor = await db.execute(
        "SELECT id, file_id, user_id, total_size, current_offset, next_chunk, expires_at "
        "FROM tus_uploads WHERE id = ? AND user_id = ?",
        (upload_id, user.id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    now_iso = datetime.now(timezone.utc).isoformat()
    if row["expires_at"] < now_iso:
        raise HTTPException(status_code=410, detail="Upload has expired")

    if client_offset != row["current_offset"]:
        raise HTTPException(
            status_code=409,
            detail=f"Offset conflict: server is at {row['current_offset']}",
        )

    # --- Read and validate chunk body ---
    chunk_data = await request.body()
    if not chunk_data:
        raise HTTPException(status_code=400, detail="Empty chunk body")

    chunk_size = len(chunk_data)
    if chunk_size > _MAX_CHUNK_BYTES:
        raise HTTPException(status_code=413, detail="Chunk body too large")

    # --- Verify per-chunk hash (application-layer integrity check) ---
    # Client sends SHA-256 of the ciphertext bytes as "sha256:<64 hex chars>".
    # This is independent of TLS integrity and lets the server confirm the bytes
    # received match what the client computed before sending.
    chunk_hash_header = request.headers.get("X-Chunk-Hash", "")
    if not chunk_hash_header:
        raise HTTPException(status_code=400, detail="X-Chunk-Hash header required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", chunk_hash_header):
        raise HTTPException(status_code=400, detail="Invalid X-Chunk-Hash format (expected sha256:<64 hex chars>)")
    expected_hex = chunk_hash_header[7:]
    # Offload to thread pool: SHA-256 over a 5 MB chunk is ~15–20 ms of pure CPU
    # and must not block the async event loop.
    actual_hex = await asyncio.to_thread(lambda: hashlib.sha256(chunk_data).hexdigest())
    if actual_hex != expected_hex:
        logger.warning(
            "Chunk hash mismatch for upload %s chunk %d at offset %d "
            "(expected=%s actual=%s size=%d)",
            upload_id, row["next_chunk"], client_offset,
            expected_hex, actual_hex, chunk_size,
        )
        raise HTTPException(status_code=400, detail="Chunk integrity check failed: hash mismatch")

    new_offset = client_offset + chunk_size
    if new_offset > row["total_size"]:
        raise HTTPException(status_code=400, detail="Chunk extends beyond Upload-Length")

    # --- Bandwidth enforcement (checked before disk write) ---
    await check_bandwidth(db, user.id, chunk_size)

    # --- Fetch storage_key from file record ---
    cursor = await db.execute(
        "SELECT id, storage_key, folder_id, owner_id FROM files WHERE id = ?",
        (row["file_id"],),
    )
    file_row = await cursor.fetchone()
    if file_row is None:
        raise HTTPException(status_code=500, detail="File record missing for upload")

    storage_key = file_row["storage_key"]
    validate_uuid(storage_key)  # defense-in-depth before path join (matches files.py)
    chunk_index = row["next_chunk"]
    is_complete = new_offset == row["total_size"]

    # --- Write chunk to staging blob (seek+write+truncate = idempotent) ---
    upload_blob = settings.UPLOADS_DIR / upload_id
    try:
        await asyncio.to_thread(_write_chunk_at, upload_blob, client_offset, chunk_data)
    except OSError as exc:
        logger.error("Failed to write chunk for upload %s: %s", upload_id, exc)
        raise HTTPException(status_code=500, detail="Chunk write failed")

    # --- Stride-based page-cache eviction ---
    # Every UPLOAD_EVICT_STRIDE_MB bytes, fdatasync the staging blob and advise
    # the OS to evict all pages written so far.  This caps page-cache consumption
    # to ~stride per concurrent upload, avoiding a climb proportional to file size
    # that would otherwise appear in container memory metrics.  0 = disabled.
    evict_stride = settings.UPLOAD_EVICT_STRIDE_MB * 1024 * 1024
    last_evicted = _evict_offsets.get(upload_id, 0)
    if evict_stride > 0 and new_offset - last_evicted >= evict_stride:
        try:
            await asyncio.to_thread(_stride_evict, upload_blob, new_offset)
            _evict_offsets[upload_id] = new_offset
        except Exception:
            pass  # eviction is best-effort; never fail a chunk write over it

    # --- Phase 1 DB update: record this chunk and advance the tus offset ---
    # Committed regardless of whether this is the final chunk.
    chunk_id = str(uuid.uuid4())
    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            INSERT INTO file_chunks (id, file_id, chunk_index, iv, size_bytes, "offset")
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (chunk_id, row["file_id"], chunk_index, chunk_iv_b64, chunk_size, client_offset),
        )
        new_expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=settings.TUS_UPLOAD_EXPIRY_HOURS)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        chunk_now = datetime.now(timezone.utc).isoformat()
        await db.execute(
            "UPDATE tus_uploads "
            "SET current_offset = ?, next_chunk = ?, expires_at = ?, updated_at = ? "
            "WHERE id = ?",
            (new_offset, chunk_index + 1, new_expires_at, chunk_now, upload_id),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    # --- If complete, verify blob integrity then finalize in a second DB transaction ---
    if is_complete:
        final_path = settings.FILES_DIR / storage_key

        # Move staging blob to permanent storage, then evict its pages from the
        # page cache.  Page cache entries follow the inode on rename, so the
        # pages accumulated during the chunked write are still resident under
        # the new path.  DONTNEED after the move signals the OS to drop them;
        # they will be faulted back in on demand when users download the file.
        def _finalize():
            try:
                upload_blob.rename(final_path)
            except OSError:
                # Cross-device link (UPLOADS_DIR and FILES_DIR on different mounts)
                shutil.move(str(upload_blob), str(final_path))
            # Evict any remaining dirty pages from the tail of the last stride.
            # Page cache entries follow the inode on rename, so we open the
            # final path.  After this the file is fully on disk and out of cache.
            try:
                with open(final_path, "r+b") as f:
                    os.fdatasync(f.fileno())
                    os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            except (AttributeError, OSError):
                pass  # not available (Windows/macOS) or unsupported filesystem

        try:
            await asyncio.to_thread(_finalize)
        except OSError as exc:
            logger.error(
                "Failed to move upload blob %s -> %s: %s", upload_id, storage_key, exc
            )
            raise HTTPException(status_code=500, detail="Upload finalization failed: move error")
        finally:
            _evict_offsets.pop(upload_id, None)

        # Verify the blob landed at the expected size.
        # A cross-device copy that got interrupted would produce a truncated file.
        def _stat_size() -> int:
            return final_path.stat().st_size

        try:
            actual_size = await asyncio.to_thread(_stat_size)
        except OSError as exc:
            logger.error(
                "Failed to stat finalized blob for upload %s (storage_key=%s): %s",
                upload_id, storage_key, exc,
            )
            raise HTTPException(status_code=500, detail="Upload finalization failed: stat error")

        if actual_size != new_offset:
            # Blob is corrupt — delete it so downstream reads don't serve garbage.
            def _remove_corrupt():
                final_path.unlink(missing_ok=True)
            await asyncio.to_thread(_remove_corrupt)
            logger.error(
                "Blob size mismatch for file %s: expected %d bytes, got %d — blob deleted",
                row["file_id"], new_offset, actual_size,
            )
            raise HTTPException(status_code=500, detail="Upload finalization failed: size mismatch")

        # Phase 2 DB update: mark file complete, update quota, remove tus record.
        # Runs only after the blob is confirmed on disk.
        await db.execute("BEGIN")
        try:
            # Belt-and-suspenders: verify chunk count matches what we expect.
            # Under normal operation this is always true (SQLite atomicity); this
            # catches any future code path that could corrupt next_chunk.
            count_cursor = await db.execute(
                "SELECT COUNT(*) FROM file_chunks WHERE file_id = ?",
                (row["file_id"],),
            )
            count_row = await count_cursor.fetchone()
            expected_chunks = chunk_index + 1  # chunk_index is 0-based
            if count_row[0] != expected_chunks:
                await db.rollback()
                logger.error(
                    "Chunk count mismatch for file %s: expected %d, got %d",
                    row["file_id"], expected_chunks, count_row[0],
                )
                raise HTTPException(
                    status_code=500,
                    detail="Upload finalization failed: chunk count mismatch",
                )

            await db.execute(
                """
                UPDATE files
                SET upload_complete = 1,
                    encrypted_size   = ?,
                    updated_at       = NOW()
                WHERE id = ?
                """,
                (new_offset, row["file_id"]),
            )
            await db.execute(
                "UPDATE users SET disk_used = disk_used + ? WHERE id = ?",
                (new_offset, user.id),
            )
            await db.execute("DELETE FROM tus_uploads WHERE id = ?", (upload_id,))
            await db.commit()
        except HTTPException:
            raise
        except Exception:
            await db.rollback()
            raise

        # Notify any SSE subscribers watching this folder
        _topic = file_row["folder_id"] or f"root:{file_row['owner_id']}"
        sse_broker.publish(_topic, {"type": "change"})

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

@router.delete("/{upload_id}")
async def abort_upload(
    upload_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Abort an upload: delete the tus record, incomplete file record, and staging blob."""
    try:
        upload_id = validate_uuid(upload_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Upload not found")

    cursor = await db.execute(
        "SELECT tus_uploads.file_id "
        "FROM tus_uploads "
        "WHERE tus_uploads.id = ? AND tus_uploads.user_id = ?",
        (upload_id, user.id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    file_id = row["file_id"]

    await db.execute("BEGIN")
    try:
        # Deleting the file cascades to file_chunks via FK; tus_uploads also FKs to files.
        await db.execute("DELETE FROM tus_uploads WHERE id = ?", (upload_id,))
        await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    upload_blob = settings.UPLOADS_DIR / upload_id

    def _cleanup():
        try:
            upload_blob.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Failed to delete upload blob %s: %s", upload_id, exc)

    await asyncio.to_thread(_cleanup)
    _evict_offsets.pop(upload_id, None)

    return Response(status_code=204, headers=_tus_headers())


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
            await db.execute("DELETE FROM tus_uploads WHERE id = ?", (upload_id,))
            await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
            await db.commit()
        except Exception:
            await db.rollback()
            logger.exception("Failed to clean up expired upload %s", upload_id)
            continue

        blob = settings.UPLOADS_DIR / upload_id
        try:
            blob.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not delete staging blob for upload %s: %s", upload_id, exc)
        _evict_offsets.pop(upload_id, None)

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
