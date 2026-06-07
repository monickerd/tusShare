"""Batch upload endpoint.

Accepts a single multipart/form-data POST containing:
  - one 'metadata' JSON part (array of per-file metadata objects, first)
  - one 'file_N' binary part per file, in index order

All files must be single-chunk (already fully encrypted by the client).
Returns a per-file results array so partial failures are isolated.
"""

import asyncio
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, Request
from multipart.multipart import MultipartParser

import app.storage.manager as storage
from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import Database, db_session, get_db
from app.middleware.rate_limit import check_upload_rate_limit
from app.routes._access import check_data_permission, copy_folder_permissions
from app.routes.uploads import _record_upload_folder_activity
from app.services.av_scanner import enqueue_scan
from app.schemas.security_event import SecurityEvent
from app.services import event_bus, sse_broker
from app.util.db import get_admin_setting
from app.validation.sanitizers import sanitize_filename, validate_base64, validate_uuid
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

# Server-side limits (client enforces a lower byte budget; these are backstops).
_MAX_FILES_PER_BATCH = 50
_MAX_METADATA_BYTES = 64 * 1024        # 64 KB
_MAX_FILE_ENCRYPTED_BYTES = 21 * 1024 * 1024   # mirrors _MAX_CHUNK_BYTES in uploads.py
_BOUNDARY_RE = re.compile(r'boundary=([^\s;]+)', re.IGNORECASE)
_HASH_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
_PART_NAME_FILE_RE = re.compile(rb'^file_(\d+)$')
_CONTENT_DISP_NAME_RE = re.compile(rb';\s*name="([^"]+)"')

_bg_tasks: set = set()


class _BatchFileError(Exception):
    """Raised when a specific file causes a batch transaction failure."""
    def __init__(self, index: int, detail: str) -> None:
        self.index = index
        self.detail = detail
        super().__init__(detail)


# ---------------------------------------------------------------------------
# Per-file metadata (parsed + validated)
# ---------------------------------------------------------------------------

@dataclass
class _FileMeta:
    index: int
    filename: str
    sanitized_name: str
    filetype: str
    folder_id: str | None
    original_size: int
    encrypted_size: int
    encrypted_file_key: str
    key_iv: str
    chunk_iv: str
    chunk_hash: str                   # "sha256:<64 hex chars>"
    last_modified_ms: int | None
    escrow_ephemeral_pk: str | None
    escrow_encrypted_key: str | None
    escrow_key_iv: str | None
    key_version: str                   # 'v1-master' or 'v2-folder'
    chunk_size: int                   # admin chunk size stored in files table


# ---------------------------------------------------------------------------
# Streaming multipart parse state
# ---------------------------------------------------------------------------

class _MultipartState:
    """Accumulates per-callback bytes and signals completed parts to the main loop."""

    def __init__(self, max_file_bytes: int) -> None:
        self._max_file_bytes = max_file_bytes
        # Header accumulation (reset per part)
        self._hdr_field = bytearray()
        self._hdr_value = bytearray()
        self._part_name = b""
        # Current part data
        self._is_metadata = False
        self._is_file = False
        self._meta_buf = bytearray()
        self._file_buf = bytearray()
        self._file_index = -1
        # Protocol tracking
        self._metadata_part_count = 0
        self._next_file_index = 0
        # Signals consumed by the main loop
        self.error: str = ""
        self.metadata_ready: bytes | None = None
        self.file_ready_queue: list[tuple[int, bytes]] = []
        self.stream_ended: bool = False


def _make_callbacks(state: _MultipartState) -> dict:
    """Return the python-multipart callback dict wired to the given state."""

    def on_part_begin() -> None:
        state._hdr_field = bytearray()
        state._hdr_value = bytearray()
        state._part_name = b""
        state._meta_buf = bytearray()
        state._file_buf = bytearray()
        state._is_metadata = False
        state._is_file = False
        state._file_index = -1

    def on_header_field(data: bytes, start: int, end: int) -> None:
        state._hdr_field.extend(data[start:end])

    def on_header_value(data: bytes, start: int, end: int) -> None:
        state._hdr_value.extend(data[start:end])

    def on_header_end() -> None:
        if state._hdr_field.lower() == b"content-disposition":
            m = _CONTENT_DISP_NAME_RE.search(state._hdr_value)
            if m:
                state._part_name = m.group(1)
        state._hdr_field = bytearray()
        state._hdr_value = bytearray()

    def on_headers_finished() -> None:
        if state.error:
            return
        name = state._part_name
        if name == b"metadata":
            _handle_metadata_header(state)
        elif _PART_NAME_FILE_RE.fullmatch(name):
            _handle_file_header(state, name)
        else:
            state.error = f"Unexpected part name: {name!r}"

    def on_part_data(data: bytes, start: int, end: int) -> None:
        if state.error:
            return
        chunk = data[start:end]
        if state._is_metadata:
            _append_metadata_chunk(state, chunk)
        elif state._is_file:
            _append_file_chunk(state, chunk)

    def on_part_end() -> None:
        if state.error:
            return
        if state._is_metadata:
            state.metadata_ready = bytes(state._meta_buf)
        elif state._is_file:
            state.file_ready_queue.append((state._file_index, bytes(state._file_buf)))
            state._next_file_index += 1
        state._is_metadata = False
        state._is_file = False

    def on_end() -> None:
        state.stream_ended = True

    return {
        "on_part_begin": on_part_begin,
        "on_header_field": on_header_field,
        "on_header_value": on_header_value,
        "on_header_end": on_header_end,
        "on_headers_finished": on_headers_finished,
        "on_part_data": on_part_data,
        "on_part_end": on_part_end,
        "on_end": on_end,
    }


def _handle_metadata_header(state: _MultipartState) -> None:
    if state._metadata_part_count > 0:
        state.error = "Duplicate metadata part"
        return
    state._is_metadata = True
    state._metadata_part_count += 1


def _handle_file_header(state: _MultipartState, name: bytes) -> None:
    if state._metadata_part_count == 0:
        state.error = "File part arrived before metadata"
        return
    idx = int(name[5:])
    if idx != state._next_file_index:
        state.error = f"Out-of-order file part: expected file_{state._next_file_index}, got file_{idx}"
        return
    state._is_file = True
    state._file_index = idx


def _append_metadata_chunk(state: _MultipartState, chunk: bytes) -> None:
    if len(state._meta_buf) + len(chunk) > _MAX_METADATA_BYTES:
        state.error = "Metadata part exceeds size limit"
        return
    state._meta_buf.extend(chunk)


def _append_file_chunk(state: _MultipartState, chunk: bytes) -> None:
    if len(state._file_buf) + len(chunk) > state._max_file_bytes:
        state.error = f"File part {state._file_index} exceeds size limit"
        return
    state._file_buf.extend(chunk)


# ---------------------------------------------------------------------------
# Metadata JSON validation
# ---------------------------------------------------------------------------

def _extract_boundary(content_type: str) -> bytes | None:
    m = _BOUNDARY_RE.search(content_type)
    return m.group(1).strip().encode() if m else None


def _parse_batch_json(raw: bytes) -> list[dict]:
    """Decode and basic-type-check the metadata JSON array."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Metadata JSON invalid: {exc}")
    if not isinstance(parsed, list):
        raise HTTPException(status_code=400, detail="Metadata must be a JSON array")
    if len(parsed) == 0:
        raise HTTPException(status_code=400, detail="Metadata array is empty")
    if len(parsed) > _MAX_FILES_PER_BATCH:
        raise HTTPException(status_code=400, detail=f"Batch exceeds {_MAX_FILES_PER_BATCH} files")
    return parsed


def _parse_file_sizes(entry: dict, index: int) -> tuple[int, int]:
    """Parse and validate original_size and encrypted_size from one entry."""
    try:
        original_size = int(entry["original_size"])
        encrypted_size = int(entry["encrypted_size"])
    except (KeyError, ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"Entry {index}: original_size and encrypted_size must be integers")
    if original_size <= 0:
        raise HTTPException(status_code=400, detail=f"Entry {index}: original_size must be positive")
    if encrypted_size != original_size + 16:
        raise HTTPException(status_code=400, detail=f"Entry {index}: encrypted_size must be original_size + 16")
    if encrypted_size > _MAX_FILE_ENCRYPTED_BYTES:
        raise HTTPException(status_code=413, detail=f"Entry {index}: file too large for batch upload")
    return original_size, encrypted_size


def _parse_file_string_fields(entry: dict, index: int) -> tuple[str, str, str, str, str]:
    """Validate and return (encrypted_file_key, key_iv, chunk_iv, chunk_hash, filetype)."""
    for field_name in ("encrypted_file_key", "key_iv", "chunk_iv", "chunk_hash"):
        if field_name not in entry:
            raise HTTPException(status_code=400, detail=f"Entry {index}: missing field '{field_name}'")
    try:
        enc_key = validate_base64(entry["encrypted_file_key"])
        key_iv = validate_base64(entry["key_iv"])
        chunk_iv = validate_base64(entry["chunk_iv"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Entry {index}: {exc}")
    chunk_hash = entry["chunk_hash"]
    if not _HASH_RE.match(chunk_hash):
        raise HTTPException(status_code=400, detail=f"Entry {index}: chunk_hash must be sha256:<64 hex chars>")
    filetype = (entry.get("filetype") or "application/octet-stream")[:256]
    return enc_key, key_iv, chunk_iv, chunk_hash, filetype


def _parse_last_modified(entry: dict, index: int) -> int | None:
    raw = entry.get("last_modified_ms")
    if not raw:
        return None
    try:
        val = int(raw)
        if val <= 0:
            raise ValueError("non-positive")
        return val
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"Entry {index}: last_modified_ms must be a positive integer")


def _parse_escrow_fields(entry: dict, index: int) -> tuple[str | None, str | None, str | None]:
    pk = entry.get("escrow_ephemeral_pk") or None
    enc = entry.get("escrow_encrypted_key") or None
    iv = entry.get("escrow_key_iv") or None
    if pk and enc and iv:
        try:
            validate_base64(pk)
            validate_base64(enc)
            validate_base64(iv)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Entry {index}: invalid escrow field encoding")
    return pk, enc, iv


async def _validate_folder_access(entry: dict, index: int, user_id: str, db) -> str | None:
    """Return validated folder_id or None; raises 400/403/404 on failure."""
    raw = entry.get("folder_id") or None
    if not raw:
        return None
    try:
        folder_id = validate_uuid(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Entry {index}: invalid folder_id")
    cursor = await db.execute("SELECT id, owner_id FROM folders WHERE id = ?", (folder_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Entry {index}: folder not found")
    if row["owner_id"] == user_id:
        return folder_id
    allowed = await check_data_permission(db, "folder", folder_id, user_id, "write")
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Entry {index}: folder access denied")  # NOSONAR
    return folder_id


async def _build_file_meta(entry: dict, index: int, user_id: str, db, admin_chunk_size: int) -> _FileMeta:
    """Parse and validate one metadata entry. Returns _FileMeta on success."""
    if "filename" not in entry:
        raise HTTPException(status_code=400, detail=f"Entry {index}: missing 'filename'")
    try:
        sanitized = sanitize_filename(entry["filename"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Entry {index}: {exc}")

    original_size, encrypted_size = _parse_file_sizes(entry, index)
    enc_key, key_iv, chunk_iv, chunk_hash, filetype = _parse_file_string_fields(entry, index)
    last_modified_ms = _parse_last_modified(entry, index)
    escrow_pk, escrow_enc, escrow_iv = _parse_escrow_fields(entry, index)
    folder_id = await _validate_folder_access(entry, index, user_id, db)

    key_version_raw = entry.get("key_version") or "v1-master"
    if key_version_raw not in ("v1-master", "v2-folder"):
        raise HTTPException(status_code=400, detail=f"Entry {index}: invalid key_version")

    return _FileMeta(
        index=index,
        filename=entry["filename"],
        sanitized_name=sanitized.name,
        filetype=filetype,
        folder_id=folder_id,
        original_size=original_size,
        encrypted_size=encrypted_size,
        encrypted_file_key=enc_key,
        key_iv=key_iv,
        chunk_iv=chunk_iv,
        chunk_hash=chunk_hash,
        last_modified_ms=last_modified_ms,
        escrow_ephemeral_pk=escrow_pk,
        escrow_encrypted_key=escrow_enc,
        escrow_key_iv=escrow_iv,
        key_version=key_version_raw,
        chunk_size=admin_chunk_size,
    )


async def _validate_batch_quota(file_metas: list[_FileMeta], user_id: str, db) -> None:
    """Pre-flight quota check for the entire batch. Per-file increments happen in _store_file."""
    total_encrypted = sum(m.encrypted_size for m in file_metas)
    cursor = await db.execute(
        "SELECT disk_used, disk_quota, max_file_size FROM users WHERE id = ?", (user_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    gmax_val = await get_admin_setting(db, "global_max_file_size")
    global_max = int(gmax_val) if gmax_val is not None else settings.GLOBAL_MAX_FILE_SIZE

    for meta in file_metas:
        if global_max > 0 and meta.encrypted_size > global_max:
            raise HTTPException(status_code=413, detail=f"Entry {meta.index}: exceeds server maximum file size")
        if row["max_file_size"] is not None and meta.encrypted_size > row["max_file_size"]:
            raise HTTPException(status_code=413, detail=f"Entry {meta.index}: exceeds your maximum file size")

    if row["disk_quota"] is not None and row["disk_used"] + total_encrypted > row["disk_quota"]:
        raise HTTPException(status_code=413, detail="Batch would exceed storage quota")


async def _parse_and_validate_metadata(raw: bytes, user_id: str, db, admin_chunk_size: int) -> list[_FileMeta]:
    entries = _parse_batch_json(raw)
    file_metas = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise HTTPException(status_code=400, detail=f"Entry {i}: must be a JSON object")
        meta = await _build_file_meta(entry, i, user_id, db, admin_chunk_size)
        file_metas.append(meta)
    await _validate_batch_quota(file_metas, user_id, db)
    return file_metas


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------

def _verify_file_hash_and_size(index: int, data: bytes, meta: _FileMeta) -> str | None:
    """Verify SHA-256 hash and byte count. Returns an error string or None."""
    if len(data) != meta.encrypted_size:
        return f"size mismatch: expected {meta.encrypted_size} bytes, got {len(data)}"
    expected_hex = meta.chunk_hash[7:]   # strip "sha256:"
    actual_hex = hashlib.sha256(data).hexdigest()
    if actual_hex != expected_hex:
        return "integrity check failed: hash mismatch"
    return None


async def _insert_file_in_tx(
    db,
    user_id: str,
    meta: _FileMeta,
    data: bytes,
    file_id: str,
    storage_key: str,
    chunk_id: str,
) -> None:
    """Insert all DB records and blob for one file. Caller owns the open transaction."""
    await db.execute(
        """
        INSERT INTO files (
            id, original_name, sanitized_name, storage_key, folder_id, owner_id,
            mime_type, size_bytes, encrypted_size, chunk_size, total_chunks,
            encrypted_file_key, key_iv, key_version, upload_complete,
            escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv,
            last_modified_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 1, ?, ?, ?, ?)
        """,
        (
            file_id, meta.filename, meta.sanitized_name, storage_key,
            meta.folder_id, user_id, meta.filetype,
            meta.original_size, meta.encrypted_size, meta.chunk_size,
            meta.encrypted_file_key, meta.key_iv, meta.key_version,
            meta.escrow_ephemeral_pk, meta.escrow_encrypted_key, meta.escrow_key_iv,
            meta.last_modified_ms,
        ),
    )
    if meta.folder_id:
        await copy_folder_permissions(db, meta.folder_id, "file", file_id)
    await db.execute(
        """
        INSERT INTO file_chunks (id, file_id, chunk_index, iv, size_bytes, "offset")
        VALUES (?, ?, 0, ?, ?, 0)
        """,
        (chunk_id, file_id, meta.chunk_iv, meta.encrypted_size),
    )
    await db.execute(
        "UPDATE users SET disk_used = disk_used + ? WHERE id = ?",
        (meta.encrypted_size, user_id),
    )
    if meta.folder_id:
        await db.execute(
            """
            INSERT INTO pending_share_keying (id, share_id, file_id, folder_id)
            SELECT gen_random_uuid()::text, s.id, ?, ?
            FROM shares s
            WHERE s.target_folder_id = ?
              AND s.key_type = 'hkdf-v1'
              AND s.is_active = 1
              AND (s.expires_at IS NULL OR s.expires_at > NOW())
            ON CONFLICT (share_id, file_id) DO NOTHING
            """,
            (file_id, meta.folder_id, meta.folder_id),
        )
    # write_blob writes the physical blob + inserts file_storage_locations.
    # Runs last: if any earlier step fails the transaction rolls back cleanly.
    await storage.get_manager().write_blob(db, file_id, storage_key, data)
    await enqueue_scan(db, file_id)


async def _write_batch(
    user_id: str,
    items: list[tuple[int, bytes, "_FileMeta"]],
) -> tuple[dict[int, tuple[str, int, str | None]], int | None, str]:
    """Store all files in one transaction. Returns (file_id_map, problem_index, problem_detail).

    file_id_map maps each item's index → (file_id, encrypted_size, folder_id).
    On success problem_index is None.  On a per-file write failure the transaction
    is fully rolled back and problem_index identifies the offending file so the
    caller can report it separately and queue siblings for individual retry.
    """
    file_id_map: dict[int, tuple[str, int, str | None]] = {}
    problem_index: int | None = None
    problem_detail: str = ""

    async with db_session() as db:
        await db.execute("BEGIN")
        try:
            for index, data, meta in items:
                file_id = str(uuid.uuid4())
                storage_key = str(uuid.uuid4())
                chunk_id = str(uuid.uuid4())
                try:
                    await _insert_file_in_tx(db, user_id, meta, data, file_id, storage_key, chunk_id)
                    file_id_map[index] = (file_id, meta.encrypted_size, meta.folder_id)
                except Exception as exc:
                    logger.error("Batch upload: file write failed (index=%s): %s", index, exc)
                    problem_index = index
                    problem_detail = "storage error"
                    break
            if problem_index is None:
                await db.commit()
            else:
                await db.rollback()
        except Exception:
            await db.rollback()
            raise

    return file_id_map, problem_index, problem_detail


def _emit_file_events(file_id: str, user_id: str, encrypted_size: int, folder_id: str | None) -> None:
    event_bus.emit(
        SecurityEvent(
            event_type="file.upload.completed",
            severity="info",
            outcome="success",
            user_id=user_id,
            detail={"file_id": file_id, "size": encrypted_size, "via": "batch"},
        )
    )
    topic = folder_id or f"root:{user_id}"
    sse_broker.publish(topic, {"type": "file.added", "file_id": file_id, "folder_id": folder_id})


def _fire_background_tasks(file_id: str, user_id: str, folder_id: str | None) -> None:
    if folder_id:
        t = asyncio.create_task(_record_upload_folder_activity(user_id, folder_id))
        _bg_tasks.add(t)
        t.add_done_callback(_bg_tasks.discard)


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.post(
    "/batch",
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        413: {"description": "Payload Too Large"},
    },
)
async def batch_upload(
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db: Database = Depends(get_db),
    _rl: None = Depends(check_upload_rate_limit),
):
    """
    Accept multiple single-chunk encrypted files in one multipart POST.

    Expects:
      1. A 'metadata' part containing a JSON array of file metadata objects.
      2. One 'file_N' binary part per file, in index order (0, 1, 2, ...).

    Returns a 'results' array with per-file status so callers can handle
    partial failures without resending the whole batch.
    """
    boundary = _extract_boundary(request.headers.get("content-type", ""))
    if not boundary:
        raise HTTPException(status_code=400, detail="Content-Type must be multipart/form-data with a boundary")

    cs_val = await get_admin_setting(db, "default_chunk_size")
    admin_chunk_size = int(cs_val) if cs_val is not None else settings.DEFAULT_CHUNK_SIZE

    state = _MultipartState(max_file_bytes=_MAX_FILE_ENCRYPTED_BYTES)
    parser = MultipartParser(boundary, _make_callbacks(state))

    file_metas: list[_FileMeta] | None = None
    verify_tasks: list[asyncio.Task] = []
    file_data: dict[int, bytes] = {}

    # Stream the request body. As each file part completes, launch its hash
    # verification concurrently in a thread pool. File bytes are buffered here
    # and committed to the DB in a single transaction after all parts arrive.
    async for raw_chunk in request.stream():
        parser.write(raw_chunk)
        if state.error:
            break

        if state.metadata_ready is not None and file_metas is None:
            file_metas = await _parse_and_validate_metadata(
                state.metadata_ready, user.id, db, admin_chunk_size
            )

        while state.file_ready_queue and not state.error:
            index, data = state.file_ready_queue.pop(0)
            if file_metas is None or index >= len(file_metas):
                state.error = f"file part {index} received before metadata was validated"
                break
            file_data[index] = data
            verify_tasks.append(
                asyncio.create_task(
                    asyncio.to_thread(_verify_file_hash_and_size, index, data, file_metas[index])
                )
            )

        if state.error:
            break

    async def _cancel_and_wait() -> None:
        for t in verify_tasks:
            t.cancel()
        await asyncio.gather(*verify_tasks, return_exceptions=True)

    if state.error:
        await _cancel_and_wait()
        raise HTTPException(status_code=400, detail=f"Malformed batch: {state.error}")

    try:
        parser.finalize()
    except Exception:
        await _cancel_and_wait()
        raise HTTPException(status_code=400, detail="Malformed batch: incomplete multipart body")

    if not state.stream_ended:
        await _cancel_and_wait()
        raise HTTPException(status_code=400, detail="Malformed batch: terminal boundary not reached")

    if file_metas is None:
        raise HTTPException(status_code=400, detail="No metadata part received")

    if len(verify_tasks) != len(file_metas):
        await _cancel_and_wait()
        raise HTTPException(
            status_code=400,
            detail=f"Expected {len(file_metas)} file parts, received {len(verify_tasks)}",
        )

    # Gather hash results (ran concurrently with the tail of the request stream).
    verify_results = await asyncio.gather(*verify_tasks, return_exceptions=True)
    hash_errors: dict[int, str] = {}
    verified_items: list[tuple[int, bytes, _FileMeta]] = []
    for task_idx, vr in enumerate(verify_results):
        if isinstance(vr, BaseException):
            hash_errors[task_idx] = f"verification error: {vr}"
        elif vr is not None:                  # error string from _verify_file_hash_and_size
            hash_errors[task_idx] = vr
        else:
            verified_items.append((task_idx, file_data[task_idx], file_metas[task_idx]))

    # Write all hash-passed files in a single transaction (one WAL flush).
    # If one file's write fails, the entire transaction rolls back and
    # problem_index identifies it so siblings can be queued for individual retry.
    file_id_map: dict[int, tuple[str, int, str | None]] = {}
    problem_index: int | None = None
    problem_detail: str = ""
    if verified_items:
        try:
            file_id_map, problem_index, problem_detail = await _write_batch(user.id, verified_items)
        except Exception as exc:
            logger.error("Batch upload: write_batch raised unexpectedly: %s", exc)  # NOSONAR
            for idx, _, _ in verified_items:
                hash_errors[idx] = "internal storage error"

    # Build per-file result list.
    # "rolled_back" tells the client the file itself had no issue but was caught
    # in a sibling's rollback — it should retry individually rather than be
    # reported as a permanent failure.
    results = []
    for meta in file_metas:
        idx = meta.index
        if idx in hash_errors:
            results.append({"index": idx, "file_id": None, "status": "error", "detail": hash_errors[idx]})
        elif problem_index is None:
            file_id, enc_size, folder_id = file_id_map[idx]
            _emit_file_events(file_id, user.id, enc_size, folder_id)
            _fire_background_tasks(file_id, user.id, folder_id)
            results.append({"index": idx, "file_id": file_id, "status": "ok"})
        elif idx == problem_index:
            results.append({"index": idx, "file_id": None, "status": "error", "detail": problem_detail})
        else:
            results.append({"index": idx, "file_id": None, "status": "rolled_back",
                            "detail": "rolled back due to sibling failure"})

    return {"results": sorted(results, key=lambda r: r["index"])}
