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
from app.database import db_session, get_db
from app.middleware.bandwidth import check_bandwidth
from app.middleware.rate_limit import _get_client_ip
from app.models.file import File, FileChunk
from app.routes._access import copy_folder_permissions, get_folder_team_id, has_folder_permission, is_in_shared_tree, is_team_folder_member
from app.services import event_bus, sse_broker
import app.storage.manager as storage
from app.validation.sanitizers import SanitizedFilename, sanitize_filename, validate_uuid

logger = logging.getLogger(__name__)


async def check_file_access(db, file_row, user: AuthenticatedUser) -> None:
    """Verify user has access to a file. Raises 403 if denied.

    Shared helper used by get_file_metadata, get_file_chunks, etc.
    Full permission-tree check will replace this in Phase 6.
    """
    from app.models.role import FLAG_ACCESS_ALL_FILES
    if file_row["owner_id"] == user.id or user.has_flag(FLAG_ACCESS_ALL_FILES):
        return
    if file_row["folder_id"] and await is_in_shared_tree(db, file_row["folder_id"]):
        return
    if file_row["folder_id"] and await is_team_folder_member(db, file_row["folder_id"], user.id):
        return
    if file_row["folder_id"] and await has_folder_permission(db, file_row["folder_id"], user.id):
        return
    raise HTTPException(status_code=403, detail="Access denied")

router = APIRouter()


async def _av_gate_active(db) -> bool:
    """Return True when av_require_clean is enabled AND av_scan_endpoint is configured."""
    cursor = await db.execute(
        "SELECT key, value FROM admin_settings "
        "WHERE key IN ('av_require_clean', 'av_scan_endpoint')"
    )
    rows = {r["key"]: r["value"] for r in await cursor.fetchall()}
    return (
        rows.get("av_require_clean", "false").lower() == "true"
        and bool(rows.get("av_scan_endpoint", "").strip())
    )


async def _check_av_gate(db, file_row) -> None:
    """Raise 451 if av_require_clean is active and file is not clean."""
    if file_row.get("av_scan_status") == "clean":
        return
    if not await _av_gate_active(db):
        return
    status = file_row.get("av_scan_status") or "null"
    raise HTTPException(
        status_code=451,
        detail={
            "detail":    "File pending antivirus scan",
            "av_status": status,
        },
    )


class UpdateFileRequest(BaseModel):
    original_name: str | None = None
    folder_id: str | None = None
    move_to_root: bool = False

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


class _BatchMoveFileKey(BaseModel):
    """PRE-encrypted file key for a team destination. All fields are base64."""
    pre_c1: str
    encrypted_file_key: str
    key_iv: str

    @field_validator("pre_c1", "encrypted_file_key", "key_iv")
    @classmethod
    def validate_b64(cls, v: str) -> str:
        from app.validation.sanitizers import validate_base64
        return validate_base64(v)


class _BatchMoveItem(BaseModel):
    id: str
    # Required when the destination is a team folder; absent for personal destinations
    team_key: _BatchMoveFileKey | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        return validate_uuid(v)


_BATCH_MOVE_MAX = 50


class BatchMoveRequest(BaseModel):
    files: list[_BatchMoveItem]
    destination_folder_id: str | None = None

    @field_validator("files")
    @classmethod
    def validate_files(cls, v: list) -> list:
        if not v:
            raise ValueError("files list must not be empty")
        if len(v) > _BATCH_MOVE_MAX:
            raise ValueError(f"Cannot move more than {_BATCH_MOVE_MAX} files per request")
        return v

    @field_validator("destination_folder_id")
    @classmethod
    def validate_dest(cls, v: str | None) -> str | None:
        if v is not None:
            return validate_uuid(v)
        return v


@router.post("/batch-move")
async def batch_move_files(
    body: BatchMoveRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Move up to 50 files to a destination folder in a single request.

    When the destination is a team folder, each item must include a ``team_key``
    containing the PRE-encrypted file key for that team.  The endpoint atomically
    updates ``folder_id``, inserts the new ``file_team_keys`` row (if destination
    is a team folder), and deletes the old ``file_team_keys`` row (if the source
    was a different team folder).  Inherited ``permissions`` rows are also
    refreshed from the destination folder.

    Returns a summary of succeeded and failed file IDs.
    """
    dest_id = body.destination_folder_id

    # Resolve destination team (if any)
    dest_team_id: str | None = None
    if dest_id:
        cursor = await db.execute("SELECT owner_id FROM folders WHERE id = ?", (dest_id,))
        dest_folder = await cursor.fetchone()
        if dest_folder is None:
            raise HTTPException(status_code=404, detail="Destination folder not found")
        if dest_folder["owner_id"] != user.id and not user.is_admin:
            if not await is_team_folder_member(db, dest_id, user.id):
                raise HTTPException(status_code=403, detail="Access denied to destination folder")
        dest_team_id = await get_folder_team_id(db, dest_id)

    # Validate team_key presence: required for each file when dest is a team folder
    if dest_team_id:
        missing = [item.id for item in body.files if item.team_key is None]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"team_key required for all files when destination is a team folder; missing for: {missing[:5]}",
            )

    succeeded: list[str] = []
    failed: list[dict] = []

    gate_active = await _av_gate_active(db)

    for item in body.files:
        try:
            cursor = await db.execute(
                "SELECT id, folder_id, owner_id, av_scan_status FROM files WHERE id = ? AND deleted_at IS NULL", (item.id,)
            )
            file_row = await cursor.fetchone()
            if file_row is None:
                failed.append({"id": item.id, "reason": "not_found"})
                continue

            if gate_active and file_row.get("av_scan_status") != "clean":
                failed.append({"id": item.id, "reason": "av_not_clean"})
                continue

            src_folder_id = file_row["folder_id"]
            src_team_id = await get_folder_team_id(db, src_folder_id) if src_folder_id else None
            is_owner = file_row["owner_id"] == user.id

            # --- Move permission checks ---
            if not is_owner:
                # Non-owner: allowed only when moving others' files out of a team folder
                # and the user holds move_others_files_out_of_team for that team.
                if not src_team_id:
                    failed.append({"id": item.id, "reason": "permission_denied"})
                    continue
                from app.models.team_role import get_user_team_move_flags, TEAM_FLAG_MOVE_OTHERS_OUT
                move_flags = await get_user_team_move_flags(db, user.id, src_team_id)
                if not move_flags[TEAM_FLAG_MOVE_OTHERS_OUT]:
                    failed.append({"id": item.id, "reason": "permission_denied"})
                    continue
            elif src_team_id and src_team_id != dest_team_id:
                # Owner moving their file OUT of a team (to personal space or a different team)
                from app.models.team_role import get_user_team_move_flags, TEAM_FLAG_MOVE_OWN_OUT
                move_flags = await get_user_team_move_flags(db, user.id, src_team_id)
                if not move_flags[TEAM_FLAG_MOVE_OWN_OUT]:
                    failed.append({"id": item.id, "reason": "permission_denied"})
                    continue

            await db.execute("BEGIN")
            try:
                # Move the file
                await db.execute(
                    "UPDATE files SET folder_id = ?, updated_at = NOW() WHERE id = ?",
                    (dest_id, item.id),
                )

                # Replace inherited permissions
                await db.execute(
                    "DELETE FROM permissions WHERE resource_type = 'file' AND resource_id = ? AND recursive = 1",
                    (item.id,),
                )
                if dest_id:
                    await copy_folder_permissions(db, dest_id, "file", item.id)

                # Remove old team key if source was a team folder
                if src_team_id and src_team_id != dest_team_id:
                    await db.execute(
                        "DELETE FROM file_team_keys WHERE team_id = ? AND file_id = ?",
                        (src_team_id, item.id),
                    )

                # Insert new team key if destination is a team folder
                if dest_team_id and item.team_key:
                    tk = item.team_key
                    new_ftk_id = str(uuid.uuid4())
                    await db.execute(
                        "INSERT INTO file_team_keys "
                        "(id, team_id, file_id, pre_c1, encrypted_file_key, key_iv) "
                        "VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(team_id, file_id) DO UPDATE SET "
                        "    pre_c1 = excluded.pre_c1, "
                        "    encrypted_file_key = excluded.encrypted_file_key, "
                        "    key_iv = excluded.key_iv",
                        (new_ftk_id, dest_team_id, item.id,
                         tk.pre_c1, tk.encrypted_file_key, tk.key_iv),
                    )

                await db.commit()
                succeeded.append(item.id)

                # SSE notifications
                if src_folder_id:
                    sse_broker.publish(src_folder_id, {"type": "change"})
                else:
                    sse_broker.publish(f"root:{user.id}", {"type": "change"})
                if dest_id and dest_id != src_folder_id:
                    sse_broker.publish(dest_id, {"type": "change"})

            except Exception:
                await db.rollback()
                failed.append({"id": item.id, "reason": "error"})

        except Exception:
            failed.append({"id": item.id, "reason": "error"})

    return {"succeeded": succeeded, "failed": failed}


# ---------------------------------------------------------------------------
# POST /files/batch-copy
# ---------------------------------------------------------------------------

class _BatchCopyItem(BaseModel):
    file_id: str
    # Cross-team (path 3): rk-transformed C1; personal→team (path 4): full PRE envelope C1
    pre_c1: str | None = None
    # New personal DEK wrapper (path 4 or 5); absent for server-handled paths 1, 2
    encrypted_file_key: str | None = None
    key_iv: str | None = None

    @field_validator("file_id")
    @classmethod
    def validate_file_id(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("pre_c1", "encrypted_file_key", "key_iv")
    @classmethod
    def validate_b64(cls, v: str | None) -> str | None:
        if v is not None:
            from app.validation.sanitizers import validate_base64
            return validate_base64(v)
        return v


_BATCH_COPY_MAX = 50


class BatchCopyRequest(BaseModel):
    destination_folder_id: str
    files: list[_BatchCopyItem]

    @field_validator("destination_folder_id")
    @classmethod
    def validate_dest(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("files")
    @classmethod
    def validate_files(cls, v: list) -> list:
        if not v:
            raise ValueError("files list must not be empty")
        if len(v) > _BATCH_COPY_MAX:
            raise ValueError(f"Cannot copy more than {_BATCH_COPY_MAX} files per request")
        return v


@router.post("/batch-copy")
async def batch_copy_files(
    body: BatchCopyRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Copy up to 50 files to a destination folder, sharing the encrypted blob.

    Five crypto paths are handled (client provides the appropriate key material):
      1. Personal → Personal: server copies key fields verbatim.
      2. Same Team → Same Team: server copies file_team_keys verbatim.
      3. Cross-Team (A→B): client sends rk-transformed C1; C2/IV copied from source.
      4. Personal → Team: client sends full PRE envelope (pre_c1 + encrypted DEK + iv).
      5. Team → Personal: client sends personal DEK wrapper (encrypted_file_key + iv).

    Blob ref-counting is tracked via multiple files rows sharing storage_key;
    the hard-delete path only removes the blob when the last reference is deleted.
    """
    from app.models.role import FLAG_COPY_FILES
    from app.schemas.security_event import EventActor, EventTarget, SecurityEvent

    if not user.has_flag(FLAG_COPY_FILES):
        raise HTTPException(status_code=403, detail="copy.permission_denied")

    dest_id = body.destination_folder_id
    ip = _get_client_ip(request)

    # Validate destination folder
    cursor = await db.execute(
        "SELECT owner_id FROM folders WHERE id = ? AND deleted_at IS NULL", (dest_id,)
    )
    dest_folder = await cursor.fetchone()
    if dest_folder is None:
        raise HTTPException(status_code=404, detail="Destination folder not found")
    if dest_folder["owner_id"] != user.id and not user.is_admin:
        if not await is_team_folder_member(db, dest_id, user.id):
            raise HTTPException(status_code=403, detail="Access denied to destination folder")

    dest_team_id = await get_folder_team_id(db, dest_id)

    # Fetch copy_boundary admin setting
    cursor = await db.execute("SELECT value FROM admin_settings WHERE key = 'copy_boundary'")
    boundary_row = await cursor.fetchone()
    copy_boundary = (boundary_row["value"] if boundary_row else "any").lower()

    if copy_boundary == "disabled":
        event_bus.emit(SecurityEvent(
            event_type="file.copy.blocked",
            severity="warning",
            outcome="failure",
            actor=EventActor(user_id=user.id, username=user.username, ip=ip),
            detail={
                "block_reason": "policy_disabled",
                "copy_boundary_setting": "disabled",
                "destination_folder_id": dest_id,
            },
        ))
        raise HTTPException(status_code=403, detail="copy.disabled")

    copied: list[dict] = []
    failed: list[dict] = []

    for item in body.files:
        try:
            # Fetch source file
            cursor = await db.execute(
                "SELECT * FROM files WHERE id = ? AND deleted_at IS NULL AND upload_complete = 1",
                (item.file_id,),
            )
            src_row = await cursor.fetchone()
            if src_row is None:
                failed.append({"source_id": item.file_id, "reason": "not_found"})
                continue

            # Source read access
            try:
                await check_file_access(db, src_row, user)
            except HTTPException:
                failed.append({"source_id": item.file_id, "reason": "permission_denied"})
                continue

            src_folder_id = src_row["folder_id"]
            src_team_id = await get_folder_team_id(db, src_folder_id) if src_folder_id else None

            # copy_boundary same_team enforcement
            if copy_boundary == "same_team" and src_team_id != dest_team_id:
                event_bus.emit(SecurityEvent(
                    event_type="file.copy.blocked",
                    severity="warning",
                    outcome="failure",
                    actor=EventActor(user_id=user.id, username=user.username, ip=ip),
                    target=EventTarget(type="file", id=item.file_id, name=src_row["original_name"]),
                    detail={
                        "block_reason": "boundary_violation",
                        "copy_boundary_setting": "same_team",
                        "source_team_id": src_team_id,
                        "destination_team_id": dest_team_id,
                    },
                ))
                failed.append({"source_id": item.file_id, "reason": "boundary_violation"})
                continue

            # Determine crypto fields per path
            new_file_id = str(uuid.uuid4())
            new_enc_key = src_row["encrypted_file_key"]
            new_key_iv  = src_row["key_iv"]
            ftk_pre_c1  = None
            ftk_enc_key = None
            ftk_key_iv  = None
            needs_ftk   = False

            if src_team_id == dest_team_id:
                if src_team_id is not None:
                    # Path 2: Same Team → Same Team — copy file_team_keys verbatim
                    cursor = await db.execute(
                        "SELECT pre_c1, encrypted_file_key, key_iv FROM file_team_keys "
                        "WHERE team_id = ? AND file_id = ?",
                        (src_team_id, item.file_id),
                    )
                    src_ftk = await cursor.fetchone()
                    if src_ftk:
                        ftk_pre_c1  = src_ftk["pre_c1"]
                        ftk_enc_key = src_ftk["encrypted_file_key"]
                        ftk_key_iv  = src_ftk["key_iv"]
                        needs_ftk   = True
                # Path 1: Personal → Personal — new_enc_key/new_key_iv already set from src

            elif src_team_id is None:
                # Path 4: Personal → Team — client provides full PRE envelope
                if not item.pre_c1 or not item.encrypted_file_key or not item.key_iv:
                    failed.append({"source_id": item.file_id, "reason": "missing_crypto_fields"})
                    continue
                ftk_pre_c1  = item.pre_c1
                ftk_enc_key = item.encrypted_file_key
                ftk_key_iv  = item.key_iv
                needs_ftk   = True

            elif dest_team_id is None:
                # Path 5: Team → Personal — client provides personal DEK wrapper
                if not item.encrypted_file_key or not item.key_iv:
                    failed.append({"source_id": item.file_id, "reason": "missing_crypto_fields"})
                    continue
                new_enc_key = item.encrypted_file_key
                new_key_iv  = item.key_iv

            else:
                # Path 3: Cross-Team (A → B) — client sends rk-transformed C1
                if not item.pre_c1:
                    failed.append({"source_id": item.file_id, "reason": "missing_crypto_fields"})
                    continue
                cursor = await db.execute(
                    "SELECT pre_c1, encrypted_file_key, key_iv FROM file_team_keys "
                    "WHERE team_id = ? AND file_id = ?",
                    (src_team_id, item.file_id),
                )
                src_ftk = await cursor.fetchone()
                if src_ftk is None:
                    failed.append({"source_id": item.file_id, "reason": "missing_team_key"})
                    continue
                ftk_pre_c1  = item.pre_c1
                ftk_enc_key = src_ftk["encrypted_file_key"]
                ftk_key_iv  = src_ftk["key_iv"]
                needs_ftk   = True

            # Execute copy in a single transaction
            await db.execute("BEGIN")
            try:
                await db.execute(
                    """
                    INSERT INTO files (
                        id, original_name, sanitized_name, storage_key,
                        folder_id, owner_id, mime_type,
                        size_bytes, encrypted_size, chunk_size, total_chunks,
                        encrypted_file_key, key_iv, checksum_sha256,
                        upload_complete, av_scan_status, av_scanned_at,
                        escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_file_id,
                        src_row["original_name"], src_row["sanitized_name"],
                        src_row["storage_key"],
                        dest_id, user.id, src_row["mime_type"],
                        src_row["size_bytes"], src_row["encrypted_size"],
                        src_row["chunk_size"], src_row["total_chunks"],
                        new_enc_key, new_key_iv,
                        src_row["checksum_sha256"],
                        src_row["av_scan_status"], src_row["av_scanned_at"],
                        src_row["escrow_ephemeral_pk"],
                        src_row["escrow_encrypted_key"],
                        src_row["escrow_key_iv"],
                    ),
                )

                # Copy chunk manifest (per-chunk IVs — same blob, same chunks)
                await db.execute(
                    """
                    INSERT INTO file_chunks (id, file_id, chunk_index, iv, size_bytes, "offset")
                    SELECT gen_random_uuid()::text, ?, chunk_index, iv, size_bytes, "offset"
                    FROM file_chunks WHERE file_id = ?
                    """,
                    (new_file_id, item.file_id),
                )

                # Insert file_team_keys for team destination
                if needs_ftk and ftk_pre_c1 and dest_team_id:
                    ftk_id = str(uuid.uuid4())
                    await db.execute(
                        "INSERT INTO file_team_keys "
                        "(id, team_id, file_id, pre_c1, encrypted_file_key, key_iv) "
                        "VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT (team_id, file_id) DO UPDATE SET "
                        "pre_c1 = excluded.pre_c1, "
                        "encrypted_file_key = excluded.encrypted_file_key, "
                        "key_iv = excluded.key_iv",
                        (ftk_id, dest_team_id, new_file_id, ftk_pre_c1, ftk_enc_key, ftk_key_iv),
                    )

                # Inherit destination folder's recursive permissions
                await copy_folder_permissions(db, dest_id, "file", new_file_id)

                # Increment copying user's disk quota
                if src_row["encrypted_size"]:
                    await db.execute(
                        "UPDATE users SET disk_used = disk_used + ?::bigint WHERE id = ?",
                        (src_row["encrypted_size"], user.id),
                    )

                await db.commit()
                copied.append({"source_id": item.file_id, "new_id": new_file_id})

                sse_broker.publish(dest_id, {"type": "change"})

            except Exception:
                await db.rollback()
                failed.append({"source_id": item.file_id, "reason": "error"})

        except Exception:
            failed.append({"source_id": item.file_id, "reason": "error"})

    if copied:
        first = copied[0]
        event_bus.emit(SecurityEvent(
            event_type="file.copy",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=user.id, username=user.username, ip=ip),
            target=EventTarget(type="file", id=first["source_id"]),
            detail={
                "destination_folder_id": dest_id,
                "destination_file_id":   first["new_id"],
                "destination_team_id":   dest_team_id,
                "copy_count":            len(copied),
            },
        ))

    return {"copied": copied, "failed": failed}


@router.get("/{file_id}")
async def get_file_metadata(
    file_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Get file metadata (not content)."""
    file_id = validate_uuid(file_id)

    cursor = await db.execute("SELECT * FROM files WHERE id = ? AND deleted_at IS NULL", (file_id,))
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

    cursor = await db.execute("SELECT * FROM files WHERE id = ? AND deleted_at IS NULL", (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    if body.move_to_root and body.folder_id is not None:
        raise HTTPException(status_code=400, detail="Cannot specify both folder_id and move_to_root")

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
    if body.move_to_root:
        updates.append("folder_id = ?")
        params.append(None)
    elif body.folder_id is not None:
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
            # Allow moves into team folders where the user is a member
            if not await is_team_folder_member(db, body.folder_id, user.id):
                raise HTTPException(status_code=403, detail="Access denied to target folder")
        updates.append("folder_id = ?")
        params.append(body.folder_id)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = NOW()")
    params.append(file_id)

    await db.execute(
        f"UPDATE files SET {', '.join(updates)} WHERE id = ?",
        params,
    )

    # On a folder change, replace inherited permissions with those from the new folder.
    new_folder_id = body.folder_id if (body.folder_id and not body.move_to_root) else None
    is_move = body.move_to_root or body.folder_id is not None
    if is_move:
        await db.execute(
            "DELETE FROM permissions WHERE resource_type = 'file' AND resource_id = ? AND recursive = 1",
            (file_id,),
        )
        if new_folder_id:
            await copy_folder_permissions(db, new_folder_id, "file", file_id)

        # Clean up stale file_team_keys if the file is leaving a team's scope.
        old_team_id = await get_folder_team_id(db, row["folder_id"]) if row["folder_id"] else None
        new_team_id = await get_folder_team_id(db, new_folder_id) if new_folder_id else None
        if old_team_id and old_team_id != new_team_id:
            await db.execute(
                "DELETE FROM file_team_keys WHERE team_id = ? AND file_id = ?",
                (old_team_id, file_id),
            )

    await db.commit()

    # Notify the folder the file was in (and the destination if it was moved)
    old_topic = row["folder_id"] or f"root:{row['owner_id']}"
    sse_broker.publish(old_topic, {"type": "change"})
    if body.folder_id and body.folder_id != row["folder_id"]:
        sse_broker.publish(body.folder_id, {"type": "change"})

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
    """Delete a file.

    When trash is enabled the file is soft-deleted (moved to trash). Otherwise
    the row and blob are permanently removed immediately.
    DB mutations are atomic; blob removal is non-blocking and best-effort.
    """
    file_id = validate_uuid(file_id)

    cursor = await db.execute(
        "SELECT id, storage_key, owner_id, folder_id, encrypted_size FROM files "
        "WHERE id = ? AND deleted_at IS NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    # Check whether trash is enabled.
    cursor = await db.execute(
        "SELECT value FROM admin_settings WHERE key = 'trash_enabled'",
    )
    setting = await cursor.fetchone()
    trash_enabled = (setting["value"] if setting else "true") == "true"

    if trash_enabled:
        await db.execute(
            "UPDATE files SET deleted_at = NOW(), deleted_by = ? WHERE id = ?",
            (user.id, file_id),
        )
        await db.commit()
        sse_broker.publish(row["folder_id"] or f"root:{row['owner_id']}", {"type": "change"})
        return {"message": "File moved to trash"}

    # Trash disabled — hard delete immediately.
    storage_key = row["storage_key"]
    encrypted_size = row["encrypted_size"]
    owner_id = row["owner_id"]

    # Atomic: update quota + delete record in one transaction.
    # file_storage_locations cascades on files DELETE.
    await db.execute("BEGIN")
    try:
        await db.execute(
            "UPDATE users SET disk_used = GREATEST(0, disk_used - ?::bigint) WHERE id = ?",
            (encrypted_size, owner_id),
        )
        await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    sse_broker.publish(row["folder_id"] or f"root:{row['owner_id']}", {"type": "change"})

    # Blob ref-count: only delete the blob when no other files row shares storage_key
    cursor = await db.execute(
        "SELECT COUNT(*) AS cnt FROM files WHERE storage_key = ?", (storage_key,)
    )
    cnt_row = await cursor.fetchone()
    blob_is_last_ref = cnt_row is None or cnt_row["cnt"] == 0

    if blob_is_last_ref:
        async def _bg_delete(fid: str, key: str) -> None:
            try:
                async with db_session() as _db:
                    await storage.get_manager().delete_blob(_db, fid, key)
            except Exception:
                pass

        asyncio.create_task(_bg_delete(file_id, storage_key))

    return {"message": "File deleted"}


async def _update_last_accessed(file_id: str) -> None:
    try:
        from datetime import datetime, timezone
        async with db_session() as _db:
            await _db.execute(
                "UPDATE files SET last_accessed_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), file_id),
            )
            await _db.commit()
    except Exception:
        pass


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
        ip = _get_client_ip(request)[:64]
        ua = (request.headers.get("User-Agent") or "")[:512]
        log_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO access_logs
                (id, file_id, user_id, actor_username, share_id, ip_address, user_agent, action)
            VALUES (?, ?, ?, ?, NULL, ?, ?, 'download')
            """,
            (log_id, file_id, user.id, user.username, ip, ua),
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
        "encrypted_size, upload_complete, transfer_locked_at, av_scan_status FROM files "
        "WHERE id = ? AND deleted_at IS NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    if not row["upload_complete"]:
        raise HTTPException(status_code=409, detail="File upload is not complete")

    if row["transfer_locked_at"] is not None:
        raise HTTPException(status_code=423, detail="File is transfer-locked by an administrator")

    await check_file_access(db, row, user)

    # AV gate: block download when av_require_clean is enabled and file is not confirmed clean
    await _check_av_gate(db, row)

    storage_key = row["storage_key"]
    encrypted_size: int = row["encrypted_size"]

    if encrypted_size <= 0:
        raise HTTPException(status_code=422, detail="File has no content")

    # Verify blob is reachable before committing to stream
    blob_exists = await storage.get_manager().exists(db, file_id, storage_key)
    if not blob_exists:
        logger.error("Blob missing for file %s (storage_key=%s)", file_id, storage_key)
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

    # --- Access log + last_accessed_at update (on first chunk request) ---
    if not range_header or start == 0:
        await _log_download(db, request, user, file_id)
        asyncio.create_task(_update_last_accessed(file_id))

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

    stream = await storage.get_manager().read_stream(db, file_id, storage_key, start, end)
    return StreamingResponse(
        stream,
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

    cursor = await db.execute("SELECT * FROM files WHERE id = ? AND deleted_at IS NULL", (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    await check_file_access(db, row, user)

    cursor = await db.execute(
        "SELECT * FROM file_chunks WHERE file_id = ? ORDER BY chunk_index LIMIT ? OFFSET ?",
        (file_id, limit, offset),
    )
    chunks = [FileChunk.from_row(r).to_dict() for r in await cursor.fetchall()]

    is_owner = row["owner_id"] == user.id
    return {
        "file_id": file_id,
        "original_name": row["original_name"],
        "mime_type": row["mime_type"],
        "size_bytes": row["size_bytes"],          # plaintext file size for integrity check
        "encrypted_file_key": row["encrypted_file_key"] if is_owner else None,
        "key_iv": row["key_iv"] if is_owner else None,
        "chunk_size": row["chunk_size"],
        "total_chunks": row["total_chunks"],
        "chunks": chunks,
        "offset": offset,
        "limit": limit,
    }
