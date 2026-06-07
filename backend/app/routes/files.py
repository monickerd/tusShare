"""File metadata and content routes.

Content serving (with Range support) and access logging implemented in
Phase 4. Encrypted bytes are served verbatim — the server never decrypts.
"""

import asyncio
import hashlib as _hashlib
import logging
import re as _re
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

import app.storage.manager as storage
from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import Database, db_session, get_db
from app.middleware.bandwidth import check_bandwidth
from app.middleware.rate_limit import _get_client_ip
from app.models.file import File, FileChunk
from app.routes._access import (
    _team_level_for_user,
    check_data_permission,
    copy_folder_permissions,
    get_folder_team_id,
    is_in_shared_tree,
    is_team_folder_member,
)
from app.services import event_bus, sse_broker
from app.util.db import get_admin_setting
from app.util.http import content_disposition, parse_range_header
from app.validation.sanitizers import sanitize_filename, validate_uuid

_ERR_ACCESS_DENIED = "Access denied"
_SQL_FILE_BY_ID = "SELECT * FROM files WHERE id = ? AND deleted_at IS NULL"
_ERR_FILE_NOT_FOUND = "File not found"

_bg_tasks: set = set()

logger = logging.getLogger(__name__)


async def check_file_access(db, file_row, user: AuthenticatedUser) -> None:
    """Verify user has read access to a file. Raises 403 if denied.

    Evaluation order:
      1. Owner or files_access_all_read/write flag → allow immediately.
      2. Public shared-folder tree → allow (backward-compat public sharing).
      3. Full Phase 1 permission chain via check_data_permission:
         explicit deny/allow ACL → team-based grant → ancestry walk → deny.
    """
    from app.models.role import FLAG_FILES_ACCESS_ALL_READ, FLAG_FILES_ACCESS_ALL_WRITE

    if (
        file_row["owner_id"] == user.id
        or user.has_flag(FLAG_FILES_ACCESS_ALL_READ)
        or user.has_flag(FLAG_FILES_ACCESS_ALL_WRITE)
    ):
        return
    if file_row["folder_id"] and await is_in_shared_tree(db, file_row["folder_id"]):
        return
    if await check_data_permission(db, "file", file_row["id"], user.id, "read"):
        return
    raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)  # NOSONAR — helper; 403 documented in callers


router = APIRouter()


async def _av_gate_active(db) -> bool:
    """Return True when av_require_clean is enabled AND av_scan_endpoint is configured."""
    cursor = await db.execute(
        "SELECT key, value FROM admin_settings WHERE key IN ('av_require_clean', 'av_scan_endpoint')"
    )
    rows = {r["key"]: r["value"] for r in await cursor.fetchall()}
    return rows.get("av_require_clean", "false").lower() == "true" and bool(rows.get("av_scan_endpoint", "").strip())


async def _check_av_gate(db, file_row) -> None:
    """Raise 451 if av_require_clean is active and file is not clean."""
    if file_row.get("av_scan_status") == "clean":
        return
    if not await _av_gate_active(db):
        return
    status = file_row.get("av_scan_status") or "null"
    raise HTTPException(  # NOSONAR — helper; 451 documented in callers
        status_code=451,
        detail={
            "detail": "File pending antivirus scan",
            "av_status": status,
        },
    )


_NAME_IDX_PATTERN_FILES = __import__('re').compile(r'^[0-9a-f]{64}$')


class UpdateFileRequest(BaseModel):
    original_name: str | None = None
    folder_id: str | None = None
    move_to_root: bool = False
    name_ct: str | None = None
    name_idx: str | None = None

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

    @field_validator("name_ct")
    @classmethod
    def validate_name_ct(cls, v: str | None) -> str | None:
        if v is not None:
            from app.validation.sanitizers import validate_base64
            return validate_base64(v)
        return v

    @field_validator("name_idx")
    @classmethod
    def validate_name_idx(cls, v: str | None) -> str | None:
        if v is not None and not _NAME_IDX_PATTERN_FILES.match(v):
            raise ValueError("name_idx must be a 64-char hex string")
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


async def _check_batch_move_permission(
    db, user, file_row, src_team_id: str | None, dest_team_id: str | None
) -> str | None:
    """Return a deny reason string, or None if the move is permitted."""
    is_owner = file_row["owner_id"] == user.id
    if not is_owner:
        if not src_team_id:
            return "permission_denied"
        from app.models.team_role import TEAM_FLAG_MOVE_OTHERS_OUT, get_user_team_move_flags

        move_flags = await get_user_team_move_flags(db, user.id, src_team_id)
        return None if move_flags[TEAM_FLAG_MOVE_OTHERS_OUT] else "permission_denied"
    if src_team_id and src_team_id != dest_team_id:
        from app.models.team_role import TEAM_FLAG_MOVE_OWN_OUT, get_user_team_move_flags

        move_flags = await get_user_team_move_flags(db, user.id, src_team_id)
        return None if move_flags[TEAM_FLAG_MOVE_OWN_OUT] else "permission_denied"
    return None


async def _execute_file_move_tx(db, item, dest_id, dest_team_id, src_folder_id, src_team_id, user) -> str | None:
    """Execute DB transaction for one file move. Returns error reason or None on success."""
    await db.execute("BEGIN")
    try:
        await db.execute(
            "UPDATE files SET folder_id = ?, updated_at = NOW() WHERE id = ?",
            (dest_id, item.id),
        )
        await db.execute(
            "DELETE FROM permissions WHERE resource_type = 'file' AND resource_id = ? AND recursive = 1",
            (item.id,),
        )
        # Recursive file-level permissions may have been propagated from a folder
        # that has a policy_folder_grant with acl_written=1.  The folder grant
        # itself is not stale (it still covers the folder), so no tracking update
        # is needed here — only the derived file rows were cleared.
        if dest_id:
            await copy_folder_permissions(db, dest_id, "file", item.id)
        if src_team_id and src_team_id != dest_team_id:
            await db.execute(
                "DELETE FROM file_team_keys WHERE team_id = ? AND file_id = ?",
                (src_team_id, item.id),
            )
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
                (new_ftk_id, dest_team_id, item.id, tk.pre_c1, tk.encrypted_file_key, tk.key_iv),
            )
        await db.commit()
        topic = src_folder_id if src_folder_id else f"root:{user.id}"
        sse_broker.publish(topic, {"type": "change"})
        if dest_id and dest_id != src_folder_id:
            sse_broker.publish(dest_id, {"type": "change"})
        return None
    except Exception:
        await db.rollback()
        return "error"


async def _validate_move_destination(db, dest_id: str | None, user) -> str | None:
    """Validate access to destination folder and return its team_id (or None)."""
    if not dest_id:
        return None
    cursor = await db.execute("SELECT owner_id FROM folders WHERE id = ?", (dest_id,))
    dest_folder = await cursor.fetchone()
    if dest_folder is None:
        raise HTTPException(status_code=404, detail="Destination folder not found")
    if dest_folder["owner_id"] != user.id and not user.is_admin:
        if not await check_data_permission(db, "folder", dest_id, user.id, "write"):
            raise HTTPException(status_code=403, detail="Access denied to destination folder")
    return await get_folder_team_id(db, dest_id)


async def _process_single_file_move(
    db, item, dest_id, dest_team_id, gate_active, user
) -> tuple[str | None, str | None]:
    """Process one file in batch-move. Returns (succeeded_id, failed_entry) with one set."""
    try:
        cursor = await db.execute(
            "SELECT id, folder_id, owner_id, av_scan_status FROM files WHERE id = ? AND deleted_at IS NULL",
            (item.id,),
        )
        file_row = await cursor.fetchone()
        if file_row is None:
            return None, "not_found"
        if gate_active and file_row.get("av_scan_status") != "clean":
            return None, "av_not_clean"
        src_folder_id = file_row["folder_id"]
        src_team_id = await get_folder_team_id(db, src_folder_id) if src_folder_id else None
        deny_reason = await _check_batch_move_permission(db, user, file_row, src_team_id, dest_team_id)
        if deny_reason:
            return None, deny_reason
        err_reason = await _execute_file_move_tx(db, item, dest_id, dest_team_id, src_folder_id, src_team_id, user)
        return (None, err_reason) if err_reason else (item.id, None)
    except Exception:
        return None, "error"


@router.get("/search")
async def search_files(
    q: Annotated[str, Query(max_length=200)] = "",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)] = None,
    db: Annotated[Database, Depends(get_db)] = None,
):
    """Search files by name substring across all folders the authenticated user may access.

    Access scope is computed entirely server-side (not caller-supplied):
    - Files the user owns
    - Files in team folders where the user holds a confirmed key (user_team_keys)
    - Files in folders with an explicit permissions grant (recursive grants propagate
      downward, both stopping at restrict_permissions boundaries)

    Uses case-insensitive substring match against original_name.
    """
    term = q.strip()
    if not term:
        return {"files": []}

    escaped = term.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    pattern = f"%{escaped}%"

    # Two recursive CTEs derive the user's accessible folder set server-side.
    # team_tree: all folders reachable from a team root the user is a member of,
    #            descending through non-restricted subfolders.
    # perm_tree: all folders with a direct permission grant for the user, plus
    #            descendants of recursive grants, stopping at restrict_permissions.
    cursor = await db.execute(
        "WITH RECURSIVE "
        "team_tree(id) AS ( "
        "    SELECT tf.folder_id "
        "    FROM team_folders tf "
        "    JOIN user_team_keys utk ON utk.team_id = tf.team_id AND utk.user_id = ? AND utk.key_confirmed = 1 "
        "    UNION ALL "
        "    SELECT f.id "
        "    FROM folders f "
        "    JOIN team_tree tt ON f.parent_id = tt.id "
        "    WHERE f.restrict_permissions = false AND f.deleted_at IS NULL "
        "), "
        "perm_tree(id, rec) AS ( "
        "    SELECT p.resource_id, p.recursive "
        "    FROM permissions p "
        "    WHERE p.resource_type = 'folder' AND p.user_id = ? "
        "    UNION ALL "
        "    SELECT f.id, 1 "
        "    FROM folders f "
        "    JOIN perm_tree pt ON f.parent_id = pt.id AND pt.rec = 1 "
        "    WHERE f.restrict_permissions = false AND f.deleted_at IS NULL "
        ") "
        "SELECT f.id, f.original_name, f.name_ct, f.size_bytes, f.created_at, f.folder_id, "
        "       f.encrypted_file_key, f.key_iv, fold.name AS folder_name "
        "FROM files f "
        "LEFT JOIN folders fold ON fold.id = f.folder_id "
        "WHERE f.deleted_at IS NULL "
        "  AND LOWER(f.original_name) LIKE LOWER(?) ESCAPE '!' "
        "  AND (f.owner_id = ? "
        "       OR f.folder_id IN (SELECT id FROM team_tree) "
        "       OR f.folder_id IN (SELECT id FROM perm_tree)) "
        "ORDER BY f.created_at DESC "
        "LIMIT ?",
        (user.id, user.id, pattern, user.id, limit),
    )
    rows = await cursor.fetchall()
    return {
        "files": [
            {
                "id": r["id"],
                "original_name": r["original_name"],
                "name_ct": r["name_ct"],
                "size_bytes": r["size_bytes"],
                "created_at": str(r["created_at"]) if r["created_at"] else None,
                "folder_id": r["folder_id"],
                "folder_path": r["folder_name"] or "(root)",
                "encrypted_file_key": r["encrypted_file_key"],
                "key_iv": r["key_iv"],
            }
            for r in rows
        ]
    }


_MANIFEST_LIMIT = 10000


def _manifest_cte_params(user_id: str) -> tuple[str, tuple]:
    """Return the manifest CTE SQL fragment and its positional parameters."""
    sql = (
        "WITH RECURSIVE "
        "team_tree(id) AS ( "
        "    SELECT tf.folder_id "
        "    FROM team_folders tf "
        "    JOIN user_team_keys utk ON utk.team_id = tf.team_id AND utk.user_id = ? AND utk.key_confirmed = 1 "
        "    UNION ALL "
        "    SELECT f.id FROM folders f "
        "    JOIN team_tree tt ON f.parent_id = tt.id "
        "    WHERE f.restrict_permissions = false AND f.deleted_at IS NULL "
        "), "
        "perm_tree(id, rec) AS ( "
        "    SELECT p.resource_id, p.recursive FROM permissions p "
        "    WHERE p.resource_type = 'folder' AND p.user_id = ? "
        "    UNION ALL "
        "    SELECT f.id, 1 FROM folders f "
        "    JOIN perm_tree pt ON f.parent_id = pt.id AND pt.rec = 1 "
        "    WHERE f.restrict_permissions = false AND f.deleted_at IS NULL "
        ") "
    )
    return sql, (user_id, user_id)


def _rows_to_manifest_files(rows) -> list[dict]:
    return [
        {
            "id":                r["id"],
            "name_ct":           r["name_ct"],
            "original_name":     r["original_name"],
            "size_bytes":        r["size_bytes"],
            "created_at":        str(r["created_at"]) if r["created_at"] else None,
            "folder_id":         r["folder_id"],
            "folder_path":       r["folder_name"] or "(root)",
            "encrypted_file_key": r["encrypted_file_key"],
            "key_iv":            r["key_iv"],
        }
        for r in rows
    ]


@router.get("/manifest")
async def get_file_manifest(
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    folder_id: str | None = None,
):
    """Return all files accessible to the user for client-side search.

    The server returns name_ct (ciphertext) rather than executing a plaintext
    query — the client decrypts names locally and performs substring matching
    in-memory, so the server never learns the search term.  original_name is
    included as a fallback for rows that have not yet been through the lazy
    name-encryption migration.

    Optional folder_id param scopes the manifest to a specific folder subtree
    (permission-boundary optimisation — reduces payload when searching within
    a single restricted folder).

    Supports ETag-based conditional GET: returns 304 Not Modified when the
    client's cached manifest is still current.
    """
    if folder_id is not None:
        try:
            folder_id = validate_uuid(folder_id)
        except ValueError:
            folder_id = None

    cte_sql, cte_params = _manifest_cte_params(user.id)

    if folder_id:
        # Scope to a specific folder subtree using a secondary recursive CTE.
        sql = (
            cte_sql
            + "subtree(id) AS ( "
            "    SELECT ? "
            "    UNION ALL "
            "    SELECT f.id FROM folders f "
            "    JOIN subtree s ON f.parent_id = s.id "
            "    WHERE f.restrict_permissions = false AND f.deleted_at IS NULL "
            ") "
            "SELECT f.id, f.name_ct, f.original_name, f.size_bytes, f.created_at, "
            "       f.folder_id, f.encrypted_file_key, f.key_iv, fold.name AS folder_name "
            "FROM files f "
            "LEFT JOIN folders fold ON fold.id = f.folder_id "
            "WHERE f.deleted_at IS NULL AND f.upload_complete = 1 "
            "  AND f.folder_id IN (SELECT id FROM subtree) "
            "  AND (f.owner_id = ? "
            "       OR f.folder_id IN (SELECT id FROM team_tree) "
            "       OR f.folder_id IN (SELECT id FROM perm_tree)) "
            "ORDER BY f.created_at DESC "
            f"LIMIT {_MANIFEST_LIMIT}"
        )
        params = (*cte_params, folder_id, user.id)
    else:
        sql = (
            cte_sql
            + "SELECT f.id, f.name_ct, f.original_name, f.size_bytes, f.created_at, "
            "       f.folder_id, f.encrypted_file_key, f.key_iv, fold.name AS folder_name "
            "FROM files f "
            "LEFT JOIN folders fold ON fold.id = f.folder_id "
            "WHERE f.deleted_at IS NULL AND f.upload_complete = 1 "
            "  AND (f.owner_id = ? "
            "       OR f.folder_id IN (SELECT id FROM team_tree) "
            "       OR f.folder_id IN (SELECT id FROM perm_tree)) "
            "ORDER BY f.created_at DESC "
            f"LIMIT {_MANIFEST_LIMIT}"
        )
        params = (*cte_params, user.id)

    cursor = await db.execute(sql, params)
    rows = await cursor.fetchall()
    files = _rows_to_manifest_files(rows)

    # ETag: SHA-256 of all file IDs + updated_at values in result order.
    # Cheap proxy for "did the set of files change?" without hashing full content.
    etag_src = "|".join(f"{r['id']},{r['created_at']}" for r in rows)
    etag = f'"{_hashlib.sha256(etag_src.encode()).hexdigest()[:32]}"'

    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "no-cache, private"})

    return Response(
        content=__import__("json").dumps({"files": files, "etag": etag}),
        media_type="application/json",
        headers={"ETag": etag, "Cache-Control": "no-cache, private"},
    )


_NAME_IDX_RE = _re.compile(r'^[0-9a-f]{64}$')

_UNMIGRATED_PAGE_SIZE = 200


@router.get("/unmigrated-names", responses={200: {"description": "OK"}})
async def get_unmigrated_names(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return all of the authenticated user's files and folders that lack an encrypted name.

    The client calls this once after login and encrypts the names locally, then
    submits the results to POST /files/migrate-names.
    """
    cursor = await db.execute(
        "SELECT id, original_name FROM files "
        "WHERE owner_id = ? AND name_ct IS NULL AND upload_complete = 1 AND deleted_at IS NULL "
        "LIMIT ?",
        (user.id, _UNMIGRATED_PAGE_SIZE),
    )
    files = [{"id": r["id"], "name": r["original_name"], "type": "file"} for r in await cursor.fetchall()]

    cursor = await db.execute(
        "SELECT id, name FROM folders "
        "WHERE owner_id = ? AND name_ct IS NULL AND deleted_at IS NULL "
        "LIMIT ?",
        (user.id, _UNMIGRATED_PAGE_SIZE),
    )
    folders = [{"id": r["id"], "name": r["name"], "type": "folder"} for r in await cursor.fetchall()]

    return {"items": files + folders}


class _MigrateNameItem(BaseModel):
    id: str
    type: str
    name_ct: str
    name_idx: str

    @field_validator("id")
    @classmethod
    def _vid(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("type")
    @classmethod
    def _vtype(cls, v: str) -> str:
        if v not in ("file", "folder"):
            raise ValueError("type must be 'file' or 'folder'")
        return v

    @field_validator("name_ct")
    @classmethod
    def _vct(cls, v: str) -> str:
        from app.validation.sanitizers import validate_base64
        return validate_base64(v)

    @field_validator("name_idx")
    @classmethod
    def _vidx(cls, v: str) -> str:
        if not _NAME_IDX_RE.match(v):
            raise ValueError("name_idx must be a 64-char hex string")
        return v


class _MigrateNamesRequest(BaseModel):
    items: list[_MigrateNameItem]

    @field_validator("items")
    @classmethod
    def _vitems(cls, v: list) -> list:
        if not v:
            raise ValueError("items must not be empty")
        if len(v) > _UNMIGRATED_PAGE_SIZE:
            raise ValueError(f"Cannot migrate more than {_UNMIGRATED_PAGE_SIZE} items per request")
        return v


@router.post("/migrate-names", responses={200: {"description": "OK"}, 400: {"description": "Bad Request"}})
async def migrate_names(
    body: _MigrateNamesRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Bulk-write encrypted name ciphertext for the user's own files and folders.

    Only rows where the caller is the owner and name_ct IS NULL are updated —
    already-migrated rows are silently skipped.  This prevents a race between
    concurrent sessions from corrupting previously set values.
    """
    updated = 0
    for item in body.items:
        if item.type == "file":
            cur = await db.execute(
                "UPDATE files SET name_ct = ?, name_idx = ? "
                "WHERE id = ? AND owner_id = ? AND name_ct IS NULL",
                (item.name_ct, item.name_idx, item.id, user.id),
            )
        else:
            cur = await db.execute(
                "UPDATE folders SET name_ct = ?, name_idx = ? "
                "WHERE id = ? AND owner_id = ? AND name_ct IS NULL",
                (item.name_ct, item.name_idx, item.id, user.id),
            )
        updated += cur.rowcount if hasattr(cur, "rowcount") else 0
    await db.commit()
    return {"updated": updated}


@router.post(
    "/batch-move",
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
async def batch_move_files(
    body: BatchMoveRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
    from app.schemas.security_event import EventActor, SecurityEvent

    dest_id = body.destination_folder_id
    dest_team_id = await _validate_move_destination(db, dest_id, user)

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
        ok_id, fail_reason = await _process_single_file_move(db, item, dest_id, dest_team_id, gate_active, user)
        if ok_id:
            succeeded.append(ok_id)
        else:
            failed.append({"id": item.id, "reason": fail_reason})

    if succeeded:
        event_bus.emit(
            SecurityEvent(
                event_type="file.move",
                severity="info",
                outcome="success",
                actor=EventActor(user_id=user.id, username=user.username, ip=_get_client_ip(request)),
                detail={
                    "destination_folder_id": dest_id,
                    "destination_team_id": dest_team_id,
                    "file_ids": succeeded,
                    "move_count": len(succeeded),
                },
            )
        )

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


def _copy_fields(new_enc_key, new_key_iv, ftk_pre_c1=None, ftk_enc_key=None, ftk_key_iv=None, needs_ftk=False):
    return {
        "new_enc_key": new_enc_key,
        "new_key_iv": new_key_iv,
        "ftk_pre_c1": ftk_pre_c1,
        "ftk_enc_key": ftk_enc_key,
        "ftk_key_iv": ftk_key_iv,
        "needs_ftk": needs_ftk,
    }


async def _resolve_same_team_path(db, item, src_row, src_team_id):
    """Path 1 (personal→personal) or Path 2 (same-team copy)."""
    if src_team_id is None:
        return _copy_fields(src_row["encrypted_file_key"], src_row["key_iv"]), None
    cursor = await db.execute(
        "SELECT pre_c1, encrypted_file_key, key_iv FROM file_team_keys WHERE team_id = ? AND file_id = ?",
        (src_team_id, item.file_id),
    )
    src_ftk = await cursor.fetchone()
    if src_ftk:
        return _copy_fields(
            src_row["encrypted_file_key"],
            src_row["key_iv"],
            src_ftk["pre_c1"],
            src_ftk["encrypted_file_key"],
            src_ftk["key_iv"],
            True,
        ), None
    return _copy_fields(src_row["encrypted_file_key"], src_row["key_iv"]), None


def _resolve_personal_to_team_path(item, src_row):
    """Path 4: personal → team."""
    if not item.pre_c1 or not item.encrypted_file_key or not item.key_iv:
        return None, "missing_crypto_fields"
    return _copy_fields(
        src_row["encrypted_file_key"], src_row["key_iv"], item.pre_c1, item.encrypted_file_key, item.key_iv, True
    ), None


def _resolve_team_to_personal_path(item):
    """Path 5: team → personal."""
    if not item.encrypted_file_key or not item.key_iv:
        return None, "missing_crypto_fields"
    return _copy_fields(item.encrypted_file_key, item.key_iv), None


async def _resolve_cross_team_path(db, item, src_row, src_team_id):
    """Path 3: cross-team copy."""
    if not item.pre_c1:
        return None, "missing_crypto_fields"
    cursor = await db.execute(
        "SELECT pre_c1, encrypted_file_key, key_iv FROM file_team_keys WHERE team_id = ? AND file_id = ?",
        (src_team_id, item.file_id),
    )
    src_ftk = await cursor.fetchone()
    if src_ftk is None:
        return None, "missing_team_key"
    return _copy_fields(
        src_row["encrypted_file_key"],
        src_row["key_iv"],
        item.pre_c1,
        src_ftk["encrypted_file_key"],
        src_ftk["key_iv"],
        True,
    ), None


async def _resolve_copy_crypto_fields(
    db, item: "_BatchCopyItem", src_row, src_team_id: str | None, dest_team_id: str | None
) -> "tuple[dict | None, str | None]":
    """Return (fields_dict, None) on success or (None, reason) on failure."""
    if src_team_id == dest_team_id:
        return await _resolve_same_team_path(db, item, src_row, src_team_id)
    if src_team_id is None:
        return _resolve_personal_to_team_path(item, src_row)
    if dest_team_id is None:
        return _resolve_team_to_personal_path(item)
    return await _resolve_cross_team_path(db, item, src_row, src_team_id)


async def _execute_file_copy_tx(
    db, item, src_row, dest_id: str, dest_team_id: str | None, user, cf: dict
) -> "tuple[str | None, str | None]":
    """Execute DB transaction for one file copy. Returns (new_file_id, None) or (None, reason)."""
    new_file_id = str(uuid.uuid4())
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
                src_row["original_name"],
                src_row["sanitized_name"],
                src_row["storage_key"],
                dest_id,
                user.id,
                src_row["mime_type"],
                src_row["size_bytes"],
                src_row["encrypted_size"],
                src_row["chunk_size"],
                src_row["total_chunks"],
                cf["new_enc_key"],
                cf["new_key_iv"],
                src_row["checksum_sha256"],
                src_row["av_scan_status"],
                src_row["av_scanned_at"],
                src_row["escrow_ephemeral_pk"],
                src_row["escrow_encrypted_key"],
                src_row["escrow_key_iv"],
            ),
        )
        await db.execute(
            """
            INSERT INTO file_chunks (id, file_id, chunk_index, iv, size_bytes, "offset")
            SELECT gen_random_uuid()::text, ?, chunk_index, iv, size_bytes, "offset"
            FROM file_chunks WHERE file_id = ?
            """,
            (new_file_id, item.file_id),
        )
        if cf["needs_ftk"] and cf["ftk_pre_c1"] and dest_team_id:
            ftk_id = str(uuid.uuid4())
            await db.execute(
                "INSERT INTO file_team_keys "
                "(id, team_id, file_id, pre_c1, encrypted_file_key, key_iv) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (team_id, file_id) DO UPDATE SET "
                "pre_c1 = excluded.pre_c1, "
                "encrypted_file_key = excluded.encrypted_file_key, "
                "key_iv = excluded.key_iv",
                (ftk_id, dest_team_id, new_file_id, cf["ftk_pre_c1"], cf["ftk_enc_key"], cf["ftk_key_iv"]),
            )
        await copy_folder_permissions(db, dest_id, "file", new_file_id)
        if src_row["encrypted_size"]:
            await db.execute(
                "UPDATE users SET disk_used = disk_used + ?::bigint WHERE id = ?",
                (src_row["encrypted_size"], user.id),
            )
        await db.commit()
        sse_broker.publish(dest_id, {"type": "change"})
        return new_file_id, None
    except Exception:
        await db.rollback()
        return None, "error"


async def _validate_copy_destination(db, dest_id: str, user) -> str | None:
    """Validate access to copy destination folder and return its team_id (or None)."""
    cursor = await db.execute("SELECT owner_id FROM folders WHERE id = ? AND deleted_at IS NULL", (dest_id,))
    dest_folder = await cursor.fetchone()
    if dest_folder is None:
        raise HTTPException(status_code=404, detail="Destination folder not found")
    if dest_folder["owner_id"] != user.id and not user.is_admin:
        if not await check_data_permission(db, "folder", dest_id, user.id, "write"):
            raise HTTPException(status_code=403, detail="Access denied to destination folder")
    return await get_folder_team_id(db, dest_id)


async def _process_single_copy(db, item, dest_id, dest_team_id, copy_boundary, user, ip) -> tuple:
    """Process one file in batch-copy. Returns (copy_info, fail_info) with one set."""
    from app.schemas.security_event import EventActor, EventTarget, SecurityEvent

    try:
        cursor = await db.execute(
            "SELECT * FROM files WHERE id = ? AND deleted_at IS NULL AND upload_complete = 1",
            (item.file_id,),
        )
        src_row = await cursor.fetchone()
        if src_row is None:
            return None, {"source_id": item.file_id, "reason": "not_found"}
        try:
            await check_file_access(db, src_row, user)
        except HTTPException:
            return None, {"source_id": item.file_id, "reason": "permission_denied"}
        src_folder_id = src_row["folder_id"]
        src_team_id = await get_folder_team_id(db, src_folder_id) if src_folder_id else None
        if copy_boundary == "same_team" and src_team_id != dest_team_id:
            event_bus.emit(
                SecurityEvent(
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
                )
            )
            return None, {"source_id": item.file_id, "reason": "boundary_violation"}
        crypto_fields, reason = await _resolve_copy_crypto_fields(db, item, src_row, src_team_id, dest_team_id)
        if reason:
            return None, {"source_id": item.file_id, "reason": reason}
        new_file_id, err = await _execute_file_copy_tx(db, item, src_row, dest_id, dest_team_id, user, crypto_fields)
        if err:
            return None, {"source_id": item.file_id, "reason": err}
        return {"source_id": item.file_id, "new_id": new_file_id}, None
    except Exception:
        return None, {"source_id": item.file_id, "reason": "error"}


@router.post("/batch-copy", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def batch_copy_files(
    body: BatchCopyRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
    from app.models.role import FLAG_FILES_COPY
    from app.schemas.security_event import EventActor, EventTarget, SecurityEvent

    if not user.has_flag(FLAG_FILES_COPY):
        raise HTTPException(status_code=403, detail="copy.permission_denied")

    dest_id = body.destination_folder_id
    ip = _get_client_ip(request)
    dest_team_id = await _validate_copy_destination(db, dest_id, user)

    # Fetch copy_boundary admin setting
    boundary_val = await get_admin_setting(db, "copy_boundary", default="any")
    copy_boundary = boundary_val.lower()

    if copy_boundary == "disabled":
        event_bus.emit(
            SecurityEvent(
                event_type="file.copy.blocked",
                severity="warning",
                outcome="failure",
                actor=EventActor(user_id=user.id, username=user.username, ip=ip),
                detail={
                    "block_reason": "policy_disabled",
                    "copy_boundary_setting": "disabled",
                    "destination_folder_id": dest_id,
                },
            )
        )
        raise HTTPException(status_code=403, detail="copy.disabled")

    copied: list[dict] = []
    failed: list[dict] = []

    for item in body.files:
        copy_info, fail_info = await _process_single_copy(db, item, dest_id, dest_team_id, copy_boundary, user, ip)
        if copy_info:
            copied.append(copy_info)
        else:
            failed.append(fail_info)

    if copied:
        first = copied[0]
        event_bus.emit(
            SecurityEvent(
                event_type="file.copy",
                severity="info",
                outcome="success",
                actor=EventActor(user_id=user.id, username=user.username, ip=ip),
                target=EventTarget(type="file", id=first["source_id"]),
                detail={
                    "destination_folder_id": dest_id,
                    "destination_file_id": first["new_id"],
                    "destination_team_id": dest_team_id,
                    "copy_count": len(copied),
                },
            )
        )

    return {"copied": copied, "failed": failed}


@router.get("/{file_id}", responses={404: {"description": "Not Found"}})
async def get_file_metadata(
    file_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get file metadata (not content)."""
    file_id = validate_uuid(file_id)

    cursor = await db.execute(_SQL_FILE_BY_ID, (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_FILE_NOT_FOUND)

    file = File.from_row(row)
    await check_file_access(db, row, user)
    return {"file": file.to_dict()}


@router.get("/{file_id}/info", responses={404: {"description": "Not Found"}})
async def get_file_info(
    file_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return file statistics: name, size, creator, download count, last 5 access log entries."""
    file_id = validate_uuid(file_id)

    cursor = await db.execute(_SQL_FILE_BY_ID, (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_FILE_NOT_FOUND)
    await check_file_access(db, row, user)

    # Creator username
    owner_cursor = await db.execute("SELECT username FROM users WHERE id = ?", (row["owner_id"],))
    owner_row = await owner_cursor.fetchone()
    creator = owner_row["username"] if owner_row else row["owner_id"]

    # Download count
    dc_cursor = await db.execute(
        "SELECT COUNT(*) AS cnt FROM access_logs WHERE file_id = ? AND action = 'download'",
        (file_id,),
    )
    dc_row = await dc_cursor.fetchone()
    download_count = dc_row["cnt"] if dc_row else 0

    # Last 5 access log entries
    al_cursor = await db.execute(
        "SELECT actor_username, action, timestamp, ip_address FROM access_logs "
        "WHERE file_id = ? ORDER BY timestamp DESC LIMIT 5",
        (file_id,),
    )
    audit_rows = await al_cursor.fetchall()
    audit = [
        {
            "user": r["actor_username"],
            "action": r["action"],
            "timestamp": str(r["timestamp"]) if r["timestamp"] else None,
            "ip": r["ip_address"],
        }
        for r in audit_rows
    ]

    return {
        "file_id": row["id"],
        "name": row["original_name"],
        "size_bytes": row["size_bytes"],
        "created_at": str(row["created_at"]) if row["created_at"] else None,
        "creator": creator,
        "download_count": download_count,
        "audit": audit,
    }


async def _build_file_update_fields(db, body: UpdateFileRequest, user) -> "tuple[list, list, list[str]]":
    """Build SQL update clauses for a file update. Raises HTTPException on invalid input."""
    if body.move_to_root and body.folder_id is not None:
        raise HTTPException(status_code=400, detail="Cannot specify both folder_id and move_to_root")

    updates: list = []
    params: list = []
    removed_chars: list[str] = []
    if body.original_name is not None:
        updates.append("original_name = ?")
        params.append(body.original_name)
        sanitized = sanitize_filename(body.original_name)
        updates.append("sanitized_name = ?")
        params.append(sanitized.name)
        removed_chars = sanitized.removed_chars
    if body.name_ct is not None:
        if body.name_idx is None:
            raise HTTPException(status_code=400, detail="name_idx required when name_ct is provided")
        updates.append("name_ct = ?")
        params.append(body.name_ct)
        updates.append("name_idx = ?")
        params.append(body.name_idx)
    if body.move_to_root:
        updates.append("folder_id = ?")
        params.append(None)
    elif body.folder_id is not None:
        # Verify the target folder exists and is owned by this user.
        # Without this check, a user could move their file into another user's folder,
        # making it appear in that user's folder listing (since listing queries by folder_id).
        target_cursor = await db.execute("SELECT owner_id FROM folders WHERE id = ?", (body.folder_id,))
        target_folder = await target_cursor.fetchone()
        if target_folder is None:
            raise HTTPException(status_code=404, detail="Target folder not found")
        if target_folder["owner_id"] != user.id and not user.is_admin:
            if not await is_team_folder_member(db, body.folder_id, user.id):
                raise HTTPException(status_code=403, detail="Access denied to target folder")
        updates.append("folder_id = ?")
        params.append(body.folder_id)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    return updates, params, removed_chars


async def _apply_move_side_effects(db, body: UpdateFileRequest, file_id: str, row) -> None:
    """Update inherited permissions and team keys after a file is moved to a new folder."""
    new_folder_id = body.folder_id if (body.folder_id and not body.move_to_root) else None
    is_move = body.move_to_root or body.folder_id is not None
    if not is_move:
        return
    await db.execute(
        "DELETE FROM permissions WHERE resource_type = 'file' AND resource_id = ? AND recursive = 1",
        (file_id,),
    )
    # policy_folder_grants tracks folder-level grants only; derived file permissions
    # are not tracked separately and re-inherit from the new parent after copy below.
    if new_folder_id:
        await copy_folder_permissions(db, new_folder_id, "file", file_id)
    old_team_id = await get_folder_team_id(db, row["folder_id"]) if row["folder_id"] else None
    new_team_id = await get_folder_team_id(db, new_folder_id) if new_folder_id else None
    if old_team_id and old_team_id != new_team_id:
        await db.execute(
            "DELETE FROM file_team_keys WHERE team_id = ? AND file_id = ?",
            (old_team_id, file_id),
        )


async def _require_file_write_access(db, row, user: AuthenticatedUser) -> None:
    """Raise 403 if user is not the file owner, not an admin, and not a team write+ member."""
    if row["owner_id"] == user.id or user.is_admin:
        return
    if row["folder_id"]:
        team_id = await get_folder_team_id(db, row["folder_id"])
        if team_id:
            level = await _team_level_for_user(db, team_id, user.id)
            if level in ("admin", "write"):
                return
    raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)


@router.put(
    "/{file_id}",
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
async def update_file(
    file_id: str,
    body: UpdateFileRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Update file metadata (rename, move)."""
    from app.schemas.security_event import EventActor, EventTarget, SecurityEvent

    file_id = validate_uuid(file_id)

    cursor = await db.execute(_SQL_FILE_BY_ID, (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_FILE_NOT_FOUND)
    await _require_file_write_access(db, row, user)

    updates, params, removed_chars = await _build_file_update_fields(db, body, user)
    updates.append("updated_at = NOW()")
    params.append(file_id)

    await db.execute(f"UPDATE files SET {', '.join(updates)} WHERE id = ?", params)
    await _apply_move_side_effects(db, body, file_id, row)
    await db.commit()

    old_topic = row["folder_id"] or f"root:{row['owner_id']}"
    is_move = body.folder_id is not None or body.move_to_root
    new_folder_id = body.folder_id if not body.move_to_root else None
    sse_event_type = "file.moved" if is_move else "file.updated"
    sse_file_payload = {
        "id": file_id,
        "folder_id": new_folder_id if is_move else row["folder_id"],
        "name_ct": body.name_ct if body.name_ct else row["name_ct"],
        "original_name": body.original_name if body.original_name else row["original_name"],
    }
    sse_broker.publish(old_topic, {"type": sse_event_type, "file": sse_file_payload})
    if body.folder_id and body.folder_id != row["folder_id"]:
        sse_broker.publish(body.folder_id, {"type": "file.moved", "file": sse_file_payload})

    ip = _get_client_ip(request)
    if is_move:
        event_bus.emit(
            SecurityEvent(
                event_type="file.move",
                severity="info",
                outcome="success",
                actor=EventActor(user_id=user.id, username=user.username, ip=ip),
                target=EventTarget(type="file", id=file_id, name=row["original_name"]),
                detail={"from_folder_id": row["folder_id"], "to_folder_id": body.folder_id},
            )
        )
    elif body.original_name:
        event_bus.emit(
            SecurityEvent(
                event_type="file.rename",
                severity="info",
                outcome="success",
                actor=EventActor(user_id=user.id, username=user.username, ip=ip),
                target=EventTarget(type="file", id=file_id, name=body.original_name),
                detail={"old_name": row["original_name"]},
            )
        )

    result = {"message": "File updated"}
    if removed_chars:
        result["removed_chars"] = removed_chars
    return result


@router.delete("/{file_id}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def delete_file(
    file_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete a file.

    When trash is enabled the file is soft-deleted (moved to trash). Otherwise
    the row and blob are permanently removed immediately.
    DB mutations are atomic; blob removal is non-blocking and best-effort.
    """
    from app.schemas.security_event import EventActor, EventTarget, SecurityEvent

    file_id = validate_uuid(file_id)

    cursor = await db.execute(
        "SELECT id, storage_key, owner_id, folder_id, encrypted_size, original_name FROM files "
        "WHERE id = ? AND deleted_at IS NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_FILE_NOT_FOUND)

    await _require_file_write_access(db, row, user)

    ip = _get_client_ip(request)
    # Check whether trash is enabled.
    trash_enabled = (await get_admin_setting(db, "trash_enabled", default="true")) == "true"

    if trash_enabled:
        await db.execute(
            "UPDATE files SET deleted_at = NOW(), deleted_by = ? WHERE id = ?",
            (user.id, file_id),
        )
        await db.commit()
        sse_broker.publish(
            row["folder_id"] or f"root:{row['owner_id']}",
            {"type": "file.removed", "file_id": file_id, "folder_id": row["folder_id"]},
        )
        event_bus.emit(
            SecurityEvent(
                event_type="file.delete",
                severity="warning",
                outcome="success",
                actor=EventActor(user_id=user.id, username=user.username, ip=ip),
                target=EventTarget(type="file", id=file_id, name=row["original_name"]),
                detail={"trash": True},
            )
        )
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

    sse_broker.publish(
        row["folder_id"] or f"root:{row['owner_id']}",
        {"type": "file.removed", "file_id": file_id, "folder_id": row["folder_id"]},
    )

    # Blob ref-count: only delete the blob when no other files row shares storage_key
    cursor = await db.execute("SELECT COUNT(*) AS cnt FROM files WHERE storage_key = ?", (storage_key,))
    cnt_row = await cursor.fetchone()
    blob_is_last_ref = cnt_row is None or cnt_row["cnt"] == 0

    if blob_is_last_ref:

        async def _bg_delete(fid: str, key: str) -> None:
            try:
                async with db_session() as _db:
                    await storage.get_manager().delete_blob(_db, fid, key)
            except Exception:
                pass

        _t = asyncio.create_task(_bg_delete(file_id, storage_key))
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)

    event_bus.emit(
        SecurityEvent(
            event_type="file.delete",
            severity="warning",
            outcome="success",
            actor=EventActor(user_id=user.id, username=user.username, ip=ip),
            target=EventTarget(type="file", id=file_id, name=row["original_name"]),
            detail={"trash": False},
        )
    )
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
                (id, file_id, user_id, actor_username, actor_auth_method, share_id,
                 ip_address, user_agent, action)
            VALUES (?, ?, ?, ?, ?, NULL, ?, ?, 'download')
            """,
            (log_id, file_id, user.id, user.username, user.auth_method, ip, ua),
        )
        await db.commit()
    except Exception:
        logger.warning(
            "Failed to write access log for file %s", file_id
        )  # NOSONAR — server-side audit log; values are Pydantic-validated


@router.get(
    "/{file_id}/content",
    responses={
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
        422: {"description": "Unprocessable Entity"},
        423: {"description": "423"},
        503: {"description": "503"},
    },
)
async def get_file_content(
    file_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
        raise HTTPException(status_code=404, detail=_ERR_FILE_NOT_FOUND)

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
        logger.error(
            "Blob missing for file %s (storage_key=%s)", file_id, storage_key
        )  # NOSONAR — server-side audit log; values are Pydantic-validated
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

    # --- Bandwidth enforcement (checked before streaming begins) ---
    await check_bandwidth(db, user.id, content_length, user.bandwidth_limit)

    # --- Access log + last_accessed_at update (on first chunk request) ---
    if not range_header or start == 0:
        await _log_download(db, request, user, file_id)
        _t = asyncio.create_task(_update_last_accessed(file_id))
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)

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


@router.get("/{file_id}/chunks", responses={404: {"description": "Not Found"}})
async def get_file_chunks(
    file_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
):
    """Return chunk manifest for client-side decryption.

    Paginated: use offset/limit for files with many chunks.
    """
    file_id = validate_uuid(file_id)

    cursor = await db.execute(_SQL_FILE_BY_ID, (file_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_FILE_NOT_FOUND)

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
        "size_bytes": row["size_bytes"],  # plaintext file size for integrity check
        "encrypted_file_key": row["encrypted_file_key"] if is_owner else None,
        "key_iv": row["key_iv"] if is_owner else None,
        "chunk_size": row["chunk_size"],
        "total_chunks": row["total_chunks"],
        "chunks": chunks,
        "offset": offset,
        "limit": limit,
    }
