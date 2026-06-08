"""Folder management routes."""

import asyncio
import re as _re_folders
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import Database, DuplicateError, get_db
from app.middleware.rate_limit import check_management_write_rate_limit
from app.models.file import File, Folder
from app.routes._access import (
    _team_level_for_user,
    check_data_permission,
    copy_folder_permissions,
    get_folder_team_id,
    get_restricted_subtree_info,
    is_in_shared_tree,
)
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import event_bus, sse_broker
from app.services.escrow import resolve_effective_escrow_agents
from app.util.db import get_admin_setting
from app.validation.sanitizers import sanitize_folder_name, validate_uuid

_SQL_FOLDER_BY_ID = "SELECT * FROM folders WHERE id = ?"
_ERR_FOLDER_NOT_FOUND = "Folder not found"
_ERR_ACCESS_DENIED = "Access denied"


async def _check_parent_write_access(db, parent: dict, user: AuthenticatedUser, parent_id: str) -> None:
    if parent["owner_id"] == user.id or user.is_admin:
        return
    if not await is_in_shared_tree(db, parent_id):
        if not await check_data_permission(db, "folder", parent_id, user.id, "write"):
            raise HTTPException(status_code=403, detail="No write access to parent folder")


# Permission levels that imply manage_permissions capability
_MANAGE_LEVELS = ("admin", "manage_permissions")


async def _annotate_can_manage(db, user_id: str, is_admin: bool, folder_dicts: list[dict]) -> None:
    """Annotate each dict in folder_dicts with user_can_manage: bool (in-place).

    True when any of:
      - caller is an org admin
      - the folder is owned by the caller (owner_id match)
      - caller has an explicit ACL grant at admin/manage_permissions level
      - caller has team_admin or team_manager scope-role for the team owning this folder
        (team owner bypass, covers manage_all authority)
      - caller has team_folder_manage_all via a custom team role assignment
    """
    if is_admin:
        for fd in folder_dicts:
            fd["user_can_manage"] = True
        return

    can_manage: set[str] = {fd["id"] for fd in folder_dicts if fd["owner_id"] == user_id}
    non_owned = [fd["id"] for fd in folder_dicts if fd["id"] not in can_manage]

    if non_owned:
        # --- Explicit ACL grants ---
        placeholders = ",".join("?" * len(non_owned))
        level_placeholders = ",".join("?" * len(_MANAGE_LEVELS))
        cursor = await db.execute(
            f"SELECT DISTINCT resource_id FROM permissions "
            f"WHERE resource_type = 'folder' AND user_id = ? "
            f"AND resource_id IN ({placeholders}) "
            f"AND permission IN ({level_placeholders})",
            (user_id, *non_owned, *_MANAGE_LEVELS),
        )
        for row in await cursor.fetchall():
            can_manage.add(row["resource_id"])

        # --- Team-based manage authority (team owner bypass + manage_all flag) ---
        still_not_managed = [fid for fid in non_owned if fid not in can_manage]
        if still_not_managed:
            from app.models.team_role import TEAM_FLAG_MANAGE_FOLDER_ALL, get_user_team_manage_flags

            ph = ",".join("?" * len(still_not_managed))
            cursor = await db.execute(
                f"SELECT f.id AS folder_id, tf.team_id "
                f"FROM folders f "
                f"JOIN team_folders tf ON tf.folder_id = f.root_folder_id "
                f"WHERE f.id IN ({ph})",
                (*still_not_managed,),
            )
            folder_to_team: dict[str, str] = {}
            for r in await cursor.fetchall():
                folder_to_team[r["folder_id"]] = r["team_id"]

            # Cache per-team result to avoid re-querying the same team multiple times.
            team_manage_all: dict[str, bool] = {}
            for team_id in set(folder_to_team.values()):
                flags = await get_user_team_manage_flags(db, user_id, team_id)
                team_manage_all[team_id] = flags[TEAM_FLAG_MANAGE_FOLDER_ALL]

            for folder_id, team_id in folder_to_team.items():
                if team_manage_all.get(team_id, False):
                    can_manage.add(folder_id)

    for fd in folder_dicts:
        fd["user_can_manage"] = fd["id"] in can_manage


router = APIRouter(dependencies=[Depends(check_management_write_rate_limit)])


_NAME_IDX_RE_FOLDERS = _re_folders.compile(r'^[0-9a-f]{64}$')


def _validate_name_ct_pair(name_ct: str | None, name_idx: str | None) -> None:
    """Raise ValueError if name_ct is provided without a valid name_idx."""
    if name_ct is not None:
        from app.validation.sanitizers import validate_base64
        validate_base64(name_ct)
        if name_idx is None or not _NAME_IDX_RE_FOLDERS.match(name_idx):
            raise ValueError("name_idx must be a 64-char hex string when name_ct is provided")


class CreateFolderRequest(BaseModel):
    name: str
    parent_id: str | None = None
    name_ct: str | None = None
    name_idx: str | None = None
    folder_key_ct: str | None = None
    folder_key_iv: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return sanitize_folder_name(v)

    @field_validator("parent_id")
    @classmethod
    def validate_parent_id(cls, v: str | None) -> str | None:
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

    @field_validator("folder_key_ct", "folder_key_iv")
    @classmethod
    def validate_folder_key_fields(cls, v: str | None) -> str | None:
        if v is not None:
            from app.validation.sanitizers import validate_base64
            return validate_base64(v)
        return v

    @field_validator("name_idx")
    @classmethod
    def validate_name_idx(cls, v: str | None) -> str | None:
        if v is not None and not _NAME_IDX_RE_FOLDERS.match(v):
            raise ValueError("name_idx must be a 64-char hex string")
        return v


class UpdateFolderRequest(BaseModel):
    name: str | None = None
    parent_id: str | None = None
    move_to_root: bool = False
    restrict_permissions: bool | None = None
    name_ct: str | None = None
    name_idx: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            return sanitize_folder_name(v)
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
        if v is not None and not _NAME_IDX_RE_FOLDERS.match(v):
            raise ValueError("name_idx must be a 64-char hex string")
        return v


@router.get("")
async def list_root_folders(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """List user's root-level folders, root-level files, and the shared folder."""
    # User's own root folders (no parent), excluding team-owned folders and deleted folders
    cursor = await db.execute(
        "SELECT f.* FROM folders f "
        "LEFT JOIN team_folders tf ON tf.folder_id = f.id "
        "WHERE f.owner_id = ? AND f.parent_id IS NULL AND f.is_shared = 0 "
        "  AND tf.folder_id IS NULL AND f.deleted_at IS NULL "
        "ORDER BY f.name",
        (user.id,),
    )
    own_folders = [Folder.from_row(r).to_dict() for r in await cursor.fetchall()]
    for fd in own_folders:
        fd["user_can_manage"] = True

    # User's root-level files (no folder), excluding deleted files
    cursor = await db.execute(
        "SELECT * FROM files WHERE owner_id = ? AND folder_id IS NULL AND upload_complete = 1 "
        "AND deleted_at IS NULL ORDER BY original_name",
        (user.id,),
    )
    own_files = [File.from_row(r).to_dict() for r in await cursor.fetchall()]

    # Shared folder
    cursor = await db.execute("SELECT * FROM folders WHERE is_shared = 1 AND parent_id IS NULL")
    shared_row = await cursor.fetchone()
    shared_folder = Folder.from_row(shared_row).to_dict() if shared_row else None

    # Incomplete uploads at the root level for this user
    cursor = await db.execute(
        """
        SELECT tu.id AS upload_id, f.id AS file_id, f.original_name, f.size_bytes,
               f.encrypted_file_key, f.key_iv,
               tu.current_offset, tu.total_size, tu.expires_at
          FROM tus_uploads tu
          JOIN files f ON tu.file_id = f.id
         WHERE tu.user_id = ? AND f.folder_id IS NULL
         ORDER BY f.original_name
        """,
        (user.id,),
    )
    pending_uploads = [dict(r) for r in await cursor.fetchall()]

    return {
        "folders": own_folders,
        "files": own_files,
        "shared_folder": shared_folder,
        "pending_uploads": pending_uploads,
    }


@router.post(
    "",
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}},
)
async def create_folder(
    body: CreateFolderRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create a new folder."""
    folder_id = str(uuid.uuid4())

    # If parent_id is specified, verify it exists and user has write access
    root_folder_id = folder_id  # default: this folder is its own root
    if body.parent_id:
        cursor = await db.execute(_SQL_FOLDER_BY_ID, (body.parent_id,))
        parent = await cursor.fetchone()
        if parent is None:
            raise HTTPException(status_code=404, detail="Parent folder not found")
        await _check_parent_write_access(db, parent, user, body.parent_id)
        root_folder_id = parent["root_folder_id"] or body.parent_id

    if body.name_ct is not None and body.name_idx is None:
        raise HTTPException(status_code=400, detail="name_idx required when name_ct is provided")

    if body.folder_key_ct is not None and body.folder_key_iv is None:
        raise HTTPException(status_code=400, detail="folder_key_iv required when folder_key_ct is provided")

    try:
        await db.execute(
            "INSERT INTO folders "
            "    (id, name, parent_id, owner_id, root_folder_id, name_ct, name_idx, folder_key_ct, folder_key_iv) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (folder_id, body.name, body.parent_id, user.id, root_folder_id,
             body.name_ct, body.name_idx, body.folder_key_ct, body.folder_key_iv),
        )
        # Inherit recursive permissions from the parent folder (personal root = no-inherit)
        if body.parent_id:
            await copy_folder_permissions(db, body.parent_id, "folder", folder_id)
        await db.commit()
    except DuplicateError:
        cursor = await db.execute(
            "SELECT id FROM folders WHERE name = ? AND parent_id IS NOT DISTINCT FROM ? AND owner_id = ? AND deleted_at IS NULL",
            (body.name, body.parent_id, user.id),
        )
        existing = await cursor.fetchone()
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Folder with this name already exists here",
                "existing_folder_id": existing["id"] if existing else None,
            },
        )

    event_bus.emit(
        SecurityEvent(
            event_type="file.folder.created",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=str(user.id), username=user.username),
            detail={"folder_id": folder_id, "name": body.name, "parent_id": body.parent_id},
        )
    )

    # Notify the parent folder (or root) that a new subfolder appeared
    sse_broker.publish(body.parent_id or f"root:{user.id}", {"type": "change"})

    # Record recent activity on the parent folder (best-effort, non-blocking)
    if body.parent_id:
        from app.database import db_session
        from app.routes.auth import record_folder_activity

        async def _record() -> None:
            try:
                async with db_session() as _db:
                    _cur = await _db.execute(
                        """
                        SELECT f.name, tf.team_id, t.name AS team_name
                        FROM   folders f
                        LEFT   JOIN team_folders tf ON tf.folder_id = f.root_folder_id
                        LEFT   JOIN teams t ON t.id = tf.team_id
                        WHERE  f.id = ?
                        """,
                        (body.parent_id,),
                    )
                    _row = await _cur.fetchone()
                    if _row:
                        await record_folder_activity(
                            _db,
                            str(user.id),
                            body.parent_id,
                            _row["team_id"],
                            _row["name"],
                            _row["team_name"],
                        )
            except Exception:
                pass

        _t = asyncio.create_task(_record())
        _t.add_done_callback(lambda _: None)

    return {"folder": {"id": folder_id, "name": body.name, "parent_id": body.parent_id}}


@router.get("/{folder_id}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def get_folder_contents(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get a folder's contents (child folders and files).

    All three queries run inside a single read transaction for a consistent snapshot.
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    folder = Folder.from_row(folder_row)

    # Access check: owner, admin, public shared tree, or Phase 1 permission chain.
    if folder.owner_id != user.id and not user.is_admin:
        if not await is_in_shared_tree(db, folder_id):
            if not await check_data_permission(db, "folder", folder_id, user.id, "read"):
                team_id = await get_folder_team_id(db, folder_id)
                if team_id:
                    cursor = await db.execute(
                        "SELECT 1 FROM user_roles "
                        "WHERE scope_type = 'team' AND scope_id = ? AND user_id = ? "
                        "AND NOT EXISTS ("
                        "  SELECT 1 FROM user_team_keys WHERE team_id = ? AND user_id = ?"
                        ")",
                        (team_id, user.id, team_id, user.id),
                    )
                    if await cursor.fetchone():
                        raise HTTPException(status_code=403, detail="key_pending")
                raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    # Child folders (excluding soft-deleted)
    cursor = await db.execute(
        "SELECT * FROM folders WHERE parent_id = ? AND deleted_at IS NULL ORDER BY name",
        (folder_id,),
    )
    child_folders = [Folder.from_row(r).to_dict() for r in await cursor.fetchall()]
    await _annotate_can_manage(db, user.id, user.is_admin, child_folders)

    # Files in this folder (excluding soft-deleted)
    cursor = await db.execute(
        "SELECT * FROM files WHERE folder_id = ? AND upload_complete = 1 AND deleted_at IS NULL ORDER BY original_name",
        (folder_id,),
    )
    files = [File.from_row(r).to_dict() for r in await cursor.fetchall()]

    # Incomplete uploads in this folder for the current user
    cursor = await db.execute(
        """
        SELECT tu.id AS upload_id, f.id AS file_id, f.original_name, f.size_bytes,
               f.encrypted_file_key, f.key_iv,
               tu.current_offset, tu.total_size, tu.expires_at
          FROM tus_uploads tu
          JOIN files f ON tu.file_id = f.id
         WHERE tu.user_id = ? AND f.folder_id = ?
         ORDER BY f.original_name
        """,
        (user.id, folder_id),
    )
    pending_uploads = [dict(r) for r in await cursor.fetchall()]

    # Build breadcrumb ancestry (walk up parent_id chain)
    # visited_bc guards against any existing parent_id cycles in the DB
    breadcrumbs = []
    current = folder
    visited_bc: set[str] = {folder.id}
    while current.parent_id and current.parent_id not in visited_bc:
        visited_bc.add(current.parent_id)
        cursor = await db.execute(_SQL_FOLDER_BY_ID, (current.parent_id,))
        parent_row = await cursor.fetchone()
        if not parent_row:
            break
        parent = Folder.from_row(parent_row)
        breadcrumbs.insert(0, {"id": parent.id, "name": parent.name})
        current = parent

    team_id = await get_folder_team_id(db, folder_id)

    return {
        "folder": folder.to_dict(),
        "child_folders": child_folders,
        "files": files,
        "pending_uploads": pending_uploads,
        "breadcrumbs": breadcrumbs,
        "team_id": team_id,
    }


async def _list_team_folder_files(
    db, folder_id: str, team_id: str, user_id: str, limit: int, offset: int
) -> tuple[list, int]:
    _cte = """
        WITH RECURSIVE folder_tree(id) AS (
            SELECT ? AS id
            UNION ALL
            SELECT f.id
              FROM folders f
              JOIN folder_tree ft ON f.parent_id = ft.id
             WHERE f.deleted_at IS NULL
        )
    """
    count_cursor = await db.execute(
        _cte
        + """
        SELECT COUNT(*) AS total
          FROM files fi
          JOIN folder_tree ft ON fi.folder_id = ft.id
         WHERE fi.upload_complete = 1
           AND fi.deleted_at IS NULL
        """,
        (folder_id,),
    )
    count_row = await count_cursor.fetchone()
    total = count_row["total"] if count_row else 0

    cursor = await db.execute(
        _cte
        + """
        SELECT fi.id, fi.original_name, fi.name_ct, fi.size_bytes, fi.owner_id, fi.folder_id,
               fi.encrypted_file_key, fi.key_iv,
               ftk.pre_c1, ftk.encrypted_file_key AS team_encrypted_file_key,
               ftk.key_iv AS team_key_iv,
               fold.name AS folder_name
          FROM files fi
          JOIN folder_tree ft ON fi.folder_id = ft.id
          LEFT JOIN file_team_keys ftk ON ftk.file_id = fi.id AND ftk.team_id = ?
          LEFT JOIN folders fold ON fold.id = fi.folder_id
         WHERE fi.upload_complete = 1
           AND fi.deleted_at IS NULL
         ORDER BY fi.original_name
         LIMIT ? OFFSET ?
        """,
        (folder_id, team_id, limit, offset),
    )
    rows = await cursor.fetchall()
    files = [
        {
            "id": r["id"],
            "original_name": r["original_name"],
            "name_ct": r["name_ct"],
            "size_bytes": r["size_bytes"],
            "folder_id": r["folder_id"],
            "folder_name": r["folder_name"],
            "encrypted_file_key": r["encrypted_file_key"] if r["owner_id"] == user_id else None,
            "key_iv": r["key_iv"] if r["owner_id"] == user_id else None,
            "pre_c1": r["pre_c1"],
            "team_encrypted_file_key": r["team_encrypted_file_key"],
            "team_key_iv": r["team_key_iv"],
        }
        for r in rows
    ]
    return files, total


async def _list_personal_folder_files(db, folder_id: str, user_id: str, limit: int, offset: int) -> tuple[list, int]:
    _cte = """
        WITH RECURSIVE folder_tree(id) AS (
            SELECT ? AS id
            UNION ALL
            SELECT f.id
              FROM folders f
              JOIN folder_tree ft ON f.parent_id = ft.id
             WHERE f.owner_id = ?
        )
    """
    count_cursor = await db.execute(
        _cte
        + """
        SELECT COUNT(*) AS total
          FROM files fi
          JOIN folder_tree ft ON fi.folder_id = ft.id
         WHERE fi.upload_complete = 1
           AND fi.owner_id = ?
        """,
        (folder_id, user_id, user_id),
    )
    count_row = await count_cursor.fetchone()
    total = count_row["total"] if count_row else 0

    cursor = await db.execute(
        _cte
        + """
        SELECT fi.id, fi.original_name, fi.size_bytes,
               fi.encrypted_file_key, fi.key_iv
          FROM files fi
          JOIN folder_tree ft ON fi.folder_id = ft.id
         WHERE fi.upload_complete = 1
           AND fi.owner_id = ?
         ORDER BY fi.original_name
         LIMIT ? OFFSET ?
        """,
        (folder_id, user_id, user_id, limit, offset),
    )
    rows = await cursor.fetchall()
    files = [
        {
            "id": r["id"],
            "original_name": r["original_name"],
            "size_bytes": r["size_bytes"],
            "encrypted_file_key": r["encrypted_file_key"],
            "key_iv": r["key_iv"],
        }
        for r in rows
    ]
    return files, total


@router.get("/{folder_id}/files", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def list_folder_files_recursive(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Return a paginated flat list of all complete files within a folder tree (recursive).

    Uses a recursive CTE to walk the folder hierarchy.  Only files owned by the
    requesting user are included — shared-tree folders are excluded to prevent
    accidentally exposing other users' file keys.

    Returns: { files: [...], total: <int>, offset: <int>, limit: <int> }
    `total` is the full count across all pages; use with offset/limit for pagination.
    Caller is responsible for re-wrapping each file's key before sharing.
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT owner_id FROM folders WHERE id = ?", (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    team_id = await get_folder_team_id(db, folder_id)
    if folder_row["owner_id"] != user.id and not user.is_admin:
        level = await _team_level_for_user(db, team_id, user.id) if team_id else None
        if level not in ("admin", "write"):
            raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    if team_id:
        files, total = await _list_team_folder_files(db, folder_id, team_id, user.id, limit, offset)
    else:
        files, total = await _list_personal_folder_files(db, folder_id, user.id, limit, offset)

    return {"files": files, "total": total, "offset": offset, "limit": limit}


@router.get(
    "/{folder_id}/all-subfolders",
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}},
)
async def list_all_subfolders(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return all folders in the subtree rooted at folder_id (root included), with crypto fields.

    Used by the frontend share-creation flow to enumerate folder keys when building a
    folder-key share: one share_item per folder, rather than one per file.

    Returns { folders: [{ id, folder_key_ct, folder_key_iv }] }
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT owner_id FROM folders WHERE id = ?", (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    if folder_row["owner_id"] != user.id and not user.is_admin:
        team_id = await get_folder_team_id(db, folder_id)
        level = await _team_level_for_user(db, team_id, user.id) if team_id else None
        if level not in ("admin", "write"):
            raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    cursor = await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id, folder_key_ct, folder_key_iv
            FROM folders WHERE id = ? AND deleted_at IS NULL
            UNION ALL
            SELECT f.id, f.folder_key_ct, f.folder_key_iv
            FROM folders f JOIN subtree s ON f.parent_id = s.id
            WHERE f.deleted_at IS NULL
        )
        SELECT id, folder_key_ct, folder_key_iv FROM subtree
        """,
        (folder_id,),
    )
    rows = await cursor.fetchall()
    return {
        "folders": [
            {"id": r["id"], "folder_key_ct": r["folder_key_ct"], "folder_key_iv": r["folder_key_iv"]}
            for r in rows
        ]
    }


async def _check_no_ancestor_cycle(db, folder_id: str, new_parent_id: str) -> None:
    """Raise 400 if new_parent_id is a descendant of folder_id."""
    visited: set[str] = set()
    current: str | None = new_parent_id
    while current and current not in visited:
        if current == folder_id:
            raise HTTPException(
                status_code=400,
                detail="Cannot move a folder into itself or one of its descendants",
            )
        visited.add(current)
        anc_cursor = await db.execute("SELECT parent_id FROM folders WHERE id = ?", (current,))
        anc_row = await anc_cursor.fetchone()
        current = anc_row["parent_id"] if anc_row else None


async def _build_folder_update_params(db, folder_id: str, folder_row, body) -> tuple[list, list]:
    """Build (updates, params) for the folder UPDATE statement."""
    updates: list = []
    params: list = []
    if body.name is not None:
        updates.append("name = ?")
        params.append(body.name)
    if body.name_ct is not None:
        if body.name_idx is None:
            raise HTTPException(status_code=400, detail="name_idx required when name_ct is provided")
        updates.append("name_ct = ?")
        params.append(body.name_ct)
        updates.append("name_idx = ?")
        params.append(body.name_idx)
    if body.restrict_permissions is not None:
        updates.append("restrict_permissions = ?")
        params.append(body.restrict_permissions)
    if body.move_to_root:
        if folder_row["parent_id"] is None:
            raise HTTPException(status_code=400, detail="Folder is already at root")
        updates.append("parent_id = ?")
        params.append(None)
    elif body.parent_id is not None:
        pid = validate_uuid(body.parent_id)
        await _check_no_ancestor_cycle(db, folder_id, pid)
        updates.append("parent_id = ?")
        params.append(pid)
    return updates, params


async def _update_root_folder_id_on_move(db, folder_id: str, move_to_root: bool, new_parent_id: str | None) -> None:
    """Cascade root_folder_id to the moved folder and all its descendants."""
    if not move_to_root and new_parent_id is None:
        return
    if move_to_root:
        new_root = folder_id
    else:
        cur = await db.execute("SELECT root_folder_id FROM folders WHERE id = ?", (new_parent_id,))
        row = await cur.fetchone()
        new_root = (row["root_folder_id"] if row else None) or new_parent_id
    await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        UPDATE folders SET root_folder_id = ?
        WHERE id IN (SELECT id FROM subtree)
        """,
        (folder_id, new_root),
    )


async def _update_move_permissions(db, folder_id: str, move_to_root: bool, parent_id: str | None) -> None:
    """Delete stale recursive permissions and copy from new parent after a move."""
    if not move_to_root and parent_id is None:
        return
    new_parent_id = None if move_to_root else parent_id
    await db.execute(
        "DELETE FROM permissions WHERE resource_type = 'folder' AND resource_id = ? AND recursive = 1",
        (folder_id,),
    )
    # Any policy_folder_grants whose recursive ACL row was just stripped are now stale.
    # Mark acl_written=0 so re-evaluation knows to re-insert the permissions row.
    await db.execute(
        "UPDATE policy_folder_grants SET acl_written = 0 "
        "WHERE folder_id = ? AND acl_written = 1 "
        "  AND effect_id IN (SELECT id FROM policy_effects WHERE recursive = 1)",
        (folder_id,),
    )
    if new_parent_id:
        await copy_folder_permissions(db, new_parent_id, "folder", folder_id)


def _emit_folder_update_event(user, folder_id: str, folder_row, body, is_move: bool) -> None:
    if is_move:
        new_parent = None if body.move_to_root else body.parent_id
        event_bus.emit(
            SecurityEvent(
                event_type="file.folder.moved",
                severity="info",
                outcome="success",
                actor=EventActor(user_id=str(user.id), username=user.username),
                detail={"folder_id": folder_id, "old_parent_id": folder_row["parent_id"], "new_parent_id": new_parent},
            )
        )
    elif body.name is not None:
        event_bus.emit(
            SecurityEvent(
                event_type="file.folder.renamed",
                severity="info",
                outcome="success",
                actor=EventActor(user_id=str(user.id), username=user.username),
                detail={"folder_id": folder_id, "old_name": folder_row["name"], "new_name": body.name},
            )
        )


async def _require_folder_write_access(db, folder_id: str, folder_row, user: AuthenticatedUser) -> None:
    """Raise 403 if user is not the folder owner, not an admin, and not a team write+ member."""
    if folder_row["owner_id"] == user.id or user.is_admin:
        return
    team_id = await get_folder_team_id(db, folder_id)
    level = await _team_level_for_user(db, team_id, user.id) if team_id else None
    if level not in ("admin", "write"):
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)


@router.put(
    "/{folder_id}",
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
async def update_folder(
    folder_id: str,
    body: UpdateFolderRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Rename or move a folder."""
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute(_SQL_FOLDER_BY_ID, (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_write_access(db, folder_id, folder_row, user)

    if folder_row["is_shared"]:
        raise HTTPException(status_code=400, detail="Cannot modify the shared folder")

    if body.move_to_root and body.parent_id is not None:
        raise HTTPException(status_code=400, detail="Cannot specify both parent_id and move_to_root")

    # Restricted-folder guards — only when changing structure or name.
    # _is_rename is keyed solely on body.name being present; other fields in the
    # same request (e.g. restrict_permissions) do not suppress this guard, which
    # would otherwise allow a guard-bypass via a compound request.
    _is_move = body.move_to_root or (
        body.parent_id is not None and body.parent_id != folder_row["parent_id"]
    )
    _is_rename = body.name is not None and not _is_move

    if _is_move:
        _restricted = await get_restricted_subtree_info(db, folder_id, user.id, user.is_admin)
        _blocking = [e for e in _restricted if not e["has_manage_access"]]
        if _blocking:
            raise _restricted_folder_error(_blocking[0])
    elif _is_rename and folder_row["restrict_permissions"]:
        if not user.is_admin and folder_row["owner_id"] != user.id:
            if not await check_data_permission(db, "folder", folder_id, user.id, "manage_permissions"):
                raise _restricted_folder_error({"name": folder_row["name"], "path": folder_row["name"]})

    if body.restrict_permissions is not None:
        await _require_folder_manage_access(db, folder_id, folder_row, user)

    updates, params = await _build_folder_update_params(db, folder_id, folder_row, body)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = NOW()")
    params.append(folder_id)

    await db.execute(
        f"UPDATE folders SET {', '.join(updates)} WHERE id = ?",
        params,
    )

    # On a parent change, replace inherited permissions and cascade root_folder_id.
    await _update_move_permissions(db, folder_id, body.move_to_root, body.parent_id)
    await _update_root_folder_id_on_move(db, folder_id, body.move_to_root, body.parent_id)

    await db.commit()

    old_parent = folder_row["parent_id"]
    is_move = body.move_to_root or (body.parent_id is not None and body.parent_id != old_parent)
    _emit_folder_update_event(user, folder_id, folder_row, body, is_move)

    # Notify old parent (rename) and new parent (move) if different
    old_parent = folder_row["parent_id"]
    sse_broker.publish(old_parent or f"root:{folder_row['owner_id']}", {"type": "change"})
    if body.parent_id and body.parent_id != old_parent:
        sse_broker.publish(body.parent_id, {"type": "change"})

    cursor = await db.execute(_SQL_FOLDER_BY_ID, (folder_id,))
    updated_row = await cursor.fetchone()
    return {"folder": Folder.from_row(updated_row).to_dict()}


@router.delete(
    "/{folder_id}",
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
async def delete_folder(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete a folder and all its contents.

    When trash is enabled the folder and entire subtree are soft-deleted.
    Otherwise the row is hard-deleted immediately (cascade removes descendants;
    blob cleanup is deferred to a future background pass).
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_write_access(db, folder_id, folder_row, user)

    if folder_row["is_shared"]:
        raise HTTPException(status_code=400, detail="Cannot delete the shared folder")

    _restricted = await get_restricted_subtree_info(db, folder_id, user.id, user.is_admin)
    _blocking = [e for e in _restricted if not e["has_manage_access"]]
    if _blocking:
        raise _restricted_folder_error(_blocking[0])

    trash_enabled = (await get_admin_setting(db, "trash_enabled", default="true")) == "true"

    # Count subtree size for audit detail (folders + files in the subtree)
    subtree_count_cursor = await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        SELECT
            (SELECT COUNT(*) FROM subtree) AS folder_count,
            (SELECT COUNT(*) FROM files WHERE folder_id IN (SELECT id FROM subtree)
             AND deleted_at IS NULL AND upload_complete = 1) AS file_count
        """,
        (folder_id,),
    )
    subtree_row = await subtree_count_cursor.fetchone()
    subtree_folder_count = subtree_row["folder_count"] if subtree_row else 1
    subtree_file_count = subtree_row["file_count"] if subtree_row else 0

    if trash_enabled:
        await db.execute("BEGIN")
        try:
            # Mark the entire subtree deleted.
            await db.execute(
                """
                WITH RECURSIVE subtree AS (
                    SELECT id FROM folders WHERE id = ?
                    UNION ALL
                    SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
                )
                UPDATE folders
                   SET deleted_at = NOW(), deleted_by = ?
                 WHERE id IN (SELECT id FROM subtree)
                """,
                (folder_id, user.id),
            )
            await db.execute(
                """
                WITH RECURSIVE subtree AS (
                    SELECT id FROM folders WHERE id = ?
                    UNION ALL
                    SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
                )
                UPDATE files
                   SET deleted_at = NOW(), deleted_by = ?
                 WHERE folder_id IN (SELECT id FROM subtree)
                """,
                (folder_id, user.id),
            )
            # Escrow policies are not cascade-deleted on soft-delete, so remove them explicitly.
            await db.execute(
                """
                WITH RECURSIVE subtree AS (
                    SELECT id FROM folders WHERE id = ?
                    UNION ALL
                    SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
                )
                DELETE FROM folder_escrow_policies
                 WHERE folder_id IN (SELECT id FROM subtree)
                """,
                (folder_id,),
            )
            await db.commit()
        except Exception:
            await db.rollback()
            raise

        event_bus.emit(
            SecurityEvent(
                event_type="file.folder.deleted",
                severity="warning",
                outcome="success",
                actor=EventActor(user_id=str(user.id), username=user.username),
                detail={
                    "folder_id": folder_id,
                    "name": folder_row["name"],
                    "soft_delete": True,
                    "subtree_folders": subtree_folder_count,
                    "subtree_files": subtree_file_count,
                },
            )
        )
        sse_broker.publish(
            folder_row["parent_id"] or f"root:{folder_row['owner_id']}",
            {"type": "change"},
        )
        return {"message": "Folder moved to trash"}

    # Trash disabled — hard delete immediately (blob cleanup deferred).
    await db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type="file.folder.deleted",
            severity="warning",
            outcome="success",
            actor=EventActor(user_id=str(user.id), username=user.username),
            detail={
                "folder_id": folder_id,
                "name": folder_row["name"],
                "soft_delete": False,
                "subtree_folders": subtree_folder_count,
                "subtree_files": subtree_file_count,
            },
        )
    )
    sse_broker.publish(
        folder_row["parent_id"] or f"root:{folder_row['owner_id']}",
        {"type": "change"},
    )
    return {"message": "Folder deleted"}


@router.get(
    "/{folder_id}/effective-escrow-agents",
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}},
)
async def get_effective_escrow_agents(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return the resolved escrow agent list for the given folder.

    Used by the team-creation flow: the client calls this before POST /teams
    to know which agents to wrap sk_team for.  The result reflects the closest
    folder-level policy override (replace/merge/none) or the org default when
    no override exists.

    Does not require escrow_manage — any user with a user role can call
    this so that team creation works without an admin account.
    """
    folder_id = validate_uuid(folder_id)

    # Verify the folder exists and the caller has access to it
    cursor = await db.execute("SELECT id, owner_id FROM folders WHERE id = ?", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    has_access = (
        folder_row["owner_id"] == user.id
        or user.is_admin
        or await check_data_permission(db, "folder", folder_id, user.id, "read")
    )
    if not has_access:
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    return await resolve_effective_escrow_agents(db, folder_id)


# ---------------------------------------------------------------------------
# Folder stats
# ---------------------------------------------------------------------------

@router.get("/{folder_id}/stats", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def get_folder_stats(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return aggregate stats for a folder: file count, total size, dates, owner username."""
    folder_id = validate_uuid(folder_id)
    cursor = await db.execute(
        "SELECT f.*, u.username AS owner_username FROM folders f "
        "JOIN users u ON u.id = f.owner_id "
        "WHERE f.id = ? AND f.deleted_at IS NULL",
        (folder_id,),
    )
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    if folder_row["owner_id"] != user.id and not user.is_admin:
        if not await is_in_shared_tree(db, folder_id):
            if not await check_data_permission(db, "folder", folder_id, user.id, "read"):
                raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    stats_cursor = await db.execute(
        "SELECT COUNT(*) AS file_count, COALESCE(SUM(size_bytes), 0) AS total_size_bytes "
        "FROM files WHERE folder_id = ? AND deleted_at IS NULL AND upload_complete = 1",
        (folder_id,),
    )
    stats_row = await stats_cursor.fetchone()

    # --- caller_context: drives permission-ceiling enforcement in the UI ---
    # Mapping: folder-level atomic flag → team-level flag that must be on for the
    # caller to be permitted to grant it to others.
    _FOLDER_TEAM_CEILING: dict[str, str] = {
        "move_own_within_folder": "move_own_within_team",
        "move_all_within_folder": "move_all_within_team",
        "move_own_out_of_folder": "move_own_files_out_of_team",
        "move_all_out_of_folder": "move_others_files_out_of_team",
        "folder_create":          "folder_create",
        "manage_own_subfolders":  "team_folder_manage_own",
        "manage_all_subfolders":  "team_folder_manage_all",
        "share_create":           "share_create",
        "share_manage_own":       "share_manage_own",
        "share_manage_all":       "share_manage_all",
    }
    _BASE_FLAGS = [
        "view_contents", "download_files", "upload_files",
        "delete_files", "manage_this_folder",
    ]

    caller_context: dict = {"is_team_owner": False, "allowed_flags": None, "has_org_access": False}

    # Find the team for this folder (if any) via its root_folder_id.
    tf_cursor = await db.execute(
        "SELECT tf.team_id FROM team_folders tf "
        "WHERE tf.folder_id = COALESCE("
        "    (SELECT root_folder_id FROM folders WHERE id = ?), ?)",
        (folder_id, folder_id),
    )
    team_row = await tf_cursor.fetchone()

    if team_row:
        team_id = team_row["team_id"]
        # Is the caller a team owner?
        owner_cursor = await db.execute(
            "SELECT 1 FROM user_roles "
            "WHERE user_id = ? AND scope_type = 'team' AND scope_id = ? AND role_id = 'team_admin'",
            (user.id, team_id),
        )
        is_team_owner = (await owner_cursor.fetchone()) is not None
        caller_context["is_team_owner"] = is_team_owner

        if not user.is_admin and not is_team_owner:
            from app.models.team_role import get_user_all_team_flags
            team_flags = await get_user_all_team_flags(db, user.id, team_id)
            extra = [ff for ff, tf in _FOLDER_TEAM_CEILING.items() if team_flags.get(tf, False)]
            caller_context["allowed_flags"] = [*_BASE_FLAGS, *extra]
        # else: is_admin or is_team_owner → allowed_flags stays None (all allowed)

    # has_org_access: true when accounts outside normal ACL can read this folder's files.
    # Triggers on: (a) any active user with files_access_all_read/write role permission,
    # or (b) active escrow agents who actually hold team key material (policy_effect_id
    # links to a team_escrow policy_effects row).  "can_act_as_escrow" alone on a role
    # does NOT trigger — the agent must have been provisioned with real keys.
    file_bypass_cursor = await db.execute(
        "SELECT 1 FROM users u "
        "JOIN user_roles ur ON ur.user_id = u.id AND ur.scope_type IS NULL "
        "JOIN role_permissions rp ON rp.role_id = ur.role_id "
        "WHERE u.is_active = 1 AND u.id != ? "
        "  AND rp.flag IN ('files_access_all_read', 'files_access_all_write') "
        "  AND rp.value = '1' "
        "LIMIT 1",
        (user.id,),
    )
    has_file_bypass = (await file_bypass_cursor.fetchone()) is not None

    has_active_escrow = False
    if team_row:
        escrow_cursor = await db.execute(
            "SELECT 1 FROM user_team_keys utk "
            "JOIN policy_effects pe ON pe.id = utk.policy_effect_id "
            "WHERE utk.team_id = ? AND pe.effect_type = 'team_escrow' "
            "LIMIT 1",
            (team_row["team_id"],),
        )
        has_active_escrow = (await escrow_cursor.fetchone()) is not None

    caller_context["has_org_access"] = has_file_bypass or has_active_escrow

    return {
        "id":                   folder_id,
        "name":                 folder_row["name"],
        "owner_username":       folder_row["owner_username"],
        "owner_id":             folder_row["owner_id"],
        "created_at":           str(folder_row["created_at"]) if folder_row["created_at"] else None,
        "updated_at":           str(folder_row["updated_at"]) if folder_row["updated_at"] else None,
        "restrict_permissions": bool(folder_row["restrict_permissions"]),
        "file_count":           stats_row["file_count"] if stats_row else 0,
        "total_size_bytes":     stats_row["total_size_bytes"] if stats_row else 0,
        "caller_context":       caller_context,
    }


# ---------------------------------------------------------------------------
# Folder grants — explicit per-user permission grants on a folder
# ---------------------------------------------------------------------------

_ALLOWED_FOLDER_FLAGS: frozenset[str] = frozenset({
    # Legacy single-level values kept for backwards compatibility
    "read", "download", "write", "admin", "manage_permissions",
    # Atomic flags (Read / Write group)
    "view_contents", "download_files", "upload_files", "delete_files", "manage_this_folder",
    # Atomic flags (Move / Copy group)
    "move_own_within_folder", "move_all_within_folder",
    "move_own_out_of_folder", "move_all_out_of_folder",
    # Atomic flags (Folders group)
    "folder_create", "manage_own_subfolders", "manage_all_subfolders",
    # Atomic flags (Shares group)
    "share_create", "share_manage_own", "share_manage_all",
})


def _validate_folder_permission(v: str) -> str:
    flags = {f.strip() for f in v.split(",")}
    unknown = flags - _ALLOWED_FOLDER_FLAGS
    if unknown:
        raise ValueError(f"unknown permission flag(s): {sorted(unknown)}")
    return v


class AddGrantRequest(BaseModel):
    username: str
    permission: str
    recursive: bool = True

    @field_validator("permission")
    @classmethod
    def validate_permission(cls, v: str) -> str:
        return _validate_folder_permission(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("username is required")
        return v


async def _require_folder_manage_access(db, folder_id: str, folder_row, user: AuthenticatedUser) -> None:
    """Raise 403 unless caller may manage this folder.

    Allowed when: org admin, folder owner, explicit manage_permissions ACL grant,
    or team_admin/manager scope-role / team_folder_manage_all custom flag for the
    team that owns this folder.
    """
    if user.is_admin or folder_row["owner_id"] == user.id:
        return
    if await check_data_permission(db, "folder", folder_id, user.id, "manage_permissions"):
        return
    # Team-based authority: find the team for this folder (via root_folder_id).
    cursor = await db.execute(
        "SELECT tf.team_id FROM team_folders tf "
        "WHERE tf.folder_id = COALESCE("
        "    (SELECT root_folder_id FROM folders WHERE id = ?), ?)",
        (folder_id, folder_id),
    )
    team_row = await cursor.fetchone()
    if team_row:
        from app.models.team_role import TEAM_FLAG_MANAGE_FOLDER_ALL, get_user_team_manage_flags
        flags = await get_user_team_manage_flags(db, user.id, team_row["team_id"])
        if flags[TEAM_FLAG_MANAGE_FOLDER_ALL]:
            return
    raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)


def _restricted_folder_error(folder: dict) -> HTTPException:
    """Build the structured 403 used when a restricted-folder manage check fails."""
    return HTTPException(
        status_code=403,
        detail={
            "error":       "restricted_folder_access",
            "message":     f'You do not have access to complete this action on "{folder["name"]}"',
            "folder_name": folder["name"],
            "folder_path": folder["path"],
        },
    )


@router.get(
    "/{folder_id}/subtree-restricted",
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}},
)
async def get_folder_subtree_restricted(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return all restrict_permissions=True folders in the subtree, classified by access.

    Used by the frontend before destructive or structural operations to show
    pre-confirmation modals and determine whether the operation can proceed.
    """
    folder_id = validate_uuid(folder_id)
    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    if not user.is_admin and folder_row["owner_id"] != user.id:
        if not await check_data_permission(db, "folder", folder_id, user.id, "read"):
            raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    entries = await get_restricted_subtree_info(db, folder_id, user.id, user.is_admin)
    return {
        "restricted_folders":  entries,
        "has_blocking_folders": any(not e["has_manage_access"] for e in entries),
    }


@router.get("/{folder_id}/grants", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def list_folder_grants(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """List explicit per-user permission grants for a folder (excludes policy-sourced grants)."""
    folder_id = validate_uuid(folder_id)
    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_manage_access(db, folder_id, folder_row, user)

    grants_cursor = await db.execute(
        "SELECT p.id, p.user_id, u.username, p.permission, p.recursive, p.created_at, "
        "       g.username AS granted_by_username "
        "FROM permissions p "
        "JOIN users u ON u.id = p.user_id "
        "LEFT JOIN users g ON g.id = p.granted_by "
        "WHERE p.resource_type = 'folder' AND p.resource_id = ? AND p.policy_effect_id IS NULL "
        "ORDER BY u.username",
        (folder_id,),
    )
    rows = await grants_cursor.fetchall()
    return {
        "grants": [
            {
                "id":                 r["id"],
                "user_id":            r["user_id"],
                "username":           r["username"],
                "permission":         r["permission"],
                "recursive":          bool(r["recursive"]),
                "created_at":         str(r["created_at"]) if r["created_at"] else None,
                "granted_by_username": r["granted_by_username"],
            }
            for r in rows
        ]
    }


@router.post(
    "/{folder_id}/grants",
    status_code=201,
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 409: {"description": "Already granted"}},
)
async def add_folder_grant(
    folder_id: str,
    body: AddGrantRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Add a per-user permission grant on a folder."""
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_manage_access(db, folder_id, folder_row, user)

    # Resolve target user
    cursor = await db.execute("SELECT id FROM users WHERE username = ? AND is_active = 1", (body.username,))
    target_user = await cursor.fetchone()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found or inactive")

    grant_id = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO permissions (id, resource_type, resource_id, user_id, permission, recursive, granted_by) "
            "VALUES (?, 'folder', ?, ?, ?, ?, ?)",
            (grant_id, folder_id, target_user["id"], body.permission, 1 if body.recursive else 0, user.id),
        )
        await db.commit()
    except DuplicateError:
        raise HTTPException(status_code=409, detail="A grant for this user already exists on this folder")

    return {"id": grant_id, "user_id": target_user["id"], "username": body.username, "permission": body.permission, "recursive": body.recursive}


@router.delete(
    "/{folder_id}/grants/{grant_id}",
    status_code=204,
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}},
)
async def remove_folder_grant(
    folder_id: str,
    grant_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Remove a per-user permission grant from a folder."""
    folder_id = validate_uuid(folder_id)
    grant_id  = validate_uuid(grant_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_manage_access(db, folder_id, folder_row, user)

    cursor = await db.execute(
        "SELECT id FROM permissions WHERE id = ? AND resource_type = 'folder' AND resource_id = ? AND policy_effect_id IS NULL",
        (grant_id, folder_id),
    )
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail="Grant not found")

    await db.execute("DELETE FROM permissions WHERE id = ?", (grant_id,))
    await db.commit()


# ---------------------------------------------------------------------------
# Folder role-grants — role-based (non-user-specific) permission grants
# ---------------------------------------------------------------------------


class AddRoleGrantRequest(BaseModel):
    role_id: str
    permission: str
    recursive: bool = True

    @field_validator("permission")
    @classmethod
    def validate_permission(cls, v: str) -> str:
        return _validate_folder_permission(v)

    @field_validator("role_id")
    @classmethod
    def validate_role_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("role_id is required")
        return v


@router.get(
    "/{folder_id}/role-grants",
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}},
)
async def list_folder_role_grants(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """List role-based permission grants for a folder."""
    folder_id = validate_uuid(folder_id)
    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_manage_access(db, folder_id, folder_row, user)

    cursor = await db.execute(
        "SELECT rrg.id, rrg.role_id, COALESCE(r.name, tr.name) AS role_name, "
        "       rrg.permission, rrg.recursive, rrg.created_at, "
        "       u.username AS granted_by_username "
        "FROM resource_role_grants rrg "
        "LEFT JOIN roles r ON r.id = rrg.role_id "
        "LEFT JOIN team_roles tr ON tr.id = rrg.role_id "
        "LEFT JOIN users u ON u.id = rrg.granted_by "
        "WHERE rrg.resource_type = 'folder' AND rrg.resource_id = ? "
        "ORDER BY COALESCE(r.name, tr.name)",
        (folder_id,),
    )
    rows = await cursor.fetchall()
    return {
        "role_grants": [
            {
                "id":                  r["id"],
                "role_id":             r["role_id"],
                "role_name":           r["role_name"],
                "permission":          r["permission"],
                "recursive":           bool(r["recursive"]),
                "created_at":          str(r["created_at"]) if r["created_at"] else None,
                "granted_by_username": r["granted_by_username"],
            }
            for r in rows
        ]
    }


@router.post(
    "/{folder_id}/role-grants",
    status_code=201,
    responses={
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        409: {"description": "Role already granted"},
    },
)
async def add_folder_role_grant(
    folder_id: str,
    body: AddRoleGrantRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Add a role-based permission grant on a folder."""
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_manage_access(db, folder_id, folder_row, user)

    cursor = await db.execute("SELECT id, name FROM roles WHERE id = ?", (body.role_id,))
    role_row = await cursor.fetchone()
    if not role_row:
        cursor = await db.execute("SELECT id, name FROM team_roles WHERE id = ?", (body.role_id,))
        role_row = await cursor.fetchone()
    if not role_row:
        raise HTTPException(status_code=404, detail="Role not found")

    grant_id = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO resource_role_grants "
            "(id, resource_type, resource_id, role_id, permission, recursive, granted_by) "
            "VALUES (?, 'folder', ?, ?, ?, ?, ?)",
            (grant_id, folder_id, body.role_id, body.permission, 1 if body.recursive else 0, user.id),
        )
        await db.commit()
    except DuplicateError:
        raise HTTPException(status_code=409, detail="A grant for this role already exists on this folder")

    return {
        "id":         grant_id,
        "role_id":    body.role_id,
        "role_name":  role_row["name"],
        "permission": body.permission,
        "recursive":  body.recursive,
    }


@router.delete(
    "/{folder_id}/role-grants/{grant_id}",
    status_code=204,
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}},
)
async def remove_folder_role_grant(
    folder_id: str,
    grant_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Remove a role-based permission grant from a folder."""
    folder_id = validate_uuid(folder_id)
    grant_id  = validate_uuid(grant_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,))
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail=_ERR_FOLDER_NOT_FOUND)

    await _require_folder_manage_access(db, folder_id, folder_row, user)

    cursor = await db.execute(
        "SELECT id FROM resource_role_grants WHERE id = ? AND resource_type = 'folder' AND resource_id = ?",
        (grant_id, folder_id),
    )
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail="Role grant not found")

    await db.execute("DELETE FROM resource_role_grants WHERE id = ?", (grant_id,))
    await db.commit()
