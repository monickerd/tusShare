"""Folder management routes."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator

from app.auth.dependencies import get_current_user, require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.middleware.rate_limit import check_management_rate_limit
from app.models.file import File, Folder
from app.routes._access import copy_folder_permissions, get_folder_team_id, has_folder_permission, is_in_shared_tree, is_team_folder_member
from app.services import sse_broker
from app.services.escrow import resolve_effective_escrow_agents
from app.util.db import get_admin_setting
from app.validation.sanitizers import sanitize_folder_name, validate_uuid

router = APIRouter(dependencies=[Depends(check_management_rate_limit)])


class CreateFolderRequest(BaseModel):
    name: str
    parent_id: str | None = None

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


class UpdateFolderRequest(BaseModel):
    name: str | None = None
    parent_id: str | None = None
    move_to_root: bool = False
    restrict_permissions: bool | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            return sanitize_folder_name(v)
        return v


@router.get("")
async def list_root_folders(
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
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

    # User's root-level files (no folder), excluding deleted files
    cursor = await db.execute(
        "SELECT * FROM files WHERE owner_id = ? AND folder_id IS NULL AND upload_complete = 1 "
        "AND deleted_at IS NULL ORDER BY original_name",
        (user.id,),
    )
    own_files = [File.from_row(r).to_dict() for r in await cursor.fetchall()]

    # Shared folder
    cursor = await db.execute(
        "SELECT * FROM folders WHERE is_shared = 1 AND parent_id IS NULL"
    )
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

    return {"folders": own_folders, "files": own_files, "shared_folder": shared_folder, "pending_uploads": pending_uploads}


@router.post("")
async def create_folder(
    body: CreateFolderRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Create a new folder."""
    folder_id = str(uuid.uuid4())

    # If parent_id is specified, verify it exists and user has write access
    if body.parent_id:
        cursor = await db.execute(
            "SELECT * FROM folders WHERE id = ?", (body.parent_id,)
        )
        parent = await cursor.fetchone()
        if parent is None:
            raise HTTPException(status_code=404, detail="Parent folder not found")
        # Check ownership or shared folder tree access
        if parent["owner_id"] != user.id and not user.is_admin:
            if not await is_in_shared_tree(db, body.parent_id):
                raise HTTPException(status_code=403, detail="No write access to parent folder")

    try:
        await db.execute(
            "INSERT INTO folders (id, name, parent_id, owner_id) VALUES (?, ?, ?, ?)",
            (folder_id, body.name, body.parent_id, user.id),
        )
        # Inherit recursive permissions from the parent folder (personal root = no-inherit)
        if body.parent_id:
            await copy_folder_permissions(db, body.parent_id, "folder", folder_id)
        await db.commit()
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(status_code=409, detail="Folder with this name already exists here")
        raise

    # Notify the parent folder (or root) that a new subfolder appeared
    sse_broker.publish(body.parent_id or f"root:{user.id}", {"type": "change"})

    return {"folder": {"id": folder_id, "name": body.name, "parent_id": body.parent_id}}


@router.get("/{folder_id}")
async def get_folder_contents(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Get a folder's contents (child folders and files).

    All three queries run inside a single read transaction for a consistent snapshot.
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute(
        "SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,)
    )
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    folder = Folder.from_row(folder_row)

    # Access check: owner, admin, shared tree, team member, or explicit permission
    if folder.owner_id != user.id and not user.is_admin:
        if not await is_in_shared_tree(db, folder_id) and \
           not await is_team_folder_member(db, folder_id, user.id) and \
           not await has_folder_permission(db, folder_id, user.id):
            raise HTTPException(status_code=403, detail="Access denied")

    # Child folders (excluding soft-deleted)
    cursor = await db.execute(
        "SELECT * FROM folders WHERE parent_id = ? AND deleted_at IS NULL ORDER BY name",
        (folder_id,),
    )
    child_folders = [Folder.from_row(r).to_dict() for r in await cursor.fetchall()]

    # Files in this folder (excluding soft-deleted)
    cursor = await db.execute(
        "SELECT * FROM files WHERE folder_id = ? AND upload_complete = 1 AND deleted_at IS NULL "
        "ORDER BY original_name",
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
        cursor = await db.execute(
            "SELECT * FROM folders WHERE id = ?", (current.parent_id,)
        )
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


@router.get("/{folder_id}/files")
async def list_folder_files_recursive(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
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
        raise HTTPException(status_code=404, detail="Folder not found")

    if folder_row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    # Recursive CTE shared by both the count and data queries.
    # Scoped to owner_id so we never traverse folders owned by other users
    # even if they happen to share a parent_id (shouldn't happen, but defense-in-depth).
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
        _cte + """
        SELECT COUNT(*) AS total
          FROM files fi
          JOIN folder_tree ft ON fi.folder_id = ft.id
         WHERE fi.upload_complete = 1
           AND fi.owner_id = ?
        """,
        (folder_id, user.id, user.id),
    )
    count_row = await count_cursor.fetchone()
    total = count_row["total"] if count_row else 0

    cursor = await db.execute(
        _cte + """
        SELECT fi.id, fi.original_name, fi.size_bytes,
               fi.encrypted_file_key, fi.key_iv
          FROM files fi
          JOIN folder_tree ft ON fi.folder_id = ft.id
         WHERE fi.upload_complete = 1
           AND fi.owner_id = ?
         ORDER BY fi.original_name
         LIMIT ? OFFSET ?
        """,
        (folder_id, user.id, user.id, limit, offset),
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
    return {"files": files, "total": total, "offset": offset, "limit": limit}


@router.put("/{folder_id}")
async def update_folder(
    folder_id: str,
    body: UpdateFolderRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Rename or move a folder."""
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ?", (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    if folder_row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    if folder_row["is_shared"]:
        raise HTTPException(status_code=400, detail="Cannot modify the shared folder")

    if body.move_to_root and body.parent_id is not None:
        raise HTTPException(status_code=400, detail="Cannot specify both parent_id and move_to_root")

    updates = []
    params = []
    if body.name is not None:
        updates.append("name = ?")
        params.append(body.name)
    if body.restrict_permissions is not None:
        updates.append("restrict_permissions = ?")
        params.append(body.restrict_permissions)
    if body.move_to_root:
        if folder_row["parent_id"] is None:
            raise HTTPException(status_code=400, detail="Folder is already at root")
        updates.append("parent_id = ?")
        params.append(None)
    elif body.parent_id is not None:
        parent_id = validate_uuid(body.parent_id)
        # Walk the ancestor chain of parent_id and confirm folder_id doesn't appear in it.
        # Without this, moving A into one of its own descendants creates a parent_id cycle
        # which infinite-loops the breadcrumb traversal in get_folder_contents.
        visited: set[str] = set()
        current = parent_id
        while current and current not in visited:
            if current == folder_id:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot move a folder into itself or one of its descendants",
                )
            visited.add(current)
            anc_cursor = await db.execute(
                "SELECT parent_id FROM folders WHERE id = ?", (current,)
            )
            anc_row = await anc_cursor.fetchone()
            current = anc_row["parent_id"] if anc_row else None
        updates.append("parent_id = ?")
        params.append(parent_id)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = NOW()")
    params.append(folder_id)

    await db.execute(
        f"UPDATE folders SET {', '.join(updates)} WHERE id = ?",
        params,
    )

    # On a parent change, replace inherited permissions with those from the new parent.
    # Rename-only (body.parent_id is None and not move_to_root) leaves permissions untouched.
    is_move = body.move_to_root or body.parent_id is not None
    if is_move:
        new_parent_id = body.parent_id if not body.move_to_root else None
        await db.execute(
            "DELETE FROM permissions WHERE resource_type = 'folder' AND resource_id = ? AND recursive = 1",
            (folder_id,),
        )
        if new_parent_id:
            await copy_folder_permissions(db, new_parent_id, "folder", folder_id)

    await db.commit()

    # Notify old parent (rename) and new parent (move) if different
    old_parent = folder_row["parent_id"]
    sse_broker.publish(old_parent or f"root:{folder_row['owner_id']}", {"type": "change"})
    if body.parent_id and body.parent_id != old_parent:
        sse_broker.publish(body.parent_id, {"type": "change"})

    cursor = await db.execute("SELECT * FROM folders WHERE id = ?", (folder_id,))
    updated_row = await cursor.fetchone()
    return {"folder": Folder.from_row(updated_row).to_dict()}


@router.delete("/{folder_id}")
async def delete_folder(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Delete a folder and all its contents.

    When trash is enabled the folder and entire subtree are soft-deleted.
    Otherwise the row is hard-deleted immediately (cascade removes descendants;
    blob cleanup is deferred to a future background pass).
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute(
        "SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL", (folder_id,)
    )
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    if folder_row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    if folder_row["is_shared"]:
        raise HTTPException(status_code=400, detail="Cannot delete the shared folder")

    trash_enabled = (await get_admin_setting(db, "trash_enabled", default="true")) == "true"

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

        sse_broker.publish(
            folder_row["parent_id"] or f"root:{folder_row['owner_id']}",
            {"type": "change"},
        )
        return {"message": "Folder moved to trash"}

    # Trash disabled — hard delete immediately (blob cleanup deferred).
    await db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    await db.commit()

    sse_broker.publish(
        folder_row["parent_id"] or f"root:{folder_row['owner_id']}",
        {"type": "change"},
    )
    return {"message": "Folder deleted"}


@router.get("/{folder_id}/effective-escrow-agents")
async def get_effective_escrow_agents(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Return the resolved escrow agent list for the given folder.

    Used by the team-creation flow: the client calls this before POST /teams
    to know which agents to wrap sk_team for.  The result reflects the closest
    folder-level policy override (replace/merge/none) or the org default when
    no override exists.

    Does not require can_manage_escrow — any user with a user role can call
    this so that team creation works without an admin account.
    """
    folder_id = validate_uuid(folder_id)

    # Verify the folder exists and the caller has access to it
    cursor = await db.execute(
        "SELECT id, owner_id FROM folders WHERE id = ?", (folder_id,)
    )
    folder_row = await cursor.fetchone()
    if not folder_row:
        raise HTTPException(status_code=404, detail="Folder not found")

    has_access = (
        folder_row["owner_id"] == user.id
        or user.is_admin
        or await has_folder_permission(db, folder_id, user.id)
        or await is_team_folder_member(db, folder_id, user.id)
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    return await resolve_effective_escrow_agents(db, folder_id)
