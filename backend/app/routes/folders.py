"""Folder management routes."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator

from app.auth.dependencies import get_current_user, require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.middleware.rate_limit import check_management_rate_limit
from app.models.file import File, Folder
from app.routes._access import is_in_shared_tree
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
    # User's own root folders (no parent)
    cursor = await db.execute(
        "SELECT * FROM folders WHERE owner_id = ? AND parent_id IS NULL AND is_shared = 0 "
        "ORDER BY name",
        (user.id,),
    )
    own_folders = [Folder.from_row(r).to_dict() for r in await cursor.fetchall()]

    # User's root-level files (no folder)
    cursor = await db.execute(
        "SELECT * FROM files WHERE owner_id = ? AND folder_id IS NULL AND upload_complete = 1 "
        "ORDER BY original_name",
        (user.id,),
    )
    own_files = [File.from_row(r).to_dict() for r in await cursor.fetchall()]

    # Shared folder
    cursor = await db.execute(
        "SELECT * FROM folders WHERE is_shared = 1 AND parent_id IS NULL"
    )
    shared_row = await cursor.fetchone()
    shared_folder = Folder.from_row(shared_row).to_dict() if shared_row else None

    return {"folders": own_folders, "files": own_files, "shared_folder": shared_folder}


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
        await db.commit()
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(status_code=409, detail="Folder with this name already exists here")
        raise

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

    await db.execute("BEGIN")
    try:
        cursor = await db.execute("SELECT * FROM folders WHERE id = ?", (folder_id,))
        folder_row = await cursor.fetchone()
        if folder_row is None:
            await db.execute("ROLLBACK")
            raise HTTPException(status_code=404, detail="Folder not found")

        folder = Folder.from_row(folder_row)

        # Access check: owner, in shared tree, or has permission
        if folder.owner_id != user.id and not user.is_admin:
            if not await is_in_shared_tree(db, folder_id):
                await db.execute("ROLLBACK")
                raise HTTPException(status_code=403, detail="Access denied")

        # Child folders
        cursor = await db.execute(
            "SELECT * FROM folders WHERE parent_id = ? ORDER BY name",
            (folder_id,),
        )
        child_folders = [Folder.from_row(r).to_dict() for r in await cursor.fetchall()]

        # Files in this folder
        cursor = await db.execute(
            "SELECT * FROM files WHERE folder_id = ? AND upload_complete = 1 ORDER BY original_name",
            (folder_id,),
        )
        files = [File.from_row(r).to_dict() for r in await cursor.fetchall()]

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

        await db.execute("ROLLBACK")  # Read-only — no changes to commit
    except HTTPException:
        raise
    except Exception:
        await db.execute("ROLLBACK")
        raise

    return {
        "folder": folder.to_dict(),
        "child_folders": child_folders,
        "files": files,
        "breadcrumbs": breadcrumbs,
    }


@router.get("/{folder_id}/files")
async def list_folder_files_recursive(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
):
    """Return a flat list of all complete files within a folder tree (recursive).

    Uses a recursive CTE to walk the folder hierarchy.  Only files owned by the
    requesting user are included — shared-tree folders are excluded to prevent
    accidentally exposing other users' file keys.

    Returns: { files: [{ id, original_name, size_bytes, encrypted_file_key, key_iv }] }
    Caller is responsible for re-wrapping each file's key before sharing.
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT owner_id FROM folders WHERE id = ?", (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    if folder_row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    # Recursive CTE: walk entire subtree rooted at folder_id.
    # Scoped to owner_id so we never traverse folders owned by other users
    # even if they happen to share a parent_id (shouldn't happen, but defense-in-depth).
    cursor = await db.execute(
        """
        WITH RECURSIVE folder_tree(id) AS (
            SELECT ? AS id
            UNION ALL
            SELECT f.id
              FROM folders f
              JOIN folder_tree ft ON f.parent_id = ft.id
             WHERE f.owner_id = ?
        )
        SELECT fi.id, fi.original_name, fi.size_bytes,
               fi.encrypted_file_key, fi.key_iv
          FROM files fi
          JOIN folder_tree ft ON fi.folder_id = ft.id
         WHERE fi.upload_complete = 1
           AND fi.owner_id = ?
         ORDER BY fi.original_name
         LIMIT ?
        """,
        (folder_id, user.id, user.id, limit),
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
    return {"files": files, "total": len(files)}


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

    updates = []
    params = []
    if body.name is not None:
        updates.append("name = ?")
        params.append(body.name)
    if body.parent_id is not None:
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

    updates.append("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
    params.append(folder_id)

    await db.execute(
        f"UPDATE folders SET {', '.join(updates)} WHERE id = ?",
        params,
    )
    await db.commit()

    return {"message": "Folder updated"}


@router.delete("/{folder_id}")
async def delete_folder(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Delete a folder and all its contents (cascade)."""
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute("SELECT * FROM folders WHERE id = ?", (folder_id,))
    folder_row = await cursor.fetchone()
    if folder_row is None:
        raise HTTPException(status_code=404, detail="Folder not found")

    if folder_row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    if folder_row["is_shared"]:
        raise HTTPException(status_code=400, detail="Cannot delete the shared folder")

    # CASCADE handles child folders and files in DB
    await db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    await db.commit()

    # TODO: Clean up orphaned file blobs from disk in Phase 3+

    return {"message": "Folder deleted"}
