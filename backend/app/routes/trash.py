"""Trash routes: list, restore, and permanently delete soft-deleted items."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import db_session, get_db
from app.models.file import File, Folder
from app.models.role import FLAG_ACCESS_ALL_FILES
from app.services import sse_broker
from app.services.trash import get_trash_settings, purge_file
import app.storage.manager as storage
from app.validation.sanitizers import validate_uuid

router = APIRouter()


# ---------------------------------------------------------------------------
# List trash
# ---------------------------------------------------------------------------

@router.get("")
async def list_trash(
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Return all soft-deleted files and folders owned by the current user."""
    cursor = await db.execute(
        "SELECT * FROM files WHERE owner_id = ? AND deleted_at IS NOT NULL "
        "ORDER BY deleted_at DESC",
        (user.id,),
    )
    files = [File.from_row(r).to_dict() for r in await cursor.fetchall()]

    cursor = await db.execute(
        "SELECT * FROM folders WHERE owner_id = ? AND deleted_at IS NOT NULL "
        "ORDER BY deleted_at DESC",
        (user.id,),
    )
    folders = [Folder.from_row(r).to_dict() for r in await cursor.fetchall()]

    return {"files": files, "folders": folders}


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

@router.post("/files/{file_id}/restore")
async def restore_file(
    file_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Restore a soft-deleted file. If its parent folder is also deleted, moves it to root."""
    file_id = validate_uuid(file_id)

    cursor = await db.execute(
        "SELECT id, owner_id, folder_id FROM files WHERE id = ? AND deleted_at IS NOT NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found in trash")

    if row["owner_id"] != user.id and not user.has_flag(FLAG_ACCESS_ALL_FILES):
        raise HTTPException(status_code=403, detail="Access denied")

    # If the parent folder is also deleted, move the file to root so it's visible.
    new_folder_id = row["folder_id"]
    if new_folder_id:
        cursor = await db.execute(
            "SELECT deleted_at FROM folders WHERE id = ?", (new_folder_id,)
        )
        parent = await cursor.fetchone()
        if parent is None or parent["deleted_at"] is not None:
            new_folder_id = None

    await db.execute(
        "UPDATE files SET deleted_at = NULL, deleted_by = NULL, folder_id = ? WHERE id = ?",
        (new_folder_id, file_id),
    )
    await db.commit()

    sse_broker.publish(new_folder_id or f"root:{row['owner_id']}", {"type": "change"})
    return {"message": "File restored"}


@router.post("/folders/{folder_id}/restore")
async def restore_folder(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Restore a soft-deleted folder and all its contents recursively.

    If the folder's parent is also deleted, the folder is moved to root.
    """
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute(
        "SELECT id, owner_id, parent_id FROM folders WHERE id = ? AND deleted_at IS NOT NULL",
        (folder_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Folder not found in trash")

    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    # If the parent folder is also deleted, detach to root.
    new_parent_id = row["parent_id"]
    if new_parent_id:
        cursor = await db.execute(
            "SELECT deleted_at FROM folders WHERE id = ?", (new_parent_id,)
        )
        parent = await cursor.fetchone()
        if parent is None or parent["deleted_at"] is not None:
            new_parent_id = None

    # Restore folder + all descendants + all files in the subtree.
    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            WITH RECURSIVE subtree AS (
                SELECT id FROM folders WHERE id = ?
                UNION ALL
                SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
            )
            UPDATE folders
               SET deleted_at = NULL, deleted_by = NULL
             WHERE id IN (SELECT id FROM subtree)
            """,
            (folder_id,),
        )
        await db.execute(
            """
            WITH RECURSIVE subtree AS (
                SELECT id FROM folders WHERE id = ?
                UNION ALL
                SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
            )
            UPDATE files
               SET deleted_at = NULL, deleted_by = NULL
             WHERE folder_id IN (SELECT id FROM subtree)
            """,
            (folder_id,),
        )
        if new_parent_id != row["parent_id"]:
            await db.execute(
                "UPDATE folders SET parent_id = ? WHERE id = ?",
                (new_parent_id, folder_id),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    sse_broker.publish(new_parent_id or f"root:{row['owner_id']}", {"type": "change"})
    return {"message": "Folder restored"}


# ---------------------------------------------------------------------------
# Permanent delete
# ---------------------------------------------------------------------------

@router.delete("/files/{file_id}")
async def permanently_delete_file(
    file_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Permanently delete a file that is currently in the trash."""
    file_id = validate_uuid(file_id)

    cursor = await db.execute(
        "SELECT id, owner_id, storage_key, encrypted_size FROM files "
        "WHERE id = ? AND deleted_at IS NOT NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found in trash")

    if row["owner_id"] != user.id and not user.has_flag(FLAG_ACCESS_ALL_FILES):
        raise HTTPException(status_code=403, detail="Access denied")

    await purge_file(db, row["id"], row["storage_key"], row["encrypted_size"], row["owner_id"])
    return {"message": "File permanently deleted"}


@router.delete("/folders/{folder_id}")
async def permanently_delete_folder(
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Permanently delete a folder and all its contents from the trash."""
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute(
        "SELECT id, owner_id FROM folders WHERE id = ? AND deleted_at IS NOT NULL",
        (folder_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Folder not found in trash")

    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    # Purge all files in the subtree first (quota + blob cleanup).
    cursor = await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        SELECT fi.id, fi.storage_key, fi.encrypted_size, fi.owner_id
          FROM files fi
         WHERE fi.folder_id IN (SELECT id FROM subtree)
        """,
        (folder_id,),
    )
    file_rows = await cursor.fetchall()

    for fr in file_rows:
        try:
            await purge_file(db, fr["id"], fr["storage_key"], fr["encrypted_size"], fr["owner_id"])
        except Exception:
            pass

    # Delete the folder tree (cascade removes descendants).
    await db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    await db.commit()
    return {"message": "Folder permanently deleted"}


@router.delete("")
async def empty_trash(
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Permanently delete all items in the current user's trash."""
    cursor = await db.execute(
        "SELECT id, storage_key, encrypted_size, owner_id FROM files "
        "WHERE owner_id = ? AND deleted_at IS NOT NULL",
        (user.id,),
    )
    file_rows = await cursor.fetchall()

    for fr in file_rows:
        try:
            await purge_file(db, fr["id"], fr["storage_key"], fr["encrypted_size"], fr["owner_id"])
        except Exception:
            pass

    # Delete all root-level deleted folders owned by the user (cascade removes subtrees).
    await db.execute(
        "DELETE FROM folders WHERE owner_id = ? AND deleted_at IS NOT NULL",
        (user.id,),
    )
    await db.commit()
    return {"message": "Trash emptied"}
