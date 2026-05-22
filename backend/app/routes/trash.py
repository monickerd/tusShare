"""Trash routes: list, restore, and permanently delete soft-deleted items."""

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import Database, db_session, get_db
from app.models.role import FLAG_FILES_ACCESS_ALL_WRITE
from app.services import event_bus, sse_broker
from app.schemas.security_event import EventActor, SecurityEvent
from app.services.trash import get_trash_settings, purge_file
import app.storage.manager as storage
from app.validation.sanitizers import validate_uuid
from typing import Annotated

router = APIRouter()

_ERR_ACCESS_DENIED = "Access denied"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _permanent_delete_at(deleted_at: str | None, retention_days: int) -> str | None:
    if not deleted_at:
        return None
    try:
        dt = datetime.fromisoformat(deleted_at.replace("Z", "+00:00"))
        return (dt + timedelta(days=retention_days)).isoformat()
    except (ValueError, TypeError):
        return None


def _enrich_file(row, retention_days: int) -> dict:
    d = dict(row)
    d["item_type"] = "file"
    d["permanent_delete_at"] = _permanent_delete_at(d.get("deleted_at"), retention_days)
    return d


def _enrich_folder(row, retention_days: int) -> dict:
    d = dict(row)
    d["item_type"] = "folder"
    d["permanent_delete_at"] = _permanent_delete_at(d.get("deleted_at"), retention_days)
    return d


class BulkItemsRequest(BaseModel):
    file_ids: list[str] = []
    folder_ids: list[str] = []


# ---------------------------------------------------------------------------
# List trash (personal)
# ---------------------------------------------------------------------------

@router.get("")
async def list_trash(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return all soft-deleted files and folders owned by the current user.

    Sorted by deleted_at ASC (expiring soonest first). Includes folder_name,
    deleted_by_username, and computed permanent_delete_at.
    """
    _, retention_days = await get_trash_settings(db)

    cursor = await db.execute(
        """
        SELECT f.*, u.username AS deleted_by_username, p.name AS folder_name
          FROM files f
          LEFT JOIN users u ON u.id = f.deleted_by
          LEFT JOIN folders p ON p.id = f.folder_id
         WHERE f.owner_id = ? AND f.deleted_at IS NOT NULL
         ORDER BY f.deleted_at ASC
        """,
        (user.id,),
    )
    files = [_enrich_file(r, retention_days) for r in await cursor.fetchall()]

    cursor = await db.execute(
        """
        SELECT fo.*, u.username AS deleted_by_username, p.name AS parent_name
          FROM folders fo
          LEFT JOIN users u ON u.id = fo.deleted_by
          LEFT JOIN folders p ON p.id = fo.parent_id
         WHERE fo.owner_id = ? AND fo.deleted_at IS NOT NULL
         ORDER BY fo.deleted_at ASC
        """,
        (user.id,),
    )
    folders = [_enrich_folder(r, retention_days) for r in await cursor.fetchall()]

    return {"files": files, "folders": folders, "retention_days": retention_days}


# ---------------------------------------------------------------------------
# Team trash
# ---------------------------------------------------------------------------

@router.get("/teams/{team_id}")
async def list_team_trash(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return all soft-deleted files and folders within a team's folder tree.

    Requires team membership (any role) or files_access_all_write.
    """
    team_id = validate_uuid(team_id)

    if not user.has_flag(FLAG_FILES_ACCESS_ALL_WRITE):
        cursor = await db.execute(
            "SELECT 1 FROM team_role_assignments WHERE user_id = ? AND team_id = ?",
            (user.id, team_id),
        )
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    _, retention_days = await get_trash_settings(db)

    # Expand the full folder tree for this team (regardless of deletion status)
    # then filter for deleted items.
    cursor = await db.execute(
        """
        WITH RECURSIVE team_tree AS (
            SELECT tf.folder_id AS id FROM team_folders tf WHERE tf.team_id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN team_tree tt ON f.parent_id = tt.id
        )
        SELECT fi.*, u.username AS deleted_by_username, p.name AS folder_name
          FROM files fi
          LEFT JOIN users u ON u.id = fi.deleted_by
          LEFT JOIN folders p ON p.id = fi.folder_id
         WHERE fi.folder_id IN (SELECT id FROM team_tree)
           AND fi.deleted_at IS NOT NULL
         ORDER BY fi.deleted_at ASC
        """,
        (team_id,),
    )
    files = [_enrich_file(r, retention_days) for r in await cursor.fetchall()]

    cursor = await db.execute(
        """
        WITH RECURSIVE team_tree AS (
            SELECT tf.folder_id AS id FROM team_folders tf WHERE tf.team_id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN team_tree tt ON f.parent_id = tt.id
        )
        SELECT fo.*, u.username AS deleted_by_username, p.name AS parent_name
          FROM folders fo
          LEFT JOIN users u ON u.id = fo.deleted_by
          LEFT JOIN folders p ON p.id = fo.parent_id
         WHERE fo.id IN (SELECT id FROM team_tree)
           AND fo.deleted_at IS NOT NULL
         ORDER BY fo.deleted_at ASC
        """,
        (team_id,),
    )
    folders = [_enrich_folder(r, retention_days) for r in await cursor.fetchall()]

    return {"files": files, "folders": folders, "retention_days": retention_days}


# ---------------------------------------------------------------------------
# Restore (single item)
# ---------------------------------------------------------------------------

@router.post("/files/{file_id}/restore", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def restore_file(
    file_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Restore a soft-deleted file. If its parent folder is also deleted, moves it to root."""
    file_id = validate_uuid(file_id)
    await _restore_file_by_id(db, file_id, user)
    return {"message": "File restored"}


@router.post("/folders/{folder_id}/restore", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def restore_folder(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Restore a soft-deleted folder and all its contents recursively."""
    folder_id = validate_uuid(folder_id)
    await _restore_folder_by_id(db, folder_id, user)
    return {"message": "Folder restored"}


# ---------------------------------------------------------------------------
# Bulk restore
# ---------------------------------------------------------------------------

@router.post("/recover-bulk")
async def recover_bulk(
    body: BulkItemsRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Restore multiple files and folders from trash. Best-effort: skips items
    that are not found or are not accessible. Returns counts of successes and failures."""
    file_ids = [validate_uuid(fid) for fid in body.file_ids]
    folder_ids = [validate_uuid(fid) for fid in body.folder_ids]

    restored_files = 0
    restored_folders = 0
    failed = 0

    for fid in file_ids:
        try:
            await _restore_file_by_id(db, fid, user)
            restored_files += 1
        except HTTPException:
            failed += 1

    for fid in folder_ids:
        try:
            await _restore_folder_by_id(db, fid, user)
            restored_folders += 1
        except HTTPException:
            failed += 1

    return {"restored_files": restored_files, "restored_folders": restored_folders, "failed": failed}


# ---------------------------------------------------------------------------
# Permanent delete (single item)
# ---------------------------------------------------------------------------

@router.delete("/files/{file_id}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def permanently_delete_file(
    file_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Permanently delete a file that is currently in the trash."""
    file_id = validate_uuid(file_id)
    await _purge_file_by_id(db, file_id, user)
    return {"message": "File permanently deleted"}


@router.delete("/folders/{folder_id}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def permanently_delete_folder(
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Permanently delete a folder and all its contents from the trash."""
    folder_id = validate_uuid(folder_id)
    await _purge_folder_by_id(db, folder_id, user)
    return {"message": "Folder permanently deleted"}


# ---------------------------------------------------------------------------
# Bulk permanent delete
# ---------------------------------------------------------------------------

@router.post("/bulk-delete")
async def permanently_delete_bulk(
    body: BulkItemsRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Permanently delete multiple files and folders from trash. Best-effort."""
    file_ids = [validate_uuid(fid) for fid in body.file_ids]
    folder_ids = [validate_uuid(fid) for fid in body.folder_ids]

    deleted_files = 0
    deleted_folders = 0
    failed = 0

    for fid in file_ids:
        try:
            await _purge_file_by_id(db, fid, user)
            deleted_files += 1
        except HTTPException:
            failed += 1

    for fid in folder_ids:
        try:
            await _purge_folder_by_id(db, fid, user)
            deleted_folders += 1
        except HTTPException:
            failed += 1

    return {"deleted_files": deleted_files, "deleted_folders": deleted_folders, "failed": failed}


@router.delete("")
async def empty_trash(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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

    await db.execute(
        "DELETE FROM folders WHERE owner_id = ? AND deleted_at IS NOT NULL",
        (user.id,),
    )
    await db.commit()
    return {"message": "Trash emptied"}


# ---------------------------------------------------------------------------
# Inner helpers (shared by single and bulk endpoints)
# ---------------------------------------------------------------------------

async def _restore_file_by_id(db, file_id: str, user: AuthenticatedUser) -> None:
    cursor = await db.execute(
        "SELECT id, owner_id, folder_id FROM files WHERE id = ? AND deleted_at IS NOT NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found in trash")
    if row["owner_id"] != user.id and not user.has_flag(FLAG_FILES_ACCESS_ALL_WRITE):
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    new_folder_id = row["folder_id"]
    if new_folder_id:
        cursor = await db.execute("SELECT deleted_at FROM folders WHERE id = ?", (new_folder_id,))
        parent = await cursor.fetchone()
        if parent is None or parent["deleted_at"] is not None:
            new_folder_id = None

    await db.execute(
        "UPDATE files SET deleted_at = NULL, deleted_by = NULL, folder_id = ? WHERE id = ?",
        (new_folder_id, file_id),
    )
    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="file.restored",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        detail={"file_id": file_id},
    ))
    sse_broker.publish(new_folder_id or f"root:{row['owner_id']}", {"type": "change"})


async def _restore_folder_by_id(db, folder_id: str, user: AuthenticatedUser) -> None:
    cursor = await db.execute(
        "SELECT id, owner_id, parent_id FROM folders WHERE id = ? AND deleted_at IS NOT NULL",
        (folder_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Folder not found in trash")
    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

    new_parent_id = row["parent_id"]
    if new_parent_id:
        cursor = await db.execute("SELECT deleted_at FROM folders WHERE id = ?", (new_parent_id,))
        parent = await cursor.fetchone()
        if parent is None or parent["deleted_at"] is not None:
            new_parent_id = None

    await db.execute("BEGIN")
    try:
        await db.execute(
            """
            WITH RECURSIVE subtree AS (
                SELECT id FROM folders WHERE id = ?
                UNION ALL
                SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
            )
            UPDATE folders SET deleted_at = NULL, deleted_by = NULL
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
            UPDATE files SET deleted_at = NULL, deleted_by = NULL
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

    event_bus.emit(SecurityEvent(
        event_type="file.restored",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        detail={"folder_id": folder_id},
    ))
    sse_broker.publish(new_parent_id or f"root:{row['owner_id']}", {"type": "change"})


async def _purge_file_by_id(db, file_id: str, user: AuthenticatedUser) -> None:
    cursor = await db.execute(
        "SELECT id, owner_id, storage_key, encrypted_size FROM files "
        "WHERE id = ? AND deleted_at IS NOT NULL",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found in trash")
    if row["owner_id"] != user.id and not user.has_flag(FLAG_FILES_ACCESS_ALL_WRITE):
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)
    await purge_file(db, row["id"], row["storage_key"], row["encrypted_size"], row["owner_id"])


async def _purge_folder_by_id(db, folder_id: str, user: AuthenticatedUser) -> None:
    cursor = await db.execute(
        "SELECT id, owner_id FROM folders WHERE id = ? AND deleted_at IS NOT NULL",
        (folder_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Folder not found in trash")
    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail=_ERR_ACCESS_DENIED)

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

    await db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    await db.commit()
