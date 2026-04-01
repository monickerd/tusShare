"""Access log viewing routes."""

from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import get_current_user
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.models.access_log import AccessLog
from app.validation.sanitizers import validate_uuid
from app.validation.validators import validate_pagination

router = APIRouter()


@router.get("/file/{file_id}")
async def get_file_access_logs(
    file_id: str,
    page: int = 1,
    limit: int = 20,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Get access logs for a specific file. Requires ownership or admin."""
    file_id = validate_uuid(file_id)
    pagination = validate_pagination(page, limit)

    # Verify ownership or admin
    cursor = await db.execute(
        "SELECT owner_id FROM files WHERE id = ?", (file_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")
    if row["owner_id"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    cursor = await db.execute(
        "SELECT * FROM access_logs WHERE file_id = ? ORDER BY timestamp DESC "
        "LIMIT ? OFFSET ?",
        (file_id, pagination.limit, pagination.offset),
    )
    logs = [AccessLog.from_row(r).to_dict() for r in await cursor.fetchall()]

    count_cursor = await db.execute(
        "SELECT COUNT(*) FROM access_logs WHERE file_id = ?", (file_id,)
    )
    total = (await count_cursor.fetchone())[0]

    return {"logs": logs, "total": total, "page": pagination.page, "limit": pagination.limit}


@router.get("/share/{share_id}")
async def get_share_access_logs(
    share_id: str,
    page: int = 1,
    limit: int = 20,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Get access logs for a specific share. Requires ownership or admin."""
    share_id = validate_uuid(share_id)
    pagination = validate_pagination(page, limit)

    # Verify share ownership or admin
    cursor = await db.execute(
        "SELECT created_by FROM shares WHERE id = ?", (share_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Share not found")
    if row["created_by"] != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    cursor = await db.execute(
        "SELECT * FROM access_logs WHERE share_id = ? ORDER BY timestamp DESC "
        "LIMIT ? OFFSET ?",
        (share_id, pagination.limit, pagination.offset),
    )
    logs = [AccessLog.from_row(r).to_dict() for r in await cursor.fetchall()]

    count_cursor = await db.execute(
        "SELECT COUNT(*) FROM access_logs WHERE share_id = ?", (share_id,)
    )
    total = (await count_cursor.fetchone())[0]

    return {"logs": logs, "total": total, "page": pagination.page, "limit": pagination.limit}
