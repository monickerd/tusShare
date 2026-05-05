"""Trash / soft-delete background cleanup."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import app.storage.manager as storage
from app.database import db_session

_bg_tasks: set = set()

logger = logging.getLogger(__name__)


async def get_trash_settings(db) -> tuple[bool, int]:
    """Return (trash_enabled, retention_days) from admin_settings."""
    cursor = await db.execute(
        "SELECT key, value FROM admin_settings WHERE key IN ('trash_enabled', 'trash_retention_days')"
    )
    cfg = {r["key"]: r["value"] for r in await cursor.fetchall()}
    enabled = cfg.get("trash_enabled", "true") == "true"
    days = int(cfg.get("trash_retention_days", "30"))
    return enabled, days


async def purge_file(db, file_id: str, storage_key: str, encrypted_size: int, owner_id: str) -> None:
    """Hard-delete one file row, adjust quota, and schedule blob removal."""
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

    fid, key = file_id, storage_key

    async def _bg() -> None:
        try:
            async with db_session() as _db:
                await storage.get_manager().delete_blob(_db, fid, key)
        except Exception:
            pass

    _t = asyncio.create_task(_bg())
    _bg_tasks.add(_t)
    _t.add_done_callback(_bg_tasks.discard)


async def _purge_expired(db) -> None:
    """Hard-delete files and folders whose trash retention window has elapsed."""
    _, days = await get_trash_settings(db)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    cursor = await db.execute(
        "SELECT id, storage_key, encrypted_size, owner_id FROM files "
        "WHERE deleted_at IS NOT NULL AND deleted_at < ?",
        (cutoff,),
    )
    expired_files = await cursor.fetchall()

    for row in expired_files:
        try:
            await purge_file(db, row["id"], row["storage_key"], row["encrypted_size"], row["owner_id"])
        except Exception:
            logger.exception("Failed to purge expired file %s from trash", row["id"])

    # Cascade handles descendant folders; files already removed above.
    await db.execute(
        "DELETE FROM folders WHERE deleted_at IS NOT NULL AND deleted_at < ?",
        (cutoff,),
    )
    await db.commit()


async def run_trash_cleanup(db_factory, interval: float = 3600.0) -> None:
    """Periodic background task — purges items past their trash retention window."""
    while True:
        await asyncio.sleep(interval)
        try:
            async with db_factory() as db:
                await _purge_expired(db)
        except Exception:
            logger.exception("Trash cleanup task failed")
