"""Trash / soft-delete background cleanup."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import app.storage.manager as storage
from app.database import db_session
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus

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
        "SELECT id, storage_key, encrypted_size, owner_id FROM files WHERE deleted_at IS NOT NULL AND deleted_at < ?",
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


async def _purge_expired_users(db) -> None:
    """Hard-delete users whose scheduled_delete_at window has elapsed."""
    cursor = await db.execute(
        "SELECT id, username FROM users WHERE scheduled_delete_at IS NOT NULL AND scheduled_delete_at < NOW()"
    )
    expired = await cursor.fetchall()

    for row in expired:
        user_id, username = row["id"], row["username"]
        try:
            fc = await db.execute("SELECT id, storage_key FROM files WHERE owner_id = ?", (user_id,))
            file_rows = await fc.fetchall()

            await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            await db.commit()

            event_bus.emit(
                SecurityEvent(
                    event_type="system.user.purged",
                    severity="critical",
                    outcome="success",
                    actor=EventActor(user_id="system", username="system"),
                    target=EventTarget(type="user", id=user_id, name=username),
                )
            )

            rows_snapshot = list(file_rows)

            async def _cleanup(rows=rows_snapshot, uid=user_id):
                mgr = storage.get_manager()
                async with db_session() as _db:
                    for r in rows:
                        try:
                            cur = await _db.execute(
                                "SELECT COUNT(*) AS cnt FROM files WHERE storage_key = ?", (r["storage_key"],)
                            )
                            cnt = await cur.fetchone()
                            if cnt and cnt["cnt"] > 0:
                                continue
                            await mgr.delete_blob(_db, r["id"], r["storage_key"])
                        except Exception as exc:
                            logger.warning("Failed to delete blob %s for purged user %s: %s", r["storage_key"], uid, exc)

            _t = asyncio.create_task(_cleanup())
            _bg_tasks.add(_t)
            _t.add_done_callback(_bg_tasks.discard)
        except Exception:
            logger.exception("Failed to purge soft-deleted user %s", user_id)


async def _purge_expired_teams(db) -> None:
    """Hard-delete teams whose scheduled_delete_at window has elapsed."""
    cursor = await db.execute(
        "SELECT id, name FROM teams WHERE scheduled_delete_at IS NOT NULL AND scheduled_delete_at < NOW()"
    )
    expired = await cursor.fetchall()

    for row in expired:
        team_id, team_name = row["id"], row["name"]
        try:
            # Collect team folder IDs before cascade wipes team_folders
            fc = await db.execute("SELECT folder_id FROM team_folders WHERE team_id = ?", (team_id,))
            folder_ids = [r["folder_id"] for r in await fc.fetchall()]

            await db.execute("DELETE FROM user_roles WHERE scope_type = 'team' AND scope_id = ?", (team_id,))
            await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
            for fid in folder_ids:
                await db.execute("DELETE FROM folders WHERE id = ?", (fid,))
            await db.commit()

            event_bus.emit(
                SecurityEvent(
                    event_type="system.team.purged",
                    severity="warning",
                    outcome="success",
                    actor=EventActor(user_id="system", username="system"),
                    target=EventTarget(type="team", id=team_id, name=team_name),
                )
            )
        except Exception:
            logger.exception("Failed to purge soft-deleted team %s", team_id)


async def run_trash_cleanup(db_factory, interval: float = 3600.0) -> None:
    """Periodic background task — purges items past their trash retention window."""
    while True:
        await asyncio.sleep(interval)
        try:
            async with db_factory() as db:
                await _purge_expired(db)
                await _purge_expired_users(db)
                await _purge_expired_teams(db)
        except Exception:
            logger.exception("Trash cleanup task failed")
