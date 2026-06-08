"""Trash / soft-delete background cleanup."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus
from app.services.folder_cleanup import hard_delete_folder_tree

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
    """Hard-delete one file row, adjust quota, and queue blob removal.

    All mutations (blob queue entry, ACL cleanup, quota update, DELETE) are in
    a single transaction so no partial state survives a crash.
    """
    await db.execute("BEGIN")
    try:
        # Queue blob before file_storage_locations cascades away.
        locs_cursor = await db.execute(
            "SELECT volume_id FROM file_storage_locations WHERE file_id = ?", (file_id,)
        )
        locs = await locs_cursor.fetchall()
        if locs:
            for loc in locs:
                await db.execute(
                    "INSERT INTO blob_cleanup_queue (storage_key, volume_id) VALUES (?, ?)",
                    (storage_key, loc["volume_id"]),
                )
        else:
            await db.execute(
                "INSERT INTO blob_cleanup_queue (storage_key, volume_id) VALUES (?, '__default__')",
                (storage_key,),
            )

        # Clean orphaned ACL rows.
        await db.execute(
            "DELETE FROM permissions WHERE resource_type = 'file' AND resource_id = ?", (file_id,)
        )
        await db.execute(
            "DELETE FROM resource_role_grants WHERE resource_type = 'file' AND resource_id = ?", (file_id,)
        )

        # Clean share_items and orphaned shares.
        si_cursor = await db.execute(
            "SELECT DISTINCT share_id FROM share_items WHERE resource_type = 'file' AND resource_id = ?",
            (file_id,),
        )
        affected_share_ids = [r["share_id"] for r in await si_cursor.fetchall()]
        await db.execute(
            "DELETE FROM share_items WHERE resource_type = 'file' AND resource_id = ?", (file_id,)
        )
        if affected_share_ids:
            sph = ",".join("?" * len(affected_share_ids))
            await db.execute(
                f"DELETE FROM shares WHERE id IN ({sph})"
                f" AND id NOT IN (SELECT DISTINCT share_id FROM share_items)",
                affected_share_ids,
            )

        await db.execute(
            "UPDATE users SET disk_used = GREATEST(0, disk_used - ?::bigint) WHERE id = ?",
            (encrypted_size, owner_id),
        )
        await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise


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

    # Purge expired folder subtrees.  We process only the "topmost" expired
    # folder in each chain — one whose parent is either absent or not itself
    # expired.  hard_delete_folder_tree then cascades to all descendants, so
    # we never call it twice on the same subtree.
    #
    # This handles both: root folders deleted by the owner, and subfolders
    # that were individually trashed while their parent remained active.
    cursor = await db.execute(
        """
        SELECT f.id FROM folders f
        WHERE f.deleted_at IS NOT NULL AND f.deleted_at < ?
          AND (
              f.parent_id IS NULL
              OR NOT EXISTS (
                  SELECT 1 FROM folders p
                  WHERE p.id = f.parent_id
                    AND p.deleted_at IS NOT NULL AND p.deleted_at < ?
              )
          )
        """,
        (cutoff, cutoff),
    )
    topmost_expired = [r["id"] for r in await cursor.fetchall()]

    for fid in topmost_expired:
        try:
            await db.execute("BEGIN")
            await hard_delete_folder_tree(db, fid)
            await db.commit()
        except Exception:
            await db.rollback()
            logger.exception("Failed to purge expired folder %s from trash", fid)


async def _purge_expired_users(db) -> None:
    """Hard-delete users whose scheduled_delete_at window has elapsed."""
    cursor = await db.execute(
        "SELECT id, username FROM users WHERE scheduled_delete_at IS NOT NULL AND scheduled_delete_at < NOW()"
    )
    expired = await cursor.fetchall()

    for row in expired:
        user_id, username = row["id"], row["username"]
        try:
            await db.execute("BEGIN")

            # Capture blob info before file_storage_locations cascades away.
            blob_cursor = await db.execute(
                "SELECT DISTINCT fi.storage_key, COALESCE(fsl.volume_id, '__default__') AS volume_id "
                "FROM files fi LEFT JOIN file_storage_locations fsl ON fsl.file_id = fi.id "
                "WHERE fi.owner_id = ?",
                (user_id,),
            )
            for bp in await blob_cursor.fetchall():
                await db.execute(
                    "INSERT INTO blob_cleanup_queue (storage_key, volume_id) VALUES (?, ?)",
                    (bp["storage_key"], bp["volume_id"]),
                )

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
        except Exception:
            await db.rollback()
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
            fc = await db.execute("SELECT folder_id FROM team_folders WHERE team_id = ?", (team_id,))
            folder_ids = [r["folder_id"] for r in await fc.fetchall()]

            await db.execute("BEGIN")
            await db.execute("DELETE FROM user_roles WHERE scope_type = 'team' AND scope_id = ?", (team_id,))
            await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
            for fid in folder_ids:
                await hard_delete_folder_tree(db, fid)
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
            await db.rollback()
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
