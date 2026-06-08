"""Durable blob cleanup worker.

Processes blob_cleanup_queue entries written within deletion transactions.
Because the queue rows are committed atomically with the file/user/folder
deletion, they survive a process crash and are retried on the next startup.

The worker checks the live ref-count (SELECT COUNT(*) FROM files WHERE
storage_key = ?) before deleting any blob, so blobs shared across multiple
file rows (copies) are only removed when the last reference is gone.
"""

import asyncio
import logging

import app.storage.manager as storage

logger = logging.getLogger(__name__)

_BATCH = 200


async def run_blob_cleanup_worker(db_factory, interval: float = 300.0) -> None:
    """Process blob_cleanup_queue on startup then every `interval` seconds."""
    await _process_queue(db_factory)
    while True:
        await asyncio.sleep(interval)
        await _process_queue(db_factory)


async def _process_queue(db_factory) -> None:
    try:
        async with db_factory() as db:
            cursor = await db.execute(
                "SELECT id, storage_key, volume_id FROM blob_cleanup_queue "
                "ORDER BY created_at LIMIT ?",
                (_BATCH,),
            )
            rows = await cursor.fetchall()
            if not rows:
                return

            mgr = storage.get_manager()
            cleaned = 0
            for row in rows:
                try:
                    cnt_cur = await db.execute(
                        "SELECT COUNT(*) AS cnt FROM files WHERE storage_key = ?",
                        (row["storage_key"],),
                    )
                    cnt_row = await cnt_cur.fetchone()
                    if cnt_row and cnt_row["cnt"] == 0:
                        await mgr.delete_blob_direct(row["storage_key"], row["volume_id"])
                        cleaned += 1
                except Exception:
                    logger.exception(
                        "Blob cleanup failed for storage_key=%s volume=%s",
                        row["storage_key"],
                        row["volume_id"],
                    )
                await db.execute(
                    "DELETE FROM blob_cleanup_queue WHERE id = ?", (row["id"],)
                )
                await db.commit()

            if cleaned:
                logger.info("Blob cleanup: removed %d orphaned blob(s)", cleaned)
    except Exception:
        logger.exception("Blob cleanup worker error")
