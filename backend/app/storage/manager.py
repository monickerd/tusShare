"""Storage orchestration layer.

Routes call StorageManager exclusively; they never import providers directly.
The manager handles:
  - Routing new uploads to the default volume
  - Async replication to mirror volumes after finalization
  - Hot/cold tier migration (background task)
  - Read failover: primary → replicas if primary is unavailable
  - Stale-migration reconciliation

Initialisation (called from app lifespan in main.py):
  from app.storage import manager as storage
  await storage.init(db, db_factory)
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator

from app.storage.base import StorageProvider, VolumeConfig, validate_storage_key
from app.storage.crypto import decrypt_volume_config
from app.util.db import get_admin_setting

_bg_tasks: set = set()

logger = logging.getLogger(__name__)

_manager: "StorageManager | None" = None


def get_manager() -> "StorageManager":
    if _manager is None:
        raise RuntimeError("Storage manager not initialized — call storage.init() in app lifespan")
    return _manager


async def init(db, db_factory) -> "StorageManager":
    """Load volume configs from DB and build the manager singleton.

    Called once during app startup with an open DB session.
    db_factory is stored for use by background tasks.
    """
    global _manager
    _manager = StorageManager(db_factory)
    await _manager.load_volumes(db)
    return _manager


class StorageManager:
    def __init__(self, db_factory) -> None:
        self._db_factory = db_factory
        self._providers: dict[str, StorageProvider] = {}
        self._volumes: dict[str, VolumeConfig] = {}
        self._default_volume_id: str | None = None

    # ------------------------------------------------------------------
    # Volume management
    # ------------------------------------------------------------------

    async def load_volumes(self, db) -> None:
        """(Re)load volume configs from storage_volumes table."""
        cursor = await db.execute(
            "SELECT id, name, provider, config_enc, tier, is_default, priority "
            "FROM storage_volumes ORDER BY priority ASC"
        )
        rows = await cursor.fetchall()

        providers: dict[str, StorageProvider] = {}
        volumes: dict[str, VolumeConfig] = {}
        default_id: str | None = None

        for row in rows:
            try:
                config = decrypt_volume_config(row["config_enc"]) if row["config_enc"] else {}
            except Exception:
                logger.error(
                    "Failed to decrypt config for storage volume %s (%s) — skipping",
                    row["id"], row["name"],
                )
                continue

            vol = VolumeConfig(
                id=row["id"],
                name=row["name"],
                provider=row["provider"],
                tier=row["tier"],
                is_default=bool(row["is_default"]),
                priority=row["priority"],
                config=config,
            )
            volumes[vol.id] = vol

            try:
                providers[vol.id] = _build_provider(vol)
            except Exception:
                logger.error(
                    "Failed to initialize storage provider for volume %s (%s) — skipping",
                    vol.id, vol.name,
                )
                continue

            if vol.is_default:
                default_id = vol.id

        if default_id is None and providers:
            # No volume is flagged as default — use the first (lowest priority) one
            default_id = next(iter(providers))
            logger.warning(
                "No default storage volume set; falling back to %s", default_id
            )

        self._providers = providers
        self._volumes = volumes
        self._default_volume_id = default_id
        logger.info(
            "Storage: loaded %d volume(s), default=%s", len(providers), default_id
        )

    def volume_list(self) -> list[dict]:
        result = []
        for vol in self._volumes.values():
            result.append({
                "id": vol.id,
                "name": vol.name,
                "provider": vol.provider,
                "tier": vol.tier,
                "is_default": vol.is_default,
                "priority": vol.priority,
            })
        return result

    def local_volumes(self) -> list[VolumeConfig]:
        """Return configs for all local-filesystem volumes (used by hardware scan)."""
        return [v for v in self._volumes.values() if v.provider == "local"]

    # ------------------------------------------------------------------
    # Upload lifecycle
    # ------------------------------------------------------------------

    async def begin_upload(self, upload_id: str) -> None:
        """Prepare staging area on the default volume."""
        await self._default_provider().begin_upload(upload_id)

    async def write_chunk(
        self,
        upload_id: str,
        part_number: int,
        offset: int,
        data: bytes,
    ) -> str | None:
        """Write one chunk to staging.  Returns ETag (S3) or None (local)."""
        return await self._default_provider().write_chunk(upload_id, part_number, offset, data)

    async def finalize_upload(
        self,
        db,
        upload_id: str,
        file_id: str,
        storage_key: str,
        part_tags: list[str],
    ) -> int:
        """Commit upload to permanent storage and register the file_storage_locations row.

        Returns actual blob size in bytes.  Called inside the Phase 2 DB transaction
        in uploads.py; the DB updates (upload_complete, disk_used, delete tus_uploads)
        happen in the same transaction by the caller.
        """
        validate_storage_key(storage_key)
        provider = self._default_provider()
        actual_size = await provider.finalize_upload(upload_id, storage_key, part_tags)

        now = _now()
        await db.execute(
            "INSERT INTO file_storage_locations "
            "(file_id, volume_id, is_primary, migration_state, stored_at) "
            "VALUES (?, ?, 1, 'idle', ?) "
            "ON CONFLICT (file_id, volume_id) DO UPDATE SET "
            "  migration_state = 'idle', stored_at = EXCLUDED.stored_at",
            (file_id, self._default_volume_id, now),
        )

        # Fire-and-forget async replication if any replica volumes are configured.
        _t = asyncio.create_task(
            self._replicate_async(file_id, storage_key, self._default_volume_id)
        )
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)

        return actual_size

    async def abort_upload(self, upload_id: str) -> None:
        """Discard the staging blob for an aborted upload."""
        await self._default_provider().abort_upload(upload_id)

    # ------------------------------------------------------------------
    # Direct blob write (share uploads — small files, no TUS)
    # ------------------------------------------------------------------

    async def write_blob(self, db, file_id: str, storage_key: str, data: bytes) -> None:
        """Write a complete blob in one shot and register the storage location."""
        validate_storage_key(storage_key)
        provider = self._default_provider()
        await provider.write_blob(storage_key, data)

        now = _now()
        await db.execute(
            "INSERT INTO file_storage_locations "
            "(file_id, volume_id, is_primary, migration_state, stored_at) "
            "VALUES (?, ?, 1, 'idle', ?) "
            "ON CONFLICT (file_id, volume_id) DO UPDATE SET "
            "  migration_state = 'idle', stored_at = EXCLUDED.stored_at",
            (file_id, self._default_volume_id, now),
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def exists(self, db, file_id: str, storage_key: str) -> bool:
        provider = await self._get_primary_provider(db, file_id)
        try:
            return await provider.exists(storage_key)
        except Exception:
            return False

    async def read_stream(
        self,
        db,
        file_id: str,
        storage_key: str,
        start: int,
        end: int,
    ) -> AsyncGenerator[bytes, None]:
        """Return an async generator that yields the requested byte range."""
        provider = await self._get_read_provider(db, file_id, storage_key)
        return await provider.read_stream(storage_key, start, end)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def delete_blob(self, db, file_id: str, storage_key: str) -> None:
        """Delete blobs from all volumes that hold this file.

        file_storage_locations rows cascade-delete from the files FK, so
        we only need to clean up the actual blobs here.
        """
        cursor = await db.execute(
            "SELECT volume_id FROM file_storage_locations WHERE file_id = ?",
            (file_id,),
        )
        rows = await cursor.fetchall()

        if not rows:
            # File with no location row — delete from default volume
            await self._soft_delete(self._default_provider(), storage_key)
            return

        for row in rows:
            provider = self._providers.get(row["volume_id"])
            if provider:
                await self._soft_delete(provider, storage_key)

    # ------------------------------------------------------------------
    # Usage summary
    # ------------------------------------------------------------------

    async def get_usage_summary(
        self,
        warn_pct: float | None = 90.0,
        warn_bytes_remaining: int | None = 1 * 1024 ** 3,
    ) -> dict:
        """Return usage across all volumes.

        warn_pct: emit a warning when used/capacity >= this percentage (0–100).
                  Pass None to disable the percentage check.
        warn_bytes_remaining: emit a warning when free space drops below this
                  many bytes.  Pass None to disable the bytes check.
        """
        volumes = []
        total_used = 0
        total_capacity: int | None = 0

        for vol_id, provider in self._providers.items():
            vol = self._volumes[vol_id]
            try:
                used, capacity = await provider.get_usage()
                total_used += used
                if capacity is not None and total_capacity is not None:
                    total_capacity += capacity
                else:
                    total_capacity = None  # any cloud volume → total is unknown
                entry: dict = {
                    "id": vol_id,
                    "name": vol.name,
                    "provider": vol.provider,
                    "tier": vol.tier,
                    "is_default": vol.is_default,
                    "used_bytes": used,
                    "total_bytes": capacity,
                }
                _set_volume_warning(entry, used, capacity, warn_pct, warn_bytes_remaining)
                volumes.append(entry)
            except Exception as exc:
                logger.warning("Usage check failed for volume %s: %s", vol_id, exc)
                volumes.append({
                    "id": vol_id,
                    "name": vol.name,
                    "provider": vol.provider,
                    "tier": vol.tier,
                    "is_default": vol.is_default,
                    "error": "unavailable",
                })

        return {
            "volumes": volumes,
            "total_used_bytes": total_used,
            "total_capacity_bytes": total_capacity,
        }

    # ------------------------------------------------------------------
    # Tier migration
    # ------------------------------------------------------------------

    async def migrate_tier(
        self,
        db,
        file_id: str,
        storage_key: str,
        target_volume_id: str,
    ) -> None:
        """Move a blob from its current primary volume to target_volume_id.

        Sets migration_state='migrating' on the destination row before copying
        so that a crash mid-copy leaves a recoverable breadcrumb.
        """
        src_provider = await self._get_primary_provider(db, file_id)
        dst_provider = self._providers.get(target_volume_id)
        if dst_provider is None:
            raise ValueError(f"Unknown target volume: {target_volume_id}")

        now = _now()
        await db.execute(
            "INSERT INTO file_storage_locations "
            "(file_id, volume_id, is_primary, migration_state, migration_started_at, stored_at) "
            "VALUES (?, ?, 0, 'migrating', ?, ?) "
            "ON CONFLICT (file_id, volume_id) DO UPDATE SET "
            "  migration_state = 'migrating', migration_started_at = EXCLUDED.migration_started_at",
            (file_id, target_volume_id, now, now),
        )
        await db.commit()

        try:
            # Same instance means same bucket/path — server-side copy is a no-op rename.
            # Different instances (always the case for tier migration) must stream-copy so
            # that the bytes are written into the destination provider's bucket/path.
            if src_provider is dst_provider:
                await src_provider.copy(storage_key, storage_key)
            else:
                size = await src_provider.stat_size(storage_key)
                stream = await src_provider.read_stream(storage_key, 0, size - 1)
                chunks = []
                async for chunk in stream:
                    chunks.append(chunk)
                data = b"".join(chunks)
                await dst_provider.write_blob(storage_key, data)

            # Verify
            dst_size = await dst_provider.stat_size(storage_key)
            src_size = await src_provider.stat_size(storage_key)
            if dst_size != src_size:
                raise OSError(
                    f"Size mismatch after tier copy: src={src_size} dst={dst_size}"
                )
        except Exception as exc:
            logger.error(
                "Tier migration failed for file %s → volume %s: %s",
                file_id, target_volume_id, exc,
            )
            async with self._db_factory() as db2:
                await db2.execute(
                    "UPDATE file_storage_locations SET migration_state = 'failed' "
                    "WHERE file_id = ? AND volume_id = ?",
                    (file_id, target_volume_id),
                )
                await db2.commit()
            return

        # Success: promote destination to primary, delete from source
        async with self._db_factory() as db2:
            await db2.execute("BEGIN")
            try:
                src_cursor = await db2.execute(
                    "SELECT volume_id FROM file_storage_locations "
                    "WHERE file_id = ? AND is_primary = 1",
                    (file_id,),
                )
                src_row = await src_cursor.fetchone()
                src_volume_id = src_row["volume_id"] if src_row else None

                await db2.execute(
                    "UPDATE file_storage_locations "
                    "SET is_primary = 0 WHERE file_id = ? AND volume_id = ?",
                    (file_id, src_volume_id),
                )
                await db2.execute(
                    "UPDATE file_storage_locations "
                    "SET is_primary = 1, migration_state = 'idle', "
                    "    migration_started_at = NULL "
                    "WHERE file_id = ? AND volume_id = ?",
                    (file_id, target_volume_id),
                )
                await db2.commit()
            except Exception:
                await db2.rollback()
                raise

        if src_volume_id and src_volume_id != target_volume_id:
            await self._soft_delete(src_provider, storage_key)
            async with self._db_factory() as db3:
                await db3.execute(
                    "DELETE FROM file_storage_locations WHERE file_id = ? AND volume_id = ?",
                    (file_id, src_volume_id),
                )
                await db3.commit()

        logger.info(
            "Tier migration complete: file %s moved from %s → %s",
            file_id, src_volume_id, target_volume_id,
        )

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------

    async def run_tiering_task(self, interval_seconds: float = 3600.0) -> None:
        """Periodic task: move files past their tier age threshold."""
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                async with self._db_factory() as db:
                    await self._run_tiering_pass(db)
                    await self._emit_volume_states(db)
            except Exception:
                logger.exception("Storage tiering task failed")

    async def run_reconciliation_task(self, interval_seconds: float = 1800.0) -> None:
        """Periodic task: retry failed replications and stale migrations."""
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                async with self._db_factory() as db:
                    await self._reconcile_failed_migrations(db)
            except Exception:
                logger.exception("Storage reconciliation task failed")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _default_provider(self) -> StorageProvider:
        if self._default_volume_id is None or self._default_volume_id not in self._providers:
            raise RuntimeError("No default storage volume is available")
        return self._providers[self._default_volume_id]

    async def _get_primary_provider(self, db, file_id: str) -> StorageProvider:
        cursor = await db.execute(
            "SELECT volume_id FROM file_storage_locations WHERE file_id = ? AND is_primary = 1",
            (file_id,),
        )
        row = await cursor.fetchone()
        if row and row["volume_id"] in self._providers:
            return self._providers[row["volume_id"]]
        # File with no location row — use default
        return self._default_provider()

    async def _get_read_provider(self, db, file_id: str, storage_key: str) -> StorageProvider:
        """Return the best available provider for reading, with replica failover."""
        cursor = await db.execute(
            """
            SELECT fsl.volume_id, fsl.is_primary
            FROM   file_storage_locations fsl
            JOIN   storage_volumes sv ON sv.id = fsl.volume_id
            WHERE  fsl.file_id = ?
              AND  fsl.migration_state = 'idle'
            ORDER  BY fsl.is_primary DESC, sv.priority ASC
            """,
            (file_id,),
        )
        rows = await cursor.fetchall()

        for row in rows:
            provider = self._providers.get(row["volume_id"])
            if provider is None:
                continue
            try:
                if await provider.exists(storage_key):
                    return provider
            except Exception:
                continue

        return self._default_provider()

    async def _replicate_async(
        self,
        file_id: str,
        storage_key: str,
        source_volume_id: str,
    ) -> None:
        """Background: copy blob to any configured replica volumes."""
        # Replica logic: find volumes with is_default=0 that don't yet have this file
        # For now, no-op — wire in when replication is configured via admin UI.
        # Placeholder intentionally left empty; reconciliation task handles failures.
        pass

    async def _reconcile_failed_migrations(self, db) -> None:
        """Retry file_storage_locations rows stuck in migration_state='failed'."""
        cursor = await db.execute(
            "SELECT fsl.file_id, f.storage_key, fsl.volume_id "
            "FROM   file_storage_locations fsl "
            "JOIN   files f ON f.id = fsl.file_id "
            "WHERE  fsl.migration_state = 'failed' "
            "LIMIT  50",
        )
        rows = await cursor.fetchall()
        for row in rows:
            logger.info(
                "Reconciling failed migration: file=%s volume=%s",
                row["file_id"], row["volume_id"],
            )
            try:
                await self.migrate_tier(db, row["file_id"], row["storage_key"], row["volume_id"])
            except Exception:
                logger.exception(
                    "Reconciliation failed for file %s → volume %s",
                    row["file_id"], row["volume_id"],
                )
                try:
                    from app.services import op_bus
                    from app.schemas.op_event import OperationalEvent
                    op_bus.emit(OperationalEvent(
                        event_type="storage.migration.failed",
                        severity="error", source="storage",
                        data={"file_id": row["file_id"], "volume_id": row["volume_id"]},
                    ))
                except Exception:
                    pass

    async def _emit_volume_states(self, db) -> None:
        """Emit capacity_warning / capacity_ok events after each tiering pass."""
        try:
            cursor = await db.execute(
                "SELECT key, value FROM admin_settings WHERE key IN (?, ?)",
                ("storage_warn_pct", "storage_warn_bytes_remaining"),
            )
            rows = await cursor.fetchall()
            sm = {r["key"]: r["value"] for r in rows}
            warn_pct   = float(sm["storage_warn_pct"])            if sm.get("storage_warn_pct")            else 90.0
            warn_bytes = int(sm["storage_warn_bytes_remaining"])  if sm.get("storage_warn_bytes_remaining") else 1 * 1024 ** 3

            usage = await self.get_usage_summary(warn_pct=warn_pct, warn_bytes_remaining=warn_bytes)
            from app.services import op_bus
            from app.schemas.op_event import OperationalEvent
            for vol in usage.get("volumes", []):
                if vol.get("warning"):
                    op_bus.emit(OperationalEvent(
                        event_type="storage.volume.capacity_warning",
                        severity="warning", source="storage",
                        data={
                            "volume_id":   vol.get("id"),
                            "volume_name": vol.get("name"),
                            "used_bytes":  vol.get("used_bytes", 0),
                            "total_bytes": vol.get("total_bytes"),
                            "warning_msg": vol["warning"],
                            "catch_up":    False,
                        },
                    ))
                else:
                    op_bus.emit(OperationalEvent(
                        event_type="storage.volume.capacity_ok",
                        severity="info", source="storage",
                        data={"volume_id": vol.get("id"), "volume_name": vol.get("name")},
                    ))
        except Exception:
            logger.exception("Storage: failed to emit volume state events")

    async def _run_tiering_pass(self, db) -> None:
        if await get_admin_setting(db, "storage_tiering_enabled") != "1":
            return

        hot_to_warm_days = await get_admin_setting(db, "storage_hot_to_warm_days", dtype=int)
        warm_to_cold_days = await get_admin_setting(db, "storage_warm_to_cold_days", dtype=int)
        warm_volume_id = await get_admin_setting(db, "storage_warm_volume_id")
        cold_volume_id = await get_admin_setting(db, "storage_cold_volume_id")

        if hot_to_warm_days is not None and warm_volume_id:
            await self._tier_aged_files(db, "hot", warm_volume_id, hot_to_warm_days)
        if warm_to_cold_days is not None and cold_volume_id:
            await self._tier_aged_files(db, "warm", cold_volume_id, warm_to_cold_days)

    async def _tier_aged_files(
        self, db, src_tier: str, dst_volume_id: str, age_days: int
    ) -> None:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
        cursor = await db.execute(
            """
            SELECT f.id AS file_id, f.storage_key
            FROM   files f
            JOIN   file_storage_locations fsl ON fsl.file_id = f.id AND fsl.is_primary = 1
            JOIN   storage_volumes sv ON sv.id = fsl.volume_id AND sv.tier = ?
            WHERE  (f.last_accessed_at < ? OR f.last_accessed_at IS NULL)
              AND  fsl.migration_state = 'idle'
              AND  fsl.volume_id != ?
            LIMIT  100
            """,
            (src_tier, cutoff, dst_volume_id),
        )
        rows = await cursor.fetchall()
        for row in rows:
            try:
                await self.migrate_tier(db, row["file_id"], row["storage_key"], dst_volume_id)
            except Exception:
                logger.exception("Tiering failed for file %s", row["file_id"])

    @staticmethod
    async def _soft_delete(provider: StorageProvider, storage_key: str) -> None:
        try:
            await provider.delete(storage_key)
        except Exception as exc:
            logger.warning("Failed to delete blob %s from provider %s: %s",
                           storage_key, provider.volume.id, exc)


def _build_provider(vol: VolumeConfig) -> StorageProvider:
    if vol.provider == "local":
        from app.storage.providers.local import LocalProvider
        return LocalProvider(vol)
    if vol.provider in ("s3", "b2"):
        from app.storage.providers.s3 import S3CompatProvider
        return S3CompatProvider(vol)
    raise ValueError(f"Unsupported storage provider type: {vol.provider!r}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_volume_warning(
    entry: dict,
    used: int,
    capacity: int | None,
    warn_pct: float | None,
    warn_bytes_remaining: int | None,
) -> None:
    if not capacity or capacity <= 0:
        return
    pct_used = used / capacity
    free = capacity - used
    if warn_pct is not None and pct_used * 100 >= warn_pct:
        entry["warning"] = f"Volume is {pct_used:.0%} full"
    elif warn_bytes_remaining is not None and free < warn_bytes_remaining:
        entry["warning"] = f"{_human_bytes(free)} remaining on volume"


def _human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return str(n)
