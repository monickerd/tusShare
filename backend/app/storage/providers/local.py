"""Local filesystem storage provider.

Staging blobs are written to UPLOADS_DIR using seek+write-at-offset (idempotent
for TUS chunk retransmit).  On finalize, the staging blob is renamed (or
shutil.move'd across devices) into FILES_DIR under storage_key.

Page-cache eviction is handled internally via fdatasync + posix_fadvise, capped
to settings.UPLOAD_EVICT_STRIDE_MB per concurrent upload.  On platforms that
don't support posix_fadvise (Windows, macOS) the calls are silently skipped.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import AsyncGenerator

from app.config import settings
from app.services import live_settings
from app.storage.base import StorageProvider, VolumeConfig, validate_storage_key

logger = logging.getLogger(__name__)

# Tracks {upload_id → bytes_evicted_so_far} for stride-based cache eviction.
# Process-local fallback for upload eviction stride tracking.
# When Redis is configured, Redis HASH is used so offsets are shared across workers.
_evict_offsets: dict[str, int] = {}
_EVICT_REDIS_KEY = "evict_offsets"


async def _get_evict_offset(upload_id: str) -> int:
    from app.redis_client import get_redis

    r = get_redis()
    if r is not None:
        try:
            val = await r.hget(_EVICT_REDIS_KEY, upload_id)
            return int(val) if val is not None else 0
        except Exception:
            pass
    return _evict_offsets.get(upload_id, 0)


async def _set_evict_offset(upload_id: str, value: int) -> None:
    from app.redis_client import get_redis

    r = get_redis()
    if r is not None:
        try:
            await r.hset(_EVICT_REDIS_KEY, upload_id, value)
            return
        except Exception:
            pass
    _evict_offsets[upload_id] = value


async def _del_evict_offset(upload_id: str) -> None:
    from app.redis_client import get_redis

    r = get_redis()
    if r is not None:
        try:
            await r.hdel(_EVICT_REDIS_KEY, upload_id)
            return
        except Exception:
            pass
    _evict_offsets.pop(upload_id, None)


class LocalProvider(StorageProvider):
    def __init__(self, volume: VolumeConfig) -> None:
        super().__init__(volume)
        # Allow per-volume path overrides via config; fall back to global settings
        cfg = volume.config
        self._files_dir = Path(cfg.get("files_dir", str(settings.FILES_DIR)))
        self._uploads_dir = Path(cfg.get("uploads_dir", str(settings.UPLOADS_DIR)))

    # ------------------------------------------------------------------
    # Upload lifecycle
    # ------------------------------------------------------------------

    async def begin_upload(self, upload_id: str) -> None:
        # Staging file is created implicitly on first write_chunk call.
        # Nothing to do here for local storage.
        pass

    async def write_chunk(
        self,
        upload_id: str,
        part_number: int,
        offset: int,
        data: bytes,
    ) -> str | None:
        blob = self._uploads_dir / upload_id
        try:
            await asyncio.to_thread(_write_at, blob, offset, data)
        except OSError as exc:
            raise OSError(f"Local write_chunk failed for {upload_id}: {exc}") from exc

        new_offset = offset + len(data)
        evict_stride = live_settings.get_int("upload_evict_stride_mb", settings.UPLOAD_EVICT_STRIDE_MB) * 1024 * 1024
        if evict_stride > 0:
            last_evicted = await _get_evict_offset(upload_id)
            if new_offset - last_evicted >= evict_stride:
                try:
                    await asyncio.to_thread(_stride_evict, blob, new_offset)
                    await _set_evict_offset(upload_id, new_offset)
                except Exception:
                    pass  # eviction is best-effort

        return None  # local provider has no ETag concept

    async def finalize_upload(
        self,
        upload_id: str,
        storage_key: str,
        part_tags: list[str],
    ) -> int:
        validate_storage_key(storage_key)
        src = self._uploads_dir / upload_id
        dst = self._files_dir / storage_key

        def _move_and_sync():
            try:
                src.rename(dst)
            except OSError:
                shutil.move(str(src), str(dst))
            try:
                with open(dst, "r+b") as f:
                    os.fdatasync(f.fileno())
                    os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            except (AttributeError, OSError):
                pass
            return dst.stat().st_size

        try:
            size = await asyncio.to_thread(_move_and_sync)
        except OSError as exc:
            raise OSError(f"Local finalize failed for {upload_id}: {exc}") from exc
        finally:
            await _del_evict_offset(upload_id)

        return size

    async def abort_upload(self, upload_id: str) -> None:
        blob = self._uploads_dir / upload_id

        def _remove():
            try:
                blob.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("Failed to remove staging blob %s: %s", upload_id, exc)

        await asyncio.to_thread(_remove)
        await _del_evict_offset(upload_id)

    # ------------------------------------------------------------------
    # Direct blob write (share uploads)
    # ------------------------------------------------------------------

    async def write_blob(self, storage_key: str, data: bytes) -> int:
        validate_storage_key(storage_key)
        path = self._files_dir / storage_key
        await asyncio.to_thread(path.write_bytes, data)
        return len(data)

    # ------------------------------------------------------------------
    # Permanent storage operations
    # ------------------------------------------------------------------

    async def copy(self, src_key: str, dst_key: str) -> None:
        validate_storage_key(src_key)
        validate_storage_key(dst_key)
        src = self._files_dir / src_key
        dst = self._files_dir / dst_key
        await asyncio.to_thread(shutil.copy2, str(src), str(dst))

    async def delete(self, storage_key: str) -> None:
        validate_storage_key(storage_key)
        path = self._files_dir / storage_key

        def _unlink():
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("Failed to delete blob %s: %s", storage_key, exc)

        await asyncio.to_thread(_unlink)

    async def exists(self, storage_key: str) -> bool:
        validate_storage_key(storage_key)
        path = self._files_dir / storage_key
        return await asyncio.to_thread(path.exists)

    async def stat_size(self, storage_key: str) -> int:
        validate_storage_key(storage_key)
        path = self._files_dir / storage_key
        return await asyncio.to_thread(lambda: path.stat().st_size)

    async def read_stream(
        self,
        storage_key: str,
        start: int,
        end: int,
    ) -> AsyncGenerator[bytes, None]:
        validate_storage_key(storage_key)
        path = self._files_dir / storage_key
        return _local_stream(path, start, end)

    async def get_usage(self) -> tuple[int, int | None]:
        def _du():
            return shutil.disk_usage(str(self._files_dir))

        try:
            du = await asyncio.to_thread(_du)
            return du.used, du.total
        except OSError:
            return 0, 0


# ------------------------------------------------------------------
# Module-level helpers (avoid repeated lambda closures in hot path)
# ------------------------------------------------------------------


def _write_at(path: Path, offset: int, data: bytes) -> None:
    """Seek to offset, write data, truncate beyond end. Idempotent."""
    mode = "r+b" if path.exists() else "wb"
    with open(path, mode) as f:
        f.seek(offset)
        f.write(data)
        f.truncate()


def _stride_evict(path: Path, up_to: int) -> None:
    """fdatasync then posix_fadvise(DONTNEED) to evict clean pages."""
    try:
        with open(path, "r+b") as f:
            os.fdatasync(f.fileno())
            os.posix_fadvise(f.fileno(), 0, up_to, os.POSIX_FADV_DONTNEED)
    except (AttributeError, OSError):
        pass


async def _local_stream(
    path: Path,
    start: int,
    end: int,
) -> AsyncGenerator[bytes, None]:
    READ_SIZE = 256 * 1024
    pos = start
    remaining = end - start + 1

    def _read(p: int, n: int) -> bytes:
        with open(path, "rb") as f:
            f.seek(p)
            return f.read(n)

    while remaining > 0:
        to_read = min(READ_SIZE, remaining)
        data = await asyncio.to_thread(_read, pos, to_read)
        if not data:
            break
        yield data
        pos += len(data)
        remaining -= len(data)
