"""Azure Blob Storage provider.

Required config keys (stored encrypted in storage_volumes.config_enc):
  connection_string   Azure Storage Account connection string (from portal →
                      Storage Account → Access keys → Connection string)
  container_name      Blob container name

Upload lifecycle (Block Blob pattern):
  begin_upload    → no Azure API call; initialises Redis block-ID list
  write_chunk     → StageBlock with base64-encoded block ID; appends ID to list
  finalize_upload → CommitBlockList on staging blob → server-side copy to
                    permanent key → delete staging → return size
  abort_upload    → delete staging blob; clean up Redis key

Redis key: "azure:blocks:{upload_id}" (JSON array of block ID strings, TTL = 3600 s).
Falls back to in-process _blocks dict when Redis is not configured.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import AsyncGenerator

from app.storage.base import StorageProvider, VolumeConfig, validate_storage_key

logger = logging.getLogger(__name__)


class AzureBlobProvider(StorageProvider):
    def __init__(self, volume: VolumeConfig) -> None:
        super().__init__(volume)
        cfg = volume.config
        self._connection_string: str = cfg["connection_string"]
        self._container_name: str = cfg["container_name"]
        self._blocks: dict[str, list[str]] = {}
        _require_azure()

    def _service_client(self):
        from azure.storage.blob.aio import BlobServiceClient  # type: ignore[import]

        return BlobServiceClient.from_connection_string(self._connection_string)

    def _blob_client(self, service_client, blob_name: str):
        return service_client.get_blob_client(container=self._container_name, blob=blob_name)

    # ------------------------------------------------------------------
    # Redis-aware block-list helpers
    # ------------------------------------------------------------------

    async def _store_blocks(self, upload_id: str, block_ids: list[str]) -> None:
        from app.redis_client import get_redis

        r = get_redis()
        if r is not None:
            await r.set(f"azure:blocks:{upload_id}", json.dumps(block_ids), ex=3600)
        else:
            self._blocks[upload_id] = block_ids

    async def _get_blocks(self, upload_id: str) -> list[str]:
        from app.redis_client import get_redis

        r = get_redis()
        if r is not None:
            raw = await r.get(f"azure:blocks:{upload_id}")
            return json.loads(raw) if raw else []
        return list(self._blocks.get(upload_id, []))

    async def _del_blocks(self, upload_id: str) -> None:
        from app.redis_client import get_redis

        r = get_redis()
        if r is not None:
            await r.delete(f"azure:blocks:{upload_id}")
        self._blocks.pop(upload_id, None)

    # ------------------------------------------------------------------
    # Upload lifecycle
    # ------------------------------------------------------------------

    async def begin_upload(self, upload_id: str) -> None:
        await self._store_blocks(upload_id, [])

    async def write_chunk(
        self,
        upload_id: str,
        part_number: int,
        offset: int,
        data: bytes,
    ) -> str | None:
        block_id = base64.b64encode(str(part_number).zfill(6).encode()).decode()
        async with self._service_client() as svc:
            blob = self._blob_client(svc, upload_id)
            await blob.stage_block(block_id, data)

        block_ids = await self._get_blocks(upload_id)
        block_ids.append(block_id)
        await self._store_blocks(upload_id, block_ids)
        return block_id

    async def finalize_upload(
        self,
        upload_id: str,
        storage_key: str,
        part_tags: list[str],
    ) -> int:
        validate_storage_key(storage_key)
        # part_tags contains the block IDs returned by write_chunk in order
        block_ids = part_tags if part_tags else await self._get_blocks(upload_id)
        await self._del_blocks(upload_id)

        async with self._service_client() as svc:
            staging_blob = self._blob_client(svc, upload_id)
            await staging_blob.commit_block_list(block_ids)

            if upload_id != storage_key:
                perm_blob = self._blob_client(svc, storage_key)
                src_url = staging_blob.url
                await perm_blob.start_copy_from_url(src_url)
                await staging_blob.delete_blob()
                props = await perm_blob.get_blob_properties()
            else:
                props = await staging_blob.get_blob_properties()

        return props.size

    async def abort_upload(self, upload_id: str) -> None:
        await self._del_blocks(upload_id)
        try:
            async with self._service_client() as svc:
                blob = self._blob_client(svc, upload_id)
                await blob.delete_blob()
        except Exception as exc:
            logger.warning("Azure abort_upload failed for %s: %s", upload_id, exc)

    # ------------------------------------------------------------------
    # Direct blob write
    # ------------------------------------------------------------------

    async def write_blob(self, storage_key: str, data: bytes) -> int:
        validate_storage_key(storage_key)
        async with self._service_client() as svc:
            blob = self._blob_client(svc, storage_key)
            await blob.upload_blob(data, overwrite=True)
        return len(data)

    # ------------------------------------------------------------------
    # Permanent storage operations
    # ------------------------------------------------------------------

    async def copy(self, src_key: str, dst_key: str) -> None:
        validate_storage_key(src_key)
        validate_storage_key(dst_key)
        async with self._service_client() as svc:
            src_blob = self._blob_client(svc, src_key)
            dst_blob = self._blob_client(svc, dst_key)
            await dst_blob.start_copy_from_url(src_blob.url)

    async def delete(self, storage_key: str) -> None:
        validate_storage_key(storage_key)
        try:
            async with self._service_client() as svc:
                blob = self._blob_client(svc, storage_key)
                await blob.delete_blob()
        except Exception as exc:
            from azure.core.exceptions import ResourceNotFoundError  # type: ignore[import]

            if not isinstance(exc, ResourceNotFoundError):
                logger.warning("Azure delete failed for %s: %s", storage_key, exc)

    async def exists(self, storage_key: str) -> bool:
        validate_storage_key(storage_key)
        try:
            async with self._service_client() as svc:
                blob = self._blob_client(svc, storage_key)
                await blob.get_blob_properties()
            return True
        except Exception:
            return False

    async def stat_size(self, storage_key: str) -> int:
        validate_storage_key(storage_key)
        async with self._service_client() as svc:
            blob = self._blob_client(svc, storage_key)
            props = await blob.get_blob_properties()
        return props.size

    async def read_stream(
        self,
        storage_key: str,
        start: int,
        end: int,
    ) -> AsyncGenerator[bytes, None]:
        validate_storage_key(storage_key)
        return _azure_stream(self._service_client, self._container_name, storage_key, start, end)

    async def get_usage(self) -> tuple[int, int | None]:
        return 0, None


def _require_azure():
    try:
        import azure.storage.blob  # noqa: F401  type: ignore[import]
    except ImportError:
        raise RuntimeError(
            "azure-storage-blob is required for Azure Blob Storage. "
            "Install it with: pip install 'azure-storage-blob[aio]'"
        )


async def _azure_stream(
    service_client_factory,
    container_name: str,
    storage_key: str,
    start: int,
    end: int,
) -> AsyncGenerator[bytes, None]:
    length = end - start + 1
    async with service_client_factory() as svc:
        blob = svc.get_blob_client(container=container_name, blob=storage_key)
        stream = await blob.download_blob(offset=start, length=length)
        async for chunk in stream.chunks():
            yield chunk
