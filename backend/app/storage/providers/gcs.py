"""Google Cloud Storage provider.

Required config keys (stored encrypted in storage_volumes.config_enc):
  project_id            GCP project ID
  bucket_name           GCS bucket name
  service_account_json  Full JSON string of a service account key with the
                        Storage Object Admin role on the target bucket

Upload lifecycle (resumable upload):
  begin_upload    → initiate_resumable_upload() → store session URI in Redis
  write_chunk     → PUT to session URI with Content-Range header via httpx
  finalize_upload → final PUT closes session; server-side copy staging → perm key;
                    delete staging; return size
  abort_upload    → DELETE request to session URI; clean up Redis key

Redis key: "gcs:session:{upload_id}" (session URI string, TTL = 3600 s).
Falls back to in-process _pending dict when Redis is not configured.

The google-cloud-storage SDK is synchronous; all blocking calls are wrapped in
asyncio.to_thread.  Chunk PUTs use httpx.AsyncClient for native async I/O.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator

from app.storage.base import StorageProvider, VolumeConfig, validate_storage_key

logger = logging.getLogger(__name__)

_CHUNK = 256 * 1024  # 256 KB read chunk for streaming


class GCSProvider(StorageProvider):
    def __init__(self, volume: VolumeConfig) -> None:
        super().__init__(volume)
        cfg = volume.config
        self._project_id: str = cfg["project_id"]
        self._bucket_name: str = cfg["bucket_name"]
        self._sa_json: str = cfg["service_account_json"]
        self._pending: dict[str, str] = {}
        _require_gcs()

    def _client(self):
        from google.cloud import storage as gcs  # type: ignore[import]
        from google.oauth2 import service_account  # type: ignore[import]
        info = json.loads(self._sa_json)
        creds = service_account.Credentials.from_service_account_info(
            info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        return gcs.Client(project=self._project_id, credentials=creds)

    def _bucket(self, client):
        return client.bucket(self._bucket_name)

    # ------------------------------------------------------------------
    # Redis-aware resumable-session helpers
    # ------------------------------------------------------------------

    async def _store_session(self, upload_id: str, session_uri: str) -> None:
        from app.redis_client import get_redis
        r = get_redis()
        if r is not None:
            await r.set(f"gcs:session:{upload_id}", session_uri, ex=3600)
        else:
            self._pending[upload_id] = session_uri

    async def _get_session(self, upload_id: str) -> str | None:
        from app.redis_client import get_redis
        r = get_redis()
        if r is not None:
            return await r.get(f"gcs:session:{upload_id}")
        return self._pending.get(upload_id)

    async def _del_session(self, upload_id: str) -> str | None:
        from app.redis_client import get_redis
        r = get_redis()
        session_uri: str | None = None
        if r is not None:
            session_uri = await r.get(f"gcs:session:{upload_id}")
            await r.delete(f"gcs:session:{upload_id}")
        session_uri = session_uri or self._pending.pop(upload_id, None)
        return session_uri

    # ------------------------------------------------------------------
    # Upload lifecycle
    # ------------------------------------------------------------------

    async def begin_upload(self, upload_id: str) -> None:
        def _initiate():
            client = self._client()
            bucket = self._bucket(client)
            blob = bucket.blob(upload_id)
            return blob.initiate_resumable_upload(
                content_type="application/octet-stream"
            )

        session_uri = await asyncio.to_thread(_initiate)
        await self._store_session(upload_id, session_uri)

    async def write_chunk(
        self,
        upload_id: str,
        part_number: int,
        offset: int,
        data: bytes,
    ) -> str | None:
        session_uri = await self._get_session(upload_id)
        if session_uri is None:
            raise RuntimeError(f"No active GCS resumable upload for {upload_id}")

        end = offset + len(data) - 1
        headers = {
            "Content-Range": f"bytes {offset}-{end}/*",
            "Content-Type": "application/octet-stream",
        }
        import httpx  # type: ignore[import]
        async with httpx.AsyncClient() as http:
            resp = await http.put(session_uri, content=data, headers=headers)
            if resp.status_code not in (200, 201, 308):
                raise RuntimeError(
                    f"GCS write_chunk failed for {upload_id}: HTTP {resp.status_code}"
                )
        return None

    async def finalize_upload(
        self,
        upload_id: str,
        storage_key: str,
        part_tags: list[str],
    ) -> int:
        validate_storage_key(storage_key)
        session_uri = await self._get_session(upload_id)
        if session_uri is None:
            raise RuntimeError(f"No active GCS resumable upload to finalize for {upload_id}")

        # Retrieve total size to send the closing Content-Range
        def _get_size():
            client = self._client()
            blob = self._bucket(client).blob(upload_id)
            # A HEAD on the session URI gives us the offset; we can also query
            # blob properties if the final chunk already closed the session.
            try:
                blob.reload()
                return blob.size
            except Exception:
                return None

        total_size = await asyncio.to_thread(_get_size)

        if total_size is None:
            # Session not yet closed — send zero-byte closing request
            import httpx  # type: ignore[import]
            async with httpx.AsyncClient() as http:
                query_resp = await http.put(
                    session_uri,
                    headers={"Content-Range": "bytes */*"},
                )
                if query_resp.status_code == 308:
                    # In progress — shouldn't happen after all chunks written
                    raise RuntimeError(
                        f"GCS session {upload_id} still in progress during finalize"
                    )

        await self._del_session(upload_id)

        def _copy_and_stat():
            client = self._client()
            bucket = self._bucket(client)
            staging_blob = bucket.blob(upload_id)
            if upload_id != storage_key:
                perm_blob = bucket.copy_blob(staging_blob, bucket, storage_key)
                staging_blob.delete()
                perm_blob.reload()
                return perm_blob.size
            else:
                staging_blob.reload()
                return staging_blob.size

        size = await asyncio.to_thread(_copy_and_stat)
        return size

    async def abort_upload(self, upload_id: str) -> None:
        session_uri = await self._del_session(upload_id)
        if session_uri is not None:
            try:
                import httpx  # type: ignore[import]
                async with httpx.AsyncClient() as http:
                    await http.delete(session_uri)
            except Exception as exc:
                logger.warning("GCS abort session DELETE failed for %s: %s", upload_id, exc)
        # Best-effort: also delete the staging blob in case it was committed
        try:
            def _del():
                client = self._client()
                bucket = self._bucket(client)
                bucket.blob(upload_id).delete()
            await asyncio.to_thread(_del)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Direct blob write
    # ------------------------------------------------------------------

    async def write_blob(self, storage_key: str, data: bytes) -> int:
        validate_storage_key(storage_key)

        def _upload():
            client = self._client()
            blob = self._bucket(client).blob(storage_key)
            blob.upload_from_string(data)

        await asyncio.to_thread(_upload)
        return len(data)

    # ------------------------------------------------------------------
    # Permanent storage operations
    # ------------------------------------------------------------------

    async def copy(self, src_key: str, dst_key: str) -> None:
        validate_storage_key(src_key)
        validate_storage_key(dst_key)

        def _copy():
            client = self._client()
            bucket = self._bucket(client)
            src_blob = bucket.blob(src_key)
            bucket.copy_blob(src_blob, bucket, dst_key)

        await asyncio.to_thread(_copy)

    async def delete(self, storage_key: str) -> None:
        validate_storage_key(storage_key)

        def _del():
            try:
                client = self._client()
                self._bucket(client).blob(storage_key).delete()
            except Exception as exc:
                from google.cloud.exceptions import NotFound  # type: ignore[import]
                if not isinstance(exc, NotFound):
                    logger.warning("GCS delete failed for %s: %s", storage_key, exc)

        await asyncio.to_thread(_del)

    async def exists(self, storage_key: str) -> bool:
        validate_storage_key(storage_key)

        def _exists():
            client = self._client()
            return self._bucket(client).blob(storage_key).exists()

        return await asyncio.to_thread(_exists)

    async def stat_size(self, storage_key: str) -> int:
        validate_storage_key(storage_key)

        def _stat():
            client = self._client()
            blob = self._bucket(client).blob(storage_key)
            blob.reload()
            return blob.size

        return await asyncio.to_thread(_stat)

    async def read_stream(
        self,
        storage_key: str,
        start: int,
        end: int,
    ) -> AsyncGenerator[bytes, None]:
        validate_storage_key(storage_key)
        return _gcs_stream(self._client, self._bucket_name, storage_key, start, end)

    async def get_usage(self) -> tuple[int, int | None]:
        return 0, None


def _require_gcs():
    try:
        from google.cloud import storage  # noqa: F401  type: ignore[import]
    except ImportError:
        raise RuntimeError(
            "google-cloud-storage is required for GCS storage. "
            "Install it with: pip install google-cloud-storage"
        )


async def _gcs_stream(
    client_factory,
    bucket_name: str,
    storage_key: str,
    start: int,
    end: int,
) -> AsyncGenerator[bytes, None]:
    def _download():
        client = client_factory()
        blob = client.bucket(bucket_name).blob(storage_key)
        return blob.download_as_bytes(start=start, end=end)

    data = await asyncio.to_thread(_download)
    pos = 0
    while pos < len(data):
        chunk = data[pos : pos + _CHUNK]
        yield chunk
        pos += len(chunk)
