"""S3-compatible storage provider (AWS S3, MinIO, Backblaze B2, Cloudflare R2).

Required config keys (stored encrypted in storage_volumes.config_enc):
  endpoint_url       URL of the S3-compatible endpoint
                     Leave empty for AWS S3 (boto3 uses the regional default)
  bucket             Bucket name
  access_key_id      Access key / key ID
  secret_access_key  Secret key
  region             AWS region (e.g. "us-east-1"; required for AWS, optional for MinIO)

Upload flow:
  begin_upload   → CreateMultipartUpload → stores multipart_upload_id in _pending
  write_chunk    → UploadPart → returns ETag
  finalize_upload → CompleteMultipartUpload with ordered ETag list
  abort_upload   → AbortMultipartUpload

For future Azure Blob and GCS providers, mirror this module:
  Azure: use azure-storage-blob asyncio SDK; StageBlock/CommitBlockList
  GCS:   use google-cloud-storage async client; resumable upload for large files

TODO (Azure): implement AzureBlobProvider in providers/azure.py
TODO (GCS):   implement GCSProvider in providers/gcs.py
"""

from __future__ import annotations

import logging
from typing import AsyncGenerator

from app.storage.base import StorageProvider, VolumeConfig, validate_storage_key

logger = logging.getLogger(__name__)


class S3CompatProvider(StorageProvider):
    def __init__(self, volume: VolumeConfig) -> None:
        super().__init__(volume)
        cfg = volume.config
        self._endpoint_url: str | None = cfg.get("endpoint_url") or None
        self._bucket: str = cfg["bucket"]
        self._region: str = cfg.get("region", "us-east-1")
        self._access_key_id: str = cfg["access_key_id"]
        self._secret_access_key: str = cfg["secret_access_key"]

        # Multipart upload state: {upload_id → s3_multipart_upload_id}
        # Process-local; aborted on restart (S3 aborts expire after 7 days by default).
        self._pending: dict[str, str] = {}

        self._aioboto3 = _require_aioboto3()

    def _session(self):
        return self._aioboto3.Session(
            aws_access_key_id=self._access_key_id,
            aws_secret_access_key=self._secret_access_key,
            region_name=self._region,
        )

    def _client(self):
        kwargs = {}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        return self._session().client("s3", **kwargs)

    # ------------------------------------------------------------------
    # Upload lifecycle
    # ------------------------------------------------------------------

    async def begin_upload(self, upload_id: str) -> None:
        async with self._client() as s3:
            resp = await s3.create_multipart_upload(Bucket=self._bucket, Key=upload_id)
        self._pending[upload_id] = resp["UploadId"]

    async def write_chunk(
        self,
        upload_id: str,
        part_number: int,
        offset: int,
        data: bytes,
    ) -> str | None:
        mpu_id = self._pending.get(upload_id)
        if mpu_id is None:
            raise RuntimeError(f"No active multipart upload for {upload_id}")

        async with self._client() as s3:
            resp = await s3.upload_part(
                Bucket=self._bucket,
                Key=upload_id,
                UploadId=mpu_id,
                PartNumber=part_number,
                Body=data,
            )
        return resp["ETag"]

    async def finalize_upload(
        self,
        upload_id: str,
        storage_key: str,
        part_tags: list[str],
    ) -> int:
        validate_storage_key(storage_key)
        mpu_id = self._pending.pop(upload_id, None)
        if mpu_id is None:
            raise RuntimeError(f"No active multipart upload to finalize for {upload_id}")

        parts = [
            {"PartNumber": i + 1, "ETag": etag}
            for i, etag in enumerate(part_tags)
        ]

        async with self._client() as s3:
            await s3.complete_multipart_upload(
                Bucket=self._bucket,
                Key=upload_id,
                UploadId=mpu_id,
                MultipartUpload={"Parts": parts},
            )
            # Rename staging key (upload_id) to permanent key (storage_key)
            if upload_id != storage_key:
                await s3.copy_object(
                    Bucket=self._bucket,
                    CopySource={"Bucket": self._bucket, "Key": upload_id},
                    Key=storage_key,
                )
                await s3.delete_object(Bucket=self._bucket, Key=upload_id)

            resp = await s3.head_object(Bucket=self._bucket, Key=storage_key)

        return resp["ContentLength"]

    async def abort_upload(self, upload_id: str) -> None:
        mpu_id = self._pending.pop(upload_id, None)
        if mpu_id is None:
            return
        try:
            async with self._client() as s3:
                await s3.abort_multipart_upload(
                    Bucket=self._bucket,
                    Key=upload_id,
                    UploadId=mpu_id,
                )
        except Exception as exc:
            logger.warning("S3 abort_multipart_upload failed for %s: %s", upload_id, exc)

    # ------------------------------------------------------------------
    # Direct blob write
    # ------------------------------------------------------------------

    async def write_blob(self, storage_key: str, data: bytes) -> int:
        validate_storage_key(storage_key)
        async with self._client() as s3:
            await s3.put_object(Bucket=self._bucket, Key=storage_key, Body=data)
        return len(data)

    # ------------------------------------------------------------------
    # Permanent storage operations
    # ------------------------------------------------------------------

    async def copy(self, src_key: str, dst_key: str) -> None:
        validate_storage_key(src_key)
        validate_storage_key(dst_key)
        async with self._client() as s3:
            await s3.copy_object(
                Bucket=self._bucket,
                CopySource={"Bucket": self._bucket, "Key": src_key},
                Key=dst_key,
            )

    async def delete(self, storage_key: str) -> None:
        validate_storage_key(storage_key)
        try:
            async with self._client() as s3:
                await s3.delete_object(Bucket=self._bucket, Key=storage_key)
        except Exception as exc:
            logger.warning("S3 delete failed for %s: %s", storage_key, exc)

    async def exists(self, storage_key: str) -> bool:
        validate_storage_key(storage_key)
        try:
            async with self._client() as s3:
                await s3.head_object(Bucket=self._bucket, Key=storage_key)
            return True
        except Exception:
            return False

    async def stat_size(self, storage_key: str) -> int:
        validate_storage_key(storage_key)
        async with self._client() as s3:
            resp = await s3.head_object(Bucket=self._bucket, Key=storage_key)
        return resp["ContentLength"]

    async def read_stream(
        self,
        storage_key: str,
        start: int,
        end: int,
    ) -> AsyncGenerator[bytes, None]:
        validate_storage_key(storage_key)
        return _s3_stream(self._client, self._bucket, storage_key, start, end)

    async def get_usage(self) -> tuple[int, int | None]:
        # S3 doesn't expose total capacity; estimate used via CloudWatch or list.
        # Returning 0, None means "unknown total, unknown used" — admin UI shows N/A.
        # A full ListObjectsV2 aggregate is too slow for a health check; operators
        # should use their S3 provider's native dashboard for capacity planning.
        return 0, None


def _require_aioboto3():
    try:
        import aioboto3
        return aioboto3
    except ImportError:
        raise RuntimeError(
            "aioboto3 is required for S3-compatible storage. "
            "Install it with: pip install aioboto3"
        )


async def _s3_stream(
    client_factory,
    bucket: str,
    storage_key: str,
    start: int,
    end: int,
) -> AsyncGenerator[bytes, None]:
    range_str = f"bytes={start}-{end}"
    async with client_factory() as s3:
        resp = await s3.get_object(Bucket=bucket, Key=storage_key, Range=range_str)
        body = resp["Body"]
        try:
            async for chunk in body.iter_chunks(chunk_size=256 * 1024):
                yield chunk
        finally:
            body.close()
