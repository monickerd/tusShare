"""Abstract storage provider interface.

All provider backends (local filesystem, S3-compatible, future Azure/GCS)
implement this interface.  The StorageManager is the only caller; routes
never import providers directly.

Upload lifecycle maps onto the TUS protocol:
  begin_upload   → POST /uploads creates staging area
  write_chunk    → PATCH /uploads/{id} appends one encrypted chunk
  finalize_upload → final PATCH moves staging → permanent storage
  abort_upload   → DELETE /uploads/{id} discards staging

For local storage, write_chunk uses seek+write-at-offset (idempotent).
For S3-compatible storage, write_chunk calls UploadPart and returns an ETag;
finalize_upload calls CompleteMultipartUpload with the ordered ETag list.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncGenerator

_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def validate_storage_key(key: str) -> str:
    """Reject keys that could cause path traversal or shell injection.

    Accepts UUIDs (hex + hyphens) and URL-safe base64 tokens (A-Za-z0-9_-).
    Raises ValueError on anything else.
    """
    if not key or not _SAFE_KEY_RE.match(key):
        raise ValueError(f"Unsafe storage key: {key!r}")
    return key


@dataclass
class VolumeConfig:
    id: str
    name: str
    provider: str  # 'local' | 's3' | 'azure' | 'gcs' | 'b2'
    tier: str  # 'hot' | 'warm' | 'cold'
    is_default: bool
    priority: int
    config: dict = field(default_factory=dict)  # decrypted provider-specific config


class StorageProvider(ABC):
    """Abstract base for all storage backends."""

    def __init__(self, volume: VolumeConfig) -> None:
        self.volume = volume

    @property
    def is_local(self) -> bool:
        return self.volume.provider == "local"

    # --- Upload lifecycle ---

    @abstractmethod
    async def begin_upload(self, upload_id: str) -> None:
        """Prepare staging area for a new chunked upload."""

    @abstractmethod
    async def write_chunk(
        self,
        upload_id: str,
        part_number: int,
        offset: int,
        data: bytes,
    ) -> str | None:
        """Write one chunk.

        part_number: 1-based part index (used by S3 multipart).
        offset: byte offset in the final file (used by local seek+write).
        Returns an ETag string for multipart providers, None for local.
        """

    @abstractmethod
    async def finalize_upload(
        self,
        upload_id: str,
        storage_key: str,
        part_tags: list[str],
    ) -> int:
        """Commit the upload.  Moves staging → permanent storage.

        part_tags: ordered list of ETags from write_chunk calls (S3 only;
                   pass an empty list for local uploads).
        Returns the final blob size in bytes.
        """

    @abstractmethod
    async def abort_upload(self, upload_id: str) -> None:
        """Discard staging area for an aborted upload."""

    # --- Permanent storage ---

    @abstractmethod
    async def write_blob(self, storage_key: str, data: bytes) -> int:
        """Write a complete blob in one shot (used for small share uploads).

        Returns the number of bytes written.
        """

    @abstractmethod
    async def copy(self, src_key: str, dst_key: str) -> None:
        """Server-side copy (used for tier migration without re-download)."""

    @abstractmethod
    async def delete(self, storage_key: str) -> None:
        """Delete a blob.  No-op if the key does not exist."""

    @abstractmethod
    async def exists(self, storage_key: str) -> bool:
        """Return True if the blob exists."""

    @abstractmethod
    async def stat_size(self, storage_key: str) -> int:
        """Return the size of a blob in bytes."""

    @abstractmethod
    async def read_stream(
        self,
        storage_key: str,
        start: int,
        end: int,
    ) -> AsyncGenerator[bytes, None]:
        """Yield [start, end] bytes (inclusive) in chunks of up to 256 KB."""

    @abstractmethod
    async def get_usage(self) -> tuple[int, int | None]:
        """Return (used_bytes, total_bytes).  total is None for cloud providers."""
