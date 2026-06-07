"""
Unit tests for storage provider Redis helpers and _build_provider routing.

Covers three independent concerns:

1. In-process fallback (no Redis configured)
   Each provider's upload-state helpers (_store_mpu / _get_mpu / _del_mpu for
   S3, _store_blocks / _get_blocks / _del_blocks for Azure, _store_session /
   _get_session / _del_session for GCS) fall back to an in-process dict when
   get_redis() returns None.  No cloud SDKs or running servers required.

2. Redis-backed path
   The same helpers store/retrieve/delete state in a fakeredis instance (an
   in-process pure-Python Redis emulator).  Verifies TTL is set, cross-worker
   isolation works, and cleanup is complete.

3. _build_provider routing
   The manager._build_provider() factory returns the correct class for each
   provider string without importing or initialising cloud SDKs (patched out).

Run with: pytest tests/unit/test_storage_providers.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ------------------------------------------------------------------
# Ensure backend/ is on sys.path (mirrors unit/conftest.py)
# ------------------------------------------------------------------
_backend = Path(__file__).resolve().parents[2] / "backend"
if str(_backend) not in sys.path:
    sys.path.insert(0, str(_backend))

from app.storage.base import VolumeConfig  # noqa: E402

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


def _vol(provider: str, config: dict | None = None) -> VolumeConfig:
    return VolumeConfig(
        id="test-vol-1",
        name="Test Volume",
        provider=provider,
        tier="hot",
        is_default=True,
        priority=10,
        config=config or {},
    )


# fakeredis is only available when installed; skip gracefully if absent.
try:
    import fakeredis.aioredis as _fakeredis_aio  # type: ignore[import]
    _FAKEREDIS_AVAILABLE = True
except ImportError:
    _FAKEREDIS_AVAILABLE = False

_requires_fakeredis = pytest.mark.skipif(
    not _FAKEREDIS_AVAILABLE,
    reason="fakeredis not installed — run: pip install fakeredis",
)


def _fake_redis():
    """Return a fresh in-process FakeRedis instance."""
    return _fakeredis_aio.FakeRedis(decode_responses=True)


# ==================================================================
# S3CompatProvider — _store_mpu / _get_mpu / _del_mpu
# ==================================================================

class TestS3MpuHelpers:
    """Tests for the S3 multipart-upload state helpers."""

    def _make_provider(self):
        """Build an S3CompatProvider with aioboto3 import patched out."""
        with patch("app.storage.providers.s3._require_aioboto3", return_value=MagicMock()):
            from app.storage.providers.s3 import S3CompatProvider
            return S3CompatProvider(_vol("s3", {
                "bucket": "test-bucket",
                "access_key_id": "key",
                "secret_access_key": "secret",
            }))

    # -- no-Redis fallback --

    def test_store_get_fallback(self):
        """_store_mpu / _get_mpu use in-process dict when Redis is None."""
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            _run(p._store_mpu("uid-1", "mpu-abc"))
            result = _run(p._get_mpu("uid-1"))
        assert result == "mpu-abc"
        assert p._pending["uid-1"] == "mpu-abc"

    def test_del_fallback_returns_id(self):
        """_del_mpu returns the mpu_id and removes it from _pending."""
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            _run(p._store_mpu("uid-2", "mpu-xyz"))
            returned = _run(p._del_mpu("uid-2"))
        assert returned == "mpu-xyz"
        assert "uid-2" not in p._pending

    def test_del_missing_fallback_returns_none(self):
        """_del_mpu on a missing upload_id returns None without error."""
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            result = _run(p._del_mpu("nonexistent"))
        assert result is None

    def test_get_missing_fallback_returns_none(self):
        """_get_mpu returns None when upload_id has no entry."""
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            result = _run(p._get_mpu("nonexistent"))
        assert result is None

    # -- Redis-backed path --

    @_requires_fakeredis
    def test_store_get_redis(self):
        """_store_mpu / _get_mpu round-trip through fakeredis."""
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_mpu("uid-r1", "mpu-redis"))
            result = _run(p._get_mpu("uid-r1"))
        assert result == "mpu-redis"
        assert "uid-r1" not in p._pending  # must NOT land in local dict

    @_requires_fakeredis
    def test_del_redis(self):
        """_del_mpu removes the key from Redis and returns the value."""
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_mpu("uid-r2", "mpu-del"))
            returned = _run(p._del_mpu("uid-r2"))
            still_there = _run(p._get_mpu("uid-r2"))
        assert returned == "mpu-del"
        assert still_there is None

    @_requires_fakeredis
    def test_redis_key_has_ttl(self):
        """Keys stored by _store_mpu must have a positive TTL."""
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_mpu("uid-r3", "mpu-ttl"))
            ttl = _run(r.ttl("s3:mpu:uid-r3"))
        assert ttl > 0, f"Expected positive TTL, got {ttl}"

    @_requires_fakeredis
    def test_redis_isolation_across_upload_ids(self):
        """Each upload_id is stored under a separate key — no cross-contamination."""
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_mpu("uid-a", "mpu-A"))
            _run(p._store_mpu("uid-b", "mpu-B"))
            a = _run(p._get_mpu("uid-a"))
            b = _run(p._get_mpu("uid-b"))
        assert a == "mpu-A"
        assert b == "mpu-B"


# ==================================================================
# AzureBlobProvider — _store_blocks / _get_blocks / _del_blocks
# ==================================================================

class TestAzureBlockHelpers:
    """Tests for the Azure block-list state helpers."""

    def _make_provider(self):
        with patch("app.storage.providers.azure._require_azure"):
            from app.storage.providers.azure import AzureBlobProvider
            return AzureBlobProvider(_vol("azure", {
                "connection_string": "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=fake;BlobEndpoint=http://localhost:10000/devstoreaccount1;",
                "container_name": "test-container",
            }))

    # -- no-Redis fallback --

    def test_store_get_fallback(self):
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            _run(p._store_blocks("uid-1", ["blk-A", "blk-B"]))
            result = _run(p._get_blocks("uid-1"))
        assert result == ["blk-A", "blk-B"]

    def test_append_and_retrieve_fallback(self):
        """Simulates sequential write_chunk block-ID accumulation."""
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            _run(p._store_blocks("uid-2", []))
            ids = _run(p._get_blocks("uid-2"))
            ids.append("blk-1")
            _run(p._store_blocks("uid-2", ids))
            ids = _run(p._get_blocks("uid-2"))
            ids.append("blk-2")
            _run(p._store_blocks("uid-2", ids))
            final = _run(p._get_blocks("uid-2"))
        assert final == ["blk-1", "blk-2"]

    def test_del_fallback(self):
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            _run(p._store_blocks("uid-3", ["blk-X"]))
            _run(p._del_blocks("uid-3"))
            result = _run(p._get_blocks("uid-3"))
        assert result == []

    def test_get_missing_returns_empty_list(self):
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            result = _run(p._get_blocks("nonexistent"))
        assert result == []

    # -- Redis-backed path --

    @_requires_fakeredis
    def test_store_get_redis(self):
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_blocks("uid-r1", ["rblk-1", "rblk-2"]))
            result = _run(p._get_blocks("uid-r1"))
        assert result == ["rblk-1", "rblk-2"]
        assert "uid-r1" not in p._blocks

    @_requires_fakeredis
    def test_del_redis(self):
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_blocks("uid-r2", ["blk-del"]))
            _run(p._del_blocks("uid-r2"))
            result = _run(p._get_blocks("uid-r2"))
        assert result == []

    @_requires_fakeredis
    def test_redis_key_has_ttl(self):
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_blocks("uid-r3", ["blk-ttl"]))
            ttl = _run(r.ttl("azure:blocks:uid-r3"))
        assert ttl > 0

    @_requires_fakeredis
    def test_json_roundtrip_preserves_order(self):
        """Block IDs must survive JSON serialisation in the correct order."""
        p = self._make_provider()
        r = _fake_redis()
        block_ids = [f"blk-{i:06d}" for i in range(20)]
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_blocks("uid-r4", block_ids))
            result = _run(p._get_blocks("uid-r4"))
        assert result == block_ids


# ==================================================================
# GCSProvider — _store_session / _get_session / _del_session
# ==================================================================

class TestGCSSessionHelpers:
    """Tests for the GCS resumable-upload session-URI state helpers."""

    def _make_provider(self):
        with patch("app.storage.providers.gcs._require_gcs"):
            from app.storage.providers.gcs import GCSProvider
            return GCSProvider(_vol("gcs", {
                "project_id": "test-project",
                "bucket_name": "test-bucket",
                "service_account_json": '{"type":"service_account"}',
            }))

    SESSION_URI = "https://storage.googleapis.com/upload/storage/v1/b/test-bucket/o?uploadType=resumable&upload_id=fake-session-id"

    # -- no-Redis fallback --

    def test_store_get_fallback(self):
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            _run(p._store_session("uid-1", self.SESSION_URI))
            result = _run(p._get_session("uid-1"))
        assert result == self.SESSION_URI
        assert p._pending["uid-1"] == self.SESSION_URI

    def test_del_fallback_returns_uri(self):
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            _run(p._store_session("uid-2", self.SESSION_URI))
            returned = _run(p._del_session("uid-2"))
        assert returned == self.SESSION_URI
        assert "uid-2" not in p._pending

    def test_del_missing_returns_none(self):
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            result = _run(p._del_session("nonexistent"))
        assert result is None

    def test_get_missing_returns_none(self):
        p = self._make_provider()
        with patch("app.redis_client.get_redis", return_value=None):
            result = _run(p._get_session("nonexistent"))
        assert result is None

    # -- Redis-backed path --

    @_requires_fakeredis
    def test_store_get_redis(self):
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_session("uid-r1", self.SESSION_URI))
            result = _run(p._get_session("uid-r1"))
        assert result == self.SESSION_URI
        assert "uid-r1" not in p._pending

    @_requires_fakeredis
    def test_del_redis(self):
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_session("uid-r2", self.SESSION_URI))
            returned = _run(p._del_session("uid-r2"))
            still_there = _run(p._get_session("uid-r2"))
        assert returned == self.SESSION_URI
        assert still_there is None

    @_requires_fakeredis
    def test_redis_key_has_ttl(self):
        p = self._make_provider()
        r = _fake_redis()
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._store_session("uid-r3", self.SESSION_URI))
            ttl = _run(r.ttl("gcs:session:uid-r3"))
        assert ttl > 0

    @_requires_fakeredis
    def test_del_also_clears_local_pending(self):
        """_del_session must clean both Redis and the local fallback dict."""
        p = self._make_provider()
        r = _fake_redis()
        # Seed local dict directly (simulates a previous no-Redis write)
        p._pending["uid-mixed"] = self.SESSION_URI
        with patch("app.redis_client.get_redis", return_value=r):
            _run(p._del_session("uid-mixed"))
        assert "uid-mixed" not in p._pending


# ==================================================================
# _build_provider routing
# ==================================================================

class TestBuildProvider:
    """_build_provider must return the correct class for every provider string."""

    def _build(self, provider: str, config: dict | None = None):
        from app.storage import manager as _mgr
        return _mgr._build_provider(_vol(provider, config or {}))

    def test_local_returns_local_provider(self):
        from app.storage.providers.local import LocalProvider
        result = self._build("local")
        assert isinstance(result, LocalProvider)

    def test_s3_returns_s3_provider(self):
        with patch("app.storage.providers.s3._require_aioboto3", return_value=MagicMock()):
            from app.storage.providers.s3 import S3CompatProvider
            result = self._build("s3", {
                "bucket": "b", "access_key_id": "k", "secret_access_key": "s"
            })
        assert isinstance(result, S3CompatProvider)

    def test_b2_returns_s3_provider(self):
        """Backblaze B2 uses the S3-compatible provider."""
        with patch("app.storage.providers.s3._require_aioboto3", return_value=MagicMock()):
            from app.storage.providers.s3 import S3CompatProvider
            result = self._build("b2", {
                "bucket": "b", "access_key_id": "k", "secret_access_key": "s"
            })
        assert isinstance(result, S3CompatProvider)

    def test_azure_returns_azure_provider(self):
        with patch("app.storage.providers.azure._require_azure"):
            from app.storage.providers.azure import AzureBlobProvider
            result = self._build("azure", {
                "connection_string": "fake", "container_name": "c"
            })
        assert isinstance(result, AzureBlobProvider)

    def test_gcs_returns_gcs_provider(self):
        with patch("app.storage.providers.gcs._require_gcs"):
            from app.storage.providers.gcs import GCSProvider
            result = self._build("gcs", {
                "project_id": "p",
                "bucket_name": "b",
                "service_account_json": "{}",
            })
        assert isinstance(result, GCSProvider)

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unsupported storage provider"):
            self._build("hdfs")
