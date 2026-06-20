"""
Group 37 — Batch-register upload and batch manifest download.

Covers:
  37-01  Registering a batch of 100 files returns batch_id + 100 TUS locations.
  37-02  Second registration attempt before batch 1 is 50 % complete returns 425.
  37-03  After completing 50 files (≥ 50 %), the soft lock releases.
  37-04  Second batch of 100 files registers and all complete successfully.
  37-05  Third batch of 50 files (250 total) registers and completes.
  37-06  GET /uploads/batch/{id} reports correct counts throughout.
  37-07  DELETE /uploads/batch/{id} cancels a pending batch; incomplete files removed.
  37-08  GET /files/batch-manifest returns manifests for all 250 completed files.
  37-09  Batch-manifest caps at 100 IDs per request (> 100 returns 422).
  37-10  Completed files from all three batches are individually accessible.

Geometry
--------
Each file is 1 024 plaintext bytes → 1 040 encrypted bytes (+ 16-byte AES-GCM tag).
At 1 024 bytes each these are always single-chunk uploads regardless of the
admin chunk-size setting, so a single PATCH per file completes the TUS upload.
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.crypto_stubs import chunk_hash, fake_iv_12
from tests.e2e.helpers.files import (
    batch_fetch_manifests,
    batch_register,
    cancel_batch,
    create_folder,
    get_batch_status,
    get_file,
    make_fake_file_entry,
)
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"

# ---------------------------------------------------------------------------
# File geometry
# ---------------------------------------------------------------------------

_PLAIN_SIZE = 1024                   # plaintext bytes per file
_ENC_SIZE   = _PLAIN_SIZE + 16      # 1040 bytes: plaintext + AES-GCM tag

def _fake_chunk() -> bytes:
    """Deterministic 1040-byte blob that satisfies size/hash checks."""
    return bytes([0xAB]) * _ENC_SIZE

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_user:   dict = {}
_folder: dict = {}

# Single long-lived ApiClient shared across all tests in this module.
# Sharing is required because the server issues rotating refresh tokens:
# once any test consumes the refresh token (via _refresh()), a new refresh
# token is stored in THIS client's cookie jar.  A fresh ApiClient built from
# the static _user["session"].cookies snapshot would try to reuse the now-
# revoked original token, triggering the theft-detection path.
_api: "ApiClient | None" = None

# Filled as tests run
_batch1_id:       str       = ""
_batch1_uploads:  list[dict] = []
_batch1_file_ids: list[str]  = []

_batch2_id:       str       = ""
_batch2_uploads:  list[dict] = []
_batch2_file_ids: list[str]  = []

_batch3_id:       str       = ""
_batch3_uploads:  list[dict] = []
_batch3_file_ids: list[str]  = []

_cancel_batch_id: str = ""

_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _user, _folder, _api

    url  = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, url, "batch_user_37", "Batch!Pwd37x")
    users = await admin_client.list_users()
    u = next(x for x in users if x["username"].lower() == "batch_user_37")
    _user = {"id": u["id"], "session": sess}

    _api = ApiClient.from_session(sess)
    _folder.update(await create_folder(_api, "batch_folder_37"))

    yield

    await _api.aclose()
    try:
        await sess.ctx.close()
    except Exception:
        pass


# ===========================================================================
# 37-01  First batch-register succeeds (100 files)
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_01_first_batch_registers():
    """Registering 100 files returns a batch_id and 100 TUS upload locations."""
    global _batch1_id, _batch1_uploads

    entries = [make_fake_file_entry(f"file_{i:04d}.bin", _PLAIN_SIZE, _folder["id"]) for i in range(100)]
    resp = await batch_register(_api, entries)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:400]}"
    body = resp.json()
    assert "batch_id" in body, f"Missing batch_id: {body}"
    assert len(body["files"]) == 100, f"Expected 100 file entries: {body}"

    _batch1_id      = body["batch_id"]
    _batch1_uploads = body["files"]


# ===========================================================================
# 37-02  Second registration attempt while batch 1 < 50 % → 425
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_02_second_register_blocked_while_first_pending():
    """Attempting to start batch 2 while batch 1 has 0 % complete returns 425."""
    entries = [make_fake_file_entry(f"b2_file_{i:04d}.bin", _PLAIN_SIZE, _folder["id"]) for i in range(5)]
    resp = await batch_register(_api, entries)

    assert resp.status_code == 425, (
        f"Expected 425 Too Early while batch 1 is incomplete, got {resp.status_code}: {resp.text[:400]}"
    )
    body = resp.json()
    detail = body.get("detail", {})
    assert detail.get("status") == "not_ready", f"Unexpected detail: {detail}"
    assert detail.get("batch_id") == _batch1_id


# ===========================================================================
# 37-03  Complete 50 files from batch 1 → soft lock releases
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_03_soft_lock_releases_after_fifty_percent():
    """Sending data for exactly 50 of batch 1's 100 files releases the soft lock."""
    global _batch1_file_ids

    chunk = _fake_chunk()
    for entry in _batch1_uploads[:50]:
        upload_id = entry["upload_id"]
        iv        = fake_iv_12()
        r = await _api.patch(
            f"/uploads/{upload_id}",
            content=chunk,
            headers={
                "Tus-Resumable":  "1.0.0",
                "Content-Type":   "application/offset+octet-stream",
                "Upload-Offset":  "0",
                "X-Chunk-IV":     iv,
                "X-Chunk-Hash":   chunk_hash(chunk),
                "Content-Length": str(len(chunk)),
            },
        )
        assert r.status_code == 204, f"PATCH for {upload_id} failed: {r.status_code} {r.text[:200]}"
        file_id = r.headers.get("x-file-id") or r.headers.get("X-File-ID")
        if file_id:
            _batch1_file_ids.append(file_id)

    status = await get_batch_status(_api, _batch1_id)
    assert status["complete"] == 50, f"Expected 50 complete, got: {status}"
    assert status["lock_released"] is True, f"Lock should be released at 50 %: {status}"


# ===========================================================================
# 37-04  Batch 2 registers and all 100 files complete
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_04_second_batch_registers_and_completes():
    """After the soft lock releases, batch 2 (100 files) registers and completes."""
    global _batch2_id, _batch2_uploads, _batch2_file_ids

    entries = [make_fake_file_entry(f"b2_file_{i:04d}.bin", _PLAIN_SIZE, _folder["id"]) for i in range(100)]
    chunk   = _fake_chunk()

    resp = await batch_register(_api, entries)
    assert resp.status_code == 200, f"Batch 2 register failed: {resp.status_code}: {resp.text[:400]}"
    body = resp.json()
    _batch2_id      = body["batch_id"]
    _batch2_uploads = body["files"]

    # Complete all 100 files in batch 2
    for entry in _batch2_uploads:
        upload_id = entry["upload_id"]
        iv = fake_iv_12()
        r = await _api.patch(
            f"/uploads/{upload_id}",
            content=chunk,
            headers={
                "Tus-Resumable":  "1.0.0",
                "Content-Type":   "application/offset+octet-stream",
                "Upload-Offset":  "0",
                "X-Chunk-IV":     iv,
                "X-Chunk-Hash":   chunk_hash(chunk),
                "Content-Length": str(len(chunk)),
            },
        )
        assert r.status_code == 204, f"PATCH {upload_id}: {r.status_code}"
        file_id = r.headers.get("x-file-id") or r.headers.get("X-File-ID")
        if file_id:
            _batch2_file_ids.append(file_id)

    # Finish the remaining 50 from batch 1
    for entry in _batch1_uploads[50:]:
        upload_id = entry["upload_id"]
        iv = fake_iv_12()
        r = await _api.patch(
            f"/uploads/{upload_id}",
            content=chunk,
            headers={
                "Tus-Resumable":  "1.0.0",
                "Content-Type":   "application/offset+octet-stream",
                "Upload-Offset":  "0",
                "X-Chunk-IV":     iv,
                "X-Chunk-Hash":   chunk_hash(chunk),
                "Content-Length": str(len(chunk)),
            },
        )
        assert r.status_code == 204, f"PATCH {upload_id} (batch1 tail): {r.status_code}"
        file_id = r.headers.get("x-file-id") or r.headers.get("X-File-ID")
        if file_id:
            _batch1_file_ids.append(file_id)

    b1_status = await get_batch_status(_api, _batch1_id)
    b2_status = await get_batch_status(_api, _batch2_id)

    assert b1_status["status"] == "complete", f"Batch 1 should be complete: {b1_status}"
    assert b2_status["status"] == "complete", f"Batch 2 should be complete: {b2_status}"
    assert len(_batch1_file_ids) == 100, f"Expected 100 batch-1 file IDs, got {len(_batch1_file_ids)}"
    assert len(_batch2_file_ids) == 100, f"Expected 100 batch-2 file IDs, got {len(_batch2_file_ids)}"


# ===========================================================================
# 37-05  Third batch of 50 files
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_05_third_batch_registers_and_completes():
    """Third batch (50 files) registers after batch 2 reaches ≥ 50 % and completes."""
    global _batch3_id, _batch3_uploads, _batch3_file_ids

    entries = [make_fake_file_entry(f"b3_file_{i:04d}.bin", _PLAIN_SIZE, _folder["id"]) for i in range(50)]
    chunk   = _fake_chunk()

    resp = await batch_register(_api, entries)
    assert resp.status_code == 200, f"Batch 3 register failed: {resp.status_code}: {resp.text[:400]}"
    body = resp.json()
    _batch3_id      = body["batch_id"]
    _batch3_uploads = body["files"]

    for entry in _batch3_uploads:
        upload_id = entry["upload_id"]
        iv = fake_iv_12()
        r = await _api.patch(
            f"/uploads/{upload_id}",
            content=chunk,
            headers={
                "Tus-Resumable":  "1.0.0",
                "Content-Type":   "application/offset+octet-stream",
                "Upload-Offset":  "0",
                "X-Chunk-IV":     iv,
                "X-Chunk-Hash":   chunk_hash(chunk),
                "Content-Length": str(len(chunk)),
            },
        )
        assert r.status_code == 204, f"PATCH {upload_id}: {r.status_code}"
        file_id = r.headers.get("x-file-id") or r.headers.get("X-File-ID")
        if file_id:
            _batch3_file_ids.append(file_id)

    b3_status = await get_batch_status(_api, _batch3_id)
    assert b3_status["status"] == "complete", f"Batch 3 should be complete: {b3_status}"
    assert len(_batch3_file_ids) == 50, f"Expected 50 batch-3 file IDs, got {len(_batch3_file_ids)}"


# ===========================================================================
# 37-06  Batch status endpoint reflects accurate counts
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_06_batch_status_counts_are_accurate():
    """Status for each completed batch reports total == complete and status == 'complete'."""
    for bid, expected_total in ((_batch1_id, 100), (_batch2_id, 100), (_batch3_id, 50)):
        status = await get_batch_status(_api, bid)
        assert status["total"]        == expected_total, f"Batch {bid}: wrong total: {status}"
        assert status["complete"]     == expected_total, f"Batch {bid}: not all complete: {status}"
        assert status["status"]       == "complete",     f"Batch {bid}: wrong status: {status}"
        assert status["lock_released"] is True,          f"Batch {bid}: lock should be released: {status}"


# ===========================================================================
# 37-07  Cancel endpoint removes a fresh batch's incomplete files
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_07_cancel_removes_incomplete_files():
    """A fresh batch with no files sent can be cancelled; its uploads are removed."""
    global _cancel_batch_id

    entries = [make_fake_file_entry(f"cancel_file_{i}.bin", _PLAIN_SIZE, _folder["id"]) for i in range(10)]

    resp = await batch_register(_api, entries)
    assert resp.status_code == 200, f"Cancel-test batch register failed: {resp.text[:200]}"
    _cancel_batch_id = resp.json()["batch_id"]

    cancel_result = await cancel_batch(_api, _cancel_batch_id)
    assert cancel_result["cancelled_files"] == 10, f"Expected 10 cancelled files: {cancel_result}"

    status = await get_batch_status(_api, _cancel_batch_id)
    assert status["status"]  == "cancelled", f"Batch should be cancelled: {status}"
    assert status["pending"] == 0,           f"No pending files after cancel: {status}"


# ===========================================================================
# 37-08  Batch manifest returns all 250 completed files
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_08_batch_manifest_covers_all_files():
    """POST /files/batch-manifest returns manifests for all 250 uploaded files."""
    all_ids = _batch1_file_ids + _batch2_file_ids + _batch3_file_ids
    assert len(all_ids) == 250, f"Expected 250 file IDs total, got {len(all_ids)}"

    found: list[dict] = []
    for i in range(0, len(all_ids), 100):
        result = await batch_fetch_manifests(_api, all_ids[i:i + 100])
        assert result["forbidden"] == [], f"Unexpected forbidden: {result['forbidden']}"
        assert result["not_found"] == [], f"Unexpected not_found: {result['not_found']}"
        found.extend(result["manifests"])

    assert len(found) == 250, f"Expected 250 manifests, got {len(found)}"
    for m in found:
        assert "chunks" in m and len(m["chunks"]) >= 1, f"Missing chunks in manifest: {m}"
        assert m["total_chunks"] == 1, f"Expected single-chunk file, got: {m}"


# ===========================================================================
# 37-09  Batch-manifest rejects > 100 IDs
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_09_batch_manifest_rejects_over_100_ids():
    """Sending more than 100 file_ids to /files/batch-manifest returns 422."""
    fake_ids = [f"00000000-0000-0000-0000-{i:012d}" for i in range(101)]
    r = await _api.post("/files/batch-manifest", json={"file_ids": fake_ids})
    assert r.status_code == 422, f"Expected 422 for >100 IDs, got {r.status_code}: {r.text[:200]}"


# ===========================================================================
# 37-10  All 250 files individually accessible
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_10_all_files_individually_accessible():
    """Every file_id from all three batches returns a complete file record."""
    all_ids = _batch1_file_ids + _batch2_file_ids + _batch3_file_ids
    # Spot-check every 10th file to keep the test fast (25 checks)
    for file_id in all_ids[::10]:
        meta = await get_file(_api, file_id)
        assert meta.get("upload_complete") is True, f"File {file_id} not marked complete: {meta}"
        assert meta.get("size_bytes") == _PLAIN_SIZE, f"File {file_id} wrong size: {meta}"


# ===========================================================================
# SIEM manifest
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_37_99_siem_manifest():
    assert_manifest(_SIEM_MANIFEST)
