"""
Group 22 — Server-enforced chunk size.

Tests the two enforcement points added in Phase 2 Tier 2, plus the public
endpoint that exposes the current value to unauthenticated clients.

Enforcement points
------------------
  1. Upload creation (POST /uploads): the chunk_size in the client's
     Upload-Metadata must match the admin-configured default_chunk_size.
     Mismatches are rejected with 400 before any data is written.

  2. Per-chunk body (PATCH /uploads/{id}): each non-final chunk's byte length
     must equal the stored chunk_size + 16 (AES-GCM tag overhead).  The stored
     value comes from the files row created at upload start, not the current
     admin setting — so changing the setting mid-upload does not break
     in-flight uploads.

Public-settings endpoint
------------------------
  GET /auth/public-settings is unauthenticated and exposes the current
  chunk_size so the frontend can read it on startup without a session.

Tests
-----
  22-01  GET /auth/public-settings returns chunk_size matching the admin setting
  22-02  Changing default_chunk_size in admin settings is reflected in /auth/public-settings
  22-03  POST /uploads with mismatched chunk_size metadata → 400 "invalid chunk_size"
  22-04  Non-final chunk with wrong body size → 400 "Unexpected chunk size"

Test 22-04 notes
----------------
To exercise the non-final chunk path, the test temporarily sets
default_chunk_size to the minimum valid value (65536 bytes), creates an upload
totalling 65652 bytes (two chunks needed), then sends a first PATCH with a
deliberately wrong body size.  The original chunk size is restored in a
try/finally block to avoid cross-test contamination.
"""

from __future__ import annotations

import base64

import httpx
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.crypto_stubs import chunk_hash, fake_aes256_key, fake_iv_12
from tests.e2e.helpers.files import _SERVER_DEFAULT_CHUNK_SIZE
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_user: dict = {}   # regular user for upload tests

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# Chunk size enforcement returns 400 (not 403), so auth.forbidden is not
# emitted.  No other SIEM-instrumented paths are exercised here.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enc(s: str) -> str:
    """Base64-encode a string value for TUS Upload-Metadata."""
    return base64.b64encode(s.encode()).decode()


async def _start_upload(
    api: ApiClient,
    *,
    chunk_size: int,
    total_size: int,
    original_size: int,
) -> str:
    """POST /uploads and return the upload_id extracted from the Location header."""
    metadata = ", ".join([
        f"filename {_enc('test_chunk_enforcement.bin')}",
        f"filetype {_enc('application/octet-stream')}",
        f"encrypted_file_key {_enc(fake_aes256_key())}",
        f"key_iv {_enc(fake_iv_12())}",
        f"chunk_size {_enc(str(chunk_size))}",
        f"original_size {_enc(str(original_size))}",
    ])
    r = await api.post(
        "/uploads",
        headers={
            "Tus-Resumable":  "1.0.0",
            "Upload-Length":   str(total_size),
            "Upload-Metadata": metadata,
            "Content-Length":  "0",
        },
    )
    return r, r.headers.get("location", "").rstrip("/").split("/")[-1]


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _user

    url     = await admin_client.create_invite_url()
    session = await register_via_invite(browser, url, "chunk_user_22", "Chunk!Pass99")
    users   = await admin_client.list_users()
    u       = next(x for x in users if x["username"].lower() == "chunk_user_22")
    _user   = {
        "id":      u["id"],
        "session": session,
        "api":     ApiClient.from_session(session),
    }

    yield

    try:
        await _user["api"].aclose()
        await session.ctx.close()
    except Exception:
        pass


# ===========================================================================
# 22-01 — /auth/public-settings returns chunk_size
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_22_01_public_settings_returns_chunk_size(admin_client: AdminClient):
    """GET /auth/public-settings (no auth) returns chunk_size matching the admin setting."""
    admin_settings = await admin_client.get_settings()
    configured = int(admin_settings["default_chunk_size"])

    async with httpx.AsyncClient() as client:
        r = await client.get(f"{API}/auth/public-settings")

    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    body = r.json()
    assert "chunk_size" in body, f"chunk_size key missing: {body}"
    assert isinstance(body["chunk_size"], int), "chunk_size must be an integer"
    assert body["chunk_size"] > 0, "chunk_size must be positive"
    assert body["chunk_size"] == configured, (
        f"Public setting {body['chunk_size']} != admin setting {configured}"
    )


# ===========================================================================
# 22-02 — Admin setting change is reflected in public-settings
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_22_02_setting_change_reflected_in_public_settings(admin_client: AdminClient):
    """Changing default_chunk_size is immediately visible in /auth/public-settings."""
    original = str(_SERVER_DEFAULT_CHUNK_SIZE)
    new_value = str(_SERVER_DEFAULT_CHUNK_SIZE // 2)

    try:
        await admin_client.set_setting("default_chunk_size", new_value)

        async with httpx.AsyncClient() as client:
            r = await client.get(f"{API}/auth/public-settings")

        assert r.status_code == 200
        assert r.json()["chunk_size"] == int(new_value), (
            f"Expected updated value {new_value}, got {r.json()['chunk_size']}"
        )
    finally:
        await admin_client.set_setting("default_chunk_size", original)

    # Verify restore
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{API}/auth/public-settings")
    assert r.json()["chunk_size"] == _SERVER_DEFAULT_CHUNK_SIZE


# ===========================================================================
# 22-03 — Wrong chunk_size at upload creation → 400
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_22_03_mismatched_chunk_size_at_upload_start_is_rejected():
    """POST /uploads with a chunk_size that doesn't match the admin setting → 400."""
    wrong_chunk_size = 1024   # almost certainly not the admin default (5 MB)

    r, _ = await _start_upload(
        _user["api"],
        chunk_size=wrong_chunk_size,
        total_size=wrong_chunk_size + 16,
        original_size=wrong_chunk_size,
    )

    assert r.status_code == 400, (
        f"Expected 400 for mismatched chunk_size, got {r.status_code}: {r.text}"
    )
    assert "chunk_size" in r.json().get("detail", "").lower(), (
        f"Expected 'chunk_size' in error detail: {r.text}"
    )


# ===========================================================================
# 22-04 — Non-final chunk with wrong body size → 400
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_22_04_non_final_chunk_wrong_body_size_is_rejected(admin_client: AdminClient):
    """Non-final PATCH chunk with wrong byte count → 400 "Unexpected chunk size".

    Uses the minimum valid chunk_size (65536 bytes) to keep the upload small.
    Upload total is 65652 bytes so the first chunk is non-final, triggering the
    per-chunk body-size check.
    """
    small_chunk_size = 65536
    expected_enc_size = small_chunk_size + 16  # 65552 bytes — correct non-final chunk size
    total_size = 65652                         # needs 2+ chunks → first is non-final
    original_size = 65600

    original_setting = str(_SERVER_DEFAULT_CHUNK_SIZE)

    try:
        # Set chunk_size to the small test value
        await admin_client.set_setting("default_chunk_size", str(small_chunk_size))

        # Create the upload with the now-matching small chunk_size
        r_post, upload_id = await _start_upload(
            _user["api"],
            chunk_size=small_chunk_size,
            total_size=total_size,
            original_size=original_size,
        )
        assert r_post.status_code == 201, (
            f"Expected 201 for upload creation, got {r_post.status_code}: {r_post.text}"
        )
        assert upload_id, "No upload_id in Location header"

        # Send a non-final chunk with wrong body size (100 bytes instead of 144)
        wrong_body = b"x" * 100
        r_patch = await _user["api"].patch(
            f"/uploads/{upload_id}",
            content=wrong_body,
            headers={
                "Tus-Resumable":  "1.0.0",
                "Content-Type":   "application/offset+octet-stream",
                "Upload-Offset":  "0",
                "Content-Length": str(len(wrong_body)),
                "X-Chunk-IV":     fake_iv_12(),
                "X-Chunk-Hash":   chunk_hash(wrong_body),
            },
        )

        assert r_patch.status_code == 400, (
            f"Expected 400 for wrong chunk body size, got {r_patch.status_code}: {r_patch.text}"
        )
        detail = r_patch.json().get("detail", "")
        assert "chunk size" in detail.lower(), (
            f"Expected 'chunk size' in error detail, got: {detail}"
        )
        assert str(expected_enc_size) in detail, (
            f"Expected the correct size ({expected_enc_size}) mentioned in detail: {detail}"
        )

    finally:
        await admin_client.set_setting("default_chunk_size", original_setting)


# ---------------------------------------------------------------------------
# 22-05  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_22_05_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
