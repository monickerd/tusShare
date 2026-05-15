"""
Group 28 — Theme system + setup wizard (Phase 5).

Tests the hardware scan probe, theme write API (brand name, UI flags, logo
upload, hot-reload), and the first_run_completed wizard state flag.

Sections
--------
  A. Hardware scan
    28-01  GET /admin/hw-scan returns the expected structure
    28-02  PBKDF2 recommendation meets the 600 000-iteration OWASP floor
    28-03  Unauthenticated request cannot access hw-scan

  B. Theme — brand name & UI flags
    28-04  PATCH /admin/theme sets brand_name; response confirms it
    28-05  PATCH /admin/theme sets a known ui flag without error
    28-06  PATCH /admin/theme with brand_name='' → 400
    28-07  PATCH /admin/theme with brand_name > 64 chars → 400
    28-08  PATCH /admin/theme with unknown ui flag → 400

  C. Theme — logo upload
    28-09  POST /admin/theme/logo with valid PNG → 200, logo_url returned
    28-10  POST /admin/theme/logo with file > 2 MB → 413
    28-11  POST /admin/theme/logo with .txt extension → 400 (invalid MIME)
    28-12  POST /admin/theme/logo with empty filename → 400

  D. Theme hot-reload
    28-13  POST /admin/theme/reload echoes back the brand_name set in 28-04

  E. Setup wizard flow
    28-14  first_run_completed can be reset to '0' via the settings API
    28-15  Setting first_run_completed to an invalid value ('2') → 400
    28-16  Applying a profile with mark_first_run=True sets first_run_completed='1'

Notes
-----
Theme endpoints do not emit SIEM events; there is no manifest section.

Step-up tokens (section E) are minted against the test JWT secret for action
key "admin.settings.security.*" (same as group 27).

Teardown ensures first_run_completed is restored to '1' so subsequent groups
are not affected by state changes in section E.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

_TEST_JWT_SECRET = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
_PROFILE_ACTION  = "admin.settings.security.*"

# Minimal 1×1 transparent PNG (67 bytes).
# The logo endpoint validates by filename extension only, but real bytes are
# cleaner than arbitrary data in case validation is ever strengthened.
_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDAT\x08\xd7c\xf8\xcf\xc0\x00\x00\x00\x02\x00\x01"
    b"\xe2!\xbc3"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

# 2 MB + 1 byte — triggers the server-side size limit check.
_OVERSIZED = b"\x00" * (2 * 1024 * 1024 + 1)

# OWASP minimum floor enforced by hw_scan._probe_pbkdf2
_MIN_PBKDF2_ITERS = 600_000

_state: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _step_up(user_id: str) -> str:
    """Mint a valid step-up JWT for admin.settings.security.* operations."""
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub":    user_id,
            "type":   "step_up",
            "action": _PROFILE_ACTION,
            "scope":  "*",
            "iat":    now,
            "exp":    now + timedelta(minutes=5),
        },
        _TEST_JWT_SECRET,
        algorithm="HS512",
    )


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_world(seeded_env, browser: Browser):
    """Capture admin ID for step-up minting; restore wizard state on teardown."""
    global _state
    admin_client: AdminClient = seeded_env["admin_client"]

    me_r = await admin_client._client.get(f"{API}/auth/me")
    me_r.raise_for_status()
    _state["admin_id"] = me_r.json()["user"]["id"]

    yield

    # Teardown: restore first_run_completed so later groups see a clean state.
    try:
        await admin_client.set_setting("first_run_completed", "1")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# A. Hardware scan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_28_01_hw_scan_structure(admin_client: AdminClient):
    """hw-scan returns cpu, ram, pbkdf2, pre_batch, disk, and recommendations."""
    result = await admin_client.get_hw_scan()

    for key in ("cpu", "ram", "pbkdf2", "pre_batch", "disk", "recommendations"):
        assert key in result, f"Missing top-level key {key!r} in hw-scan: {list(result)}"

    rec = result["recommendations"]
    for rec_key in ("pbkdf2_iterations", "thread_pool_size", "pre_batch_size"):
        assert rec_key in rec, f"Missing recommendation key {rec_key!r}: {list(rec)}"
        assert isinstance(rec[rec_key], int) and rec[rec_key] > 0, (
            f"recommendations.{rec_key} must be a positive int, got: {rec[rec_key]!r}"
        )

    cpu = result["cpu"]
    assert cpu.get("logical_cores", 0) >= 1, f"Expected at least 1 CPU core: {cpu}"


@pytest.mark.asyncio(loop_scope="session")
async def test_28_02_pbkdf2_meets_floor(admin_client: AdminClient):
    """PBKDF2 recommended_iterations must meet the OWASP 600 000 floor."""
    result = await admin_client.get_hw_scan()
    iters  = result["pbkdf2"]["recommended_iterations"]
    assert iters >= _MIN_PBKDF2_ITERS, (
        f"Expected >= {_MIN_PBKDF2_ITERS} recommended PBKDF2 iterations, got {iters}"
    )
    assert result["pbkdf2"]["min_floor"] == _MIN_PBKDF2_ITERS, (
        f"min_floor should be {_MIN_PBKDF2_ITERS}, got {result['pbkdf2']['min_floor']}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_03_hw_scan_requires_auth():
    """GET /admin/hw-scan without credentials → 401 or 403."""
    async with httpx.AsyncClient(base_url=APP_URL) as anon:
        r = await anon.get(f"{API}/admin/hw-scan")
    assert r.status_code in (401, 403), (
        f"Expected 401/403 for unauthenticated hw-scan, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# B. Theme — brand name & UI flags
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_28_04_update_brand_name(admin_client: AdminClient):
    """PATCH /admin/theme sets brand_name; the response echoes the new value."""
    result = await admin_client.update_theme(brand_name="Acme Test Corp")
    assert result.get("brand_name") == "Acme Test Corp", (
        f"Expected brand_name 'Acme Test Corp' in response, got: {result.get('brand_name')!r}"
    )
    assert result.get("message") == "Theme updated", f"Unexpected message: {result}"


@pytest.mark.asyncio(loop_scope="session")
async def test_28_05_update_ui_flag(admin_client: AdminClient):
    """PATCH /admin/theme sets a known ui flag (admin_transparency_banner) without error."""
    result = await admin_client.update_theme(ui={"admin_transparency_banner": False})
    assert result.get("message") == "Theme updated", f"Unexpected response: {result}"


@pytest.mark.asyncio(loop_scope="session")
async def test_28_06_brand_name_empty_returns_400(admin_client: AdminClient):
    """PATCH /admin/theme with brand_name='' → 400."""
    r = await admin_client._client.patch(
        f"{API}/admin/theme", json={"brand_name": ""}
    )
    assert r.status_code == 400, (
        f"Expected 400 for empty brand_name, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_07_brand_name_too_long_returns_400(admin_client: AdminClient):
    """PATCH /admin/theme with brand_name of 65 chars → 400 (limit is 64)."""
    r = await admin_client._client.patch(
        f"{API}/admin/theme", json={"brand_name": "A" * 65}
    )
    assert r.status_code == 400, (
        f"Expected 400 for brand_name > 64 chars, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_08_unknown_ui_flag_returns_400(admin_client: AdminClient):
    """PATCH /admin/theme with an unrecognised ui flag → 400."""
    r = await admin_client._client.patch(
        f"{API}/admin/theme", json={"ui": {"nonexistent_flag_xyz": True}}
    )
    assert r.status_code == 400, (
        f"Expected 400 for unknown ui flag, got {r.status_code}: {r.text}"
    )
    detail = r.json().get("detail", "")
    assert "Unknown" in detail or "unknown" in detail, (
        f"Expected 'Unknown' in error detail: {r.text}"
    )


# ---------------------------------------------------------------------------
# C. Theme — logo upload
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_28_09_upload_valid_logo(admin_client: AdminClient):
    """POST /admin/theme/logo with a valid PNG → 200, logo_url in response."""
    r = await admin_client.upload_theme_logo("test_logo.png", _TINY_PNG)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert "logo_url"  in data, f"Expected logo_url in response: {data}"
    assert "logo_path" in data, f"Expected logo_path in response: {data}"
    assert data["logo_url"] == "/api/v1/theme/logo", (
        f"Unexpected logo_url: {data['logo_url']!r}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_10_oversized_logo_returns_413(admin_client: AdminClient):
    """POST /admin/theme/logo with file > 2 MB → 413."""
    r = await admin_client.upload_theme_logo("big.png", _OVERSIZED)
    assert r.status_code == 413, (
        f"Expected 413 for oversized logo, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_11_invalid_mime_logo_returns_400(admin_client: AdminClient):
    """POST /admin/theme/logo with .txt extension → 400 (MIME not allowed)."""
    r = await admin_client.upload_theme_logo("logo.txt", b"not an image", "text/plain")
    assert r.status_code == 400, (
        f"Expected 400 for non-image MIME type, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_12_empty_filename_returns_400(admin_client: AdminClient):
    """POST /admin/theme/logo with empty filename → 400 or 422.

    httpx sends an empty filename as a malformed multipart field, so FastAPI
    may reject it at the schema layer (422) before our handler checks it (400).
    Both indicate the request was refused.
    """
    r = await admin_client.upload_theme_logo("", b"data", "image/png")
    assert r.status_code in (400, 422), (
        f"Expected 400/422 for empty filename, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# D. Theme hot-reload
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_28_13_theme_reload(admin_client: AdminClient):
    """POST /admin/theme/reload succeeds and reflects the brand_name set in 28-04."""
    result = await admin_client.reload_theme()
    assert result.get("message") == "Theme reloaded", f"Unexpected response: {result}"

    for key in ("brand_name", "has_logo", "color_overrides"):
        assert key in result, f"Missing key {key!r} in reload response: {result}"

    # brand_name written in 28-04 must survive logo upload (28-09) and still
    # be present after an explicit hot-reload.
    assert result.get("brand_name") == "Acme Test Corp", (
        f"Expected 'Acme Test Corp' after reload, got: {result.get('brand_name')!r}"
    )
    # Logo uploaded in 28-09 must be reflected
    assert result.get("has_logo") is True, (
        "Expected has_logo=True after uploading a logo in 28-09"
    )


# ---------------------------------------------------------------------------
# E. Setup wizard flow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_28_14_first_run_flag_can_be_reset(admin_client: AdminClient):
    """first_run_completed can be written to '0' via the settings API."""
    await admin_client.set_setting("first_run_completed", "0")
    settings = await admin_client.get_settings()
    assert settings.get("first_run_completed") == "0", (
        f"Expected first_run_completed='0', got: {settings.get('first_run_completed')!r}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_15_invalid_first_run_value_returns_400(admin_client: AdminClient):
    """PUT /admin/settings with first_run_completed='2' → 400 (only '0'/'1' allowed)."""
    r = await admin_client._client.put(
        f"{API}/admin/settings",
        json={"settings": {"first_run_completed": "2"}},
    )
    assert r.status_code == 400, (
        f"Expected 400 for first_run_completed='2', got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_28_16_apply_profile_with_mark_first_run(admin_client: AdminClient):
    """Applying a profile with mark_first_run=True transitions first_run_completed to '1'."""
    # Confirm we're in the reset state from 28-14.
    settings = await admin_client.get_settings()
    assert settings.get("first_run_completed") == "0", (
        "Expected first_run_completed='0' at start of this test (28-14 must run first)"
    )

    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile("recommended", tok, mode="replace", mark_first_run=True)

    settings = await admin_client.get_settings()
    assert settings.get("first_run_completed") == "1", (
        f"Expected first_run_completed='1' after wizard completion via mark_first_run=True, "
        f"got: {settings.get('first_run_completed')!r}"
    )
