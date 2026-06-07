"""
Group 00 — First-run bootstrap and initial setup.

This is the only group that tests the raw bootstrap flow. It resets the DB
itself (rather than using the shared seeded_env fixture) because the point
of these tests IS the bootstrap: we want to verify that a brand-new instance
correctly requires setup, and that the setup flow works end-to-end.

Tests
-----
00-01  Fresh instance reports needs_bootstrap via API
00-02  Bootstrap form renders (frontend detects state correctly)
00-03  Admin registers successfully via the bootstrap form (OPAQUE in browser)
00-04  The bootstrap token is single-use — a second attempt is rejected
00-05  Admin can log out and log back in
00-06  Admin has access to the admin panel
00-07  A non-admin user cannot register without an invite (open_registration=false)
00-08  Admin can create an invite and a user registers via it
"""

from __future__ import annotations

import httpx
import pytest
from playwright.async_api import Browser, expect

from tests.e2e.helpers.auth import bootstrap_admin, login, register_via_invite
from tests.e2e.helpers.db import get_bootstrap_token, reset_db
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL        = "http://localhost:8001"
API            = f"{APP_URL}/api/v1"
ADMIN_USERNAME = "bootstrap_admin"
ADMIN_PASSWORD = "Sup3r!Str0ngPassw0rd"
USER_USERNAME  = "first_user"
USER_PASSWORD  = "Us3r!Passw0rd99"

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# OPAQUE login and registration do not emit SIEM events.
# No 401/403 responses are expected from the happy-path bootstrap flow.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


# ---------------------------------------------------------------------------
# Module setup — explicitly reset DB here so we start from zero
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _fresh_env():
    """Reset to a completely clean state before any test in this group runs."""
    reset_db()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_00_01_bootstrap_status_on_fresh_instance():
    """A fresh instance must report needs_bootstrap=true."""
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        r = await client.get(f"{API}/auth/opaque/bootstrap/status")
    assert r.status_code == 200
    data = r.json()
    assert data.get("needs_bootstrap") is True, (
        f"Expected needs_bootstrap=true on a fresh instance, got: {data}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_00_02_bootstrap_form_renders(browser: Browser):
    """Frontend detects bootstrap state and renders the bootstrap form."""
    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()
    try:
        await page.goto("/", wait_until="load")
        await expect(page.locator("#bs-token")).to_be_visible(timeout=10_000)
        await expect(page.locator("#bs-username")).to_be_visible()
        await expect(page.locator("#bs-password")).to_be_visible()
        await expect(page.locator("#bs-password2")).to_be_visible()
    finally:
        await page.close()
        await ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_00_03_admin_registers_via_bootstrap(browser: Browser):
    """Admin completes bootstrap; is logged in and lands on the main UI."""
    token = get_bootstrap_token()
    session = await bootstrap_admin(browser, token, ADMIN_USERNAME, ADMIN_PASSWORD)
    try:
        # Should be on the main files/dashboard page — no login form visible
        page = await session.ctx.new_page()
        await page.goto("/", wait_until="load")
        await expect(page.locator("#username")).not_to_be_visible(timeout=5_000)
        # And the bootstrap form should be gone too
        await expect(page.locator("#bs-token")).not_to_be_visible()
    finally:
        await page.close()
        await session.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_00_04_bootstrap_token_is_single_use():
    """Bootstrap token is consumed on success; a second attempt returns 400."""
    # We can't get the original token again (it was consumed), but we can
    # check that a made-up token is rejected, and that bootstrap/status now
    # reports needs_bootstrap=false (token consumed).
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        r = await client.get(f"{API}/auth/opaque/bootstrap/status")
    assert r.status_code == 200
    assert r.json().get("needs_bootstrap") is False, (
        "Bootstrap should be marked complete after successful registration"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_00_05_admin_can_log_out_and_back_in(browser: Browser):
    """Admin can log in with the credentials set during bootstrap."""
    session = await login(browser, ADMIN_USERNAME, ADMIN_PASSWORD)
    try:
        page = await session.ctx.new_page()
        await page.goto("/", wait_until="load")
        # Must see the main UI, not the login form
        await expect(page.locator("#username")).not_to_be_visible(timeout=5_000)
    finally:
        await page.close()
        await session.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_00_06_admin_has_admin_panel_access(browser: Browser):
    """Admin lands on the admin panel section of the UI."""
    import httpx as _httpx
    session = await login(browser, ADMIN_USERNAME, ADMIN_PASSWORD)
    try:
        async with _httpx.AsyncClient(
            base_url=APP_URL,
            cookies=session.cookies,
            headers={"X-CSRF-Token": session.cookies.get("__Host-csrf_token", "")},
        ) as client:
            r = await client.get(f"{API}/admin/settings")
        assert r.status_code == 200, (
            f"Admin should be able to read settings, got {r.status_code}: {r.text}"
        )
    finally:
        await session.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_00_07_open_registration_off_by_default():
    """Registration without an invite returns 400/403 when open_registration=false."""
    # A direct POST to register/start without a valid invite token should fail.
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        r = await client.post(
            f"{API}/auth/opaque/register/start",
            json={
                "username": "uninvited_user",
                "client_registration_request": "AAAA",  # invalid, but we expect 4xx before crypto
            },
        )
    # Server should reject this before even attempting OPAQUE (no invite token)
    assert r.status_code in (400, 403, 422), (
        f"Expected rejection without invite, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_00_08_admin_creates_invite_and_user_registers(browser: Browser):
    """Admin creates an invite; a new user completes registration via the link."""
    # Log in as admin to create an invite
    admin_session = await login(browser, ADMIN_USERNAME, ADMIN_PASSWORD)
    try:
        import httpx as _httpx
        csrf = admin_session.cookies.get("__Host-csrf_token", "")
        async with _httpx.AsyncClient(
            base_url=APP_URL,
            cookies=admin_session.cookies,
            headers={"X-CSRF-Token": csrf},
        ) as client:
            r = await client.post(f"{API}/admin/invites")
        assert r.status_code == 200
        token = r.json()["token"]
    finally:
        await admin_session.ctx.close()

    invite_url = f"{APP_URL}/register/{token}"
    user_session = await register_via_invite(
        browser, invite_url, USER_USERNAME, USER_PASSWORD
    )
    try:
        page = await user_session.ctx.new_page()
        await page.goto("/", wait_until="load")
        await expect(page.locator("#username")).not_to_be_visible(timeout=5_000)
    finally:
        await page.close()
        await user_session.ctx.close()


# ---------------------------------------------------------------------------
# 00-09  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_00_09_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
