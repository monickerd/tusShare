"""
Group 24 — SSE tab-identity sync (Tier 8).

Tests that admin deactivation and emergency revocation events are delivered
via Server-Sent Events to all open browser tabs of the affected user,
causing an automatic logout with a toast notification.

Background
----------
Auth.startIdentityWatch() in auth.js opens an EventSource to
GET /api/v1/events/identity after every successful login.  On receipt of an
identity_changed event the app shows a toast and calls logout() after 1.5 s.

On the backend:
  - admin deactivation (PUT /admin/users/{id} with is_active=false) publishes
    to sse_broker topic "identity:{user_id}" with reason "deactivated"
  - emergency revocation (POST /admin/users/{id}/emergency-revoke) publishes
    with reason "emergency_revoke"

The headless Playwright browser supports multiple pages (tabs) within the
same BrowserContext — they share cookies but each has its own sessionStorage.
This means each tab independently opens an EventSource connection, and all
tabs receive the published event when deactivation occurs.

Tests
-----
24-01  GET /events/identity requires authentication (no auth → 401 or 403)
24-02  Admin deactivation publishes identity_changed; logged-in app tab logs out
24-03  Emergency revocation publishes identity_changed; logged-in app tab logs out
24-04  Two open tabs in the same browser context both receive the SSE event
       and both navigate to the login form (multi-tab scenario)
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from playwright.async_api import Browser, Page, expect
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from tests.e2e.helpers.admin import AdminClient
from tests.e2e.helpers.auth import UserSession, register_via_invite
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL        = "http://localhost:8001"
API            = f"{APP_URL}/api/v1"
OPAQUE_MS      = 30_000   # generous timeout for OPAQUE round-trips
NAV_MS         = 15_000   # page navigation timeout
SSE_LOGOUT_MS  = 10_000   # max time for SSE → 1.5 s toast → logout to complete

# Module-level user state (populated in setup fixture)
_alice:   dict = {}
_bob:     dict = {}
_charlie: dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# admin.user.deactivated: 24-02 (admin deactivates Alice → identity_changed SSE).
# admin.emergency_revocation: 24-03 (emergency revoke on Bob → identity_changed SSE).
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("admin.user.deactivated",   outcome="success", severity="warning",  tier=2),
    ExpectedSiemEvent("admin.emergency_revocation", outcome="success", severity="critical", tier=3),
]


# ---------------------------------------------------------------------------
# Helper: open the main app in a new tab within an existing session
# ---------------------------------------------------------------------------

async def _open_app_page(session: UserSession) -> Page:
    """
    Open a new Playwright page (browser tab) within the session's existing
    BrowserContext and wait until the main app UI is visible.

    New tabs have empty sessionStorage, so Auth.checkSession() returns false
    immediately and the app renders the login form.  We fill in the credentials
    and submit, then wait for the app to finish loading.

    After returning, startIdentityWatch() will have been called by the login
    flow, and the EventSource connection to /api/v1/events/identity will be
    establishing.  We sleep 1 s to let the connection fully open before any
    test triggers a deactivation event.
    """
    page = await session.ctx.new_page()
    await page.goto("/", wait_until="load", timeout=NAV_MS)

    # New tabs have empty sessionStorage, so the app shows the login form.
    username_input = page.locator("#username")
    try:
        await username_input.wait_for(state="visible", timeout=5_000)
        await username_input.fill(session.username)
        await page.fill("#password", session.password)
        await page.click("button[type='submit']")
    except PlaywrightTimeoutError:
        pass  # Login form did not appear — try key-prompt fallback below

    # Fallback: if the key prompt appears instead (e.g. sessionStorage was not
    # fully cleared), unlock it with the stored password.
    key_prompt = page.locator("#key-password")
    try:
        await key_prompt.wait_for(state="visible", timeout=5_000)
        await key_prompt.fill(session.password)
        await page.click("button[type='submit']")
    except PlaywrightTimeoutError:
        pass  # Key prompt did not appear either

    # Wait until neither the login form nor the key prompt is in the DOM
    await page.wait_for_function(
        """() => {
            const u = document.getElementById('username');
            const k = document.getElementById('key-password');
            return !u && !k;
        }""",
        timeout=OPAQUE_MS,
    )

    # Allow time for startIdentityWatch() to open the EventSource connection
    await asyncio.sleep(1.0)
    return page


# ---------------------------------------------------------------------------
# Module fixture: register three independent users
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_users(browser: Browser, admin_client: AdminClient):
    global _alice, _bob, _charlie

    user_specs = [
        ("alice_24",   "Al1ce!Sse99",   "_alice"),
        ("bob_24",     "B0b!Sse99",     "_bob"),
        ("charlie_24", "Ch4rlie!Sse99", "_charlie"),
    ]
    sessions: dict[str, dict] = {}

    for username, password, key in user_specs:
        url  = await admin_client.create_invite_url()
        sess = await register_via_invite(browser, url, username, password)
        users = await admin_client.list_users()
        rec   = next(u for u in users if u["username"].lower() == username)
        sessions[key] = {
            "id":       rec["id"],
            "session":  sess,
            "username": username,
            "password": password,
        }

    _alice   = sessions["_alice"]
    _bob     = sessions["_bob"]
    _charlie = sessions["_charlie"]

    yield

    for data in sessions.values():
        try:
            await data["session"].ctx.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 24-01: Endpoint requires authentication
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_24_01_identity_sse_requires_auth():
    """
    An unauthenticated GET to /events/identity must be rejected.
    The app uses cookie-based auth so a plain httpx client with no cookies
    should receive 401 or 403.
    """
    async with httpx.AsyncClient(base_url=APP_URL, follow_redirects=False) as client:
        await client.get("/")  # obtain a CSRF cookie
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.get(
            f"{API}/events/identity",
            headers={"Accept": "text/event-stream", "X-CSRF-Token": csrf},
        )
    assert r.status_code in (401, 403), (
        f"Expected 401 or 403 for unauthenticated SSE access, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# 24-02: Regular deactivation → SSE → logout
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_24_02_deactivation_triggers_sse_logout(admin_client: AdminClient):
    """
    Admin deactivates alice while she has a tab open.
    The sse_broker publishes to "identity:{alice_id}" and the browser tab
    should receive the event, show a toast, and navigate to the login form.
    """
    if not _alice:
        pytest.skip("alice_24 not registered")

    page = await _open_app_page(_alice["session"])
    try:
        # Deactivate alice — this publishes identity_changed(reason=deactivated)
        await admin_client.set_user_active(_alice["id"], False)

        # Wait for the app to navigate to the login form after the SSE logout
        await page.wait_for_function(
            "() => document.getElementById('username') !== null",
            timeout=SSE_LOGOUT_MS,
        )
        await expect(page.locator("#username")).to_be_visible(timeout=5_000)
    finally:
        await page.close()
        # Reactivate so alice's session context cleanup in teardown can close cleanly
        await admin_client.set_user_active(_alice["id"], True)


# ---------------------------------------------------------------------------
# 24-03: Emergency revocation → SSE → logout
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_24_03_emergency_revocation_triggers_sse_logout(admin_client: AdminClient):
    """
    Admin emergency-revokes bob while he has a tab open.
    The sse_broker publishes to "identity:{bob_id}" with reason=emergency_revoke.
    The browser tab should receive the event and log out automatically.
    """
    if not _bob:
        pytest.skip("bob_24 not registered")

    page = await _open_app_page(_bob["session"])
    try:
        result = await admin_client.emergency_revoke(
            _bob["id"],
            reason="test revocation in group 24",
            scope="owned_only",
        )
        assert result.get("ok") is True, f"Emergency revoke API error: {result}"

        await page.wait_for_function(
            "() => document.getElementById('username') !== null",
            timeout=SSE_LOGOUT_MS,
        )
        await expect(page.locator("#username")).to_be_visible(timeout=5_000)
    finally:
        await page.close()


# ---------------------------------------------------------------------------
# 24-04: Two open tabs both receive the SSE event (multi-tab scenario)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_24_04_two_tabs_both_receive_identity_sse(admin_client: AdminClient):
    """
    Playwright supports multiple Page objects (browser tabs) within one
    BrowserContext — they share the session cookies so both are authenticated
    as the same user.

    This test opens two tabs for charlie_24 (simulating a user browsing with
    two windows open), then has the admin deactivate the account.  The
    sse_broker delivers the identity_changed event to BOTH open EventSource
    connections, and both tabs should independently navigate to the login form.

    Scenario:
      1. Register charlie_24 (invite flow in setup fixture)
      2. tab1 = open new page in charlie's context → app loads → identity watch starts
      3. tab2 = open second page in charlie's context → app loads → identity watch starts
      4. Admin deactivates charlie via API
      5. Both tab1 and tab2 should show the login form within SSE_LOGOUT_MS
    """
    if not _charlie:
        pytest.skip("charlie_24 not registered")

    # Open two tabs within charlie's same browser context.
    # Each tab independently connects to the SSE identity endpoint.
    tab1 = await _open_app_page(_charlie["session"])
    tab2 = await _open_app_page(_charlie["session"])

    try:
        # Admin deactivates charlie — publishes to "identity:{charlie_id}"
        # The sse_broker delivers to all active subscribers (both tab connections)
        await admin_client.set_user_active(_charlie["id"], False)

        # Both tabs receive the event independently and should log out.
        # Run the waits concurrently so a slow second tab does not hide a fast first tab.
        await asyncio.gather(
            tab1.wait_for_function(
                "() => document.getElementById('username') !== null",
                timeout=SSE_LOGOUT_MS,
            ),
            tab2.wait_for_function(
                "() => document.getElementById('username') !== null",
                timeout=SSE_LOGOUT_MS,
            ),
        )

        # Assert the login form is visible on both tabs
        await expect(tab1.locator("#username")).to_be_visible(timeout=5_000)
        await expect(tab2.locator("#username")).to_be_visible(timeout=5_000)
    finally:
        await tab1.close()
        await tab2.close()


# ---------------------------------------------------------------------------
# 24-05  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_24_05_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
