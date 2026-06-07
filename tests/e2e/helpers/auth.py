"""
Authentication helpers for Playwright-based E2E tests.

All OPAQUE crypto runs inside the real browser (Chromium via Playwright),
so these helpers drive the actual frontend forms rather than reimplementing
the protocol in Python. This means the tests exercise the full client-side
crypto stack — the same code path a real user follows.

Helpers:
    bootstrap_admin()      — complete first-run admin setup via the bootstrap form
    login()                — log in as an existing user, return session context
    register_via_invite()  — accept an invite link and register a new user
    logout()               — log out and clear session
    ldap_login()           — log in as an LDAP user via the API (no browser)
    oidc_login()           — complete an OIDC login via Playwright through the Dex form

Key selectors (from frontend/js/auth.js):
    Bootstrap form: #bs-token, #bs-username, #bs-password, #bs-password2
    Login form:     #username, #password
    Register form:  #reg-username, #reg-password, #reg-password-confirm
    Key prompt:     #key-password  (appears after page refresh if session alive)
    Status lines:   #bs-status, #login-status, #reg-status
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
from playwright.async_api import Browser, BrowserContext, expect

if TYPE_CHECKING:
    from tests.e2e.helpers.admin import ApiClient

APP_URL = os.getenv("TEST_APP_URL", "http://localhost:8001")
HEADED  = os.getenv("TEST_HEADED", "0") == "1"

# How long to wait for OPAQUE crypto + network round-trips.
# The two-round OPAQUE handshake + key generation typically takes 2-8 s in a
# headless browser, so set generous timeouts here.
OPAQUE_TIMEOUT_MS = 30_000
NAV_TIMEOUT_MS    = 15_000


@dataclass
class UserSession:
    """Holds a logged-in user's browser context and basic credentials."""
    ctx:      BrowserContext
    username: str
    password: str
    # Set after login; useful for direct API calls via httpx
    cookies:  dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Bootstrap (first-run admin setup)
# ---------------------------------------------------------------------------

async def bootstrap_admin(
    browser:  Browser,
    token:    str,
    username: str,
    password: str,
) -> UserSession:
    """
    Complete the first-run admin bootstrap via the browser UI.

    The frontend auto-detects bootstrap state on load
    (GET /api/v1/auth/opaque/bootstrap/status → needs_bootstrap: true)
    and renders the bootstrap form instead of the login form.

    Returns a UserSession with an open browser context logged in as the
    new admin.
    """
    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()

    await page.goto("/", wait_until="load", timeout=NAV_TIMEOUT_MS)

    # Frontend detects needs_bootstrap and shows the bootstrap form
    await expect(page.locator("#bs-token")).to_be_visible(timeout=NAV_TIMEOUT_MS)

    await page.fill("#bs-token",    token)
    await page.fill("#bs-username", username)
    await page.fill("#bs-password",  password)
    await page.fill("#bs-password2", password)
    await page.click("button[type='submit']")

    # Wait for success — status line shows progress, then app redirects
    status = page.locator("#bs-status")
    await expect(status).not_to_have_text("", timeout=OPAQUE_TIMEOUT_MS)

    # Wait until we leave the bootstrap form (app navigates to main UI)
    await page.wait_for_function(
        "() => !document.getElementById('bs-token')",
        timeout=OPAQUE_TIMEOUT_MS,
    )

    await page.close()
    session = UserSession(ctx=ctx, username=username, password=password)
    session.cookies = await _extract_cookies(ctx)
    return session


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

async def login(
    browser:  Browser,
    username: str,
    password: str,
) -> UserSession:
    """
    Log in as an existing user via the standard login form.

    Returns a UserSession holding the authenticated browser context.
    """
    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()

    await page.goto("/", wait_until="load", timeout=NAV_TIMEOUT_MS)

    await expect(page.locator("#username")).to_be_visible(timeout=NAV_TIMEOUT_MS)
    await page.fill("#username", username)
    await page.fill("#password", password)
    await page.click("button[type='submit']")

    # Wait for OPAQUE login round-trips and key derivation to complete
    await page.wait_for_function(
        "() => !document.getElementById('username')",
        timeout=OPAQUE_TIMEOUT_MS,
    )

    # If the key prompt appears (e.g. after session refresh scenario), unlock it
    key_prompt = page.locator("#key-password")
    if await key_prompt.is_visible():
        await key_prompt.fill(password)
        await page.click("button[type='submit']")
        await page.wait_for_function(
            "() => !document.getElementById('key-password')",
            timeout=OPAQUE_TIMEOUT_MS,
        )

    await page.close()
    session = UserSession(ctx=ctx, username=username, password=password)
    session.cookies = await _extract_cookies(ctx)
    return session


# ---------------------------------------------------------------------------
# Invite registration
# ---------------------------------------------------------------------------

async def register_via_invite(
    browser:     Browser,
    invite_url:  str,
    username:    str,
    password:    str,
) -> UserSession:
    """
    Register a new user by navigating to an invite link.

    The invite_url should be the full URL to the /register/{token} page.
    Returns a UserSession with the new user logged in.
    """
    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()

    await page.goto(invite_url, wait_until="load", timeout=NAV_TIMEOUT_MS)

    # Registration form
    await expect(page.locator("#reg-username")).to_be_visible(timeout=NAV_TIMEOUT_MS)
    await page.fill("#reg-username",  username)
    await page.fill("#reg-password",  password)
    await page.fill("#reg-password2", password)

    # Accept the recovery-key checkbox if present (it may be required)
    save_cb = page.locator("#reg-save-recovery-key")
    if await save_cb.is_visible():
        await save_cb.check()

    await page.click("button[type='submit']")

    status = page.locator("#reg-status")
    await expect(status).not_to_have_text("", timeout=OPAQUE_TIMEOUT_MS)

    # Wait for navigation away from the registration form
    await page.wait_for_function(
        "() => !document.getElementById('reg-username')",
        timeout=OPAQUE_TIMEOUT_MS,
    )

    await page.close()
    session = UserSession(ctx=ctx, username=username, password=password)
    session.cookies = await _extract_cookies(ctx)
    return session


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

async def logout(session: UserSession) -> None:
    """
    Log out the given session via the UI and close its browser context.
    """
    page = await session.ctx.new_page()
    try:
        await page.goto("/", wait_until="load", timeout=NAV_TIMEOUT_MS)
        # Trigger logout — the app may expose a logout button or dropdown
        logout_btn = page.locator("[data-action='logout'], button:has-text('Log out'), a:has-text('Log out')")
        if await logout_btn.first.is_visible(timeout=3000):
            await logout_btn.first.click()
    except Exception:
        pass
    finally:
        await page.close()
        await session.ctx.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _extract_cookies(ctx: BrowserContext) -> dict[str, str]:
    """Return a flat {name: value} dict of all cookies in the context."""
    cookies = await ctx.cookies()
    return {c["name"]: c["value"] for c in cookies}


async def get_csrf_token(ctx: BrowserContext) -> str:
    """
    Return the CSRF token value from the context's cookies.

    The app uses the double-submit pattern: the readable __Host-csrf_token
    cookie must be mirrored in the X-CSRF-Token request header.
    """
    cookies = await _extract_cookies(ctx)
    token = cookies.get("__Host-csrf_token", "")
    if not token:
        raise RuntimeError(
            "CSRF token cookie not found. Is the user logged in?"
        )
    return token


# ---------------------------------------------------------------------------
# IdP login helpers (no browser required for LDAP)
# ---------------------------------------------------------------------------

async def ldap_login(
    provider_id: str,
    username:    str,
    password:    str,
) -> dict[str, str]:
    """
    Log in as an LDAP user via the API and return session cookies.

    Returns a cookies dict suitable for passing directly to ApiClient(cookies).
    The caller is responsible for closing the ApiClient when done.
    """
    async with httpx.AsyncClient(base_url=APP_URL, follow_redirects=True) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.post(
            f"{APP_URL}/api/v1/auth/ldap/login",
            json={
                "provider_id":      provider_id,
                "username":         username,
                "password":         password,
                "is_public_device": False,
            },
            headers={"X-CSRF-Token": csrf},
        )
        r.raise_for_status()
        if r.json().get("mfa_required"):
            raise RuntimeError(
                f"LDAP login for {username!r} triggered MFA gate — "
                "enroll MFA before using ldap_login() in tests"
            )
        return dict(client.cookies)


async def register_asymmetric_keys(client: "ApiClient") -> None:
    """Register stub asymmetric keys for a user who has no keys yet (e.g. fresh LDAP/OIDC login).

    Calls POST /api/v1/auth/me/asymmetric-keys with format-valid stub material.
    Raises on failure.
    """
    from tests.e2e.helpers.crypto_stubs import fake_asymmetric_keys
    r = await client.post("/auth/me/asymmetric-keys", json=fake_asymmetric_keys())
    r.raise_for_status()


async def oidc_login(
    browser:      Browser,
    provider_id:  str,
    dex_uid:      str,
    dex_password: str,
) -> UserSession:
    """
    Complete an OIDC login via Playwright through the Dex login form.

    Rewrites the docker-internal Dex hostname to localhost so the browser
    (running on the host) can navigate to the Dex consent page.

    Returns a UserSession with cookies from the authenticated browser context.
    The caller must close session.ctx when done.
    """
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.get(
            f"{APP_URL}/api/v1/auth/oidc/{provider_id}/begin",
            headers={"X-CSRF-Token": csrf},
        )
        r.raise_for_status()

    auth_url = r.json()["redirect_url"]
    browser_url = auth_url.replace("http://dex:5556", "http://localhost:5556")

    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()
    try:
        await page.goto(browser_url, wait_until="load")
        await page.fill(
            "input#login, input[name='login'], input[type='text']",
            dex_uid,
        )
        await page.fill(
            "input#password, input[name='password'], input[type='password']",
            dex_password,
        )
        await page.click("button[type='submit'], input[type='submit']")
        await page.wait_for_url(f"{APP_URL}/**", timeout=15_000)
    finally:
        await page.close()

    session = UserSession(ctx=ctx, username=dex_uid, password=dex_password)
    session.cookies = await _extract_cookies(ctx)
    return session
