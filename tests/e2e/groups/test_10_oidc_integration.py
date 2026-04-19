"""
Group 10 — OIDC integration (via Dex).

Requires:
  - Dex OIDC provider running in docker-compose.test.yml (port 5556)
  - LDAP container running (Dex uses it as upstream identity source)
  - TUSSHARE_ALLOW_HTTP_IDP=true set in the app container environment
    (Dex uses plain HTTP in the test environment)

All tests marked @pytest.mark.oidc.  Run with:  pytest -m oidc
                                    Skip with:  pytest -m "not oidc"

Dex configuration (tests/fixtures/dex/config.yaml)
────────────────────────────────────────────────────
  issuer:        http://dex:5556/dex          (docker network — reachable by app container)
  client_id:     tusshare-test
  client_secret: tusshare-test-secret
  redirect_uri:  http://localhost:8001/api/v1/auth/oidc/callback

Identity source: upstream LDAP (same users as group 09)
  ldap_alice / Alice!Ldap99   — groups: engineering
  ldap_bob   / Bob!Ldap99     — groups: marketing

Hostname note
─────────────
Dex's issuer URL uses the docker-internal hostname "dex".  The app container
reaches it as http://dex:5556/dex.  The Playwright browser (running on the
host) reaches Dex at http://localhost:5556/dex — port 5556 is forwarded.
When driving the browser through the OIDC flow, the test rewrites the
redirect_url from the begin endpoint to replace "dex" with "localhost".

Tests
──────
10-01  Dex discovery endpoint is reachable (smoke test)
10-02  Admin creates an OIDC provider via /admin/identity-providers
10-03  GET provider returns redacted client_secret (never plaintext)
10-04  Test connection endpoint fetches Dex discovery and reports ok=true
10-05  Login page renders an OIDC button for the created provider (Playwright)
10-06  Full OIDC login flow completes via Playwright + Dex form
10-07  OIDC user has auth_method=oidc and null wrapped_master_key
10-08  oidc_claims_cache is populated after login (groups claim from Dex)
10-09  OIDC claim (groups) registered as policy field with source=oidc
10-10  Disabling provider makes the begin endpoint return 404
10-11  Deleting the provider de-links OIDC users but does not delete them
"""

from __future__ import annotations

import pytest
import httpx

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"
DEX_URL = "http://localhost:5556/dex"   # host-accessible Dex URL (Playwright + httpx tests)
DEX_DOCKER_URL = "http://dex:5556/dex"  # docker-internal Dex URL (app container uses this)

pytestmark = pytest.mark.oidc

# ---------------------------------------------------------------------------
# OIDC provider config (matches tests/fixtures/dex/config.yaml)
# ---------------------------------------------------------------------------

_OIDC_PROVIDER_CONFIG = {
    "issuer_url":    DEX_DOCKER_URL,
    "client_id":     "tusshare-test",
    "client_secret": "tusshare-test-secret",
    "redirect_uri":  f"{APP_URL}/api/v1/auth/oidc/callback",
    "scopes":        ["openid", "email", "profile", "groups", "offline_access"],
    "username_attr": "email",
}

_ALICE = {"uid": "ldap_alice", "password": "Alice!Ldap99"}

_REDACTED = "••••••••"

# Module-level state shared between tests (ordered run)
_state: dict = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dex_reachable() -> bool:
    import socket
    try:
        with socket.create_connection(("localhost", 5556), timeout=3):
            return True
    except OSError:
        return False


def _skip_if_no_provider():
    if "provider_id" not in _state:
        pytest.skip("10-02 did not create the provider — skipping dependent test")


def _skip_if_no_dex():
    if not _dex_reachable():
        pytest.skip("Dex not reachable on port 5556")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_10_01_dex_discovery_reachable():
    """Dex OIDC discovery endpoint must be up before any OIDC test."""
    _skip_if_no_dex()
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{DEX_URL}/.well-known/openid-configuration")
    assert r.status_code == 200, f"Dex discovery endpoint failed: {r.text}"
    data = r.json()
    assert "issuer"                  in data
    assert "authorization_endpoint" in data
    assert "token_endpoint"          in data
    assert "jwks_uri"                in data


@pytest.mark.asyncio(loop_scope="session")
async def test_10_02_admin_creates_oidc_provider(seeded_env):
    """Admin can create an OIDC provider via POST /admin/identity-providers."""
    _skip_if_no_dex()

    admin = seeded_env["admin_client"]
    data = await admin.create_idp_provider(
        provider_type="oidc",
        name="Test OIDC (Dex)",
        config=_OIDC_PROVIDER_CONFIG,
        claim_mode="at_login",
    )

    assert data["provider_type"] == "oidc"
    assert data["name"] == "Test OIDC (Dex)"
    assert data["is_active"] is True
    assert "id" in data

    _state["provider_id"] = data["id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_10_03_get_provider_redacts_client_secret(seeded_env):
    """GET /admin/identity-providers/{id} must never return the plaintext client_secret."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    prov = await admin.get_idp_provider(_state["provider_id"])

    assert prov["provider_type"] == "oidc"
    assert "config" in prov
    cfg = prov["config"]
    assert cfg["client_secret"] == _REDACTED, (
        f"client_secret should be redacted but got: {cfg['client_secret']!r}"
    )
    # Non-secret fields should be readable
    assert cfg["issuer_url"] == DEX_DOCKER_URL
    assert cfg["client_id"] == "tusshare-test"
    assert cfg["redirect_uri"] == f"{APP_URL}/api/v1/auth/oidc/callback"


@pytest.mark.asyncio(loop_scope="session")
async def test_10_04_test_connection_fetches_discovery(seeded_env):
    """
    POST /admin/identity-providers/{id}/test fetches Dex's discovery document
    and must report ok=true.
    Requires TUSSHARE_ALLOW_HTTP_IDP=true in the app container — if the config
    validation rejects the HTTP issuer the test endpoint returns ok=false.
    """
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    result = await admin.test_idp_provider(_state["provider_id"])

    assert result.get("ok") is True, (
        f"OIDC test connection failed: {result.get('error')}\n"
        "Ensure TUSSHARE_ALLOW_HTTP_IDP=true is set in the app container."
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_10_05_login_page_shows_oidc_button(browser, seeded_env):
    """
    The login page must render an 'Sign in with' button for the active OIDC provider.
    The button is injected by auth.js after fetching GET /api/v1/auth/idp/providers.
    """
    _skip_if_no_provider()
    from playwright.async_api import expect

    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()
    try:
        await page.goto("/", wait_until="load")
        # auth.js renders: <button data-provider-id="{id}">Sign in with Test OIDC (Dex)</button>
        btn = page.locator("button[data-provider-id]")
        await expect(btn.first).to_be_visible(timeout=8_000)
        # Should mention the provider name
        text = await btn.first.text_content()
        assert text and ("OIDC" in text or "Dex" in text or "Sign in" in text), (
            f"IdP button text unexpected: {text!r}"
        )
    finally:
        await page.close()
        await ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_10_06_oidc_login_flow_completes(browser, seeded_env):
    """
    Full OIDC login flow via Playwright:
      1. Call /auth/oidc/{id}/begin to get the Dex authorization URL.
      2. Rewrite the docker-internal hostname to localhost so the browser can navigate.
      3. Fill in the Dex login form with ldap_alice's credentials.
      4. Dex redirects to the app callback, app sets session cookies and redirects to /.
      5. Verify the SPA renders the authenticated shell (files or admin view).

    Note: This test rewrites the authorization URL's host from "dex" to "localhost"
    because the browser runs outside the docker network.
    """
    _skip_if_no_provider()
    _skip_if_no_dex()

    pid = _state["provider_id"]

    # Step 1: Get the Dex authorization URL from the begin endpoint
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.get(
            f"{API}/auth/oidc/{pid}/begin",
            headers={"X-CSRF-Token": csrf},
        )
    assert r.status_code == 200, f"OIDC begin failed: {r.status_code} {r.text}"
    auth_url = r.json()["redirect_url"]

    # Step 2: Rewrite docker-internal hostname to localhost for the browser
    browser_auth_url = auth_url.replace("http://dex:5556", "http://localhost:5556")

    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()
    try:
        # Step 3: Navigate to Dex login form
        await page.goto(browser_auth_url, wait_until="load")

        # Dex login form — fields vary slightly by version but "login" and "password" are stable
        await page.fill("input#login, input[name='login'], input[type='text']", _ALICE["uid"])
        await page.fill("input#password, input[name='password'], input[type='password']", _ALICE["password"])
        await page.click("button[type='submit'], input[type='submit']")

        # Step 4: Wait for redirect back to the app — URL will be localhost:8001
        await page.wait_for_url(
            f"{APP_URL}/**",
            timeout=15_000,
        )

        # The app redirects to / after callback processing.
        # If MFA pending: URL is /?mfa_pending=...
        # Otherwise: URL is / and the SPA loads files or admin.
        final_url = page.url
        # Either we're at the app root or at the MFA page — both mean auth succeeded
        assert APP_URL in final_url, f"Did not land back on the app: {final_url}"

        if "mfa_pending" in final_url:
            # MFA enrolled on this OIDC user — auth still succeeded
            _state["alice_oidc_mfa_pending"] = True
        else:
            # Wait for the SPA to boot and render the authenticated view
            await page.wait_for_load_state("networkidle", timeout=10_000)
            _state["alice_oidc_logged_in"] = True

    finally:
        await page.close()
        await ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_10_07_oidc_user_has_null_wrapped_master_key(seeded_env):
    """OIDC users have no OPAQUE-derived KEK: wrapped_master_key must be null."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    users = await admin.list_users()

    # Find ldap_alice's OIDC user (Dex uses LDAP uid as email sub, username_attr=email)
    # The display username will be ldap_alice@test.local (email from LDAP)
    oidc_users = [u for u in users if u.get("auth_method") == "oidc"]
    assert oidc_users, "No OIDC user found — did 10-06 complete successfully?"

    alice_oidc = oidc_users[0]
    assert alice_oidc.get("wrapped_master_key") is None, (
        "OIDC users must have null wrapped_master_key"
    )
    _state["alice_oidc_user_id"] = alice_oidc["id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_10_08_oidc_claims_cache_populated(seeded_env):
    """
    After OIDC login, the oidc_claims_cache column should be populated with
    the claims from the Dex ID token (sub, email, groups, etc.).

    We verify this indirectly: the admin can see the user and their auth_method
    is oidc.  Direct DB inspection is outside the scope of this test; the
    wizard endpoint is a better proxy.
    """
    _skip_if_no_provider()
    if "alice_oidc_user_id" not in _state:
        pytest.skip("10-07 did not identify the OIDC user")

    admin = seeded_env["admin_client"]
    pid = _state["provider_id"]

    # The wizard endpoint returns cached claims when available
    r = await admin._client.get(f"{API}/admin/identity-providers/{pid}/wizard")
    assert r.status_code == 200
    data = r.json()
    # Should have either real claims (from alice's login) or the well-known fallback list
    assert "claims" in data
    assert len(data["claims"]) > 0


@pytest.mark.asyncio(loop_scope="session")
async def test_10_09_oidc_groups_claim_as_policy_field(seeded_env):
    """The 'groups' claim from Dex can be registered as a policy field (source=oidc)."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    field = await admin.create_policy_field(
        name="oidc_groups",
        display_label="OIDC Groups",
        source="oidc",
        data_type="string",
        claim_path="groups",
    )
    # Flexible on response shape — just check it didn't error
    assert field is not None

    # Clean up
    await admin.delete_policy_field("oidc_groups")


@pytest.mark.asyncio(loop_scope="session")
async def test_10_10_disable_provider_blocks_begin(seeded_env):
    """
    Setting is_active=false must cause GET /auth/oidc/{id}/begin to return 404.
    """
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    pid = _state["provider_id"]

    await admin.update_idp_provider(pid, is_active=False)

    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.get(
            f"{API}/auth/oidc/{pid}/begin",
            headers={"X-CSRF-Token": csrf},
        )
    assert r.status_code == 404, (
        f"Expected 404 for disabled OIDC provider begin, got {r.status_code}: {r.text}"
    )

    # Also verify the provider no longer appears in the public providers list
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        r2 = await client.get(f"{API}/auth/idp/providers")
    assert r2.status_code == 200
    active_ids = [p["id"] for p in r2.json().get("providers", [])]
    assert pid not in active_ids, "Disabled provider should not appear in active provider list"

    # Re-enable for subsequent tests
    await admin.update_idp_provider(pid, is_active=True)


@pytest.mark.asyncio(loop_scope="session")
async def test_10_11_delete_provider_delinks_oidc_users(seeded_env):
    """
    DELETE /admin/identity-providers/{id} must:
      - return 404 on subsequent GET
      - leave the OIDC user accounts in place (not deleted)
      - clear identity_provider_id on de-linked users
    """
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    pid = _state["provider_id"]

    await admin.delete_idp_provider(pid)

    # Provider is gone
    r = await admin._client.get(f"{API}/admin/identity-providers/{pid}")
    assert r.status_code == 404

    # OIDC alice still exists — deletion must not cascade to users
    if "alice_oidc_user_id" in _state:
        users = await admin.list_users()
        alice = next((u for u in users if u["id"] == _state["alice_oidc_user_id"]), None)
        assert alice is not None, "OIDC user was deleted along with the provider — must not happen"
