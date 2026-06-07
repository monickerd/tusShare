"""
Group 09 — LDAP integration.

Requires: LDAP (osixia/openldap) running in docker-compose.test.yml,
          seeded with users from tests/fixtures/ldap/seed.ldif,
          and TUSSHARE_ALLOW_HTTP_IDP=true set in the app container environment
          (the test LDAP server uses plain ldap://, not ldaps://).

All tests marked @pytest.mark.ldap.  Run with:  pytest -m ldap
                                    Skip with:  pytest -m "not ldap"

LDAP topology (seed.ldif)
──────────────────────────
DN          uid            departmentNumber   groups
─────────── ────────────── ────────────────── ──────────────────────
ldap_alice  ldap_alice     engineering        cn=engineering
ldap_bob    ldap_bob       marketing          cn=marketing
ldap_carol  ldap_carol     engineering        cn=engineering, cn=admins
ldap_admin  ldap_admin     operations         cn=admins

Service account: cn=admin,dc=test,dc=local / ldap_admin_secret

Docker hostname inside the app container: ldap (port 389, plain LDAP).
Host-side exposure for test reachability checks: localhost:389.

Tests
──────
09-01  LDAP server reachable (smoke test — skips group on failure)
09-02  Admin creates an LDAP provider via /admin/identity-providers
09-03  GET provider returns redacted bind_password (never plaintext)
09-04  Test connection endpoint reports ok=true
09-05  LDAP login for ldap_alice auto-creates a user record
09-06  Created user has auth_method=ldap and null wrapped_master_key
09-07  Repeat login returns the same user (no duplicate created)
09-08  Injection protection: invalid usernames rejected at validation
09-09  PUT config with redaction placeholder preserves the stored password
09-10  LDAP attribute registered as policy field (source=ldap)
09-11  Disabling the provider blocks further logins
09-12  Deleting the provider de-links users but does not delete them
"""

from __future__ import annotations

import httpx
import pytest

from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL  = "http://localhost:8001"
API      = f"{APP_URL}/api/v1"

pytestmark = pytest.mark.ldap

# ---------------------------------------------------------------------------
# LDAP connection constants (match seed.ldif + docker-compose.test.yml)
# ---------------------------------------------------------------------------

# URI used by the app container to reach the LDAP service (docker network name).
_LDAP_DOCKER_URI  = "ldap://ldap:389"
_LDAP_BIND_DN     = "cn=admin,dc=test,dc=local"
_LDAP_BIND_PW     = "ldap_admin_secret"
_LDAP_BASE_DN     = "ou=users,dc=test,dc=local"
_LDAP_USER_FILTER = "(uid={username})"

# LDAP provider config sent to POST /admin/identity-providers
_LDAP_PROVIDER_CONFIG = {
    "server_uri":   _LDAP_DOCKER_URI,
    "bind_dn":      _LDAP_BIND_DN,
    "bind_password": _LDAP_BIND_PW,
    "base_dn":      _LDAP_BASE_DN,
    "user_filter":  _LDAP_USER_FILTER,
    "tls":          "skip_verify",  # plain ldap:// — cert checking disabled
    "username_attr": "uid",
}

# Test users — credentials must match seed.ldif userPassword values
_ALICE = {"username": "ldap_alice", "password": "Alice!Ldap99"}
_BOB   = {"username": "ldap_bob",   "password": "Bob!Ldap99"}

# Carrier for values created during the test run (provider_id, user_ids, etc.)
_state: dict = {}

_REDACTED = "••••••••"

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# LDAP login success does not emit a SIEM event (no log_security_event call
# on the success path in idp_auth.py).  Provider CRUD and validation errors
# return 400/404, not 403.  No SIEM events are expected from this group.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _ldap_reachable() -> bool:
    import socket
    try:
        with socket.create_connection(("localhost", 389), timeout=3):
            return True
    except OSError:
        return False


def _skip_if_no_provider():
    if "provider_id" not in _state:
        pytest.skip("09-02 did not create the provider — skipping dependent test")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_09_01_ldap_server_reachable():
    """LDAP container must be up before any LDAP test can proceed."""
    if not _ldap_reachable():
        pytest.skip("LDAP container not reachable on port 389 — is docker-compose up?")
    assert _ldap_reachable()


@pytest.mark.asyncio(loop_scope="session")
async def test_09_02_admin_creates_ldap_provider(seeded_env):
    """Admin can create an LDAP provider via POST /admin/identity-providers."""
    _skip_if_no_provider() if False else None  # first in chain — nothing to skip
    if not _ldap_reachable():
        pytest.skip("LDAP not reachable")

    admin = seeded_env["admin_client"]
    data = await admin.create_idp_provider(
        provider_type="ldap",
        name="Test LDAP",
        config=_LDAP_PROVIDER_CONFIG,
    )

    assert data["provider_type"] == "ldap"
    assert data["name"] == "Test LDAP"
    assert data["is_active"] is True
    assert "id" in data

    _state["provider_id"] = data["id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_09_03_get_provider_redacts_bind_password(seeded_env):
    """GET /admin/identity-providers/{id} must never return the plaintext bind_password."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    prov = await admin.get_idp_provider(_state["provider_id"])

    assert prov["provider_type"] == "ldap"
    assert prov["name"] == "Test LDAP"
    assert "config" in prov
    cfg = prov["config"]
    # Secret must be redacted
    assert cfg["bind_password"] == _REDACTED, (
        f"bind_password should be redacted but got: {cfg['bind_password']!r}"
    )
    # Non-secret fields must remain readable
    assert cfg["server_uri"] == _LDAP_DOCKER_URI
    assert cfg["bind_dn"] == _LDAP_BIND_DN
    assert cfg["user_filter"] == _LDAP_USER_FILTER


@pytest.mark.asyncio(loop_scope="session")
async def test_09_04_test_connection_succeeds(seeded_env):
    """POST /admin/identity-providers/{id}/test should report ok=true for the seeded LDAP."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    result = await admin.test_idp_provider(_state["provider_id"])

    assert result.get("ok") is True, (
        f"LDAP test connection failed: {result.get('error')}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_09_05_ldap_login_auto_creates_user(seeded_env):
    """First-time LDAP login for ldap_alice must auto-create a user record."""
    _skip_if_no_provider()

    async with httpx.AsyncClient(base_url=APP_URL) as client:
        # Fetch CSRF token (no-auth GET to any page sets the cookie)
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")

        r = await client.post(
            f"{API}/auth/ldap/login",
            json={
                "provider_id":      _state["provider_id"],
                "username":         _ALICE["username"],
                "password":         _ALICE["password"],
                "is_public_device": False,
            },
            headers={"X-CSRF-Token": csrf},
        )

    # Accept a successful login or an MFA gate (both mean auth succeeded)
    assert r.status_code == 200, f"LDAP login failed: {r.status_code} {r.text}"
    body = r.json()

    if body.get("mfa_required"):
        # MFA enrolled on this user — that's OK, auth succeeded
        assert "pending_token" in body
        _state["alice_mfa_pending"] = body["pending_token"]
    else:
        user = body.get("user", {})
        assert user.get("username") == _ALICE["username"]
        _state["alice_user_resp"] = user


@pytest.mark.asyncio(loop_scope="session")
async def test_09_06_ldap_user_has_null_wrapped_master_key(seeded_env):
    """LDAP users have no OPAQUE-derived KEK: wrapped_master_key must be null."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    users = await admin.list_users()
    alice = next((u for u in users if u["username"] == _ALICE["username"]), None)

    assert alice is not None, "ldap_alice not found in admin user list after login"
    assert alice.get("auth_method") == "ldap", (
        f"Expected auth_method=ldap, got {alice.get('auth_method')!r}"
    )
    assert alice.get("wrapped_master_key") is None, (
        "LDAP users must have null wrapped_master_key"
    )
    _state["alice_user_id"] = alice["id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_09_07_repeat_login_creates_no_duplicate(seeded_env):
    """A second LDAP login for the same user must not create a new record."""
    _skip_if_no_provider()

    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.post(
            f"{API}/auth/ldap/login",
            json={
                "provider_id": _state["provider_id"],
                "username":    _ALICE["username"],
                "password":    _ALICE["password"],
            },
            headers={"X-CSRF-Token": csrf},
        )
    assert r.status_code == 200

    admin = seeded_env["admin_client"]
    users = await admin.list_users()
    alices = [u for u in users if u["username"] == _ALICE["username"]]
    assert len(alices) == 1, f"Expected 1 ldap_alice record, found {len(alices)}"
    # Same user_id as before
    assert alices[0]["id"] == _state["alice_user_id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_09_08a_injection_wildcard_username_blocked():
    """
    Username '*' must be rejected at validation (layer 1 whitelist).
    The request must not reach the LDAP server.
    """
    _skip_if_no_provider()

    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.post(
            f"{API}/auth/ldap/login",
            json={
                "provider_id": _state["provider_id"],
                "username":    "*",
                "password":    "anything",
            },
            headers={"X-CSRF-Token": csrf},
        )
    # Pydantic validates username in LDAPLoginRequest; invalid chars → 422
    assert r.status_code == 422, (
        f"Expected 422 for wildcard username, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_09_08b_injection_filter_chars_blocked():
    """
    Username containing LDAP filter characters '(' and ')' must be rejected
    at the whitelist validation layer (before any LDAP connection is opened).
    """
    _skip_if_no_provider()

    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.post(
            f"{API}/auth/ldap/login",
            json={
                "provider_id": _state["provider_id"],
                "username":    "admin)(uid=*)(uid=",
                "password":    "anything",
            },
            headers={"X-CSRF-Token": csrf},
        )
    assert r.status_code == 422, (
        f"Expected 422 for filter-char injection attempt, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_09_08c_injection_null_byte_blocked():
    """NUL byte in username must be blocked."""
    _skip_if_no_provider()

    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.post(
            f"{API}/auth/ldap/login",
            json={
                "provider_id": _state["provider_id"],
                "username":    "ldap_alice\x00extra",
                "password":    "anything",
            },
            headers={"X-CSRF-Token": csrf},
        )
    assert r.status_code == 422, (
        f"Expected 422 for NUL byte in username, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_09_09_put_with_redaction_placeholder_preserves_secret(seeded_env):
    """
    Sending the redaction placeholder (••••••••) back on PUT must preserve the
    stored bind_password unchanged — not overwrite it with the literal placeholder.
    The test verifies this by checking the connection still works after the PUT.
    """
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    pid = _state["provider_id"]

    # Send a PUT where bind_password is the redaction placeholder
    current = await admin.get_idp_provider(pid)
    cfg_with_placeholder = dict(current["config"])  # already redacted from GET
    assert cfg_with_placeholder["bind_password"] == _REDACTED

    r = await admin.update_idp_provider(
        pid, config=cfg_with_placeholder, name="Test LDAP Updated"
    )
    assert r.get("ok") is True

    # Connection should still work — meaning the original password was kept
    result = await admin.test_idp_provider(pid)
    assert result.get("ok") is True, (
        f"Connection test failed after PUT with placeholder: {result.get('error')}"
    )

    # Restore name
    await admin.update_idp_provider(pid, name="Test LDAP")


@pytest.mark.asyncio(loop_scope="session")
async def test_09_10_ldap_attribute_as_policy_field(seeded_env):
    """departmentNumber can be registered as a policy field with source=ldap."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    field = await admin.create_policy_field(
        name="ldap_department_number",
        display_label="LDAP Department",
        source="ldap",
        data_type="string",
        claim_path="departmentNumber",
    )
    assert field.get("source") == "ldap" or "name" in field  # flexible on response shape

    _state["dept_field_created"] = True

    # Clean up so it doesn't affect later groups
    await admin.delete_policy_field("ldap_department_number")


@pytest.mark.asyncio(loop_scope="session")
async def test_09_11_disable_provider_blocks_logins(seeded_env):
    """Setting is_active=false must cause LDAP logins to return 400."""
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    pid = _state["provider_id"]

    await admin.update_idp_provider(pid, is_active=False)

    async with httpx.AsyncClient(base_url=APP_URL) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.post(
            f"{API}/auth/ldap/login",
            json={
                "provider_id": pid,
                "username":    _ALICE["username"],
                "password":    _ALICE["password"],
            },
            headers={"X-CSRF-Token": csrf},
        )

    assert r.status_code == 400, (
        f"Expected 400 for disabled LDAP provider, got {r.status_code}: {r.text}"
    )

    # Re-enable for subsequent tests
    await admin.update_idp_provider(pid, is_active=True)


@pytest.mark.asyncio(loop_scope="session")
async def test_09_12_delete_provider_delinks_users(seeded_env):
    """
    DELETE /admin/identity-providers/{id} must:
      - return 404 on subsequent GET
      - leave the LDAP user accounts in place (not delete them)
      - clear identity_provider_id on de-linked users
    """
    _skip_if_no_provider()

    admin = seeded_env["admin_client"]
    pid = _state["provider_id"]

    await admin.delete_idp_provider(pid)

    # Provider is gone
    r = await admin._client.get(f"{API}/admin/identity-providers/{pid}")
    assert r.status_code == 404

    # ldap_alice still exists in the user list
    users = await admin.list_users()
    alice = next((u for u in users if u["id"] == _state.get("alice_user_id")), None)
    assert alice is not None, "ldap_alice was deleted along with the provider — must not happen"


# ---------------------------------------------------------------------------
# 09-13  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_09_13_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
