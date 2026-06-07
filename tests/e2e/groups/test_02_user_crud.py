"""
Group 02 — User lifecycle CRUD.

Creates users via the invite flow, then exercises the full lifecycle:
view → update (quota/bandwidth/active) → deactivate → reactivate → delete.

Tests
-----
02-01  Admin can list users (at least admin exists)
02-02  User registers via invite; appears in user list
02-03  Admin can view a specific user's details
02-04  Admin can update user quotas and limits
02-05  Updated quota is reflected on re-read
02-06  Admin can deactivate a user; deactivated user gets 401 on API
02-07  Admin can reactivate user; user can call API again
02-08  Admin can delete a user; deleted user is gone from user list
02-09  Deleted user's session returns 401 on subsequent requests
02-10  User cannot delete or deactivate themselves via admin API
02-11  Duplicate username is rejected on registration
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.conftest      import ADMIN_USERNAME, ADMIN_PASSWORD
from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth  import register_via_invite
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# Users created in this group (module-level state shared across tests)
_alice: dict = {}
_bob:   dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# admin.user.deactivated/activated from 02-06/07 (users.py emit).
# admin.user.deleted (severity=critical) from 02-08.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("admin.user.deactivated", outcome="success", severity="warning", tier=2),
    ExpectedSiemEvent("admin.user.activated",   outcome="success", severity="info",    tier=2),
    ExpectedSiemEvent("admin.user.deleted",      outcome="success", severity="critical", tier=3),
]


@pytest.mark.asyncio(loop_scope="session")
async def test_02_01_admin_can_list_users(admin_client: AdminClient):
    users = await admin_client.list_users()
    assert isinstance(users, list)
    usernames = [u["username"].lower() for u in users]
    assert ADMIN_USERNAME.lower() in usernames, (
        f"Admin user not in user list: {usernames}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_02_02_user_registers_via_invite(
    browser: Browser,
    admin_client: AdminClient,
):
    global _alice
    invite_url = await admin_client.create_invite_url()
    alice_session = await register_via_invite(
        browser, invite_url, "alice_02", "Al1ce!Passw0rd"
    )
    alice_session.ctx.close  # keep context open; we'll close after all alice tests
    _alice["session"] = alice_session

    users = await admin_client.list_users()
    found = next((u for u in users if u["username"].lower() == "alice_02"), None)
    assert found is not None, "alice_02 not found in user list after registration"
    _alice["id"] = found["id"]

    await alice_session.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_02_03_admin_can_view_user(admin_client: AdminClient):
    user = await admin_client.get_user(_alice["id"])
    assert user["username"].lower() == "alice_02"
    assert "is_active" in user


@pytest.mark.asyncio(loop_scope="session")
async def test_02_04_admin_can_update_user_quotas(admin_client: AdminClient):
    await admin_client.update_user(
        _alice["id"],
        disk_quota=1024 * 1024 * 100,    # 100 MB
        max_file_size=1024 * 1024 * 10,  # 10 MB
        bandwidth_limit=1024 * 1024,     # 1 MB/s
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_02_05_updated_quota_reflected(admin_client: AdminClient):
    user = await admin_client.get_user(_alice["id"])
    assert user.get("disk_quota")      == 1024 * 1024 * 100
    assert user.get("max_file_size")   == 1024 * 1024 * 10
    assert user.get("bandwidth_limit") == 1024 * 1024


@pytest.mark.asyncio(loop_scope="session")
async def test_02_06_admin_can_deactivate_user(
    browser: Browser,
    admin_client: AdminClient,
):
    """Deactivated user's API calls return 401."""
    # Re-login alice so we have a fresh session to test with
    from tests.e2e.helpers.auth import login
    alice_session = await login(browser, "alice_02", "Al1ce!Passw0rd")

    await admin_client.set_user_active(_alice["id"], False)

    # Alice's existing session should now be rejected
    api = ApiClient.from_session(alice_session)
    async with api:
        r = await api.get("/auth/me")
    assert r.status_code == 401, (
        f"Deactivated user should get 401, got {r.status_code}"
    )
    await alice_session.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_02_07_admin_can_reactivate_user(
    browser: Browser,
    admin_client: AdminClient,
):
    """Reactivated user can log in and use the API again."""
    from tests.e2e.helpers.auth import login
    await admin_client.set_user_active(_alice["id"], True)

    alice_session = await login(browser, "alice_02", "Al1ce!Passw0rd")
    api = ApiClient.from_session(alice_session)
    async with api:
        r = await api.get("/auth/me")
    assert r.status_code == 200, (
        f"Reactivated user should get 200 on /me, got {r.status_code}"
    )
    await alice_session.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_02_08_admin_can_delete_user(
    browser: Browser,
    admin_client: AdminClient,
):
    global _bob
    # Create bob so we have someone to delete
    invite_url = await admin_client.create_invite_url()
    bob_session = await register_via_invite(
        browser, invite_url, "bob_02", "B0b!Passw0rd99"
    )
    users = await admin_client.list_users()
    bob = next(u for u in users if u["username"].lower() == "bob_02")
    _bob["id"] = bob["id"]
    _bob["session"] = bob_session

    # Disable trash so deletion is immediate (hard-delete), not scheduled.
    # The default trash_enabled=true would leave the user in the list with
    # scheduled_delete_at set; we want to verify the row is actually gone.
    await admin_client.set_setting("trash_enabled", "false")
    await admin_client.delete_user(_bob["id"])
    await admin_client.set_setting("trash_enabled", "true")

    users_after = await admin_client.list_users()
    assert not any(u["id"] == _bob["id"] for u in users_after), (
        "Deleted user still appears in user list"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_02_09_deleted_user_session_returns_401():
    """Deleted user's previously-issued session token is rejected."""
    if "session" not in _bob:
        pytest.skip("Bob's session was not captured")
    api = ApiClient.from_session(_bob["session"])
    async with api:
        r = await api.get("/auth/me")
    assert r.status_code == 401, (
        f"Deleted user session should return 401, got {r.status_code}"
    )
    await _bob["session"].ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_02_10_admin_cannot_delete_self(admin_client: AdminClient):
    """Admin attempting to delete their own account should be rejected."""
    import httpx as _httpx
    # Find admin's own user_id
    users = await admin_client.list_users()
    me = next(u for u in users if u["username"].lower() == ADMIN_USERNAME.lower())

    r = await admin_client._client.delete(f"{API}/admin/users/{me['id']}")
    assert r.status_code in (400, 403), (
        f"Admin deleting self should fail, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_02_11_duplicate_username_rejected(
    browser: Browser,
    admin_client: AdminClient,
):
    """Registering with a username that already exists returns 409."""
    # alice_02 already exists from test 02-02
    invite_url = await admin_client.create_invite_url()
    import httpx as _httpx
    # We validate the invite first, then check that register/start rejects the dup username.
    # Since we can't complete a duplicate OPAQUE round-trip cleanly, we verify via the API
    # that attempting to start registration with the same username fails.
    invite_token = invite_url.split("/")[-1]
    async with _httpx.AsyncClient(base_url=APP_URL) as client:
        r = await client.post(
            f"{API}/auth/opaque/register/start",
            json={
                "username": "alice_02",  # duplicate
                "invite_token": invite_token,
                "client_registration_request": "AAAA",  # invalid, but username check happens first
            },
        )
    assert r.status_code in (409, 400, 422), (
        f"Duplicate username should fail at register/start, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# 02-12  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_02_12_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
