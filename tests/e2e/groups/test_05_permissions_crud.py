"""
Group 05 — Permission flag enforcement.

Tests that each permission flag on a role actually controls access to the
corresponding endpoint. The pattern is:
  1. Create a custom role with a specific flag enabled
  2. Assign it to a test user
  3. Verify the user can reach the guarded endpoint
  4. Revoke the flag (update role)
  5. Verify the user is now blocked

This is separate from group 03 (role CRUD) — here we focus on whether the
flags actually enforce access at the HTTP layer.

Permission flags tested
-----------------------
can_view_admin_panel      → GET /api/v1/admin/settings (200 vs 403)
can_manage_users          → GET /api/v1/admin/users    (200 vs 403)
can_manage_roles          → GET /api/v1/admin/roles    (200 vs 403)
can_create_invites        → POST /api/v1/admin/invites (200 vs 403)
can_view_all_users        → GET /api/v1/admin/users    (200 vs 403)

Additional edge cases
---------------------
05-09  A user with no extra roles cannot access any admin endpoint
05-10  Granting then revoking a flag restores the blocked state
"""

from __future__ import annotations

import pytest
import httpx
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth  import register_via_invite, login

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# Module-level test state
_test_user: dict = {}
_test_role: dict = {}


async def _get_user_api(browser: Browser, admin_client: AdminClient, username: str, password: str) -> tuple:
    """Register a user and return (user_dict, ApiClient). Also store session."""
    invite_url = await admin_client.create_invite_url()
    session = await register_via_invite(browser, invite_url, username, password)
    users = await admin_client.list_users()
    user = next(u for u in users if u["username"].lower() == username.lower())
    api  = ApiClient.from_session(session)
    return user, api, session


@pytest.fixture(scope="module", autouse=True)
async def setup_test_user(browser: Browser, admin_client: AdminClient):
    """Register the user and role used by all permission tests."""
    global _test_user, _test_role

    invite_url = await admin_client.create_invite_url()
    session = await register_via_invite(browser, invite_url, "perm_user_05", "Perm!Passw0rd")
    users = await admin_client.list_users()
    user  = next(u for u in users if u["username"].lower() == "perm_user_05")
    _test_user = {"id": user["id"], "session": session, "username": "perm_user_05", "password": "Perm!Passw0rd"}

    role = await admin_client.create_role(name="perm_test_role_05")
    _test_role = role

    yield

    await session.ctx.close()
    await admin_client.delete_role(_test_role["id"])


# ---------------------------------------------------------------------------
# Helper: check endpoint, optionally as fresh login (cookie refresh)
# ---------------------------------------------------------------------------

async def _check(session, method: str, path: str) -> int:
    api = ApiClient.from_session(session)
    async with api:
        fn = getattr(api, method)
        r  = await fn(path)
    return r.status_code


# ---------------------------------------------------------------------------
# can_view_admin_panel
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_05_01_no_flag_blocks_admin_settings():
    r_status = await _check(_test_user["session"], "get", "/admin/settings")
    assert r_status == 403, f"User without flag should be blocked from admin settings"


@pytest.mark.asyncio(loop_scope="session")
async def test_05_02_can_view_admin_panel_flag_grants_access(admin_client: AdminClient):
    await admin_client.set_role_permissions(
        _test_role["id"], {"can_view_admin_panel": True}
    )
    await admin_client.grant_role(_test_user["id"], _test_role["id"])

    r_status = await _check(_test_user["session"], "get", "/admin/settings")
    assert r_status == 200, f"User with can_view_admin_panel should see settings"


@pytest.mark.asyncio(loop_scope="session")
async def test_05_03_revoking_flag_blocks_again(admin_client: AdminClient):
    await admin_client.set_role_permissions(
        _test_role["id"], {"can_view_admin_panel": False}
    )
    r_status = await _check(_test_user["session"], "get", "/admin/settings")
    assert r_status == 403, f"After flag revoked, should be blocked again"


# ---------------------------------------------------------------------------
# can_manage_users / can_view_all_users
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_05_04_can_manage_users_flag(admin_client: AdminClient):
    await admin_client.set_role_permissions(
        _test_role["id"],
        {"can_view_admin_panel": True, "can_manage_users": True},
    )
    r_status = await _check(_test_user["session"], "get", "/admin/users")
    assert r_status == 200, "User with can_manage_users should list users"


@pytest.mark.asyncio(loop_scope="session")
async def test_05_05_removing_manage_users_blocks(admin_client: AdminClient):
    await admin_client.set_role_permissions(
        _test_role["id"],
        {"can_view_admin_panel": True, "can_manage_users": False},
    )
    r_status = await _check(_test_user["session"], "get", "/admin/users")
    assert r_status == 403, "Without can_manage_users should be blocked"


# ---------------------------------------------------------------------------
# can_manage_roles
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_05_06_can_manage_roles_flag(admin_client: AdminClient):
    await admin_client.set_role_permissions(
        _test_role["id"],
        {"can_view_admin_panel": True, "can_manage_roles": True},
    )
    r_status = await _check(_test_user["session"], "get", "/admin/roles")
    assert r_status == 200, "User with can_manage_roles should list roles"


@pytest.mark.asyncio(loop_scope="session")
async def test_05_07_removing_manage_roles_blocks(admin_client: AdminClient):
    await admin_client.set_role_permissions(
        _test_role["id"],
        {"can_view_admin_panel": True, "can_manage_roles": False},
    )
    r_status = await _check(_test_user["session"], "get", "/admin/roles")
    assert r_status == 403


# ---------------------------------------------------------------------------
# can_create_invites
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_05_08_can_create_invites_flag(admin_client: AdminClient):
    await admin_client.set_role_permissions(
        _test_role["id"],
        {"can_view_admin_panel": True, "can_manage_invites": True},
    )
    api = ApiClient.from_session(_test_user["session"])
    async with api:
        r = await api.post("/admin/invites")
    # 200 means they can create invites; 403 means the flag doesn't work
    assert r.status_code == 200, (
        f"User with can_create_invites should create invites, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_05_09_plain_user_blocked_from_all_admin(
    browser: Browser,
    admin_client: AdminClient,
):
    """A freshly registered user with no extra roles cannot touch any admin endpoint."""
    invite_url = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, invite_url, "plain_user_05", "Pla1n!Pwd99")
    try:
        api = ApiClient.from_session(sess)
        async with api:
            for path in ("/admin/settings", "/admin/users", "/admin/roles", "/admin/invites"):
                r = await api.get(path)
                assert r.status_code == 403, (
                    f"Plain user should not access {path}, got {r.status_code}"
                )
    finally:
        await sess.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_05_10_grant_revoke_cycle(admin_client: AdminClient):
    """Grant → verify access → revoke → verify blocked (full cycle)."""
    await admin_client.set_role_permissions(
        _test_role["id"], {"can_view_admin_panel": True}
    )
    assert await _check(_test_user["session"], "get", "/admin/settings") == 200

    await admin_client.revoke_role(_test_user["id"], _test_role["id"])
    assert await _check(_test_user["session"], "get", "/admin/settings") == 403

    # Re-grant so teardown fixture can clean up without role-in-use errors
    await admin_client.grant_role(_test_user["id"], _test_role["id"])
