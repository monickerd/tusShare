"""
Group 03 — Role CRUD.

Tests creating, reading, updating, and deleting custom roles, plus granting
and revoking them from users.

Tests
-----
03-01  System roles exist and are listed
03-02  Admin can create a custom role
03-03  Custom role appears in role list
03-04  Admin can read role details
03-05  Admin can update a role's name and description
03-06  Admin can set permission flags on a role
03-07  Admin can grant a custom role to a user
03-08  Granted role appears in user's role list
03-09  Admin can revoke a role from a user
03-10  Revoked role disappears from user's role list
03-11  Admin cannot delete a system role
03-12  Admin can delete a custom role
03-13  Deleting a role removes it from all users who held it
03-15  can_create_roles required to create a role (can_manage_roles alone is not enough)
03-16  Inheritance cap: cannot create a role with flags the creator does not hold
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth  import register_via_invite
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

SYSTEM_ROLE_NAMES = {
    "server_admin", "org_admin", "operational_admin",
    "team_admin", "team_manager", "team_member",
    "role_admin", "role_user",
    # team-scoped built-ins
    "team_owner", "team_supervisor",
}

# Module-level state
_custom_role:   dict = {}
_user_for_role: dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# admin.role.granted: 03-07, 03-13, 03-15, 03-16 (grant_role emits via users.py).
# admin.role.revoked: 03-09 (revoke_role emits via users.py).
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("admin.role.granted", outcome="success", severity="warning", tier=2),
    ExpectedSiemEvent("admin.role.revoked", outcome="success", severity="warning", tier=2),
]


@pytest.mark.asyncio(loop_scope="session")
async def test_03_01_system_roles_exist(admin_client: AdminClient):
    roles = await admin_client.list_roles()
    role_ids = {r["id"] for r in roles}
    # At minimum, role_user and team_member should exist (checked by ID)
    for expected in ("role_user", "team_member"):
        assert expected in role_ids, (
            f"System role '{expected}' not found. Got: {role_ids}"
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_03_02_admin_creates_custom_role(admin_client: AdminClient):
    global _custom_role
    role = await admin_client.create_role(
        name="test_viewer",
        description="Read-only test role",
    )
    assert role["name"] == "test_viewer"
    assert role.get("is_system") is False
    _custom_role = role


@pytest.mark.asyncio(loop_scope="session")
async def test_03_03_custom_role_in_list(admin_client: AdminClient):
    roles = await admin_client.list_roles()
    ids = [r["id"] for r in roles]
    assert _custom_role["id"] in ids


@pytest.mark.asyncio(loop_scope="session")
async def test_03_04_admin_can_read_role(admin_client: AdminClient):
    role = await admin_client.get_role(_custom_role["id"])
    assert role["id"]   == _custom_role["id"]
    assert role["name"] == "test_viewer"


@pytest.mark.asyncio(loop_scope="session")
async def test_03_05_admin_can_update_role(admin_client: AdminClient):
    updated = await admin_client.update_role(
        _custom_role["id"],
        name="test_viewer_updated",
        description="Updated description",
    )
    assert updated["name"] == "test_viewer_updated"
    # Patch back to original name so subsequent tests are consistent
    await admin_client.update_role(_custom_role["id"], name="test_viewer")


@pytest.mark.asyncio(loop_scope="session")
async def test_03_06_admin_can_set_permission_flags(admin_client: AdminClient):
    result = await admin_client.set_role_permissions(
        _custom_role["id"],
        flags={
            "admin_panel_view": True,
            "users_manage":     False,
        },
    )
    # The response should reflect the flags we set
    assert result.get("admin_panel_view") is True
    assert result.get("users_manage")     is False


@pytest.mark.asyncio(loop_scope="session")
async def test_03_07_admin_grants_role_to_user(
    browser: Browser,
    admin_client: AdminClient,
):
    global _user_for_role
    invite_url = await admin_client.create_invite_url()
    from tests.e2e.helpers.auth import register_via_invite
    sess = await register_via_invite(browser, invite_url, "carol_03", "Car0l!Pwd99")

    users = await admin_client.list_users()
    carol = next(u for u in users if u["username"].lower() == "carol_03")
    _user_for_role = {"id": carol["id"], "session": sess}

    await admin_client.grant_role(carol["id"], _custom_role["id"])


@pytest.mark.asyncio(loop_scope="session")
async def test_03_08_granted_role_in_user_roles(admin_client: AdminClient):
    roles = await admin_client.get_user_roles(_user_for_role["id"])
    role_ids = [r["role_id"] for r in roles]
    assert _custom_role["id"] in role_ids, (
        f"Granted role not found in user's roles: {role_ids}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_03_09_admin_revokes_role(admin_client: AdminClient):
    await admin_client.revoke_role(_user_for_role["id"], _custom_role["id"])


@pytest.mark.asyncio(loop_scope="session")
async def test_03_10_revoked_role_absent(admin_client: AdminClient):
    roles = await admin_client.get_user_roles(_user_for_role["id"])
    role_ids = [r["role_id"] for r in roles]
    assert _custom_role["id"] not in role_ids


@pytest.mark.asyncio(loop_scope="session")
async def test_03_11_cannot_delete_system_role(admin_client: AdminClient):
    roles = await admin_client.list_roles()
    system = next(r for r in roles if r.get("is_system") is True)
    r = await admin_client._client.delete(f"/api/v1/admin/roles/{system['id']}")
    assert r.status_code in (400, 403), (
        f"Deleting a system role should fail, got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_03_12_admin_can_delete_custom_role(admin_client: AdminClient):
    # Create a fresh role to delete (don't reuse _custom_role — it may be in use)
    role = await admin_client.create_role(name="role_to_delete")
    await admin_client.delete_role(role["id"])

    roles = await admin_client.list_roles()
    assert not any(r["id"] == role["id"] for r in roles)


@pytest.mark.asyncio(loop_scope="session")
async def test_03_13_deleting_role_removes_from_users(admin_client: AdminClient):
    """Grant a role, delete the role, verify the user no longer has it."""
    role = await admin_client.create_role(name="ephemeral_role")
    await admin_client.grant_role(_user_for_role["id"], role["id"])

    roles_before = await admin_client.get_user_roles(_user_for_role["id"])
    assert any(r["role_id"] == role["id"] for r in roles_before)

    await admin_client.delete_role(role["id"])

    roles_after = await admin_client.get_user_roles(_user_for_role["id"])
    assert not any(r["role_id"] == role["id"] for r in roles_after)

    # Cleanup
    if "session" in _user_for_role:
        await _user_for_role["session"].ctx.close()


# ---------------------------------------------------------------------------
# 03-15  can_create_roles required to create (separate from can_manage_roles)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_03_15_can_create_roles_required(
    browser: Browser,
    admin_client: AdminClient,
):
    """A user with only can_manage_roles (but not can_create_roles) cannot create a role.

    Verifies the Phase 1 overhaul split: create_role now requires the
    dedicated can_create_roles flag; can_manage_roles alone only covers
    update/delete/assign operations.
    """
    url  = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, url, "role_mgr_03", "R0le!Mgr99")
    users = await admin_client.list_users()
    mgr = next(u for u in users if u["username"].lower() == "role_mgr_03")

    # Grant a custom role that has can_manage_roles but not can_create_roles
    mgr_role = await admin_client.create_role(name="manage_only_role_03")
    await admin_client.set_role_permissions(
        mgr_role["id"],
        {"admin_panel_view": True, "roles_manage": True, "roles_create": False},
    )
    await admin_client.grant_role(mgr["id"], mgr_role["id"])

    api = ApiClient.from_session(sess)
    try:
        r = await api.post(
            "/admin/roles",
            json={"id": "should_be_blocked_03", "name": "Should Not Create"},
        )
        assert r.status_code == 403, (
            f"can_manage_roles without can_create_roles must block role creation; "
            f"got {r.status_code}: {r.text}"
        )
    finally:
        await api.aclose()
        await sess.ctx.close()
        await admin_client.delete_role(mgr_role["id"])


# ---------------------------------------------------------------------------
# 03-16  Inheritance cap: cannot create a role granting a flag you do not hold
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_03_16_inheritance_cap_blocks_unowned_flag(
    browser: Browser,
    admin_client: AdminClient,
):
    """A limited admin cannot create a role that grants a flag they do not hold.

    The inheritance cap (enforced in create_role) prevents privilege escalation
    by ensuring new roles are strict subsets of the creator's own flag set.
    Here can_access_all_files is a sensitive flag the limited admin does not have;
    trying to create a role with that flag must return 403.
    """
    url  = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, url, "limited_admin_03", "L1m1ted!Admin03")
    users = await admin_client.list_users()
    la = next(u for u in users if u["username"].lower() == "limited_admin_03")

    # Grant only can_view_admin_panel + can_create_roles (not can_access_all_files)
    la_role = await admin_client.create_role(name="limited_creator_role_03")
    await admin_client.set_role_permissions(
        la_role["id"],
        {"admin_panel_view": True, "roles_create": True},
    )
    await admin_client.grant_role(la["id"], la_role["id"])

    api = ApiClient.from_session(sess)
    try:
        r = await api.post(
            "/admin/roles",
            json={
                "id":          "escalation_attempt_03",
                "name":        "Escalation Attempt",
                "permissions": {"files_access_all_read": "1"},
            },
        )
        assert r.status_code == 403, (
            f"Inheritance cap must block granting an unowned flag; "
            f"got {r.status_code}: {r.text}"
        )
    finally:
        await api.aclose()
        await sess.ctx.close()
        await admin_client.delete_role(la_role["id"])


# ---------------------------------------------------------------------------
# 03-17  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_03_17_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
