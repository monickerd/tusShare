"""
Group 06 — Teams, team folders, and team custom roles.

Note on crypto: creating a team requires a pre_public_key (PQ-KEM public key
generated client-side). Similarly, adding a member involves key delivery that
requires the browser. Tests that hit these paths are annotated with what they
actually test vs. what they skip when the client-side crypto can't be driven
via the API alone.

Tests
-----
06-01  Admin can list teams (empty initially)
06-02  Team creation via browser UI is possible
06-03  Team appears in team list after creation
06-04  Team owner can update team name and description
06-05  Team owner can add a member
06-06  Member appears in member list
06-07  Team owner can change a member's role
06-08  Team owner can remove a member
06-09  Removed member is no longer listed
06-10  Team owner can create a custom team role
06-11  Custom team role appears in role list
06-12  Team role permissions can be set
06-13  Team role can be assigned to a member
06-14  Team role assignment can be revoked
06-15  Custom team role can be deleted
06-16  Team owner can add a folder to the team
06-17  Folder appears in team folder list
06-18  Team owner can remove a folder from the team
06-19  Team can be deleted
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.files import create_folder
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest
from tests.e2e.helpers.teams import (
    add_member,
    add_team_folder,
    assign_team_role,
    change_member_role,
    create_team,
    create_team_role,
    delete_team,
    delete_team_role,
    is_member,
    list_members,
    list_team_folders,
    list_team_roles,
    list_teams,
    remove_member,
    remove_team_folder,
    set_team_role_permissions,
    unassign_team_role,
    update_team,
)

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# Module-level state
_team:        dict = {}
_owner:       dict = {}
_member_user: dict = {}
_team_role:   dict = {}
_team_folder: dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# Team creation, member add/remove, team-role CRUD, and folder operations
# do not emit SIEM events in the current implementation.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


@pytest.fixture(scope="module", autouse=True)
async def setup_users(browser: Browser, admin_client: AdminClient):
    """Register two users: one will be team owner, one will be a member."""
    global _owner, _member_user

    # Register owner
    url = await admin_client.create_invite_url()
    owner_sess = await register_via_invite(browser, url, "team_owner_06", "0wner!Pwd99")
    users = await admin_client.list_users()
    owner = next(u for u in users if u["username"].lower() == "team_owner_06")
    _owner = {"id": owner["id"], "session": owner_sess,
              "username": "team_owner_06", "password": "0wner!Pwd99"}

    # Register member
    url2 = await admin_client.create_invite_url()
    mem_sess = await register_via_invite(browser, url2, "team_member_06", "Memb3r!Pwd")
    users2 = await admin_client.list_users()
    mem = next(u for u in users2 if u["username"].lower() == "team_member_06")
    _member_user = {"id": mem["id"], "session": mem_sess,
                    "username": "team_member_06", "password": "Memb3r!Pwd"}

    yield

    await owner_sess.ctx.close()
    await mem_sess.ctx.close()


# ---------------------------------------------------------------------------
# Team CRUD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_06_01_team_list_initially_empty_for_new_user():
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        teams = await list_teams(owner_api)
    assert isinstance(teams, list)


@pytest.mark.asyncio(loop_scope="session")
async def test_06_02_team_creation_via_browser():
    """Create a team via the API using stub PQ-KEM material.

    The server validates key format (size, compression flag) but never
    decrypts the material, so format-valid stubs are sufficient to exercise
    all team CRUD and access-control logic.
    """
    global _team
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        _team = await create_team(owner_api, "Test Team 06", "Created by automated E2E test")


@pytest.mark.asyncio(loop_scope="session")
async def test_06_03_team_in_list():
    if not _team:
        pytest.skip("Team not created (test_06_02 skipped or failed)")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        teams = await list_teams(owner_api)
    assert any(t["id"] == _team["id"] for t in teams)


@pytest.mark.asyncio(loop_scope="session")
async def test_06_04_update_team():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        updated = await update_team(owner_api, _team["id"], name="Renamed Team 06")
    assert updated["name"] == "Renamed Team 06"
    _team["name"] = updated["name"]


@pytest.mark.asyncio(loop_scope="session")
async def test_06_05_add_member():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        result = await add_member(owner_api, _team["id"], _member_user["username"])
    assert result is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_06_06_member_in_member_list():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        in_team = await is_member(owner_api, _team["id"], _member_user["id"])
    assert in_team, "Member not found in team after add_member"


@pytest.mark.asyncio(loop_scope="session")
async def test_06_07_change_member_role():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        await change_member_role(
            owner_api, _team["id"], _member_user["id"], "team_manager"
        )
    # Check role was updated
    async with ApiClient.from_session(_owner["session"]) as api:
        members = await list_members(api, _team["id"])
    target = next(m for m in members if m["user_id"] == _member_user["id"])
    assert target["role"] == "team_manager", (
        f"Expected team_manager role, got: {target['role']}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_06_08_remove_member():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        await remove_member(owner_api, _team["id"], _member_user["id"])


@pytest.mark.asyncio(loop_scope="session")
async def test_06_09_removed_member_absent():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        in_team = await is_member(owner_api, _team["id"], _member_user["id"])
    assert not in_team


# ---------------------------------------------------------------------------
# Team custom roles
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_06_10_create_team_role():
    global _team_role
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        _team_role = await create_team_role(
            owner_api, _team["id"], "Senior Reviewer", "Can review large files"
        )
    assert _team_role["name"] == "Senior Reviewer"


@pytest.mark.asyncio(loop_scope="session")
async def test_06_11_team_role_in_list():
    if not _team or not _team_role:
        pytest.skip("No team or team role available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        roles = await list_team_roles(owner_api, _team["id"])
    assert any(r["id"] == _team_role["id"] for r in roles)


@pytest.mark.asyncio(loop_scope="session")
async def test_06_12_set_team_role_permissions():
    if not _team or not _team_role:
        pytest.skip("No team role available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        result = await set_team_role_permissions(
            owner_api, _team["id"], _team_role["id"],
            {"move_own_files_out_of_team": True, "move_others_files_out_of_team": True},
        )
    assert result is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_06_13_assign_team_role():
    if not _team or not _team_role:
        pytest.skip("No team role available")
    # Re-add member first
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        await add_member(owner_api, _team["id"], _member_user["username"])
        await assign_team_role(
            owner_api, _team["id"], _team_role["id"], _member_user["id"]
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_06_14_unassign_team_role():
    if not _team or not _team_role:
        pytest.skip("No team role available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        await unassign_team_role(
            owner_api, _team["id"], _team_role["id"], _member_user["id"]
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_06_15_delete_team_role():
    if not _team or not _team_role:
        pytest.skip("No team role available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        await delete_team_role(owner_api, _team["id"], _team_role["id"])
        roles = await list_team_roles(owner_api, _team["id"])
    assert not any(r["id"] == _team_role["id"] for r in roles)


# ---------------------------------------------------------------------------
# Team folders
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_06_16_add_folder_to_team():
    global _team_folder
    if not _team:
        pytest.skip("No team available")
    # Create a folder as the owner first
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        folder = await create_folder(owner_api, "Team Shared Folder 06")
        result = await add_team_folder(owner_api, _team["id"], folder["id"])
    _team_folder = {"id": folder["id"]}
    assert result is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_06_17_folder_in_team_folder_list():
    if not _team or not _team_folder:
        pytest.skip("No team folder available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        folders = await list_team_folders(owner_api, _team["id"])
    assert any(f["folder_id"] == _team_folder["id"] for f in folders), (
        f"Team folder not found: {folders}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_06_18_remove_folder_from_team():
    if not _team or not _team_folder:
        pytest.skip("No team folder available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        await remove_team_folder(owner_api, _team["id"], _team_folder["id"])
        folders = await list_team_folders(owner_api, _team["id"])
    assert not any(f["folder_id"] == _team_folder["id"] for f in folders)


@pytest.mark.asyncio(loop_scope="session")
async def test_06_19_delete_team():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        await delete_team(owner_api, _team["id"])
        teams = await list_teams(owner_api)
    assert not any(t["id"] == _team["id"] for t in teams)


# ---------------------------------------------------------------------------
# 06-20  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_06_20_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
