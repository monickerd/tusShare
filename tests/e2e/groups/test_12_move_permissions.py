"""
Group 12 — Share link revocation when a file is moved out of access.

Security scenario
-----------------
User A (file owner) uploads passwords.txt to a team folder shared with User B.
User B (a team member, not the file owner) creates a public share link for the
file while they have team-based access to it.

User A then moves the file out of the team folder into their personal space.

Expected outcomes
-----------------
- User B's share link no longer resolves (User B lost team access).
- User A's direct file access still works (owner always has access).
- If User A creates their own share link after the move, that link resolves
  (owner always has access).
- Moving the file BACK into the team folder restores User B's share link.

Tests
-----
12-01  User B can see the file while it is in the team folder
12-02  User B creates a share link for the team file
12-03  Share resolves while User B has team access
12-04  User A moves the file out of the team folder (to personal root)
12-05  User B's share no longer resolves (returns 404)
12-06  User A can still access the file directly (owner check)
12-07  User A's own share link for a personal file persists through moves
12-08  File moved back into the team folder → User B's share resolves again
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient
from tests.e2e.helpers.auth   import register_via_invite
from tests.e2e.helpers.files  import (
    create_folder, can_get_file_meta, move_file_to_root,
    upload_file_api, batch_move_files,
)
from tests.e2e.helpers.shares import (
    create_link_share, resolve_share_public,
)
from tests.e2e.helpers.teams  import (
    create_team, add_member, add_team_folder,
)

# Module-level world state
_owner:       dict = {}   # User A — file owner, team creator
_member:      dict = {}   # User B — team member, non-owner share creator
_team:        dict = {}
_team_folder: dict = {}
_file:        dict = {}   # the "passwords.txt" file
_member_share: dict = {}  # share created by User B while they had team access
_owner_share:  dict = {}  # share created by User A (owner) — should always resolve


@pytest.fixture(scope="module", autouse=True)
async def build_world(browser: Browser, admin_client: AdminClient):
    """
    Register two users, create a team, add both to it, upload a file to the
    team folder, and record initial share state.
    """
    global _owner, _member, _team, _team_folder, _file

    # Register owner (User A)
    url = await admin_client.create_invite_url()
    owner_sess = await register_via_invite(browser, url, "file_owner_12", "0wner!Pwd12")
    users = await admin_client.list_users()
    owner = next(u for u in users if u["username"].lower() == "file_owner_12")
    _owner = {"id": owner["id"], "session": owner_sess, "username": "file_owner_12"}

    # Register member (User B)
    url2 = await admin_client.create_invite_url()
    mem_sess = await register_via_invite(browser, url2, "team_member_12", "Memb3r!Pwd12")
    users2 = await admin_client.list_users()
    mem = next(u for u in users2 if u["username"].lower() == "team_member_12")
    _member = {"id": mem["id"], "session": mem_sess, "username": "team_member_12"}

    # Create team (owner creates it — owner has all team flags including move_own_out)
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        _team = await create_team(owner_api, "Security Test Team 12")

    # Add User B to the team
    async with ApiClient.from_session(_owner["session"]) as api:
        await add_member(api, _team["id"], _member["username"])

    # Create a folder, register it as a team folder
    async with ApiClient.from_session(_owner["session"]) as api:
        _team_folder = await create_folder(api, "Team Folder 12")
        await add_team_folder(api, _team["id"], _team_folder["id"])

    # Upload the "sensitive" file to the team folder (owner is User A)
    async with ApiClient.from_session(_owner["session"]) as api:
        _file = await upload_file_api(
            api, "passwords.txt", b"hunter2", folder_id=_team_folder["id"]
        )

    yield

    await owner_sess.ctx.close()
    await mem_sess.ctx.close()


# ---------------------------------------------------------------------------
# Baseline: User B has access while file is in the team folder
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_12_01_member_can_see_file_in_team_folder():
    """User B (non-owner team member) can read file metadata while it's in the team folder."""
    if not _file:
        pytest.skip("File not uploaded (setup failed)")
    async with ApiClient.from_session(_member["session"]) as api:
        can_read = await can_get_file_meta(api, _file["id"])
    assert can_read, "Team member should be able to see a file in their team folder"


@pytest.mark.asyncio(loop_scope="session")
async def test_12_02_member_creates_share_link_for_team_file():
    """User B creates a share link for User A's file using their team-based access."""
    global _member_share
    if not _file:
        pytest.skip("No file available")
    async with ApiClient.from_session(_member["session"]) as api:
        _member_share = await create_link_share(api, [_file["id"]])
    assert "token" in _member_share, "Share creation should succeed for team members"


@pytest.mark.asyncio(loop_scope="session")
async def test_12_03_member_share_resolves_while_in_team_folder():
    """While the file is still in the team folder, User B's share link resolves."""
    if not _member_share:
        pytest.skip("No member share available")
    resp = await resolve_share_public(_member_share["token"])
    assert resp.status_code == 200, (
        f"Share should resolve while creator has team access, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# User A also creates a share (owner) — used in 12-07 to verify owner shares persist
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_12_07_owner_share_created_before_move():
    """User A (file owner) creates a share link. This should persist after any move."""
    global _owner_share
    if not _file:
        pytest.skip("No file available")
    async with ApiClient.from_session(_owner["session"]) as api:
        _owner_share = await create_link_share(api, [_file["id"]])
    assert "token" in _owner_share


# ---------------------------------------------------------------------------
# The move: User A moves the file out of the team folder
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_12_04_owner_moves_file_out_of_team_folder():
    """User A moves passwords.txt to their personal root (no longer in team folder)."""
    if not _file:
        pytest.skip("No file available")
    async with ApiClient.from_session(_owner["session"]) as api:
        updated = await move_file_to_root(api, _file["id"])
    assert updated["folder_id"] is None, (
        f"File should be at root after move, folder_id={updated['folder_id']}"
    )


# ---------------------------------------------------------------------------
# After the move: User B's share should fail; User A keeps access
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_12_05_member_share_fails_after_file_moved():
    """
    User B's share link should return 404 now that the file is no longer in the
    team folder. User B is not the owner and no longer has team-based access to
    the file at its new (personal) location.
    """
    if not _member_share:
        pytest.skip("No member share available")
    resp = await resolve_share_public(_member_share["token"])
    assert resp.status_code == 404, (
        f"Share should be revoked once creator loses access to the file's new location; "
        f"got {resp.status_code}: {resp.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_12_06_owner_can_still_access_file_directly():
    """User A (file owner) retains direct GET /files/{id} access regardless of folder."""
    if not _file:
        pytest.skip("No file available")
    async with ApiClient.from_session(_owner["session"]) as api:
        can_read = await can_get_file_meta(api, _file["id"])
    assert can_read, "File owner should always be able to read their own file"


@pytest.mark.asyncio(loop_scope="session")
async def test_12_07_owner_share_persists_after_move():
    """User A's own share link (created while file was in team folder) still resolves.

    The owner retains access to their file at any location, so their share is valid.
    """
    if not _owner_share:
        pytest.skip("No owner share available")
    resp = await resolve_share_public(_owner_share["token"])
    assert resp.status_code == 200, (
        f"Owner's share should persist after moving their own file; "
        f"got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# Move back: restoring the file to the team folder should restore User B's share
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_12_08_member_share_restores_when_file_moved_back():
    """
    User A moves the file back into the team folder. User B's share should resolve
    again because the access re-check passes (User B is still a team member).
    """
    if not _file or not _member_share or not _team_folder:
        pytest.skip("Setup incomplete")

    # Move file back to team folder (single-file PUT)
    async with ApiClient.from_session(_owner["session"]) as api:
        r = await api.put(
            f"/files/{_file['id']}",
            json={"folder_id": _team_folder["id"]},
        )
        assert r.status_code == 200, (
            f"Moving file back to team folder failed: {r.status_code} {r.text}"
        )

    resp = await resolve_share_public(_member_share["token"])
    assert resp.status_code == 200, (
        f"Share should resolve again once file is back in team folder; "
        f"got {resp.status_code}: {resp.text}"
    )
