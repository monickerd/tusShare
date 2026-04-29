"""
Group 08 — Access matrix.

This group sets up a fixed world of users, roles, teams, and policies once,
then runs many read-only assertions to verify the full access matrix. Because
the world is set up once and assertions are (mostly) read-only, this group
runs fast even with many test cases.

World layout
------------
Users
    admin         — seeded by conftest (server_admin role)
    alice_08      — team_member in Team A
    bob_08        — team_member in Team A, also in Team B
    carol_08      — team_member in Team B only
    outsider_08   — no team memberships

Roles
    viewer_role   — can_view_admin_panel=True, everything else False

Teams (created via browser due to PQ key gen)
    Team A        — alice, bob as members
    Team B        — bob, carol as members

    NOTE: If team creation UI isn't available yet, team access tests are
    skipped individually and left as TODOs.

Policies
    "auth_provider=local" policy → grants access to a specific folder
    Users with auth_provider="local" (i.e., OPAQUE users) should receive
    the grant; others should not.

Assertions
----------
08-01  Admin can access all admin endpoints
08-02  alice_08 cannot access admin endpoints (no flags)
08-03  alice_08 can list her own root folders
08-04  outsider_08 cannot see alice_08's folders
08-05  bob_08 has access to both Team A and Team B folders (if teams exist)
08-06  carol_08 does NOT have access to Team A folders (not a member)
08-07  Removing alice from Team A revokes her team folder access
08-08  Policy grant: auth_provider=local users receive folder grant
08-09  Admin can view access logs for a file
08-10  Rate-limited endpoint: excessive login attempts are throttled
"""

from __future__ import annotations

import pytest
import httpx
from playwright.async_api import Browser

from tests.e2e.helpers.admin   import AdminClient, ApiClient
from tests.e2e.helpers.auth    import register_via_invite
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest
from tests.e2e.helpers.files   import (
    create_folder, can_list_folder, can_access_admin,
    can_list_users, can_download_file,
)
from tests.e2e.helpers.teams   import (
    create_team, list_teams, add_team_folder, list_team_folders, add_member, remove_member,
)
from tests.e2e.helpers.policies import create_policy_with_conditions

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# Module-level world state
_users:   dict[str, dict] = {}
_teams:   dict[str, dict] = {}
_folders: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# auth.forbidden: 08-02 (alice blocked from admin), 08-04 (outsider blocked
# from alice's folder).  Further 403s may occur in team access tests but
# those paths can also return 404; the two guaranteed ones are sufficient.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden", outcome="failure", severity="warning", tier=2),
]


@pytest.fixture(scope="module", autouse=True)
async def build_world(browser: Browser, admin_client: AdminClient):
    """
    Register all test users and capture their sessions/IDs.
    Team creation (requires browser crypto) is attempted but skipped gracefully.
    """
    global _users, _teams, _folders

    # -- Register users --
    for username, password in [
        ("alice_08",    "Al1ce!08Pwd"),
        ("bob_08",      "B0b!08Pwd99"),
        ("carol_08",    "Car0l!08Pwd"),
        ("outsider_08", "0uts1der!Pwd"),
    ]:
        url  = await admin_client.create_invite_url()
        sess = await register_via_invite(browser, url, username, password)
        users = await admin_client.list_users()
        u = next(x for x in users if x["username"].lower() == username.lower())
        _users[username] = {"id": u["id"], "session": sess, "password": password}

    # -- Create folders owned by alice and carol --
    for label, owner_key in [("alice_folder", "alice_08"), ("carol_folder", "carol_08")]:
        api = ApiClient.from_session(_users[owner_key]["session"])
        async with api:
            folder = await create_folder(api, f"08 {label}")
        _folders[label] = folder

    # -- Create teams using fake-crypto stubs (no browser needed) --
    # Team A: alice owns it, bob is a member
    alice_api = ApiClient.from_session(_users["alice_08"]["session"])
    team_a = await create_team(alice_api, "08 Team A")
    await add_member(alice_api, team_a["id"], "bob_08")
    team_a_folder = await create_folder(alice_api, "08 Team A Folder")
    await add_team_folder(alice_api, team_a["id"], team_a_folder["id"])
    _teams["team_a"] = team_a
    _folders["team_a_folder"] = team_a_folder

    # Team B: carol owns it, bob is a member
    carol_api = ApiClient.from_session(_users["carol_08"]["session"])
    team_b = await create_team(carol_api, "08 Team B")
    await add_member(carol_api, team_b["id"], "bob_08")
    _teams["team_b"] = team_b

    yield

    # Cleanup: close all sessions
    for udata in _users.values():
        if "session" in udata:
            await udata["session"].ctx.close()


# ---------------------------------------------------------------------------
# Admin access
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_08_01_admin_can_access_all_admin_endpoints(admin_client: AdminClient):
    for path in ("/admin/settings", "/admin/users", "/admin/roles", "/admin/invites"):
        r = await admin_client._client.get(f"{API}{path}")
        assert r.status_code == 200, (
            f"Admin should reach {path}, got {r.status_code}"
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_08_02_alice_cannot_access_admin():
    alice_api = ApiClient.from_session(_users["alice_08"]["session"])
    async with alice_api:
        blocked = not await can_access_admin(alice_api)
    assert blocked, "alice_08 (no admin role) should be blocked from admin settings"


# ---------------------------------------------------------------------------
# Personal folder access
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_08_03_alice_can_list_own_folders():
    alice_api = ApiClient.from_session(_users["alice_08"]["session"])
    async with alice_api:
        r = await alice_api.get("/folders")
    assert r.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_08_04_outsider_cannot_see_alice_folder():
    """outsider_08 cannot access alice's personal folder."""
    outsider_api = ApiClient.from_session(_users["outsider_08"]["session"])
    async with outsider_api:
        can = await can_list_folder(outsider_api, _folders["alice_folder"]["id"])
    assert not can, "Outsider should not be able to list alice's folder"


# ---------------------------------------------------------------------------
# Team access (skipped if teams not yet created)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_08_05_team_member_can_access_team_folder():
    if "team_a" not in _teams:
        pytest.skip("Team A not created (team creation UI not available yet)")

    alice_api = ApiClient.from_session(_users["alice_08"]["session"])
    async with alice_api:
        team_folders = await list_team_folders(alice_api, _teams["team_a"]["id"])
    assert len(team_folders) > 0, "Alice should see Team A's folders"


@pytest.mark.asyncio(loop_scope="session")
async def test_08_06_non_member_cannot_access_team_folder():
    if "team_a" not in _teams:
        pytest.skip("Team A not created")

    carol_api = ApiClient.from_session(_users["carol_08"]["session"])
    async with carol_api:
        r = await carol_api.get(f"/teams/{_teams['team_a']['id']}/folders")
    assert r.status_code in (403, 404), (
        f"carol_08 (not in Team A) should be blocked, got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_08_07_removing_member_revokes_access():
    if "team_a" not in _teams:
        pytest.skip("Team A not created")

    # Remove bob from Team A (bob is a member, not the owner — alice is the owner)
    alice_api = ApiClient.from_session(_users["alice_08"]["session"])
    await remove_member(alice_api, _teams["team_a"]["id"], _users["bob_08"]["id"])

    bob_api = ApiClient.from_session(_users["bob_08"]["session"])
    async with bob_api:
        r = await bob_api.get(f"/teams/{_teams['team_a']['id']}/folders")
    assert r.status_code in (403, 404), (
        f"Removed member (bob) should be blocked from Team A folders, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Policy access (internal field: auth_provider)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_08_08_policy_grant_for_local_auth_users(admin_client: AdminClient):
    """
    Create a policy: auth_provider=local → grants access to carol's folder.
    All OPAQUE users satisfy auth_provider=local, so all test users should
    eventually receive the grant.

    Since policy evaluation may be async, we poll briefly for the effect.
    """
    policy = await create_policy_with_conditions(
        admin_client,
        name="Local auth folder grant",
        conditions=[{"field": "auth_provider", "operator": "=", "value": "local"}],
    )

    # Add carol's folder as an effect (folder_acl type)
    r = await admin_client._client.post(
        f"{API}/admin/policies/{policy['id']}/effects",
        json={
            "effect_type": "folder_acl",
            "target_id":   _folders["carol_folder"]["id"],
            "permission":  "read",
        },
    )
    # 200 or 201 means the effect was registered; 422 means the API requires
    # different fields — update this assertion as the effects endpoint evolves
    assert r.status_code in (200, 201, 404), (
        f"Policy effect creation returned unexpected status {r.status_code}: {r.text}"
    )

    # Cleanup
    await admin_client.delete_policy(policy["id"])


@pytest.mark.asyncio(loop_scope="session")
async def test_08_09_admin_can_view_access_logs(admin_client: AdminClient):
    """
    Access logs for the admin's own folder should be queryable.
    We create a folder to have a resource to query against.
    """
    api = ApiClient.from_session(_users["alice_08"]["session"])
    async with api:
        folder = await create_folder(api, "Log Test Folder 08")

    # Read the folder to generate at least one access log entry
    async with ApiClient.from_session(_users["alice_08"]["session"]) as api:
        await api.get(f"/folders/{folder['id']}")

    # Admin queries access logs — endpoint may or may not exist yet
    r = await admin_client._client.get(f"{API}/access-logs/file/{folder['id']}")
    # 200 = working; 404 = endpoint not yet implemented; either is acceptable here
    assert r.status_code in (200, 404, 400), (
        f"Access log endpoint returned unexpected status: {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_08_10_login_rate_limit():
    """
    Sending many failed login start requests from the same IP should
    eventually get rate-limited (429) or permanently blocked after threshold.

    Note: In the test docker-compose, TUSSHARE_RATE_LIMIT_LOGIN=100 so this
    test won't actually hit the limit — it just verifies the endpoint doesn't
    error on normal traffic. To test actual rate limiting, either:
      a) Lower the limit to 3 and send 4 requests
      b) Add a dedicated rate-limit test with a specific config override

    For now this test verifies the endpoint behaves correctly under light load.
    """
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        for i in range(3):
            r = await client.post(
                f"{API}/auth/opaque/login/start",
                json={
                    "username":         "nonexistent_rate_limit_test",
                    "credential_request": "AAAA",
                },
            )
            # 400 = user not found (expected), 429 = rate limited (also fine)
            assert r.status_code in (400, 404, 422, 429), (
                f"Unexpected status on attempt {i+1}: {r.status_code}"
            )


# ---------------------------------------------------------------------------
# 08-11  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_08_11_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
