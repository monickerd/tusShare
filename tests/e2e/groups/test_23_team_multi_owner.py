"""
Group 23 — Multi-owner teams and the allow_multi_team_owner admin flag.

Tests the Tier 6 additions:
  - allow_multi_team_owner admin_settings flag (default: false)
  - GET /teams/{team_id} includes the flag in the response
  - PUT /teams/{team_id}/members/{user_id} enforces the flag when promoting to owner
  - Role ID correctness: backend stores team_admin / team_manager (not team_owner / team_supervisor)
  - Self-role-change guard (422)
  - After promotion: original owner can be demoted by the new owner when 2 owners exist

Tests
-----
23-01  allow_multi_team_owner defaults to false
23-02  Create team as regular user
23-03  Add a supervisor to the team (role: team_manager)
23-04  Promote supervisor to team_admin is blocked (403) when flag is disabled
23-05  GET /teams/{team_id} includes allow_multi_team_owner=false while disabled
23-06  Admin enables the flag
23-07  GET /teams/{team_id} now shows allow_multi_team_owner=true
23-08  Promote supervisor to team_admin succeeds when flag is enabled
23-09  Member list shows two team_admin entries after promotion
23-10  Owner cannot change their own role (422 — self-change guard)
23-11  New owner can demote original owner when two owners exist
23-12  Demoted original owner (now team_manager) cannot change member roles (403)
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth  import register_via_invite
from tests.e2e.helpers.teams import create_team, list_members, add_member

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# Module-level state
_team:       dict = {}
_owner:      dict = {}
_supervisor: dict = {}


@pytest.fixture(scope="module", autouse=True)
async def setup_users(browser: Browser, admin_client: AdminClient):
    global _owner, _supervisor

    # Ensure the flag starts disabled so tests run in a known state
    await admin_client.set_setting("allow_multi_team_owner", "false")

    # Register owner
    url = await admin_client.create_invite_url()
    owner_sess = await register_via_invite(browser, url, "mowner_23", "0wner!Pwd99")
    users = await admin_client.list_users()
    owner_rec = next(u for u in users if u["username"].lower() == "mowner_23")
    _owner = {
        "id":       owner_rec["id"],
        "session":  owner_sess,
        "username": "mowner_23",
        "password": "0wner!Pwd99",
    }

    # Register supervisor
    url2 = await admin_client.create_invite_url()
    sup_sess = await register_via_invite(browser, url2, "msuper_23", "Sup3r!Pwd99")
    users2 = await admin_client.list_users()
    sup_rec = next(u for u in users2 if u["username"].lower() == "msuper_23")
    _supervisor = {
        "id":       sup_rec["id"],
        "session":  sup_sess,
        "username": "msuper_23",
        "password": "Sup3r!Pwd99",
    }

    yield

    await owner_sess.ctx.close()
    await sup_sess.ctx.close()
    # Restore flag to default for subsequent test groups
    await admin_client.set_setting("allow_multi_team_owner", "false")


# ---------------------------------------------------------------------------
# Default state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_23_01_allow_multi_team_owner_defaults_false(admin_client: AdminClient):
    settings = await admin_client.get_settings()
    assert settings.get("allow_multi_team_owner") == "false", (
        f"Expected 'false', got: {settings.get('allow_multi_team_owner')!r}"
    )


# ---------------------------------------------------------------------------
# Setup team
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_23_02_create_team_as_owner():
    global _team
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        _team = await create_team(owner_api, "Multi-Owner Test 23", "For multi-owner tests")
    assert _team.get("id"), f"Team creation failed: {_team}"


@pytest.mark.asyncio(loop_scope="session")
async def test_23_03_add_supervisor_to_team():
    if not _team:
        pytest.skip("Team not created")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        result = await add_member(owner_api, _team["id"], _supervisor["username"], "team_manager")
    assert result is not None
    # Confirm member appears with the correct role
    owner_api2 = ApiClient.from_session(_owner["session"])
    async with owner_api2:
        members = await list_members(owner_api2, _team["id"])
    sup_entry = next((m for m in members if m["user_id"] == _supervisor["id"]), None)
    assert sup_entry is not None, "Supervisor not found in member list"
    assert sup_entry["role"] == "team_manager", (
        f"Expected team_manager, got: {sup_entry['role']!r}"
    )


# ---------------------------------------------------------------------------
# Flag-disabled enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_23_04_promote_to_owner_blocked_while_flag_disabled():
    if not _team or not _supervisor:
        pytest.skip("Team or supervisor not set up")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        r = await owner_api.put(
            f"/teams/{_team['id']}/members/{_supervisor['id']}",
            json={"role": "team_admin"},
        )
    assert r.status_code == 403, (
        f"Expected 403 (flag disabled), got {r.status_code}: {r.text}"
    )
    assert "not enabled" in r.json().get("detail", "").lower()


@pytest.mark.asyncio(loop_scope="session")
async def test_23_05_team_detail_shows_flag_false():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        r = await owner_api.get(f"/teams/{_team['id']}")
        r.raise_for_status()
    data = r.json()
    assert "allow_multi_team_owner" in data, (
        f"allow_multi_team_owner missing from team detail response: {list(data.keys())}"
    )
    assert data["allow_multi_team_owner"] is False


# ---------------------------------------------------------------------------
# Enable flag
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_23_06_admin_enables_multi_owner_flag(admin_client: AdminClient):
    await admin_client.set_setting("allow_multi_team_owner", "true")
    settings = await admin_client.get_settings()
    assert settings.get("allow_multi_team_owner") == "true"


@pytest.mark.asyncio(loop_scope="session")
async def test_23_07_team_detail_shows_flag_true():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        r = await owner_api.get(f"/teams/{_team['id']}")
        r.raise_for_status()
    data = r.json()
    assert data["allow_multi_team_owner"] is True, (
        "allow_multi_team_owner should be True after enabling the flag"
    )


# ---------------------------------------------------------------------------
# Promotion succeeds
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_23_08_promote_supervisor_to_owner_succeeds():
    if not _team or not _supervisor:
        pytest.skip("Team or supervisor not set up")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        r = await owner_api.put(
            f"/teams/{_team['id']}/members/{_supervisor['id']}",
            json={"role": "team_admin"},
        )
    assert r.status_code == 200, (
        f"Expected 200 (flag enabled), got {r.status_code}: {r.text}"
    )
    assert r.json().get("ok") is True


@pytest.mark.asyncio(loop_scope="session")
async def test_23_09_team_has_two_owners_after_promotion():
    if not _team:
        pytest.skip("No team available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        members = await list_members(owner_api, _team["id"])
    owners = [m for m in members if m["role"] == "team_admin"]
    assert len(owners) == 2, (
        f"Expected 2 team_admin entries, got {len(owners)}: {owners}"
    )


# ---------------------------------------------------------------------------
# Self-change guard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_23_10_owner_cannot_change_own_role():
    """PUT to change one's own role returns 422 regardless of target role."""
    if not _team or not _owner:
        pytest.skip("No team or owner available")
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        r = await owner_api.put(
            f"/teams/{_team['id']}/members/{_owner['id']}",
            json={"role": "team_manager"},
        )
    assert r.status_code == 422, (
        f"Expected 422 (self-change guard), got {r.status_code}: {r.text}"
    )
    assert "own role" in r.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Demotion with two owners present
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_23_11_new_owner_can_demote_original_owner():
    """
    With two owners (A=original, B=supervisor-promoted), B can demote A.
    The last-owner guard does not fire because owner_count is 2 before the
    demotion, leaving exactly one owner (B) after.
    """
    if not _team or not _supervisor or not _owner:
        pytest.skip("Team not fully set up")
    # B (supervisor, now team_admin) demotes A (original owner)
    supervisor_api = ApiClient.from_session(_supervisor["session"])
    async with supervisor_api:
        r = await supervisor_api.put(
            f"/teams/{_team['id']}/members/{_owner['id']}",
            json={"role": "team_manager"},
        )
    assert r.status_code == 200, (
        f"Expected 200 (2 owners → 1 owner), got {r.status_code}: {r.text}"
    )
    # Confirm role changed
    supervisor_api2 = ApiClient.from_session(_supervisor["session"])
    async with supervisor_api2:
        members = await list_members(supervisor_api2, _team["id"])
    owner_entry = next((m for m in members if m["user_id"] == _owner["id"]), None)
    assert owner_entry is not None, "Original owner not found in member list"
    assert owner_entry["role"] == "team_manager", (
        f"Expected team_manager after demotion, got: {owner_entry['role']!r}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_23_12_demoted_owner_loses_role_change_privilege():
    """
    After demotion, the original owner (now team_manager) cannot change
    another member's role — the endpoint requires team_admin (owner) level.
    """
    if not _team or not _owner or not _supervisor:
        pytest.skip("Team not fully set up")
    # Original owner (now team_manager) tries to change the supervisor's role
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        r = await owner_api.put(
            f"/teams/{_team['id']}/members/{_supervisor['id']}",
            json={"role": "team_member"},
        )
    assert r.status_code == 403, (
        f"Expected 403 (insufficient role after demotion), got {r.status_code}: {r.text}"
    )
