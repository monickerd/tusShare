"""
Group 31 — Permissions v2 (Phase 1 overhaul).

Validates the new check_data_permission evaluator, explicit deny ACL entries,
team_folder_role_levels overrides, GET /admin/roles/capabilities, scoped role
grants, and lock-at-tier admin settings enforcement.

Sections
--------
A. Explicit deny ACL — stops the walk even for team members
B. New permission levels — download-only grant does not imply write
C. Inheritance walk — recursive grant on parent reaches child folder
D. team_folder_role_levels override — team admin configures per-role levels
E. GET /admin/roles/capabilities — response structure and cap enforcement
F. Scoped role grant — team-scoped admin flag via /admin/users/{id}/roles
G. Lock-at-tier — lower-tier admin cannot change a locked setting

World
-----
Users:
  _owner    — creates team and folders; has server_admin for setup
  _member   — team_member in _owner's team; no admin flags
  _outsider — no team membership; has a recursive permission on one folder

Teams:
  _team — owned by _owner; _member is team_member

Folders:
  _team_folder          — registered as team folder
  _team_deny_folder     — inside team_folder; _member has explicit deny ACL
  _perm_parent_folder   — _outsider has recursive read permission (DB-seeded)
  _perm_child_folder    — child of _perm_parent_folder (tests inheritance)
  _dl_folder            — _outsider has download-only ACL (tests level isolation)
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.db import PG_DB_NAME, _psql
from tests.e2e.helpers.files import create_folder, tus_create_request, upload_file_api
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest
from tests.e2e.helpers.teams import add_member, add_team_folder, create_team

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_owner:    dict = {}
_member:   dict = {}
_outsider: dict = {}

_team_id:            str = ""
_team_folder_id:     str = ""
_team_deny_id:       str = ""
_perm_parent_id:     str = ""
_perm_child_id:      str = ""
_dl_folder_id:       str = ""
_dl_file_id:         str = ""

# ---------------------------------------------------------------------------
# SIEM manifest
# auth.forbidden fires on: 31-01 (deny blocks member), 31-06 (dl-only blocks write),
# 31-11 (member=read cannot write after override), 31-18 (lock-at-tier rejected).
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden",     outcome="failure", severity="warning", tier=2),
    ExpectedSiemEvent("admin.role.granted", outcome="success", severity="warning", tier=2),
    ExpectedSiemEvent("admin.role.revoked", outcome="success", severity="warning", tier=2),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _reg(
    browser: Browser, admin_client: AdminClient, username: str, password: str
) -> dict:
    url     = await admin_client.create_invite_url()
    session = await register_via_invite(browser, url, username, password)
    users   = await admin_client.list_users()
    user    = next(u for u in users if u["username"].lower() == username.lower())
    return {
        "id":       user["id"],
        "username": username,
        "password": password,
        "session":  session,
        "api":      ApiClient.from_session(session),
    }


def _seed_permission(
    resource_type: str,
    resource_id:   str,
    user_id:       str,
    permission:    str = "read",
    recursive:     bool = True,
) -> None:
    """Insert a permissions row directly, bypassing the API."""
    _psql(
        f"INSERT INTO permissions "
        f"(id, resource_type, resource_id, user_id, permission, recursive, granted_by) "
        f"VALUES (gen_random_uuid()::text, '{resource_type}', '{resource_id}', "
        f"'{user_id}', '{permission}', {'1' if recursive else '0'}, NULL) "
        f"ON CONFLICT DO NOTHING;",
        db=PG_DB_NAME,
    )


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _owner, _member, _outsider
    global _team_id, _team_folder_id, _team_deny_id
    global _perm_parent_id, _perm_child_id, _dl_folder_id, _dl_file_id

    _owner    = await _reg(browser, admin_client, "owner_31",    "0wner!31Pass")
    _member   = await _reg(browser, admin_client, "member_31",   "Member!31Pass")
    _outsider = await _reg(browser, admin_client, "outsider_31", "0uts!31Pass99")

    admin_api = ApiClient(admin_client._cookies)

    try:
        # Team + team folder
        team = await create_team(_owner["api"], "team_31")
        _team_id = team["id"]
        await add_member(_owner["api"], _team_id, _member["username"])

        tf = await create_folder(_owner["api"], "team_folder_31")
        _team_folder_id = tf["id"]
        await add_team_folder(_owner["api"], _team_id, _team_folder_id)

        # Sub-folder where _member gets an explicit deny
        deny_f = await create_folder(_owner["api"], "deny_sub_31", parent_id=_team_folder_id)
        _team_deny_id = deny_f["id"]
        _seed_permission("folder", _team_deny_id, _member["id"], "deny", recursive=False)

        # Explicit-permission tree for inheritance walk tests (sections B & C)
        pp = await create_folder(admin_api, "perm_parent_31")
        _perm_parent_id = pp["id"]
        pc = await create_folder(admin_api, "perm_child_31", parent_id=_perm_parent_id)
        _perm_child_id = pc["id"]
        _seed_permission("folder", _perm_parent_id, _outsider["id"], "read", recursive=True)

        # Download-only folder (tests level isolation)
        dl_f = await create_folder(admin_api, "dl_folder_31")
        _dl_folder_id = dl_f["id"]
        _seed_permission("folder", _dl_folder_id, _outsider["id"], "download", recursive=False)
        dl_file = await upload_file_api(admin_api, "dl_31.bin", b"data", folder_id=_dl_folder_id)
        _dl_file_id = dl_file["id"]

        yield

    finally:
        for u in (_owner, _member, _outsider):
            try:
                await u["api"].aclose()
                await u["session"].ctx.close()
            except Exception:
                pass
        try:
            await admin_api.aclose()
        except Exception:
            pass


# ===========================================================================
# A. Explicit deny ACL
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_31_01_explicit_deny_blocks_team_member():
    """_member is a team member of team_folder but has an explicit deny on deny_sub.
    check_data_permission must return DENY before reaching the team-based grant.
    """
    r = await _member["api"].get(f"/folders/{_team_deny_id}")
    assert r.status_code == 403, (
        f"Explicit deny must block team member; got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_31_02_team_member_can_access_team_folder_without_deny():
    """_member has no deny on team_folder itself — team membership grants access."""
    r = await _member["api"].get(f"/folders/{_team_folder_id}")
    assert r.status_code == 200, (
        f"Team member should access team folder; got {r.status_code}: {r.text}"
    )


# ===========================================================================
# B. New permission level — download-only isolation
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_31_03_download_only_grant_allows_file_read():
    """A 'download' ACL on the folder grants read + download on files inside it."""
    r = await _outsider["api"].get(f"/files/{_dl_file_id}")
    assert r.status_code == 200, (
        f"download grant should allow file metadata read; got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_31_04_download_only_grant_does_not_imply_write():
    """A 'download' ACL does not imply write — upload into dl_folder must be blocked."""
    r = await tus_create_request(_outsider["api"], _dl_folder_id, filename="injected.bin")
    assert r.status_code == 403, (
        f"download-only grant must not allow upload; got {r.status_code}"
    )


# ===========================================================================
# C. Inheritance walk — recursive grant reaches child folder
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_31_05_recursive_read_grant_reaches_child_folder():
    """_outsider has a recursive read grant on perm_parent_31.
    The ancestor walk in check_data_permission must grant read on perm_child_31.
    """
    r = await _outsider["api"].get(f"/folders/{_perm_child_id}")
    assert r.status_code == 200, (
        f"Recursive grant on parent should reach child folder; got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_31_06_recursive_read_grant_does_not_imply_write_on_child():
    """Inherited read does not imply write — upload must be blocked on perm_child."""
    r = await tus_create_request(_outsider["api"], _perm_child_id, filename="intruder.bin")
    assert r.status_code == 403, (
        f"Inherited read must not allow write on child; got {r.status_code}"
    )


# ===========================================================================
# D. team_folder_role_levels override
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_31_07_get_folder_role_levels_returns_defaults(admin_client: AdminClient):
    """GET /admin/teams/{id}/folder-role-levels returns the current levels.
    Before any override the defaults should be returned.
    """
    r = await admin_client._client.get(f"{API}/admin/teams/{_team_id}/folder-role-levels")
    assert r.status_code == 200, f"GET folder-role-levels failed: {r.status_code} {r.text}"
    levels = r.json().get("levels", {})
    # Default: team_member → write
    assert levels.get("team_member") == "write", (
        f"Default team_member level should be 'write'; got {levels}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_31_08_put_folder_role_levels_sets_member_to_read(admin_client: AdminClient):
    """PUT /admin/teams/{id}/folder-role-levels — set team_member level to read."""
    r = await admin_client._client.put(
        f"{API}/admin/teams/{_team_id}/folder-role-levels",
        json={"levels": {"team_member": "read"}},
    )
    assert r.status_code == 200, f"PUT folder-role-levels failed: {r.status_code} {r.text}"
    r2 = await admin_client._client.get(f"{API}/admin/teams/{_team_id}/folder-role-levels")
    assert r2.json()["levels"]["team_member"] == "read"


@pytest.mark.asyncio(loop_scope="session")
async def test_31_09_member_still_reads_team_folder_after_level_read():
    """After override to read, _member can still GET the team folder (read is allowed)."""
    r = await _member["api"].get(f"/folders/{_team_folder_id}")
    assert r.status_code == 200, (
        f"read-level member should still access team folder; got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_31_10_member_cannot_upload_after_level_downgraded_to_read():
    """After override to read, _member cannot upload into the team folder (write blocked)."""
    r = await tus_create_request(_member["api"], _team_folder_id, filename="blocked.bin")
    assert r.status_code == 403, (
        f"read-level member must not upload; got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_31_11_restore_member_level_to_write(admin_client: AdminClient):
    """Restore team_member to write so subsequent tests are unaffected."""
    r = await admin_client._client.put(
        f"{API}/admin/teams/{_team_id}/folder-role-levels",
        json={"levels": {"team_member": "write"}},
    )
    assert r.status_code == 200, f"Restore folder-role-levels failed: {r.status_code}"
    r2 = await admin_client._client.get(f"{API}/admin/teams/{_team_id}/folder-role-levels")
    assert r2.json()["levels"]["team_member"] == "write"


# ===========================================================================
# E. GET /admin/roles/capabilities
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_31_12_capabilities_response_structure(admin_client: AdminClient):
    """GET /admin/roles/capabilities returns required top-level keys."""
    r = await admin_client._client.get(f"{API}/admin/roles/capabilities")
    assert r.status_code == 200, f"capabilities failed: {r.status_code} {r.text}"
    body = r.json()
    for key in ("admin_tier", "grantable_flags", "grantable_role_ids", "scope"):
        assert key in body, f"Missing key '{key}' in capabilities response: {body}"


@pytest.mark.asyncio(loop_scope="session")
async def test_31_13_server_admin_can_grant_all_flags(admin_client: AdminClient):
    """Server admin's grantable_flags includes all defined permission flags."""
    r = await admin_client._client.get(f"{API}/admin/roles/capabilities")
    r.raise_for_status()
    body = r.json()
    flags = set(body["grantable_flags"])
    # A server admin should be able to grant at least these core flags
    for flag in ("users_manage", "roles_manage", "admin_panel_view"):
        assert flag in flags, f"Server admin should be able to grant '{flag}'"


@pytest.mark.asyncio(loop_scope="session")
async def test_31_14_capabilities_scope_is_org_wide_for_server_admin(admin_client: AdminClient):
    """Server admin's scope.org_wide must be True."""
    r = await admin_client._client.get(f"{API}/admin/roles/capabilities")
    r.raise_for_status()
    scope = r.json()["scope"]
    assert scope.get("org_wide") is True, (
        f"Server admin scope.org_wide should be True; got {scope}"
    )


# ===========================================================================
# F. Scoped role grant
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_31_15_scoped_role_grant_via_api(admin_client: AdminClient):
    """POST /admin/users/{id}/roles/{role_id} with scope body creates a team-scoped grant."""
    r = await admin_client._client.post(
        f"{API}/admin/users/{_member['id']}/roles/team_admin",
        json={"scope_type": "team", "scope_id": _team_id},
    )
    # 200 or 201 = created; 409 = already exists (idempotent, acceptable)
    assert r.status_code in (200, 201, 409), (
        f"Scoped role grant returned unexpected status: {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_31_16_revoke_scoped_role(admin_client: AdminClient):
    """DELETE /admin/users/{id}/roles/{role_id} with scope query params removes scoped grant."""
    r = await admin_client._client.delete(
        f"{API}/admin/users/{_member['id']}/roles/team_admin",
        params={"scope_type": "team", "scope_id": _team_id},
    )
    # 200 = removed; 404 = already gone (idempotent)
    assert r.status_code in (200, 404), (
        f"Scoped role revoke returned unexpected status: {r.status_code}: {r.text}"
    )


# ===========================================================================
# G. Lock-at-tier admin settings enforcement
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_31_17_server_admin_can_lock_a_setting(admin_client: AdminClient):
    """PUT /admin/settings/locks lets server admin lock a setting."""
    r = await admin_client._client.put(
        f"{API}/admin/settings/locks",
        json={"locks": {"audit_retention_days": {"is_locked": True, "locked_min_tier": 1}}},
    )
    assert r.status_code == 200, f"Lock setting failed: {r.status_code} {r.text}"


@pytest.mark.asyncio(loop_scope="session")
async def test_31_18_lower_admin_cannot_change_locked_setting(
    browser: Browser, admin_client: AdminClient
):
    """An operational_admin (lower tier) cannot modify a setting locked to server_admin tier."""
    # Register a lower-tier admin
    url  = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, url, "op_admin_31", "0pAdmin!Pass31")
    users = await admin_client.list_users()
    op_user = next(u for u in users if u["username"].lower() == "op_admin_31")

    await admin_client.grant_role(op_user["id"], "operational_admin")
    op_api = ApiClient.from_session(sess)
    try:
        r = await op_api.put(
            "/admin/settings",
            json={"settings": {"audit_retention_days": "999"}},
        )
        assert r.status_code == 403, (
            f"Locked setting must block lower-tier admin; got {r.status_code}: {r.text}"
        )
    finally:
        await op_api.aclose()
        await sess.ctx.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_31_19_server_admin_can_unlock_setting(admin_client: AdminClient):
    """Server admin can unlock a setting they previously locked."""
    r = await admin_client._client.put(
        f"{API}/admin/settings/locks",
        json={"locks": {"audit_retention_days": {"is_locked": False, "locked_min_tier": None}}},
    )
    assert r.status_code == 200, f"Unlock setting failed: {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# 31-20  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_31_20_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
