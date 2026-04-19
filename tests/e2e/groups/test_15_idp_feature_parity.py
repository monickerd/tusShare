"""
Group 15 — IdP feature parity and cross-authentication access.

Verifies that LDAP and OIDC users can perform the same core operations as
OPAQUE users, that private resources are isolated across all authentication
methods, and that mixed teams and admin roles work correctly for IdP users.

Infrastructure
--------------
  Requires LDAP reachable on localhost:389 (docker-compose.test.yml exposes
  the container port).  OIDC tests require Dex on localhost:5556.  The whole
  module is skipped if LDAP is unavailable.  Individual OIDC tests skip if
  Dex is unavailable.

Actors
------
  opaque_15    — registered via invite (normal OPAQUE / local auth)
  ldap_alice   — ldap_alice via LDAP provider 1  (dept=engineering)
  ldap_carol   — ldap_carol via LDAP provider 2  (same LDAP server, separate
                 provider record → distinct identity in tusShare)
  oidc_alice   — ldap_alice authenticated through OIDC (Dex + LDAP upstream)

Tests
-----
Feature parity (LDAP)
  15-01  LDAP user can list their root folders
  15-02  LDAP user can create a folder
  15-03  LDAP user can rename a folder
  15-04  LDAP user can upload a file (stub crypto)
  15-05  LDAP user can delete a file
  15-06  LDAP user can create a link share
  15-07  LDAP user can create a team and add an OPAQUE member

Feature parity (OIDC)
  15-08  OIDC user can list their root folders
  15-09  OIDC user can create a folder
  15-10  OIDC user can create a link share

Private folder isolation
  15-11  OPAQUE user cannot access LDAP user's private folder
  15-12  LDAP user cannot access OPAQUE user's private folder
  15-13  OIDC user cannot access LDAP user's private folder
  15-14  LDAP user cannot access OIDC user's private folder
  15-15  LDAP provider-1 user cannot access LDAP provider-2 user's private folder

Cross-authentication link sharing
  15-16  OPAQUE creates link share → LDAP user can resolve the token
  15-17  LDAP creates link share → OPAQUE user can resolve the token
  15-18  LDAP creates link share → OIDC user can resolve the token

Direct user-to-IdP share is rejected
  15-19  Direct user share to LDAP user fails (no PQ keys)

Mixed team
  15-20  OPAQUE user creates a team; LDAP + OIDC members added
  15-21  LDAP member can list the mixed team's folders
  15-22  OIDC member can list the mixed team's folders
  15-23  Non-member (ldap_carol, different provider) cannot access mixed team folders

Admin role for LDAP users
  15-24  LDAP user without admin role is blocked from admin endpoints
  15-25  Admin grants server_admin role to LDAP user → they can access admin endpoints
  15-26  Admin revokes role → LDAP user is blocked again
"""

from __future__ import annotations

import pytest
import httpx
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient
from tests.e2e.helpers.auth   import ldap_login, oidc_login, register_asymmetric_keys, register_via_invite
from tests.e2e.helpers.files  import (
    create_folder, upload_file_api, can_list_folder, rename_folder, delete_file,
)
from tests.e2e.helpers.shares import create_link_share, resolve_share_public
from tests.e2e.helpers.teams  import (
    create_team, add_member, list_team_folders, delete_team, add_team_folder,
)

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

_LDAP_CONFIG = {
    "server_uri":    "ldap://ldap:389",
    "bind_dn":       "cn=admin,dc=test,dc=local",
    "bind_password": "ldap_admin_secret",
    "base_dn":       "ou=users,dc=test,dc=local",
    "user_filter":   "(uid={username})",
    "tls":           "skip_verify",
    "username_attr": "uid",
}

_OIDC_CONFIG = {
    "issuer_url":    "http://dex:5556/dex",
    "client_id":     "tusshare-test",
    "client_secret": "tusshare-test-secret",
    "redirect_uri":  f"{APP_URL}/api/v1/auth/oidc/callback",
    "scopes":        ["openid", "email", "profile", "groups"],
    "username_attr": "email",
}

# ---------------------------------------------------------------------------
# Module-level world state (mutated by build_world, read by tests)
# ---------------------------------------------------------------------------

_providers: dict[str, str]       = {}   # "ldap_p1", "ldap_p2", "oidc" → provider_id
_apis:      dict[str, ApiClient] = {}   # "opaque", "ldap_alice", "ldap_carol", "oidc_alice"
_user_ids:  dict[str, str]       = {}   # → server user_id
_usernames: dict[str, str]       = {}   # → display username (used for team membership)
_folders:   dict[str, dict]      = {}   # private folder per actor
_files:     dict[str, dict]      = {}   # uploaded files for sharing tests
_mixed_team: dict                = {}   # team created in test 15-20
_contexts:  list                 = []   # BrowserContexts to close in teardown


# ---------------------------------------------------------------------------
# Reachability checks
# ---------------------------------------------------------------------------

def _ldap_ok() -> bool:
    import socket
    try:
        with socket.create_connection(("localhost", 389), timeout=3):
            return True
    except OSError:
        return False


def _oidc_ok() -> bool:
    import socket
    try:
        with socket.create_connection(("localhost", 5556), timeout=3):
            return True
    except OSError:
        return False


def _skip_if_no_oidc():
    if "oidc_alice" not in _apis:
        pytest.skip("OIDC not available (Dex unreachable or login failed)")


# ---------------------------------------------------------------------------
# Build / teardown world
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def build_world(browser: Browser, admin_client: AdminClient, seeded_env):
    global _providers, _apis, _user_ids, _usernames, _folders, _files, _contexts

    if not _ldap_ok():
        pytest.skip("LDAP not reachable on localhost:389 — skipping group 15")

    # -- LDAP providers -------------------------------------------------------
    p1 = await admin_client.create_idp_provider(
        provider_type="ldap", name="15 LDAP P1", config=_LDAP_CONFIG,
    )
    p2 = await admin_client.create_idp_provider(
        provider_type="ldap", name="15 LDAP P2", config=_LDAP_CONFIG,
    )
    _providers["ldap_p1"] = p1["id"]
    _providers["ldap_p2"] = p2["id"]

    # -- LDAP logins (API-based, no browser) ----------------------------------
    alice_cookies    = await ldap_login(p1["id"], "ldap_alice", "Alice!Ldap99")
    carol_p2_cookies = await ldap_login(p2["id"], "ldap_carol", "Carol!Ldap99")
    _apis["ldap_alice"] = ApiClient(alice_cookies)
    _apis["ldap_carol"] = ApiClient(carol_p2_cookies)

    # -- OIDC provider + login (optional) ------------------------------------
    if _oidc_ok():
        oidc_prov = await admin_client.create_idp_provider(
            provider_type="oidc", name="15 OIDC",
            config=_OIDC_CONFIG, claim_mode="at_login",
        )
        _providers["oidc"] = oidc_prov["id"]
        try:
            oidc_sess = await oidc_login(browser, oidc_prov["id"], "ldap_alice", "Alice!Ldap99")
            _contexts.append(oidc_sess.ctx)
            _apis["oidc_alice"] = ApiClient.from_session(oidc_sess)
        except Exception:
            pass  # OIDC login failed; OIDC tests will skip individually

    # -- Register stub asymmetric keys for IdP users --------------------------
    # LDAP/OIDC users are created without x25519/ML-KEM keys; the real client
    # would generate and upload them on first login.  We register stubs here so
    # these users can be added to teams (invite_member checks x25519_public_key).
    await register_asymmetric_keys(_apis["ldap_alice"])
    await register_asymmetric_keys(_apis["ldap_carol"])
    if "oidc_alice" in _apis:
        await register_asymmetric_keys(_apis["oidc_alice"])

    # -- OPAQUE user ----------------------------------------------------------
    invite_url  = await admin_client.create_invite_url()
    opaque_sess = await register_via_invite(browser, invite_url, "opaque_15", "0p4que!15Pwd")
    _contexts.append(opaque_sess.ctx)
    _apis["opaque"] = ApiClient.from_session(opaque_sess)

    # -- Resolve server-side user IDs and usernames ---------------------------
    users = await admin_client.list_users()

    for u in users:
        pid = u.get("identity_provider_id")
        am  = u.get("auth_method")
        if pid == _providers["ldap_p1"] and am == "ldap":
            _user_ids["ldap_alice"]  = u["id"]
            _usernames["ldap_alice"] = u["username"]
        elif pid == _providers["ldap_p2"] and am == "ldap":
            _user_ids["ldap_carol"]  = u["id"]
            _usernames["ldap_carol"] = u["username"]
        elif am == "oidc" and "oidc" in _providers and pid == _providers["oidc"]:
            _user_ids["oidc_alice"]  = u["id"]
            _usernames["oidc_alice"] = u["username"]
        elif u.get("username") == "opaque_15":
            _user_ids["opaque"]  = u["id"]
            _usernames["opaque"] = u["username"]

    # -- Private folders (isolation tests) ------------------------------------
    _folders["ldap_alice"] = await create_folder(_apis["ldap_alice"], "15 ldap_alice private")
    _folders["ldap_carol"] = await create_folder(_apis["ldap_carol"], "15 ldap_carol private")
    _folders["opaque"]     = await create_folder(_apis["opaque"],     "15 opaque private")
    if "oidc_alice" in _apis:
        _folders["oidc_alice"] = await create_folder(_apis["oidc_alice"], "15 oidc_alice private")

    # -- Files for sharing tests ----------------------------------------------
    _files["opaque"]     = await upload_file_api(_apis["opaque"],     "opaque_15.bin",     b"opaque content")
    _files["ldap_alice"] = await upload_file_api(_apis["ldap_alice"], "ldap_alice_15.bin", b"ldap content")

    yield

    # -- Teardown -------------------------------------------------------------
    if _mixed_team:
        try:
            await delete_team(_apis["opaque"], _mixed_team["id"])
        except Exception:
            pass

    for prov_id in _providers.values():
        try:
            await admin_client._client.delete(f"{API}/admin/identity-providers/{prov_id}")
        except Exception:
            pass

    for api in _apis.values():
        try:
            await api.aclose()
        except Exception:
            pass

    for ctx in _contexts:
        try:
            await ctx.close()
        except Exception:
            pass


# ===========================================================================
# Feature parity — LDAP
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_15_01_ldap_user_can_list_root():
    r = await _apis["ldap_alice"].get("/folders")
    assert r.status_code == 200, f"LDAP user should list root: {r.status_code}"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_02_ldap_user_can_create_folder():
    folder = await create_folder(_apis["ldap_alice"], "15 ldap create test")
    assert folder["name"] == "15 ldap create test"
    assert "id" in folder


@pytest.mark.asyncio(loop_scope="session")
async def test_15_03_ldap_user_can_rename_folder():
    folder = await create_folder(_apis["ldap_alice"], "15 ldap rename before")
    renamed = await rename_folder(_apis["ldap_alice"], folder["id"], "15 ldap rename after")
    assert renamed["name"] == "15 ldap rename after"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_04_ldap_user_can_upload_file():
    f = await upload_file_api(_apis["ldap_alice"], "ldap_15_upload.bin", b"ldap upload data")
    assert "id" in f
    assert f.get("original_name") == "ldap_15_upload.bin"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_05_ldap_user_can_delete_file():
    f = await upload_file_api(_apis["ldap_alice"], "ldap_15_delete.bin", b"to delete")
    await delete_file(_apis["ldap_alice"], f["id"])
    r = await _apis["ldap_alice"].get(f"/files/{f['id']}")
    assert r.status_code == 404, "Deleted file should return 404"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_06_ldap_user_can_create_link_share():
    share = await create_link_share(_apis["ldap_alice"], [_files["ldap_alice"]["id"]])
    assert "token" in share
    assert share.get("share_type") == "link"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_07_ldap_user_can_create_team_and_add_member():
    team = await create_team(_apis["ldap_alice"], "15 LDAP-owned Team")
    assert "id" in team

    # Add the OPAQUE user as a member
    await add_member(_apis["ldap_alice"], team["id"], _usernames["opaque"])

    from tests.e2e.helpers.teams import list_members
    members = await list_members(_apis["ldap_alice"], team["id"])
    member_ids = [m["user_id"] for m in members]
    assert _user_ids["opaque"] in member_ids, "OPAQUE user should appear as team member"

    await delete_team(_apis["ldap_alice"], team["id"])


# ===========================================================================
# Feature parity — OIDC
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_15_08_oidc_user_can_list_root():
    _skip_if_no_oidc()
    r = await _apis["oidc_alice"].get("/folders")
    assert r.status_code == 200, f"OIDC user should list root: {r.status_code}"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_09_oidc_user_can_create_folder():
    _skip_if_no_oidc()
    folder = await create_folder(_apis["oidc_alice"], "15 oidc create test")
    assert folder["name"] == "15 oidc create test"
    assert "id" in folder


@pytest.mark.asyncio(loop_scope="session")
async def test_15_10_oidc_user_can_create_link_share():
    _skip_if_no_oidc()
    f = await upload_file_api(_apis["oidc_alice"], "oidc_15_share.bin", b"oidc share content")
    share = await create_link_share(_apis["oidc_alice"], [f["id"]])
    assert "token" in share
    assert share.get("share_type") == "link"


# ===========================================================================
# Private folder isolation
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_15_11_opaque_cannot_access_ldap_private_folder():
    can = await can_list_folder(_apis["opaque"], _folders["ldap_alice"]["id"])
    assert not can, "OPAQUE user must not access LDAP user's private folder"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_12_ldap_cannot_access_opaque_private_folder():
    can = await can_list_folder(_apis["ldap_alice"], _folders["opaque"]["id"])
    assert not can, "LDAP user must not access OPAQUE user's private folder"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_13_oidc_cannot_access_ldap_private_folder():
    _skip_if_no_oidc()
    can = await can_list_folder(_apis["oidc_alice"], _folders["ldap_alice"]["id"])
    assert not can, "OIDC user must not access LDAP user's private folder"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_14_ldap_cannot_access_oidc_private_folder():
    _skip_if_no_oidc()
    can = await can_list_folder(_apis["ldap_alice"], _folders["oidc_alice"]["id"])
    assert not can, "LDAP user must not access OIDC user's private folder"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_15_ldap_p1_cannot_access_ldap_p2_private_folder():
    """
    ldap_alice (provider 1) and ldap_carol (provider 2) are distinct identities
    even though they authenticate against the same LDAP server.
    """
    can = await can_list_folder(_apis["ldap_alice"], _folders["ldap_carol"]["id"])
    assert not can, (
        "LDAP provider-1 user must not access LDAP provider-2 user's private folder"
    )


# ===========================================================================
# Cross-authentication link sharing
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_15_16_opaque_share_accessible_by_ldap_user():
    """OPAQUE user creates a link share; any user with the token can resolve it."""
    share = await create_link_share(_apis["opaque"], [_files["opaque"]["id"]])
    token = share["token"]

    # Resolve as the LDAP user (authenticated download path)
    r = await _apis["ldap_alice"].get(f"/s/{token}")
    assert r.status_code == 200, (
        f"LDAP user should resolve OPAQUE-created share, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_15_17_ldap_share_accessible_by_opaque_user():
    """LDAP user creates a link share; OPAQUE user can resolve it."""
    share = await create_link_share(_apis["ldap_alice"], [_files["ldap_alice"]["id"]])
    token = share["token"]

    r = await _apis["opaque"].get(f"/s/{token}")
    assert r.status_code == 200, (
        f"OPAQUE user should resolve LDAP-created share, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_15_18_ldap_share_accessible_by_oidc_user():
    """LDAP user creates a link share; OIDC user can resolve it."""
    _skip_if_no_oidc()
    share = await create_link_share(_apis["ldap_alice"], [_files["ldap_alice"]["id"]])
    token = share["token"]

    r = await _apis["oidc_alice"].get(f"/s/{token}")
    assert r.status_code == 200, (
        f"OIDC user should resolve LDAP-created share, got {r.status_code}: {r.text}"
    )


# ===========================================================================
# Direct user-to-IdP share is rejected
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_15_19_direct_user_share_to_ldap_user_rejected():
    """
    Direct user shares require the recipient to have PQ keys
    (wrapped_master_key set from OPAQUE registration).  LDAP users have null
    wrapped_master_key, so the server must reject the share request.
    """
    from tests.e2e.helpers.crypto_stubs import fake_aes256_key, fake_iv_12

    r = await _apis["opaque"]._client.post(
        f"{API}/shares",
        json={
            "share_type":         "user",
            "recipient_username": _usernames["ldap_alice"],
            "items": [
                {
                    "resource_type":      "file",
                    "resource_id":        _files["opaque"]["id"],
                    "encrypted_file_key": fake_aes256_key(),
                    "key_iv":             fake_iv_12(),
                }
            ],
        },
    )
    assert r.status_code in (400, 422), (
        f"Direct share to LDAP user (no PQ keys) should fail, got {r.status_code}: {r.text}"
    )


# ===========================================================================
# Mixed team (OPAQUE + LDAP + OIDC members)
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_15_20_create_mixed_team_with_ldap_and_oidc_members(
    admin_client: AdminClient,
):
    """OPAQUE user creates a team and adds both LDAP and OIDC members."""
    global _mixed_team
    team = await create_team(_apis["opaque"], "15 Mixed Auth Team")

    # Add LDAP member
    await add_member(_apis["opaque"], team["id"], _usernames["ldap_alice"])

    # Add OIDC member if available
    if "oidc_alice" in _apis:
        await add_member(_apis["opaque"], team["id"], _usernames["oidc_alice"])

    # Create and register a team folder
    folder = await create_folder(_apis["opaque"], "15 Mixed Team Folder")
    await add_team_folder(_apis["opaque"], team["id"], folder["id"])

    _mixed_team.update(team)
    _mixed_team["folder_id"] = folder["id"]

    from tests.e2e.helpers.teams import list_members
    members = await list_members(_apis["opaque"], team["id"])
    usernames = {m["username"] for m in members}
    assert _usernames["ldap_alice"] in usernames, "ldap_alice should be a team member"


@pytest.mark.asyncio(loop_scope="session")
async def test_15_21_ldap_member_can_list_mixed_team_folders():
    if not _mixed_team:
        pytest.skip("15-20 did not create the mixed team")

    folders = await list_team_folders(_apis["ldap_alice"], _mixed_team["id"])
    folder_ids = [f["folder_id"] for f in folders]
    assert _mixed_team["folder_id"] in folder_ids, (
        "LDAP member should see the mixed team's folder"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_15_22_oidc_member_can_list_mixed_team_folders():
    _skip_if_no_oidc()
    if not _mixed_team:
        pytest.skip("15-20 did not create the mixed team")

    folders = await list_team_folders(_apis["oidc_alice"], _mixed_team["id"])
    folder_ids = [f["folder_id"] for f in folders]
    assert _mixed_team["folder_id"] in folder_ids, (
        "OIDC member should see the mixed team's folder"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_15_23_non_member_cannot_access_mixed_team_folders():
    """ldap_carol (different provider, not a member) must be blocked."""
    if not _mixed_team:
        pytest.skip("15-20 did not create the mixed team")

    r = await _apis["ldap_carol"].get(f"/teams/{_mixed_team['id']}/folders")
    assert r.status_code in (403, 404), (
        f"Non-member ldap_carol should be blocked from mixed team, got {r.status_code}"
    )


# ===========================================================================
# Admin role for LDAP users
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_15_24_ldap_user_without_admin_role_is_blocked():
    r = await _apis["ldap_alice"].get("/admin/settings")
    assert r.status_code in (403, 401), (
        f"LDAP user with no admin role should be blocked from /admin/settings, "
        f"got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_15_25_grant_admin_role_to_ldap_user_grants_access(
    admin_client: AdminClient,
):
    if "ldap_alice" not in _user_ids:
        pytest.skip("ldap_alice user ID not resolved — did build_world succeed?")

    await admin_client.grant_role(_user_ids["ldap_alice"], "server_admin")

    r = await _apis["ldap_alice"].get("/admin/settings")
    assert r.status_code == 200, (
        f"LDAP user with server_admin role should reach /admin/settings, "
        f"got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_15_26_revoke_admin_role_from_ldap_user_blocks_access(
    admin_client: AdminClient,
):
    if "ldap_alice" not in _user_ids:
        pytest.skip("ldap_alice user ID not resolved")

    await admin_client.revoke_role(_user_ids["ldap_alice"], "server_admin")

    r = await _apis["ldap_alice"].get("/admin/settings")
    assert r.status_code in (403, 401), (
        f"LDAP user after role revocation should be blocked from /admin/settings, "
        f"got {r.status_code}"
    )
