"""
Group 16 — Policy enforcement and restricted-role boundaries.

Tests the policy engine enforcement layer end-to-end:
  • LDAP attribute conditions that grant (and revoke) folder access
  • Compound AND conditions — both must match; one failing excludes the user
  • team_member effects — users matching conditions are auto-enrolled in teams
  • Restricted admin roles — can_manage_policies gates all policy CRUD

Requires LDAP reachable on localhost:389 (docker-compose.test.yml exposes the
container port).  The whole module is skipped if LDAP is unavailable.

Actors
------
  ldap_alice   — departmentNumber=engineering, auth_provider=ldap
  ldap_bob     — departmentNumber=marketing,   auth_provider=ldap
  ldap_carol   — departmentNumber=engineering, auth_provider=ldap
  opaque_16    — registered OPAQUE user (used for restricted-role tests only)

LDAP attributes sourced from: tests/fixtures/ldap/seed.ldif

Tests
-----
LDAP field → folder_acl enforcement
  16-01  dept_number policy field created (source=ldap, claim_path=departmentNumber)
  16-02  Policy + condition (dept_number=engineering) + folder_acl effect →
           alice gains read access to the admin-owned gated folder
  16-03  ldap_bob (marketing) is denied access to the same gated folder
  16-04  Updating the condition value to "marketing" revokes alice's access;
           bob (marketing) gains access
  16-05  Restoring the condition to "engineering" restores alice's access

Compound conditions (AND semantics)
  16-06  Two conditions: dept_number=engineering AND auth_provider=ldap →
           alice (engineering + ldap) matches and gains access to compound folder
  16-07  ldap_bob (ldap, marketing) satisfies only one condition → denied
  16-08  ldap_carol (engineering, ldap) also matches → gains access
  16-09  Adding a third contradictory condition (dept_number=operations) removes
           all current matches — proves AND, not OR semantics

Policy team_member effect
  16-10  dept_number=engineering policy + team_member effect →
           alice auto-enrolled in the admin-owned enrollment team
  16-11  ldap_bob (marketing) is not auto-enrolled
  16-12  Deleting the team_member effect removes alice from the team (CASCADE)

Restricted admin role capabilities
  16-13  User with no extra roles is blocked from POST /admin/policies (403)
  16-14  can_view_admin_panel alone is insufficient to create policies or
           policy fields — can_manage_policies is required
  16-15  Granting can_manage_policies allows policy CRUD; revoking it
           immediately re-blocks the user within the same session
"""

from __future__ import annotations

import asyncio
from typing import Optional

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import ldap_login, register_via_invite
from tests.e2e.helpers.files import can_list_folder, create_folder
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest
from tests.e2e.helpers.teams import create_team, delete_team, is_member

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state (mutated by build_world, read by tests)
# ---------------------------------------------------------------------------

_provider_id: str = ""
_apis:        dict[str, ApiClient] = {}
_user_ids:    dict[str, str]       = {}
_admin_api:   Optional[ApiClient]  = None

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# auth.forbidden: 16-03/07/09 (LDAP users denied gated folder → 403),
#   16-13 (no manage_policies → 403 on /admin/policies),
#   16-14 (can_view_admin_panel alone → 403 on policy CRUD).
# set_role_permissions() hits the role-permissions endpoint, not the
# user-role endpoint, so admin.role.granted/revoked are NOT emitted here.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden", outcome="failure", severity="warning", tier=2),
]

# Folders owned by the admin — LDAP users have no default access
_gated_folder:    dict = {}   # used by section 1 (single condition)
_compound_folder: dict = {}   # used by section 2 (compound conditions)

# Section 1 state
_single_policy:    dict = {}
_single_cond_id:   str  = ""
_single_effect_id: str  = ""

# Section 2 state
_compound_policy:    dict = {}
_compound_cond_ids:  list = []   # [eng_cond_id, ldap_cond_id]
_compound_effect_id: str  = ""
_third_cond_id:      str  = ""

# Section 3 state
_team_policy:     dict = {}
_team_effect_id:  str  = ""
_enrollment_team: dict = {}

# Section 4 state
_opaque_session         = None
_opaque_user:     dict  = {}
_restricted_role: dict  = {}

# ---------------------------------------------------------------------------
# LDAP provider config (docker service name used inside app container)
# ---------------------------------------------------------------------------

_LDAP_CONFIG = {
    "server_uri":    "ldap://ldap:389",
    "bind_dn":       "cn=admin,dc=test,dc=local",
    "bind_password": "ldap_admin_secret",
    "base_dn":       "ou=users,dc=test,dc=local",
    "user_filter":   "(uid={username})",
    "tls":           "skip_verify",
    "username_attr": "uid",
}

# ---------------------------------------------------------------------------
# Reachability check
# ---------------------------------------------------------------------------


def _ldap_ok() -> bool:
    import socket
    try:
        with socket.create_connection(("localhost", 389), timeout=3):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Polling helpers (policy sweep is a background task — give it up to 10 s)
# ---------------------------------------------------------------------------


async def _wait_folder_access(
    api:       ApiClient,
    folder_id: str,
    expect:    bool,
    timeout_s: int = 10,
) -> bool:
    """Poll can_list_folder until it returns `expect` or the timeout expires."""
    loop     = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if await can_list_folder(api, folder_id) == expect:
            return True
        await asyncio.sleep(1)
    return False


async def _wait_team_membership(
    api:       ApiClient,
    team_id:   str,
    user_id:   str,
    expect:    bool,
    timeout_s: int = 10,
) -> bool:
    """Poll team membership until the user's presence matches `expect`."""
    loop     = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if await is_member(api, team_id, user_id) == expect:
            return True
        await asyncio.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Module-scoped world fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
async def build_world(browser: Browser, admin_client: AdminClient, seeded_env):
    global _provider_id, _apis, _user_ids, _admin_api
    global _gated_folder, _compound_folder, _enrollment_team
    global _opaque_session, _opaque_user, _restricted_role

    if not _ldap_ok():
        pytest.skip("LDAP not reachable on localhost:389 — skipping group 16")

    # Admin ApiClient for folder/team creation (admin is the resource owner)
    _admin_api = ApiClient.from_session(seeded_env["admin_session"])

    # Create LDAP provider
    prov = await admin_client.create_idp_provider(
        provider_type="ldap", name="16 LDAP P1", config=_LDAP_CONFIG,
    )
    _provider_id = prov["id"]

    # Log in all three LDAP actors (auto-provisions their user records)
    for uname, pwd in [
        ("ldap_alice", "Alice!Ldap99"),
        ("ldap_bob",   "Bob!Ldap99"),
        ("ldap_carol", "Carol!Ldap99"),
    ]:
        cookies = await ldap_login(_provider_id, uname, pwd)
        _apis[uname] = ApiClient(cookies)

    # Resolve server-side user IDs (needed for team membership checks)
    users = await admin_client.list_users()
    for u in users:
        if u.get("identity_provider_id") == _provider_id:
            _user_ids[u["username"]] = u["id"]

    # Create policy-gated folders (admin-owned; no default access for LDAP users)
    _gated_folder    = await create_folder(_admin_api, "16 Gated Single")
    _compound_folder = await create_folder(_admin_api, "16 Gated Compound")

    # Team for section 3 enrollment tests (admin-owned)
    _enrollment_team = await create_team(_admin_api, "16 Policy Enrollment Team")

    # OPAQUE user for section 4 restricted-role tests
    invite_url      = await admin_client.create_invite_url()
    _opaque_session = await register_via_invite(browser, invite_url, "opaque_16", "0p4que!16Pwd")
    all_users       = await admin_client.list_users()
    _opaque_user.update(next(u for u in all_users if u["username"] == "opaque_16"))

    # Custom role with no flags (section 4)
    _restricted_role.update(await admin_client.create_role(name="16_restricted_role"))

    yield

    # Teardown — best-effort cleanup
    for api in _apis.values():
        try:
            await api.aclose()
        except Exception:
            pass
    if _admin_api:
        try:
            await _admin_api.aclose()
        except Exception:
            pass
    if _opaque_session:
        try:
            await _opaque_session.ctx.close()
        except Exception:
            pass
    try:
        await admin_client.delete_role(_restricted_role["id"])
    except Exception:
        pass
    try:
        await admin_client._client.delete(
            f"{API}/admin/identity-providers/{_provider_id}"
        )
    except Exception:
        pass
    try:
        await delete_team(_admin_api, _enrollment_team["id"])
    except Exception:
        pass
    try:
        await admin_client.delete_policy_field("dept_number")
    except Exception:
        pass


# ===========================================================================
# Section 1 — LDAP attribute field → folder_acl enforcement
# ===========================================================================


@pytest.mark.asyncio(loop_scope="session")
async def test_16_01_create_ldap_policy_field(admin_client: AdminClient):
    """Create dept_number as a policy field backed by the LDAP departmentNumber attribute."""
    field = await admin_client.create_policy_field(
        name="dept_number",
        display_label="Department Number",
        source="ldap",
        data_type="string",
        claim_path="departmentNumber",
    )
    assert field["name"] == "dept_number"
    assert field["source"] == "ldap"


@pytest.mark.asyncio(loop_scope="session")
async def test_16_02_engineering_condition_grants_alice_folder_access(
    admin_client: AdminClient,
):
    """
    Policy with condition dept_number=engineering + folder_acl effect on _gated_folder.
    ldap_alice (departmentNumber=engineering) must gain read access after the sweep.
    """
    global _single_policy, _single_cond_id, _single_effect_id

    _single_policy = await admin_client.create_policy(name="16 Engineering Access")

    cond = await admin_client.add_policy_condition(
        _single_policy["id"],
        field="dept_number",
        operator="=",
        value="engineering",
    )
    _single_cond_id = cond["id"]

    effect = await admin_client.create_policy_effect(
        _single_policy["id"],
        effect_type="folder_acl",
        target_id=_gated_folder["id"],
        permission="read",
    )
    _single_effect_id = effect["id"]

    granted = await _wait_folder_access(
        _apis["ldap_alice"], _gated_folder["id"], expect=True
    )
    assert granted, (
        "ldap_alice (engineering) should gain access to gated folder after policy effect is applied"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_16_03_bob_marketing_denied_gated_folder():
    """ldap_bob (departmentNumber=marketing) must not match the engineering condition."""
    can = await can_list_folder(_apis["ldap_bob"], _gated_folder["id"])
    assert not can, "ldap_bob (marketing) must be denied access to the engineering-gated folder"


@pytest.mark.asyncio(loop_scope="session")
async def test_16_04_updating_condition_revokes_alice_grants_bob(
    admin_client: AdminClient,
):
    """
    Changing the condition value to 'marketing' triggers a re-sweep.
    Alice (engineering) loses access; Bob (marketing) gains it.
    Verifies that policy effects are re-evaluated on every condition change.
    """
    r = await admin_client._client.patch(
        f"{API}/admin/policies/{_single_policy['id']}/conditions/{_single_cond_id}",
        json={"value": "marketing"},
    )
    assert r.status_code == 200, f"PATCH condition failed: {r.status_code} {r.text}"

    alice_revoked = await _wait_folder_access(
        _apis["ldap_alice"], _gated_folder["id"], expect=False
    )
    assert alice_revoked, "ldap_alice should lose access when condition value changes to marketing"

    bob_granted = await _wait_folder_access(
        _apis["ldap_bob"], _gated_folder["id"], expect=True
    )
    assert bob_granted, "ldap_bob (marketing) should gain access after condition update"


@pytest.mark.asyncio(loop_scope="session")
async def test_16_05_restoring_condition_restores_alice_access(
    admin_client: AdminClient,
):
    """Changing the condition back to 'engineering' must restore alice's access."""
    r = await admin_client._client.patch(
        f"{API}/admin/policies/{_single_policy['id']}/conditions/{_single_cond_id}",
        json={"value": "engineering"},
    )
    assert r.status_code == 200

    alice_back = await _wait_folder_access(
        _apis["ldap_alice"], _gated_folder["id"], expect=True
    )
    assert alice_back, "ldap_alice should regain access after condition is restored to engineering"


# ===========================================================================
# Section 2 — Compound conditions (AND semantics)
# ===========================================================================


@pytest.mark.asyncio(loop_scope="session")
async def test_16_06_compound_policy_alice_matches_both_conditions(
    admin_client: AdminClient,
):
    """
    Policy with two conditions: dept_number=engineering AND auth_provider=ldap.
    ldap_alice satisfies both → gains access to compound folder.
    """
    global _compound_policy, _compound_cond_ids, _compound_effect_id

    _compound_policy = await admin_client.create_policy(name="16 Compound Access")

    cond_eng = await admin_client.add_policy_condition(
        _compound_policy["id"],
        field="dept_number",
        operator="=",
        value="engineering",
    )
    cond_ldap = await admin_client.add_policy_condition(
        _compound_policy["id"],
        field="auth_provider",
        operator="=",
        value="ldap",
    )
    _compound_cond_ids.extend([cond_eng["id"], cond_ldap["id"]])

    effect = await admin_client.create_policy_effect(
        _compound_policy["id"],
        effect_type="folder_acl",
        target_id=_compound_folder["id"],
        permission="read",
    )
    _compound_effect_id = effect["id"]

    granted = await _wait_folder_access(
        _apis["ldap_alice"], _compound_folder["id"], expect=True
    )
    assert granted, (
        "ldap_alice (engineering + ldap) should satisfy both conditions and gain access"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_16_07_compound_bob_fails_dept_condition():
    """
    ldap_bob satisfies auth_provider=ldap but NOT dept_number=engineering.
    AND semantics require both conditions — bob must be denied.
    """
    can = await can_list_folder(_apis["ldap_bob"], _compound_folder["id"])
    assert not can, (
        "ldap_bob satisfies only one of two compound conditions; "
        "AND semantics must deny access"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_16_08_compound_carol_also_matches():
    """
    ldap_carol is also engineering + ldap — must match the compound policy.
    Confirms policy effects apply to every qualifying user, not just the first one
    evaluated by the sweep.
    """
    granted = await _wait_folder_access(
        _apis["ldap_carol"], _compound_folder["id"], expect=True
    )
    assert granted, (
        "ldap_carol (engineering + ldap) should also satisfy both conditions and gain access"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_16_09_contradictory_third_condition_removes_all_matches(
    admin_client: AdminClient,
):
    """
    Add a third condition: dept_number=operations.
    No user can simultaneously have dept_number=engineering AND dept_number=operations,
    so all grants must be revoked.  Directly proves AND (not OR) semantics.
    """
    global _third_cond_id

    cond = await admin_client.add_policy_condition(
        _compound_policy["id"],
        field="dept_number",
        operator="=",
        value="operations",
    )
    _third_cond_id = cond["id"]

    alice_revoked = await _wait_folder_access(
        _apis["ldap_alice"], _compound_folder["id"], expect=False
    )
    assert alice_revoked, (
        "After adding dept_number=operations, alice (engineering) must lose access "
        "— cannot satisfy both engineering and operations simultaneously"
    )

    carol_revoked = await _wait_folder_access(
        _apis["ldap_carol"], _compound_folder["id"], expect=False
    )
    assert carol_revoked, (
        "ldap_carol must also lose access after contradictory condition is added"
    )


# ===========================================================================
# Section 3 — Policy team_member effect
# ===========================================================================


@pytest.mark.asyncio(loop_scope="session")
async def test_16_10_team_member_effect_auto_enrolls_alice(admin_client: AdminClient):
    """
    Policy with dept_number=engineering + team_member effect on _enrollment_team.
    ldap_alice (engineering) must be auto-enrolled after the sweep.
    """
    global _team_policy, _team_effect_id

    _team_policy = await admin_client.create_policy(name="16 Team Enrollment")
    await admin_client.add_policy_condition(
        _team_policy["id"],
        field="dept_number",
        operator="=",
        value="engineering",
    )
    effect = await admin_client.create_policy_effect(
        _team_policy["id"],
        effect_type="team_member",
        target_id=_enrollment_team["id"],
        role_level="team_member",
    )
    _team_effect_id = effect["id"]

    alice_id = _user_ids.get("ldap_alice", "")
    enrolled = await _wait_team_membership(
        _admin_api, _enrollment_team["id"], alice_id, expect=True
    )
    assert enrolled, (
        "ldap_alice (engineering) should be auto-enrolled in the team by the team_member effect"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_16_11_team_member_effect_excludes_bob():
    """ldap_bob (marketing) must not be auto-enrolled by the engineering team policy."""
    bob_id = _user_ids.get("ldap_bob", "")
    in_team = await is_member(_admin_api, _enrollment_team["id"], bob_id)
    assert not in_team, "ldap_bob (marketing) must not be enrolled by the engineering team policy"


@pytest.mark.asyncio(loop_scope="session")
async def test_16_12_deleting_team_effect_removes_alice(admin_client: AdminClient):
    """
    DELETE the team_member effect.  The policy_effect_id CASCADE must remove
    alice's policy-sourced team membership.
    """
    await admin_client.delete_policy_effect(_team_policy["id"], _team_effect_id)

    alice_id = _user_ids.get("ldap_alice", "")
    removed = await _wait_team_membership(
        _admin_api, _enrollment_team["id"], alice_id, expect=False
    )
    assert removed, (
        "ldap_alice should be removed from the team when the team_member effect is deleted"
    )


# ===========================================================================
# Section 4 — Restricted admin role capabilities
# ===========================================================================


@pytest.mark.asyncio(loop_scope="session")
async def test_16_13_user_without_manage_policies_cannot_create_policy():
    """A freshly registered user with no extra roles must get 403 on POST /admin/policies."""
    api = ApiClient.from_session(_opaque_session)
    try:
        r = await api.post("/admin/policies", json={"name": "Should Fail", "scope_type": "org"})
    finally:
        await api.aclose()
    assert r.status_code == 403, (
        f"User with no roles should be blocked from creating policies, got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_16_14_can_view_admin_panel_without_manage_policies_is_blocked(
    admin_client: AdminClient,
):
    """
    can_view_admin_panel and can_manage_policies are independent flags.
    Having only can_view_admin_panel must NOT grant access to policy or
    policy-field creation endpoints.
    """
    await admin_client.set_role_permissions(
        _restricted_role["id"],
        {"admin_panel_view": True, "policies_manage": False},
    )
    await admin_client.grant_role(_opaque_user["id"], _restricted_role["id"])

    api = ApiClient.from_session(_opaque_session)
    try:
        r_policy = await api.post(
            "/admin/policies", json={"name": "Should Fail", "scope_type": "org"}
        )
        r_field = await api.post(
            "/admin/policy-fields",
            json={
                "name":          "should_fail_field",
                "display_label": "Fail",
                "source":        "ldap",
                "data_type":     "string",
                "claim_path":    "fail",
            },
        )
    finally:
        await api.aclose()

    assert r_policy.status_code == 403, (
        f"can_view_admin_panel alone must not grant policy creation, "
        f"got {r_policy.status_code}: {r_policy.text}"
    )
    assert r_field.status_code == 403, (
        f"can_view_admin_panel alone must not grant policy-field creation, "
        f"got {r_field.status_code}: {r_field.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_16_15_manage_policies_flag_enables_and_revoking_blocks(
    admin_client: AdminClient,
):
    """
    Granting can_manage_policies enables policy CRUD for the user.
    Revoking it mid-session immediately re-blocks further mutations,
    because the flag is evaluated server-side on every request.
    """
    await admin_client.set_role_permissions(
        _restricted_role["id"],
        {"admin_panel_view": True, "policies_manage": True},
    )

    created_policy_id: str = ""
    api = ApiClient.from_session(_opaque_session)
    try:
        r_create = await api.post(
            "/admin/policies",
            json={"name": "16 Restricted Create Test", "scope_type": "org"},
        )
        assert r_create.status_code == 200, (
            f"User with can_manage_policies should create a policy, "
            f"got {r_create.status_code}: {r_create.text}"
        )
        created_policy_id = r_create.json()["id"]

        # Revoke the flag — checked on the next request without a session change
        await admin_client.set_role_permissions(
            _restricted_role["id"], {"policies_manage": False}
        )

        r_blocked = await api.post(
            "/admin/policies",
            json={"name": "Should Fail Again", "scope_type": "org"},
        )
        assert r_blocked.status_code == 403, (
            f"After revoking can_manage_policies, policy creation must be blocked, "
            f"got {r_blocked.status_code}: {r_blocked.text}"
        )
    finally:
        await api.aclose()
        if created_policy_id:
            try:
                await admin_client.delete_policy(created_policy_id)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 16-16  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_16_16_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
