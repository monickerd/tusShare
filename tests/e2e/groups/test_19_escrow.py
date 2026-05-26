"""
Group 19 — Escrow by Default.

Tests cover the full escrow-by-default lifecycle:
  A. Org-level settings & initial state
  B. Effective-agent resolution (org default, replace, merge, none, inheritance)
  C. Team creation enforcement (require_coverage)
  D. Coverage report (content + pagination)
  E. Default rotation — no automatic backfill; coverage report as the signal
  F. Access control (can_manage_escrow flag)
  G. Folder policy constraints (overrides_allowed, policy_locked)
  H. Folder deletion cascades to policy

Design note on "rotation" (tests 19-21 to 19-22):
  Escrow-by-default does NOT automatically rotate existing team keys when the default changes.
  Old teams remain covered only as long as their current escrow member still holds
  the escrow_agent role.  The coverage report surfaces teams that have lost coverage.
  Admins trigger backfill via the pending-key-grants flow.

Tests
-----
19-01  Initial escrow settings — empty user list, escrow_agent role, require_coverage=False
19-02  Regular user (no admin) cannot read escrow settings (403)
19-03  Admin without can_manage_escrow flag gets 403 on GET escrow settings
19-04  Set escrow_user1 as org default; verify settings reflect change
19-05  Escrow agent without registered keys excluded from resolved agent list
19-06  Folder with no override inherits org default (escrow_user1)
19-07  Deeply nested folder (3 levels) with no overrides inherits org default
19-08  'replace' override: escrow_user2 in list, escrow_user1 absent
19-09  Subfolder of replace-override folder inherits parent policy (no own override)
19-10  'merge' override: both org default (e1) and policy agent (e2) present, no duplicates
19-11  'none' override: empty agent list, source='none'
19-12  Subfolder under 'none' folder also returns none (ancestor inheritance)
19-13  require_coverage=False: POST /teams without escrow_members → 201
19-14  require_coverage=True: POST /teams without escrow_members → 422
19-15  require_coverage=True: POST /teams with escrow_members → 201
19-16  Team without any escrow member appears in coverage report
19-17  Team with valid escrow member NOT in coverage report
19-18  Coverage report pagination: limit and offset work correctly
19-19  Revoking escrow_agent role from team's only escrow member exposes team in report
19-20  Restoring escrow_agent role removes team from coverage report
19-21  Changing org default to e2: new resolution returns e2 (not e1)
19-22  Old team with e1 member stays covered after org default changes (no auto-rotation)
19-23  GET effective-escrow-agents accessible to folder owner without can_manage_escrow
19-24  GET effective-escrow-agents returns 403 for folder caller does not own
19-25  overrides_allowed=False on parent blocks child policy creation (403)
19-26  policy_locked=True blocks modification by lower-tier admin (403)
19-27  policy_locked at tier 2 allows server_admin but still blocks operational_admin
19-28  Deleting folder with an escrow policy removes the policy (ON DELETE CASCADE)
"""

from __future__ import annotations

import httpx
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient
from tests.e2e.helpers.auth   import register_via_invite
from tests.e2e.helpers.crypto_stubs import fake_asymmetric_keys, fake_g2_point, fake_kem_bundle
from tests.e2e.helpers.files  import create_folder
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_e1:       dict = {}   # escrow_user1 — escrow_agent role + registered keys
_e2:       dict = {}   # escrow_user2 — escrow_agent role + registered keys
_e3:       dict = {}   # escrow_user3 — escrow_agent role, NO keys
_plain:    dict = {}   # regular user, no special roles
_mgr:      dict = {}   # admin with can_view_admin_panel only (not can_manage_escrow)
_op_admin: dict = {}   # admin with operational_admin (tier 3) + can_manage_escrow

_folder: dict = {}     # named folder IDs
_unprotected_team_id: str = ""   # team from test_19_13 (no escrow member)
_protected_team_id:   str = ""   # team from test_19_15 (e1 as escrow member)

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# auth.forbidden: 19-02 (_plain blocked from escrow settings), 19-03 (_mgr
#   blocked without can_manage_escrow), 19-24 (inaccessible folder → 403),
#   19-25 (overrides_allowed=False blocks child policy → 403),
#   19-26/27 (policy_locked blocks lower-tier admin → 403).
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden", outcome="failure", severity="warning", tier=2),
]


async def _reg(browser, admin_client, username: str, password: str) -> dict:
    url     = await admin_client.create_invite_url()
    session = await register_via_invite(browser, url, username, password)
    users   = await admin_client.list_users()
    user    = next(u for u in users if u["username"].lower() == username.lower())
    return {"id": user["id"], "username": username, "password": password,
            "session": session, "api": ApiClient.from_session(session)}


async def _register_keys(api: ApiClient) -> None:
    r = await api.post("/auth/me/asymmetric-keys", json=fake_asymmetric_keys())
    r.raise_for_status()


async def _create_team(api: ApiClient, name: str, escrow_uids: list[str] | None = None) -> httpx.Response:
    """POST /teams — always returns the raw response so callers can inspect status."""
    payload: dict = {
        "name":           name,
        "pre_public_key": fake_g2_point(),
        **fake_kem_bundle(),
    }
    if escrow_uids:
        payload["escrow_members"] = [
            {"user_id": uid, **fake_kem_bundle()} for uid in escrow_uids
        ]
    return await api.post("/teams", json=payload)


async def _effective(api: ApiClient, folder_id: str) -> dict:
    r = await api.get(f"/folders/{folder_id}/effective-escrow-agents")
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _e1, _e2, _e3, _plain, _mgr, _op_admin

    _e1      = await _reg(browser, admin_client, "escrow_u1_19", "Escr0w!One99")
    _e2      = await _reg(browser, admin_client, "escrow_u2_19", "Escr0w!Two99")
    _e3      = await _reg(browser, admin_client, "escrow_u3_19", "Escr0w!Thr99")
    _plain   = await _reg(browser, admin_client, "plain_u_19",   "Pl4in!User99")
    _mgr     = await _reg(browser, admin_client, "escrow_mgr_19","Escr0w!Mgr99")
    _op_admin= await _reg(browser, admin_client, "op_adm_19",    "0pAdm!in99")

    # escrow_agent role for e1, e2, e3
    for u in (_e1, _e2, _e3):
        await admin_client.grant_role(u["id"], "escrow_agent")

    # Register proper fake keys for e1 and e2 (overwrites browser-auto-registered keys)
    await _register_keys(_e1["api"])
    await _register_keys(_e2["api"])
    # e3 intentionally has no keys — clear any auto-registered during browser signup
    await admin_client.clear_user_asymmetric_keys(_e3["id"])

    # _mgr: can_view_admin_panel only (no can_manage_escrow)
    no_esc = await admin_client.create_role("no_escrow_adm_19")
    await admin_client.set_role_permissions(no_esc["id"], {"can_view_admin_panel": True})
    await admin_client.grant_role(_mgr["id"], no_esc["id"])

    # _op_admin: operational_admin (tier 3) + can_manage_escrow via helper role
    await admin_client.grant_role(_op_admin["id"], "operational_admin")
    helper = await admin_client.create_role("op_esc_helper_19")
    await admin_client.set_role_permissions(helper["id"], {"can_manage_escrow": True})
    await admin_client.grant_role(_op_admin["id"], helper["id"])

    yield

    for u in (_e1, _e2, _e3, _plain, _mgr, _op_admin):
        try:
            await u["api"].aclose()
            await u["session"].ctx.close()
        except Exception:
            pass
    for rid in ("no_escrow_adm_19", "op_esc_helper_19"):
        try:
            await admin_client.delete_role(rid)
        except Exception:
            pass


# ===========================================================================
# A. Org-level settings & initial state
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_01_initial_settings(admin_client: AdminClient):
    s = await admin_client.get_escrow_settings()
    assert s["escrow_require_coverage"] is False
    assert isinstance(s["escrow_default_user_ids"], list)
    assert "escrow_agent" in s["escrow_default_role_ids"]
    assert s["is_locked"] is False


@pytest.mark.asyncio(loop_scope="session")
async def test_19_02_plain_user_cannot_read_escrow_settings():
    r = await _plain["api"].get("/admin/escrow/settings")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio(loop_scope="session")
async def test_19_03_admin_without_escrow_flag_gets_403():
    """_mgr has can_view_admin_panel but not can_manage_escrow → 403."""
    r = await _mgr["api"].get("/admin/escrow/settings")
    assert r.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_19_04_set_escrow_user1_as_org_default(admin_client: AdminClient):
    await admin_client.update_escrow_settings(
        escrow_default_user_ids=[_e1["id"]],
        escrow_default_role_ids=[],
    )
    s = await admin_client.get_escrow_settings()
    assert _e1["id"] in s["escrow_default_user_ids"]
    assert s["escrow_default_role_ids"] == []


# ===========================================================================
# B. Effective-agent resolution
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_05_agent_without_keys_excluded_from_resolved_list(admin_client: AdminClient):
    """e3 has escrow_agent role but no x25519/mlkem keys — must not appear in resolved list."""
    # Temporarily set e3 as the sole org default user to force a resolution that
    # would include them if the key-filter weren't working.
    await admin_client.update_escrow_settings(
        escrow_default_user_ids=[_e3["id"]],
        escrow_default_role_ids=[],
    )
    f = await create_folder(_e1["api"], "escrow_keycheck_19")
    _folder["keycheck"] = f["id"]

    resolved = await _effective(_e1["api"], f["id"])
    agent_ids = [a["user_id"] for a in resolved["agents"]]
    assert _e3["id"] not in agent_ids, "Agent without keys must be filtered out"
    # No agents → source should be 'none' (empty list)
    assert resolved["agents"] == []

    # Restore e1 as org default
    await admin_client.update_escrow_settings(
        escrow_default_user_ids=[_e1["id"]],
        escrow_default_role_ids=[],
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_19_06_folder_with_no_override_inherits_org_default():
    f = await create_folder(_e1["api"], "escrow_plain_19")
    _folder["plain"] = f["id"]

    resolved = await _effective(_e1["api"], f["id"])
    assert resolved["source"] == "org_default"
    assert resolved["override_folder_id"] is None
    assert _e1["id"] in [a["user_id"] for a in resolved["agents"]]


@pytest.mark.asyncio(loop_scope="session")
async def test_19_07_deeply_nested_folder_inherits_org_default():
    """A subfolder 3 levels deep with no overrides at any level inherits org default."""
    a = await create_folder(_e1["api"], "escrow_nest_a_19")
    b = await create_folder(_e1["api"], "escrow_nest_b_19", parent_id=a["id"])
    c = await create_folder(_e1["api"], "escrow_nest_c_19", parent_id=b["id"])
    _folder["nest_c"] = c["id"]

    resolved = await _effective(_e1["api"], c["id"])
    assert resolved["source"] == "org_default"
    assert _e1["id"] in [a["user_id"] for a in resolved["agents"]]


@pytest.mark.asyncio(loop_scope="session")
async def test_19_08_replace_override_returns_only_policy_agents(admin_client: AdminClient):
    """'replace' policy on folder_d: resolved list contains e2 only; e1 absent."""
    d = await create_folder(_e1["api"], "escrow_d_19")
    _folder["d"] = d["id"]

    await admin_client.upsert_folder_escrow_policy(
        d["id"],
        override_mode="replace",
        agents=[{"user_id": _e2["id"]}],
    )

    resolved = await _effective(_e1["api"], d["id"])
    agent_ids = [a["user_id"] for a in resolved["agents"]]
    assert resolved["source"] == "folder_override"
    assert resolved["override_folder_id"] == d["id"]
    assert _e2["id"] in agent_ids
    assert _e1["id"] not in agent_ids, "escrow_user1 must be absent from a replace-only policy"


@pytest.mark.asyncio(loop_scope="session")
async def test_19_09_subfolder_inherits_parent_replace_policy(admin_client: AdminClient):
    """Subfolder of folder_d (no own policy) resolves through parent's replace policy."""
    sub = await create_folder(_e1["api"], "escrow_d_sub_19", parent_id=_folder["d"])
    _folder["d_sub"] = sub["id"]

    resolved = await _effective(_e1["api"], sub["id"])
    agent_ids = [a["user_id"] for a in resolved["agents"]]
    assert resolved["source"] == "folder_override"
    assert resolved["override_folder_id"] == _folder["d"]
    assert _e2["id"] in agent_ids
    assert _e1["id"] not in agent_ids


@pytest.mark.asyncio(loop_scope="session")
async def test_19_10_merge_policy_returns_union_of_policy_and_org_default(admin_client: AdminClient):
    """'merge' policy returns e2 (policy) + e1 (org default), no duplicates."""
    m = await create_folder(_e1["api"], "escrow_m_19")
    _folder["m"] = m["id"]

    await admin_client.upsert_folder_escrow_policy(
        m["id"],
        override_mode="merge",
        agents=[{"user_id": _e2["id"]}],
    )

    resolved = await _effective(_e1["api"], m["id"])
    agent_ids = [a["user_id"] for a in resolved["agents"]]
    assert resolved["source"] == "folder_override"
    assert _e1["id"] in agent_ids, "merge must include org default (e1)"
    assert _e2["id"] in agent_ids, "merge must include policy agent (e2)"
    assert len(agent_ids) == len(set(agent_ids)), "no duplicates"


@pytest.mark.asyncio(loop_scope="session")
async def test_19_11_none_policy_returns_empty_list(admin_client: AdminClient):
    n = await create_folder(_e1["api"], "escrow_n_19")
    _folder["n"] = n["id"]

    await admin_client.upsert_folder_escrow_policy(
        n["id"],
        override_mode="none",
        agents=[],
    )

    resolved = await _effective(_e1["api"], n["id"])
    assert resolved["source"] == "none"
    assert resolved["agents"] == []


@pytest.mark.asyncio(loop_scope="session")
async def test_19_12_subfolder_under_none_folder_also_returns_none():
    """Child of a 'none' folder inherits none — does NOT fall through to org default."""
    sub = await create_folder(_e1["api"], "escrow_n_sub_19", parent_id=_folder["n"])

    resolved = await _effective(_e1["api"], sub["id"])
    assert resolved["source"] == "none"
    assert resolved["agents"] == []


# ===========================================================================
# C. Team creation enforcement
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_13_team_without_escrow_allowed_when_coverage_not_required(
    admin_client: AdminClient,
):
    global _unprotected_team_id
    # require_coverage should still be False from test_19_01
    s = await admin_client.get_escrow_settings()
    assert s["escrow_require_coverage"] is False

    r = await _create_team(_e1["api"], "escrow_nc_team_19")
    assert r.status_code == 201
    _unprotected_team_id = r.json()["team_id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_19_14_team_without_escrow_blocked_when_coverage_required(
    admin_client: AdminClient,
):
    await admin_client.update_escrow_settings(escrow_require_coverage=True)

    r = await _create_team(_e1["api"], "escrow_cov_blocked_19")
    assert r.status_code == 422
    assert "escrow_require_coverage" in r.json().get("detail", "")


@pytest.mark.asyncio(loop_scope="session")
async def test_19_15_team_with_escrow_allowed_when_coverage_required(
    admin_client: AdminClient,
):
    global _protected_team_id
    r = await _create_team(_e1["api"], "escrow_cov_ok_19", escrow_uids=[_e1["id"]])
    assert r.status_code == 201
    _protected_team_id = r.json()["team_id"]

    # Reset require_coverage so later tests aren't affected
    await admin_client.update_escrow_settings(escrow_require_coverage=False)


# ===========================================================================
# D. Coverage report
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_16_unprotected_team_appears_in_coverage_report(admin_client: AdminClient):
    report = await admin_client.get_escrow_coverage_report()
    reported = {t["team_id"] for t in report["teams"]}
    assert _unprotected_team_id in reported


@pytest.mark.asyncio(loop_scope="session")
async def test_19_17_protected_team_absent_from_coverage_report(admin_client: AdminClient):
    report = await admin_client.get_escrow_coverage_report()
    reported = {t["team_id"] for t in report["teams"]}
    assert _protected_team_id not in reported


@pytest.mark.asyncio(loop_scope="session")
async def test_19_18_coverage_report_pagination(admin_client: AdminClient):
    # Create two extra unprotected teams so there are at least three in the report
    for i in range(2):
        r = await _create_team(_e1["api"], f"escrow_pag_{i}_19")
        assert r.status_code == 201

    full = await admin_client.get_escrow_coverage_report(limit=200, offset=0)
    total = full["total"]
    assert total >= 3

    p0 = await admin_client.get_escrow_coverage_report(limit=1, offset=0)
    p1 = await admin_client.get_escrow_coverage_report(limit=1, offset=1)
    assert len(p0["teams"]) == 1
    assert len(p1["teams"]) == 1
    assert p0["teams"][0]["team_id"] != p1["teams"][0]["team_id"]

    beyond = await admin_client.get_escrow_coverage_report(limit=10, offset=total + 100)
    assert beyond["teams"] == []


# ===========================================================================
# E. Default rotation — no automatic backfill
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_19_revoking_escrow_role_makes_team_unprotected(admin_client: AdminClient):
    """Revoking escrow_agent from e1 exposes the protected team in the coverage report.

    Coverage is checked at query time: if the user_team_keys member no longer holds
    can_act_as_escrow, the team is flagged as unprotected.
    """
    await admin_client.revoke_role(_e1["id"], "escrow_agent")

    report = await admin_client.get_escrow_coverage_report()
    reported = {t["team_id"] for t in report["teams"]}
    assert _protected_team_id in reported, (
        "Revoking escrow_agent from the only escrow member must surface the team"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_19_20_restoring_escrow_role_removes_team_from_report(admin_client: AdminClient):
    await admin_client.grant_role(_e1["id"], "escrow_agent")

    report = await admin_client.get_escrow_coverage_report()
    reported = {t["team_id"] for t in report["teams"]}
    assert _protected_team_id not in reported


@pytest.mark.asyncio(loop_scope="session")
async def test_19_21_changing_org_default_updates_new_resolutions(admin_client: AdminClient):
    """After switching org default to e2, folders with no override now resolve to e2."""
    await admin_client.update_escrow_settings(
        escrow_default_user_ids=[_e2["id"]],
        escrow_default_role_ids=[],
    )

    resolved = await _effective(_e1["api"], _folder["plain"])
    agent_ids = [a["user_id"] for a in resolved["agents"]]
    assert _e2["id"] in agent_ids
    assert _e1["id"] not in agent_ids


@pytest.mark.asyncio(loop_scope="session")
async def test_19_22_old_team_stays_covered_after_default_change(admin_client: AdminClient):
    """No automatic key rotation: old team with e1 in user_team_keys stays covered.

    Even though the org default is now e2, e1 still holds escrow_agent, so
    the coverage query finds e1 in that team's user_team_keys — team not flagged.
    """
    report = await admin_client.get_escrow_coverage_report()
    reported = {t["team_id"] for t in report["teams"]}
    assert _protected_team_id not in reported, (
        "Existing team with e1 escrow member must remain covered "
        "after org default changes to e2 — no automatic rotation on default change"
    )

    # Restore e1 as org default for remaining tests
    await admin_client.update_escrow_settings(
        escrow_default_user_ids=[_e1["id"]],
        escrow_default_role_ids=[],
    )


# ===========================================================================
# F. Access control
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_23_effective_escrow_accessible_to_folder_owner_without_admin_flag():
    """GET /folders/{id}/effective-escrow-agents is a user-facing endpoint — no admin flags needed."""
    resolved = await _effective(_e1["api"], _folder["plain"])
    assert "agents" in resolved


@pytest.mark.asyncio(loop_scope="session")
async def test_19_24_effective_escrow_returns_403_for_inaccessible_folder():
    """Calling effective-escrow-agents for a folder you don't own → 403."""
    r = await _plain["api"].get(f"/folders/{_folder['plain']}/effective-escrow-agents")
    assert r.status_code == 403


# ===========================================================================
# G. Folder policy constraints
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_25_overrides_allowed_false_blocks_child_policy_creation(
    admin_client: AdminClient,
):
    """Parent policy with overrides_allowed=False prevents child folder policies."""
    parent = await create_folder(_e1["api"], "escrow_oa_parent_19")
    child  = await create_folder(_e1["api"], "escrow_oa_child_19", parent_id=parent["id"])
    _folder["oa_parent"] = parent["id"]
    _folder["oa_child"]  = child["id"]

    await admin_client.upsert_folder_escrow_policy(
        parent["id"],
        override_mode="replace",
        overrides_allowed=False,
        agents=[{"user_id": _e1["id"]}],
    )

    # Child policy creation must be blocked
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await admin_client.upsert_folder_escrow_policy(
            child["id"],
            override_mode="replace",
            agents=[{"user_id": _e2["id"]}],
        )
    assert exc_info.value.response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_19_26_policy_locked_blocks_lower_tier_admin(admin_client: AdminClient):
    """policy_locked=True, locked_min_tier=1 blocks modification by operational_admin (tier 3)."""
    fl = await create_folder(_e1["api"], "escrow_locked_19")
    _folder["locked"] = fl["id"]

    await admin_client.upsert_folder_escrow_policy(
        fl["id"],
        override_mode="replace",
        policy_locked=True,
        locked_min_tier=1,
        agents=[{"user_id": _e1["id"]}],
    )

    op_client = AdminClient.from_session(_op_admin["session"])
    try:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await op_client.upsert_folder_escrow_policy(
                fl["id"],
                override_mode="merge",
                agents=[{"user_id": _e2["id"]}],
            )
        assert exc_info.value.response.status_code == 403
    finally:
        await op_client.aclose()


@pytest.mark.asyncio(loop_scope="session")
async def test_19_27_policy_locked_at_tier2_allows_server_admin_blocks_operational(
    admin_client: AdminClient,
):
    """Lock at tier 2: server_admin (tier 1 ≤ 2) can modify; operational_admin (tier 3) cannot."""
    ft2 = await create_folder(_e1["api"], "escrow_locked_t2_19")
    _folder["locked_t2"] = ft2["id"]

    await admin_client.upsert_folder_escrow_policy(
        ft2["id"],
        override_mode="replace",
        policy_locked=True,
        locked_min_tier=2,
        agents=[{"user_id": _e1["id"]}],
    )

    # server_admin (tier 1) can modify (1 ≤ 2)
    await admin_client.upsert_folder_escrow_policy(
        ft2["id"],
        override_mode="merge",
        policy_locked=True,
        locked_min_tier=2,
        agents=[{"user_id": _e1["id"]}],
    )

    # operational_admin (tier 3) cannot modify (3 > 2)
    op_client = AdminClient.from_session(_op_admin["session"])
    try:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await op_client.upsert_folder_escrow_policy(
                ft2["id"],
                override_mode="replace",
                agents=[{"user_id": _e2["id"]}],
            )
        assert exc_info.value.response.status_code == 403
    finally:
        await op_client.aclose()


# ===========================================================================
# H. Folder deletion cascade
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_19_28_folder_deletion_cascades_to_escrow_policy(admin_client: AdminClient):
    """Deleting a folder removes its escrow policy via ON DELETE CASCADE."""
    fd = await create_folder(_e1["api"], "escrow_del_19")
    await admin_client.upsert_folder_escrow_policy(
        fd["id"],
        override_mode="replace",
        agents=[{"user_id": _e1["id"]}],
    )

    # Confirm policy exists
    policy = await admin_client.get_folder_escrow_policy(fd["id"])
    assert policy["folder_id"] == fd["id"]

    # Delete folder
    r = await _e1["api"].delete(f"/folders/{fd['id']}")
    r.raise_for_status()

    # Policy must be gone
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await admin_client.get_folder_escrow_policy(fd["id"])
    assert exc_info.value.response.status_code == 404


# ---------------------------------------------------------------------------
# 19-29  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_19_29_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
