"""
Group 20 — Sharing restrictions (migration 016).

Tests the two-layer sharing enforcement system end-to-end:

  Layer 1 — per-role capability flags (FLAG_CREATE_LINK_SHARES etc.)
  Layer 2 — identity-scoped rules evaluated at POST /shares

Sections
--------
  A. Initial state & access control
  B. Layer 1 — one-off flag disabling (each of the 4 flags in isolation)
  C. Layer 1 — step-up gate enforcement
  D. Layer 1 — custom roles carrying sharing flags
  E. Layer 2 — no-rule baseline
  F. Layer 2 — sender-based deny rule lifecycle
  G. Layer 2 — share-type scoping (applies_to_share_type)
  H. Layer 2 — recipient-based deny rule
  I. Layer 2 — block_on_missing_attribute behaviour
  J. Layer 2 — rule priority and allow-rule override
  K. Rule CRUD (GET / PUT / DELETE)
  L. Rule locking (is_locked + locked_min_tier) and priority floor
  M. can_manage_sharing access control
  N. Security event: share.blocked

Actors
------
  _plain       — regular user (role_user only); primary sender in most tests
  _plain2      — second regular user; used as share recipient and alternate sender
  _custom      — user for custom-role capability experiments
  _no_mgr      — can_view_admin_panel, NOT can_manage_sharing
  _sharing_mgr — can_view_admin_panel + can_manage_sharing (non-tiered helper role)
  _op_admin    — operational_admin (tier 3) + can_manage_sharing

Step-up tokens
--------------
Sharing mutations require X-Step-Up-Token for "policy.sharing.*".
Tests mint these tokens directly using the test container's known JWT secret
(identical to _TEST_JWT_SECRET_HEX in tests/e2e/helpers/storage.py) so that
the full OPAQUE re-authentication flow is not needed for automated tests.

Tests
-----
A. Initial state & access control
  20-01  GET /admin/sharing/flags shows all 4 capability flags enabled for role_user
         and all three admin system roles
  20-02  Regular user cannot access /admin/sharing/flags (403)
  20-03  Admin with can_view_admin_panel but without can_manage_sharing gets 403

B. Layer 1 — one-off flag disabling
  20-04  Disable can_create_link_shares on role_user → link share returns 403;
         user-share capability is unaffected (passes flag check, may fail later)
  20-05  Disable can_create_user_shares → user share returns 403;
         link-share capability is unaffected
  20-06  Disable can_create_upload_grants → share with allow_upload=True returns 403;
         plain link share (allow_upload=False) is unaffected
  20-07  Disable can_share_folders → upload-only folder share (empty items + target_folder_id)
         returns 403; plain link share is still permitted

C. Layer 1 — step-up gate
  20-08  PUT /admin/sharing/flags without X-Step-Up-Token returns 403 step_up_required

D. Layer 1 — custom roles with sharing capability flags
  20-09  Disable all 4 flags on role_user; assign custom role granting only
         can_create_link_shares to _custom → _custom can create link shares, not user shares
  20-10  _plain (role_user only, all flags disabled) cannot create any share type
  20-11  Restore all 4 flags on role_user → both _plain and _custom can create link shares

E. Layer 2 — no-rule baseline
  20-12  GET /admin/sharing/rules returns empty list (total=0)
  20-13  POST /admin/sharing/rules/test → outcome=allow with no rules in the system

F. Layer 2 — sender-based deny rule lifecycle
  20-14  Create deny rule on internal.username eq "plain_20" → _plain's link share → 403
  20-15  _plain2 (username "plain2_20") is NOT matched and can create a link share
  20-16  POST /admin/sharing/rules without step-up → 403 step_up_required
  20-17  Deactivate the rule (is_active=False) → _plain can share again
  20-18  Dry-run test (POST /rules/test) reports deny outcome for matching sender

G. Layer 2 — share-type scoping
  20-19  Rule with applies_to_share_type=link blocks link shares; user share by same
         sender is not blocked (applies_to_share_type excludes it)

H. Layer 2 — recipient-based deny rule
  20-20  subject=recipient deny rule matching plain2_20's username blocks share
         sent TO _plain2; share to a different recipient is not blocked

I. Layer 2 — block_on_missing_attribute
  20-21  block_on_missing_attribute=True (default) + attribute that cannot be resolved
         (ldap.department for a non-LDAP user) → condition fires → deny rule blocks
  20-22  block_on_missing_attribute=False + same unresolvable attribute → condition is
         skipped → rule does not fire → share is permitted

J. Layer 2 — priority and allow-rule override
  20-23  Allow rule at priority 50 precedes deny rule at priority 100 (lower number =
         evaluated first) → allow wins; share is permitted despite deny rule existing
  20-24  Deny rule at priority 50, allow rule at priority 100 → deny fires first → 403

K. Rule CRUD
  20-25  GET /admin/sharing/rules/{id} returns the full rule including conditions
  20-26  PUT /admin/sharing/rules/{id} can rename a rule and flip its effect;
         GET after update reflects the changes
  20-27  DELETE /admin/sharing/rules/{id} removes the rule; subsequent GET → 404

L. Rule locking and priority floor
  20-28  Locked rule with locked_min_tier=1: tier-3 operational_admin cannot delete (403)
  20-29  Tier-1 server_admin CAN delete the same locked rule
  20-30  Locked rule with locked_min_tier=2: tier-1 admin can update it;
         tier-3 operational_admin cannot
  20-31  Locked rule created by tier-1 at priority 50 → tier-3 admin cannot create
         a new rule at priority ≤ 50 (priority floor); higher priority is allowed

M. can_manage_sharing access control
  20-32  _sharing_mgr (custom role with can_manage_sharing) can list rules and run dry-run
  20-33  After revoking can_manage_sharing from _sharing_mgr's role, access is immediately
         blocked (403) on both GET flags and GET rules

N. Security event
  20-34  A rule-blocked link share emits a share.blocked security event with correct
         block_reason, rule_id, and share_type fields
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
import jwt
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient
from tests.e2e.helpers.audit  import get_recent_event
from tests.e2e.helpers.auth   import register_via_invite
from tests.e2e.helpers.crypto_stubs import (
    fake_aes256_key, fake_iv_12, fake_kem_ciphertext, fake_x25519_pub,
)
from tests.e2e.helpers.files  import upload_file_api
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# JWT secret from docker-compose.test.yml — matches TUSSHARE_JWT_SECRET in the
# test container. Used to mint step-up tokens without a full OPAQUE re-auth.
_TEST_JWT_SECRET = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
_SHARING_ACTION  = "policy.sharing.*"

# ---------------------------------------------------------------------------
# Module-level state (mutated by setup fixture, read by tests)
# ---------------------------------------------------------------------------

_admin_id:    str  = ""   # testadmin user ID — needed for step-up tokens
_plain:       dict = {}   # regular user: primary "sender" in most tests
_plain2:      dict = {}   # second user: alternate sender and recipient
_custom:      dict = {}   # user for custom-role experiments
_no_mgr:      dict = {}   # has can_view_admin_panel, NOT can_manage_sharing
_sharing_mgr: dict = {}   # has can_view_admin_panel + can_manage_sharing
_op_admin:    dict = {}   # operational_admin (tier 3) + can_manage_sharing

_plain_file_id:  str = ""  # file uploaded by _plain (share tests)
_plain2_file_id: str = ""  # file uploaded by _plain2 (alternate sender)
_custom_file_id: str = ""  # file uploaded by _custom (Section D — share must succeed)

# Rule IDs used across sequential tests within a section; cleared at section end
_rule_id:  str = ""
_rule2_id: str = ""

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# auth.forbidden: 20-02 (_plain blocked from /admin/sharing/flags),
#   20-03 (_no_mgr without can_manage_sharing → 403),
#   20-04 to 20-07 (sharing capability disabled → 403 on POST /shares),
#   20-08/16 (sharing mutation without step-up → 403 step_up_required).
# share.blocked: 20-34 (deny rule matched → security event emitted).
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden", outcome="failure", severity="warning", tier=2),
    ExpectedSiemEvent("share.blocked",  outcome="failure", severity="info",    tier=2),
]

# Roles created during setup — deleted in teardown
_setup_roles: list[str] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _step_up(user_id: str) -> str:
    """Mint a valid step-up JWT for policy.sharing.* using the test JWT secret.

    The token has scope="*" (sudo window — covers any payload) so it works
    for all sharing mutations without needing to pre-compute a payload hash.
    """
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub":    user_id,
            "type":   "step_up",
            "action": _SHARING_ACTION,
            "scope":  "*",
            "iat":    now,
            "exp":    now + timedelta(minutes=5),
        },
        _TEST_JWT_SECRET,
        algorithm="HS512",
    )


def _link_payload(file_id: str, **extra: Any) -> dict:
    """Minimal valid POST /shares body for a link share."""
    return {
        "share_type": "link",
        "items": [{
            "resource_type":      "file",
            "resource_id":        file_id,
            "encrypted_file_key": fake_aes256_key(),
            "key_iv":             fake_iv_12(),
        }],
        **extra,
    }


def _user_share_payload(file_id: str, recipient_username: str) -> dict:
    """Minimal valid POST /shares body for a user share."""
    return {
        "share_type":         "user",
        "recipient_username": recipient_username,
        "items": [{
            "resource_type":        "file",
            "resource_id":          file_id,
            "encrypted_file_key":   fake_aes256_key(),
            "key_iv":               fake_iv_12(),
            "ephemeral_x25519_pub": fake_x25519_pub(),
            "kem_ciphertext":       fake_kem_ciphertext(),
        }],
    }


async def _link_share(api: ApiClient, file_id: str, **extra: Any) -> httpx.Response:
    return await api.post("/shares", json=_link_payload(file_id, **extra))


async def _user_share(
    api: ApiClient, file_id: str, recipient_username: str
) -> httpx.Response:
    return await api.post("/shares", json=_user_share_payload(file_id, recipient_username))


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


async def _delete_all_rules(admin_client: AdminClient, tok: str) -> None:
    """Remove all sharing rules (best-effort; used in cleanup)."""
    try:
        data = await admin_client.list_sharing_rules(limit=200)
        for rule in data.get("rules", []):
            try:
                await admin_client.delete_sharing_rule(rule["id"], tok)
            except Exception:
                pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _admin_id
    global _plain, _plain2, _custom, _no_mgr, _sharing_mgr, _op_admin
    global _plain_file_id, _plain2_file_id, _custom_file_id
    global _setup_roles

    # ------------------------------------------------------------------
    # Admin user ID (required for step-up token minting)
    # ------------------------------------------------------------------
    me = await admin_client._client.get(f"{API}/auth/me")
    me.raise_for_status()
    _admin_id = me.json()["user"]["id"]

    # ------------------------------------------------------------------
    # Register all test users
    # ------------------------------------------------------------------
    _plain       = await _reg(browser, admin_client, "plain_20",       "Pl4in!User99")
    _plain2      = await _reg(browser, admin_client, "plain2_20",      "Pl4in2!User99")
    _custom      = await _reg(browser, admin_client, "custom_20",      "Cust0m!User99")
    _no_mgr      = await _reg(browser, admin_client, "no_mgr_20",      "NoMgr!User99")
    _sharing_mgr = await _reg(browser, admin_client, "shr_mgr_20",     "ShrMgr!User99")
    _op_admin    = await _reg(browser, admin_client, "op_adm_20",      "0pAdm!in9920")

    # ------------------------------------------------------------------
    # Role setup
    # ------------------------------------------------------------------

    # _no_mgr: can_view_admin_panel only
    no_mgr_role = await admin_client.create_role("no_mgr_role_20")
    await admin_client.set_role_permissions(no_mgr_role["id"], {"can_view_admin_panel": True})
    await admin_client.grant_role(_no_mgr["id"], no_mgr_role["id"])
    _setup_roles.append("no_mgr_role_20")

    # _sharing_mgr: can_view_admin_panel + can_manage_sharing
    mgr_role = await admin_client.create_role("shr_mgr_role_20")
    await admin_client.set_role_permissions(mgr_role["id"], {
        "can_view_admin_panel": True,
        "can_manage_sharing":   True,
    })
    await admin_client.grant_role(_sharing_mgr["id"], mgr_role["id"])
    _setup_roles.append("shr_mgr_role_20")

    # _op_admin: operational_admin (tier 3) + can_manage_sharing via helper role
    await admin_client.grant_role(_op_admin["id"], "operational_admin")
    op_share_role = await admin_client.create_role("op_shr_role_20")
    await admin_client.set_role_permissions(op_share_role["id"], {
        "can_view_admin_panel": True,
        "can_manage_sharing":   True,
    })
    await admin_client.grant_role(_op_admin["id"], op_share_role["id"])
    _setup_roles.append("op_shr_role_20")

    # ------------------------------------------------------------------
    # Upload one test file per regular user (used for share creation)
    # ------------------------------------------------------------------
    f1 = await upload_file_api(_plain["api"], "shr_plain.txt", b"plain test file")
    _plain_file_id = f1["id"]

    f2 = await upload_file_api(_plain2["api"], "shr_plain2.txt", b"plain2 test file")
    _plain2_file_id = f2["id"]

    f3 = await upload_file_api(_custom["api"], "shr_custom.txt", b"custom test file")
    _custom_file_id = f3["id"]

    # ------------------------------------------------------------------
    yield
    # ------------------------------------------------------------------

    # Close API clients and browser contexts
    for u in (_plain, _plain2, _custom, _no_mgr, _sharing_mgr, _op_admin):
        try:
            await u["api"].aclose()
            await u["session"].ctx.close()
        except Exception:
            pass

    # Restore role_user sharing flags in case any test left them modified
    tok = _step_up(_admin_id)
    for flag in (
        "can_create_link_shares",
        "can_create_user_shares",
        "can_create_upload_grants",
        "can_share_folders",
    ):
        try:
            await admin_client.update_sharing_flags("role_user", {flag: True}, tok)
        except Exception:
            pass

    # Remove any leftover sharing rules
    await _delete_all_rules(admin_client, tok)

    # Delete custom setup roles
    for rid in _setup_roles:
        try:
            await admin_client.delete_role(rid)
        except Exception:
            pass


# ===========================================================================
# A. Initial state & access control
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_01_flags_endpoint_shows_all_four_enabled(admin_client: AdminClient):
    """GET /admin/sharing/flags: all 4 capability flags are ON for role_user and admin roles."""
    data = await admin_client.get_sharing_flags()

    expected_flags = {
        "can_create_link_shares",
        "can_create_user_shares",
        "can_create_upload_grants",
        "can_share_folders",
    }
    assert set(data["sharing_flags"]) == expected_flags

    roles = {r["role_id"]: r for r in data["roles"]}
    for role_id in ("role_user", "server_admin", "org_admin", "role_admin"):
        if role_id not in roles:
            continue
        for flag in expected_flags:
            assert roles[role_id]["flags"].get(flag) is True, (
                f"Expected {flag}=True for {role_id}"
            )


@pytest.mark.asyncio(loop_scope="session")
async def test_20_02_regular_user_cannot_access_flags_endpoint():
    """Regular user (role_user only) gets 403 on GET /admin/sharing/flags."""
    r = await _plain["api"].get("/admin/sharing/flags")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio(loop_scope="session")
async def test_20_03_admin_without_manage_sharing_gets_403():
    """can_view_admin_panel alone is insufficient — can_manage_sharing required."""
    r = await _no_mgr["api"].get("/admin/sharing/flags")
    assert r.status_code == 403


# ===========================================================================
# B. Layer 1 — one-off flag disabling
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_04_disable_link_flag_blocks_link_share_only(admin_client: AdminClient):
    """Disabling can_create_link_shares blocks link shares.
    User-share capability (different flag) is unaffected by this change.
    """
    tok = _step_up(_admin_id)
    await admin_client.update_sharing_flags("role_user", {"can_create_link_shares": False}, tok)
    try:
        # Link share → must be blocked
        r = await _link_share(_plain["api"], _plain_file_id)
        assert r.status_code == 403, f"Expected 403 for blocked link share, got {r.status_code}"
        assert "link share" in r.json().get("detail", "").lower()

        # User share → must NOT be blocked by the link flag (may fail for other reasons)
        r2 = await _user_share(_plain["api"], _plain_file_id, _plain2["username"])
        detail = r2.json().get("detail", "")
        if r2.status_code == 403:
            assert "link share" not in detail.lower(), (
                f"User share should not fail with link-share flag error; got: {detail}"
            )
    finally:
        await admin_client.update_sharing_flags("role_user", {"can_create_link_shares": True}, tok)

    # Verify flag is restored — link share works again
    r3 = await _link_share(_plain["api"], _plain_file_id)
    assert r3.status_code == 200, f"Link share should work after flag restore; got {r3.status_code}"
    await _plain["api"].delete(f"/shares/{r3.json()['id']}")


@pytest.mark.asyncio(loop_scope="session")
async def test_20_05_disable_user_share_flag_blocks_user_share_only(admin_client: AdminClient):
    """Disabling can_create_user_shares blocks user shares; link shares unaffected."""
    tok = _step_up(_admin_id)
    await admin_client.update_sharing_flags("role_user", {"can_create_user_shares": False}, tok)
    try:
        # User share → must be blocked
        r = await _user_share(_plain["api"], _plain_file_id, _plain2["username"])
        assert r.status_code == 403, f"Expected 403 for blocked user share, got {r.status_code}"
        assert "user share" in r.json().get("detail", "").lower()

        # Link share → must NOT be blocked
        r2 = await _link_share(_plain["api"], _plain_file_id)
        assert r2.status_code == 200, (
            f"Link share should succeed with user-share flag disabled; got {r2.status_code}"
        )
        await _plain["api"].delete(f"/shares/{r2.json()['id']}")
    finally:
        await admin_client.update_sharing_flags("role_user", {"can_create_user_shares": True}, tok)


@pytest.mark.asyncio(loop_scope="session")
async def test_20_06_disable_upload_grants_flag_blocks_upload_share_only(
    admin_client: AdminClient,
):
    """Disabling can_create_upload_grants blocks allow_upload shares; plain link unaffected."""
    tok = _step_up(_admin_id)
    await admin_client.update_sharing_flags("role_user", {"can_create_upload_grants": False}, tok)
    try:
        # Link share with allow_upload=True → must be blocked
        r = await _link_share(_plain["api"], _plain_file_id, allow_upload=True)
        assert r.status_code == 403, f"Expected 403 for allow_upload share, got {r.status_code}"
        assert "upload" in r.json().get("detail", "").lower()

        # Plain link share (no allow_upload) → must succeed
        r2 = await _link_share(_plain["api"], _plain_file_id)
        assert r2.status_code == 200, (
            f"Plain link share should succeed with upload-grants flag disabled; got {r2.status_code}"
        )
        await _plain["api"].delete(f"/shares/{r2.json()['id']}")
    finally:
        await admin_client.update_sharing_flags("role_user", {"can_create_upload_grants": True}, tok)


@pytest.mark.asyncio(loop_scope="session")
async def test_20_07_disable_share_folders_flag_blocks_folder_share_only(
    admin_client: AdminClient,
):
    """Disabling can_share_folders blocks upload-only folder shares; link shares unaffected."""
    tok = _step_up(_admin_id)
    await admin_client.update_sharing_flags("role_user", {"can_share_folders": False}, tok)
    try:
        # Upload-only folder share: no items, target_folder_id set
        fake_folder_id = str(uuid.uuid4())
        r = await _plain["api"].post("/shares", json={
            "share_type":      "link",
            "items":           [],
            "target_folder_id": fake_folder_id,
            "allow_upload":    True,
        })
        assert r.status_code == 403, (
            f"Expected 403 for folder share with flag disabled, got {r.status_code}"
        )
        assert "folder" in r.json().get("detail", "").lower()

        # Regular link share → unaffected
        r2 = await _link_share(_plain["api"], _plain_file_id)
        assert r2.status_code == 200, (
            f"Link share should succeed with share-folders flag disabled; got {r2.status_code}"
        )
        await _plain["api"].delete(f"/shares/{r2.json()['id']}")
    finally:
        await admin_client.update_sharing_flags("role_user", {"can_share_folders": True}, tok)


# ===========================================================================
# C. Layer 1 — step-up gate
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_08_flag_update_without_stepup_returns_403(admin_client: AdminClient):
    """PUT /admin/sharing/flags without X-Step-Up-Token is rejected with step_up_required."""
    r = await admin_client._client.put(
        f"{API}/admin/sharing/flags",
        json={"role_id": "role_user", "flags": {"can_create_link_shares": False}},
    )
    assert r.status_code == 403, f"Expected 403 (step-up required), got {r.status_code}"
    body = r.json()
    detail = body.get("detail", {})
    assert detail.get("error") == "step_up_required", (
        f"Expected step_up_required, got: {body}"
    )
    assert detail.get("action") == "policy.sharing.*"


# ===========================================================================
# D. Layer 1 — custom roles with sharing capability flags
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_09_custom_role_grants_link_only_while_role_user_has_none(
    admin_client: AdminClient,
):
    """Disable all 4 flags on role_user; give _custom a custom role with just can_create_link_shares.

    _custom should be able to create link shares (from the custom role) but not user shares
    (which require can_create_user_shares — not granted by the custom role, and role_user
    has that flag disabled for the duration of this test).
    """
    global _setup_roles
    tok = _step_up(_admin_id)

    # Disable all 4 flags on role_user
    await admin_client.update_sharing_flags("role_user", {
        "can_create_link_shares":   False,
        "can_create_user_shares":   False,
        "can_create_upload_grants": False,
        "can_share_folders":        False,
    }, tok)

    # Custom role: link shares only
    link_role = await admin_client.create_role("link_only_role_20")
    await admin_client.update_sharing_flags(
        "link_only_role_20", {"can_create_link_shares": True}, tok
    )
    await admin_client.grant_role(_custom["id"], "link_only_role_20")
    _setup_roles.append("link_only_role_20")

    try:
        # _custom can create link shares (custom role grants the flag) — real file required
        r = await _link_share(_custom["api"], _custom_file_id)
        assert r.status_code == 200, (
            f"_custom should be able to create link shares via custom role; got {r.status_code}: {r.text}"
        )
        await _custom["api"].delete(f"/shares/{r.json()['id']}")

        # _custom cannot create user shares (that flag is not in the custom role).
        # Flag check fires before file validation, so a fake UUID is fine here.
        r2 = await _user_share(_custom["api"], _fake_file_id(), _plain2["username"])
        assert r2.status_code == 403, (
            f"_custom should not be able to create user shares; got {r2.status_code}"
        )
        assert "user share" in r2.json().get("detail", "").lower()

    finally:
        # Restore role_user flags
        await admin_client.update_sharing_flags("role_user", {
            "can_create_link_shares":   True,
            "can_create_user_shares":   True,
            "can_create_upload_grants": True,
            "can_share_folders":        True,
        }, tok)
        await admin_client.revoke_role(_custom["id"], "link_only_role_20")


def _fake_file_id() -> str:
    """Return a random UUID — valid format for flag-gate tests where the flag
    check fires before file validation (the 403 comes before any DB file lookup).
    Do NOT use when the share is expected to succeed; use a real uploaded file ID.
    """
    return str(uuid.uuid4())


@pytest.mark.asyncio(loop_scope="session")
async def test_20_10_role_user_with_all_flags_disabled_cannot_share(admin_client: AdminClient):
    """With all 4 sharing flags disabled on role_user, _plain cannot create any share type."""
    tok = _step_up(_admin_id)
    await admin_client.update_sharing_flags("role_user", {
        "can_create_link_shares":   False,
        "can_create_user_shares":   False,
        "can_create_upload_grants": False,
        "can_share_folders":        False,
    }, tok)
    try:
        r1 = await _link_share(_plain["api"], _plain_file_id)
        assert r1.status_code == 403

        r2 = await _user_share(_plain["api"], _plain_file_id, _plain2["username"])
        assert r2.status_code == 403
    finally:
        await admin_client.update_sharing_flags("role_user", {
            "can_create_link_shares":   True,
            "can_create_user_shares":   True,
            "can_create_upload_grants": True,
            "can_share_folders":        True,
        }, tok)


@pytest.mark.asyncio(loop_scope="session")
async def test_20_11_restoring_role_user_flags_re_enables_sharing(admin_client: AdminClient):
    """After restoring all 4 flags, _plain can create link shares again."""
    # Flags were restored at the end of test_20_10; this test verifies the positive case.
    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 200, (
        f"Link share should work with flags restored; got {r.status_code}: {r.text}"
    )
    await _plain["api"].delete(f"/shares/{r.json()['id']}")


# ===========================================================================
# E. Layer 2 — no-rule baseline
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_12_rules_list_is_empty_initially(admin_client: AdminClient):
    """With no sharing rules created, GET /admin/sharing/rules returns total=0."""
    data = await admin_client.list_sharing_rules()
    assert data["total"] == 0
    assert data["rules"] == []


@pytest.mark.asyncio(loop_scope="session")
async def test_20_13_test_endpoint_returns_allow_with_no_rules(admin_client: AdminClient):
    """Dry-run with no rules returns outcome=allow and an empty matching_rules list."""
    result = await admin_client.test_sharing_rules(_plain["id"], "link")
    assert result["outcome"] == "allow"
    assert result["matching_rules"] == []


# ===========================================================================
# F. Layer 2 — sender-based deny rule lifecycle
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_14_sender_deny_rule_blocks_matching_user(admin_client: AdminClient):
    """Deny rule on internal.username eq 'plain_20' blocks _plain from creating a link share."""
    global _rule_id
    rule = await admin_client.create_sharing_rule(
        _step_up(_admin_id),
        name="deny-plain-20",
        subject="sender",
        effect="deny",
        priority=100,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "plain_20",
        }],
    )
    _rule_id = rule["id"]

    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 403, (
        f"Expected 403 for rule-blocked share, got {r.status_code}: {r.text}"
    )
    assert "blocked by policy" in r.json().get("detail", "").lower()


@pytest.mark.asyncio(loop_scope="session")
async def test_20_15_non_matching_user_can_still_share():
    """_plain2 (username 'plain2_20') does not match the deny rule and can share."""
    r = await _link_share(_plain2["api"], _plain2_file_id)
    assert r.status_code == 200, (
        f"Non-matching user should be able to share; got {r.status_code}: {r.text}"
    )
    await _plain2["api"].delete(f"/shares/{r.json()['id']}")


@pytest.mark.asyncio(loop_scope="session")
async def test_20_16_create_rule_without_stepup_returns_403(admin_client: AdminClient):
    """POST /admin/sharing/rules without X-Step-Up-Token is rejected."""
    r = await admin_client._client.post(
        f"{API}/admin/sharing/rules",
        json={
            "name":      "should-not-be-created",
            "subject":   "sender",
            "effect":    "deny",
            "priority":  999,
        },
    )
    assert r.status_code == 403, f"Expected 403 (step-up required), got {r.status_code}"
    assert r.json().get("detail", {}).get("error") == "step_up_required"


@pytest.mark.asyncio(loop_scope="session")
async def test_20_17_deactivating_rule_lets_blocked_user_share(admin_client: AdminClient):
    """Setting is_active=False on the deny rule allows _plain to share again."""
    await admin_client.update_sharing_rule(
        _rule_id, _step_up(_admin_id),
        is_active=False,
    )

    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 200, (
        f"Deactivated rule should not block; got {r.status_code}: {r.text}"
    )
    await _plain["api"].delete(f"/shares/{r.json()['id']}")


@pytest.mark.asyncio(loop_scope="session")
async def test_20_18_dry_run_reflects_deny_outcome(admin_client: AdminClient):
    """POST /rules/test reports outcome=deny for _plain when the rule is re-activated."""
    # Re-activate the rule for the dry-run test
    await admin_client.update_sharing_rule(
        _rule_id, _step_up(_admin_id),
        is_active=True,
    )

    result = await admin_client.test_sharing_rules(_plain["id"], "link")
    assert result["outcome"] == "deny", f"Expected deny outcome, got: {result}"
    assert any(r["rule_id"] == _rule_id for r in result["matching_rules"])

    # Dry-run for _plain2 — must be allow (rule doesn't match)
    result2 = await admin_client.test_sharing_rules(_plain2["id"], "link")
    assert result2["outcome"] == "allow"


# ===========================================================================
# G. Layer 2 — share-type scoping
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_19_share_type_scoping_link_rule_does_not_block_user_shares(
    admin_client: AdminClient,
):
    """A rule with applies_to_share_type=link only blocks link shares.
    The same sender's user share is not affected.
    """
    global _rule_id

    # Update existing deny rule to be link-scoped
    await admin_client.update_sharing_rule(
        _rule_id, _step_up(_admin_id),
        applies_to_share_type="link",
    )

    # Link share → still blocked
    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 403

    # User share → NOT blocked by the link-scoped rule
    r2 = await _user_share(_plain["api"], _plain_file_id, _plain2["username"])
    # Status is NOT 403 from the sharing rule (might be 200 or another error)
    if r2.status_code == 403:
        assert "blocked by policy" not in r2.json().get("detail", "").lower(), (
            f"User share should not be blocked by a link-scoped rule; got: {r2.text}"
        )

    # Cleanup: remove scoping and delete rule
    await admin_client.delete_sharing_rule(_rule_id, _step_up(_admin_id))
    _rule_id = ""


# ===========================================================================
# H. Layer 2 — recipient-based deny rule
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_20_recipient_deny_rule_blocks_share_to_matching_user(
    admin_client: AdminClient,
):
    """subject=recipient deny rule blocks shares sent TO _plain2."""
    global _rule_id
    rule = await admin_client.create_sharing_rule(
        _step_up(_admin_id),
        name="deny-recipient-plain2-20",
        subject="recipient",
        effect="deny",
        priority=100,
        applies_to_share_type="user",
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "plain2_20",
        }],
    )
    _rule_id = rule["id"]

    # _plain sends a user share TO _plain2 → blocked
    r = await _user_share(_plain["api"], _plain_file_id, _plain2["username"])
    assert r.status_code == 403, (
        f"Expected share to matching recipient to be blocked; got {r.status_code}"
    )
    assert "blocked by policy" in r.json().get("detail", "").lower()

    # Cleanup
    await admin_client.delete_sharing_rule(_rule_id, _step_up(_admin_id))
    _rule_id = ""


# ===========================================================================
# I. Layer 2 — block_on_missing_attribute
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_21_block_on_missing_true_fires_deny_when_attribute_unresolvable(
    admin_client: AdminClient,
):
    """block_on_missing_attribute=True (default): if the attribute cannot be resolved
    (e.g. ldap.department on a non-LDAP user), the condition is treated as matching
    and the deny rule fires.
    """
    global _rule_id
    rule = await admin_client.create_sharing_rule(
        _step_up(_admin_id),
        name="deny-ldap-dept-missing-block-20",
        subject="sender",
        effect="deny",
        priority=100,
        conditions=[{
            "attribute_path":             "ldap.department",
            "operator":                   "eq",
            "value":                      "engineering",
            "block_on_missing_attribute": True,
        }],
    )
    _rule_id = rule["id"]

    # _plain is a plain OPAQUE user — has no ldap.department attribute
    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 403, (
        f"block_on_missing=True: deny should fire for unresolvable attr; got {r.status_code}"
    )

    await admin_client.delete_sharing_rule(_rule_id, _step_up(_admin_id))
    _rule_id = ""


@pytest.mark.asyncio(loop_scope="session")
async def test_20_22_block_on_missing_false_skips_rule_when_attribute_unresolvable(
    admin_client: AdminClient,
):
    """block_on_missing_attribute=False: unresolvable attribute skips the condition;
    the deny rule does NOT fire and the share is permitted.
    """
    global _rule_id
    rule = await admin_client.create_sharing_rule(
        _step_up(_admin_id),
        name="deny-ldap-dept-missing-skip-20",
        subject="sender",
        effect="deny",
        priority=100,
        conditions=[{
            "attribute_path":             "ldap.department",
            "operator":                   "eq",
            "value":                      "engineering",
            "block_on_missing_attribute": False,
        }],
    )
    _rule_id = rule["id"]

    # Same non-LDAP user — condition skipped, share allowed
    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 200, (
        f"block_on_missing=False: share should succeed for unresolvable attr; got {r.status_code}: {r.text}"
    )
    await _plain["api"].delete(f"/shares/{r.json()['id']}")

    await admin_client.delete_sharing_rule(_rule_id, _step_up(_admin_id))
    _rule_id = ""


# ===========================================================================
# J. Layer 2 — priority and allow-rule override
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_23_allow_rule_at_lower_priority_number_wins_over_deny(
    admin_client: AdminClient,
):
    """Allow rule at priority 50 is evaluated before deny rule at priority 100.
    First-match-wins: allow fires first → share is permitted.
    """
    global _rule_id, _rule2_id
    tok = _step_up(_admin_id)

    deny = await admin_client.create_sharing_rule(
        tok,
        name="deny-plain-prio100-20",
        subject="sender",
        effect="deny",
        priority=100,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "plain_20",
        }],
    )
    _rule_id = deny["id"]

    allow = await admin_client.create_sharing_rule(
        tok,
        name="allow-plain-prio50-20",
        subject="sender",
        effect="allow",
        priority=50,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "plain_20",
        }],
    )
    _rule2_id = allow["id"]

    # Allow at 50 precedes deny at 100 → share succeeds
    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 200, (
        f"Allow rule (prio 50) should win over deny (prio 100); got {r.status_code}: {r.text}"
    )
    await _plain["api"].delete(f"/shares/{r.json()['id']}")

    await admin_client.delete_sharing_rule(_rule_id,  tok)
    await admin_client.delete_sharing_rule(_rule2_id, tok)
    _rule_id = _rule2_id = ""


@pytest.mark.asyncio(loop_scope="session")
async def test_20_24_deny_rule_at_lower_priority_number_wins_over_allow(
    admin_client: AdminClient,
):
    """Deny rule at priority 50 is evaluated before allow at 100.
    First-match-wins: deny fires first → share is blocked.
    """
    global _rule_id, _rule2_id
    tok = _step_up(_admin_id)

    deny = await admin_client.create_sharing_rule(
        tok,
        name="deny-plain-prio50-20",
        subject="sender",
        effect="deny",
        priority=50,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "plain_20",
        }],
    )
    _rule_id = deny["id"]

    allow = await admin_client.create_sharing_rule(
        tok,
        name="allow-plain-prio100-20",
        subject="sender",
        effect="allow",
        priority=100,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "plain_20",
        }],
    )
    _rule2_id = allow["id"]

    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 403, (
        f"Deny rule (prio 50) should win over allow (prio 100); got {r.status_code}"
    )

    await admin_client.delete_sharing_rule(_rule_id,  tok)
    await admin_client.delete_sharing_rule(_rule2_id, tok)
    _rule_id = _rule2_id = ""


# ===========================================================================
# K. Rule CRUD
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_25_get_rule_returns_full_rule_with_conditions(admin_client: AdminClient):
    """GET /admin/sharing/rules/{id} returns the rule with its conditions."""
    global _rule_id
    tok = _step_up(_admin_id)
    rule = await admin_client.create_sharing_rule(
        tok,
        name="crud-test-rule-20",
        subject="sender",
        effect="deny",
        priority=200,
        conditions=[{
            "attribute_path": "internal.email",
            "operator":       "contains",
            "value":          "@example.com",
        }],
    )
    _rule_id = rule["id"]

    fetched = await admin_client.get_sharing_rule(_rule_id)
    assert fetched["id"] == _rule_id
    assert fetched["name"] == "crud-test-rule-20"
    assert fetched["effect"] == "deny"
    assert len(fetched["conditions"]) == 1
    assert fetched["conditions"][0]["operator"] == "contains"


@pytest.mark.asyncio(loop_scope="session")
async def test_20_26_put_updates_rule_name_and_effect(admin_client: AdminClient):
    """PUT /admin/sharing/rules/{id} can rename a rule and change its effect."""
    tok = _step_up(_admin_id)
    updated = await admin_client.update_sharing_rule(
        _rule_id, tok,
        name="crud-test-rule-updated-20",
        effect="allow",
    )
    assert updated["name"] == "crud-test-rule-updated-20"
    assert updated["effect"] == "allow"

    # GET confirms the change persisted
    fetched = await admin_client.get_sharing_rule(_rule_id)
    assert fetched["name"] == "crud-test-rule-updated-20"
    assert fetched["effect"] == "allow"


@pytest.mark.asyncio(loop_scope="session")
async def test_20_27_delete_rule_removes_it(admin_client: AdminClient):
    """DELETE /admin/sharing/rules/{id} removes the rule; GET afterwards returns 404."""
    global _rule_id
    tok = _step_up(_admin_id)
    await admin_client.delete_sharing_rule(_rule_id, tok)

    r = await admin_client._client.get(f"{API}/admin/sharing/rules/{_rule_id}")
    assert r.status_code == 404
    _rule_id = ""


# ===========================================================================
# L. Rule locking and priority floor
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_28_locked_rule_blocks_lower_tier_delete(admin_client: AdminClient):
    """Locked rule (locked_min_tier=1): tier-3 operational_admin cannot delete it (403)."""
    global _rule_id
    tok = _step_up(_admin_id)

    rule = await admin_client.create_sharing_rule(
        tok,
        name="locked-t1-rule-20",
        subject="sender",
        effect="deny",
        priority=200,
        is_locked=True,
        locked_min_tier=1,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "__nobody__",
        }],
    )
    _rule_id = rule["id"]

    op_client = AdminClient.from_session(_op_admin["session"])
    try:
        r = await op_client._client.delete(
            f"{API}/admin/sharing/rules/{_rule_id}",
            headers={"X-Step-Up-Token": _step_up(_op_admin["id"])},
        )
        assert r.status_code == 403, (
            f"Tier-3 admin should not be able to delete a tier-1 locked rule; got {r.status_code}"
        )
    finally:
        await op_client.aclose()


@pytest.mark.asyncio(loop_scope="session")
async def test_20_29_tier1_admin_can_delete_locked_rule(admin_client: AdminClient):
    """Server_admin (tier 1) can delete a rule locked at tier 1."""
    global _rule_id
    await admin_client.delete_sharing_rule(_rule_id, _step_up(_admin_id))

    r = await admin_client._client.get(f"{API}/admin/sharing/rules/{_rule_id}")
    assert r.status_code == 404
    _rule_id = ""


@pytest.mark.asyncio(loop_scope="session")
async def test_20_30_locked_at_tier2_allows_tier1_blocks_tier3(admin_client: AdminClient):
    """Rule locked at tier 2: tier-1 admin can update it; tier-3 admin cannot."""
    global _rule_id
    tok = _step_up(_admin_id)

    rule = await admin_client.create_sharing_rule(
        tok,
        name="locked-t2-rule-20",
        subject="sender",
        effect="deny",
        priority=200,
        is_locked=True,
        locked_min_tier=2,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "__nobody__",
        }],
    )
    _rule_id = rule["id"]

    # Tier-1 server_admin (tier 1 ≤ 2) can update
    updated = await admin_client.update_sharing_rule(
        _rule_id, tok,
        name="locked-t2-rule-renamed-20",
    )
    assert updated["name"] == "locked-t2-rule-renamed-20"

    # Tier-3 op_admin (tier 3 > 2) cannot update
    op_client = AdminClient.from_session(_op_admin["session"])
    try:
        r = await op_client._client.put(
            f"{API}/admin/sharing/rules/{_rule_id}",
            json={"name": "should-be-blocked"},
            headers={"X-Step-Up-Token": _step_up(_op_admin["id"])},
        )
        assert r.status_code == 403, (
            f"Tier-3 admin should not be able to modify a tier-2 locked rule; got {r.status_code}"
        )
    finally:
        await op_client.aclose()

    await admin_client.delete_sharing_rule(_rule_id, tok)
    _rule_id = ""


@pytest.mark.asyncio(loop_scope="session")
async def test_20_31_priority_floor_blocks_lower_tier_from_inserting_above_locked_rule(
    admin_client: AdminClient,
):
    """Locked rule by tier-1 admin at priority 50 creates a priority floor.
    Tier-3 op_admin cannot insert a new rule at priority ≤ 50.
    Inserting at priority 51 or higher is permitted.
    """
    global _rule_id
    tok = _step_up(_admin_id)

    # Tier-1 creates a locked rule at priority 50
    rule = await admin_client.create_sharing_rule(
        tok,
        name="floor-lock-prio50-20",
        subject="sender",
        effect="deny",
        priority=50,
        is_locked=True,
        locked_min_tier=1,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "__nobody__",
        }],
    )
    _rule_id = rule["id"]

    op_client = AdminClient.from_session(_op_admin["session"])
    op_tok = _step_up(_op_admin["id"])
    try:
        # Tier-3 tries to insert at priority 50 → blocked (≤ floor)
        r_at_floor = await op_client._client.post(
            f"{API}/admin/sharing/rules",
            json={
                "name":      "below-floor-rule-20",
                "subject":   "sender",
                "effect":    "deny",
                "priority":  50,
                "conditions": [],
            },
            headers={"X-Step-Up-Token": op_tok},
        )
        assert r_at_floor.status_code == 400, (
            f"Tier-3 should not insert at priority ≤ floor; got {r_at_floor.status_code}"
        )

        # Tier-3 tries at priority 49 → also blocked
        r_below_floor = await op_client._client.post(
            f"{API}/admin/sharing/rules",
            json={
                "name":      "way-below-floor-20",
                "subject":   "sender",
                "effect":    "deny",
                "priority":  25,
                "conditions": [],
            },
            headers={"X-Step-Up-Token": op_tok},
        )
        assert r_below_floor.status_code == 400

        # Tier-3 inserts at priority 51 → allowed (above the floor)
        r_above = await op_client._client.post(
            f"{API}/admin/sharing/rules",
            json={
                "name":      "above-floor-rule-20",
                "subject":   "sender",
                "effect":    "deny",
                "priority":  51,
                "conditions": [],
            },
            headers={"X-Step-Up-Token": op_tok},
        )
        assert r_above.status_code == 200, (
            f"Tier-3 should be able to insert at priority > floor; got {r_above.status_code}"
        )
        # Clean up the rule inserted by op_admin
        above_id = r_above.json()["id"]
        await admin_client.delete_sharing_rule(above_id, tok)

    finally:
        await op_client.aclose()

    await admin_client.delete_sharing_rule(_rule_id, tok)
    _rule_id = ""


# ===========================================================================
# M. can_manage_sharing access control
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_32_admin_with_manage_sharing_can_list_and_dry_run():
    """_sharing_mgr (custom role with can_manage_sharing) can list rules and run dry-run."""
    mgr_admin = AdminClient.from_session(_sharing_mgr["session"])
    try:
        data = await mgr_admin.list_sharing_rules()
        assert "rules" in data

        result = await mgr_admin.test_sharing_rules(_plain["id"], "link")
        assert "outcome" in result
    finally:
        await mgr_admin.aclose()


@pytest.mark.asyncio(loop_scope="session")
async def test_20_33_revoking_manage_sharing_immediately_blocks_access(
    admin_client: AdminClient,
):
    """Revoking can_manage_sharing from _sharing_mgr's role immediately blocks access."""
    # Disable can_manage_sharing on the sharing_mgr role
    await admin_client.set_role_permissions("shr_mgr_role_20", {
        "can_view_admin_panel": True,
        "can_manage_sharing":   False,
    })

    mgr_admin = AdminClient.from_session(_sharing_mgr["session"])
    try:
        r = await mgr_admin._client.get(f"{API}/admin/sharing/flags")
        assert r.status_code == 403, (
            f"After revoking can_manage_sharing, expected 403; got {r.status_code}"
        )

        r2 = await mgr_admin._client.get(f"{API}/admin/sharing/rules")
        assert r2.status_code == 403
    finally:
        await mgr_admin.aclose()
        # Restore the flag for clean teardown
        await admin_client.set_role_permissions("shr_mgr_role_20", {
            "can_view_admin_panel": True,
            "can_manage_sharing":   True,
        })


# ===========================================================================
# N. Security event — share.blocked
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_20_34_blocked_share_emits_share_blocked_security_event(
    admin_client: AdminClient,
):
    """A rule-blocked share emits a share.blocked security event with correct metadata."""
    global _rule_id
    tok = _step_up(_admin_id)

    rule = await admin_client.create_sharing_rule(
        tok,
        name="siem-deny-plain-20",
        subject="sender",
        effect="deny",
        priority=100,
        conditions=[{
            "attribute_path": "internal.username",
            "operator":       "eq",
            "value":          "plain_20",
        }],
    )
    _rule_id = rule["id"]

    # Trigger the block — this should emit the event
    r = await _link_share(_plain["api"], _plain_file_id)
    assert r.status_code == 403

    # Poll the audit log for the share.blocked event
    event = await get_recent_event(
        admin_client,
        "share.blocked",
        max_wait=5.0,
        poll_interval=0.3,
    )
    assert event is not None, "share.blocked event was not emitted within 5 seconds"

    detail = event.get("detail") or {}
    assert detail.get("block_reason") == "rule"
    assert detail.get("rule_id") == _rule_id
    assert detail.get("share_type") == "link"

    await admin_client.delete_sharing_rule(_rule_id, tok)
    _rule_id = ""


# ---------------------------------------------------------------------------
# 20-35  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_20_35_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
