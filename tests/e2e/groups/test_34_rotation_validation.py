"""
Group 34 — Team key rotation input validation.

Tests cover server-side guards added in the A1 security fix:
  • Completeness check: rotation must cover ALL current members (C1 finding)
  • Escrow coverage: rotation must include an escrow agent when
    escrow_require_coverage is enabled (part of same fix)

Note on crypto: a successful rotation requires valid BLS12-381 scalar
multiplication (rk consistency pairing + per-file DLEQ proofs), which
cannot be reproduced with stub values.  Tests here therefore target the
error paths that fire *before* BLS verification.

Tests
-----
34-01  Rotation omitting a current member returns 422
34-02  Rotation omitting the requesting user returns 422
34-03  Rotation including a non-member user returns 422
34-04  require_coverage=True: rotation missing escrow agent returns 422
"""

from __future__ import annotations

import httpx
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin        import AdminClient, ApiClient
from tests.e2e.helpers.auth         import register_via_invite
from tests.e2e.helpers.crypto_stubs import (
    fake_g1_point, fake_g2_point, fake_kem_bundle,
)
from tests.e2e.helpers.teams        import create_team, add_member, list_members

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_owner:   dict = {}   # creates teams, initiates rotations
_member:  dict = {}   # second team member — must be included in rotations
_escrow:  dict = {}   # user with escrow_agent role (for test 34-04)

_team_two_member: dict = {}   # team with owner + member (tests 34-01)
_team_owner_only: dict = {}   # team with owner only (tests 34-02, 34-04)


def _rotation_payload(member_user_ids: list[str]) -> dict:
    """Build a structurally-valid RotateKeysRequest with stub crypto.

    Stub G1/G2 points are not valid curve points — BLS verification will
    reject them.  The goal here is to trigger validation errors that run
    *before* the pairing check (member completeness, escrow coverage).
    """
    return {
        "pre_public_key_new": fake_g2_point(),
        "rk_point":           fake_g1_point(),
        "file_keys":          [],
        "members": [
            {"user_id": uid, **fake_kem_bundle()}
            for uid in member_user_ids
        ],
    }


@pytest.fixture(scope="module", autouse=True)
async def setup_users(browser: Browser, admin_client: AdminClient):
    global _owner, _member, _escrow
    global _team_two_member, _team_owner_only

    # Register owner
    url = await admin_client.create_invite_url()
    owner_sess = await register_via_invite(browser, url, "rot_owner_34", "0wner!Rot99")
    users = await admin_client.list_users()
    owner_row = next(u for u in users if u["username"].lower() == "rot_owner_34")
    _owner = {"id": owner_row["id"], "session": owner_sess}

    # Register member
    url2 = await admin_client.create_invite_url()
    mem_sess = await register_via_invite(browser, url2, "rot_member_34", "Memb3r!Rot99")
    users2 = await admin_client.list_users()
    mem_row = next(u for u in users2 if u["username"].lower() == "rot_member_34")
    _member = {"id": mem_row["id"], "session": mem_sess}

    # Register escrow agent user
    url3 = await admin_client.create_invite_url()
    esc_sess = await register_via_invite(browser, url3, "rot_escrow_34", "Escr0w!Rot99")
    users3 = await admin_client.list_users()
    esc_row = next(u for u in users3 if u["username"].lower() == "rot_escrow_34")
    _escrow = {"id": esc_row["id"], "session": esc_sess}

    # Grant escrow_agent role to the escrow user
    await admin_client.grant_role(_escrow["id"], "escrow_agent")

    # Create a two-member team (owner + member)
    owner_api = ApiClient.from_session(_owner["session"])
    async with owner_api:
        _team_two_member = await create_team(owner_api, "Rotation Test Team Two Members")
        await add_member(owner_api, _team_two_member["id"], "rot_member_34")

    # Create an owner-only team
    async with owner_api:
        _team_owner_only = await create_team(owner_api, "Rotation Test Team Owner Only")

    yield

    await owner_sess.ctx.close()
    await mem_sess.ctx.close()
    await esc_sess.ctx.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_34_01_rotation_omitting_member_returns_422():
    """Rotation that excludes a current team member is rejected (completeness check)."""
    if not _team_two_member or not _owner or not _member:
        pytest.skip("Setup incomplete")

    owner_api = ApiClient.from_session(_owner["session"])
    # Submit rotation with only the owner — member is absent
    payload = _rotation_payload([_owner["id"]])
    async with owner_api:
        r = await owner_api.post(
            f"/teams/{_team_two_member['id']}/rotate",
            json=payload,
        )
    assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"
    detail = r.json().get("detail", "")
    assert "Rotation must cover all current members" in detail, (
        f"Expected completeness-check error, got: {detail}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_34_02_rotation_omitting_self_returns_422():
    """Rotation that excludes the requesting user is rejected."""
    if not _team_two_member or not _owner or not _member:
        pytest.skip("Setup incomplete")

    owner_api = ApiClient.from_session(_owner["session"])
    # Submit rotation with only the member — owner omits themselves
    payload = _rotation_payload([_member["id"]])
    async with owner_api:
        r = await owner_api.post(
            f"/teams/{_team_two_member['id']}/rotate",
            json=payload,
        )
    assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"
    detail = r.json().get("detail", "")
    assert "requesting user" in detail, (
        f"Expected self-omission error, got: {detail}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_34_03_rotation_with_non_member_returns_422():
    """Rotation that includes a user who is not a team member is rejected."""
    if not _team_owner_only or not _owner or not _member:
        pytest.skip("Setup incomplete")

    owner_api = ApiClient.from_session(_owner["session"])
    # Submit rotation that includes both owner and non-member
    payload = _rotation_payload([_owner["id"], _member["id"]])
    async with owner_api:
        r = await owner_api.post(
            f"/teams/{_team_owner_only['id']}/rotate",
            json=payload,
        )
    assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"
    detail = r.json().get("detail", "")
    assert "non-members" in detail, (
        f"Expected non-member error, got: {detail}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_34_04_rotation_missing_escrow_agent_returns_422_when_required(
    admin_client: AdminClient,
):
    """When escrow_require_coverage is enabled, rotation without an escrow agent is 422."""
    if not _team_owner_only or not _owner or not _escrow:
        pytest.skip("Setup incomplete")

    # Enable coverage requirement
    await admin_client.set_setting("escrow_require_coverage", "1")

    try:
        owner_api = ApiClient.from_session(_owner["session"])
        # Owner-only team: submit rotation with just the owner (no escrow agent)
        payload = _rotation_payload([_owner["id"]])
        async with owner_api:
            r = await owner_api.post(
                f"/teams/{_team_owner_only['id']}/rotate",
                json=payload,
            )
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"
        detail = r.json().get("detail", "")
        assert "escrow_require_coverage" in detail, (
            f"Expected escrow coverage error, got: {detail}"
        )
    finally:
        await admin_client.set_setting("escrow_require_coverage", "0")
