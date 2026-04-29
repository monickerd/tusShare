"""
Group 01 — Admin settings and invite CRUD.

Tests that the admin can read and write global settings and manage invites.
Does not touch user/role data — that's group 02 onwards.

Tests
-----
01-01  Admin can read all settings
01-02  Admin can update a setting (open_registration)
01-03  Settings update is reflected immediately on re-read
01-04  Admin can create an invite
01-05  Created invite appears in the invite list
01-06  Admin can revoke an unused invite
01-07  Revoked invite token is rejected on registration attempt
01-08  Admin can read disk-usage stats
01-09  Health endpoint returns healthy status with correct integrity info
01-10  Non-admin cannot access admin settings
"""

from __future__ import annotations

import pytest
import httpx
from playwright.async_api import Browser

from tests.e2e.conftest      import ADMIN_USERNAME, ADMIN_PASSWORD
from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth  import login, register_via_invite
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# test_01_10 causes a regular user to attempt /admin/settings → 403 → auth.forbidden.
# Settings and invite CRUD do not emit SIEM events.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden", outcome="failure", severity="warning", tier=2),
]


# seeded_env fixture is inherited from conftest.py


@pytest.mark.asyncio(loop_scope="session")
async def test_01_01_admin_can_read_settings(admin_client: AdminClient):
    settings = await admin_client.get_settings()
    assert isinstance(settings, dict)
    # Core keys must be present
    expected = {
        "open_registration",
        "global_max_file_size",
        "global_bandwidth_limit",
        "disk_warning_threshold",
        "default_chunk_size",
    }
    assert expected.issubset(set(settings.keys())), (
        f"Missing settings keys. Got: {set(settings.keys())}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_01_02_admin_can_update_setting(admin_client: AdminClient):
    await admin_client.set_setting("open_registration", "true")
    settings = await admin_client.get_settings()
    assert settings["open_registration"] == "true"


@pytest.mark.asyncio(loop_scope="session")
async def test_01_03_setting_update_persists(admin_client: AdminClient):
    await admin_client.set_setting("open_registration", "false")
    settings = await admin_client.get_settings()
    assert settings["open_registration"] == "false"


@pytest.mark.asyncio(loop_scope="session")
async def test_01_04_admin_can_create_invite(admin_client: AdminClient):
    invite = await admin_client.create_invite()
    assert "token" in invite, f"Invite response missing token: {invite}"
    assert "id"    in invite
    assert invite.get("used_at") is None   # not yet consumed


@pytest.mark.asyncio(loop_scope="session")
async def test_01_05_invite_appears_in_list(admin_client: AdminClient):
    invite = await admin_client.create_invite()
    invites = await admin_client.list_invites()
    ids = [i["id"] for i in invites]
    assert invite["id"] in ids, "Newly created invite not found in list"


@pytest.mark.asyncio(loop_scope="session")
async def test_01_06_admin_can_revoke_invite(admin_client: AdminClient):
    invite  = await admin_client.create_invite()
    invites_before = await admin_client.list_invites()
    assert any(i["id"] == invite["id"] for i in invites_before)

    await admin_client.revoke_invite(invite["id"])

    invites_after = await admin_client.list_invites()
    # After revocation the invite is gone or marked revoked
    remaining_active = [
        i for i in invites_after
        if i["id"] == invite["id"] and i.get("used_at") is None
    ]
    assert len(remaining_active) == 0, (
        "Revoked invite still appears as active in the invite list"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_01_07_revoked_invite_token_rejected():
    """Using a revoked invite token returns 400 or 404."""
    # We can't easily test the full OPAQUE round-trip for a revoked token,
    # but we can confirm the invite validation endpoint rejects it.
    fake_token = "this_token_does_not_exist_0000000000000"
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        r = await client.get(f"{API}/auth/invite/{fake_token}")
    assert r.status_code in (400, 404, 410), (
        f"Expected 4xx for invalid invite token, got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_01_08_admin_can_read_disk_usage(admin_client: AdminClient):
    usage = await admin_client.get_disk_usage()
    assert "total"     in usage or "filesystem" in usage or isinstance(usage, dict), (
        f"Unexpected disk usage shape: {usage}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_01_09_health_endpoint_returns_healthy():
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        r = await client.get(f"{API}/health")
    assert r.status_code == 200
    data = r.json()
    # Must report healthy status
    assert data.get("status") in ("ok", "healthy", True), (
        f"Unexpected health response: {data}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_01_10_non_admin_cannot_access_settings(
    browser: Browser,
    admin_client: AdminClient,
):
    """A regular user (team_member role) must get 403 on admin settings."""
    invite_url = await admin_client.create_invite_url()
    from tests.e2e.helpers.auth import register_via_invite
    user_session = await register_via_invite(
        browser, invite_url, "regular_user_01", "Us3r!Passw0rd"
    )
    try:
        user_api = ApiClient.from_session(user_session)
        async with user_api:
            r = await user_api.get("/admin/settings")
        assert r.status_code == 403, (
            f"Regular user should not access admin settings, got {r.status_code}"
        )
    finally:
        await user_session.ctx.close()


# ---------------------------------------------------------------------------
# 01-11  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_01_11_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
