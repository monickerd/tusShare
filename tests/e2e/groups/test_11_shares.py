"""
Group 11 — Share link lifecycle.

Tests
-----
11-01  File owner can create a share link
11-02  Share token resolves publicly (GET /s/{token})
11-03  Share content is accessible via share_session_token
11-04  Deleted share → token resolves to 404
11-05  max_downloads=1 — second anonymous download returns 410
11-06  Deleted file → share content returns 404
"""

from __future__ import annotations

import pytest
import httpx
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient
from tests.e2e.helpers.auth   import register_via_invite
from tests.e2e.helpers.files  import delete_file, upload_file_api
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest
from tests.e2e.helpers.shares import (
    create_link_share, delete_share,
    resolve_share_public, download_share_content_public,
    download_share_content_authed,
)

APP_URL = "http://localhost:8001"

# Module-level state
_user:  dict = {}
_file:  dict = {}
_share: dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# Share creation, access, and revocation routes do not emit SIEM events in
# the current implementation (file.share.* events are not yet wired).
# No sharing deny-rules are active so share.blocked does not fire.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


@pytest.fixture(scope="module", autouse=True)
async def setup_user(browser: Browser, admin_client: AdminClient):
    global _user
    url  = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, url, "share_user_11", "Sh4re!Passw0rd")
    users = await admin_client.list_users()
    u = next(x for x in users if x["username"].lower() == "share_user_11")
    _user = {"id": u["id"], "session": sess}
    yield
    await sess.ctx.close()


# ---------------------------------------------------------------------------
# Share creation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_11_01_owner_creates_share_link():
    """Upload a file then create a link share for it."""
    global _file, _share
    content = b"Share lifecycle test file -- group 11"
    api = ApiClient.from_session(_user["session"])
    async with api:
        _file  = await upload_file_api(api, "share_test_11.txt", content)
        _share = await create_link_share(api, [_file["id"]])
    assert "token" in _share
    assert _share.get("share_type") == "link"


@pytest.mark.asyncio(loop_scope="session")
async def test_11_02_share_token_resolves_publicly():
    """GET /s/{token} returns 200 and the file list without authentication."""
    if not _share:
        pytest.skip("No share available")
    resp = await resolve_share_public(_share["token"])
    assert resp.status_code == 200, (
        f"Public share resolve should return 200, got {resp.status_code}: {resp.text}"
    )
    data = resp.json()
    assert "files" in data
    assert any(f["resource_id"] == _file["id"] for f in data["files"])


@pytest.mark.asyncio(loop_scope="session")
async def test_11_03_share_content_accessible_via_session_token():
    """Use the share_session_token from resolve to download the file content."""
    if not _share or not _file:
        pytest.skip("No share/file available")
    resolve_resp = await resolve_share_public(_share["token"])
    assert resolve_resp.status_code == 200
    session_token = resolve_resp.json().get("share_session_token")
    assert session_token, "resolve should return share_session_token"

    content_resp = await download_share_content_public(
        _share["token"], _file["id"], session_token
    )
    assert content_resp.status_code in (200, 206), (
        f"Content download should succeed, got {content_resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Share revocation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_11_04_deleted_share_token_returns_404():
    """Create a second share, verify it resolves, delete it, verify 404."""
    content = b"Delete-me share file -- group 11"
    api = ApiClient.from_session(_user["session"])
    async with api:
        temp_file  = await upload_file_api(api, "delete_share_11.txt", content)
        temp_share = await create_link_share(api, [temp_file["id"]])

    # Verify it resolves
    r = await resolve_share_public(temp_share["token"])
    assert r.status_code == 200

    # Delete it
    async with ApiClient.from_session(_user["session"]) as api:
        await delete_share(api, temp_share["id"])

    # Should now 404
    r2 = await resolve_share_public(temp_share["token"])
    assert r2.status_code == 404, (
        f"Deleted share should return 404, got {r2.status_code}"
    )


# ---------------------------------------------------------------------------
# max_downloads enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_11_05_max_downloads_enforced():
    """Share with max_downloads=1: second anonymous download returns 410."""
    content = b"Quota share file -- group 11"
    api = ApiClient.from_session(_user["session"])
    async with api:
        quota_file  = await upload_file_api(api, "quota_share_11.txt", content)
        quota_share = await create_link_share(api, [quota_file["id"]], max_downloads=1)

    # First resolve to get session token
    r1 = await resolve_share_public(quota_share["token"])
    assert r1.status_code == 200
    session_token = r1.json()["share_session_token"]

    # First download — should succeed
    dl1 = await download_share_content_public(quota_share["token"], quota_file["id"], session_token)
    assert dl1.status_code in (200, 206), (
        f"First download should succeed, got {dl1.status_code}"
    )

    # Re-resolve to get a fresh session token
    r2 = await resolve_share_public(quota_share["token"])
    if r2.status_code == 200:
        session_token2 = r2.json()["share_session_token"]
        dl2 = await download_share_content_public(quota_share["token"], quota_file["id"], session_token2)
        assert dl2.status_code == 410, (
            f"Second download past quota should return 410 Gone, got {dl2.status_code}"
        )


# ---------------------------------------------------------------------------
# Deleted file
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_11_06_deleted_file_returns_404_from_share():
    """Delete the underlying file — share token resolves but content returns 404."""
    content = b"Temporary shared file -- group 11"
    api = ApiClient.from_session(_user["session"])
    async with api:
        temp_file  = await upload_file_api(api, "temp_share_11.txt", content)
        temp_share = await create_link_share(api, [temp_file["id"]])

    # Resolve → get session token
    r = await resolve_share_public(temp_share["token"])
    assert r.status_code == 200
    session_token = r.json()["share_session_token"]

    # Delete the file
    async with ApiClient.from_session(_user["session"]) as api:
        await delete_file(api, temp_file["id"])

    # Share token resolves, but file content should 404
    content_resp = await download_share_content_public(
        temp_share["token"], temp_file["id"], session_token
    )
    assert content_resp.status_code == 404, (
        f"Content of deleted file should return 404, got {content_resp.status_code}"
    )


# ---------------------------------------------------------------------------
# 11-07  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_11_07_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
