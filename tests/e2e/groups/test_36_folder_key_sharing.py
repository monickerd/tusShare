"""
Group 36 — Folder-key sharing model.

Tests the per-folder AES-256-GCM key model introduced to make share creation
O(subfolder count) rather than O(file count), and the share_exclusions API
for subfolder-level revocation.

Endpoints exercised
-------------------
  POST   /folders                                  (with folder_key_ct/iv)
  GET    /folders/{id}
  GET    /folders/{id}/all-subfolders
  POST   /uploads  +  PATCH /uploads/{id}          (with key_version=v2-folder)
  GET    /files/{id}
  POST   /shares                                   (resource_type='folder' items)
  GET    /s/{token}
  GET    /s/{token}/files/{id}/content
  GET    /shares/{id}/exclusions
  POST   /shares/{id}/exclusions
  DELETE /shares/{id}/exclusions/{folder_id}

Tests
-----
  36-01  Folder created with folder_key_ct/iv stores and returns those fields
  36-02  GET /folders/{id}/all-subfolders returns full subtree with crypto fields
  36-03  File uploaded with key_version='v2-folder' stores that value
  36-04  Create a link share with resource_type='folder' items succeeds
  36-05  Public share resolve includes folder-type items in the items list
  36-06  v2-folder file in a shared folder is accessible via the share
  36-07  POST exclusion + GET exclusions reflects the added folder
  36-08  File in excluded folder is absent from the public share item list
  36-09  DELETE exclusion restores the folder to the share
  36-10  Non-owner cannot add an exclusion to someone else's share (403)
  36-11  Legacy per-file share (resource_type='file') continues to work alongside
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.files import (
    create_folder_with_key,
    delete_file,
    get_folder_subtree,
    upload_file_api,
)
from tests.e2e.helpers.shares import (
    add_share_exclusion,
    create_folder_key_share,
    create_link_share,
    delete_share,
    download_share_content_public,
    list_share_exclusions,
    remove_share_exclusion,
    resolve_share_public,
)
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_owner:  dict = {}   # user who creates folders + shares
_other:  dict = {}   # second user — used for the non-owner access-control test

_root_folder:  dict = {}   # personal folder with folder_key_ct/iv
_sub_folder_a: dict = {}   # child of root — stays included in share
_sub_folder_b: dict = {}   # child of root — will be excluded in test 36-08

_file_in_root: dict = {}   # v2-folder file in root_folder
_file_in_b:    dict = {}   # v2-folder file in sub_folder_b

_fk_share:    dict = {}   # the folder-key link share

_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_users(browser: Browser, admin_client: AdminClient):
    global _owner, _other
    invite_owner = await admin_client.create_invite_url()
    invite_other = await admin_client.create_invite_url()
    sess_owner = await register_via_invite(browser, invite_owner, "fk_owner_36", "Fk0wner!Pass99")
    sess_other = await register_via_invite(browser, invite_other, "fk_other_36", "Fk0ther!Pass99")
    users = await admin_client.list_users()
    uid_owner = next(u["id"] for u in users if u["username"].lower() == "fk_owner_36")
    uid_other = next(u["id"] for u in users if u["username"].lower() == "fk_other_36")
    _owner = {"id": uid_owner, "session": sess_owner}
    _other = {"id": uid_other, "session": sess_other}
    yield
    await sess_owner.ctx.close()
    await sess_other.ctx.close()


# ---------------------------------------------------------------------------
# Folder creation with crypto fields
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_01_folder_stores_crypto_fields():
    """A folder created with folder_key_ct/iv has those fields returned by GET."""
    global _root_folder, _sub_folder_a, _sub_folder_b
    api = ApiClient.from_session(_owner["session"])
    async with api:
        _root_folder  = await create_folder_with_key(api, "fk_root_36")
        _sub_folder_a = await create_folder_with_key(api, "fk_sub_a_36", parent_id=_root_folder["id"])
        _sub_folder_b = await create_folder_with_key(api, "fk_sub_b_36", parent_id=_root_folder["id"])

    assert _root_folder.get("folder_key_ct"), "folder_key_ct should be returned on folder"
    assert _root_folder.get("folder_key_iv"), "folder_key_iv should be returned on folder"
    assert _sub_folder_a.get("folder_key_ct")
    assert _sub_folder_b.get("folder_key_ct")


# ---------------------------------------------------------------------------
# Subtree endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_02_all_subfolders_returns_subtree():
    """GET /folders/{id}/all-subfolders returns root + both children with crypto fields."""
    if not _root_folder:
        pytest.skip("root folder not created")
    api = ApiClient.from_session(_owner["session"])
    async with api:
        data = await get_folder_subtree(api, _root_folder["id"])

    folders = data.get("folders", [])
    folder_ids = {f["id"] for f in folders}
    assert _root_folder["id"]  in folder_ids, "root folder should be in subtree"
    assert _sub_folder_a["id"] in folder_ids, "sub_a should be in subtree"
    assert _sub_folder_b["id"] in folder_ids, "sub_b should be in subtree"
    # Every folder in the subtree should carry the crypto fields
    for f in folders:
        assert f.get("folder_key_ct"), f"folder {f['id']} missing folder_key_ct"
        assert f.get("folder_key_iv"), f"folder {f['id']} missing folder_key_iv"


# ---------------------------------------------------------------------------
# File upload with key_version
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_03_upload_stores_key_version():
    """File uploaded with key_version='v2-folder' has that value in its record."""
    global _file_in_root, _file_in_b
    if not _root_folder or not _sub_folder_b:
        pytest.skip("folders not created")
    api = ApiClient.from_session(_owner["session"])
    async with api:
        _file_in_root = await upload_file_api(
            api, "fk_root_file.txt", b"folder-key root file",
            folder_id=_root_folder["id"], key_version="v2-folder",
        )
        _file_in_b = await upload_file_api(
            api, "fk_sub_b_file.txt", b"folder-key sub-b file",
            folder_id=_sub_folder_b["id"], key_version="v2-folder",
        )

    assert _file_in_root.get("key_version") == "v2-folder", (
        f"expected key_version='v2-folder', got {_file_in_root.get('key_version')!r}"
    )
    assert _file_in_b.get("key_version") == "v2-folder"


# ---------------------------------------------------------------------------
# Folder-key share creation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_04_create_folder_key_share():
    """Create a link share with resource_type='folder' items for the folder tree."""
    global _fk_share
    if not _root_folder:
        pytest.skip("folders not created")
    api = ApiClient.from_session(_owner["session"])
    async with api:
        _fk_share = await create_folder_key_share(
            api,
            folder_ids=[_root_folder["id"], _sub_folder_a["id"], _sub_folder_b["id"]],
        )

    assert "token" in _fk_share, "share should contain a token"
    assert _fk_share.get("share_type") == "link"


@pytest.mark.asyncio(loop_scope="session")
async def test_36_05_public_resolve_includes_folder_items():
    """Public share resolve returns folder-type items alongside file items."""
    if not _fk_share:
        pytest.skip("no folder-key share available")
    resp = await resolve_share_public(_fk_share["token"])
    assert resp.status_code == 200, (
        f"public resolve should return 200, got {resp.status_code}: {resp.text}"
    )
    items = resp.json().get("files", [])
    folder_items = [i for i in items if i.get("resource_type") == "folder"]
    assert len(folder_items) >= 1, (
        "share resolve should include at least one resource_type='folder' item"
    )
    folder_item_ids = {i["resource_id"] for i in folder_items}
    assert _root_folder["id"] in folder_item_ids, (
        "root folder should appear as a folder item in the share"
    )


# ---------------------------------------------------------------------------
# File access via folder-key share
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_06_v2_file_accessible_via_folder_share():
    """A v2-folder file in a shared folder can be downloaded via the share."""
    if not _fk_share or not _file_in_root:
        pytest.skip("share or file not created")
    resolve_resp = await resolve_share_public(_fk_share["token"])
    assert resolve_resp.status_code == 200
    session_token = resolve_resp.json().get("share_session_token")
    assert session_token, "resolve should return share_session_token"

    content_resp = await download_share_content_public(
        _fk_share["token"], _file_in_root["id"], session_token
    )
    assert content_resp.status_code in (200, 206), (
        f"v2-folder file should be accessible via folder-key share, "
        f"got {content_resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Share exclusions — CRUD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_07_add_and_list_exclusion():
    """Adding a folder to exclusions is reflected by GET exclusions."""
    if not _fk_share or not _sub_folder_b:
        pytest.skip("share or sub_folder_b not created")
    api = ApiClient.from_session(_owner["session"])
    async with api:
        await add_share_exclusion(api, _fk_share["id"], _sub_folder_b["id"])
        exclusions = await list_share_exclusions(api, _fk_share["id"])

    excluded_ids = set(exclusions)  # items are folder_id strings
    assert _sub_folder_b["id"] in excluded_ids, (
        f"sub_folder_b should appear in exclusions list, got {excluded_ids}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_36_08_excluded_folder_absent_from_share():
    """After exclusion, sub_folder_b's files are absent from the public share listing,
    and downloading a file from that folder returns 403."""
    if not _fk_share or not _sub_folder_b or not _file_in_b:
        pytest.skip("share or file_in_b not created")
    resolve_resp = await resolve_share_public(_fk_share["token"])
    assert resolve_resp.status_code == 200
    data = resolve_resp.json()
    items = data.get("files", [])

    # The excluded folder's key item should not appear in the listing
    folder_item_ids = {i["resource_id"] for i in items if i.get("resource_type") == "folder"}
    assert _sub_folder_b["id"] not in folder_item_ids, (
        "excluded folder should not appear as a folder item in the share"
    )

    # Downloading the file from the excluded folder should be blocked
    session_token = data.get("share_session_token")
    assert session_token
    content_resp = await download_share_content_public(
        _fk_share["token"], _file_in_b["id"], session_token
    )
    assert content_resp.status_code == 403, (
        f"file in excluded folder should return 403, got {content_resp.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_36_09_remove_exclusion_restores_folder():
    """Removing the exclusion makes sub_folder_b's folder item visible again."""
    if not _fk_share or not _sub_folder_b:
        pytest.skip("share or sub_folder_b not created")
    api = ApiClient.from_session(_owner["session"])
    async with api:
        await remove_share_exclusion(api, _fk_share["id"], _sub_folder_b["id"])
        exclusions = await list_share_exclusions(api, _fk_share["id"])

    excluded_ids = set(exclusions)  # items are folder_id strings
    assert _sub_folder_b["id"] not in excluded_ids, (
        "sub_folder_b should no longer be in the exclusions list after deletion"
    )

    # Folder item should reappear in the public share resolve
    resolve_resp = await resolve_share_public(_fk_share["token"])
    assert resolve_resp.status_code == 200
    items = resolve_resp.json().get("files", [])
    folder_item_ids = {i["resource_id"] for i in items if i.get("resource_type") == "folder"}
    assert _sub_folder_b["id"] in folder_item_ids, (
        "sub_folder_b should reappear in share after exclusion removal"
    )


# ---------------------------------------------------------------------------
# Access control — non-owner cannot manage exclusions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_10_non_owner_cannot_add_exclusion():
    """A different authenticated user receives 403 when adding an exclusion."""
    if not _fk_share or not _sub_folder_a:
        pytest.skip("share or sub_folder_a not created")
    other_api = ApiClient.from_session(_other["session"])
    async with other_api:
        r = await other_api.post(
            f"/shares/{_fk_share['id']}/exclusions",
            json={"folder_id": _sub_folder_a["id"]},
        )
    assert r.status_code == 403, (
        f"non-owner should receive 403 for exclusion creation, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Backward compatibility — per-file share alongside folder-key share
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_11_legacy_per_file_share_still_works():
    """A v1-master file shared via a legacy per-file share item is still accessible."""
    api = ApiClient.from_session(_owner["session"])
    async with api:
        legacy_file = await upload_file_api(api, "fk_legacy_36.txt", b"legacy file content")
        legacy_share = await create_link_share(api, [legacy_file["id"]])

    resolve_resp = await resolve_share_public(legacy_share["token"])
    assert resolve_resp.status_code == 200
    data = resolve_resp.json()
    assert any(
        i.get("resource_id") == legacy_file["id"] for i in data.get("files", [])
    ), "legacy per-file item should appear in share resolve"

    session_token = data.get("share_session_token")
    content_resp = await download_share_content_public(
        legacy_share["token"], legacy_file["id"], session_token
    )
    assert content_resp.status_code in (200, 206), (
        f"legacy per-file share content should be accessible, got {content_resp.status_code}"
    )

    # Cleanup
    async with ApiClient.from_session(_owner["session"]) as api:
        await delete_share(api, legacy_share["id"])
        await delete_file(api, legacy_file["id"])


# ---------------------------------------------------------------------------
# SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_36_12_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
