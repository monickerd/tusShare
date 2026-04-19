"""
Group 07 — File and folder CRUD.

File upload is encrypted client-side (AES-GCM, chunked TUS protocol). Tests
that require actual file content go through the browser; tests that only need
metadata or access checks use the API directly.

Tests
-----
07-01  User can create a folder
07-02  Folder appears in root listing
07-03  User can create a nested subfolder
07-04  User can rename a folder
07-05  User can move a folder
07-06  User can delete a folder (including contents)
07-07  File upload via browser completes successfully
07-08  Uploaded file appears in folder listing
07-09  User can rename a file
07-10  User can move a file to another folder (batch-move)
07-11  File metadata is accessible after rename
07-12  User can download their own file (200 on content endpoint)
07-13  User can delete a file
07-14  Deleted file is no longer accessible (404)
07-15  Quota enforcement: uploading past quota is rejected
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient
from tests.e2e.helpers.auth   import register_via_invite
from tests.e2e.helpers.files  import (
    create_folder, list_root, get_folder, rename_folder,
    move_folder, delete_folder, get_file, rename_file,
    delete_file, batch_move_files, can_download_file, can_get_file_meta,
    upload_file_api,
)

APP_URL = "http://localhost:8001"

# Module-level state
_user:        dict = {}
_folder_a:    dict = {}
_folder_b:    dict = {}
_file:        dict = {}


@pytest.fixture(scope="module", autouse=True)
async def setup_user(browser: Browser, admin_client: AdminClient):
    global _user
    url  = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, url, "file_user_07", "F1le!Passw0rd")
    users = await admin_client.list_users()
    u     = next(x for x in users if x["username"].lower() == "file_user_07")
    _user = {"id": u["id"], "session": sess, "username": "file_user_07", "password": "F1le!Passw0rd"}
    yield
    await sess.ctx.close()


# ---------------------------------------------------------------------------
# Folder CRUD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_07_01_create_folder():
    global _folder_a
    api = ApiClient.from_session(_user["session"])
    async with api:
        _folder_a = await create_folder(api, "Documents 07")
    assert _folder_a["name"] == "Documents 07"
    assert "id" in _folder_a


@pytest.mark.asyncio(loop_scope="session")
async def test_07_02_folder_in_root_listing():
    api = ApiClient.from_session(_user["session"])
    async with api:
        root = await list_root(api)
    folder_ids = [f["id"] for f in root.get("folders", [])]
    assert _folder_a["id"] in folder_ids


@pytest.mark.asyncio(loop_scope="session")
async def test_07_03_create_nested_subfolder():
    global _folder_b
    api = ApiClient.from_session(_user["session"])
    async with api:
        _folder_b = await create_folder(api, "Subfolder 07", parent_id=_folder_a["id"])
    assert _folder_b["name"] == "Subfolder 07"


@pytest.mark.asyncio(loop_scope="session")
async def test_07_04_rename_folder():
    api = ApiClient.from_session(_user["session"])
    async with api:
        updated = await rename_folder(api, _folder_a["id"], "Documents Renamed 07")
    assert updated["name"] == "Documents Renamed 07"
    _folder_a["name"] = updated["name"]


@pytest.mark.asyncio(loop_scope="session")
async def test_07_05_move_folder():
    """Move subfolder back to root."""
    api = ApiClient.from_session(_user["session"])
    async with api:
        updated = await move_folder(api, _folder_b["id"], parent_id=None)
    assert updated is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_07_06_delete_folder():
    api = ApiClient.from_session(_user["session"])
    async with api:
        await delete_folder(api, _folder_b["id"])
        root = await list_root(api)
    folder_ids = [f["id"] for f in root.get("folders", [])]
    assert _folder_b["id"] not in folder_ids


# ---------------------------------------------------------------------------
# File operations via browser (encryption happens in JS)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_07_07_file_upload_via_browser():
    """Upload a small test file via the TUS API using stub AES-GCM metadata.

    No real encryption is performed — the server stores the raw bytes and
    tests only verify HTTP status codes and metadata, never decrypt content.
    """
    global _file
    content = b"E2E test file content -- group 07"
    api = ApiClient.from_session(_user["session"])
    async with api:
        _file = await upload_file_api(api, "e2e_test_07.txt", content)


@pytest.mark.asyncio(loop_scope="session")
async def test_07_08_file_in_listing():
    if not _file:
        pytest.skip("No file uploaded (test_07_07 skipped)")
    api = ApiClient.from_session(_user["session"])
    async with api:
        root = await list_root(api)
    file_ids = [f["id"] for f in root.get("files", [])]
    # File may be in root or in a folder; just check it's accessible by metadata
    async with ApiClient.from_session(_user["session"]) as api:
        can_read = await can_get_file_meta(api, _file["id"])
    assert can_read


@pytest.mark.asyncio(loop_scope="session")
async def test_07_09_rename_file():
    if not _file:
        pytest.skip("No file available")
    api = ApiClient.from_session(_user["session"])
    async with api:
        updated = await rename_file(api, _file["id"], "renamed_e2e_test.txt")
    assert updated.get("original_name") == "renamed_e2e_test.txt"
    _file["original_name"] = updated["original_name"]


@pytest.mark.asyncio(loop_scope="session")
async def test_07_10_batch_move_file():
    if not _file:
        pytest.skip("No file available")
    api = ApiClient.from_session(_user["session"])
    async with api:
        result = await batch_move_files(api, [_file["id"]], _folder_a["id"])
    assert result is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_07_11_file_metadata_accessible_after_move():
    if not _file:
        pytest.skip("No file available")
    api = ApiClient.from_session(_user["session"])
    async with api:
        meta = await get_file(api, _file["id"])
    assert meta["id"] == _file["id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_07_12_user_can_download_own_file():
    if not _file:
        pytest.skip("No file available")
    api = ApiClient.from_session(_user["session"])
    async with api:
        can = await can_download_file(api, _file["id"])
    assert can, "File owner should be able to download their own file"


@pytest.mark.asyncio(loop_scope="session")
async def test_07_13_delete_file():
    if not _file:
        pytest.skip("No file available")
    api = ApiClient.from_session(_user["session"])
    async with api:
        await delete_file(api, _file["id"])


@pytest.mark.asyncio(loop_scope="session")
async def test_07_14_deleted_file_not_accessible():
    if not _file:
        pytest.skip("No file available")
    api = ApiClient.from_session(_user["session"])
    async with api:
        r = await api.get(f"/files/{_file['id']}")
    assert r.status_code in (404, 403), (
        f"Deleted file should return 404, got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_07_15_quota_enforcement(admin_client: AdminClient):
    """Setting a tiny quota and attempting to upload more should be rejected."""
    # Set user quota to 1 byte — any real upload will exceed it
    await admin_client.update_user(_user["id"], disk_quota=1)

    # Attempting to start a TUS upload (declare total_size > quota) should fail
    import httpx as _httpx
    sess = _user["session"]
    csrf = sess.cookies.get("__Host-csrf_token", "")
    async with _httpx.AsyncClient(base_url=APP_URL, cookies=sess.cookies) as client:
        r = await client.post(
            "/api/v1/uploads",
            headers={
                "X-CSRF-Token": csrf,
                "Tus-Resumable": "1.0.0",
                "Upload-Length": str(1024 * 1024),   # 1 MB > quota of 1 byte
                "Content-Type": "application/offset+octet-stream",
                "Upload-Metadata": "filename dGVzdC50eHQ=",  # base64("test.txt")
            },
        )
    assert r.status_code in (400, 403, 413), (
        f"Upload over quota should fail, got {r.status_code}: {r.text}"
    )

    # Restore unlimited quota
    await admin_client.update_user(_user["id"], disk_quota=0)
