"""
Group 32 — Azure Blob Storage (Azurite emulator).

Tests that the application correctly routes uploads/downloads/deletes through
an Azure Blob Storage backend.  Uses the official Azurite emulator container
(added to docker-compose.test.yml) with the well-known development credentials.

Strategy
────────
The Azurite volume is seeded directly into the test database (bypassing the
admin API and its SSRF blocklist), then the app is restarted so the
StorageManager reloads its volume list.  The SSRF blocklist itself is tested
separately in tests/unit/test_storage_ssrf.py.

Azurite connection (docker-compose.test.yml)
────────────────────────────────────────────
Internal (app container) : http://azurite:10000/devstoreaccount1
External (host / tests)  : http://localhost:10000/devstoreaccount1
Container                : tusshare-test
Credentials              : devstoreaccount1 / (well-known Azurite key)

All tests marked @pytest.mark.azure.  Run with:  pytest -m azure
                                   Skip with:  pytest -m "not azure"

Tests
──────
32-01  Azurite reachable smoke test (skips group on failure)
32-02  Seed Azurite volume + restart → volume appears in admin list
32-03  Seeded volume is marked is_default=true
32-04  GET /admin/storage/volumes/{id} redacts connection_string
32-05  Volume connectivity test endpoint returns ok=true
32-06  Upload a file via TUS → succeeds with Azurite as the storage backend
32-07  Download the uploaded file → 200
32-08  Delete the file → subsequent download is 404
32-09  GET /admin/storage/usage includes the Azurite volume entry
32-10  Register a non-admin user via invite
32-11  User uploads a file → lands on hot Azurite volume (DB confirmed)
32-12  User creates a folder, uploads a file into it → folder listing shows file
32-13  User can download both the root file and the folder file
"""

from __future__ import annotations

import pytest

from tests.e2e.helpers.storage import (
    AZURITE_VOLUME_ID,
    azurite_reachable,
    seed_azure_volume,
)
from tests.e2e.helpers.db import (
    reset_db,
    restart_app_and_wait,
    _psql_fetch,
    PG_DB_NAME,
)
from tests.e2e.helpers.auth import bootstrap_admin, register_via_invite
from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.files import (
    upload_file_api,
    delete_file,
    create_folder,
    get_folder,
)
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

pytestmark = pytest.mark.azure

_REDACTED = "••••••••"

_SIEM_MANIFEST: list[ExpectedSiemEvent] = []

_state: dict = {}


# ---------------------------------------------------------------------------
# Module-scoped fixture: clean DB → admin → Azurite volume → restart
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
async def azure_env(browser):
    from tests.e2e.conftest import ADMIN_USERNAME, ADMIN_PASSWORD

    token = reset_db()
    admin_session = await bootstrap_admin(
        browser,
        token=token,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
    )
    admin_client = AdminClient.from_session(admin_session)

    seed_azure_volume()
    restart_app_and_wait()

    env = {
        "admin_session": admin_session,
        "admin_client":  admin_client,
    }
    yield env

    await admin_client.aclose()
    await admin_session.ctx.close()


# ---------------------------------------------------------------------------
# Skip helpers
# ---------------------------------------------------------------------------

def _skip_if_no_azurite():
    if not azurite_reachable():
        pytest.skip("Azurite container not reachable on port 10000 — is docker-compose up?")


def _skip_if_no_volume():
    if "volume_confirmed" not in _state:
        pytest.skip("32-02 did not confirm the volume — skipping dependent test")


def _skip_if_no_user():
    if "user_client" not in _state:
        pytest.skip("32-10 did not register the test user — skipping dependent test")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_32_01_azurite_reachable():
    """Azurite must be accessible on localhost:10000 before any Azure test can proceed."""
    _skip_if_no_azurite()
    assert azurite_reachable()


@pytest.mark.asyncio(loop_scope="session")
async def test_32_02_volume_appears_in_admin_list(azure_env):
    """Seeded Azurite volume must appear in GET /admin/storage/volumes."""
    _skip_if_no_azurite()

    admin = azure_env["admin_client"]
    volumes = await admin.list_storage_volumes()

    azure_vol = next((v for v in volumes if v["id"] == AZURITE_VOLUME_ID), None)
    assert azure_vol is not None, (
        f"Azure volume '{AZURITE_VOLUME_ID}' not found in volume list: {volumes}"
    )
    assert azure_vol["provider"] == "azure"
    assert azure_vol["name"] == "Azurite Test"

    _state["volume_confirmed"] = True


@pytest.mark.asyncio(loop_scope="session")
async def test_32_03_azure_volume_is_default(azure_env):
    """Azurite volume must be marked as the default upload target after seeding."""
    _skip_if_no_azurite()
    _skip_if_no_volume()

    admin = azure_env["admin_client"]
    volumes = await admin.list_storage_volumes()

    azure_vol = next((v for v in volumes if v["id"] == AZURITE_VOLUME_ID), None)
    assert azure_vol is not None
    assert azure_vol["is_default"] in (True, 1), (
        f"Expected Azure volume to be default, got is_default={azure_vol['is_default']!r}"
    )

    local_vol = next((v for v in volumes if v["id"] == "local-default"), None)
    if local_vol is not None:
        assert local_vol["is_default"] in (False, 0), (
            "local-default should no longer be the default after seeding Azure volume"
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_32_04_get_volume_redacts_connection_string(azure_env):
    """GET /admin/storage/volumes/{id} must redact the connection_string."""
    _skip_if_no_azurite()
    _skip_if_no_volume()

    admin = azure_env["admin_client"]
    vol = await admin.get_storage_volume(AZURITE_VOLUME_ID)

    assert "config" in vol, f"GET volume response missing 'config' key: {vol}"
    cfg = vol["config"]

    assert cfg.get("connection_string") == _REDACTED, (
        f"connection_string should be redacted but got: {cfg.get('connection_string')!r}"
    )
    # Non-secret fields must remain readable
    assert cfg.get("container_name") == "tusshare-test"


@pytest.mark.asyncio(loop_scope="session")
async def test_32_05_volume_connectivity_test_ok(azure_env):
    """POST /admin/storage/volumes/{id}/test must report ok=true for the Azurite volume."""
    _skip_if_no_azurite()
    _skip_if_no_volume()

    admin = azure_env["admin_client"]
    result = await admin.test_storage_volume(AZURITE_VOLUME_ID)

    assert result.get("ok") is True, (
        f"Volume connectivity test failed: {result.get('error')}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_32_06_upload_to_azure_volume(azure_env):
    """Uploading a file must succeed with Azurite as the storage backend."""
    _skip_if_no_azurite()
    _skip_if_no_volume()

    user_client = ApiClient.from_session(azure_env["admin_session"])
    file_meta = await upload_file_api(
        user_client,
        filename="azure_test_file.bin",
        content=b"hello from Azure integration test" * 100,
    )
    assert "id" in file_meta, f"Upload response missing 'id': {file_meta}"
    _state["file_id"] = file_meta["id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_32_07_download_from_azure_volume(azure_env):
    """Downloading the Azure-stored file must return 200."""
    _skip_if_no_azurite()
    _skip_if_no_volume()
    if "file_id" not in _state:
        pytest.skip("32-06 did not produce a file_id — skipping")

    user_client = ApiClient.from_session(azure_env["admin_session"])
    r = await user_client.get(f"/files/{_state['file_id']}/content")
    assert r.status_code == 200, (
        f"Expected 200 downloading Azure-stored file, got {r.status_code}: {r.text[:200]}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_32_08_delete_removes_azure_blob(azure_env):
    """Deleting a file must remove the Azure blob; subsequent download returns 404."""
    _skip_if_no_azurite()
    _skip_if_no_volume()
    if "file_id" not in _state:
        pytest.skip("32-06 did not produce a file_id — skipping")

    user_client = ApiClient.from_session(azure_env["admin_session"])
    await delete_file(user_client, _state["file_id"])

    r = await user_client.get(f"/files/{_state['file_id']}/content")
    assert r.status_code in (404, 410), (
        f"Expected 404/410 after deleting Azure file, got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_32_09_storage_usage_includes_azure(azure_env):
    """GET /admin/storage/usage must list the Azurite volume."""
    _skip_if_no_azurite()
    _skip_if_no_volume()

    admin = azure_env["admin_client"]
    usage = await admin.get_storage_usage()

    assert "volumes" in usage, f"Usage response missing 'volumes': {usage}"
    volume_ids = [v["id"] for v in usage["volumes"]]
    assert AZURITE_VOLUME_ID in volume_ids, (
        f"Azure volume not in usage response. Got volumes: {volume_ids}"
    )

    azure_entry = next(v for v in usage["volumes"] if v["id"] == AZURITE_VOLUME_ID)
    assert "error" not in azure_entry, (
        f"Azure volume reported an error in usage: {azure_entry.get('error')}"
    )


# ---------------------------------------------------------------------------
# 32-10 to 32-13 — Regular-user file and folder I/O on the Azure backend
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_32_10_register_regular_user(azure_env, browser):
    """Register a regular (non-admin) user via invite for Azure I/O tests."""
    _skip_if_no_azurite()
    _skip_if_no_volume()

    admin = azure_env["admin_client"]
    invite_url = await admin.create_invite_url()
    user_session = await register_via_invite(
        browser,
        invite_url,
        username="azure_user",
        password="AzureUser!Test99",
    )
    _state["user_session"] = user_session
    _state["user_client"]  = ApiClient.from_session(user_session)


@pytest.mark.asyncio(loop_scope="session")
async def test_32_11_user_upload_file_to_azure(azure_env):
    """Regular user upload must land on the Azure (Azurite) backend."""
    _skip_if_no_azurite()
    _skip_if_no_volume()
    _skip_if_no_user()

    client = _state["user_client"]
    file_meta = await upload_file_api(
        client,
        filename="user_azure_file.bin",
        content=b"regular user upload to Azure" * 50,
    )
    assert "id" in file_meta
    _state["user_file_id"] = file_meta["id"]

    rows = _psql_fetch(
        f"SELECT volume_id FROM file_storage_locations "
        f"WHERE file_id = '{file_meta['id']}' AND is_primary = 1;",
        db=PG_DB_NAME,
    )
    assert rows, "No file_storage_locations row found for the uploaded file"
    assert rows[0] == AZURITE_VOLUME_ID, (
        f"Expected Azure volume {AZURITE_VOLUME_ID}, got {rows[0]}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_32_12_user_upload_file_into_folder(azure_env):
    """Regular user can create a folder and upload a file into it on Azure."""
    _skip_if_no_azurite()
    _skip_if_no_volume()
    _skip_if_no_user()

    client = _state["user_client"]

    folder = await create_folder(client, name="azure_folder")
    folder_id = folder["id"]
    _state["folder_id"] = folder_id

    file_meta = await upload_file_api(
        client,
        filename="user_azure_folder_file.bin",
        content=b"file inside folder on Azure" * 50,
        folder_id=folder_id,
    )
    assert file_meta.get("folder_id") == folder_id, (
        f"File not placed in expected folder: {file_meta}"
    )
    _state["folder_file_id"] = file_meta["id"]

    folder_contents = await get_folder(client, folder_id)
    file_ids = [f["id"] for f in folder_contents.get("files", [])]
    assert file_meta["id"] in file_ids, (
        f"Uploaded file not found in folder listing: {folder_contents}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_32_13_user_downloads_both_files(azure_env):
    """Regular user can download both the root file and the folder file from Azure."""
    _skip_if_no_azurite()
    _skip_if_no_volume()
    _skip_if_no_user()

    client = _state["user_client"]

    for label, file_id_key in [
        ("root file",   "user_file_id"),
        ("folder file", "folder_file_id"),
    ]:
        if file_id_key not in _state:
            pytest.skip(f"No {file_id_key} to download — earlier test did not succeed")

        r = await client.get(f"/files/{_state[file_id_key]}/content")
        assert r.status_code == 200, (
            f"Expected 200 downloading {label} from Azure, got {r.status_code}: {r.text[:200]}"
        )


# ---------------------------------------------------------------------------
# 32-14  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_32_14_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
