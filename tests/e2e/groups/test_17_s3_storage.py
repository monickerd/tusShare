"""
Group 17 — S3-compatible storage (MinIO).

Additional tests (17-10 to 17-17) cover:
  • Regular-user file and folder I/O on the S3 backend (17-10 to 17-13)
  • Cross-bucket tier migration triggered via POST /admin/storage/tiering/trigger
    (17-14 to 17-17).  A warm-tier MinIO volume (tusshare-warm bucket) is seeded
    alongside the hot volume; hot_to_warm_days is set to 0 so the pass migrates
    the test file without waiting for a real age threshold.


Tests that the application correctly routes uploads/downloads/deletes through
an S3-compatible storage backend.  Uses a real MinIO container (added to
docker-compose.test.yml) rather than mocking boto3 calls.

Strategy
────────
The MinIO volume is seeded directly into the test database (bypassing the admin
API and its SSRF blocklist), then the app is restarted so the StorageManager
reloads its volume list.  This approach requires zero backend changes — see
tests/e2e/helpers/storage.py for the rationale.

The SSRF blocklist itself is tested separately in tests/unit/test_storage_ssrf.py.

All tests marked @pytest.mark.s3.  Run with:  pytest -m s3
                                 Skip with:  pytest -m "not s3"

MinIO connection (docker-compose.test.yml)
──────────────────────────────────────────
Internal (app container) : http://minio:9000
External (host / tests)  : http://localhost:9000
Bucket                   : tusshare-test
Credentials              : minioadmin / minioadmin123

Tests
──────
17-01  MinIO reachable smoke test (skips group on failure)
17-02  Seed MinIO volume + restart → volume appears in admin list
17-03  Seeded volume is marked is_default=true
17-04  GET /admin/storage/volumes/{id} redacts access credentials
17-05  Volume connectivity test endpoint returns ok=true
17-06  Upload a file via TUS → succeeds with MinIO as the storage backend
17-07  Download the uploaded file → 200
17-08  Delete the file → subsequent download is 404
17-09  GET /admin/storage/usage includes the MinIO volume entry

Regular-user file and folder I/O
17-10  Register a non-admin user via invite
17-11  User uploads a file → lands on hot MinIO volume (DB confirmed)
17-12  User creates a folder, uploads a file into it → folder listing shows file
17-13  User can download both the root file and the folder file

Cross-bucket tier migration
17-14  Seed warm MinIO volume + tiering policy (0 days), restart app
17-15  Upload a file for migration → starts on hot volume (DB confirmed)
17-16  Trigger tiering pass → file_storage_locations primary becomes warm volume
17-17  Migrated file still returns 200 on download (warm bucket readable)
"""

from __future__ import annotations

import pytest

from tests.e2e.helpers.storage import (
    MINIO_VOLUME_ID,
    MINIO_WARM_VOLUME_ID,
    minio_reachable,
    seed_s3_volume,
    seed_warm_volume,
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

pytestmark = pytest.mark.s3

_REDACTED = "••••••••"

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# S3 storage and file CRUD routes do not emit SIEM events.
# No permission-denied paths (admin credentials used throughout).
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []

# Per-module state shared across tests
_state: dict = {}


# ---------------------------------------------------------------------------
# Module-scoped fixture: clean DB → admin → MinIO volume → restart
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
async def s3_env(browser):
    """
    Full environment setup for S3 tests:
      1. Fresh DB + app restart (local-default volume only)
      2. Bootstrap admin account
      3. Seed MinIO volume directly into DB (bypasses admin API + SSRF check)
      4. Restart app so StorageManager picks up the new volume as default
    Returns dict: admin_session, admin_client.
    """
    from tests.e2e.conftest import ADMIN_USERNAME, ADMIN_PASSWORD

    token = reset_db()
    admin_session = await bootstrap_admin(
        browser,
        token=token,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
    )
    admin_client = AdminClient.from_session(admin_session)

    seed_s3_volume()
    restart_app_and_wait()

    env = {
        "admin_session": admin_session,
        "admin_client":  admin_client,
    }
    yield env

    await admin_client.aclose()
    await admin_session.ctx.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skip_if_no_minio():
    if not minio_reachable():
        pytest.skip("MinIO container not reachable on port 9000 — is docker-compose up?")


def _skip_if_no_volume():
    if "volume_confirmed" not in _state:
        pytest.skip("17-02 did not confirm the volume — skipping dependent test")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_17_01_minio_reachable():
    """MinIO must be accessible on localhost:9000 before any S3 test can proceed."""
    _skip_if_no_minio()
    assert minio_reachable()


@pytest.mark.asyncio(loop_scope="session")
async def test_17_02_volume_appears_in_admin_list(s3_env):
    """Seeded MinIO volume must appear in GET /admin/storage/volumes."""
    _skip_if_no_minio()

    admin = s3_env["admin_client"]
    volumes = await admin.list_storage_volumes()

    minio_vol = next((v for v in volumes if v["id"] == MINIO_VOLUME_ID), None)
    assert minio_vol is not None, (
        f"MinIO volume '{MINIO_VOLUME_ID}' not found in volume list: {volumes}"
    )
    assert minio_vol["provider"] == "s3"
    assert minio_vol["name"] == "MinIO Test"

    _state["volume_confirmed"] = True


@pytest.mark.asyncio(loop_scope="session")
async def test_17_03_minio_volume_is_default(s3_env):
    """MinIO volume must be marked as the default upload target after seeding."""
    _skip_if_no_minio()
    _skip_if_no_volume()

    admin = s3_env["admin_client"]
    volumes = await admin.list_storage_volumes()

    minio_vol = next((v for v in volumes if v["id"] == MINIO_VOLUME_ID), None)
    assert minio_vol is not None
    assert minio_vol["is_default"] in (True, 1), (
        f"Expected MinIO volume to be default, got is_default={minio_vol['is_default']!r}"
    )

    local_vol = next((v for v in volumes if v["id"] == "local-default"), None)
    if local_vol is not None:
        assert local_vol["is_default"] in (False, 0), (
            "local-default should no longer be the default after seeding MinIO"
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_17_04_get_volume_redacts_credentials(s3_env):
    """GET /admin/storage/volumes/{id} must redact access_key_id and secret_access_key."""
    _skip_if_no_minio()
    _skip_if_no_volume()

    admin = s3_env["admin_client"]
    vol = await admin.get_storage_volume(MINIO_VOLUME_ID)

    assert "config" in vol, f"GET volume response missing 'config' key: {vol}"
    cfg = vol["config"]

    assert cfg.get("access_key_id")     == _REDACTED, (
        f"access_key_id should be redacted but got: {cfg.get('access_key_id')!r}"
    )
    assert cfg.get("secret_access_key") == _REDACTED, (
        f"secret_access_key should be redacted but got: {cfg.get('secret_access_key')!r}"
    )
    # Non-secret fields must remain readable
    assert cfg.get("bucket")       == "tusshare-test"
    assert cfg.get("endpoint_url") == "http://minio:9000"


@pytest.mark.asyncio(loop_scope="session")
async def test_17_05_volume_connectivity_test_ok(s3_env):
    """POST /admin/storage/volumes/{id}/test must report ok=true for the MinIO volume."""
    _skip_if_no_minio()
    _skip_if_no_volume()

    admin = s3_env["admin_client"]
    result = await admin.test_storage_volume(MINIO_VOLUME_ID)

    assert result.get("ok") is True, (
        f"Volume connectivity test failed: {result.get('error')}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_17_06_upload_to_s3_volume(s3_env):
    """Uploading a file must succeed with MinIO as the storage backend."""
    _skip_if_no_minio()
    _skip_if_no_volume()

    user_client = ApiClient.from_session(s3_env["admin_session"])
    file_meta = await upload_file_api(
        user_client,
        filename="s3_test_file.bin",
        content=b"hello from S3 integration test" * 100,
    )
    assert "id" in file_meta, f"Upload response missing 'id': {file_meta}"
    _state["file_id"] = file_meta["id"]


@pytest.mark.asyncio(loop_scope="session")
async def test_17_07_download_from_s3_volume(s3_env):
    """Downloading the S3-stored file must return 200."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    if "file_id" not in _state:
        pytest.skip("17-06 did not produce a file_id — skipping")

    user_client = ApiClient.from_session(s3_env["admin_session"])
    r = await user_client.get(f"/files/{_state['file_id']}/content")
    assert r.status_code == 200, (
        f"Expected 200 downloading S3-stored file, got {r.status_code}: {r.text[:200]}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_17_08_delete_removes_s3_object(s3_env):
    """Deleting a file must remove the S3 object; subsequent download returns 404."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    if "file_id" not in _state:
        pytest.skip("17-06 did not produce a file_id — skipping")

    user_client = ApiClient.from_session(s3_env["admin_session"])
    await delete_file(user_client, _state["file_id"])

    r = await user_client.get(f"/files/{_state['file_id']}/content")
    assert r.status_code in (404, 410), (
        f"Expected 404/410 after deleting S3 file, got {r.status_code}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_17_09_storage_usage_includes_minio(s3_env):
    """GET /admin/storage/usage must list the MinIO volume."""
    _skip_if_no_minio()
    _skip_if_no_volume()

    admin = s3_env["admin_client"]
    usage = await admin.get_storage_usage()

    assert "volumes" in usage, f"Usage response missing 'volumes': {usage}"
    volume_ids = [v["id"] for v in usage["volumes"]]
    assert MINIO_VOLUME_ID in volume_ids, (
        f"MinIO volume not in usage response.  Got volumes: {volume_ids}"
    )

    minio_entry = next(v for v in usage["volumes"] if v["id"] == MINIO_VOLUME_ID)
    # S3 volumes report 0 used and None total (no listing API); the entry must
    # exist without an error key to confirm the provider is reachable.
    assert "error" not in minio_entry, (
        f"MinIO volume reported an error in usage: {minio_entry.get('error')}"
    )


# ---------------------------------------------------------------------------
# 17-10 to 17-13 — Regular-user file and folder I/O on the S3 backend
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_17_10_register_regular_user(s3_env, browser):
    """Register a regular (non-admin) user via invite for S3 I/O tests."""
    _skip_if_no_minio()
    _skip_if_no_volume()

    admin = s3_env["admin_client"]
    invite_url = await admin.create_invite_url()
    user_session = await register_via_invite(
        browser,
        invite_url,
        username="s3_user",
        password="S3User!Test99",
    )
    _state["user_session"] = user_session
    _state["user_client"]  = ApiClient.from_session(user_session)


def _skip_if_no_user():
    if "user_client" not in _state:
        pytest.skip("17-10 did not register the test user — skipping dependent test")


@pytest.mark.asyncio(loop_scope="session")
async def test_17_11_user_upload_file_to_s3(s3_env):
    """Regular user upload must land on the S3 (MinIO) backend."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    _skip_if_no_user()

    client = _state["user_client"]
    file_meta = await upload_file_api(
        client,
        filename="user_s3_file.bin",
        content=b"regular user upload to S3" * 50,
    )
    assert "id" in file_meta
    _state["user_file_id"] = file_meta["id"]

    # Verify the storage location row points to the MinIO hot volume
    rows = _psql_fetch(
        f"SELECT volume_id FROM file_storage_locations "
        f"WHERE file_id = '{file_meta['id']}' AND is_primary = 1;",
        db=PG_DB_NAME,
    )
    assert rows, "No file_storage_locations row found for the uploaded file"
    assert rows[0] == MINIO_VOLUME_ID, (
        f"Expected hot volume {MINIO_VOLUME_ID}, got {rows[0]}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_17_12_user_upload_file_into_folder(s3_env):
    """Regular user can create a folder and upload a file into it on S3."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    _skip_if_no_user()

    client = _state["user_client"]

    folder = await create_folder(client, name="s3_folder")
    folder_id = folder["id"]
    _state["folder_id"] = folder_id

    file_meta = await upload_file_api(
        client,
        filename="user_folder_file.bin",
        content=b"file inside folder on S3" * 50,
        folder_id=folder_id,
    )
    assert file_meta.get("folder_id") == folder_id, (
        f"File not placed in expected folder: {file_meta}"
    )
    _state["folder_file_id"] = file_meta["id"]

    # Confirm the folder lists the file
    folder_contents = await get_folder(client, folder_id)
    file_ids = [f["id"] for f in folder_contents.get("files", [])]
    assert file_meta["id"] in file_ids, (
        f"Uploaded file not found in folder listing: {folder_contents}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_17_13_user_downloads_both_files(s3_env):
    """Regular user can download both the root file and the folder file from S3."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    _skip_if_no_user()

    client = _state["user_client"]

    for label, file_id_key in [
        ("root file",   "user_file_id"),
        ("folder file", "folder_file_id"),
    ]:
        if file_id_key not in _state:
            pytest.skip(f"No {label} to download — earlier test did not succeed")

        r = await client.get(f"/files/{_state[file_id_key]}/content")
        assert r.status_code == 200, (
            f"Expected 200 downloading {label} from S3, got {r.status_code}: {r.text[:200]}"
        )


# ---------------------------------------------------------------------------
# 17-14 to 17-17 — Cross-bucket tier migration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_17_14_seed_warm_volume(s3_env):
    """Seed the warm MinIO volume and restart app to load it."""
    _skip_if_no_minio()
    _skip_if_no_volume()

    seed_warm_volume()
    restart_app_and_wait()

    # Re-authenticate the admin client after restart (cookies remain valid)
    admin = s3_env["admin_client"]
    volumes = await admin.list_storage_volumes()
    warm_vol = next((v for v in volumes if v["id"] == MINIO_WARM_VOLUME_ID), None)
    assert warm_vol is not None, (
        f"Warm volume {MINIO_WARM_VOLUME_ID} not found after restart: {volumes}"
    )
    assert warm_vol["tier"] == "warm"
    _state["warm_volume_seeded"] = True


def _skip_if_no_warm():
    if "warm_volume_seeded" not in _state:
        pytest.skip("17-14 did not seed the warm volume — skipping dependent test")


@pytest.mark.asyncio(loop_scope="session")
async def test_17_15_upload_file_for_migration(s3_env):
    """Upload a file that will be migrated to the warm tier in the next test."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    _skip_if_no_warm()

    # Use the admin client (user client cookies may have expired after the restart)
    client = ApiClient.from_session(s3_env["admin_session"])
    file_meta = await upload_file_api(
        client,
        filename="migration_target.bin",
        content=b"to be migrated to warm tier" * 100,
    )
    assert "id" in file_meta
    _state["migration_file_id"] = file_meta["id"]

    # Confirm it starts on the hot volume
    rows = _psql_fetch(
        f"SELECT volume_id FROM file_storage_locations "
        f"WHERE file_id = '{file_meta['id']}' AND is_primary = 1;",
        db=PG_DB_NAME,
    )
    assert rows and rows[0] == MINIO_VOLUME_ID, (
        f"File should start on hot volume {MINIO_VOLUME_ID}, got: {rows}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_17_16_tiering_pass_migrates_file(s3_env):
    """POST /admin/storage/tiering/trigger must move the file to the warm volume."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    _skip_if_no_warm()
    if "migration_file_id" not in _state:
        pytest.skip("17-15 did not produce a file — skipping")

    admin = s3_env["admin_client"]
    result = await admin.trigger_tiering_pass()
    assert result.get("ok") is True, f"Tiering trigger failed: {result}"

    file_id = _state["migration_file_id"]
    rows = _psql_fetch(
        f"SELECT volume_id, is_primary FROM file_storage_locations "
        f"WHERE file_id = '{file_id}' "
        f"ORDER BY is_primary DESC;",
        db=PG_DB_NAME,
    )
    # psql -A -t outputs pipe-separated: volume_id|is_primary
    primary_row = next((r for r in rows if r.endswith("|1")), None)
    primary_volume = primary_row.split("|")[0] if primary_row else None
    assert primary_volume == MINIO_WARM_VOLUME_ID, (
        f"Expected file primary location to be warm volume {MINIO_WARM_VOLUME_ID} "
        f"after tiering pass.  Got rows: {rows}"
    )
    _state["migration_done"] = True


@pytest.mark.asyncio(loop_scope="session")
async def test_17_17_migrated_file_still_downloadable(s3_env):
    """File moved to warm MinIO bucket must still return 200 on download."""
    _skip_if_no_minio()
    _skip_if_no_volume()
    _skip_if_no_warm()
    if "migration_file_id" not in _state:
        pytest.skip("17-15 did not produce a file — skipping")
    if "migration_done" not in _state:
        pytest.skip("17-16 did not confirm migration — skipping")

    # Refresh the admin session to ensure the access token hasn't expired — group 17
    # includes two app restarts and several slow operations that can push past the
    # 5-minute access-token TTL.  The admin_client holds the refresh token cookie.
    admin = s3_env["admin_client"]
    await admin.refresh_session()
    r = await admin.get(f"/files/{_state['migration_file_id']}/content")
    assert r.status_code == 200, (
        f"Expected 200 downloading migrated file from warm S3 bucket, "
        f"got {r.status_code}: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# 17-18  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_17_18_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
