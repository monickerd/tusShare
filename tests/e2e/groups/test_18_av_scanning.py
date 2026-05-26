"""
Group 18 — AV scanning gate.

Tests the av_require_clean download gate, batch-move gate, admin AV status
endpoint, and bulk-rescan endpoint.

Strategy
────────
The AV scanner only runs when TUSSHARE_ESCROW_PRIVATE_KEY is set and
av_scan_endpoint is configured.  Neither is present in the test container by
default, so uploaded files keep av_scan_status = NULL.

To exercise the gate against specific statuses (pending, clean, infected,
error) we seed av_scan_status directly via psql — the same pattern used by
test_17 to seed storage volumes.

The download gate (_av_gate_active) requires BOTH av_require_clean = 'true'
AND a non-empty av_scan_endpoint.  Gate tests set a fake endpoint value so
no real webhook is contacted; the setting is reset to '' after each class.

Tests
─────
18-01  Gate inactive by default → null-status file downloads (200)
18-02  Gate inactive: require_clean=true but empty endpoint → still 200
18-03  Gate active: status=null     → 451
18-04  Gate active: status=pending  → 451
18-05  Gate active: status=error    → 451
18-06  Gate active: status=infected → 451
18-07  Gate active: status=clean    → 200
18-08  Gate off (require_clean=false) → all statuses download (200)
18-09  Gate active: batch-move non-clean file → in failed list (reason av_not_clean)
18-10  Gate active: batch-move clean file → succeeds
18-11  GET /admin/files/av-status returns correct per-status counts
18-12  POST /admin/files/av-rescan returns 501 when ESCROW_PRIVATE_KEY absent
"""

from __future__ import annotations

import os
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient  # ApiClient used in _api() helper
from tests.e2e.helpers.auth   import register_via_invite
from tests.e2e.helpers.files  import upload_file_api, create_folder, batch_move_files
from tests.e2e.helpers.db     import _psql, PG_DB_NAME
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = os.getenv("TEST_APP_URL", "http://localhost:8001")
API     = f"{APP_URL}/api/v1"

_FAKE_ENDPOINT = "http://av.fake.local/scan"

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# AV gate rejections return 451 (not 403), so auth.forbidden is not emitted.
# File upload/download/move routes do not emit SIEM events.
# No SIEM events are expected from this group.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []

# Module-level state populated in setup_module fixture
_user:   dict = {}
_files:  dict = {}    # keyed by seeded status: "null", "pending", "clean", "infected", "error"
_folder: dict = {}


# ---------------------------------------------------------------------------
# Module setup: one user, six uploaded files, five seeded with specific statuses
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def av_env(browser: Browser, admin_client: AdminClient):
    global _user, _files, _folder

    url  = await admin_client.create_invite_url()
    sess = await register_via_invite(browser, url, "av_user_18", "Av!Scan99Pw")
    users = await admin_client.list_users()
    u     = next(x for x in users if x["username"].lower() == "av_user_18")
    _user = {"id": u["id"], "session": sess}

    api = ApiClient.from_session(sess)

    # Upload one file per status we want to test, plus one pristine "null"
    for label in ("null", "pending", "clean", "infected", "error"):
        f = await upload_file_api(api, f"av_test_{label}.txt", b"content", folder_id=None)
        _files[label] = f

    # Create a target folder for batch-move tests
    _folder = await create_folder(api, "AV Move Target 18")

    await api.aclose()

    # Seed av_scan_status for all files except the "null" one
    for label in ("pending", "clean", "infected", "error"):
        file_id = _files[label]["id"]
        _psql(
            f"UPDATE files SET av_scan_status = '{label}' WHERE id = '{file_id}';",
            db=PG_DB_NAME,
        )

    yield

    # Restore default settings so no state bleeds to later groups
    await admin_client.set_settings({
        "av_require_clean": "false",
        "av_scan_endpoint":  "",
    })
    await sess.ctx.close()


# ---------------------------------------------------------------------------
# Helper: toggle gate state
# ---------------------------------------------------------------------------

async def _enable_gate(admin_client: AdminClient) -> None:
    await admin_client.set_settings({
        "av_require_clean": "true",
        "av_scan_endpoint":  _FAKE_ENDPOINT,
    })


async def _disable_gate(admin_client: AdminClient) -> None:
    await admin_client.set_settings({
        "av_require_clean": "false",
        "av_scan_endpoint":  "",
    })


def _api() -> ApiClient:
    return ApiClient.from_session(_user["session"])


async def _download_status(file_id: str) -> int:
    api = _api()
    r = await api.get(f"/files/{file_id}/content")
    await api.aclose()
    return r.status_code


# ---------------------------------------------------------------------------
# 18-01 / 18-02 — Gate inactive
# ---------------------------------------------------------------------------

async def test_18_01_gate_off_null_status_downloads():
    """Default config: gate is inactive; null-status file is accessible."""
    status = await _download_status(_files["null"]["id"])
    assert status == 200


async def test_18_02_require_clean_without_endpoint_does_not_block(admin_client: AdminClient):
    """require_clean=true but empty endpoint → gate stays inactive."""
    await admin_client.set_settings({"av_require_clean": "true", "av_scan_endpoint": ""})
    try:
        status = await _download_status(_files["null"]["id"])
    finally:
        await admin_client.set_settings({"av_require_clean": "false"})
    assert status == 200


# ---------------------------------------------------------------------------
# 18-03 through 18-07 — Gate active: per-status download behaviour
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label,expected", [
    ("null",     451),
    ("pending",  451),
    ("error",    451),
    ("infected", 451),
    ("clean",    200),
])
async def test_18_gate_active_download_per_status(label, expected, admin_client: AdminClient):
    await _enable_gate(admin_client)
    try:
        status = await _download_status(_files[label]["id"])
    finally:
        await _disable_gate(admin_client)
    assert status == expected, (
        f"Expected {expected} for av_scan_status={label!r}, got {status}"
    )


# ---------------------------------------------------------------------------
# 18-08 — Gate disabled: all statuses download freely
# ---------------------------------------------------------------------------

async def test_18_08_gate_off_all_statuses_download(admin_client: AdminClient):
    await admin_client.set_settings({"av_require_clean": "false", "av_scan_endpoint": ""})

    for label, file_meta in _files.items():
        status = await _download_status(file_meta["id"])
        assert status == 200, f"Expected 200 with gate off for status={label!r}, got {status}"


# ---------------------------------------------------------------------------
# 18-09 / 18-10 — Gate active: batch-move
# ---------------------------------------------------------------------------

async def test_18_09_batch_move_non_clean_file_in_failed_list(admin_client: AdminClient):
    await _enable_gate(admin_client)
    try:
        api = _api()
        r = await api.post("/files/batch-move", json={
            "files": [{"id": _files["pending"]["id"]}],
            "destination_folder_id": _folder["id"],
        })
        await api.aclose()
    finally:
        await _disable_gate(admin_client)

    body = r.json()
    failed_ids = [f["id"] for f in body.get("failed", [])]
    assert _files["pending"]["id"] in failed_ids

    reasons = {f["id"]: f["reason"] for f in body.get("failed", [])}
    assert reasons[_files["pending"]["id"]] == "av_not_clean"


async def test_18_10_batch_move_clean_file_succeeds(admin_client: AdminClient):
    await _enable_gate(admin_client)
    try:
        api = _api()
        result = await batch_move_files(api, [_files["clean"]["id"]], _folder["id"])
        await api.aclose()
    finally:
        await _disable_gate(admin_client)

    moved_ids = result.get("succeeded", [])
    assert _files["clean"]["id"] in moved_ids
    assert _files["clean"]["id"] not in [f["id"] for f in result.get("failed", [])]


# ---------------------------------------------------------------------------
# 18-11 — Admin AV status counts
# ---------------------------------------------------------------------------

async def test_18_11_admin_av_status_counts(admin_client: AdminClient):
    """GET /admin/files/av-status reflects the seeded per-status counts.

    We uploaded exactly one file per status label (null, pending, clean,
    infected, error) so each count must be ≥ 1.  We check ≥ rather than ==
    because other tests may have left additional files in the DB.
    """
    r = await admin_client._client.get(f"{API}/admin/files/av-status")
    assert r.status_code == 200

    counts = r.json()
    for label in ("null", "pending", "clean", "infected", "error"):
        assert counts.get(label, 0) >= 1, (
            f"Expected at least 1 file with av_scan_status={label!r}, got {counts}"
        )


# ---------------------------------------------------------------------------
# 18-12 — Bulk rescan returns 501 when escrow key not configured
# ---------------------------------------------------------------------------

async def test_18_12_bulk_rescan_501_without_escrow_key(admin_client: AdminClient):
    """Test container has no ESCROW_PRIVATE_KEY → rescan endpoint returns 501."""
    r = await admin_client._client.post(f"{API}/admin/files/av-rescan")
    assert r.status_code == 501
    assert "ESCROW_PRIVATE_KEY" in r.json().get("detail", "")


# ---------------------------------------------------------------------------
# 18-13  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_18_13_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
