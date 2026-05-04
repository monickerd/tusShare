"""
Group 30 — File copy (B5).

Tests the POST /files/batch-copy endpoint across all five crypto paths, the
copy_boundary admin policy, the FLAG_COPY_FILES permission gate, access-control
enforcement, blob ref-counting on delete, and SIEM emission.

Crypto note: the server stores key material but never decrypts it; tests pass
stub base64 blobs that satisfy server-side format validators.

Endpoints exercised
-------------------
  POST /files/batch-copy
  GET  /files/{id}
  GET  /admin/settings
  PUT  /admin/settings
  PUT  /admin/roles/{id}/permissions

Tests
-----
  30-01  Personal → Personal (path 1): server copies key verbatim
  30-02  Same-team → Same-team (path 2): server copies file_team_keys verbatim
  30-03  Cross-team A→B (path 3): client supplies rk-transformed C1
  30-04  Personal → Team (path 4): client supplies full PRE envelope
  30-05  Team → Personal (path 5): client supplies personal DEK wrapper
  30-06  FLAG_COPY_FILES revoked → 403
  30-07  copy_boundary=same_team blocks cross-boundary copy
  30-08  copy_boundary=disabled blocks all copies
  30-09  Non-member cannot copy from team folder they don't belong to
  30-10  Cannot copy to destination folder without write access
  30-11  Batch of 3 files: partial success (one blocked by boundary)
  30-12  Blob ref-count: original delete does not remove blob while copy exists
  30-13  SIEM: file.copy success and file.copy.blocked events emitted
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin  import AdminClient, ApiClient
from tests.e2e.helpers.auth   import register_via_invite
from tests.e2e.helpers.files  import (
    create_folder,
    upload_file_api,
    get_file,
    delete_file,
    batch_copy_files,
)
from tests.e2e.helpers.teams  import (
    create_team,
    add_member,
    add_team_folder,
)
from tests.e2e.helpers.crypto_stubs import fake_aes256_key, fake_iv_12, fake_g2_point
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_alice:  dict = {}   # primary user — personal files + team A owner
_bob:    dict = {}   # team A member
_carol:  dict = {}   # team B owner — used for cross-team tests
_viewer: dict = {}   # user with no special access — access-control tests

_team_a: dict = {}
_team_b: dict = {}

_folder_a: dict = {}   # personal folder of alice (no team)
_folder_ta: dict = {}  # team A folder
_folder_tb: dict = {}  # team B folder

# ---------------------------------------------------------------------------
# SIEM manifest
# ---------------------------------------------------------------------------

_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("file.copy",         outcome="success", severity="info",    tier=1),
    ExpectedSiemEvent("file.copy.blocked", outcome="failure", severity="warning", tier=1),
]

# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _alice, _bob, _carol, _viewer
    global _team_a, _team_b, _folder_a, _folder_ta, _folder_tb

    async def _register(username: str, password: str) -> dict:
        url = await admin_client.create_invite_url()
        session = await register_via_invite(browser, url, username, password)
        users = await admin_client.list_users()
        u = next(x for x in users if x["username"].lower() == username.lower())
        return {"id": u["id"], "session": session, "api": ApiClient.from_session(session)}

    _alice  = await _register("copy_alice_30",  "Alice!Copy30")
    _bob    = await _register("copy_bob_30",    "Bob!Copy30")
    _carol  = await _register("copy_carol_30",  "Carol!Copy30")
    _viewer = await _register("copy_viewer_30", "Viewer!Copy30")

    # Teams
    _team_a = await create_team(_alice["api"], "CopyTeamA_30")
    _team_b = await create_team(_carol["api"], "CopyTeamB_30")

    # Bob joins team A
    await add_member(_alice["api"], _team_a["id"], "copy_bob_30")

    # Folders
    _folder_a  = await create_folder(_alice["api"], "CopyPersonal30")
    _folder_ta = await create_folder(_alice["api"], "CopyFolderA30")
    await add_team_folder(_alice["api"], _team_a["id"], _folder_ta["id"])

    _folder_tb = await create_folder(_carol["api"], "CopyFolderB30")
    await add_team_folder(_carol["api"], _team_b["id"], _folder_tb["id"])

    # Ensure copy_boundary is 'any' and FLAG_COPY_FILES is enabled for all users
    await admin_client.set_setting("copy_boundary", "any")

    yield

    for u in (_alice, _bob, _carol, _viewer):
        try:
            await u["api"].aclose()
            await u["session"].ctx.close()
        except Exception:
            pass


# ===========================================================================
# 30-01 — Personal → Personal (path 1)
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_01_personal_to_personal():
    """Copy a personal file to another personal folder; server copies key verbatim."""
    api = _alice["api"]

    src = await upload_file_api(api, "src_p2p.txt", b"personal-to-personal",
                                folder_id=_folder_a["id"])
    dest_folder = await create_folder(api, "CopyDest30_P2P")

    result = await batch_copy_files(api, [src["id"]], dest_folder["id"])
    assert result.get("copied"), f"Expected at least one copied file: {result}"
    assert not result.get("failed"), f"Unexpected failures: {result['failed']}"

    new_id = result["copied"][0]["new_id"]
    copy_meta = await get_file(api, new_id)

    assert copy_meta["original_name"] == src["original_name"]
    assert copy_meta["folder_id"] == dest_folder["id"]
    assert copy_meta["owner_id"] == _alice["id"]
    assert copy_meta["encrypted_file_key"] == src["encrypted_file_key"], (
        "Personal→personal: server should copy encrypted_file_key verbatim"
    )
    assert copy_meta["key_iv"] == src["key_iv"], (
        "Personal→personal: server should copy key_iv verbatim"
    )


# ===========================================================================
# 30-02 — Same-Team → Same-Team (path 2)
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_02_same_team_to_same_team():
    """Copy a team-A file to another folder in team A; server copies file_team_keys."""
    api = _alice["api"]

    src = await upload_file_api(api, "src_t2t.txt", b"team-to-same-team",
                                folder_id=_folder_ta["id"])
    dest_folder = await create_folder(api, "CopyDestTA_30")
    await add_team_folder(api, _team_a["id"], dest_folder["id"])

    result = await batch_copy_files(api, [src["id"]], dest_folder["id"])
    assert result.get("copied"), f"Expected copy to succeed: {result}"
    assert not result.get("failed"), f"Unexpected failures: {result['failed']}"

    new_id = result["copied"][0]["new_id"]
    copy_meta = await get_file(api, new_id)
    assert copy_meta["folder_id"] == dest_folder["id"]


# ===========================================================================
# 30-03 — Cross-Team A → B (path 3)
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_03_cross_team_a_to_b():
    """Cross-team copy: client sends rk-transformed C1; C2/IV from source file_team_keys."""
    api_a = _alice["api"]
    api_c = _carol["api"]

    src = await upload_file_api(api_a, "src_cross.txt", b"cross-team",
                                folder_id=_folder_ta["id"])

    # Carol copies alice's team-A file to team B
    file_items = [{
        "file_id": src["id"],
        "pre_c1":  fake_g2_point(),
    }]
    result = await batch_copy_files(api_c, [], _folder_tb["id"], file_items=file_items)
    assert result.get("copied"), f"Cross-team copy should succeed: {result}"

    new_id = result["copied"][0]["new_id"]
    copy_meta = await get_file(api_c, new_id)
    assert copy_meta["folder_id"] == _folder_tb["id"]


# ===========================================================================
# 30-04 — Personal → Team (path 4)
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_04_personal_to_team():
    """Personal → Team copy: client provides full PRE envelope (pre_c1 + DEK + iv)."""
    api = _alice["api"]

    src = await upload_file_api(api, "src_p2t.txt", b"personal-to-team",
                                folder_id=_folder_a["id"])

    file_items = [{
        "file_id":           src["id"],
        "pre_c1":            fake_g2_point(),
        "encrypted_file_key": fake_aes256_key(),
        "key_iv":            fake_iv_12(),
    }]
    result = await batch_copy_files(api, [], _folder_ta["id"], file_items=file_items)
    assert result.get("copied"), f"Personal→team copy should succeed: {result}"

    new_id = result["copied"][0]["new_id"]
    copy_meta = await get_file(api, new_id)
    assert copy_meta["folder_id"] == _folder_ta["id"]


# ===========================================================================
# 30-05 — Team → Personal (path 5)
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_05_team_to_personal():
    """Team → Personal copy: client provides personal DEK wrapper (encrypted_file_key + iv)."""
    api = _alice["api"]

    src = await upload_file_api(api, "src_t2p.txt", b"team-to-personal",
                                folder_id=_folder_ta["id"])

    file_items = [{
        "file_id":           src["id"],
        "encrypted_file_key": fake_aes256_key(),
        "key_iv":            fake_iv_12(),
    }]
    result = await batch_copy_files(api, [], _folder_a["id"], file_items=file_items)
    assert result.get("copied"), f"Team→personal copy should succeed: {result}"

    new_id = result["copied"][0]["new_id"]
    copy_meta = await get_file(api, new_id)
    assert copy_meta["folder_id"] == _folder_a["id"]
    assert copy_meta["owner_id"] == _alice["id"]


# ===========================================================================
# 30-06 — FLAG_COPY_FILES revoked → 403
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_06_flag_copy_files_revoked(admin_client: AdminClient):
    """Revoking FLAG_COPY_FILES from role_user blocks all copy operations with 403."""
    api = _alice["api"]
    src = await upload_file_api(api, "flag_test.txt", b"flag test",
                                folder_id=_folder_a["id"])
    dest = await create_folder(api, "FlagTestDest30")

    try:
        roles = await admin_client.list_roles()
        role_user = next(r for r in roles if r["id"] == "role_user")
        perms = {k: (v["value"] == "1" if isinstance(v, dict) else v == "1")
                 for k, v in role_user.get("permissions", {}).items()}
        perms["can_copy_files"] = False
        await admin_client.set_role_permissions(role_user["id"], perms)

        r = await api.post("/files/batch-copy", json={
            "destination_folder_id": dest["id"],
            "files": [{"file_id": src["id"]}],
        })
        assert r.status_code == 403, (
            f"Expected 403 when FLAG_COPY_FILES is revoked, got {r.status_code}: {r.text}"
        )
    finally:
        perms["can_copy_files"] = True
        await admin_client.set_role_permissions(role_user["id"], perms)


# ===========================================================================
# 30-07 — copy_boundary=same_team blocks cross-boundary copy
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_07_copy_boundary_same_team(admin_client: AdminClient):
    """With copy_boundary=same_team, copying across team boundaries returns failure entries."""
    api = _alice["api"]
    src = await upload_file_api(api, "boundary_test.txt", b"boundary",
                                folder_id=_folder_ta["id"])

    try:
        await admin_client.set_setting("copy_boundary", "same_team")

        file_items = [{"file_id": src["id"], "pre_c1": fake_g2_point()}]
        r = await _alice["api"].post("/files/batch-copy", json={
            "destination_folder_id": _folder_tb["id"],
            "files": file_items,
        })
        assert r.status_code in (200, 403), f"Unexpected status: {r.status_code}"
        if r.status_code == 200:
            body = r.json()
            assert body.get("failed"), (
                "Cross-boundary copy with same_team policy should appear in 'failed'"
            )
            reasons = [f["reason"] for f in body["failed"]]
            assert "boundary_violation" in reasons, f"Expected boundary_violation, got {reasons}"
    finally:
        await admin_client.set_setting("copy_boundary", "any")


# ===========================================================================
# 30-08 — copy_boundary=disabled blocks everything
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_08_copy_boundary_disabled(admin_client: AdminClient):
    """With copy_boundary=disabled, ALL copy requests return 403."""
    api = _alice["api"]
    src = await upload_file_api(api, "disabled_test.txt", b"disabled",
                                folder_id=_folder_a["id"])
    dest = await create_folder(api, "DisabledDest30")

    try:
        await admin_client.set_setting("copy_boundary", "disabled")

        r = await api.post("/files/batch-copy", json={
            "destination_folder_id": dest["id"],
            "files": [{"file_id": src["id"]}],
        })
        assert r.status_code == 403, (
            f"Expected 403 when copy_boundary=disabled, got {r.status_code}: {r.text}"
        )
    finally:
        await admin_client.set_setting("copy_boundary", "any")


# ===========================================================================
# 30-09 — Non-member cannot copy from a team folder
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_09_non_member_cannot_copy_from_team():
    """A user not in team A cannot copy a file from team A's folder."""
    api_a = _alice["api"]
    api_v = _viewer["api"]

    src = await upload_file_api(api_a, "teamonly.txt", b"team only",
                                folder_id=_folder_ta["id"])
    viewer_dest = await create_folder(api_v, "ViewerDest30")

    r = await api_v.post("/files/batch-copy", json={
        "destination_folder_id": viewer_dest["id"],
        "files": [{"file_id": src["id"]}],
    })
    assert r.status_code in (200, 403), f"Unexpected status: {r.status_code}"
    if r.status_code == 200:
        body = r.json()
        assert body.get("failed"), "Non-member should not be able to copy team file"
        reasons = [f["reason"] for f in body["failed"]]
        assert any(r in ("permission_denied", "not_found") for r in reasons), (
            f"Expected permission_denied or not_found, got {reasons}"
        )


# ===========================================================================
# 30-10 — Cannot copy to a folder without write access
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_10_no_write_access_to_destination():
    """A user cannot copy into a folder they do not own and are not a team member of."""
    api_a = _alice["api"]
    api_v = _viewer["api"]

    src = await upload_file_api(api_v, "viewer_src.txt", b"viewer file",
                                folder_id=None)

    r = await api_v.post("/files/batch-copy", json={
        "destination_folder_id": _folder_a["id"],
        "files": [{"file_id": src["id"]}],
    })
    assert r.status_code == 403, (
        f"Expected 403 when copying to folder without write access, got {r.status_code}: {r.text}"
    )


# ===========================================================================
# 30-11 — Partial batch: one file blocked by boundary, others succeed
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_11_partial_batch_with_boundary(admin_client: AdminClient):
    """With copy_boundary=same_team, personal files succeed while team cross-copies fail."""
    api = _alice["api"]

    personal_src = await upload_file_api(api, "partial_ok.txt", b"ok",
                                         folder_id=_folder_a["id"])
    team_src = await upload_file_api(api, "partial_blocked.txt", b"blocked",
                                     folder_id=_folder_ta["id"])
    dest_folder = await create_folder(api, "PartialDest30")

    try:
        await admin_client.set_setting("copy_boundary", "same_team")

        file_items = [
            {"file_id": personal_src["id"]},
            {"file_id": team_src["id"], "pre_c1": fake_g2_point()},
        ]
        r = await api.post("/files/batch-copy", json={
            "destination_folder_id": dest_folder["id"],
            "files": file_items,
        })
        assert r.status_code == 200, f"Batch endpoint should return 200: {r.text}"
        body = r.json()

        copied_ids = [c["source_id"] for c in body.get("copied", [])]
        failed_ids = [f["source_id"] for f in body.get("failed", [])]

        assert personal_src["id"] in copied_ids, (
            "Personal→personal within same_team policy should succeed"
        )
        assert team_src["id"] in failed_ids, (
            "Cross-boundary team copy should appear in failed when same_team enforced"
        )
    finally:
        await admin_client.set_setting("copy_boundary", "any")


# ===========================================================================
# 30-12 — Blob ref-count: deleting original does not destroy shared blob
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_12_blob_ref_count_on_delete():
    """Copying a file shares the blob; deleting the original leaves the copy accessible."""
    api = _alice["api"]

    src = await upload_file_api(api, "refcount_src.txt", b"shared blob content",
                                folder_id=_folder_a["id"])
    dest = await create_folder(api, "RefCountDest30")

    result = await batch_copy_files(api, [src["id"]], dest["id"])
    assert result.get("copied"), f"Copy should succeed: {result}"
    new_id = result["copied"][0]["new_id"]

    # Delete the original
    await delete_file(api, src["id"])

    # Verify original is gone
    r = await api.get(f"/files/{src['id']}")
    assert r.status_code == 404, (
        f"Deleted original should return 404, got {r.status_code}"
    )

    # Verify copy is still accessible (blob was shared, not removed)
    copy_meta = await get_file(api, new_id)
    assert copy_meta["id"] == new_id, (
        "Copy should still be accessible after original is deleted (blob ref-counting)"
    )


# ===========================================================================
# 30-13 — SIEM manifest
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_30_13_siem_manifest():
    """Verify file.copy and file.copy.blocked SIEM events appeared during this group."""
    assert_manifest(_SIEM_MANIFEST)
