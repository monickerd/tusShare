"""
Group 29 — Trash / soft-delete.

Tests the full lifecycle: soft-delete (file + folder), trash listing,
restore (normal and orphaned-parent edge case), permanent delete,
empty-trash, admin setting validation, and access-control enforcement.

Endpoints exercised
-------------------
  GET    /trash                         — list soft-deleted items
  POST   /trash/files/{id}/restore      — restore a file
  POST   /trash/folders/{id}/restore    — restore a folder (recursive)
  DELETE /trash/files/{id}              — permanently delete a file
  DELETE /trash/folders/{id}            — permanently delete a folder + subtree
  DELETE /trash                         — empty all trash for the current user
  DELETE /files/{id}                    — soft-deletes when trash_enabled=true
  DELETE /folders/{id}                  — soft-deletes subtree when trash_enabled=true

Tests
-----
  29-01  Admin setting validation (trash_enabled + trash_retention_days)
  29-02  Deleting a file moves it to trash; file hidden from normal listing
  29-03  Deleting a folder moves it to trash; folder hidden from normal listing
  29-04  Root listing excludes soft-deleted files and folders
  29-05  Restore file → accessible again, removed from trash
  29-06  Restore folder (recursive) → folder + contents accessible
  29-07  Restore file whose parent folder is also deleted → file goes to root
  29-08  Permanently delete a file from trash → gone entirely
  29-09  Permanently delete a folder from trash → subtree gone
  29-10  Empty trash → all deleted items purged at once
  29-11  Access control: cannot restore another user's file (403/404)
  29-12  Access control: cannot permanently delete another user's file (403/404)
  29-13  With trash_enabled=false, DELETE /files/{id} hard-deletes immediately
  29-14  SIEM manifest assertion
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.files import (
    create_folder,
    list_root,
    list_trash,
    permanently_delete_file_from_trash,
    permanently_delete_folder_from_trash,
    restore_file_from_trash,
    restore_folder_from_trash,
    upload_file_api,
)
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_user:  dict = {}   # primary user
_other: dict = {}   # secondary user for access-control tests

# ---------------------------------------------------------------------------
# SIEM manifest
# ---------------------------------------------------------------------------

_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    # G21: restore emits file.restored (29-05 file, 29-06 folder)
    ExpectedSiemEvent("file.restored", outcome="success", severity="info", tier=1),
]


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _user, _other

    url = await admin_client.create_invite_url()
    session = await register_via_invite(browser, url, "trash_user_29", "Trash!Pass99")
    users = await admin_client.list_users()
    u = next(x for x in users if x["username"].lower() == "trash_user_29")
    _user = {
        "id":      u["id"],
        "session": session,
        "api":     ApiClient.from_session(session),
    }

    url2 = await admin_client.create_invite_url()
    session2 = await register_via_invite(browser, url2, "trash_other_29", "Trash!Other99")
    users2 = await admin_client.list_users()
    u2 = next(x for x in users2 if x["username"].lower() == "trash_other_29")
    _other = {
        "id":      u2["id"],
        "session": session2,
        "api":     ApiClient.from_session(session2),
    }

    yield

    try:
        await _user["api"].aclose()
        await session.ctx.close()
    except Exception:
        pass
    try:
        await _other["api"].aclose()
        await session2.ctx.close()
    except Exception:
        pass


# ===========================================================================
# 29-01 — Admin setting validation
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_01_admin_settings_validation(admin_client: AdminClient):
    """trash_enabled and trash_retention_days reject invalid values."""
    # trash_enabled only accepts "true" or "false"
    r = await admin_client._client.put(
        f"{API}/admin/settings",
        json={"settings": {"trash_enabled": "yes"}},
    )
    assert r.status_code == 400, f"Expected 400 for trash_enabled='yes': {r.text}"

    r = await admin_client._client.put(
        f"{API}/admin/settings",
        json={"settings": {"trash_enabled": "1"}},
    )
    assert r.status_code == 400, f"Expected 400 for trash_enabled='1': {r.text}"

    # trash_retention_days must be in range 1–3650
    r = await admin_client._client.put(
        f"{API}/admin/settings",
        json={"settings": {"trash_retention_days": "0"}},
    )
    assert r.status_code == 400, f"Expected 400 for trash_retention_days=0: {r.text}"

    r = await admin_client._client.put(
        f"{API}/admin/settings",
        json={"settings": {"trash_retention_days": "3651"}},
    )
    assert r.status_code == 400, f"Expected 400 for trash_retention_days=3651: {r.text}"

    # Valid values are accepted without error
    await admin_client.set_settings({"trash_enabled": "true", "trash_retention_days": "30"})


# ===========================================================================
# 29-02 — Soft-delete a file → appears in trash, hidden from normal listing
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_02_soft_delete_file_appears_in_trash():
    """DELETE /files/{id} moves the file to trash; GET /files/{id} returns 404."""
    api = _user["api"]

    file_meta = await upload_file_api(api, "trash_test_file.txt", b"hello trash")
    file_id = file_meta["id"]

    r = await api.delete(f"/files/{file_id}")
    assert r.status_code == 200, f"Delete failed: {r.text}"
    assert "trash" in r.json().get("message", "").lower(), (
        f"Expected 'trash' in delete message: {r.json()}"
    )

    # File hidden from normal GET
    r = await api.get(f"/files/{file_id}")
    assert r.status_code == 404, f"Expected 404 for deleted file, got {r.status_code}"

    # File visible in trash listing
    trash = await list_trash(api)
    trash_file_ids = [f["id"] for f in trash["files"]]
    assert file_id in trash_file_ids, f"File {file_id} not in trash listing"

    # Verify deleted_at is present in the trash entry
    entry = next(f for f in trash["files"] if f["id"] == file_id)
    assert entry.get("deleted_at") is not None, "deleted_at should be set in trash entry"

    await permanently_delete_file_from_trash(api, file_id)


# ===========================================================================
# 29-03 — Soft-delete a folder → appears in trash, hidden from normal listing
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_03_soft_delete_folder_appears_in_trash():
    """DELETE /folders/{id} moves folder to trash; GET /folders/{id} returns 404."""
    api = _user["api"]

    folder = await create_folder(api, "TrashFolder29")
    folder_id = folder["id"]

    r = await api.delete(f"/folders/{folder_id}")
    assert r.status_code == 200, f"Delete failed: {r.text}"
    assert "trash" in r.json().get("message", "").lower(), (
        f"Expected 'trash' in delete message: {r.json()}"
    )

    # Folder hidden from normal GET
    r = await api.get(f"/folders/{folder_id}")
    assert r.status_code == 404, f"Expected 404 for deleted folder, got {r.status_code}"

    # Folder visible in trash listing
    trash = await list_trash(api)
    trash_folder_ids = [f["id"] for f in trash["folders"]]
    assert folder_id in trash_folder_ids, f"Folder {folder_id} not in trash listing"

    await permanently_delete_folder_from_trash(api, folder_id)


# ===========================================================================
# 29-04 — Root listing excludes soft-deleted items
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_04_deleted_items_hidden_from_root_listing():
    """Files and folders in trash do not appear in the root listing."""
    api = _user["api"]

    file_meta = await upload_file_api(api, "hidden_file.txt", b"hidden")
    file_id = file_meta["id"]
    folder = await create_folder(api, "HiddenFolder29")
    folder_id = folder["id"]

    await api.delete(f"/files/{file_id}")
    await api.delete(f"/folders/{folder_id}")

    root = await list_root(api)
    root_file_ids   = [f["id"] for f in root.get("files", [])]
    root_folder_ids = [f["id"] for f in root.get("folders", [])]

    assert file_id not in root_file_ids, (
        "Soft-deleted file should not appear in root listing"
    )
    assert folder_id not in root_folder_ids, (
        "Soft-deleted folder should not appear in root listing"
    )

    await permanently_delete_file_from_trash(api, file_id)
    await permanently_delete_folder_from_trash(api, folder_id)


# ===========================================================================
# 29-05 — Restore a file
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_05_restore_file():
    """Restoring a file from trash makes it accessible again in its original folder."""
    api = _user["api"]

    folder = await create_folder(api, "RestoreParent29")
    folder_id = folder["id"]
    file_meta = await upload_file_api(api, "restore_me.txt", b"restore", folder_id=folder_id)
    file_id = file_meta["id"]

    await api.delete(f"/files/{file_id}")

    r_restore = await restore_file_from_trash(api, file_id)
    assert "restored" in r_restore.get("message", "").lower(), (
        f"Unexpected restore message: {r_restore}"
    )

    # File accessible again
    r = await api.get(f"/files/{file_id}")
    assert r.status_code == 200, f"File not accessible after restore: {r.status_code}"
    assert r.json()["file"]["folder_id"] == folder_id, (
        "Restored file should be back in its original folder"
    )

    # File no longer in trash
    trash = await list_trash(api)
    assert file_id not in [f["id"] for f in trash["files"]], (
        "Restored file should not appear in trash"
    )

    # Cleanup
    await api.delete(f"/files/{file_id}")
    await permanently_delete_file_from_trash(api, file_id)
    await api.delete(f"/folders/{folder_id}")
    await permanently_delete_folder_from_trash(api, folder_id)


# ===========================================================================
# 29-06 — Restore a folder recursively
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_06_restore_folder_recursive():
    """Restoring a folder also restores all its nested files."""
    api = _user["api"]

    folder = await create_folder(api, "RecursiveRestore29")
    folder_id = folder["id"]
    file_meta = await upload_file_api(api, "nested_file.txt", b"nested", folder_id=folder_id)
    file_id = file_meta["id"]

    # Deleting the folder soft-deletes folder + nested file
    await api.delete(f"/folders/{folder_id}")

    trash = await list_trash(api)
    assert folder_id in [f["id"] for f in trash["folders"]], "Folder should be in trash"
    assert file_id in [f["id"] for f in trash["files"]], "Nested file should be in trash"

    r_restore = await restore_folder_from_trash(api, folder_id)
    assert "restored" in r_restore.get("message", "").lower()

    # Both folder and file accessible again
    r = await api.get(f"/folders/{folder_id}")
    assert r.status_code == 200, f"Folder not accessible after restore: {r.status_code}"

    r = await api.get(f"/files/{file_id}")
    assert r.status_code == 200, f"Nested file not accessible after restore: {r.status_code}"

    # Cleanup
    await api.delete(f"/folders/{folder_id}")
    await permanently_delete_folder_from_trash(api, folder_id)


# ===========================================================================
# 29-07 — Restore file whose parent is also deleted → file goes to root
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_07_restore_file_with_deleted_parent_goes_to_root():
    """Restoring a file whose parent folder is still in trash moves it to root."""
    api = _user["api"]

    folder = await create_folder(api, "OrphanParent29")
    folder_id = folder["id"]
    file_meta = await upload_file_api(api, "orphan_file.txt", b"orphan", folder_id=folder_id)
    file_id = file_meta["id"]

    # Deleting the folder soft-deletes both folder and the file inside it
    await api.delete(f"/folders/{folder_id}")

    # Restore only the file; folder remains deleted
    await restore_file_from_trash(api, file_id)

    r = await api.get(f"/files/{file_id}")
    assert r.status_code == 200, f"Orphaned file not accessible after restore: {r.status_code}"
    assert r.json()["file"]["folder_id"] is None, (
        "File restored with deleted parent should have folder_id=null (moved to root)"
    )

    # File should appear in root listing
    root = await list_root(api)
    root_ids = [f["id"] for f in root.get("files", [])]
    assert file_id in root_ids, "Restored orphan file should appear in root listing"

    # Cleanup: folder is still in trash; file needs to be re-deleted first
    await api.delete(f"/files/{file_id}")
    await permanently_delete_file_from_trash(api, file_id)
    await permanently_delete_folder_from_trash(api, folder_id)


# ===========================================================================
# 29-08 — Permanently delete a file from trash
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_08_permanently_delete_file_from_trash():
    """DELETE /trash/files/{id} removes the file entirely (not restorable)."""
    api = _user["api"]

    file_meta = await upload_file_api(api, "purge_me.txt", b"purge me")
    file_id = file_meta["id"]

    await api.delete(f"/files/{file_id}")
    await permanently_delete_file_from_trash(api, file_id)

    # Not in trash
    trash = await list_trash(api)
    assert file_id not in [f["id"] for f in trash["files"]], (
        "Purged file should not appear in trash"
    )

    # Not accessible at all
    r = await api.get(f"/files/{file_id}")
    assert r.status_code == 404, f"Expected 404 for purged file, got {r.status_code}"


# ===========================================================================
# 29-09 — Permanently delete a folder (with subtree) from trash
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_09_permanently_delete_folder_from_trash():
    """DELETE /trash/folders/{id} purges the folder and all its contents."""
    api = _user["api"]

    folder = await create_folder(api, "PurgeFolder29")
    folder_id = folder["id"]
    file_meta = await upload_file_api(api, "purge_child.txt", b"child", folder_id=folder_id)
    file_id = file_meta["id"]

    await api.delete(f"/folders/{folder_id}")
    await permanently_delete_folder_from_trash(api, folder_id)

    # Neither folder nor child file should be in trash
    trash = await list_trash(api)
    assert folder_id not in [f["id"] for f in trash["folders"]], (
        "Purged folder should not appear in trash"
    )
    assert file_id not in [f["id"] for f in trash["files"]], (
        "Child file of purged folder should not appear in trash"
    )

    # Child file not accessible
    r = await api.get(f"/files/{file_id}")
    assert r.status_code == 404, f"Expected 404 for child of purged folder: {r.status_code}"


# ===========================================================================
# 29-10 — Empty trash
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_10_empty_trash():
    """DELETE /trash removes all soft-deleted items for the current user at once."""
    api = _user["api"]

    file1 = await upload_file_api(api, "empty1.txt", b"empty1")
    file2 = await upload_file_api(api, "empty2.txt", b"empty2")
    folder = await create_folder(api, "EmptyMe29")
    await api.delete(f"/files/{file1['id']}")
    await api.delete(f"/files/{file2['id']}")
    await api.delete(f"/folders/{folder['id']}")

    trash_before = await list_trash(api)
    assert len(trash_before["files"]) >= 2, (
        f"Expected ≥2 files in trash before empty, got {len(trash_before['files'])}"
    )
    assert len(trash_before["folders"]) >= 1, (
        f"Expected ≥1 folder in trash before empty, got {len(trash_before['folders'])}"
    )

    r = await api.delete("/trash")
    assert r.status_code == 200
    assert "emptied" in r.json().get("message", "").lower(), (
        f"Unexpected empty-trash message: {r.json()}"
    )

    trash_after = await list_trash(api)
    assert trash_after["files"] == [], (
        f"Files still in trash after empty: {trash_after['files']}"
    )
    assert trash_after["folders"] == [], (
        f"Folders still in trash after empty: {trash_after['folders']}"
    )


# ===========================================================================
# 29-11 — Access control: cannot restore another user's file
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_11_access_control_cannot_restore_other_users_file():
    """User B cannot restore a trashed file owned by User A."""
    api_a = _user["api"]
    api_b = _other["api"]

    file_meta = await upload_file_api(api_a, "private.txt", b"private")
    file_id = file_meta["id"]
    await api_a.delete(f"/files/{file_id}")

    r = await api_b.post(f"/trash/files/{file_id}/restore")
    assert r.status_code in (403, 404), (
        f"Expected 403/404 when restoring another user's file, got {r.status_code}: {r.text}"
    )

    await permanently_delete_file_from_trash(api_a, file_id)


# ===========================================================================
# 29-12 — Access control: cannot permanently delete another user's file
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_12_access_control_cannot_purge_other_users_file():
    """User B cannot permanently delete a trashed file owned by User A."""
    api_a = _user["api"]
    api_b = _other["api"]

    file_meta = await upload_file_api(api_a, "private2.txt", b"private2")
    file_id = file_meta["id"]
    await api_a.delete(f"/files/{file_id}")

    r = await api_b.delete(f"/trash/files/{file_id}")
    assert r.status_code in (403, 404), (
        f"Expected 403/404 when purging another user's file, got {r.status_code}: {r.text}"
    )

    await permanently_delete_file_from_trash(api_a, file_id)


# ===========================================================================
# 29-13 — With trash_enabled=false, delete is an immediate hard delete
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_29_13_trash_disabled_hard_deletes_immediately(admin_client: AdminClient):
    """When trash_enabled=false, DELETE /files/{id} and DELETE /folders/{id} bypass trash."""
    api = _user["api"]

    try:
        await admin_client.set_setting("trash_enabled", "false")

        # File hard-delete
        file_meta = await upload_file_api(api, "no_trash.txt", b"no trash")
        file_id = file_meta["id"]
        r = await api.delete(f"/files/{file_id}")
        assert r.status_code == 200

        trash = await list_trash(api)
        assert file_id not in [f["id"] for f in trash["files"]], (
            "Hard-deleted file should not appear in trash"
        )
        r = await api.get(f"/files/{file_id}")
        assert r.status_code == 404, (
            f"Hard-deleted file should return 404, got {r.status_code}"
        )

        # Folder hard-delete
        folder = await create_folder(api, "NoTrashFolder29")
        folder_id = folder["id"]
        r = await api.delete(f"/folders/{folder_id}")
        assert r.status_code == 200
        assert "trash" not in r.json().get("message", "").lower(), (
            f"Hard-delete should not mention trash: {r.json()}"
        )

        trash2 = await list_trash(api)
        assert folder_id not in [f["id"] for f in trash2["folders"]], (
            "Hard-deleted folder should not appear in trash"
        )

    finally:
        await admin_client.set_setting("trash_enabled", "true")


# ---------------------------------------------------------------------------
# 29-14  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_29_14_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
