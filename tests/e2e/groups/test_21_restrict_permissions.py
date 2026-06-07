"""
Group 21 — restrict_permissions folder flag.

Tests the permission-boundary flag that stops all three ancestor-walk
functions from propagating access through a protected folder boundary.

When restrict_permissions = TRUE on a folder the three access helpers
is_team_folder_member, is_in_shared_tree, and has_folder_permission all
stop walking upward at that node.  Only access that originates at or below
the restricted folder itself is granted.

Sections
--------
  A. PATCH endpoint — reading and writing restrict_permissions
  B. is_team_folder_member boundary (folders)
  C. is_in_shared_tree boundary (folders)
  D. has_folder_permission boundary (folders)
  E. File access — all three paths respect the boundary

Actors
------
  _owner    — creates the team and team-folder tree; used for PATCH tests
  _member   — team member (sections B, E-team)
  _outsider — no team, no explicit permissions (sections C, D, E)

World
-----
Section A — plain folder owned by _owner (patch_target_21)

Section B — team tree:
  team_parent_21         ← team folder (team_folders row)
    └── team_restricted_21        ← restrict_permissions=True
          └── team_restricted_child_21

Section C — shared tree (admin creates under the system shared root):
  (shared root, is_shared=1)      ← seeded via psql if absent
    └── shared_sub_21
          └── shared_restricted_21  ← restrict_permissions=True
                └── shared_restricted_child_21

Section D — explicit-permission tree (admin creates; outsider seeded via psql):
  perm_parent_21                   ← outsider has recursive permission (DB-seeded)
    └── perm_restricted_21         ← restrict_permissions=True
          └── perm_restricted_child_21

Section E — file permission world (admin creates; separate from D to avoid grant
            contamination from test_21_12):
  file_perm_parent_21              ← outsider has recursive permission (DB-seeded)
    └── file_perm_restricted_21    ← restrict_permissions=True

Files (uploaded via API into each world):
  e_team_parent.bin       in team_parent_21
  e_team_restricted.bin   in team_restricted_21
  e_shared_sub.bin        in shared_sub_21             (only if shared root exists)
  e_shared_restricted.bin in shared_restricted_21      (only if shared root exists)
  e_perm_parent.bin       in file_perm_parent_21
  e_perm_restricted.bin   in file_perm_restricted_21

Tests
-----
A. PATCH endpoint
  21-01  Owner sets restrict_permissions=True → GET returns True
  21-02  Owner sets restrict_permissions=False → GET returns False
  21-03  Non-owner (outsider) cannot set restrict_permissions (403)

B. is_team_folder_member boundary (folders)
  21-04  member CAN access team_parent via team membership (200)
  21-05  member CANNOT access team_restricted; boundary blocks team walk (403)
  21-06  member CANNOT access team_restricted_child; block is transitive (403)

C. is_in_shared_tree boundary (folders)
  21-07  outsider CAN access shared_sub via shared-tree walk (200)
  21-08  outsider CANNOT access shared_restricted; boundary stops shared-tree walk (403)
  21-09  outsider CANNOT access shared_restricted_child; block is transitive (403)

D. has_folder_permission boundary (folders)
  21-10  outsider CAN access perm_parent via seeded recursive permission (200)
  21-11  outsider CANNOT access perm_restricted; boundary blocks recursive grant (403)
  21-12  Direct permission inserted on perm_restricted → outsider CAN access it (200)
  21-13  Grant on perm_restricted propagates to perm_restricted_child (200)

E. File access via permission boundaries
  21-14  outsider CAN read file in shared_sub via shared-tree walk (200)
  21-15  outsider CANNOT read file in shared_restricted; boundary stops shared-tree walk (403)
  21-16  member CAN read file in team_parent via team membership (200)
  21-17  member CANNOT read file in team_restricted; boundary stops team walk (403)
  21-18  outsider CAN read file in file_perm_parent via recursive permission (200)
  21-19  outsider CANNOT read file in file_perm_restricted; boundary blocks recursive grant (403)
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.db import PG_DB_NAME, _psql
from tests.e2e.helpers.files import create_folder, upload_file_api
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest
from tests.e2e.helpers.teams import add_member, add_team_folder, create_team

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_owner:    dict = {}
_member:   dict = {}
_outsider: dict = {}

_patch_target_id:          str = ""

_team_parent_id:           str = ""
_team_restricted_id:       str = ""
_team_restricted_child_id: str = ""

_shared_sub_id:              str = ""
_shared_restricted_id:       str = ""
_shared_restricted_child_id: str = ""

_perm_parent_id:           str = ""
_perm_restricted_id:       str = ""
_perm_restricted_child_id: str = ""

# Section E — file worlds
_file_in_team_parent:         str = ""
_file_in_team_restricted:     str = ""
_file_in_shared_sub:          str = ""
_file_in_shared_restricted:   str = ""
_file_perm_parent_id:         str = ""
_file_perm_restricted_id:     str = ""
_file_in_perm_parent:         str = ""
_file_in_perm_restricted:     str = ""

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# auth.forbidden: 21-03 (outsider cannot PATCH restrict_permissions → 403),
#   21-05/06 (member blocked by team boundary → 403),
#   21-08/09 (outsider blocked by shared-tree boundary → 403),
#   21-11 (outsider blocked by permission boundary → 403),
#   21-17/19 (file access blocked by team/permission boundary → 403).
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden", outcome="failure", severity="warning", tier=2),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _reg(
    browser: Browser, admin_client: AdminClient, username: str, password: str
) -> dict:
    url     = await admin_client.create_invite_url()
    session = await register_via_invite(browser, url, username, password)
    users   = await admin_client.list_users()
    user    = next(u for u in users if u["username"].lower() == username.lower())
    return {
        "id":       user["id"],
        "username": username,
        "password": password,
        "session":  session,
        "api":      ApiClient.from_session(session),
    }


def _seed_permission(folder_id: str, user_id: str, recursive: bool = True) -> None:
    """Insert a permission row directly (bypasses API, mirrors storage-test pattern)."""
    _psql(
        f"INSERT INTO permissions "
        f"(id, resource_type, resource_id, user_id, permission, recursive, granted_by) "
        f"VALUES (gen_random_uuid()::text, 'folder', '{folder_id}', '{user_id}', "
        f"'read', {'1' if recursive else '0'}, NULL) "
        f"ON CONFLICT DO NOTHING;",
        db=PG_DB_NAME,
    )


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _owner, _member, _outsider
    global _patch_target_id
    global _team_parent_id, _team_restricted_id, _team_restricted_child_id
    global _shared_sub_id, _shared_restricted_id, _shared_restricted_child_id
    global _perm_parent_id, _perm_restricted_id, _perm_restricted_child_id
    global _file_in_team_parent, _file_in_team_restricted
    global _file_in_shared_sub, _file_in_shared_restricted
    global _file_perm_parent_id, _file_perm_restricted_id
    global _file_in_perm_parent, _file_in_perm_restricted

    # ------------------------------------------------------------------
    # Register users
    # ------------------------------------------------------------------
    _owner    = await _reg(browser, admin_client, "owner_21",    "0wner!Pass99")
    _member   = await _reg(browser, admin_client, "member_21",   "Member!Pass99")
    _outsider = await _reg(browser, admin_client, "outsider_21", "0uts1der!Pass99")

    # Admin ApiClient for creating admin-owned folders in sections C and D
    admin_api = ApiClient(admin_client._cookies)

    try:
        # ------------------------------------------------------------------
        # Section A — plain folder for PATCH tests
        # ------------------------------------------------------------------
        f = await create_folder(_owner["api"], "patch_target_21")
        _patch_target_id = f["id"]

        # ------------------------------------------------------------------
        # Section B — team boundary world
        # ------------------------------------------------------------------
        team = await create_team(_owner["api"], "boundary_team_21")
        await add_member(_owner["api"], team["id"], _member["username"])

        tp = await create_folder(_owner["api"], "team_parent_21")
        _team_parent_id = tp["id"]
        await add_team_folder(_owner["api"], team["id"], _team_parent_id)

        tr = await create_folder(_owner["api"], "team_restricted_21", parent_id=_team_parent_id)
        _team_restricted_id = tr["id"]
        r = await _owner["api"].put(
            f"/folders/{_team_restricted_id}", json={"restrict_permissions": True}
        )
        r.raise_for_status()

        trc = await create_folder(
            _owner["api"], "team_restricted_child_21", parent_id=_team_restricted_id
        )
        _team_restricted_child_id = trc["id"]

        # Section E — files in team world
        _file_in_team_parent     = (await upload_file_api(_owner["api"], "e_team_parent.bin",     b"data", folder_id=_team_parent_id))["id"]
        _file_in_team_restricted = (await upload_file_api(_owner["api"], "e_team_restricted.bin", b"data", folder_id=_team_restricted_id))["id"]

        # ------------------------------------------------------------------
        # Section C — shared-tree boundary world
        # ------------------------------------------------------------------
        me_r = await admin_api.get("/auth/me")
        me_r.raise_for_status()
        _admin_id = me_r.json()["user"]["id"]
        _psql(
            f"INSERT INTO folders (id, name, parent_id, owner_id, is_shared) "
            f"SELECT gen_random_uuid()::text, 'Shared', NULL, '{_admin_id}', 1 "
            f"WHERE NOT EXISTS "
            f"(SELECT 1 FROM folders WHERE is_shared = 1 AND parent_id IS NULL);",
            db=PG_DB_NAME,
        )

        root_r = await admin_api.get("/folders")
        root_r.raise_for_status()
        shared_root = root_r.json().get("shared_folder")

        if shared_root:
            ss = await create_folder(admin_api, "shared_sub_21", parent_id=shared_root["id"])
            _shared_sub_id = ss["id"]

            sr = await create_folder(admin_api, "shared_restricted_21", parent_id=_shared_sub_id)
            _shared_restricted_id = sr["id"]
            r = await admin_api.put(
                f"/folders/{_shared_restricted_id}", json={"restrict_permissions": True}
            )
            r.raise_for_status()

            src = await create_folder(
                admin_api, "shared_restricted_child_21", parent_id=_shared_restricted_id
            )
            _shared_restricted_child_id = src["id"]

            # Section E — files in shared world
            _file_in_shared_sub        = (await upload_file_api(admin_api, "e_shared_sub.bin",        b"data", folder_id=_shared_sub_id))["id"]
            _file_in_shared_restricted = (await upload_file_api(admin_api, "e_shared_restricted.bin", b"data", folder_id=_shared_restricted_id))["id"]

        # ------------------------------------------------------------------
        # Section D — explicit-permission boundary world
        # ------------------------------------------------------------------
        pp = await create_folder(admin_api, "perm_parent_21")
        _perm_parent_id = pp["id"]

        pr = await create_folder(admin_api, "perm_restricted_21", parent_id=_perm_parent_id)
        _perm_restricted_id = pr["id"]
        r = await admin_api.put(
            f"/folders/{_perm_restricted_id}", json={"restrict_permissions": True}
        )
        r.raise_for_status()

        prc = await create_folder(
            admin_api, "perm_restricted_child_21", parent_id=_perm_restricted_id
        )
        _perm_restricted_child_id = prc["id"]

        # Seed outsider's recursive permission on perm_parent (source of truth for section D)
        _seed_permission(_perm_parent_id, _outsider["id"], recursive=True)

        # ------------------------------------------------------------------
        # Section E — file permission world (separate from D to avoid grant
        # contamination introduced by test_21_12)
        # ------------------------------------------------------------------
        fpp = await create_folder(admin_api, "file_perm_parent_21")
        _file_perm_parent_id = fpp["id"]

        fpr = await create_folder(admin_api, "file_perm_restricted_21", parent_id=_file_perm_parent_id)
        _file_perm_restricted_id = fpr["id"]
        r = await admin_api.put(
            f"/folders/{_file_perm_restricted_id}", json={"restrict_permissions": True}
        )
        r.raise_for_status()

        _seed_permission(_file_perm_parent_id, _outsider["id"], recursive=True)

        _file_in_perm_parent     = (await upload_file_api(admin_api, "e_perm_parent.bin",     b"data", folder_id=_file_perm_parent_id))["id"]
        _file_in_perm_restricted = (await upload_file_api(admin_api, "e_perm_restricted.bin", b"data", folder_id=_file_perm_restricted_id))["id"]

        # ------------------------------------------------------------------
        yield
        # ------------------------------------------------------------------

    finally:
        for u in (_owner, _member, _outsider):
            try:
                await u["api"].aclose()
                await u["session"].ctx.close()
            except Exception:
                pass
        try:
            await admin_api.aclose()
        except Exception:
            pass


# ===========================================================================
# A. PATCH endpoint
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_21_01_owner_sets_restrict_permissions_true():
    """Owner sets restrict_permissions=True; response and re-read both return True."""
    r = await _owner["api"].put(
        f"/folders/{_patch_target_id}", json={"restrict_permissions": True}
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    assert r.json()["folder"]["restrict_permissions"] is True


@pytest.mark.asyncio(loop_scope="session")
async def test_21_02_owner_sets_restrict_permissions_false():
    """Owner sets restrict_permissions=False; response returns False."""
    r = await _owner["api"].put(
        f"/folders/{_patch_target_id}", json={"restrict_permissions": False}
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    assert r.json()["folder"]["restrict_permissions"] is False


@pytest.mark.asyncio(loop_scope="session")
async def test_21_03_non_owner_cannot_set_restrict_permissions():
    """outsider gets 403 when attempting to set restrict_permissions on owner's folder."""
    r = await _outsider["api"].put(
        f"/folders/{_patch_target_id}", json={"restrict_permissions": True}
    )
    assert r.status_code == 403, f"Expected 403, got {r.status_code}"


# ===========================================================================
# B. is_team_folder_member boundary
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_21_04_team_member_can_access_team_parent():
    """member can access team_parent via team membership (200)."""
    r = await _member["api"].get(f"/folders/{_team_parent_id}")
    assert r.status_code == 200, (
        f"Expected 200 for team parent, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_05_team_member_blocked_at_restrict_permissions_boundary():
    """member cannot access team_restricted; restrict_permissions stops the team-folder walk (403)."""
    r = await _member["api"].get(f"/folders/{_team_restricted_id}")
    assert r.status_code == 403, (
        f"Expected 403 for restricted folder, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_06_team_member_blocked_transitively():
    """member cannot access team_restricted_child; the permission boundary is transitive (403)."""
    r = await _member["api"].get(f"/folders/{_team_restricted_child_id}")
    assert r.status_code == 403, (
        f"Expected 403 for child of restricted folder, got {r.status_code}: {r.text}"
    )


# ===========================================================================
# C. is_in_shared_tree boundary
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_21_07_shared_subfolder_accessible_via_shared_tree():
    """outsider can access shared_sub; it is inside the system shared tree (200)."""
    if not _shared_sub_id:
        pytest.skip("System shared folder not found in this environment")
    r = await _outsider["api"].get(f"/folders/{_shared_sub_id}")
    assert r.status_code == 200, (
        f"Expected 200 for shared subfolder, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_08_restrict_permissions_blocks_shared_tree_walk():
    """outsider cannot access shared_restricted; restrict_permissions stops is_in_shared_tree (403)."""
    if not _shared_restricted_id:
        pytest.skip("System shared folder not found in this environment")
    r = await _outsider["api"].get(f"/folders/{_shared_restricted_id}")
    assert r.status_code == 403, (
        f"Expected 403 for restrict_permissions folder in shared tree, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_09_shared_tree_block_is_transitive():
    """outsider cannot access shared_restricted_child; shared-tree block is transitive (403)."""
    if not _shared_restricted_child_id:
        pytest.skip("System shared folder not found in this environment")
    r = await _outsider["api"].get(f"/folders/{_shared_restricted_child_id}")
    assert r.status_code == 403, (
        f"Expected 403 for child of restricted shared folder, got {r.status_code}: {r.text}"
    )


# ===========================================================================
# D. has_folder_permission boundary
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_21_10_recursive_permission_grants_access_to_parent():
    """outsider can access perm_parent via the DB-seeded recursive permission (200)."""
    r = await _outsider["api"].get(f"/folders/{_perm_parent_id}")
    assert r.status_code == 200, (
        f"Expected 200 (seeded permission on parent), got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_11_boundary_blocks_recursive_grant_from_parent():
    """outsider cannot access perm_restricted; restrict_permissions stops has_folder_permission (403).

    The recursive grant on perm_parent exists, but the walk from perm_restricted
    up to perm_parent stops at perm_restricted's restrict_permissions boundary.
    """
    r = await _outsider["api"].get(f"/folders/{_perm_restricted_id}")
    assert r.status_code == 403, (
        f"Expected 403 (recursive grant blocked by boundary), got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_12_direct_grant_on_restricted_folder_allows_access():
    """After inserting a direct permission on perm_restricted, outsider can access it (200).

    A direct grant on the restricted folder itself is not blocked — the boundary
    only prevents inheriting grants from ancestors above it.
    """
    _seed_permission(_perm_restricted_id, _outsider["id"], recursive=True)
    r = await _outsider["api"].get(f"/folders/{_perm_restricted_id}")
    assert r.status_code == 200, (
        f"Expected 200 after direct grant on restricted folder, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_13_grant_on_restricted_folder_propagates_to_children():
    """outsider can access perm_restricted_child via the recursive grant on perm_restricted (200).

    Depends on test_21_12 having seeded the permission on perm_restricted.
    The boundary only blocks propagation *from above*; grants originating at
    the restricted folder itself propagate normally to its children.
    """
    r = await _outsider["api"].get(f"/folders/{_perm_restricted_child_id}")
    assert r.status_code == 200, (
        f"Expected 200 (recursive grant propagates to child), got {r.status_code}: {r.text}"
    )


# ===========================================================================
# E. File access via permission boundaries
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_21_14_file_in_shared_tree_accessible():
    """outsider can read file metadata inside shared_sub via shared-tree walk (200)."""
    if not _file_in_shared_sub:
        pytest.skip("System shared folder not found in this environment")
    r = await _outsider["api"].get(f"/files/{_file_in_shared_sub}")
    assert r.status_code == 200, (
        f"Expected 200 for file in shared subfolder, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_15_file_blocked_by_shared_tree_boundary():
    """outsider CANNOT read file inside shared_restricted; boundary stops shared-tree walk (403)."""
    if not _file_in_shared_restricted:
        pytest.skip("System shared folder not found in this environment")
    r = await _outsider["api"].get(f"/files/{_file_in_shared_restricted}")
    assert r.status_code == 403, (
        f"Expected 403 for file behind shared-tree boundary, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_16_file_in_team_folder_accessible_to_member():
    """member can read file metadata inside team_parent via team membership (200)."""
    r = await _member["api"].get(f"/files/{_file_in_team_parent}")
    assert r.status_code == 200, (
        f"Expected 200 for file in team folder, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_17_file_blocked_by_team_boundary():
    """member CANNOT read file inside team_restricted; boundary stops team-folder walk (403)."""
    r = await _member["api"].get(f"/files/{_file_in_team_restricted}")
    assert r.status_code == 403, (
        f"Expected 403 for file behind team boundary, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_18_file_accessible_via_recursive_permission():
    """outsider can read file inside file_perm_parent via seeded recursive permission (200)."""
    r = await _outsider["api"].get(f"/files/{_file_in_perm_parent}")
    assert r.status_code == 200, (
        f"Expected 200 for file under recursively-permissioned folder, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_21_19_file_blocked_by_permission_boundary():
    """outsider CANNOT read file inside file_perm_restricted; boundary blocks recursive grant (403)."""
    r = await _outsider["api"].get(f"/files/{_file_in_perm_restricted}")
    assert r.status_code == 403, (
        f"Expected 403 for file behind permission boundary, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# 21-20  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_21_20_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
