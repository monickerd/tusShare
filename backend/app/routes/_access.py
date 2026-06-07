"""Shared access-control helpers used by file and folder routes.

Phase 1 evaluation order (per resource level, then ancestry walk):
  1. Explicit deny in ACL              → DENY  (stops walk)
  2. Explicit allow in ACL             → ALLOW if action ⊆ level's implied set
  3. Team-based grant                  → ALLOW if team membership + role level covers action
  4. restrict_permissions boundary     → STOP walk
  5. Move to parent; repeat from step 1
  6. Default                           → DENY
"""

import uuid

from fastapi import HTTPException

from app.auth.interface import AuthenticatedUser
from app.conf.teams import TEAM_ROLE_MEMBER, TEAM_ROLE_OWNER, TEAM_ROLE_SUPERVISOR

# ---------------------------------------------------------------------------
# Permission level → implied action set
#
# 'read' and 'download' are intentionally identical action sets. In an
# E2E-encrypted system the raw bytes are ciphertext, so fetching a file
# without the decryption key is meaningless — there is no useful "metadata
# only" access tier below download. 'read' is kept as a named level for
# backward-compat with pre-Phase-1 rows already in the permissions table;
# 'download' is the preferred label for new explicit grants.
#
# 'rename' covers in-place name changes only. Folder restructuring (changing
# parent_id) requires 'write' because it triggers permission re-inheritance
# across the affected subtree.
# ---------------------------------------------------------------------------
_LEVEL_ACTIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"read", "write", "delete", "download", "rename", "manage_permissions"}),
    "write": frozenset({"read", "write", "delete", "download", "rename"}),
    "read": frozenset({"read", "download"}),  # backward-compat alias; prefer 'download' for new grants
    "download": frozenset({"read", "download"}),  # preferred level for explicit download grants
    "delete": frozenset({"read", "delete"}),
    "rename": frozenset({"read", "rename"}),  # in-place name change only; parent_id changes use 'write'
    "manage_permissions": frozenset({"read", "manage_permissions"}),
    "deny": frozenset(),
    "none": frozenset(),
}

# Atomic permission flags stored as comma-separated values in the permission column.
# Each flag maps to the set of internal action strings it authorises.
# Grants stored this way are always additive (no deny semantics).
_FLAG_ACTIONS: dict[str, frozenset[str]] = {
    "view_contents":      frozenset({"read"}),
    "download_files":     frozenset({"read", "download"}),
    "upload_files":       frozenset({"read", "write"}),
    "delete_files":       frozenset({"read", "delete"}),
    "manage_this_folder": frozenset({"read", "manage_permissions"}),
}

# Default folder permission level granted by each built-in team role.
# Overridden per-team via the team_folder_role_levels table.
_TEAM_ROLE_DEFAULTS: dict[str, str] = {
    TEAM_ROLE_OWNER: "admin",
    TEAM_ROLE_SUPERVISOR: "write",
    TEAM_ROLE_MEMBER: "write",
}

# Legacy alias used by callers that only need truthy / falsy.
_TEAM_ROLE_LEVELS = _TEAM_ROLE_DEFAULTS

_SQL_TEAM_FOLDER = "SELECT team_id FROM team_folders WHERE folder_id = ?"
_SQL_FOLDER_PARENT = "SELECT parent_id, restrict_permissions FROM folders WHERE id = ?"


def require_flag(user: AuthenticatedUser, flag: str, detail: str | None = None) -> None:
    """Raise 403 if *user* does not hold *flag*.

    Consolidates the per-file ``_require_X_flag`` one-liners used across admin
    route modules into a single shared call site.
    """
    if not user.has_flag(flag):
        raise HTTPException(status_code=403, detail=detail or f"{flag} permission required")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _get_team_role_level(db, team_id: str, role_id: str) -> str:
    """Return the folder permission level for role_id within team_id.

    Checks the team_folder_role_levels override table first; falls back to
    _TEAM_ROLE_DEFAULTS if no row exists.
    """
    try:
        cursor = await db.execute(
            "SELECT level FROM team_folder_role_levels WHERE team_id = ? AND role_id = ?",
            (team_id, role_id),
        )
        row = await cursor.fetchone()
        if row:
            return row["level"]
    except Exception:
        pass  # table may not exist on old schema; fall through to default
    return _TEAM_ROLE_DEFAULTS.get(role_id, "write")


async def _team_level_for_user(db, team_id: str, user_id: str) -> str | None:
    """Return the effective folder permission level for user_id within team_id.

    Returns None if the user is not a member of the team.
    """
    cursor = await db.execute(
        """SELECT ur.role_id
           FROM user_team_keys utk
           LEFT JOIN user_roles ur
             ON ur.user_id    = utk.user_id
            AND ur.scope_type = 'team'
            AND ur.scope_id   = utk.team_id
           WHERE utk.team_id = ? AND utk.user_id = ?""",
        (team_id, user_id),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    role_id = row["role_id"]
    if role_id is None:
        # Key slot exists but no team role assigned — deny team-folder access.
        # This prevents the _TEAM_ROLE_DEFAULTS fallback from silently granting
        # write access to users who lack an explicit role assignment.
        return None
    return await _get_team_role_level(db, team_id, role_id)


# ---------------------------------------------------------------------------
# Core data-plane permission evaluator (Phase 1)
# ---------------------------------------------------------------------------


async def _check_team_grant(db, folder_id: str, user_id: str, action: str) -> bool:
    cursor = await db.execute(_SQL_TEAM_FOLDER, (folder_id,))
    tf_row = await cursor.fetchone()
    if not tf_row:
        return False
    level = await _team_level_for_user(db, tf_row["team_id"], user_id)
    return bool(level and level != "none" and action in _LEVEL_ACTIONS.get(level, frozenset()))


async def _seed_folder_walk(
    db, resource_type: str, resource_id: str, user_id: str, action: str
) -> tuple[str | None, bool | None, bool]:
    """Return (folder_id, early_result, first_folder).
    early_result is set when a definitive answer is known before the walk."""
    if resource_type != "file":
        return resource_id, None, False
    file_allowed = await _check_acl(db, "file", resource_id, user_id, action, exact=True)
    if file_allowed is not None:
        return None, file_allowed, False
    role_allowed = await _check_role_acl(db, "file", resource_id, user_id, action, exact=True)
    if role_allowed is not None:
        return None, role_allowed, False
    cursor = await db.execute("SELECT folder_id FROM files WHERE id = ?", (resource_id,))
    frow = await cursor.fetchone()
    if not frow or not frow["folder_id"]:
        return None, False, False
    return frow["folder_id"], None, True


async def check_data_permission(
    db,
    resource_type: str,
    resource_id: str,
    user_id: str,
    action: str,
) -> bool:
    """Evaluate full Phase 1 permission chain for a data-plane action.

    resource_type: 'file' or 'folder'
    action: one of the keys in _LEVEL_ACTIONS (read, write, delete, download,
            rename, manage_permissions)

    For files the check starts at the file's own permission row then falls
    through to the containing folder tree.  For folders the walk starts at
    the folder itself and ascends via parent_id, stopping at any folder with
    restrict_permissions=TRUE.
    """
    folder_id, early_result, first_folder = await _seed_folder_walk(db, resource_type, resource_id, user_id, action)
    if early_result is not None:
        return early_result

    visited: set[str] = set()
    while folder_id and folder_id not in visited:
        visited.add(folder_id)
        is_exact = (resource_type == "folder" and folder_id == resource_id) or first_folder
        first_folder = False

        acl_result = await _check_acl(db, "folder", folder_id, user_id, action, exact=is_exact)
        if acl_result is not None:
            return acl_result

        # Role-based ACL grant check.
        role_result = await _check_role_acl(db, "folder", folder_id, user_id, action, exact=is_exact)
        if role_result is not None:
            return role_result

        # Team-based grant.
        if await _check_team_grant(db, folder_id, user_id, action):
            return True

        cursor = await db.execute(_SQL_FOLDER_PARENT, (folder_id,))
        row = await cursor.fetchone()
        if not row or row["restrict_permissions"]:
            return False
        folder_id = row["parent_id"]

    return False


async def _check_acl(
    db,
    resource_type: str,
    resource_id: str,
    user_id: str,
    action: str,
    exact: bool,
) -> bool | None:
    """Check the permissions table for an explicit ACL entry.

    Returns True (allow), False (deny), or None (no applicable row found).
    *exact=True*  → also accepts non-recursive rows (the resource itself).
    *exact=False* → only recursive rows count as inherited grants.
    """
    cursor = await db.execute(
        "SELECT permission, recursive FROM permissions WHERE resource_type = ? AND resource_id = ? AND user_id = ?",
        (resource_type, resource_id, user_id),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    recursive = bool(row["recursive"])
    if not exact and not recursive:
        return None  # non-recursive grant doesn't propagate to ancestors
    perm = row["permission"]
    if perm == "deny":
        return False
    if "," in perm:
        flags = {f.strip() for f in perm.split(",")}
        implied = frozenset().union(*(_FLAG_ACTIONS.get(f, frozenset()) for f in flags))
        return action in implied or None
    return action in _LEVEL_ACTIONS.get(perm, frozenset()) or None


async def _check_role_acl(
    db,
    resource_type: str,
    resource_id: str,
    user_id: str,
    action: str,
    exact: bool,
) -> bool | None:
    """Check resource_role_grants for a role-based ACL entry held by user_id.

    Returns True (allow) or None (no applicable row found — never False, since
    role grants cannot express explicit deny).
    *exact=True*  → also accepts non-recursive rows.
    *exact=False* → only recursive rows propagate.
    """
    try:
        cursor = await db.execute(
            "SELECT rrg.permission, rrg.recursive "
            "FROM resource_role_grants rrg "
            "JOIN user_roles ur ON ur.role_id = rrg.role_id "
            "WHERE rrg.resource_type = ? AND rrg.resource_id = ? AND ur.user_id = ?",
            (resource_type, resource_id, user_id),
        )
        rows = await cursor.fetchall()
    except Exception:
        return None  # table absent on old schema
    for row in rows:
        recursive = bool(row["recursive"])
        if not exact and not recursive:
            continue
        perm = row["permission"]
        if "," in perm:
            flags = {f.strip() for f in perm.split(",")}
            implied = frozenset().union(*(_FLAG_ACTIONS.get(f, frozenset()) for f in flags))
            if action in implied:
                return True
        elif action in _LEVEL_ACTIONS.get(perm, frozenset()):
            return True
    return None


# ---------------------------------------------------------------------------
# Ancestry helpers (unchanged from pre-Phase-1; still used by several routes)
# ---------------------------------------------------------------------------


async def is_team_folder_member(db, folder_id: str, user_id: str) -> str | None:
    """Walk the folder ancestry to check if any ancestor (or self) is a team folder,
    and if so, whether user_id is a member of that team.

    Stops at folders with restrict_permissions = TRUE: team membership in an
    ancestor team folder does not grant access across a permission boundary.
    Returns the effective permission level ("admin", "write", or "read") derived
    from the user's team role (via team_folder_role_levels with default fallback),
    or None if they have no team-based access.  Callers that only need a boolean
    can treat the return value as truthy/falsy.
    """
    visited: set[str] = set()
    current_id = folder_id
    while current_id and current_id not in visited:
        visited.add(current_id)
        cursor = await db.execute(_SQL_TEAM_FOLDER, (current_id,))
        tf_row = await cursor.fetchone()
        if tf_row:
            level = await _team_level_for_user(db, tf_row["team_id"], user_id)
            if level and level != "none":
                return level
            return None
        cursor = await db.execute(_SQL_FOLDER_PARENT, (current_id,))
        row = await cursor.fetchone()
        if not row or row["restrict_permissions"]:
            return None
        current_id = row["parent_id"]
    return None


async def is_in_shared_tree(db, folder_id: str) -> bool:
    """Walk the folder ancestry to check if any ancestor (or self) is the shared folder.

    Returns True if the folder or any of its ancestors has is_shared=1.
    Stops at folders with restrict_permissions = TRUE: a shared ancestor above a
    permission boundary does not grant public access to the restricted subtree.
    Uses a visited set to guard against circular parent references.
    """
    visited: set[str] = set()
    current_id = folder_id
    while current_id and current_id not in visited:
        visited.add(current_id)
        cursor = await db.execute(
            "SELECT parent_id, is_shared, restrict_permissions FROM folders WHERE id = ?", (current_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return False
        if row["is_shared"]:
            return True
        if row["restrict_permissions"]:
            return False
        current_id = row["parent_id"]
    return False


async def get_folder_team_id(db, folder_id: str) -> str | None:
    """Return the team_id for the team that owns this folder's tree, or None.

    Uses the denormalised root_folder_id to avoid an ancestor walk: team folders
    are always root-level, so the owning team is found via a single join.
    """
    cursor = await db.execute(
        "SELECT tf.team_id FROM folders f "
        "JOIN team_folders tf ON tf.folder_id = f.root_folder_id "
        "WHERE f.id = ?",
        (folder_id,),
    )
    row = await cursor.fetchone()
    return row["team_id"] if row else None


async def copy_folder_permissions(db, source_folder_id: str, dest_resource_type: str, dest_resource_id: str) -> None:
    """Copy recursive permission rows from source_folder_id to a new resource.

    Only rows with recursive=1 are inherited — non-recursive grants are
    intentionally scoped to the folder they were explicitly granted on.
    New rows get fresh UUIDs; granted_by is preserved.
    """
    cursor = await db.execute(
        "SELECT user_id, permission, granted_by FROM permissions "
        "WHERE resource_type = 'folder' AND resource_id = ? AND recursive = 1",
        (source_folder_id,),
    )
    rows = await cursor.fetchall()
    for row in rows:
        new_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO permissions "
            "(id, resource_type, resource_id, user_id, permission, recursive, granted_by) "
            "VALUES (?, ?, ?, ?, ?, 1, ?) "
            "ON CONFLICT DO NOTHING",
            (new_id, dest_resource_type, dest_resource_id, row["user_id"], row["permission"], row["granted_by"]),
        )


async def has_folder_permission(db, folder_id: str, user_id: str) -> bool:
    """Return True if user has an explicit permission entry for this folder.

    Checks the folder itself and walks up through ancestors for recursive grants.
    Stops at folders with restrict_permissions = TRUE: recursive grants from above
    a permission boundary do not propagate into the restricted subtree.
    Used to honour policy-engine folder_acl effects and manual user-share grants.

    For new code prefer check_data_permission() which evaluates the full
    Phase 1 chain including team-based grants and explicit denies.
    """
    visited: set[str] = set()
    current_id: str | None = folder_id
    while current_id and current_id not in visited:
        visited.add(current_id)
        cursor = await db.execute(
            "SELECT recursive FROM permissions WHERE resource_type = 'folder' AND resource_id = ? AND user_id = ?",
            (current_id, user_id),
        )
        row = await cursor.fetchone()
        if row and (current_id == folder_id or row["recursive"]):
            return True
        cursor = await db.execute(_SQL_FOLDER_PARENT, (current_id,))
        prow = await cursor.fetchone()
        if not prow or prow["restrict_permissions"]:
            return False
        current_id = prow["parent_id"]
    return False
