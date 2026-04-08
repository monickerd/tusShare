"""Shared access-control helpers used by file and folder routes."""

import uuid


async def is_team_folder_member(db, folder_id: str, user_id: str) -> bool:
    """Walk the folder ancestry to check if any ancestor (or self) is a team folder,
    and if so, whether user_id is a member of that team.

    Returns True if the user has team-based access to this folder.
    """
    visited: set[str] = set()
    current_id = folder_id
    while current_id and current_id not in visited:
        visited.add(current_id)
        # Check if this folder is a team folder
        cursor = await db.execute(
            "SELECT team_id FROM team_folders WHERE folder_id = ?", (current_id,)
        )
        tf_row = await cursor.fetchone()
        if tf_row:
            # Confirm user is an active member of the team
            cursor = await db.execute(
                "SELECT 1 FROM user_team_keys WHERE team_id = ? AND user_id = ?",
                (tf_row["team_id"], user_id),
            )
            return await cursor.fetchone() is not None
        # Walk up the tree
        cursor = await db.execute(
            "SELECT parent_id FROM folders WHERE id = ?", (current_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return False
        current_id = row["parent_id"]
    return False


async def is_in_shared_tree(db, folder_id: str) -> bool:
    """Walk the folder ancestry to check if any ancestor (or self) is the shared folder.

    Returns True if the folder or any of its ancestors has is_shared=1.
    Uses a visited set to guard against circular parent references.
    """
    visited: set[str] = set()
    current_id = folder_id
    while current_id and current_id not in visited:
        visited.add(current_id)
        cursor = await db.execute(
            "SELECT parent_id, is_shared FROM folders WHERE id = ?", (current_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return False
        if row["is_shared"]:
            return True
        current_id = row["parent_id"]
    return False


async def get_folder_team_id(db, folder_id: str) -> str | None:
    """Walk the folder ancestry to find the team that owns this folder tree.

    Returns the team_id if any ancestor (or self) is registered as a team folder,
    otherwise None.
    """
    visited: set[str] = set()
    current_id = folder_id
    while current_id and current_id not in visited:
        visited.add(current_id)
        cursor = await db.execute(
            "SELECT team_id FROM team_folders WHERE folder_id = ?", (current_id,)
        )
        tf_row = await cursor.fetchone()
        if tf_row:
            return tf_row["team_id"]
        cursor = await db.execute(
            "SELECT parent_id FROM folders WHERE id = ?", (current_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        current_id = row["parent_id"]
    return None


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
            "INSERT OR IGNORE INTO permissions "
            "(id, resource_type, resource_id, user_id, permission, recursive, granted_by) "
            "VALUES (?, ?, ?, ?, ?, 1, ?)",
            (new_id, dest_resource_type, dest_resource_id,
             row["user_id"], row["permission"], row["granted_by"]),
        )
