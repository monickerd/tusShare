"""Shared access-control helpers used by file and folder routes."""


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
