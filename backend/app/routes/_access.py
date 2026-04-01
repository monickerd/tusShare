"""Shared access-control helpers used by file and folder routes."""


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
