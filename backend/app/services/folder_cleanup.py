"""Shared helper for hard-deleting a folder tree within a caller-managed transaction.

Callers must have issued BEGIN before calling hard_delete_folder_tree and must
commit or roll back afterward.  The function operates purely within the
caller's transaction so that folder cleanup composes atomically with whatever
else the caller is doing (team deletion, individual folder delete, etc.).
"""

import logging

logger = logging.getLogger(__name__)


async def hard_delete_folder_tree(db, folder_id: str) -> None:
    """Hard-delete a folder and its entire subtree within an open transaction.

    In order (all within the caller's transaction):
      1. Queue every blob in the subtree for deferred cleanup.
      2. Delete orphaned ACL rows (permissions, resource_role_grants) for all
         folders and files in the subtree — these have no FK so they won't
         cascade automatically.
      3. Delete share_items for files in the subtree that are referenced by
         user-to-user shares (not folder-level shares, which cascade when the
         share row itself is deleted in step 4).
      4. Delete the root folder row.  Cascade handles:
           - Subfolders (parent_id ON DELETE CASCADE)
           - Files (folder_id ON DELETE CASCADE)
           - Folder-targeted shares (target_folder_id ON DELETE CASCADE)
             which in turn cascade to their share_items
           - team_folders, folder_escrow_policies, share_exclusions, etc.
    """
    # --- 1. Queue blobs for deferred cleanup ---
    # Capture (storage_key, volume_id) before the cascade wipes file rows and
    # file_storage_locations rows.  The blob_cleanup worker checks the live
    # ref-count before actually deleting, so shared blobs (copies) are safe.
    await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        INSERT INTO blob_cleanup_queue (storage_key, volume_id)
        SELECT DISTINCT fi.storage_key, COALESCE(fsl.volume_id, '__default__')
          FROM files fi
          LEFT JOIN file_storage_locations fsl ON fsl.file_id = fi.id
         WHERE fi.folder_id IN (SELECT id FROM subtree)
        """,
        (folder_id,),
    )

    # --- 2. Clean orphaned ACL rows ---
    await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        DELETE FROM permissions
         WHERE resource_type = 'folder'
           AND resource_id IN (SELECT id FROM subtree)
        """,
        (folder_id,),
    )
    await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        DELETE FROM resource_role_grants
         WHERE resource_type = 'folder'
           AND resource_id IN (SELECT id FROM subtree)
        """,
        (folder_id,),
    )
    await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        DELETE FROM permissions
         WHERE resource_type = 'file'
           AND resource_id IN (
               SELECT id FROM files WHERE folder_id IN (SELECT id FROM subtree)
           )
        """,
        (folder_id,),
    )
    await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        DELETE FROM resource_role_grants
         WHERE resource_type = 'file'
           AND resource_id IN (
               SELECT id FROM files WHERE folder_id IN (SELECT id FROM subtree)
           )
        """,
        (folder_id,),
    )

    # --- 3. Clean share_items for files (user-to-user shares) ---
    # Folder-targeted shares and their items are handled by the cascade in
    # step 4 (target_folder_id ON DELETE CASCADE → share cascade → share_items
    # cascade).  The only items that survive are those on shares that target a
    # *user* (not the folder) but reference files by resource_id (no FK).
    #
    # Collect the affected share_ids first so we can prune empty share rows.
    cursor = await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        SELECT DISTINCT si.share_id
          FROM share_items si
         WHERE si.resource_type = 'file'
           AND si.resource_id IN (
               SELECT id FROM files WHERE folder_id IN (SELECT id FROM subtree)
           )
        """,
        (folder_id,),
    )
    affected_share_ids = [r["share_id"] for r in await cursor.fetchall()]

    await db.execute(
        """
        WITH RECURSIVE subtree AS (
            SELECT id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
        )
        DELETE FROM share_items
         WHERE resource_type = 'file'
           AND resource_id IN (
               SELECT id FROM files WHERE folder_id IN (SELECT id FROM subtree)
           )
        """,
        (folder_id,),
    )

    # Delete share rows that now have no items left.
    if affected_share_ids:
        ph = ",".join("?" * len(affected_share_ids))
        await db.execute(
            f"DELETE FROM shares"
            f" WHERE id IN ({ph})"
            f"   AND id NOT IN (SELECT DISTINCT share_id FROM share_items)",
            affected_share_ids,
        )

    # --- 4. Delete the root folder (cascade handles everything else) ---
    await db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
