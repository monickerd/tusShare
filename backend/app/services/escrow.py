"""Escrow policy resolution — org defaults + folder-level overrides.

`resolve_effective_escrow_agents` is the single entry point.  It walks the
folder ancestor chain (PostgreSQL recursive CTE), finds the closest policy
override, then merges or replaces the org defaults as instructed.

The returned agent list is what the client needs to wrap sk_team for at team-
creation time.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def resolve_effective_escrow_agents(
    db,
    folder_id: str | None,
) -> dict[str, Any]:
    """Return resolved escrow agents for a folder (or org root when folder_id is None).

    Return shape:
        {
            "agents": [{"user_id": ..., "username": ...,
                        "x25519_public_key": ..., "mlkem768_public_key": ...}],
            "source": "folder_override" | "org_default" | "none",
            "override_folder_id": str | None,
        }

    Algorithm:
    1. Walk folder ancestor chain from folder_id up to root.
    2. Take the *closest* ancestor (or the folder itself) that has a
       folder_escrow_policies row (most-specific-wins).
    3. Apply override_mode:
       - 'replace' → use only the policy's agents (ignoring org defaults).
       - 'merge'   → union the policy's agents with the org defaults.
       - 'none'    → return empty list with source='none'.
    4. If no folder policy found, fall back to org defaults.
    5. Expand agent_role_id entries to user IDs; filter to those with keys.
    """
    # --- 1. Build ancestor chain (including folder_id itself) ---
    ancestor_ids: list[str] = []
    if folder_id is not None:
        cursor = await db.execute(
            """
            WITH RECURSIVE ancestors AS (
                SELECT id, parent_id FROM folders WHERE id = ?
                UNION ALL
                SELECT f.id, f.parent_id
                FROM folders f
                JOIN ancestors a ON f.id = a.parent_id
            )
            SELECT id FROM ancestors
            """,
            (folder_id,),
        )
        ancestor_ids = [r["id"] for r in await cursor.fetchall()]

    # --- 2. Find the closest policy override ---
    policy_row = None
    override_folder_id = None
    if ancestor_ids:
        placeholders = ",".join("?" * len(ancestor_ids))
        cursor = await db.execute(
            f"SELECT * FROM folder_escrow_policies WHERE folder_id IN ({placeholders})",
            ancestor_ids,
        )
        policies = {r["folder_id"]: r for r in await cursor.fetchall()}
        for fid in ancestor_ids:  # ordered closest → root
            if fid in policies:
                policy_row = policies[fid]
                override_folder_id = fid
                break

    # --- 3. Apply override_mode ---
    if policy_row is not None:
        mode = policy_row["override_mode"]
        if mode == "none":
            return {"agents": [], "source": "none", "override_folder_id": override_folder_id}

        policy_agents = await _expand_policy_agents(db, policy_row["id"])

        if mode == "replace":
            return {
                "agents": policy_agents,
                "source": "folder_override",
                "override_folder_id": override_folder_id,
            }

        # merge: union with org defaults (deduplicated by user_id)
        if mode == "merge":
            org_agents = await _get_org_default_agents(db)
            merged = {a["user_id"]: a for a in org_agents}
            merged.update({a["user_id"]: a for a in policy_agents})
            return {
                "agents": list(merged.values()),
                "source": "folder_override",
                "override_folder_id": override_folder_id,
            }

    # --- 4. Org defaults ---
    org_agents = await _get_org_default_agents(db)
    if not org_agents:
        return {"agents": [], "source": "none", "override_folder_id": None}
    return {"agents": org_agents, "source": "org_default", "override_folder_id": None}


async def _get_org_default_agents(db) -> list[dict]:
    """Expand org-level escrow_default_user_ids + escrow_default_role_ids."""
    cursor = await db.execute(
        "SELECT key, value FROM admin_settings WHERE key IN ('escrow_default_user_ids', 'escrow_default_role_ids')"
    )
    rows = {r["key"]: r["value"] for r in await cursor.fetchall()}

    user_ids: list[str] = json.loads(rows.get("escrow_default_user_ids", "[]") or "[]")
    role_ids: list[str] = json.loads(rows.get("escrow_default_role_ids", "[]") or "[]")

    agents: dict[str, dict] = {}

    # Direct user IDs
    for uid in user_ids:
        row = await _fetch_agent_user(db, uid)
        if row:
            agents[uid] = row

    # Role-expanded users
    for rid in role_ids:
        cursor = await db.execute(
            "SELECT u.id, u.username, u.x25519_public_key, u.mlkem768_public_key "
            "FROM users u "
            "JOIN user_roles ur ON ur.user_id = u.id "
            "WHERE ur.role_id = ? AND ur.scope_type IS NULL "
            "AND u.x25519_public_key IS NOT NULL AND u.mlkem768_public_key IS NOT NULL",
            (rid,),
        )
        for r in await cursor.fetchall():
            if r["id"] not in agents:
                agents[r["id"]] = _agent_from_row(r)

    return list(agents.values())


async def _expand_policy_agents(db, policy_id: str) -> list[dict]:
    """Expand the agent rows for a folder_escrow_policies row."""
    cursor = await db.execute(
        "SELECT agent_user_id, agent_role_id FROM folder_escrow_policy_agents WHERE policy_id = ?",
        (policy_id,),
    )
    agent_rows = await cursor.fetchall()

    agents: dict[str, dict] = {}

    for ar in agent_rows:
        if ar["agent_user_id"]:
            row = await _fetch_agent_user(db, ar["agent_user_id"])
            if row:
                agents[ar["agent_user_id"]] = row
        elif ar["agent_role_id"]:
            cursor2 = await db.execute(
                "SELECT u.id, u.username, u.x25519_public_key, u.mlkem768_public_key "
                "FROM users u "
                "JOIN user_roles ur ON ur.user_id = u.id "
                "WHERE ur.role_id = ? AND ur.scope_type IS NULL "
                "AND u.x25519_public_key IS NOT NULL AND u.mlkem768_public_key IS NOT NULL",
                (ar["agent_role_id"],),
            )
            for r in await cursor2.fetchall():
                if r["id"] not in agents:
                    agents[r["id"]] = _agent_from_row(r)

    return list(agents.values())


async def _fetch_agent_user(db, user_id: str) -> dict | None:
    cursor = await db.execute(
        "SELECT id, username, x25519_public_key, mlkem768_public_key "
        "FROM users WHERE id = ? "
        "AND x25519_public_key IS NOT NULL AND mlkem768_public_key IS NOT NULL",
        (user_id,),
    )
    row = await cursor.fetchone()
    return _agent_from_row(row) if row else None


def _agent_from_row(row) -> dict:
    return {
        "user_id": row["id"],
        "username": row["username"],
        "x25519_public_key": row["x25519_public_key"],
        "mlkem768_public_key": row["mlkem768_public_key"],
    }
