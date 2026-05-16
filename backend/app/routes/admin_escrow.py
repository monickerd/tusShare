"""Admin routes for escrow-by-default configuration.

Endpoints
─────────
GET    /admin/escrow/settings                      — org-level defaults + require_coverage
PUT    /admin/escrow/settings                      — update org-level defaults  [step-up]

GET    /admin/escrow/folder-policies               — list all folder overrides
GET    /admin/escrow/folder-policies/{folder_id}   — get one policy
PUT    /admin/escrow/folder-policies/{folder_id}   — upsert policy  [step-up]
DELETE /admin/escrow/folder-policies/{folder_id}   — delete policy  [step-up]

GET    /admin/escrow/coverage-report               — teams with no escrow agent slot filled

All mutation endpoints require:
  • require_admin dependency (can_view_admin_panel)
  • FLAG_MANAGE_ESCROW (can_manage_escrow)
  • Step-up token for action key "policy.escrow.*"

The lock model: when is_locked=TRUE on an admin_settings row, only admins
with role_tier <= locked_min_tier may modify it.  Folder policies have the
same per-row lock (policy_locked / locked_min_tier).
"""

from __future__ import annotations

import json
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.middleware.stepup import require_step_up
from app.models.role import FLAG_MANAGE_ESCROW, ROLE_TIER, admin_best_tier
from app.routes._access import require_flag
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import event_bus
from app.services.escrow import resolve_effective_escrow_agents
from app.util.db import check_admin_setting_lock
from app.validation.sanitizers import validate_uuid
from typing import Annotated


_ERR_PERM_MANAGE_ESCROW = "can_manage_escrow permission required"
_SQL_ESCROW_BY_FOLDER = "SELECT * FROM folder_escrow_policies WHERE folder_id = ?"

logger = logging.getLogger(__name__)

router = APIRouter()

_STEPUP = "policy.escrow.*"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _admin_tier(admin: AuthenticatedUser) -> int:
    return admin_best_tier(admin.roles)


def _check_policy_lock(policy_row, admin_tier: int) -> None:
    if policy_row and policy_row["policy_locked"] and policy_row["locked_min_tier"] is not None:
        if admin_tier > policy_row["locked_min_tier"]:
            raise HTTPException(  # NOSONAR — helper; 403 documented in callers
                status_code=403,
                detail=f"This folder policy is locked and requires role tier ≤ {policy_row['locked_min_tier']}",
            )


def _check_overrides_allowed(ancestor_ids: list[str], db_policies: dict) -> None:
    """Check that no ancestor policy has overrides_allowed=False."""
    for fid in ancestor_ids:
        p = db_policies.get(fid)
        if p and not p["overrides_allowed"]:
            raise HTTPException(  # NOSONAR — helper; 403 documented in callers
                status_code=403,
                detail=f"A parent folder policy (folder {fid}) disallows sub-folder escrow overrides",
            )


# ---------------------------------------------------------------------------
# Org-level settings
# ---------------------------------------------------------------------------

_ESCROW_SETTING_KEYS = frozenset({
    "escrow_default_user_ids",
    "escrow_default_role_ids",
    "escrow_require_coverage",
})


class EscrowSettingsUpdate(BaseModel):
    escrow_default_user_ids: list[str] | None = None
    escrow_default_role_ids: list[str] | None = None
    escrow_require_coverage: bool | None = None
    # Lock controls — only admins with sufficient tier may change these
    is_locked:       bool | None = None
    locked_min_tier: int | None = None


@router.get("/settings")
async def get_escrow_settings(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return org-level escrow defaults and lock state."""
    require_flag(admin, FLAG_MANAGE_ESCROW, _ERR_PERM_MANAGE_ESCROW)
    cursor = await db.execute(
        "SELECT key, value, is_locked, locked_min_tier FROM admin_settings "
        "WHERE key IN ('escrow_default_user_ids', 'escrow_default_role_ids', 'escrow_require_coverage')"
    )
    rows = {r["key"]: r for r in await cursor.fetchall()}

    def _get(key, default):
        return rows[key]["value"] if key in rows else default

    # Use first row's lock state (all three share one logical lock)
    sample = next(iter(rows.values()), None)
    return {
        "escrow_default_user_ids": json.loads(_get("escrow_default_user_ids", "[]")),
        "escrow_default_role_ids": json.loads(_get("escrow_default_role_ids", "[]")),
        "escrow_require_coverage": _get("escrow_require_coverage", "0") == "1",
        "is_locked":       sample["is_locked"]       if sample else False,
        "locked_min_tier": sample["locked_min_tier"] if sample else None,
    }


async def _collect_escrow_value_updates(db, body: "EscrowSettingsUpdate") -> list[tuple]:
    """Validate IDs and build list of (key, json_value) pairs to write."""
    updates: list[tuple] = []
    if body.escrow_default_user_ids is not None:
        for uid in body.escrow_default_user_ids:
            c = await db.execute("SELECT 1 FROM users WHERE id = ?", (uid,))
            if not await c.fetchone():
                raise HTTPException(status_code=400, detail=f"User ID not found: {uid}")
        updates.append(("escrow_default_user_ids", json.dumps(body.escrow_default_user_ids)))
    if body.escrow_default_role_ids is not None:
        for rid in body.escrow_default_role_ids:
            c = await db.execute("SELECT 1 FROM roles WHERE id = ?", (rid,))
            if not await c.fetchone():
                raise HTTPException(status_code=400, detail=f"Role ID not found: {rid}")
        updates.append(("escrow_default_role_ids", json.dumps(body.escrow_default_role_ids)))
    if body.escrow_require_coverage is not None:
        updates.append(("escrow_require_coverage", "1" if body.escrow_require_coverage else "0"))
    return updates


async def _apply_lock_only_setting_updates(db, new_is_locked, new_locked_tier) -> None:
    """Write lock fields for all three escrow settings rows when no value changed."""
    for key in ("escrow_default_user_ids", "escrow_default_role_ids", "escrow_require_coverage"):
        if new_locked_tier is not None:
            await db.execute(
                "UPDATE admin_settings SET is_locked = ?, locked_min_tier = ? WHERE key = ?",
                (new_is_locked if new_is_locked is not None else True, new_locked_tier, key),
            )
        elif new_is_locked is not None:
            await db.execute(
                "UPDATE admin_settings SET is_locked = ? WHERE key = ?",
                (new_is_locked, key),
            )


async def _apply_setting_with_lock(db, key: str, value: str, new_is_locked, new_locked_tier) -> None:
    """Write one admin_settings row, optionally updating the lock fields."""
    lock_clause = ""
    lock_params: tuple = ()
    if new_is_locked is not None and new_locked_tier is not None:
        lock_clause = ", is_locked = ?, locked_min_tier = ?"
        lock_params = (new_is_locked, new_locked_tier)
    elif new_is_locked is not None:
        lock_clause = ", is_locked = ?"
        lock_params = (new_is_locked,)
    await db.execute(
        f"UPDATE admin_settings SET value = ?, updated_at = NOW(){lock_clause} WHERE key = ?",
        (value,) + lock_params + (key,),
    )


@router.put("/settings", dependencies=[Depends(require_step_up(_STEPUP))], responses={400: {"description": "Bad Request"}})
async def update_escrow_settings(
    body: EscrowSettingsUpdate,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Update org-level escrow defaults."""
    require_flag(admin, FLAG_MANAGE_ESCROW, _ERR_PERM_MANAGE_ESCROW)
    my_tier = _admin_tier(admin)

    cursor = await db.execute(
        "SELECT key, value, is_locked, locked_min_tier FROM admin_settings "
        "WHERE key IN ('escrow_default_user_ids', 'escrow_default_role_ids', 'escrow_require_coverage')"
    )
    rows = {r["key"]: r for r in await cursor.fetchall()}
    sample = next(iter(rows.values()), None)
    check_admin_setting_lock(sample, my_tier)

    # Validate lock change doesn't set a tier the caller can't access
    new_is_locked = body.is_locked
    new_locked_tier = body.locked_min_tier
    if new_is_locked and new_locked_tier is not None and new_locked_tier < my_tier:
        raise HTTPException(status_code=400, detail="Cannot lock at a tier higher than your own")

    updates = await _collect_escrow_value_updates(db, body)

    for key, value in updates:
        await _apply_setting_with_lock(db, key, value, new_is_locked, new_locked_tier)

    # If only lock changed (no value changes)
    if not updates and (new_is_locked is not None or new_locked_tier is not None):
        await _apply_lock_only_setting_updates(db, new_is_locked, new_locked_tier)

    await db.commit()
    changed_keys = [k for k, _ in updates]
    if body.is_locked is not None or body.locked_min_tier is not None:
        changed_keys.append("lock_state")
    event_bus.emit(SecurityEvent(
        event_type="admin.escrow.settings_changed",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=str(admin.id), username=admin.username),
        detail={"keys_changed": changed_keys},
    ))
    return {"message": "Escrow settings updated"}


# ---------------------------------------------------------------------------
# Folder-level policy overrides
# ---------------------------------------------------------------------------

class FolderEscrowPolicyRequest(BaseModel):
    override_mode:     str  = "replace"  # replace | merge | none
    policy_locked:     bool = False
    locked_min_tier:   int | None = None
    overrides_allowed: bool = True
    # Agent entries — exactly one of user_id or role_id per entry
    agents: list[dict] = []  # [{"user_id": ...} | {"role_id": ...}]


def _validate_policy_body(body: FolderEscrowPolicyRequest) -> None:
    if body.override_mode not in ("replace", "merge", "none"):
        raise HTTPException(status_code=400, detail="override_mode must be replace, merge, or none")
    if body.policy_locked and body.locked_min_tier is None:
        raise HTTPException(status_code=400, detail="locked_min_tier is required when policy_locked=true")
    for entry in body.agents:
        has_user = "user_id" in entry and entry["user_id"]
        has_role = "role_id" in entry and entry["role_id"]
        if bool(has_user) == bool(has_role):
            raise HTTPException(
                status_code=400,
                detail="Each agent entry must have exactly one of user_id or role_id",
            )


async def _get_ancestor_policies(db, folder_id: str) -> tuple[list[str], dict]:
    """Return (ancestor_id_list, {folder_id: policy_row}) for all ancestors."""
    cursor = await db.execute(
        """
        WITH RECURSIVE ancestors AS (
            SELECT id, parent_id FROM folders WHERE id = ?
            UNION ALL
            SELECT f.id, f.parent_id FROM folders f JOIN ancestors a ON f.id = a.parent_id
        )
        SELECT id FROM ancestors
        """,
        (folder_id,),
    )
    ancestor_ids = [r["id"] for r in await cursor.fetchall()]
    if not ancestor_ids:
        return [], {}

    placeholders = ",".join("?" * len(ancestor_ids))
    cursor = await db.execute(
        f"SELECT * FROM folder_escrow_policies WHERE folder_id IN ({placeholders})",
        ancestor_ids,
    )
    policies = {r["folder_id"]: r for r in await cursor.fetchall()}
    return ancestor_ids, policies


@router.get("/folder-policies")
async def list_folder_policies(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all folder-level escrow policy overrides."""
    require_flag(admin, FLAG_MANAGE_ESCROW, _ERR_PERM_MANAGE_ESCROW)
    cursor = await db.execute(
        "SELECT fep.*, f.name as folder_name FROM folder_escrow_policies fep "
        "JOIN folders f ON f.id = fep.folder_id "
        "ORDER BY f.name"
    )
    policies = []
    for row in await cursor.fetchall():
        # Load agents summary
        ac = await db.execute(
            "SELECT agent_user_id, agent_role_id FROM folder_escrow_policy_agents WHERE policy_id = ?",
            (row["id"],),
        )
        agent_rows = await ac.fetchall()
        policies.append({
            "policy_id":         row["id"],
            "folder_id":         row["folder_id"],
            "folder_name":       row["folder_name"],
            "override_mode":     row["override_mode"],
            "policy_locked":     row["policy_locked"],
            "locked_min_tier":   row["locked_min_tier"],
            "overrides_allowed": row["overrides_allowed"],
            "agent_count":       len(agent_rows),
            "created_at":        row["created_at"],
            "updated_at":        row["updated_at"],
        })
    return {"policies": policies}


@router.get("/folder-policies/{folder_id}", responses={404: {"description": "Not Found"}})
async def get_folder_policy(
    folder_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get the policy override for a specific folder, including full agent list."""
    require_flag(admin, FLAG_MANAGE_ESCROW, _ERR_PERM_MANAGE_ESCROW)
    folder_id = validate_uuid(folder_id)

    cursor = await db.execute(
        _SQL_ESCROW_BY_FOLDER, (folder_id,)
    )
    policy = await cursor.fetchone()
    if not policy:
        raise HTTPException(status_code=404, detail="No policy found for this folder")

    ac = await db.execute(
        "SELECT fepa.*, u.username, r.name as role_name "
        "FROM folder_escrow_policy_agents fepa "
        "LEFT JOIN users u ON u.id = fepa.agent_user_id "
        "LEFT JOIN roles r ON r.id = fepa.agent_role_id "
        "WHERE fepa.policy_id = ?",
        (policy["id"],),
    )
    agents = [
        {
            "user_id":   r["agent_user_id"],
            "username":  r["username"],
            "role_id":   r["agent_role_id"],
            "role_name": r["role_name"],
        }
        for r in await ac.fetchall()
    ]

    return {
        "policy_id":         policy["id"],
        "folder_id":         policy["folder_id"],
        "override_mode":     policy["override_mode"],
        "policy_locked":     policy["policy_locked"],
        "locked_min_tier":   policy["locked_min_tier"],
        "overrides_allowed": policy["overrides_allowed"],
        "agents":            agents,
        "created_at":        policy["created_at"],
        "updated_at":        policy["updated_at"],
    }


async def _validate_policy_agents(db, agents: list[dict]) -> None:
    """Verify that all user/role IDs referenced in agent entries exist in the DB."""
    for entry in agents:
        if "user_id" in entry and entry["user_id"]:
            c = await db.execute("SELECT 1 FROM users WHERE id = ?", (entry["user_id"],))
            if not await c.fetchone():
                raise HTTPException(status_code=400, detail=f"User not found: {entry['user_id']}")
        elif "role_id" in entry and entry["role_id"]:
            c = await db.execute("SELECT 1 FROM roles WHERE id = ?", (entry["role_id"],))
            if not await c.fetchone():
                raise HTTPException(status_code=400, detail=f"Role not found: {entry['role_id']}")


async def _upsert_policy_record(
    db, existing, policy_id: str, folder_id: str,
    body: "FolderEscrowPolicyRequest", admin: AuthenticatedUser, my_tier: int,
) -> None:
    """Insert or update the folder_escrow_policies row and replace agents."""
    if existing:
        await db.execute(
            "UPDATE folder_escrow_policies SET override_mode=?, policy_locked=?, locked_min_tier=?, "
            "overrides_allowed=?, updated_at=NOW() WHERE id=?",
            (body.override_mode, body.policy_locked, body.locked_min_tier,
             body.overrides_allowed, policy_id),
        )
        await db.execute(
            "DELETE FROM folder_escrow_policy_agents WHERE policy_id = ?", (policy_id,)
        )
    else:
        await db.execute(
            "INSERT INTO folder_escrow_policies "
            "(id, folder_id, override_mode, policy_locked, locked_min_tier, overrides_allowed, "
            " created_by, created_by_tier) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (policy_id, folder_id, body.override_mode, body.policy_locked,
             body.locked_min_tier, body.overrides_allowed, admin.id, my_tier),
        )
    for entry in body.agents:
        await db.execute(
            "INSERT INTO folder_escrow_policy_agents (id, policy_id, agent_user_id, agent_role_id) "
            "VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), policy_id,
             entry.get("user_id") or None, entry.get("role_id") or None),
        )


@router.put("/folder-policies/{folder_id}", dependencies=[Depends(require_step_up(_STEPUP))], responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}})
async def upsert_folder_policy(
    folder_id: str,
    body: FolderEscrowPolicyRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create or replace the escrow policy for a folder."""
    require_flag(admin, FLAG_MANAGE_ESCROW, _ERR_PERM_MANAGE_ESCROW)
    folder_id = validate_uuid(folder_id)
    my_tier = _admin_tier(admin)
    _validate_policy_body(body)

    if body.policy_locked and body.locked_min_tier is not None and body.locked_min_tier < my_tier:
        raise HTTPException(status_code=400, detail="Cannot lock at a tier higher than your own")

    # Verify folder exists
    c = await db.execute("SELECT id FROM folders WHERE id = ?", (folder_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail="Folder not found")

    # Check existing policy lock (only for updates, not initial creation)
    cursor = await db.execute(
        _SQL_ESCROW_BY_FOLDER, (folder_id,)
    )
    existing = await cursor.fetchone()
    if existing:
        _check_policy_lock(existing, my_tier)

    # Check ancestor overrides_allowed (skip the folder itself — only ancestors constrain it)
    ancestor_ids, ancestor_policies = await _get_ancestor_policies(db, folder_id)
    # ancestors list includes folder_id first; skip it when checking overrides_allowed
    parent_ancestors = [fid for fid in ancestor_ids if fid != folder_id]
    parent_policies = {fid: ancestor_policies[fid] for fid in parent_ancestors if fid in ancestor_policies}
    _check_overrides_allowed(parent_ancestors, parent_policies)

    await _validate_policy_agents(db, body.agents)

    policy_id = existing["id"] if existing else str(uuid.uuid4())
    await _upsert_policy_record(db, existing, policy_id, folder_id, body, admin, my_tier)
    await db.commit()
    event_bus.emit(SecurityEvent(
        event_type="admin.escrow.folder_policy_changed",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=str(admin.id), username=admin.username),
        detail={
            "action": "updated" if existing else "created",
            "folder_id": folder_id,
            "policy_id": policy_id,
            "override_mode": body.override_mode,
        },
    ))
    return {"message": "Policy saved", "policy_id": policy_id}


@router.delete("/folder-policies/{folder_id}", dependencies=[Depends(require_step_up(_STEPUP))], responses={404: {"description": "Not Found"}})
async def delete_folder_policy(
    folder_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete the escrow policy override for a folder."""
    require_flag(admin, FLAG_MANAGE_ESCROW, _ERR_PERM_MANAGE_ESCROW)
    folder_id = validate_uuid(folder_id)
    my_tier = _admin_tier(admin)

    cursor = await db.execute(
        _SQL_ESCROW_BY_FOLDER, (folder_id,)
    )
    policy = await cursor.fetchone()
    if not policy:
        raise HTTPException(status_code=404, detail="No policy found for this folder")

    _check_policy_lock(policy, my_tier)

    await db.execute(
        "DELETE FROM folder_escrow_policies WHERE id = ?", (policy["id"],)
    )
    await db.commit()
    event_bus.emit(SecurityEvent(
        event_type="admin.escrow.folder_policy_changed",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=str(admin.id), username=admin.username),
        detail={"action": "deleted", "folder_id": folder_id, "policy_id": policy["id"]},
    ))
    return {"message": "Policy deleted"}


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------

@router.get("/coverage-report")
async def get_coverage_report(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Return teams with no escrow agent key slot currently filled.

    An "unprotected" team is one where no member in user_team_keys holds the
    can_act_as_escrow permission.
    """
    require_flag(admin, FLAG_MANAGE_ESCROW, _ERR_PERM_MANAGE_ESCROW)

    # A team is "unprotected" if no explicitly-added escrow member (team_member scoped
    # role, not the owner's team_admin) currently holds can_act_as_escrow.
    _COVERAGE_WHERE = """
        NOT EXISTS (
            SELECT 1
            FROM user_team_keys utk
            JOIN user_roles ur_team ON ur_team.user_id = utk.user_id
                AND ur_team.scope_type = 'team' AND ur_team.scope_id = t.id
                AND ur_team.role_id = 'team_member'
            JOIN user_roles ur ON ur.user_id = utk.user_id AND ur.scope_type IS NULL
            JOIN role_permissions rp ON rp.role_id = ur.role_id
            WHERE utk.team_id = t.id
              AND rp.flag = 'can_act_as_escrow' AND rp.value = '1'
        )
    """
    cursor = await db.execute(
        f"""
        SELECT t.id, t.name, t.created_at,
               u.username AS owner_username
        FROM teams t
        JOIN users u ON u.id = t.owner_id
        WHERE {_COVERAGE_WHERE}
        ORDER BY t.name
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    teams = [
        {
            "team_id":        row["id"],
            "team_name":      row["name"],
            "owner_username": row["owner_username"],
            "created_at":     row["created_at"],
        }
        for row in await cursor.fetchall()
    ]

    # Total count for pagination
    count_cursor = await db.execute(
        f"""
        SELECT COUNT(*) AS n FROM teams t
        WHERE {_COVERAGE_WHERE}
        """
    )
    total = (await count_cursor.fetchone())["n"]

    return {"teams": teams, "total": total, "limit": limit, "offset": offset}
