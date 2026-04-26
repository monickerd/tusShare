"""Policy and policy condition management routes.

Mounted at /api/v1/admin/policies.

Policies gate folder membership and team access based on user attributes.
Each policy has:
  - A scope (org-wide or team-specific)
  - A set of conditions (all must match — AND semantics)

Conditions can be inherited from admin scope conditions (locked/read-only in UI)
or manually created.  Inherited conditions have inherited_scope_id set; they
cannot be edited or deleted via this API.

Trigger 2 (policy-change sweep): whenever conditions are created, updated, or
deleted on a policy, `sweep_policy_for_all_users` is called to immediately
re-evaluate the changed policy across all applicable users.  This is synchronous
and may be slow for large deployments — a background-task variant is planned for
future infrastructure work.

Access control:
  All endpoints require can_manage_policies.
  Team-scoped policies: admins with can_manage_policies may manage any policy;
  future work may further scope this to the admin's effective scope.
"""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.auth.interface import AuthenticatedUser
from app.database import db_session, get_db
from app.models.policy import (
    Policy,
    PolicyCondition,
    PolicyEffect,
    VALID_OPERATORS,
    sweep_policy_for_all_users,
)
from app.models.role import FLAG_MANAGE_POLICIES
from app.validation.sanitizers import validate_uuid

router = APIRouter()

_MAX_POLICY_NAME_LEN = 80
_MAX_VALUE_LEN       = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_can_manage(user: AuthenticatedUser):
    if not user.has_flag(FLAG_MANAGE_POLICIES):
        raise HTTPException(status_code=403, detail="can_manage_policies required")


async def _bg_sweep(policy_id: str) -> None:
    """Run sweep_policy_for_all_users in a background task with its own DB connection.

    IMPORTANT: never pass the request's `db` to asyncio.create_task — the
    connection is released to the pool when the request handler returns, and
    another request could acquire it while the task is still using it.
    """
    try:
        async with db_session() as _db:
            await sweep_policy_for_all_users(_db, policy_id)
    except Exception:
        pass


async def _load_policy(db, policy_id: str) -> Policy:
    cursor = await db.execute("SELECT * FROM policies WHERE id = ?", (policy_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return Policy.from_row(row)


async def _load_conditions(db, policy_id: str) -> list[PolicyCondition]:
    cursor = await db.execute(
        "SELECT * FROM policy_conditions WHERE policy_id = ? ORDER BY field",
        (policy_id,),
    )
    return [PolicyCondition.from_row(r) for r in await cursor.fetchall()]


async def _load_condition(db, policy_id: str, cond_id: str) -> PolicyCondition:
    cursor = await db.execute(
        "SELECT * FROM policy_conditions WHERE id = ? AND policy_id = ?",
        (cond_id, policy_id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Policy condition not found")
    return PolicyCondition.from_row(row)


async def _field_exists(db, field_name: str) -> bool:
    cursor = await db.execute(
        "SELECT 1 FROM policy_field_definitions WHERE name = ?", (field_name,)
    )
    return await cursor.fetchone() is not None


def _policy_with_conditions(policy: Policy, conditions: list[PolicyCondition]) -> dict:
    d = policy.to_dict()
    d["conditions"] = [c.to_dict() for c in conditions]
    return d


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreatePolicyRequest(BaseModel):
    name:           str
    scope_type:     str = "org"      # 'org' | 'team'
    scope_id:       str | None = None  # team_id for team-scoped
    escrow_enabled: bool = False     # E4b: write escrow grants for covered teams


class UpdatePolicyRequest(BaseModel):
    name:           str | None = None
    escrow_enabled: bool | None = None   # E4b


class CreateConditionRequest(BaseModel):
    field:    str
    operator: str
    value:    str
    strict:   bool = False
    # If this condition mirrors an admin scope condition, pass its ID here.
    # The backend will link them (inherited_scope_id) and lock the condition.
    inherited_scope_id: str | None = None


class UpdateConditionRequest(BaseModel):
    operator: str | None = None
    value:    str | None = None
    strict:   bool | None = None


# ---------------------------------------------------------------------------
# GET /admin/policies — list all policies
# ---------------------------------------------------------------------------

@router.get("")
async def list_policies(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """List all policies with their conditions."""
    _check_can_manage(user)

    cursor = await db.execute("SELECT * FROM policies ORDER BY scope_type, name")
    policy_rows = await cursor.fetchall()

    if not policy_rows:
        return {"policies": []}

    policy_ids = [r["id"] for r in policy_rows]
    ph = ",".join("?" * len(policy_ids))
    cursor = await db.execute(
        f"SELECT * FROM policy_conditions WHERE policy_id IN ({ph}) ORDER BY field",
        policy_ids,
    )
    cond_by_policy: dict[str, list] = {r["id"]: [] for r in policy_rows}
    for r in await cursor.fetchall():
        cond = PolicyCondition.from_row(r)
        cond_by_policy[cond.policy_id].append(cond)

    policies = [
        _policy_with_conditions(Policy.from_row(r), cond_by_policy[r["id"]])
        for r in policy_rows
    ]
    return {"policies": policies}


# ---------------------------------------------------------------------------
# POST /admin/policies — create a policy
# ---------------------------------------------------------------------------

@router.post("")
async def create_policy(
    body: CreatePolicyRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Create a new policy (no conditions yet).

    For team-scoped policies, scope_id must be a valid team UUID.
    """
    _check_can_manage(user)

    if len(body.name) < 1 or len(body.name) > _MAX_POLICY_NAME_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Policy name must be 1–{_MAX_POLICY_NAME_LEN} characters",
        )
    if body.scope_type not in ("org", "team"):
        raise HTTPException(status_code=400, detail="scope_type must be 'org' or 'team'")
    if body.scope_type == "team":
        if not body.scope_id:
            raise HTTPException(status_code=400, detail="scope_id (team_id) is required for team-scoped policies")
        scope_id = validate_uuid(body.scope_id)
        cursor = await db.execute("SELECT 1 FROM teams WHERE id = ?", (scope_id,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Team not found")
    else:
        scope_id = None

    policy_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO policies (id, name, scope_type, scope_id, escrow_enabled, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (policy_id, body.name, body.scope_type, scope_id,
         1 if body.escrow_enabled else 0, user.id),
    )
    await db.commit()
    return {"message": "Policy created", "id": policy_id}


# ---------------------------------------------------------------------------
# GET /admin/policies/{policy_id}
# ---------------------------------------------------------------------------

@router.get("/{policy_id}")
async def get_policy(
    policy_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Get a single policy with its conditions."""
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    policy    = await _load_policy(db, policy_id)
    conditions = await _load_conditions(db, policy_id)
    return {"policy": _policy_with_conditions(policy, conditions)}


# ---------------------------------------------------------------------------
# PATCH /admin/policies/{policy_id} — rename a policy
# ---------------------------------------------------------------------------

@router.patch("/{policy_id}")
async def update_policy(
    policy_id: str,
    body: UpdatePolicyRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Rename a policy."""
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    await _load_policy(db, policy_id)  # 404 guard

    if body.name is None and body.escrow_enabled is None:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates = []
    params  = []

    if body.name is not None:
        if len(body.name) < 1 or len(body.name) > _MAX_POLICY_NAME_LEN:
            raise HTTPException(status_code=400, detail=f"Name must be 1–{_MAX_POLICY_NAME_LEN} characters")
        updates.append("name = ?")
        params.append(body.name)

    if body.escrow_enabled is not None:
        updates.append("escrow_enabled = ?")
        params.append(1 if body.escrow_enabled else 0)

    params.append(policy_id)
    await db.execute(f"UPDATE policies SET {', '.join(updates)} WHERE id = ?", params)
    await db.commit()

    # If escrow_enabled changed, re-sweep so escrow grants are written / cleared
    if body.escrow_enabled is not None:
        asyncio.create_task(_bg_sweep(policy_id))

    return {"message": "Policy updated"}


# ---------------------------------------------------------------------------
# DELETE /admin/policies/{policy_id}
# ---------------------------------------------------------------------------

@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Delete a policy and all its conditions and grants (CASCADE)."""
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    await _load_policy(db, policy_id)  # 404 guard

    await db.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
    await db.commit()
    return {"message": "Policy deleted"}


# ---------------------------------------------------------------------------
# POST /admin/policies/{policy_id}/conditions — add a condition
# ---------------------------------------------------------------------------

@router.post("/{policy_id}/conditions")
async def create_condition(
    policy_id: str,
    body: CreateConditionRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Add a condition to a policy.

    If inherited_scope_id is provided, the condition is linked to an admin scope
    condition and will be locked (read-only) in the UI.  The scope condition must
    exist and the field/operator/value must match it exactly.

    After adding the condition, Trigger 2 fires: the policy is immediately
    re-evaluated against all applicable users.
    """
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    await _load_policy(db, policy_id)  # 404 guard

    if body.operator not in VALID_OPERATORS:
        raise HTTPException(
            status_code=400,
            detail=f"operator must be one of: {', '.join(sorted(VALID_OPERATORS))}",
        )
    if not await _field_exists(db, body.field):
        raise HTTPException(status_code=400, detail=f"Unknown policy field: {body.field!r}")
    if not body.value or len(body.value) > _MAX_VALUE_LEN:
        raise HTTPException(status_code=400, detail=f"value is required and must be ≤{_MAX_VALUE_LEN} characters")

    inherited_scope_id = None
    if body.inherited_scope_id:
        inherited_scope_id = validate_uuid(body.inherited_scope_id)
        cursor = await db.execute(
            "SELECT * FROM admin_scope_conditions WHERE id = ?", (inherited_scope_id,)
        )
        scope_row = await cursor.fetchone()
        if scope_row is None:
            raise HTTPException(status_code=404, detail="Admin scope condition not found")
        # Enforce that the condition mirrors the scope exactly
        if (scope_row["field"] != body.field or
                scope_row["operator"] != body.operator or
                scope_row["value"] != body.value):
            raise HTTPException(
                status_code=400,
                detail="Inherited condition field/operator/value must match the referenced scope condition",
            )

    cond_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO policy_conditions "
        "(id, policy_id, field, operator, value, inherited_scope_id, scope_detached, strict) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
        (cond_id, policy_id, body.field, body.operator, body.value,
         inherited_scope_id, 1 if body.strict else 0),
    )
    await db.commit()

    # Trigger 2 — fire-and-forget sweep
    asyncio.create_task(_bg_sweep(policy_id))

    new_cond = await _load_condition(db, policy_id, cond_id)
    return new_cond.to_dict()


# ---------------------------------------------------------------------------
# GET /admin/policies/{policy_id}/conditions — list conditions
# ---------------------------------------------------------------------------

@router.get("/{policy_id}/conditions")
async def list_conditions(
    policy_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """List all conditions on a policy."""
    _check_can_manage(user)
    policy_id  = validate_uuid(policy_id)
    await _load_policy(db, policy_id)  # 404 guard
    conditions = await _load_conditions(db, policy_id)
    return {"conditions": [c.to_dict() for c in conditions]}


# ---------------------------------------------------------------------------
# PATCH /admin/policies/{policy_id}/conditions/{cond_id} — update a condition
# ---------------------------------------------------------------------------

@router.patch("/{policy_id}/conditions/{cond_id}")
async def update_condition(
    policy_id: str,
    cond_id:   str,
    body: UpdateConditionRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Update a non-inherited policy condition.

    Inherited conditions (inherited_scope_id IS NOT NULL) cannot be edited here;
    edit the source admin scope condition instead.

    After update, Trigger 2 fires.
    """
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    cond_id   = validate_uuid(cond_id)
    await _load_policy(db, policy_id)  # 404 guard

    cond = await _load_condition(db, policy_id, cond_id)
    if cond.inherited_scope_id is not None:
        raise HTTPException(
            status_code=400,
            detail="Inherited conditions cannot be edited; update the source admin scope condition",
        )

    updates = []
    params  = []

    if body.operator is not None:
        if body.operator not in VALID_OPERATORS:
            raise HTTPException(
                status_code=400,
                detail=f"operator must be one of: {', '.join(sorted(VALID_OPERATORS))}",
            )
        updates.append("operator = ?")
        params.append(body.operator)

    if body.value is not None:
        if len(body.value) > _MAX_VALUE_LEN:
            raise HTTPException(status_code=400, detail=f"value must be ≤{_MAX_VALUE_LEN} characters")
        updates.append("value = ?")
        params.append(body.value)

    if body.strict is not None:
        updates.append("strict = ?")
        params.append(1 if body.strict else 0)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(cond_id)
    await db.execute(
        f"UPDATE policy_conditions SET {', '.join(updates)} WHERE id = ?", params
    )
    await db.commit()

    # Trigger 2
    asyncio.create_task(_bg_sweep(policy_id))

    updated_cond = await _load_condition(db, policy_id, cond_id)
    return updated_cond.to_dict()


# ---------------------------------------------------------------------------
# DELETE /admin/policies/{policy_id}/conditions/{cond_id}
# ---------------------------------------------------------------------------

@router.delete("/{policy_id}/conditions/{cond_id}")
async def delete_condition(
    policy_id: str,
    cond_id:   str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Remove a condition from a policy.

    Inherited conditions (inherited_scope_id IS NOT NULL) cannot be removed here;
    delete the source admin scope condition to remove the link.

    After deletion, Trigger 2 fires.
    """
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    cond_id   = validate_uuid(cond_id)
    await _load_policy(db, policy_id)  # 404 guard

    cond = await _load_condition(db, policy_id, cond_id)
    if cond.inherited_scope_id is not None:
        raise HTTPException(
            status_code=400,
            detail="Inherited conditions cannot be deleted via this endpoint; delete the source admin scope condition",
        )

    await db.execute("DELETE FROM policy_conditions WHERE id = ?", (cond_id,))
    await db.commit()

    # Trigger 2
    asyncio.create_task(_bg_sweep(policy_id))

    return {"message": "Condition deleted"}


# ---------------------------------------------------------------------------
# Policy effects — what a matching policy grants
# ---------------------------------------------------------------------------

_TEAM_ROLES = frozenset({
    "team_member", "team_manager", "team_admin",
    "team_owner", "team_supervisor",  # legacy compat
})


class CreateEffectRequest(BaseModel):
    effect_type:     str                   # 'team_member' | 'folder_acl' | 'team_escrow'
    target_id:       str                   # team_id or folder_id
    role_level:      str | None = None     # required for team_member
    permission:      str | None = None     # required for folder_acl
    recursive:       bool = True           # folder_acl only
    escrow_override: int | None = None     # team_escrow only: 0=force-off, 1=force-on


async def _load_effect(db, policy_id: str, effect_id: str) -> PolicyEffect:
    cursor = await db.execute(
        "SELECT * FROM policy_effects WHERE id = ? AND policy_id = ?",
        (effect_id, policy_id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Policy effect not found")
    return PolicyEffect.from_row(row)


# GET /admin/policies/{policy_id}/effects — list effects
@router.get("/{policy_id}/effects")
async def list_effects(
    policy_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """List all effects defined on a policy."""
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    await _load_policy(db, policy_id)  # 404 guard

    cursor = await db.execute(
        "SELECT * FROM policy_effects WHERE policy_id = ? ORDER BY effect_type, target_id",
        (policy_id,),
    )
    effects = [PolicyEffect.from_row(r).to_dict() for r in await cursor.fetchall()]
    return {"effects": effects}


# POST /admin/policies/{policy_id}/effects — create an effect
@router.post("/{policy_id}/effects")
async def create_effect(
    policy_id: str,
    body: CreateEffectRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Add an effect to a policy.

    For team_member effects: target_id must be a valid team UUID; role_level must
    be a valid role name (e.g. 'team_member', 'team_manager', 'team_admin').

    For folder_acl effects: target_id must be a valid folder UUID; permission
    must be 'read', 'write', or 'admin'.

    After creating the effect, Trigger 2 fires to immediately apply the new effect
    to all users currently matching this policy.
    """
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    await _load_policy(db, policy_id)  # 404 guard

    if body.effect_type not in ("team_member", "folder_acl", "team_escrow"):
        raise HTTPException(
            status_code=400,
            detail="effect_type must be 'team_member', 'folder_acl', or 'team_escrow'",
        )

    target_id = validate_uuid(body.target_id)

    if body.effect_type == "team_member":
        # Validate team exists
        cursor = await db.execute("SELECT 1 FROM teams WHERE id = ?", (target_id,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Team not found")
        if not body.role_level:
            raise HTTPException(status_code=400, detail="role_level is required for team_member effects")
        # Validate role exists
        cursor = await db.execute("SELECT 1 FROM roles WHERE id = ?", (body.role_level,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=400, detail=f"Role not found: {body.role_level!r}")
        permission      = None
        recursive       = 1
        escrow_override = None

    elif body.effect_type == "folder_acl":
        # Validate folder exists
        cursor = await db.execute("SELECT 1 FROM folders WHERE id = ?", (target_id,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Folder not found")
        if not body.permission or body.permission not in ("read", "write", "admin"):
            raise HTTPException(
                status_code=400,
                detail="permission must be 'read', 'write', or 'admin' for folder_acl effects",
            )
        permission      = body.permission
        recursive       = 1 if body.recursive else 0
        escrow_override = None

    else:  # team_escrow — per-team escrow override
        # Validate team exists
        cursor = await db.execute("SELECT 1 FROM teams WHERE id = ?", (target_id,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Team not found")
        if body.escrow_override not in (0, 1):
            raise HTTPException(
                status_code=400,
                detail="escrow_override must be 0 (force-off) or 1 (force-on) for team_escrow effects",
            )
        # Prevent duplicate team_escrow effect for the same (policy, team)
        cursor = await db.execute(
            "SELECT 1 FROM policy_effects "
            "WHERE policy_id = ? AND effect_type = 'team_escrow' AND target_id = ?",
            (policy_id, target_id),
        )
        if await cursor.fetchone() is not None:
            raise HTTPException(
                status_code=409,
                detail="A team_escrow override already exists for this team on this policy",
            )
        permission      = None
        recursive       = 1
        escrow_override = body.escrow_override

    effect_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO policy_effects "
        "(id, policy_id, effect_type, target_id, role_level, permission, recursive, escrow_override) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (effect_id, policy_id, body.effect_type, target_id,
         body.role_level if body.effect_type == "team_member" else None,
         permission, recursive, escrow_override),
    )
    await db.commit()

    # Trigger 2 — immediately apply new effect to all currently matching users.
    # For team_escrow effects this re-writes or suppresses escrow grants for the target team.
    asyncio.create_task(_bg_sweep(policy_id))

    return {"message": "Effect added", "id": effect_id}


# DELETE /admin/policies/{policy_id}/effects/{effect_id}
@router.delete("/{policy_id}/effects/{effect_id}")
async def delete_effect(
    policy_id:  str,
    effect_id:  str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Remove an effect from a policy.

    ON DELETE CASCADE on policy_effect_id removes all policy-sourced user_roles,
    user_team_keys, and permissions rows associated with this effect automatically.
    The tracking rows in policy_team_grants and policy_folder_grants are also
    cascade-deleted via their effect_id FK.

    Manual rows (policy_effect_id IS NULL) are not affected.
    """
    _check_can_manage(user)
    policy_id = validate_uuid(policy_id)
    effect_id = validate_uuid(effect_id)
    await _load_policy(db, policy_id)   # 404 guard
    await _load_effect(db, policy_id, effect_id)  # 404 guard

    await db.execute("DELETE FROM policy_effects WHERE id = ?", (effect_id,))
    await db.commit()
    return {"message": "Effect deleted"}
