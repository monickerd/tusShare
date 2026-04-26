"""Admin scope condition management routes.

Mounted at /api/v1/admin/scopes.

Admin scope conditions restrict the universe of users an admin can target with
policies.  A scope condition is attached to either a specific user account or a
role (affecting all holders of that role).

A user's effective scope is the AND of all conditions inherited from:
  - their own account (holder_type='user')
  - all global roles they hold (holder_type='role')

More conditions = more restrictive scope.  An admin with no scope conditions is
unrestricted (can target all users).  This composing correctly.

Access control:
  All endpoints require can_manage_policies.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.models.policy import AdminScopeCondition, VALID_OPERATORS
from app.models.role import FLAG_MANAGE_POLICIES
from app.validation.sanitizers import validate_uuid

router = APIRouter()

_MAX_VALUE_LEN = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_can_manage(user: AuthenticatedUser):
    if not user.has_flag(FLAG_MANAGE_POLICIES):
        raise HTTPException(status_code=403, detail="can_manage_policies required")


async def _load_scope_cond(db, cond_id: str) -> AdminScopeCondition:
    cursor = await db.execute(
        "SELECT * FROM admin_scope_conditions WHERE id = ?", (cond_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Admin scope condition not found")
    return AdminScopeCondition.from_row(row)


async def _field_exists(db, field_name: str) -> bool:
    cursor = await db.execute(
        "SELECT 1 FROM policy_field_definitions WHERE name = ?", (field_name,)
    )
    return await cursor.fetchone() is not None


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateScopeCondRequest(BaseModel):
    holder_type: str   # 'user' | 'role'
    holder_id:   str   # user_id (UUID) or role name
    field:       str
    operator:    str
    value:       str


class UpdateScopeCondRequest(BaseModel):
    operator: str | None = None
    value:    str | None = None


# ---------------------------------------------------------------------------
# GET /admin/scopes — list all scope conditions
# ---------------------------------------------------------------------------

@router.get("")
async def list_scope_conditions(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """List all admin scope conditions.

    Returns all conditions across all holders.  The UI groups them by holder.
    """
    _check_can_manage(user)
    cursor = await db.execute(
        "SELECT * FROM admin_scope_conditions ORDER BY holder_type, holder_id, field"
    )
    conds = [AdminScopeCondition.from_row(r).to_dict() for r in await cursor.fetchall()]
    return {"conditions": conds}


# ---------------------------------------------------------------------------
# GET /admin/scopes/{holder_type}/{holder_id} — list conditions for a holder
# ---------------------------------------------------------------------------

@router.get("/{holder_type}/{holder_id}")
async def list_scope_conditions_for_holder(
    holder_type: str,
    holder_id:   str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """List scope conditions for a specific user or role."""
    _check_can_manage(user)

    if holder_type not in ("user", "role"):
        raise HTTPException(status_code=400, detail="holder_type must be 'user' or 'role'")

    if holder_type == "user":
        holder_id = validate_uuid(holder_id)

    cursor = await db.execute(
        "SELECT * FROM admin_scope_conditions "
        "WHERE holder_type = ? AND holder_id = ? ORDER BY field",
        (holder_type, holder_id),
    )
    conds = [AdminScopeCondition.from_row(r).to_dict() for r in await cursor.fetchall()]
    return {"conditions": conds}


# ---------------------------------------------------------------------------
# POST /admin/scopes — create a scope condition
# ---------------------------------------------------------------------------

@router.post("")
async def create_scope_condition(
    body: CreateScopeCondRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Add a scope condition to a user or role.

    holder_type='user'  → holder_id must be a valid user UUID.
    holder_type='role'  → holder_id is a role name (e.g. 'org_admin').
    """
    _check_can_manage(user)

    if body.holder_type not in ("user", "role"):
        raise HTTPException(status_code=400, detail="holder_type must be 'user' or 'role'")

    if body.operator not in VALID_OPERATORS:
        raise HTTPException(
            status_code=400,
            detail=f"operator must be one of: {', '.join(sorted(VALID_OPERATORS))}",
        )

    if not body.value or len(body.value) > _MAX_VALUE_LEN:
        raise HTTPException(status_code=400, detail=f"value is required and must be ≤{_MAX_VALUE_LEN} characters")

    # Validate holder_id
    if body.holder_type == "user":
        holder_id = validate_uuid(body.holder_id)
        # Verify user exists
        cursor = await db.execute("SELECT 1 FROM users WHERE id = ?", (holder_id,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="User not found")
    else:
        holder_id = body.holder_id
        # Verify role exists
        cursor = await db.execute("SELECT 1 FROM roles WHERE id = ?", (holder_id,))
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Role not found")

    # Verify field exists
    if not await _field_exists(db, body.field):
        raise HTTPException(status_code=400, detail=f"Unknown policy field: {body.field!r}")

    cond_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO admin_scope_conditions (id, holder_type, holder_id, field, operator, value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cond_id, body.holder_type, holder_id, body.field, body.operator, body.value),
    )
    await db.commit()
    return {"message": "Scope condition created", "id": cond_id}


# ---------------------------------------------------------------------------
# GET /admin/scopes/conditions/{cond_id}
# ---------------------------------------------------------------------------

@router.get("/conditions/{cond_id}")
async def get_scope_condition(
    cond_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Get a single scope condition by ID."""
    _check_can_manage(user)
    cond_id = validate_uuid(cond_id)
    cond = await _load_scope_cond(db, cond_id)
    return {"condition": cond.to_dict()}


# ---------------------------------------------------------------------------
# PATCH /admin/scopes/conditions/{cond_id} — update operator or value
# ---------------------------------------------------------------------------

@router.patch("/conditions/{cond_id}")
async def update_scope_condition(
    cond_id: str,
    body: UpdateScopeCondRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Update the operator and/or value of a scope condition.

    Changing operator/value may propagate through inherited policy conditions
    (they will be re-evaluated on next user login/step-up).
    """
    _check_can_manage(user)
    cond_id = validate_uuid(cond_id)
    await _load_scope_cond(db, cond_id)  # 404 guard

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

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(cond_id)
    await db.execute(
        f"UPDATE admin_scope_conditions SET {', '.join(updates)} WHERE id = ?", params
    )
    await db.commit()
    return {"message": "Scope condition updated"}


# ---------------------------------------------------------------------------
# DELETE /admin/scopes/conditions/{cond_id}
# ---------------------------------------------------------------------------

@router.delete("/conditions/{cond_id}")
async def delete_scope_condition(
    cond_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Delete a scope condition.

    Any policy_conditions that inherited from this scope condition will have
    inherited_scope_id set to NULL and scope_detached set to 1 (via DB trigger).
    Affected policies will show a review banner in the UI.
    """
    _check_can_manage(user)
    cond_id = validate_uuid(cond_id)
    await _load_scope_cond(db, cond_id)  # 404 guard

    await db.execute("DELETE FROM admin_scope_conditions WHERE id = ?", (cond_id,))
    await db.commit()
    return {"message": "Scope condition deleted"}
