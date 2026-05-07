"""Policy field definition management routes.

Mounted at /api/v1/admin/policy-fields.

Policy fields are the registry of valid condition attributes that can be used
when building policy conditions.  There are two categories:

  source='internal'  — seeded at schema init time; not user-editable; always available.
  source='ldap'      — registered by admins with can_define_policy_fields.
  source='oidc'      — registered by admins with can_define_policy_fields.

Access control:
  GET  (list / get)  — any admin with can_manage_policies
  POST / PATCH / DELETE — requires can_define_policy_fields (high-tier only)

Internal fields cannot be edited or deleted via the API.
"""

import re as _re
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.models.policy import PolicyFieldDef, VALID_OPERATORS
from app.models.role import FLAG_MANAGE_POLICIES
from app.routes._access import require_flag
from typing import Annotated


_ERR_PERM_POLICY_FIELDS = "can_define_policy_fields required"

router = APIRouter()

FLAG_DEFINE_POLICY_FIELDS = "can_define_policy_fields"

# Field name must be a simple snake_case identifier
_FIELD_NAME_RE = _re.compile(r'^[a-z][a-z0-9_]{0,63}$')
_MAX_LABEL_LEN = 80
_MAX_CLAIM_PATH_LEN = 200

_VALID_SOURCES    = frozenset({"ldap", "oidc"})    # internal cannot be created via API
_VALID_DATA_TYPES = frozenset({"string", "boolean"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------



async def _load_field(db, name: str) -> PolicyFieldDef:
    cursor = await db.execute(
        "SELECT * FROM policy_field_definitions WHERE name = ?", (name,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Policy field not found")  # NOSONAR — helper; 404 documented in callers
    return PolicyFieldDef.from_row(row)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateFieldRequest(BaseModel):
    name:          str
    display_label: str
    source:        str           # 'ldap' or 'oidc'
    data_type:     str = "string"
    claim_path:    str           # required for ldap/oidc


class UpdateFieldRequest(BaseModel):
    display_label: str | None = None
    claim_path:    str | None = None


# ---------------------------------------------------------------------------
# GET /policy-fields — list all field definitions
# ---------------------------------------------------------------------------

@router.get("")
async def list_policy_fields(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all registered policy field definitions.

    Returns internal (non-editable) and admin-registered fields.
    Any admin with can_manage_policies can view the registry.
    """
    require_flag(user, FLAG_MANAGE_POLICIES, "can_manage_policies required")
    cursor = await db.execute(
        "SELECT * FROM policy_field_definitions ORDER BY source, name"
    )
    fields = [PolicyFieldDef.from_row(r).to_dict() for r in await cursor.fetchall()]
    return {"fields": fields}


# ---------------------------------------------------------------------------
# POST /policy-fields — register a new LDAP/OIDC field
# ---------------------------------------------------------------------------

@router.post("", responses={400: {"description": "Bad Request"}, 409: {"description": "Conflict"}})
async def create_policy_field(
    body: CreateFieldRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Register a new LDAP or OIDC attribute field for use in policy conditions.

    Requires can_define_policy_fields.  Internal fields cannot be created via
    the API — they are seeded by the migration.
    """
    require_flag(user, FLAG_DEFINE_POLICY_FIELDS, _ERR_PERM_POLICY_FIELDS)

    if not _FIELD_NAME_RE.match(body.name):
        raise HTTPException(
            status_code=400,
            detail="Field name must be 1–64 lowercase alphanumeric characters / underscores, starting with a letter",
        )
    if len(body.display_label) < 1 or len(body.display_label) > _MAX_LABEL_LEN:
        raise HTTPException(status_code=400, detail=f"Display label must be 1–{_MAX_LABEL_LEN} characters")
    if body.source not in _VALID_SOURCES:
        raise HTTPException(status_code=400, detail=f"source must be one of: {', '.join(sorted(_VALID_SOURCES))}")
    if body.data_type not in _VALID_DATA_TYPES:
        raise HTTPException(status_code=400, detail=f"data_type must be one of: {', '.join(sorted(_VALID_DATA_TYPES))}")
    if not body.claim_path or len(body.claim_path) > _MAX_CLAIM_PATH_LEN:
        raise HTTPException(status_code=400, detail=f"claim_path is required and must be ≤{_MAX_CLAIM_PATH_LEN} characters")

    try:
        await db.execute(
            "INSERT INTO policy_field_definitions "
            "(name, display_label, source, data_type, claim_path, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (body.name, body.display_label, body.source, body.data_type, body.claim_path, user.id),
        )
        await db.commit()
    except Exception:
        raise HTTPException(status_code=409, detail="A field with that name already exists")

    field = await _load_field(db, body.name)
    return field.to_dict()


# ---------------------------------------------------------------------------
# GET /policy-fields/{name}
# ---------------------------------------------------------------------------

@router.get("/{name}")
async def get_policy_field(
    name: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get a single policy field definition."""
    require_flag(user, FLAG_MANAGE_POLICIES, "can_manage_policies required")
    field = await _load_field(db, name)
    return {"field": field.to_dict()}


# ---------------------------------------------------------------------------
# PATCH /policy-fields/{name} — update display_label or claim_path
# ---------------------------------------------------------------------------

@router.patch("/{name}", responses={400: {"description": "Bad Request"}})
async def update_policy_field(
    name: str,
    body: UpdateFieldRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Update the display label and/or claim_path of an LDAP/OIDC field.

    Internal fields (source='internal') cannot be edited.
    Requires can_define_policy_fields.
    """
    require_flag(user, FLAG_DEFINE_POLICY_FIELDS, _ERR_PERM_POLICY_FIELDS)

    field = await _load_field(db, name)
    if field.source == "internal":
        raise HTTPException(status_code=400, detail="Internal fields cannot be edited")

    updates = []
    params  = []

    if body.display_label is not None:
        if len(body.display_label) < 1 or len(body.display_label) > _MAX_LABEL_LEN:
            raise HTTPException(status_code=400, detail=f"Display label must be 1–{_MAX_LABEL_LEN} characters")
        updates.append("display_label = ?")
        params.append(body.display_label)

    if body.claim_path is not None:
        if len(body.claim_path) > _MAX_CLAIM_PATH_LEN:
            raise HTTPException(status_code=400, detail=f"claim_path must be ≤{_MAX_CLAIM_PATH_LEN} characters")
        updates.append("claim_path = ?")
        params.append(body.claim_path)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(name)
    await db.execute(f"UPDATE policy_field_definitions SET {', '.join(updates)} WHERE name = ?", params)
    await db.commit()
    return {"message": "Policy field updated"}


# ---------------------------------------------------------------------------
# DELETE /policy-fields/{name}
# ---------------------------------------------------------------------------

@router.delete("/{name}", responses={400: {"description": "Bad Request"}, 409: {"description": "Conflict"}})
async def delete_policy_field(
    name: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete an LDAP/OIDC field definition.

    Blocked if:
      • The field is source='internal' (system-seeded).
      • The field is referenced by any active policy_condition or
        admin_scope_condition (RESTRICT FK prevents orphaned conditions).
    Requires can_define_policy_fields.
    """
    require_flag(user, FLAG_DEFINE_POLICY_FIELDS, _ERR_PERM_POLICY_FIELDS)

    field = await _load_field(db, name)
    if field.source == "internal":
        raise HTTPException(status_code=400, detail="Internal fields cannot be deleted")

    # Check for in-use references
    cursor = await db.execute(
        "SELECT COUNT(*) FROM policy_conditions WHERE field = ?", (name,)
    )
    row = await cursor.fetchone()
    if row and row[0] > 0:
        raise HTTPException(
            status_code=409,
            detail="Field is referenced by one or more policy conditions and cannot be deleted",
        )

    cursor = await db.execute(
        "SELECT COUNT(*) FROM admin_scope_conditions WHERE field = ?", (name,)
    )
    row = await cursor.fetchone()
    if row and row[0] > 0:
        raise HTTPException(
            status_code=409,
            detail="Field is referenced by one or more admin scope conditions and cannot be deleted",
        )

    await db.execute("DELETE FROM policy_field_definitions WHERE name = ?", (name,))
    await db.commit()
    return {"message": "Policy field deleted"}
