"""Admin routes for sharing restrictions (Layer 1 flags + Layer 2 rules).

Endpoints
─────────
GET  /admin/sharing/flags                   — per-role sharing capability flags
PUT  /admin/sharing/flags                   — update flags for a role       [step-up]

GET  /admin/sharing/rules                   — list all rules (paginated)
POST /admin/sharing/rules                   — create rule + conditions      [step-up]
POST /admin/sharing/rules/test              — dry-run evaluation (no state change)
GET  /admin/sharing/rules/{rule_id}         — get one rule with conditions
PUT  /admin/sharing/rules/{rule_id}         — update rule + conditions      [step-up]
DELETE /admin/sharing/rules/{rule_id}       — delete rule                   [step-up]

All mutation endpoints require:
  • require_admin dependency (can_view_admin_panel)
  • FLAG_MANAGE_SHARING (can_manage_sharing)
  • Step-up token for action key "policy.sharing.*"

Lock model: is_locked=TRUE on a rule means only admins with role_tier ≤ locked_min_tier
may modify or delete it.  Priority floor enforcement prevents lower-tier admins from
inserting high-priority allow rules above a higher-authority locked deny.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.middleware.stepup import require_step_up
from app.models.role import (
    FLAG_MANAGE_SHARING,
    FLAG_CREATE_LINK_SHARES,
    FLAG_CREATE_USER_SHARES,
    FLAG_CREATE_UPLOAD_GRANTS,
    FLAG_SHARE_FOLDERS,
    ROLE_TIER,
    admin_best_tier,
)
from app.routes._access import require_flag
from app.services.sharing_rules import simulate_sharing_rules
from app.validation.sanitizers import validate_uuid

logger = logging.getLogger(__name__)

router = APIRouter()

_STEPUP = "policy.sharing.*"

_SHARING_CAPABILITY_FLAGS = [
    FLAG_CREATE_LINK_SHARES,
    FLAG_CREATE_USER_SHARES,
    FLAG_CREATE_UPLOAD_GRANTS,
    FLAG_SHARE_FOLDERS,
]

_VALID_OPERATORS = frozenset({
    "eq", "neq", "contains", "not_contains", "starts_with", "ends_with",
    "in", "not_in", "matches_re", "cross_eq", "cross_neq",
})
_CROSS_OPERATORS = frozenset({"cross_eq", "cross_neq"})
_VALID_SUBJECTS = frozenset({"sender", "recipient", "cross"})
_VALID_EFFECTS = frozenset({"deny", "allow"})
_VALID_SHARE_TYPES = frozenset({"link", "user"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------



def _admin_tier(admin: AuthenticatedUser) -> int:
    return admin_best_tier(admin.roles)


def _check_rule_lock(rule: dict, my_tier: int) -> None:
    if rule["is_locked"] and rule["locked_min_tier"] is not None:
        if my_tier > rule["locked_min_tier"]:
            raise HTTPException(
                status_code=403,
                detail=f"Rule is locked — requires role tier ≤ {rule['locked_min_tier']} to modify",
            )


async def _check_priority_floor(db, actor_tier: int, new_priority: int) -> None:
    """Prevent lower-tier admins from inserting rules above locked higher-authority rules."""
    cursor = await db.execute(
        "SELECT MAX(priority) AS floor FROM sharing_rules "
        "WHERE is_locked = TRUE AND created_by_tier < ?",
        (actor_tier,),
    )
    row = await cursor.fetchone()
    floor = row["floor"] if row and row["floor"] is not None else None
    if floor is not None and new_priority <= floor:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Priority {new_priority} would place this rule above a locked "
                f"higher-authority rule (priority {floor}). Use priority > {floor}."
            ),
        )


async def _rule_to_dict(db, rule: dict) -> dict:
    cond_cursor = await db.execute(
        "SELECT * FROM sharing_rule_conditions WHERE rule_id = ? ORDER BY id",
        (rule["id"],),
    )
    conditions = [
        {
            "id": c["id"],
            "attribute_path": c["attribute_path"],
            "attribute_path2": c["attribute_path2"],
            "operator": c["operator"],
            "value": c["value"],
            "block_on_missing_attribute": bool(c["block_on_missing_attribute"]),
        }
        for c in await cond_cursor.fetchall()
    ]
    return {
        "id": rule["id"],
        "name": rule["name"],
        "description": rule["description"],
        "is_active": bool(rule["is_active"]),
        "priority": rule["priority"],
        "subject": rule["subject"],
        "applies_to_share_type": rule["applies_to_share_type"],
        "effect": rule["effect"],
        "is_locked": bool(rule["is_locked"]),
        "locked_min_tier": rule["locked_min_tier"],
        "created_by": rule["created_by"],
        "created_by_tier": rule["created_by_tier"],
        "created_at": rule["created_at"],
        "updated_at": rule["updated_at"],
        "conditions": conditions,
    }


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ConditionIn(BaseModel):
    attribute_path: str
    attribute_path2: str | None = None
    operator: str
    value: str | None = None
    block_on_missing_attribute: bool = True

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        if v not in _VALID_OPERATORS:
            raise ValueError(f"Unknown operator '{v}'")
        return v

    @field_validator("attribute_path", "attribute_path2")
    @classmethod
    def validate_path(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if "." not in v:
            raise ValueError("attribute_path must be '<source>.<attribute>' (e.g. 'internal.email')")
        source = v.split(".")[0]
        if source not in ("internal", "ldap", "oidc"):
            raise ValueError("Attribute source must be 'internal', 'ldap', or 'oidc'")
        return v


class CreateRuleRequest(BaseModel):
    name: str
    description: str | None = None
    is_active: bool = True
    priority: int = 100
    subject: str
    applies_to_share_type: str | None = None
    effect: str = "deny"
    is_locked: bool = False
    locked_min_tier: int | None = None
    conditions: list[ConditionIn] = []

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, v: str) -> str:
        if v not in _VALID_SUBJECTS:
            raise ValueError(f"subject must be one of {sorted(_VALID_SUBJECTS)}")
        return v

    @field_validator("effect")
    @classmethod
    def validate_effect(cls, v: str) -> str:
        if v not in _VALID_EFFECTS:
            raise ValueError("effect must be 'deny' or 'allow'")
        return v

    @field_validator("applies_to_share_type")
    @classmethod
    def validate_share_type(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_SHARE_TYPES:
            raise ValueError("applies_to_share_type must be 'link', 'user', or null")
        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: int) -> int:
        if v < 1 or v > 10000:
            raise ValueError("priority must be 1–10000")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        if len(v) > 200:
            raise ValueError("name must be ≤ 200 characters")
        return v


class UpdateRuleRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    is_active: bool | None = None
    priority: int | None = None
    subject: str | None = None
    applies_to_share_type: str | None = None
    effect: str | None = None
    is_locked: bool | None = None
    locked_min_tier: int | None = None
    conditions: list[ConditionIn] | None = None

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_SUBJECTS:
            raise ValueError(f"subject must be one of {sorted(_VALID_SUBJECTS)}")
        return v

    @field_validator("effect")
    @classmethod
    def validate_effect(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_EFFECTS:
            raise ValueError("effect must be 'deny' or 'allow'")
        return v

    @field_validator("applies_to_share_type")
    @classmethod
    def validate_share_type(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_SHARE_TYPES:
            raise ValueError("applies_to_share_type must be 'link', 'user', or null")
        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 10000):
            raise ValueError("priority must be 1–10000")
        return v


class UpdateFlagsRequest(BaseModel):
    role_id: str
    flags: dict[str, bool]

    @field_validator("flags")
    @classmethod
    def validate_flags(cls, v: dict) -> dict:
        for flag in v:
            if flag not in _SHARING_CAPABILITY_FLAGS:
                raise ValueError(
                    f"Unknown sharing flag '{flag}'. "
                    f"Valid flags: {_SHARING_CAPABILITY_FLAGS}"
                )
        return v


class TestRulesRequest(BaseModel):
    sender_user_id: str
    recipient_user_id: str | None = None
    share_type: str

    @field_validator("sender_user_id")
    @classmethod
    def validate_sender(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("recipient_user_id")
    @classmethod
    def validate_recipient(cls, v: str | None) -> str | None:
        if v is not None:
            return validate_uuid(v)
        return v

    @field_validator("share_type")
    @classmethod
    def validate_share_type(cls, v: str) -> str:
        if v not in _VALID_SHARE_TYPES:
            raise ValueError("share_type must be 'link' or 'user'")
        return v


# ---------------------------------------------------------------------------
# Flag endpoints
# ---------------------------------------------------------------------------

@router.get("/flags")
async def get_sharing_flags(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Return sharing capability flag assignments for every role that has any of the 4 flags."""
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")

    placeholders = ",".join(["?" for _ in _SHARING_CAPABILITY_FLAGS])
    cursor = await db.execute(
        f"""
        SELECT rp.role_id, rp.flag, rp.value,
               r.name AS role_name, r.is_system
        FROM role_permissions rp
        JOIN roles r ON r.id = rp.role_id
        WHERE rp.flag IN ({placeholders})
        ORDER BY rp.role_id, rp.flag
        """,
        tuple(_SHARING_CAPABILITY_FLAGS),
    )
    rows = await cursor.fetchall()

    # Group by role
    roles: dict[str, dict] = {}
    for row in rows:
        rid = row["role_id"]
        if rid not in roles:
            roles[rid] = {
                "role_id": rid,
                "role_name": row["role_name"],
                "is_system": bool(row["is_system"]),
                "flags": {},
            }
        roles[rid]["flags"][row["flag"]] = row["value"] not in ("0", "", "false", "False")

    return {
        "sharing_flags": _SHARING_CAPABILITY_FLAGS,
        "roles": list(roles.values()),
    }


@router.put("/flags")
async def update_sharing_flags(
    body: UpdateFlagsRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    _stepup=Depends(require_step_up(_STEPUP)),
    db=Depends(get_db),
):
    """Update sharing capability flags for a role.

    Body: { role_id, flags: { flag_name: true|false, ... } }
    Only the specified flags are updated; others are untouched.
    """
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")

    # Verify role exists
    cursor = await db.execute("SELECT id FROM roles WHERE id = ?", (body.role_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Role not found")

    for flag, enabled in body.flags.items():
        value = "1" if enabled else "0"
        await db.execute(
            "INSERT INTO role_permissions (role_id, flag, value) VALUES (?, ?, ?) "
            "ON CONFLICT (role_id, flag) DO UPDATE SET value = EXCLUDED.value",
            (body.role_id, flag, value),
        )

    await db.commit()
    return {"message": "Sharing flags updated", "role_id": body.role_id}


# ---------------------------------------------------------------------------
# Rule endpoints
# ---------------------------------------------------------------------------

@router.get("/rules")
async def list_sharing_rules(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    active_only: bool = Query(False),
):
    """List all sharing rules ordered by priority."""
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")

    where = "WHERE is_active = TRUE" if active_only else ""
    cursor = await db.execute(
        f"SELECT * FROM sharing_rules {where} ORDER BY priority ASC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rules = await cursor.fetchall()

    count_cursor = await db.execute(
        f"SELECT COUNT(*) FROM sharing_rules {where}"
    )
    total = (await count_cursor.fetchone())[0]

    result = []
    for rule in rules:
        result.append(await _rule_to_dict(db, dict(rule)))

    return {"rules": result, "total": total, "offset": offset, "limit": limit}


@router.post("/rules/test")
async def test_sharing_rules(
    body: TestRulesRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Dry-run rule evaluation for a given sender + optional recipient + share_type.

    Returns the list of rules that would fire, in evaluation order.
    No state is changed; no security events are emitted.
    """
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")

    # Verify sender exists
    cursor = await db.execute("SELECT id FROM users WHERE id = ?", (body.sender_user_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Sender user not found")

    if body.recipient_user_id:
        cursor = await db.execute(
            "SELECT id FROM users WHERE id = ?", (body.recipient_user_id,)
        )
        if await cursor.fetchone() is None:
            raise HTTPException(status_code=404, detail="Recipient user not found")

    matching = await simulate_sharing_rules(
        db, body.sender_user_id, body.recipient_user_id, body.share_type
    )

    outcome = "allow"
    for m in matching:
        if m["effect"] == "deny":
            outcome = "deny"
            break

    return {
        "outcome": outcome,
        "matching_rules": matching,
        "share_type": body.share_type,
    }


@router.post("/rules")
async def create_sharing_rule(
    body: CreateRuleRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    _stepup=Depends(require_step_up(_STEPUP)),
    db=Depends(get_db),
):
    """Create a sharing rule with its conditions."""
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")

    my_tier = _admin_tier(admin)

    # Cannot lock at a tier higher than one's own (i.e. smaller tier number)
    if body.is_locked and body.locked_min_tier is not None:
        if body.locked_min_tier < my_tier:
            raise HTTPException(
                status_code=400,
                detail="Cannot lock at a tier higher than your own",
            )

    await _check_priority_floor(db, my_tier, body.priority)

    # Cross-operator conditions require a cross-subject rule
    for cond in body.conditions:
        if cond.operator in _CROSS_OPERATORS and body.subject != "cross":
            raise HTTPException(
                status_code=400,
                detail=f"Operator '{cond.operator}' is only valid for subject='cross' rules",
            )

    rule_id = str(uuid.uuid4())
    await db.execute(
        """
        INSERT INTO sharing_rules
            (id, name, description, is_active, priority, subject,
             applies_to_share_type, effect, is_locked, locked_min_tier,
             created_by, created_by_tier)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rule_id, body.name, body.description, body.is_active,
            body.priority, body.subject, body.applies_to_share_type,
            body.effect, body.is_locked, body.locked_min_tier,
            admin.id, my_tier,
        ),
    )

    for cond in body.conditions:
        await db.execute(
            """
            INSERT INTO sharing_rule_conditions
                (id, rule_id, attribute_path, attribute_path2, operator,
                 value, block_on_missing_attribute)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), rule_id,
                cond.attribute_path, cond.attribute_path2,
                cond.operator, cond.value,
                cond.block_on_missing_attribute,
            ),
        )

    await db.commit()

    cursor = await db.execute("SELECT * FROM sharing_rules WHERE id = ?", (rule_id,))
    rule = await cursor.fetchone()
    return await _rule_to_dict(db, dict(rule))


@router.get("/rules/{rule_id}")
async def get_sharing_rule(
    rule_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Get a single sharing rule with its conditions."""
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")
    rule_id = validate_uuid(rule_id)

    cursor = await db.execute("SELECT * FROM sharing_rules WHERE id = ?", (rule_id,))
    rule = await cursor.fetchone()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    return await _rule_to_dict(db, dict(rule))


@router.put("/rules/{rule_id}")
async def update_sharing_rule(
    rule_id: str,
    body: UpdateRuleRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    _stepup=Depends(require_step_up(_STEPUP)),
    db=Depends(get_db),
):
    """Update a sharing rule's metadata and/or replace its conditions."""
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")
    rule_id = validate_uuid(rule_id)

    cursor = await db.execute("SELECT * FROM sharing_rules WHERE id = ?", (rule_id,))
    existing = await cursor.fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    my_tier = _admin_tier(admin)
    _check_rule_lock(dict(existing), my_tier)

    new_priority = body.priority if body.priority is not None else existing["priority"]
    if body.priority is not None:
        await _check_priority_floor(db, my_tier, new_priority)

    new_locked = body.is_locked if body.is_locked is not None else bool(existing["is_locked"])
    new_locked_tier = body.locked_min_tier if body.locked_min_tier is not None else existing["locked_min_tier"]
    if new_locked and new_locked_tier is not None and new_locked_tier < my_tier:
        raise HTTPException(
            status_code=400,
            detail="Cannot lock at a tier higher than your own",
        )

    new_subject = body.subject if body.subject is not None else existing["subject"]
    if body.conditions is not None:
        for cond in body.conditions:
            if cond.operator in _CROSS_OPERATORS and new_subject != "cross":
                raise HTTPException(
                    status_code=400,
                    detail=f"Operator '{cond.operator}' is only valid for subject='cross' rules",
                )

    # Apply updates
    await db.execute(
        """
        UPDATE sharing_rules SET
            name        = COALESCE(?, name),
            description = COALESCE(?, description),
            is_active   = COALESCE(?, is_active),
            priority    = COALESCE(?, priority),
            subject     = COALESCE(?, subject),
            applies_to_share_type = COALESCE(?, applies_to_share_type),
            effect      = COALESCE(?, effect),
            is_locked   = ?,
            locked_min_tier = ?,
            updated_at  = NOW()
        WHERE id = ?
        """,
        (
            body.name,
            body.description,
            body.is_active,
            body.priority,
            body.subject,
            body.applies_to_share_type,
            body.effect,
            new_locked,
            new_locked_tier,
            rule_id,
        ),
    )

    if body.conditions is not None:
        await db.execute(
            "DELETE FROM sharing_rule_conditions WHERE rule_id = ?", (rule_id,)
        )
        for cond in body.conditions:
            await db.execute(
                """
                INSERT INTO sharing_rule_conditions
                    (id, rule_id, attribute_path, attribute_path2, operator,
                     value, block_on_missing_attribute)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), rule_id,
                    cond.attribute_path, cond.attribute_path2,
                    cond.operator, cond.value,
                    cond.block_on_missing_attribute,
                ),
            )

    await db.commit()

    cursor = await db.execute("SELECT * FROM sharing_rules WHERE id = ?", (rule_id,))
    rule = await cursor.fetchone()
    return await _rule_to_dict(db, dict(rule))


@router.delete("/rules/{rule_id}")
async def delete_sharing_rule(
    rule_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    _stepup=Depends(require_step_up(_STEPUP)),
    db=Depends(get_db),
):
    """Delete a sharing rule and all its conditions."""
    require_flag(admin, FLAG_MANAGE_SHARING, "can_manage_sharing permission required")
    rule_id = validate_uuid(rule_id)

    cursor = await db.execute("SELECT * FROM sharing_rules WHERE id = ?", (rule_id,))
    rule = await cursor.fetchone()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    my_tier = _admin_tier(admin)
    _check_rule_lock(dict(rule), my_tier)

    await db.execute("DELETE FROM sharing_rules WHERE id = ?", (rule_id,))
    await db.commit()

    return {"message": "Rule deleted", "rule_id": rule_id}
