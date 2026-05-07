"""Policy engine models and evaluation logic.

Core concepts
─────────────
PolicyFieldDef      — a registered condition field (internal DB field, LDAP attr, or OIDC claim)
AdminScopeCondition — restricts the universe of users an admin can target
Policy              — a named rule set scoped to the org or a single team
PolicyCondition     — a single attribute condition on a policy (all ANDed)
PolicyFolderGrant   — materialised grant written after policy evaluation

evaluate_user_policies(db, user_id)
    Splits conditions by source, resolves each group, evaluates the combined
    AND-list, and writes policy_folder_grants accordingly.  Updates
    users.policy_last_evaluated_at so callers can debounce.

LDAP integration note
─────────────────────
LDAP support requires the identity_providers table.  The resolver
gracefully no-ops if no LDAP integration is configured, treating all ldap-source
conditions as non-matching (conservative default).
"""

from __future__ import annotations

import logging
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Approved operator vocabulary (no raw regex — ReDoS risk + non-auditable)
# ---------------------------------------------------------------------------
VALID_OPERATORS: frozenset[str] = frozenset({"=", "!=", "contains", "starts_with", "ends_with", "in"})

# Debounce: skip policy evaluation if last run was within this many seconds
_DEBOUNCE_SECONDS = 300  # 5 minutes
_SQL_HAS_TEAM_KEY = "SELECT 1 FROM user_team_keys WHERE team_id = ? AND user_id = ?"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PolicyFieldDef:
    name:          str
    display_label: str
    source:        str          # 'internal' | 'ldap' | 'oidc'
    data_type:     str          # 'string' | 'boolean'
    claim_path:    str | None   # LDAP attribute or OIDC claim key; None for internal
    created_by:    str | None
    created_at:    str

    @classmethod
    def from_row(cls, row) -> "PolicyFieldDef":
        return cls(
            name=row["name"],
            display_label=row["display_label"],
            source=row["source"],
            data_type=row["data_type"],
            claim_path=row["claim_path"],
            created_by=row["created_by"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "name":          self.name,
            "display_label": self.display_label,
            "source":        self.source,
            "data_type":     self.data_type,
            "claim_path":    self.claim_path,
            "created_by":    self.created_by,
            "created_at":    self.created_at,
        }


@dataclass
class AdminScopeCondition:
    id:          str
    holder_type: str   # 'user' | 'role'
    holder_id:   str   # user_id or role name
    field:       str
    operator:    str
    value:       str

    @classmethod
    def from_row(cls, row) -> "AdminScopeCondition":
        return cls(
            id=row["id"],
            holder_type=row["holder_type"],
            holder_id=row["holder_id"],
            field=row["field"],
            operator=row["operator"],
            value=row["value"],
        )

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "holder_type": self.holder_type,
            "holder_id":   self.holder_id,
            "field":       self.field,
            "operator":    self.operator,
            "value":       self.value,
        }


@dataclass
class Policy:
    id:             str
    name:           str
    scope_type:     str          # 'org' | 'team'
    scope_id:       str | None   # team_id or None
    escrow_enabled: bool         # whether escrow grants are written for covered teams
    created_by:     str | None
    created_at:     str

    @classmethod
    def from_row(cls, row) -> "Policy":
        return cls(
            id=row["id"],
            name=row["name"],
            scope_type=row["scope_type"],
            scope_id=row["scope_id"],
            escrow_enabled=bool(row["escrow_enabled"]) if row["escrow_enabled"] is not None else False,
            created_by=row["created_by"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "name":           self.name,
            "scope_type":     self.scope_type,
            "scope_id":       self.scope_id,
            "escrow_enabled": self.escrow_enabled,
            "created_by":     self.created_by,
            "created_at":     self.created_at,
        }


@dataclass
class PolicyCondition:
    id:                 str
    policy_id:          str
    field:              str
    operator:           str
    value:              str
    inherited_scope_id: str | None
    scope_detached:     bool
    strict:             bool

    @classmethod
    def from_row(cls, row) -> "PolicyCondition":
        return cls(
            id=row["id"],
            policy_id=row["policy_id"],
            field=row["field"],
            operator=row["operator"],
            value=row["value"],
            inherited_scope_id=row["inherited_scope_id"],
            scope_detached=bool(row["scope_detached"]),
            strict=bool(row["strict"]),
        )

    def to_dict(self) -> dict:
        return {
            "id":                 self.id,
            "policy_id":          self.policy_id,
            "field":              self.field,
            "operator":           self.operator,
            "value":              self.value,
            "inherited_scope_id": self.inherited_scope_id,
            "scope_detached":     self.scope_detached,
            "strict":             self.strict,
        }


@dataclass
class PolicyEffect:
    id:              str
    policy_id:       str
    effect_type:     str                # 'team_member' | 'folder_acl' | 'team_escrow'
    target_id:       str                # team_id or folder_id
    role_level:      str | None         # roles.id for team_member; None otherwise
    permission:      str | None         # 'read'|'write'|'admin' for folder_acl; None otherwise
    recursive:       bool
    escrow_override: int | None = None  # None=use policy default, 1=force-on, 0=force-off
    created_at:      str = ""

    @classmethod
    def from_row(cls, row) -> "PolicyEffect":
        return cls(
            id=row["id"],
            policy_id=row["policy_id"],
            effect_type=row["effect_type"],
            target_id=row["target_id"],
            role_level=row["role_level"],
            permission=row["permission"],
            recursive=bool(row["recursive"]),
            escrow_override=row["escrow_override"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "policy_id":       self.policy_id,
            "effect_type":     self.effect_type,
            "target_id":       self.target_id,
            "role_level":      self.role_level,
            "permission":      self.permission,
            "recursive":       self.recursive,
            "escrow_override": self.escrow_override,
            "created_at":      self.created_at,
        }


@dataclass
class PolicyTeamGrant:
    id:          str
    effect_id:   str
    user_id:     str
    key_wrapped: bool
    granted_at:  str

    @classmethod
    def from_row(cls, row) -> "PolicyTeamGrant":
        return cls(
            id=row["id"],
            effect_id=row["effect_id"],
            user_id=row["user_id"],
            key_wrapped=bool(row["key_wrapped"]),
            granted_at=row["granted_at"],
        )


@dataclass
class PolicyFolderGrant:
    id:          str
    effect_id:   str
    user_id:     str
    folder_id:   str
    acl_written: bool
    key_wrapped: bool
    granted_at:  str

    @classmethod
    def from_row(cls, row) -> "PolicyFolderGrant":
        return cls(
            id=row["id"],
            effect_id=row["effect_id"],
            user_id=row["user_id"],
            folder_id=row["folder_id"],
            acl_written=bool(row["acl_written"]),
            key_wrapped=bool(row["key_wrapped"]),
            granted_at=row["granted_at"],
        )


# ---------------------------------------------------------------------------
# Internal field resolver
# ---------------------------------------------------------------------------

async def _resolve_totp_field(db, user_id: str) -> str:
    try:
        cursor = await db.execute("SELECT totp_enabled FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return "1" if (row and row["totp_enabled"]) else "0"
    except Exception:
        return "0"


def _set_provider_result(result: dict, fields: set, provider_type: str | None, name: str | None) -> None:
    if "auth_provider" in fields:
        result["auth_provider"] = provider_type or "opaque"
    if "identity_provider" in fields:
        result["identity_provider"] = name or ""


async def _resolve_provider_fields(db, user_id: str, fields: set) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        cursor = await db.execute(
            "SELECT ip.provider_type, ip.name "
            "FROM users u "
            "LEFT JOIN identity_provider_users ipu ON ipu.user_id = u.id "
            "LEFT JOIN identity_providers ip ON ip.id = ipu.provider_id "
            "WHERE u.id = ?",
            (user_id,),
        )
        row = await cursor.fetchone()
        if row is None or row["provider_type"] is None:
            _set_provider_result(result, fields, None, None)
        else:
            _set_provider_result(result, fields, row["provider_type"], row["name"])
    except Exception:
        # identity_providers table not available — treat as opaque user
        _set_provider_result(result, fields, None, None)
    return result


async def resolve_internal_fields(db, user_id: str, fields: set[str]) -> dict[str, str]:
    """Resolve internal policy fields from the local DB for a user.

    Returns a dict of {field_name: string_value} for each requested field.
    Missing fields are omitted — callers should treat absence as non-matching.

    Supported internal fields (seeded in schema.sql):
      totp_enabled      — '1' if user has TOTP active, '0' otherwise
      auth_provider     — 'opaque' | 'oidc' | 'ldap'
      identity_provider — the identity_providers.name for non-opaque users, or None
    """
    if not fields:
        return {}

    result: dict[str, str] = {}

    if "totp_enabled" in fields:
        result["totp_enabled"] = await _resolve_totp_field(db, user_id)

    if "auth_provider" in fields or "identity_provider" in fields:
        result.update(await _resolve_provider_fields(db, user_id, fields))

    return result


# ---------------------------------------------------------------------------
# LDAP filter builder
# ---------------------------------------------------------------------------

def _ldap_condition_to_filter(attr: str, val: str, op: str) -> str | None:
    """Translate a single operator into an LDAP filter fragment.  Returns None to skip."""
    if op == "=":
        return f"({attr}={val})"
    if op == "!=":
        return f"(!({attr}={val}))"
    if op == "contains":
        return f"({attr}=*{val}*)"
    if op == "starts_with":
        return f"({attr}={val}*)"
    if op == "ends_with":
        return f"({attr}=*{val})"
    if op == "in":
        members = [m.strip() for m in val.split(",") if m.strip()]
        if not members:
            return None
        if len(members) == 1:
            return f"({attr}={members[0]})"
        inner = "".join(f"({attr}={m})" for m in members)
        return f"(|{inner})"
    return None


def build_ldap_filter(conditions: list[PolicyCondition], field_defs: dict[str, PolicyFieldDef]) -> str:
    """Translate a list of ldap-source conditions into a single LDAP filter string.

    All conditions are ANDed: (&(attr1=val1)(attr2=*val2*))

    Uses claim_path from the field definition as the raw LDAP attribute name.
    Conditions whose field has no claim_path are skipped (should not occur
    for valid ldap-source fields, but defensive guard).
    """
    parts: list[str] = []

    for cond in conditions:
        fdef = field_defs.get(cond.field)
        if fdef is None or not fdef.claim_path:
            logger.warning("policy: skipping ldap condition for field %r — no claim_path", cond.field)
            continue
        part = _ldap_condition_to_filter(fdef.claim_path, cond.value, cond.operator)
        if part is not None:
            parts.append(part)

    if not parts:
        # No translatable conditions — caller should treat as no-match
        return ""
    if len(parts) == 1:
        return parts[0]
    return "(&" + "".join(parts) + ")"


# ---------------------------------------------------------------------------
# Condition evaluator (local values only — for internal + oidc-cache resolution)
# ---------------------------------------------------------------------------

def _evaluate_condition(cond: PolicyCondition, actual_value: str) -> bool:
    """Evaluate a single condition against a resolved string value.

    case_sensitive is used for 'strict' conditions; default is case-insensitive.
    'in' operator treats cond.value as a comma-separated list.
    """
    op    = cond.operator
    cv    = cond.value
    av    = actual_value

    if not cond.strict:
        cv = cv.lower()
        av = av.lower()

    if op == "=":
        return av == cv
    elif op == "!=":
        return av != cv
    elif op == "contains":
        return cv in av
    elif op == "starts_with":
        return av.startswith(cv)
    elif op == "ends_with":
        return av.endswith(cv)
    elif op == "in":
        members = {m.strip().lower() if not cond.strict else m.strip()
                   for m in cv.split(",") if m.strip()}
        return av in members
    return False


# ---------------------------------------------------------------------------
# Admin scope: resolve the effective scope for an admin user
# ---------------------------------------------------------------------------

async def get_user_effective_scope(db, user_id: str) -> list[AdminScopeCondition]:
    """Return the list of ALL scope conditions applicable to a user.

    Collects per-user conditions (holder_type='user', holder_id=user_id) plus
    per-role conditions for all global roles held by this user.  The caller
    ANDs all conditions together to determine the narrowest allowed scope.
    """
    cursor = await db.execute(
        """
        SELECT asc_cond.*
        FROM admin_scope_conditions asc_cond
        WHERE (asc_cond.holder_type = 'user' AND asc_cond.holder_id = ?)
           OR (asc_cond.holder_type = 'role' AND asc_cond.holder_id IN (
                   SELECT role_id FROM user_roles
                   WHERE user_id = ? AND scope_type IS NULL
               ))
        """,
        (user_id, user_id),
    )
    return [AdminScopeCondition.from_row(r) for r in await cursor.fetchall()]


async def _resolve_all_policy_fields(
    db,
    user_id: str,
    all_conditions: list,
    field_defs: dict,
) -> dict[str, str]:
    internal_fields_needed = {
        c.field for c in all_conditions
        if field_defs.get(c.field) and field_defs[c.field].source == "internal"
    }
    internal_values = await resolve_internal_fields(db, user_id, internal_fields_needed)

    ldap_conditions = [
        c for c in all_conditions
        if field_defs.get(c.field) and field_defs[c.field].source == "ldap"
    ]
    ldap_values: dict[str, str] = {}
    if ldap_conditions:
        ldap_values = await _resolve_ldap_fields(db, user_id, ldap_conditions, field_defs)

    oidc_conditions = [
        c for c in all_conditions
        if field_defs.get(c.field) and field_defs[c.field].source == "oidc"
    ]
    oidc_values: dict[str, str] = {}
    if oidc_conditions:
        oidc_values = await _resolve_oidc_fields(db, user_id, oidc_conditions, field_defs)

    return {**internal_values, **ldap_values, **oidc_values}


async def _apply_team_member_effect(
    db,
    user_id: str,
    effect_id: str,
    target_id: str,
    role_level: str | None,
    policy_id: str,
    policy_escrow_map: dict,
    escrow_overrides: dict,
    escrow_agent_ids: list[str],
) -> None:
    if not role_level:
        logger.warning("policy: team_member effect %s has no role_level — skipping", effect_id)
        return

    ur_id = str(_uuid.uuid4())
    await db.execute(
        "INSERT INTO user_roles "
        "(id, user_id, role_id, scope_type, scope_id, granted_by, policy_effect_id) "
        "VALUES (?, ?, ?, 'team', ?, NULL, ?) "
        "ON CONFLICT DO NOTHING",
        (ur_id, user_id, role_level, target_id, effect_id),
    )

    cursor = await db.execute(_SQL_HAS_TEAM_KEY, (target_id, user_id))
    has_key = await cursor.fetchone() is not None

    tg_id = str(_uuid.uuid4())
    await db.execute(
        "INSERT INTO policy_team_grants "
        "(id, effect_id, user_id, key_wrapped) VALUES (?, ?, ?, ?) "
        "ON CONFLICT DO NOTHING",
        (tg_id, effect_id, user_id, 1 if has_key else 0),
    )
    if has_key:
        await db.execute(
            "UPDATE policy_team_grants SET key_wrapped = 1 "
            "WHERE effect_id = ? AND user_id = ? AND key_wrapped = 0",
            (effect_id, user_id),
        )

    if not escrow_agent_ids:
        return
    policy_escrow = policy_escrow_map.get(policy_id, False)
    team_override = escrow_overrides.get(policy_id, {}).get(target_id)
    effective_escrow = (team_override == 1) if team_override is not None else policy_escrow
    if not effective_escrow:
        return

    for ea_id in escrow_agent_ids:
        ea_ur_id = str(_uuid.uuid4())
        await db.execute(
            "INSERT INTO user_roles "
            "(id, user_id, role_id, scope_type, scope_id, granted_by, policy_effect_id) "
            "VALUES (?, ?, 'team_member', 'team', ?, NULL, ?) "
            "ON CONFLICT DO NOTHING",
            (ea_ur_id, ea_id, target_id, effect_id),
        )
        cursor_ea = await db.execute(_SQL_HAS_TEAM_KEY, (target_id, ea_id))
        ea_has_key = await cursor_ea.fetchone() is not None
        ea_tg_id = str(_uuid.uuid4())
        await db.execute(
            "INSERT INTO policy_team_grants "
            "(id, effect_id, user_id, key_wrapped) VALUES (?, ?, ?, ?) "
            "ON CONFLICT DO NOTHING",
            (ea_tg_id, effect_id, ea_id, 1 if ea_has_key else 0),
        )
        if ea_has_key:
            await db.execute(
                "UPDATE policy_team_grants SET key_wrapped = 1 "
                "WHERE effect_id = ? AND user_id = ? AND key_wrapped = 0",
                (effect_id, ea_id),
            )


async def _apply_folder_acl_effect(
    db,
    user_id: str,
    effect_id: str,
    target_id: str,
    permission: str | None,
    recursive: bool,
) -> None:
    if not permission:
        logger.warning("policy: folder_acl effect %s has no permission — skipping", effect_id)
        return

    perm_id = str(_uuid.uuid4())
    await db.execute(
        "INSERT INTO permissions "
        "(id, resource_type, resource_id, user_id, permission, recursive, "
        " granted_by, policy_effect_id) "
        "VALUES (?, 'folder', ?, ?, ?, ?, NULL, ?) "
        "ON CONFLICT DO NOTHING",
        (perm_id, target_id, user_id, permission, recursive, effect_id),
    )
    cursor = await db.execute(
        "SELECT policy_effect_id FROM permissions "
        "WHERE resource_type = 'folder' AND resource_id = ? AND user_id = ?",
        (target_id, user_id),
    )
    perm_row = await cursor.fetchone()
    acl_written = perm_row is not None and perm_row["policy_effect_id"] == effect_id

    team_id = await _get_folder_team_id(db, target_id)
    if team_id:
        cursor = await db.execute(_SQL_HAS_TEAM_KEY, (team_id, user_id))
        key_wrapped = 1 if await cursor.fetchone() is not None else 0
    else:
        key_wrapped = 1

    fg_id = str(_uuid.uuid4())
    await db.execute(
        "INSERT INTO policy_folder_grants "
        "(id, effect_id, user_id, folder_id, acl_written, key_wrapped) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT DO NOTHING",
        (fg_id, effect_id, user_id, target_id, 1 if acl_written else 0, key_wrapped),
    )
    if key_wrapped:
        await db.execute(
            "UPDATE policy_folder_grants SET key_wrapped = 1 "
            "WHERE effect_id = ? AND user_id = ? AND folder_id = ? AND key_wrapped = 0",
            (effect_id, user_id, target_id),
        )


async def _check_policy_debounce(db, user_id: str, force: bool) -> bool:
    """Return True if the user was recently evaluated and evaluation should be skipped."""
    if force:
        return False
    cursor = await db.execute(
        "SELECT policy_last_evaluated_at FROM users WHERE id = ?", (user_id,)
    )
    row = await cursor.fetchone()
    if not (row and row["policy_last_evaluated_at"]):
        return False
    try:
        last = datetime.fromisoformat(row["policy_last_evaluated_at"])
        now  = datetime.now(timezone.utc)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return (now - last).total_seconds() < _DEBOUNCE_SECONDS
    except ValueError:
        return False  # malformed timestamp — proceed with evaluation


def _collect_matching_policy_ids(
    policies: list, conditions_by_policy: dict, all_resolved: dict
) -> "set[str]":
    """Evaluate each policy's conditions against resolved field values (AND semantics)."""
    matching: set[str] = set()
    for policy in policies:
        conds = conditions_by_policy[policy.id]
        if not conds:
            continue
        matched = True
        for cond in conds:
            actual = all_resolved.get(cond.field)
            if actual is None:
                matched = False
                break
            if not _evaluate_condition(cond, actual):
                matched = False
                break
        if matched:
            matching.add(policy.id)
    return matching


async def _write_matching_policy_grants(
    db, user_id: str, policies: list, matching_policy_ids: "set[str]"
) -> None:
    """Write policy_folder_grants for all matching policies (step 8)."""
    match_ph = ",".join("?" * len(matching_policy_ids))
    cursor = await db.execute(
        f"SELECT * FROM policy_effects WHERE policy_id IN ({match_ph})",
        list(matching_policy_ids),
    )
    effects = await cursor.fetchall()

    policy_escrow_map: dict[str, bool] = {
        p.id: p.escrow_enabled for p in policies if p.id in matching_policy_ids
    }
    escrow_overrides: dict[str, dict] = {}
    for eff in effects:
        if eff["effect_type"] == "team_escrow":
            pid = eff["policy_id"]
            if pid not in escrow_overrides:
                escrow_overrides[pid] = {}
            escrow_overrides[pid][eff["target_id"]] = eff["escrow_override"]

    cursor2 = await db.execute(
        "SELECT DISTINCT ur.user_id FROM user_roles ur "
        "WHERE ur.role_id = 'escrow_agent' AND ur.scope_type IS NULL",
    )
    escrow_agent_ids: list[str] = [r["user_id"] for r in await cursor2.fetchall()]

    for eff in effects:
        effect_type = eff["effect_type"]
        if effect_type == "team_escrow":
            continue
        if effect_type == "team_member":
            await _apply_team_member_effect(
                db, user_id, eff["id"], eff["target_id"], eff["role_level"], eff["policy_id"],
                policy_escrow_map, escrow_overrides, escrow_agent_ids,
            )
        elif effect_type == "folder_acl":
            await _apply_folder_acl_effect(
                db, user_id, eff["id"], eff["target_id"], eff["permission"], eff["recursive"],
            )


async def _revoke_non_matching_policy_grants(
    db, user_id: str, policies: list, matching_policy_ids: "set[str]"
) -> None:
    """Delete policy-sourced grants for policies that no longer match (step 9)."""
    non_matching_ids = [p.id for p in policies if p.id not in matching_policy_ids]
    if not non_matching_ids:
        return
    nm_ph = ",".join("?" * len(non_matching_ids))
    cursor = await db.execute(
        f"SELECT id FROM policy_effects WHERE policy_id IN ({nm_ph})",
        non_matching_ids,
    )
    revoke_effect_ids = [r["id"] for r in await cursor.fetchall()]
    if not revoke_effect_ids:
        return
    rev_ph = ",".join("?" * len(revoke_effect_ids))
    rev_args = [user_id] + revoke_effect_ids
    await db.execute(
        f"DELETE FROM user_roles WHERE user_id = ? AND policy_effect_id IN ({rev_ph})", rev_args,
    )
    await db.execute(
        f"DELETE FROM user_team_keys WHERE user_id = ? AND policy_effect_id IN ({rev_ph})", rev_args,
    )
    await db.execute(
        f"DELETE FROM permissions WHERE user_id = ? AND policy_effect_id IN ({rev_ph})", rev_args,
    )
    await db.execute(
        f"DELETE FROM policy_team_grants WHERE user_id = ? AND effect_id IN ({rev_ph})", rev_args,
    )
    await db.execute(
        f"DELETE FROM policy_folder_grants WHERE user_id = ? AND effect_id IN ({rev_ph})", rev_args,
    )


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

async def evaluate_user_policies(db, user_id: str, *, force: bool = False) -> None:
    """Evaluate all policies that apply to a user and write policy_folder_grants.

    Steps:
      1. Debounce check — skip if evaluated within _DEBOUNCE_SECONDS (unless force=True)
      2. Load all policies whose scope matches the user (org-level + teams the user belongs to)
      3. For each policy, load its conditions
      4. Split conditions by source (internal / ldap / oidc)
      5. Resolve internal fields from the local DB
      6. Resolve ldap fields via a single LDAP query per provider (if configured)
      7. Evaluate all conditions — AND semantics; any false → policy does not match
      8. Write grants for matching policies (ON CONFLICT DO NOTHING into policy_folder_grants)
      9. Remove grants for policies that no longer match
     10. Update policy_last_evaluated_at

    LDAP / OIDC notes:
      • LDAP: requires identity_providers table Gracefully no-ops if absent.
      • OIDC:  same — gracefully no-ops if identity providers are not configured.
      • If required integration is missing, all conditions for that source evaluate False
        (conservative — never grant based on unresolvable attributes).

    Key-wrapping note:
      Grants are written with key_wrapped=0.  The wrapping worker (to be implemented
      ) performs the actual X25519/ML-KEM key wrap on the user's next
      password-entry event.  Until key_wrapped=1, the user cannot access the folder.
    """
    # Service accounts are policy-exempt — they receive only explicitly granted
    # roles and must never be auto-enrolled via policy triggers.
    cursor = await db.execute("SELECT auth_method FROM users WHERE id = ?", (user_id,))
    _am_row = await cursor.fetchone()
    if _am_row and _am_row["auth_method"] == "service":
        return

    # 1. Debounce
    if await _check_policy_debounce(db, user_id, force):
        return

    # 2. Load policies applicable to this user
    cursor = await db.execute(
        """
        SELECT p.*
        FROM policies p
        WHERE p.scope_type = 'org'
           OR (p.scope_type = 'team' AND p.scope_id IN (
                   SELECT scope_id FROM user_roles
                   WHERE user_id = ? AND scope_type = 'team'
               ))
        """,
        (user_id,),
    )
    policies = [Policy.from_row(r) for r in await cursor.fetchall()]

    if not policies:
        await _stamp_evaluated(db, user_id)
        return

    # 3. Load all conditions for these policies in one query
    policy_ids = [p.id for p in policies]
    placeholders = ",".join("?" * len(policy_ids))
    cursor = await db.execute(
        f"SELECT * FROM policy_conditions WHERE policy_id IN ({placeholders})",
        policy_ids,
    )
    all_conditions = [PolicyCondition.from_row(r) for r in await cursor.fetchall()]

    conditions_by_policy: dict[str, list[PolicyCondition]] = {p.id: [] for p in policies}
    for cond in all_conditions:
        conditions_by_policy[cond.policy_id].append(cond)

    # 4. Load field definitions
    needed_fields = {c.field for c in all_conditions}
    if needed_fields:
        field_placeholders = ",".join("?" * len(needed_fields))
        cursor = await db.execute(
            f"SELECT * FROM policy_field_definitions WHERE name IN ({field_placeholders})",
            list(needed_fields),
        )
        field_defs: dict[str, PolicyFieldDef] = {
            r["name"]: PolicyFieldDef.from_row(r) for r in await cursor.fetchall()
        }
    else:
        field_defs = {}

    # 5-6. Resolve all condition fields (internal / LDAP / OIDC)
    all_resolved = await _resolve_all_policy_fields(db, user_id, all_conditions, field_defs)

    # 7. Evaluate each policy; collect matching policy IDs
    matching_policy_ids = _collect_matching_policy_ids(policies, conditions_by_policy, all_resolved)

    # 8. Write grants for matching policies
    if matching_policy_ids:
        await _write_matching_policy_grants(db, user_id, policies, matching_policy_ids)

    # 9. Revoke grants for policies that no longer match
    await _revoke_non_matching_policy_grants(db, user_id, policies, matching_policy_ids)

    # 10. Stamp evaluation time
    await _stamp_evaluated(db, user_id)
    await db.commit()


async def _get_folder_team_id(db, folder_id: str) -> str | None:
    """Walk the folder ancestry to find the team that owns this folder tree.

    Returns the team_id if any ancestor (or self) is a team folder, otherwise None.
    Inlined here to avoid importing from routes._access (models should not import routes).
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


async def _stamp_evaluated(db, user_id: str) -> None:
    await db.execute(
        "UPDATE users SET policy_last_evaluated_at = NOW()::text WHERE id = ?",
        (user_id,),
    )


async def _resolve_ldap_fields(
    db,
    user_id: str,
    conditions: list[PolicyCondition],
    field_defs: dict[str, PolicyFieldDef],
) -> dict[str, str]:
    """Resolve LDAP-source condition fields for a user.

    Requires identity_providers + identity_provider_users tables.
    Gracefully returns empty dict if those tables don't exist yet.

    All conditions are translated to a single LDAP filter and issued in one
    query per LDAP provider associated with this user.
    """
    try:
        cursor = await db.execute(
            """
            SELECT ip.config_enc, ipu.external_id
            FROM identity_provider_users ipu
            JOIN identity_providers ip ON ip.id = ipu.provider_id
            WHERE ipu.user_id = ? AND ip.provider_type = 'ldap'
            LIMIT 1
            """,
            (user_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return {}
    except Exception:
        return {}

    try:
        from app.auth.ldap_provider import ldap_fetch_attributes
        raw = await ldap_fetch_attributes(row["config_enc"], row["external_id"])
        if raw is None:
            return {}
    except Exception as exc:
        logger.warning("policy: LDAP resolution error for user %s: %s", user_id, exc)
        return {}

    # Map claim_path back to field name
    result: dict[str, str] = {}
    for cond in conditions:
        fdef = field_defs.get(cond.field)
        if fdef and fdef.claim_path and fdef.claim_path in raw:
            result[cond.field] = raw[fdef.claim_path]

    return result


async def _resolve_oidc_fields(
    db,
    user_id: str,
    conditions: list[PolicyCondition],
    field_defs: dict[str, PolicyFieldDef],
) -> dict[str, str]:
    """Resolve OIDC-source condition fields for a user.

    Requires identity_providers + identity_provider_users tables.
    Gracefully returns empty dict if those tables don't exist yet, or if
    the provider uses at_login mode and no cached claims are available.
    """
    try:
        cursor = await db.execute(
            """
            SELECT ip.config_enc, ip.claim_mode, u.oidc_claims_cache, u.oidc_refresh_token_enc
            FROM identity_provider_users ipu
            JOIN identity_providers ip ON ip.id = ipu.provider_id
            JOIN users u ON u.id = ipu.user_id
            WHERE ipu.user_id = ? AND ip.provider_type = 'oidc'
            LIMIT 1
            """,
            (user_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return {}
    except Exception:
        return {}

    import json

    claim_mode = row["claim_mode"] or "at_login"

    if claim_mode == "at_login":
        try:
            claims = json.loads(row["oidc_claims_cache"] or "{}")
        except (json.JSONDecodeError, TypeError):
            claims = {}
    else:
        # live_refetch: exchange the stored refresh token for fresh claims
        claims = await _fetch_oidc_userinfo(row)

    result: dict[str, str] = {}
    for cond in conditions:
        fdef = field_defs.get(cond.field)
        if fdef and fdef.claim_path:
            raw_val = claims.get(fdef.claim_path)
            if raw_val is not None:
                result[cond.field] = str(raw_val)

    return result


async def _fetch_oidc_userinfo(row) -> dict:
    """Fetch fresh OIDC claims for live_refetch mode.

    Decrypts the stored refresh token, exchanges it for an access token,
    then calls the UserInfo endpoint.  Returns {} on any error.
    """
    try:
        import asyncio
        import urllib.request
        import urllib.parse
        import json

        refresh_token_enc = row["oidc_refresh_token_enc"]
        if not refresh_token_enc:
            return {}

        from app.auth.idp_crypto import decrypt_idp_config, decrypt_token
        cfg = decrypt_idp_config(row["config_enc"])
        refresh_token = decrypt_token(refresh_token_enc)
        issuer_url = cfg["issuer_url"].rstrip("/")
        client_id = cfg["client_id"]
        client_secret = cfg["client_secret"]

        def _exchange_and_fetch():
            # Exchange refresh token for access token
            token_data = urllib.parse.urlencode({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            }).encode()
            req = urllib.request.Request(
                f"{issuer_url}/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                token_resp = json.loads(resp.read())
            access_token = token_resp.get("access_token")
            if not access_token:
                return {}

            ui_req = urllib.request.Request(
                f"{issuer_url}/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            with urllib.request.urlopen(ui_req, timeout=5) as resp:
                return json.loads(resp.read())

        return await asyncio.to_thread(_exchange_and_fetch)
    except Exception as exc:
        logger.warning("policy: OIDC UserInfo fetch error: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Policy-change sweep (Trigger 2)
# ---------------------------------------------------------------------------

async def sweep_policy_for_all_users(db, policy_id: str) -> None:
    """Re-evaluate a single policy against all active users.

    Called when a policy's conditions are created, updated, or deleted.
    Evaluates with force=True (bypasses per-user debounce) but still
    respects the policy-level scope (org vs team).

    This is a synchronous sweep — for large user bases this may be slow.
    A background task version can be added in F-phase infra work.
    """
    # Load the policy to determine scope
    cursor = await db.execute("SELECT * FROM policies WHERE id = ?", (policy_id,))
    policy_row = await cursor.fetchone()
    if policy_row is None:
        return

    scope_type = policy_row["scope_type"]
    scope_id   = policy_row["scope_id"]

    if scope_type == "org":
        # All users
        cursor = await db.execute("SELECT id FROM users")
    else:
        # Only users in the scoped team
        cursor = await db.execute(
            "SELECT DISTINCT user_id AS id FROM user_roles "
            "WHERE scope_type = 'team' AND scope_id = ?",
            (scope_id,),
        )

    user_ids = [r["id"] for r in await cursor.fetchall()]

    for uid in user_ids:
        try:
            await evaluate_user_policies(db, uid, force=True)
        except Exception:
            logger.exception("policy sweep: error evaluating user %s for policy %s", uid, policy_id)
