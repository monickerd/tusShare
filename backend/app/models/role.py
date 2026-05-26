"""Role and UserRole models with query helpers."""

from dataclasses import dataclass

from app.database import DuplicateError

# ---------------------------------------------------------------------------
# System role IDs — 6-tier hierarchy (seeded in schema.sql)
# ---------------------------------------------------------------------------
ROLE_SERVER_ADMIN = "server_admin"
ROLE_ORG_ADMIN = "org_admin"
ROLE_OPERATIONAL_ADMIN = "operational_admin"
ROLE_TEAM_ADMIN = "team_admin"
ROLE_TEAM_MANAGER = "team_manager"
ROLE_TEAM_MEMBER = "team_member"

# Basic user role — grants file storage access; separate from admin tiers
ROLE_USER = "role_user"

# All role IDs that carry administrative authority at global scope.
# Used for is_admin checks and users.is_admin sync until that column retires.
ADMIN_ROLE_IDS: frozenset[str] = frozenset(
    {
        ROLE_SERVER_ADMIN,
        ROLE_ORG_ADMIN,
        ROLE_OPERATIONAL_ADMIN,
        "role_admin",  # legacy — existing DB grants only; no new grants should use this
    }
)

# ---------------------------------------------------------------------------
# Permission flag name constants  (NOUN_VERB / NOUN_SUBNOUN_VERB convention)
# ---------------------------------------------------------------------------

# Admin panel + global settings
FLAG_ADMIN_PANEL_VIEW = "admin_panel_view"
FLAG_SYSTEM_SETTINGS_MANAGE = "system_settings_manage"
FLAG_ORG_SETTINGS_MANAGE = "org_settings_manage"

# User management (split from old can_manage_users)
# Read-only listing → FLAG_USERS_VIEW; mutations → FLAG_USERS_MANAGE;
# permanent account deletion → FLAG_USERS_DELETE (requires MANAGE).
FLAG_USERS_VIEW = "users_view"
FLAG_USERS_MANAGE = "users_manage"
FLAG_USERS_DELETE = "users_delete"
FLAG_USERS_INVITE_MANAGE = "users_invite_manage"
FLAG_USERS_MFA_MANAGE = "users_mfa_manage"

# Team management
FLAG_TEAMS_MANAGE = "teams_manage"
FLAG_TEAMS_MEMBERS_MANAGE = "teams_members_manage"

# Role management
FLAG_ROLES_MANAGE = "roles_manage"
FLAG_ROLES_CREATE = "roles_create"
FLAG_ROLES_CROSS_TEAM_CREATE = "roles_cross_team_create"

# Observability
FLAG_DISK_USAGE_VIEW = "disk_usage_view"
FLAG_AUDIT_LOG_VIEW = "audit_log_view"
FLAG_AUDIT_LOG_EXPORT = "audit_log_export"

# Integrations (split from old can_manage_integrations)
FLAG_INTEGRATIONS_IDP_MANAGE = "integrations_idp_manage"
FLAG_INTEGRATIONS_NOTIFICATIONS_MANAGE = "integrations_notifications_manage"

# Policy management (split from old can_manage_policies)
FLAG_POLICIES_VIEW = "policies_view"
FLAG_POLICIES_MANAGE = "policies_manage"
FLAG_POLICIES_FIELDS_MANAGE = "policies_fields_manage"

# File access bypass (split from old can_access_all_files)
# READ covers reads and downloads; WRITE also implies read (check: READ or WRITE).
FLAG_FILES_ACCESS_ALL_READ = "files_access_all_read"
FLAG_FILES_ACCESS_ALL_WRITE = "files_access_all_write"

# File operations
FLAG_FILES_COPY = "files_copy"

# Security / key management
FLAG_ESCROW_MANAGE = "escrow_manage"
FLAG_SHARING_MANAGE = "sharing_manage"
FLAG_SERVICE_ACCOUNTS_MANAGE = "service_accounts_manage"

# Sharing capability flags — default ON for role_user; admins remove to restrict
FLAG_SHARES_LINK_CREATE = "shares_link_create"
FLAG_SHARES_USER_CREATE = "shares_user_create"
FLAG_SHARES_UPLOAD_GRANT_CREATE = "shares_upload_grant_create"
FLAG_SHARES_FOLDER_CREATE = "shares_folder_create"

# Flags that may only be activated by server_admin or org_admin, regardless
# of other role permissions.  Enforced server-side at flag-update endpoints.
SENSITIVE_FLAGS: frozenset[str] = frozenset(
    {
        FLAG_FILES_ACCESS_ALL_READ,
        FLAG_FILES_ACCESS_ALL_WRITE,
    }
)

# Hard prerequisites: enabling flag X requires all flags in FLAG_REQUIRES[X] to
# also be active on the role.  Used for UI warnings and (optionally) enforcement.
# All admin-panel-facing flags require admin_panel_view because without it the
# admin panel UI (and most admin API endpoints) are inaccessible.
FLAG_REQUIRES: dict[str, list[str]] = {
    # Admin panel — prerequisite for every admin-facing capability
    FLAG_USERS_VIEW: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_USERS_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_USERS_DELETE: [FLAG_ADMIN_PANEL_VIEW, FLAG_USERS_MANAGE],
    FLAG_USERS_INVITE_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_USERS_MFA_MANAGE: [FLAG_ADMIN_PANEL_VIEW, FLAG_USERS_VIEW],
    FLAG_TEAMS_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_TEAMS_MEMBERS_MANAGE: [FLAG_ADMIN_PANEL_VIEW, FLAG_TEAMS_MANAGE],
    FLAG_ROLES_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_ROLES_CREATE: [FLAG_ADMIN_PANEL_VIEW, FLAG_ROLES_MANAGE],
    FLAG_ROLES_CROSS_TEAM_CREATE: [FLAG_ADMIN_PANEL_VIEW, FLAG_ROLES_CREATE, FLAG_ROLES_MANAGE],
    FLAG_DISK_USAGE_VIEW: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_AUDIT_LOG_VIEW: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_AUDIT_LOG_EXPORT: [FLAG_ADMIN_PANEL_VIEW, FLAG_AUDIT_LOG_VIEW],
    FLAG_INTEGRATIONS_IDP_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_INTEGRATIONS_NOTIFICATIONS_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_POLICIES_VIEW: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_POLICIES_MANAGE: [FLAG_ADMIN_PANEL_VIEW, FLAG_POLICIES_VIEW],
    FLAG_POLICIES_FIELDS_MANAGE: [FLAG_ADMIN_PANEL_VIEW, FLAG_POLICIES_MANAGE, FLAG_POLICIES_VIEW],
    FLAG_ESCROW_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_SHARING_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_SERVICE_ACCOUNTS_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_SYSTEM_SETTINGS_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    FLAG_ORG_SETTINGS_MANAGE: [FLAG_ADMIN_PANEL_VIEW],
    # File-access bypass (no admin panel required — used by escrow/audit paths)
    FLAG_FILES_ACCESS_ALL_WRITE: [FLAG_FILES_ACCESS_ALL_READ],
    # Sharing capability dependencies
    FLAG_SHARES_UPLOAD_GRANT_CREATE: [FLAG_SHARES_LINK_CREATE],
    FLAG_SHARES_FOLDER_CREATE: [FLAG_SHARES_LINK_CREATE],
}

# Soft relationships: flags that are commonly used together.
# Used to surface "you may also want to enable X" hints in the role editor.
FLAG_RELATED: dict[str, list[str]] = {
    FLAG_USERS_VIEW: [FLAG_USERS_MANAGE, FLAG_USERS_INVITE_MANAGE],
    FLAG_USERS_MANAGE: [FLAG_USERS_DELETE, FLAG_USERS_MFA_MANAGE],
    FLAG_AUDIT_LOG_VIEW: [FLAG_AUDIT_LOG_EXPORT, FLAG_DISK_USAGE_VIEW],
    FLAG_POLICIES_VIEW: [FLAG_POLICIES_MANAGE],
    FLAG_FILES_ACCESS_ALL_READ: [FLAG_FILES_ACCESS_ALL_WRITE],
    FLAG_SHARES_LINK_CREATE: [FLAG_SHARES_USER_CREATE, FLAG_SHARES_UPLOAD_GRANT_CREATE],
    FLAG_SHARING_MANAGE: [FLAG_POLICIES_MANAGE],
    FLAG_ESCROW_MANAGE: [FLAG_FILES_ACCESS_ALL_READ],
    FLAG_INTEGRATIONS_IDP_MANAGE: [FLAG_INTEGRATIONS_NOTIFICATIONS_MANAGE],
}


# ---------------------------------------------------------------------------
# Role tier hierarchy — used to prevent privilege escalation in role grants.
# Lower number = higher authority.  Roles absent from this map are custom or
# non-tiered (e.g. role_user) and have no escalation restriction.
# ---------------------------------------------------------------------------
ROLE_TIER: dict[str, int] = {
    ROLE_SERVER_ADMIN: 1,
    "role_admin": 1,  # legacy — existing DB grants only
    ROLE_ORG_ADMIN: 2,
    ROLE_OPERATIONAL_ADMIN: 3,
    ROLE_TEAM_ADMIN: 4,
    ROLE_TEAM_MANAGER: 5,
    ROLE_TEAM_MEMBER: 6,
}


def admin_best_tier(roles: set[str]) -> int:
    """Return the lowest (most privileged) tier among the role set.

    Returns 99 when the set contains no tiered roles (e.g. custom-role-only
    or role_user accounts), ensuring they can never grant tiered roles.
    """
    return min((ROLE_TIER.get(r, 99) for r in roles), default=99)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Role:
    id: str
    name: str
    description: str
    is_system: bool

    @classmethod
    def from_row(cls, row) -> "Role":
        return cls(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            is_system=bool(row["is_system"]),
        )


@dataclass
class UserRole:
    id: str
    user_id: str
    role_id: str
    scope_type: str | None
    scope_id: str | None
    granted_by: str | None

    @classmethod
    def from_row(cls, row) -> "UserRole":
        return cls(
            id=row["id"],
            user_id=row["user_id"],
            role_id=row["role_id"],
            scope_type=row["scope_type"],
            scope_id=row["scope_id"],
            granted_by=row["granted_by"],
        )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


async def get_user_global_role_ids(db, user_id: str) -> set[str]:
    """Return the set of global (unscoped) role IDs for a user."""
    cursor = await db.execute(
        "SELECT role_id FROM user_roles WHERE user_id = ? AND scope_type IS NULL",
        (user_id,),
    )
    return {row["role_id"] for row in await cursor.fetchall()}


async def get_user_global_flags(db, user_id: str) -> dict[str, str]:
    """Return effective permission flags from a user's global roles.

    When the user holds multiple global roles that define the same flag, the
    lexicographically largest value wins.  For the current binary flag set
    ('0'/'1') this means any role granting '1' takes precedence.
    """
    cursor = await db.execute(
        "SELECT rp.flag, MAX(rp.value) AS value "
        "FROM role_permissions rp "
        "JOIN user_roles ur ON ur.role_id = rp.role_id "
        "WHERE ur.user_id = ? AND ur.scope_type IS NULL "
        "GROUP BY rp.flag",
        (user_id,),
    )
    return {row["flag"]: row["value"] for row in await cursor.fetchall()}


async def has_role(db, user_id: str, role_id: str, scope_type: str | None = None, scope_id: str | None = None) -> bool:
    """Check if a user holds a specific role, optionally scoped."""
    if scope_type is None:
        cursor = await db.execute(
            "SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ? AND scope_type IS NULL",
            (user_id, role_id),
        )
    else:
        cursor = await db.execute(
            "SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ? AND scope_type = ? AND scope_id = ?",
            (user_id, role_id, scope_type, scope_id),
        )
    return await cursor.fetchone() is not None


async def grant_role(
    db,
    user_id: str,
    role_id: str,
    granted_by: str | None = None,
    scope_type: str | None = None,
    scope_id: str | None = None,
) -> str:
    """Grant a role to a user. Returns the user_role ID. Ignores duplicates."""
    import uuid

    ur_id = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by) VALUES (?, ?, ?, ?, ?, ?)",
            (ur_id, user_id, role_id, scope_type, scope_id, granted_by),
        )
    except DuplicateError:
        return ""
    return ur_id


async def revoke_role(
    db, user_id: str, role_id: str, scope_type: str | None = None, scope_id: str | None = None
) -> bool:
    """Revoke a role from a user. Returns True if a row was deleted."""
    if scope_type is None:
        result = await db.execute(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ? AND scope_type IS NULL RETURNING id",
            (user_id, role_id),
        )
    else:
        result = await db.execute(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ? AND scope_type = ? AND scope_id = ? RETURNING id",
            (user_id, role_id, scope_type, scope_id),
        )
    return await result.fetchone() is not None


async def get_scoped_roles(db, scope_type: str, scope_id: str) -> list[UserRole]:
    """Get all user-role assignments for a given scope (e.g., all members of a team)."""
    cursor = await db.execute(
        "SELECT * FROM user_roles WHERE scope_type = ? AND scope_id = ?",
        (scope_type, scope_id),
    )
    return [UserRole.from_row(r) for r in await cursor.fetchall()]


async def get_user_scoped_roles(db, user_id: str) -> list[dict]:
    """Return all scoped role assignments for a user as plain dicts.

    Each dict has keys: role_id, scope_type, scope_id, flags (dict[str,str]).
    Flags are the effective permission flags from that role — same logic as
    get_user_global_flags but resolved per scoped assignment.

    Also includes any rows from admin_scope_grants, which grant individual
    permission flags for a specific scope without a full role assignment.
    """
    # Scoped role assignments with their permission flags
    cursor = await db.execute(
        """
        SELECT ur.role_id, ur.scope_type, ur.scope_id,
               rp.flag, MAX(rp.value) AS value
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND ur.scope_type IS NOT NULL
        GROUP BY ur.role_id, ur.scope_type, ur.scope_id, rp.flag
        """,
        (user_id,),
    )
    rows = await cursor.fetchall()

    # Aggregate flags per (role_id, scope_type, scope_id) triple
    role_map: dict[tuple, dict] = {}
    for row in rows:
        key = (row["role_id"], row["scope_type"], row["scope_id"])
        if key not in role_map:
            role_map[key] = {
                "role_id": row["role_id"],
                "scope_type": row["scope_type"],
                "scope_id": row["scope_id"],
                "flags": {},
            }
        role_map[key]["flags"][row["flag"]] = row["value"]

    result = list(role_map.values())

    # Individual flag grants from admin_scope_grants (supplemental; no role row)
    try:
        cursor2 = await db.execute(
            "SELECT flag, scope_type, scope_id FROM admin_scope_grants WHERE user_id = ?",
            (user_id,),
        )
        grant_rows = await cursor2.fetchall()
    except Exception:
        # Table may not exist yet on old schema; ignore gracefully.
        grant_rows = []

    # Merge individual grants into a synthetic role entry keyed by scope
    grant_map: dict[tuple, dict] = {}
    for gr in grant_rows:
        key = ("__grants__", gr["scope_type"], gr["scope_id"])
        if key not in grant_map:
            grant_map[key] = {
                "role_id": None,
                "scope_type": gr["scope_type"],
                "scope_id": gr["scope_id"],
                "flags": {},
            }
        grant_map[key]["flags"][gr["flag"]] = "1"

    result.extend(grant_map.values())
    return result
