"""Role and UserRole models with query helpers."""

from dataclasses import dataclass

from app.database import DuplicateError

# ---------------------------------------------------------------------------
# System role IDs — 6-tier hierarchy (seeded in migration 010)
# ---------------------------------------------------------------------------
ROLE_SERVER_ADMIN      = "server_admin"
ROLE_ORG_ADMIN         = "org_admin"
ROLE_OPERATIONAL_ADMIN = "operational_admin"
ROLE_TEAM_ADMIN        = "team_admin"
ROLE_TEAM_MANAGER      = "team_manager"
ROLE_TEAM_MEMBER       = "team_member"

# Basic user role — grants file storage access; separate from admin tiers
ROLE_USER = "role_user"

# Legacy: predates E1; superseded by ROLE_SERVER_ADMIN.  Kept for backward
# compat during transition; will be retired in a follow-up migration.
ROLE_ADMIN = "role_admin"

# All role IDs that carry administrative authority at global scope.
# Used for is_admin checks and users.is_admin sync until that column retires.
ADMIN_ROLE_IDS: frozenset[str] = frozenset({
    ROLE_SERVER_ADMIN,
    ROLE_ORG_ADMIN,
    ROLE_OPERATIONAL_ADMIN,
    ROLE_ADMIN,  # legacy
})

# ---------------------------------------------------------------------------
# Permission flag name constants
# ---------------------------------------------------------------------------
FLAG_VIEW_ADMIN_PANEL        = "can_view_admin_panel"
FLAG_MANAGE_SYSTEM_SETTINGS  = "can_manage_system_settings"
FLAG_MANAGE_ORG_SETTINGS     = "can_manage_org_settings"
FLAG_MANAGE_USERS            = "can_manage_users"
FLAG_MANAGE_INVITES          = "can_manage_invites"
FLAG_MANAGE_TEAMS            = "can_manage_teams"
FLAG_MANAGE_TEAM_MEMBERS     = "can_manage_team_members"
FLAG_MANAGE_ROLES            = "can_manage_roles"
FLAG_CREATE_ROLES            = "can_create_roles"
FLAG_CREATE_CROSS_TEAM_ROLES = "can_create_cross_team_roles"
FLAG_VIEW_DISK_USAGE         = "can_view_disk_usage"
FLAG_VIEW_AUDIT_LOG          = "can_view_audit_log"
FLAG_EXPORT_AUDIT_LOG        = "can_export_audit_log"
FLAG_MANAGE_INTEGRATIONS     = "can_manage_integrations"
FLAG_MANAGE_POLICIES         = "can_manage_policies"
FLAG_ACCESS_ALL_FILES        = "can_access_all_files"

# Flags that may only be activated by server_admin or org_admin, regardless
# of other role permissions.  Enforced server-side at flag-update endpoints.
SENSITIVE_FLAGS: frozenset[str] = frozenset({FLAG_ACCESS_ALL_FILES})


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
        "SELECT role_id FROM user_roles "
        "WHERE user_id = ? AND scope_type IS NULL",
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
            "SELECT 1 FROM user_roles "
            "WHERE user_id = ? AND role_id = ? AND scope_type IS NULL",
            (user_id, role_id),
        )
    else:
        cursor = await db.execute(
            "SELECT 1 FROM user_roles "
            "WHERE user_id = ? AND role_id = ? AND scope_type = ? AND scope_id = ?",
            (user_id, role_id, scope_type, scope_id),
        )
    return await cursor.fetchone() is not None


async def grant_role(db, user_id: str, role_id: str, granted_by: str | None = None,
                     scope_type: str | None = None, scope_id: str | None = None) -> str:
    """Grant a role to a user. Returns the user_role ID. Ignores duplicates."""
    import uuid
    ur_id = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ur_id, user_id, role_id, scope_type, scope_id, granted_by),
        )
    except DuplicateError:
        return ""
    return ur_id


async def revoke_role(db, user_id: str, role_id: str,
                      scope_type: str | None = None, scope_id: str | None = None) -> bool:
    """Revoke a role from a user. Returns True if a row was deleted."""
    if scope_type is None:
        result = await db.execute(
            "DELETE FROM user_roles "
            "WHERE user_id = ? AND role_id = ? AND scope_type IS NULL RETURNING id",
            (user_id, role_id),
        )
    else:
        result = await db.execute(
            "DELETE FROM user_roles "
            "WHERE user_id = ? AND role_id = ? AND scope_type = ? AND scope_id = ? RETURNING id",
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
