"""Role and UserRole models with query helpers."""

from dataclasses import dataclass

from app.database import DuplicateError

# System role IDs — always present, never deleted
ROLE_ADMIN = "role_admin"
ROLE_USER = "role_user"


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


async def get_user_global_role_ids(db, user_id: str) -> set[str]:
    """Return the set of global (unscoped) role IDs for a user."""
    cursor = await db.execute(
        "SELECT role_id FROM user_roles "
        "WHERE user_id = ? AND scope_type IS NULL",
        (user_id,),
    )
    return {row["role_id"] for row in await cursor.fetchall()}


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
    """Get all user-role assignments for a given scope (e.g., all members of a team folder)."""
    cursor = await db.execute(
        "SELECT * FROM user_roles WHERE scope_type = ? AND scope_id = ?",
        (scope_type, scope_id),
    )
    return [UserRole.from_row(r) for r in await cursor.fetchall()]
