"""Team, TeamMember, and TeamFileKey data models."""

from dataclasses import dataclass

from app.conf.teams import TEAM_ROLE_HIERARCHY


@dataclass
class Team:
    id: str
    name: str
    description: str
    owner_id: str
    pre_public_key: str
    rotation_pending: bool
    created_at: int
    updated_at: int

    @classmethod
    def from_row(cls, row) -> "Team":
        return cls(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            owner_id=row["owner_id"],
            pre_public_key=row["pre_public_key"],
            rotation_pending=bool(row["rotation_pending"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner_id": self.owner_id,
            "pre_public_key": self.pre_public_key,
            "rotation_pending": self.rotation_pending,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class TeamMember:
    user_id: str
    username: str
    role: str   # team_owner | team_supervisor | team_member
    key_delivery_pending: bool = False  # True when policy grant key_wrapped=0 (no key slot yet)
    key_confirmed: bool = False         # True when Schnorr PoK submitted post-rotation

    @property
    def role_rank(self) -> int:
        """Lower index = higher privilege."""
        try:
            return TEAM_ROLE_HIERARCHY.index(self.role)
        except ValueError:
            return len(TEAM_ROLE_HIERARCHY)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role,
            "key_delivery_pending": self.key_delivery_pending,
            "key_confirmed": self.key_confirmed,
        }


@dataclass
class TeamFolder:
    team_id: str
    folder_id: str
    folder_name: str
    added_by: str

    def to_dict(self) -> dict:
        return {
            "team_id": self.team_id,
            "folder_id": self.folder_id,
            "folder_name": self.folder_name,
            "added_by": self.added_by,
        }


@dataclass
class TeamFileKey:
    team_id: str
    file_id: str
    pre_c1: str
    encrypted_file_key: str
    key_iv: str

    def to_dict(self) -> dict:
        return {
            "team_id": self.team_id,
            "file_id": self.file_id,
            "pre_c1": self.pre_c1,
            "encrypted_file_key": self.encrypted_file_key,
            "key_iv": self.key_iv,
        }


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

async def get_team(db, team_id: str) -> Team | None:
    cursor = await db.execute("SELECT * FROM teams WHERE id = ?", (team_id,))
    row = await cursor.fetchone()
    return Team.from_row(row) if row else None


async def get_team_member_role(db, team_id: str, user_id: str) -> str | None:
    """Return the user's role in the team, or None if not a member."""
    cursor = await db.execute(
        "SELECT role_id FROM user_roles "
        "WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (user_id, team_id),
    )
    row = await cursor.fetchone()
    return row["role_id"] if row else None


async def get_team_members(db, team_id: str) -> list[TeamMember]:
    """Return all team members with their key delivery and confirmation state."""
    cursor = await db.execute(
        "SELECT ur.user_id, u.username, ur.role_id AS role, "
        "       COALESCE(utk.key_confirmed, 0) AS key_confirmed, "
        "       CASE WHEN EXISTS("
        "           SELECT 1 FROM policy_team_grants ptg "
        "           JOIN policy_effects pe ON pe.id = ptg.effect_id "
        "           WHERE ptg.user_id = ur.user_id "
        "             AND pe.target_id = ? "
        "             AND ptg.key_wrapped = 0"
        "       ) THEN 1 ELSE 0 END AS key_delivery_pending "
        "FROM user_roles ur "
        "JOIN users u ON u.id = ur.user_id "
        "LEFT JOIN user_team_keys utk "
        "       ON utk.team_id = ? AND utk.user_id = ur.user_id "
        "WHERE ur.scope_type = 'team' AND ur.scope_id = ? "
        "ORDER BY u.username",
        (team_id, team_id, team_id),
    )
    rows = await cursor.fetchall()
    return [
        TeamMember(
            user_id=r["user_id"],
            username=r["username"],
            role=r["role"],
            key_delivery_pending=bool(r["key_delivery_pending"]),
            key_confirmed=bool(r["key_confirmed"]),
        )
        for r in rows
    ]


async def get_team_member_count(db, team_id: str) -> int:
    cursor = await db.execute(
        "SELECT COUNT(*) FROM user_roles "
        "WHERE scope_type = 'team' AND scope_id = ?",
        (team_id,),
    )
    row = await cursor.fetchone()
    return row[0]


async def get_user_teams(db, user_id: str) -> list[dict]:
    """Return all teams the user belongs to with roles, key state, and pending flags.

    Extra fields per team (beyond Team.to_dict()):
      my_roles              — list of role IDs the caller holds in this team
      my_key_confirmed      — True if caller's user_team_keys.key_confirmed = 1
      has_pending_key_grants — True if any policy_team_grants.key_wrapped=0 exist
                               on this team (caller should fulfil them on login)
    """
    cursor = await db.execute(
        "SELECT t.id, t.name, t.description, t.owner_id, t.pre_public_key, "
        "       t.rotation_pending, t.created_at, t.updated_at, "
        "       array_agg(ur.role_id) AS my_roles, "
        "       COALESCE(MAX(utk.key_confirmed), 0) AS my_key_confirmed, "
        "       CASE WHEN EXISTS("
        "           SELECT 1 FROM policy_team_grants ptg "
        "           JOIN policy_effects pe ON pe.id = ptg.effect_id "
        "           WHERE pe.target_id = t.id AND ptg.key_wrapped = 0"
        "       ) THEN 1 ELSE 0 END AS has_pending_key_grants "
        "FROM teams t "
        "JOIN user_roles ur ON ur.scope_id = t.id AND ur.scope_type = 'team' AND ur.user_id = ? "
        "LEFT JOIN user_team_keys utk ON utk.team_id = t.id AND utk.user_id = ? "
        "GROUP BY t.id, t.name, t.description, t.owner_id, t.pre_public_key, "
        "         t.rotation_pending, t.created_at, t.updated_at "
        "ORDER BY t.name",
        (user_id, user_id),
    )
    rows = await cursor.fetchall()
    return [
        {
            **Team.from_row(r).to_dict(),
            "my_roles":              list(r["my_roles"]) if r["my_roles"] else [],
            "my_key_confirmed":      bool(r["my_key_confirmed"]),
            "has_pending_key_grants": bool(r["has_pending_key_grants"]),
        }
        for r in rows
    ]


async def get_team_folders(db, team_id: str) -> list[TeamFolder]:
    cursor = await db.execute(
        "SELECT tf.team_id, tf.folder_id, f.name AS folder_name, tf.added_by "
        "FROM team_folders tf "
        "JOIN folders f ON f.id = tf.folder_id "
        "WHERE tf.team_id = ? "
        "ORDER BY f.name",
        (team_id,),
    )
    rows = await cursor.fetchall()
    return [
        TeamFolder(
            team_id=r["team_id"],
            folder_id=r["folder_id"],
            folder_name=r["folder_name"],
            added_by=r["added_by"],
        )
        for r in rows
    ]
