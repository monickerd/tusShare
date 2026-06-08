"""Team, TeamMember, and TeamFileKey data models."""

from dataclasses import dataclass, field
from datetime import datetime

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
    scheduled_delete_at: str | None = None

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
            scheduled_delete_at=str(row["scheduled_delete_at"]) if row["scheduled_delete_at"] else None,
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
            "scheduled_delete_at": self.scheduled_delete_at,
        }


_ROLE_PRIORITY: dict[str, int] = {r: i for i, r in enumerate(TEAM_ROLE_HIERARCHY)}


@dataclass
class TeamMember:
    user_id: str
    username: str
    role: str  # primary (highest-priority) standard role
    roles: list = field(default_factory=list)       # all standard roles this user holds
    custom_roles: list = field(default_factory=list) # [{id, name}] custom role assignments
    key_delivery_pending: bool = False
    key_confirmed: bool = False

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
            "roles": list(self.roles),
            "custom_roles": list(self.custom_roles),
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
    """Return the user's highest-priority standard role in the team, or None if not a member."""
    cursor = await db.execute(
        "SELECT role_id FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ? "
        "ORDER BY CASE role_id "
        "    WHEN 'team_admin'   THEN 0 "
        "    WHEN 'team_manager' THEN 1 "
        "    WHEN 'team_member'  THEN 2 "
        "    ELSE 99 END "
        "LIMIT 1",
        (user_id, team_id),
    )
    row = await cursor.fetchone()
    return row["role_id"] if row else None


async def get_team_members(db, team_id: str) -> list[TeamMember]:
    """Return all team members with aggregated roles and custom role assignments.

    Groups by user so a member with multiple standard role rows (e.g. policy + manual)
    or custom roles appears exactly once. The primary `role` field is the highest-priority
    standard role held by that user.
    """
    # Standard roles: one row per user, all role_ids aggregated
    cursor = await db.execute(
        "SELECT ur.user_id, u.username, "
        "       array_agg(ur.role_id) AS roles, "
        "       COALESCE(MAX(utk.key_confirmed), 0) AS key_confirmed, "
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
        "GROUP BY ur.user_id, u.username "
        "ORDER BY u.username",
        (team_id, team_id, team_id),
    )
    std_rows = await cursor.fetchall()

    # Custom roles: one row per (user, custom_role) assignment
    cursor2 = await db.execute(
        "SELECT tra.user_id, tr.id AS role_id, tr.name AS role_name "
        "FROM team_role_assignments tra "
        "JOIN team_roles tr ON tr.id = tra.team_role_id "
        "WHERE tra.team_id = ? "
        "ORDER BY tra.user_id, tr.name",
        (team_id,),
    )
    custom_rows = await cursor2.fetchall()

    custom_by_user: dict[str, list[dict]] = {}
    for cr in custom_rows:
        uid = cr["user_id"]
        if uid not in custom_by_user:
            custom_by_user[uid] = []
        custom_by_user[uid].append({"id": cr["role_id"], "name": cr["role_name"]})

    members = []
    for r in std_rows:
        all_roles: list[str] = list(r["roles"]) if r["roles"] else []
        primary = min(all_roles, key=lambda rid: _ROLE_PRIORITY.get(rid, 99), default="team_member")
        members.append(
            TeamMember(
                user_id=r["user_id"],
                username=r["username"],
                role=primary,
                roles=sorted(all_roles, key=lambda rid: _ROLE_PRIORITY.get(rid, 99)),
                custom_roles=custom_by_user.get(r["user_id"], []),
                key_delivery_pending=bool(r["key_delivery_pending"]),
                key_confirmed=bool(r["key_confirmed"]),
            )
        )
    return members


async def get_team_member_count(db, team_id: str) -> int:
    cursor = await db.execute(
        "SELECT COUNT(*) FROM user_roles WHERE scope_type = 'team' AND scope_id = ?",
        (team_id,),
    )
    row = await cursor.fetchone()
    return row[0]


async def get_user_teams(db, user_id: str) -> list[dict]:
    """Return all teams the user belongs to with roles, key state, and pending flags.

    Extra fields per team (beyond Team.to_dict()):
      my_roles               — list of role IDs the caller holds in this team
      my_key_confirmed       — True if caller's user_team_keys.key_confirmed = 1
      has_pending_key_grants — True if any policy_team_grants.key_wrapped=0 exist
                               on this team (caller should fulfil them on login)
      last_seen_at           — ISO timestamp when the caller last viewed this team's
                               management page, or null if never viewed
      has_updates            — True for managers: team was modified since last viewed
    """
    cursor = await db.execute(
        "SELECT t.id, t.name, t.description, t.owner_id, t.pre_public_key, "
        "       t.rotation_pending, t.created_at, t.updated_at, t.scheduled_delete_at, "
        "       array_agg(ur.role_id) AS my_roles, "
        "       COALESCE(MAX(utk.key_confirmed), 0) AS my_key_confirmed, "
        "       CASE WHEN EXISTS("
        "           SELECT 1 FROM policy_team_grants ptg "
        "           JOIN policy_effects pe ON pe.id = ptg.effect_id "
        "           WHERE pe.target_id = t.id AND ptg.key_wrapped = 0"
        "       ) THEN 1 ELSE 0 END AS has_pending_key_grants, "
        "       MAX(tls.seen_at) AS my_last_seen "
        "FROM teams t "
        "JOIN user_roles ur ON ur.scope_id = t.id AND ur.scope_type = 'team' AND ur.user_id = ? "
        "LEFT JOIN user_team_keys utk ON utk.team_id = t.id AND utk.user_id = ? "
        "LEFT JOIN team_last_seen tls ON tls.team_id = t.id AND tls.user_id = ? "
        "GROUP BY t.id, t.name, t.description, t.owner_id, t.pre_public_key, "
        "         t.rotation_pending, t.created_at, t.updated_at, t.scheduled_delete_at "
        "ORDER BY t.name",
        (user_id, user_id, user_id),
    )
    rows = await cursor.fetchall()

    def _has_updates(r) -> bool:
        roles = list(r["my_roles"]) if r["my_roles"] else []
        if not any(role in ("team_admin", "team_manager") for role in roles):
            return False
        last_seen = r["my_last_seen"]
        if last_seen is None:
            return True
        # updated_at is BIGINT epoch seconds; my_last_seen is an ISO string from _Row (sub-second precision)
        last_seen_float = datetime.fromisoformat(last_seen.replace("Z", "+00:00")).timestamp()
        return r["updated_at"] > last_seen_float

    return [
        {
            **Team.from_row(r).to_dict(),
            "my_roles": list(r["my_roles"]) if r["my_roles"] else [],
            "my_key_confirmed": bool(r["my_key_confirmed"]),
            "has_pending_key_grants": bool(r["has_pending_key_grants"]),
            "last_seen_at": r["my_last_seen"] if r["my_last_seen"] else None,
            "has_updates": _has_updates(r),
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
