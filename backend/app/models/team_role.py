"""Custom team-scoped role models and query helpers.

Custom team roles are created per-team by users with can_create_roles.
They carry team-specific permission flags (move flags) rather than
the global admin flags defined in role_permission_flags.

Global team roles (team_admin, team_manager, team_member) are stored in
user_roles with scope_type='team' and have implicit move defaults:
  team_admin / team_manager : both move flags on
  team_member               : both move flags off
"""

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Team-scoped permission flag name constants
# ---------------------------------------------------------------------------

TEAM_FLAG_MOVE_OWN_OUT    = "move_own_files_out_of_team"
TEAM_FLAG_MOVE_OTHERS_OUT = "move_others_files_out_of_team"

# All valid flags for team roles (the complete set checked server-side)
TEAM_ROLE_FLAGS: frozenset[str] = frozenset({
    TEAM_FLAG_MOVE_OWN_OUT,
    TEAM_FLAG_MOVE_OTHERS_OUT,
})

# Global team role IDs that carry default move authority
_MOVE_AUTHORITY_ROLES = frozenset({"team_admin", "team_manager"})

# Display metadata for UI rendering (ordered)
TEAM_FLAG_META: list[dict] = [
    {
        "flag":        TEAM_FLAG_MOVE_OWN_OUT,
        "label":       "Move own files out of team",
        "description": "May move files owned by themselves out of a team folder",
    },
    {
        "flag":        TEAM_FLAG_MOVE_OTHERS_OUT,
        "label":       "Move others' files out of team",
        "description": "May move files owned by another user out of a team folder",
    },
]

# Field length limits
MAX_TEAM_ROLE_NAME_LEN = 64
MAX_TEAM_ROLE_DESC_LEN = 255


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class TeamRole:
    id:          str
    team_id:     str
    name:        str
    description: str
    created_by:  str | None
    created_at:  str

    @classmethod
    def from_row(cls, row) -> "TeamRole":
        return cls(
            id=row["id"],
            team_id=row["team_id"],
            name=row["name"],
            description=row["description"],
            created_by=row["created_by"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "team_id":     self.team_id,
            "name":        self.name,
            "description": self.description,
            "created_by":  self.created_by,
            "created_at":  self.created_at,
        }


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

async def get_user_team_move_flags(db, user_id: str, team_id: str) -> dict[str, bool]:
    """Return the effective move permission flags for a user within a team.

    Considers both global scoped roles and custom team role assignments.
    Any granting source wins (MAX semantics).

    Global defaults:
      team_admin / team_manager → both flags True
      team_member               → both flags False (unless custom role grants them)
    """
    # Check global roles scoped to this team
    cursor = await db.execute(
        "SELECT role_id FROM user_roles "
        "WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (user_id, team_id),
    )
    scoped_role_ids = {r["role_id"] for r in await cursor.fetchall()}

    if scoped_role_ids & _MOVE_AUTHORITY_ROLES:
        # team_admin or team_manager: full move authority
        return {
            TEAM_FLAG_MOVE_OWN_OUT:    True,
            TEAM_FLAG_MOVE_OTHERS_OUT: True,
        }

    # Check custom team role assignments for this user in this team
    cursor = await db.execute(
        "SELECT tp.flag, MAX(tp.value) AS value "
        "FROM team_role_assignments tra "
        "JOIN team_role_permissions tp ON tp.team_role_id = tra.team_role_id "
        "WHERE tra.user_id = ? AND tra.team_id = ? "
        "GROUP BY tp.flag",
        (user_id, team_id),
    )
    custom_flags = {
        r["flag"]: r["value"] not in ("0", "", "false", "False", "no")
        for r in await cursor.fetchall()
    }

    return {
        TEAM_FLAG_MOVE_OWN_OUT:    custom_flags.get(TEAM_FLAG_MOVE_OWN_OUT, False),
        TEAM_FLAG_MOVE_OTHERS_OUT: custom_flags.get(TEAM_FLAG_MOVE_OTHERS_OUT, False),
    }
