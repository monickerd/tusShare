"""Custom team-scoped role models and query helpers.

Custom team roles are created per-team by users with can_create_roles.
They carry team-specific permission flags (move flags, folder-manage flags) rather than
the global admin flags defined in role_permission_flags.

Global team roles (team_admin, team_manager, team_member) are stored in
user_roles with scope_type='team' and have implicit defaults:
  team_admin / team_manager : all flags on
  team_member               : move flags off, manage_own on, manage_all off
"""

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Team-scoped permission flag name constants
# ---------------------------------------------------------------------------

TEAM_FLAG_MOVE_OWN_OUT    = "move_own_files_out_of_team"
TEAM_FLAG_MOVE_OTHERS_OUT = "move_others_files_out_of_team"
TEAM_FLAG_MOVE_OWN_IN     = "move_own_within_team"
TEAM_FLAG_MOVE_OTHERS_IN  = "move_all_within_team"

# Folder flags
TEAM_FLAG_MANAGE_FOLDER_OWN = "team_folder_manage_own"
TEAM_FLAG_MANAGE_FOLDER_ALL = "team_folder_manage_all"
TEAM_FLAG_FOLDER_CREATE     = "folder_create"

# Share flags
TEAM_FLAG_SHARE_CREATE     = "share_create"
TEAM_FLAG_SHARE_MANAGE_OWN = "share_manage_own"
TEAM_FLAG_SHARE_MANAGE_ALL = "share_manage_all"

# All valid flags for team roles (the complete set checked server-side)
TEAM_ROLE_FLAGS: frozenset[str] = frozenset(
    {
        TEAM_FLAG_MOVE_OWN_OUT,
        TEAM_FLAG_MOVE_OTHERS_OUT,
        TEAM_FLAG_MOVE_OWN_IN,
        TEAM_FLAG_MOVE_OTHERS_IN,
        TEAM_FLAG_MANAGE_FOLDER_OWN,
        TEAM_FLAG_MANAGE_FOLDER_ALL,
        TEAM_FLAG_FOLDER_CREATE,
        TEAM_FLAG_SHARE_CREATE,
        TEAM_FLAG_SHARE_MANAGE_OWN,
        TEAM_FLAG_SHARE_MANAGE_ALL,
    }
)

# Global team role IDs that carry default authority (admin + manager)
_AUTHORITY_ROLES = frozenset({"team_admin", "team_manager"})

# Backwards-compatible alias used by move-permission checks
_MOVE_AUTHORITY_ROLES = _AUTHORITY_ROLES

# Display metadata for UI rendering (ordered, grouped for hierarchical checkbox tree)
TEAM_FLAG_META: list[dict] = [
    # --- Move / Copy ---
    {
        "flag": TEAM_FLAG_MOVE_OWN_IN,
        "group": "Move / Copy",
        "label": "Own files within Team",
        "description": "Move or copy own files between folders within the team",
    },
    {
        "flag": TEAM_FLAG_MOVE_OTHERS_IN,
        "group": "Move / Copy",
        "label": "All files within Team",
        "description": "Move or copy any file between folders within the team",
    },
    {
        "flag": TEAM_FLAG_MOVE_OWN_OUT,
        "group": "Move / Copy",
        "label": "Own files out of Team",
        "description": "May move files owned by themselves out of a team folder to a personal folder",
    },
    {
        "flag": TEAM_FLAG_MOVE_OTHERS_OUT,
        "group": "Move / Copy",
        "label": "All files out of Team",
        "description": "May move files owned by another user out of a team folder",
    },
    # --- Folders ---
    {
        "flag": TEAM_FLAG_FOLDER_CREATE,
        "group": "Folders",
        "label": "Create folders",
        "description": "Create new subfolders within the team",
    },
    {
        "flag": TEAM_FLAG_MANAGE_FOLDER_OWN,
        "group": "Folders",
        "label": "Manage own folders",
        "description": "May manage (restrict permissions, set grants on) folders they created within the team",
    },
    {
        "flag": TEAM_FLAG_MANAGE_FOLDER_ALL,
        "group": "Folders",
        "label": "Manage all folders",
        "description": "May manage any folder within the team regardless of who created it",
    },
    # --- Shares ---
    {
        "flag": TEAM_FLAG_SHARE_CREATE,
        "group": "Shares",
        "label": "Create shares",
        "description": "Create share links from team files",
    },
    {
        "flag": TEAM_FLAG_SHARE_MANAGE_OWN,
        "group": "Shares",
        "label": "Manage own shares",
        "description": "Manage share links you created",
    },
    {
        "flag": TEAM_FLAG_SHARE_MANAGE_ALL,
        "group": "Shares",
        "label": "Manage all shares",
        "description": "Manage all share links within the team",
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
    id: str
    team_id: str
    name: str
    description: str
    created_by: str | None
    created_at: str

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
            "id": self.id,
            "team_id": self.team_id,
            "name": self.name,
            "description": self.description,
            "created_by": self.created_by,
            "created_at": self.created_at,
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
    cursor = await db.execute(
        "SELECT role_id FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (user_id, team_id),
    )
    scoped_role_ids = {r["role_id"] for r in await cursor.fetchall()}

    if scoped_role_ids & _AUTHORITY_ROLES:
        return {
            TEAM_FLAG_MOVE_OWN_OUT: True,
            TEAM_FLAG_MOVE_OTHERS_OUT: True,
        }

    cursor = await db.execute(
        "SELECT tp.flag, MAX(tp.value) AS value "
        "FROM team_role_assignments tra "
        "JOIN team_role_permissions tp ON tp.team_role_id = tra.team_role_id "
        "WHERE tra.user_id = ? AND tra.team_id = ? "
        "GROUP BY tp.flag",
        (user_id, team_id),
    )
    custom_flags = {r["flag"]: r["value"] not in ("0", "", "false", "False", "no") for r in await cursor.fetchall()}

    return {
        TEAM_FLAG_MOVE_OWN_OUT: custom_flags.get(TEAM_FLAG_MOVE_OWN_OUT, False),
        TEAM_FLAG_MOVE_OTHERS_OUT: custom_flags.get(TEAM_FLAG_MOVE_OTHERS_OUT, False),
    }


async def get_user_team_manage_flags(db, user_id: str, team_id: str) -> dict[str, bool]:
    """Return effective folder-manage flags for a user within a team.

    Global defaults:
      team_admin / team_manager → both manage flags True
      team_member               → manage_own True, manage_all False
    Custom roles can override either flag.
    """
    cursor = await db.execute(
        "SELECT role_id FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (user_id, team_id),
    )
    scoped_role_ids = {r["role_id"] for r in await cursor.fetchall()}

    if scoped_role_ids & _AUTHORITY_ROLES:
        return {
            TEAM_FLAG_MANAGE_FOLDER_OWN: True,
            TEAM_FLAG_MANAGE_FOLDER_ALL: True,
        }

    cursor = await db.execute(
        "SELECT tp.flag, MAX(tp.value) AS value "
        "FROM team_role_assignments tra "
        "JOIN team_role_permissions tp ON tp.team_role_id = tra.team_role_id "
        "WHERE tra.user_id = ? AND tra.team_id = ? "
        "  AND tp.flag IN (?, ?) "
        "GROUP BY tp.flag",
        (user_id, team_id, TEAM_FLAG_MANAGE_FOLDER_OWN, TEAM_FLAG_MANAGE_FOLDER_ALL),
    )
    custom_flags = {r["flag"]: r["value"] not in ("0", "", "false", "False", "no") for r in await cursor.fetchall()}

    # team_member default: manage_own=True (owner already granted by _annotate_can_manage),
    # manage_all=False (need explicit grant via custom role).
    return {
        TEAM_FLAG_MANAGE_FOLDER_OWN: custom_flags.get(TEAM_FLAG_MANAGE_FOLDER_OWN, True),
        TEAM_FLAG_MANAGE_FOLDER_ALL: custom_flags.get(TEAM_FLAG_MANAGE_FOLDER_ALL, False),
    }
