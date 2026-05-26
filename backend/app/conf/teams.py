"""Team-related constants."""

import re

from app.models.role import ROLE_TEAM_ADMIN, ROLE_TEAM_MANAGER, ROLE_TEAM_MEMBER

# --- Team roles (scoped via user_roles scope_type='team') ---
# Aliases onto the canonical role IDs defined in models/role.py.
TEAM_ROLE_OWNER = ROLE_TEAM_ADMIN  # "team_admin"
TEAM_ROLE_SUPERVISOR = ROLE_TEAM_MANAGER  # "team_manager"
TEAM_ROLE_MEMBER = ROLE_TEAM_MEMBER  # "team_member"

# Ordered from highest to lowest privilege — used for minimum-role checks.
TEAM_ROLE_HIERARCHY = (TEAM_ROLE_OWNER, TEAM_ROLE_SUPERVISOR, TEAM_ROLE_MEMBER)

VALID_TEAM_ROLES = frozenset(TEAM_ROLE_HIERARCHY)

# Roles a manager or admin may assign to invited members
ASSIGNABLE_ROLES = frozenset({TEAM_ROLE_SUPERVISOR, TEAM_ROLE_MEMBER})

# --- Team field limits ---
TEAM_NAME_MIN_LENGTH = 1
TEAM_NAME_MAX_LENGTH = 64
TEAM_DESCRIPTION_MAX_LENGTH = 500
TEAM_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9 _\-.]{1,64}$")

# Maximum members per team
TEAM_MAX_MEMBERS = 200

# --- BLS12-381 point sizes ---
# G1 compressed point: 48 bytes → 64 base64 chars (pre_c1 in file_team_keys)
G1_COMPRESSED_BYTES = 48
G1_BASE64_MAX_LENGTH = 68  # ceil(48/3)*4 = 64, +4 slack for padding variants

# G2 compressed point: 96 bytes → 128 base64 chars (pre_public_key in teams)
G2_COMPRESSED_BYTES = 96
G2_BASE64_MAX_LENGTH = 132  # ceil(96/3)*4 = 128, +4 slack

# --- Rotation ---
# Maximum number of file_team_keys rows the rotation endpoint may update
# in a single request. Prevents excessively large payloads.
ROTATION_MAX_FILE_KEYS = 50_000
