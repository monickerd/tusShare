"""Team management routes.

Endpoints:
    POST   /api/v1/teams                              create team
    GET    /api/v1/teams                              list my teams
    GET    /api/v1/teams/{team_id}                    team detail + members + folders
    PUT    /api/v1/teams/{team_id}                    update name/description
    DELETE /api/v1/teams/{team_id}                    delete team (owner only)

    GET    /api/v1/teams/{team_id}/members            list members
    POST   /api/v1/teams/{team_id}/members            invite member
    PUT    /api/v1/teams/{team_id}/members/{user_id}  change role
    DELETE /api/v1/teams/{team_id}/members/{user_id}  remove member

    GET    /api/v1/teams/{team_id}/my-key             get my wrapped team key

    GET    /api/v1/teams/{team_id}/folders            list team folders
    POST   /api/v1/teams/{team_id}/folders            add folder
    DELETE /api/v1/teams/{team_id}/folders/{folder_id} remove folder

    GET    /api/v1/teams/{team_id}/file-keys          list PRE file keys
    POST   /api/v1/teams/{team_id}/file-keys          add/update PRE file keys (batch)

    POST   /api/v1/teams/{team_id}/rotate             apply PRE key rotation
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.conf.teams import (
    ASSIGNABLE_ROLES,
    ROTATION_MAX_FILE_KEYS,
    TEAM_DESCRIPTION_MAX_LENGTH,
    TEAM_MAX_MEMBERS,
    TEAM_ROLE_HIERARCHY,
    TEAM_ROLE_MEMBER,
    TEAM_ROLE_OWNER,
    TEAM_ROLE_SUPERVISOR,
    VALID_TEAM_ROLES,
)
from app.database import get_db
from app.middleware.rate_limit import check_management_rate_limit
from app.models.role import grant_role, revoke_role
from app.models.team import (
    TeamFileKey,
    get_team,
    get_team_folders,
    get_team_member_count,
    get_team_member_role,
    get_team_members,
    get_user_teams,
)
from app.validation.sanitizers import (
    sanitize_team_name,
    sanitize_username,
    validate_base64,
    validate_g1_point,
    validate_g2_point,
    validate_uuid,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/teams",
    tags=["teams"],
    dependencies=[Depends(check_management_rate_limit)],
)

# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class _MemberKeyIn(BaseModel):
    """KEM-wrapped team key fields for a single member."""
    ephemeral_x25519_pub: str
    kem_ciphertext: str
    encrypted_sk: str
    sk_iv: str

    @field_validator("ephemeral_x25519_pub")
    @classmethod
    def validate_x25519(cls, v: str) -> str:
        return validate_base64(v, max_length=60)

    @field_validator("kem_ciphertext")
    @classmethod
    def validate_kem(cls, v: str) -> str:
        return validate_base64(v, max_length=1500)

    @field_validator("encrypted_sk")
    @classmethod
    def validate_encrypted_sk(cls, v: str) -> str:
        # 32-byte sk_team + 16-byte GCM tag = 48 bytes → 64 base64 chars
        return validate_base64(v, max_length=68)

    @field_validator("sk_iv")
    @classmethod
    def validate_sk_iv(cls, v: str) -> str:
        return validate_base64(v, max_length=20)


class CreateTeamRequest(BaseModel):
    name: str
    description: str = ""
    pre_public_key: str                # G2 point (96 bytes, base64)
    # Owner's own wrapped team key (they become the first member automatically)
    ephemeral_x25519_pub: str
    kem_ciphertext: str
    encrypted_sk: str
    sk_iv: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return sanitize_team_name(v)

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        if len(v) > TEAM_DESCRIPTION_MAX_LENGTH:
            raise ValueError(f"Description must be at most {TEAM_DESCRIPTION_MAX_LENGTH} characters")
        return v

    @field_validator("pre_public_key")
    @classmethod
    def validate_pk(cls, v: str) -> str:
        return validate_g2_point(v)

    @field_validator("ephemeral_x25519_pub")
    @classmethod
    def validate_x25519(cls, v: str) -> str:
        return validate_base64(v, max_length=60)

    @field_validator("kem_ciphertext")
    @classmethod
    def validate_kem(cls, v: str) -> str:
        return validate_base64(v, max_length=1500)

    @field_validator("encrypted_sk")
    @classmethod
    def validate_encrypted_sk(cls, v: str) -> str:
        return validate_base64(v, max_length=68)

    @field_validator("sk_iv")
    @classmethod
    def validate_sk_iv(cls, v: str) -> str:
        return validate_base64(v, max_length=20)


class UpdateTeamRequest(BaseModel):
    name: str | None = None
    description: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            return sanitize_team_name(v)
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str | None) -> str | None:
        if v is not None and len(v) > TEAM_DESCRIPTION_MAX_LENGTH:
            raise ValueError(f"Description must be at most {TEAM_DESCRIPTION_MAX_LENGTH} characters")
        return v


class InviteMemberRequest(BaseModel):
    username: str
    role: str = TEAM_ROLE_MEMBER
    # KEM-wrapped team key for the new member
    ephemeral_x25519_pub: str
    kem_ciphertext: str
    encrypted_sk: str
    sk_iv: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ASSIGNABLE_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(sorted(ASSIGNABLE_ROLES))}")
        return v

    @field_validator("ephemeral_x25519_pub")
    @classmethod
    def validate_x25519(cls, v: str) -> str:
        return validate_base64(v, max_length=60)

    @field_validator("kem_ciphertext")
    @classmethod
    def validate_kem(cls, v: str) -> str:
        return validate_base64(v, max_length=1500)

    @field_validator("encrypted_sk")
    @classmethod
    def validate_encrypted_sk(cls, v: str) -> str:
        return validate_base64(v, max_length=68)

    @field_validator("sk_iv")
    @classmethod
    def validate_sk_iv(cls, v: str) -> str:
        return validate_base64(v, max_length=20)


class UpdateMemberRoleRequest(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ASSIGNABLE_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(sorted(ASSIGNABLE_ROLES))}")
        return v


class AddTeamFolderRequest(BaseModel):
    folder_id: str

    @field_validator("folder_id")
    @classmethod
    def validate_fid(cls, v: str) -> str:
        return validate_uuid(v)


class _FileKeyIn(BaseModel):
    file_id: str
    pre_c1: str
    encrypted_file_key: str
    key_iv: str

    @field_validator("file_id")
    @classmethod
    def validate_fid(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("pre_c1")
    @classmethod
    def validate_c1(cls, v: str) -> str:
        return validate_g1_point(v)

    @field_validator("encrypted_file_key", "key_iv")
    @classmethod
    def validate_blobs(cls, v: str) -> str:
        return validate_base64(v)


class AddFileKeysRequest(BaseModel):
    file_keys: list[_FileKeyIn]

    @field_validator("file_keys")
    @classmethod
    def validate_count(cls, v: list) -> list:
        if not v:
            raise ValueError("file_keys must not be empty")
        if len(v) > ROTATION_MAX_FILE_KEYS:
            raise ValueError(f"Cannot submit more than {ROTATION_MAX_FILE_KEYS} file keys at once")
        return v


class _RotatedFileKeyIn(BaseModel):
    """Updated C1 value for a single file after PRE rotation."""
    file_id: str
    pre_c1: str

    @field_validator("file_id")
    @classmethod
    def validate_fid(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("pre_c1")
    @classmethod
    def validate_c1(cls, v: str) -> str:
        return validate_g1_point(v)


class _RotatedMemberIn(BaseModel):
    """New wrapped team key for a single remaining member."""
    user_id: str
    ephemeral_x25519_pub: str
    kem_ciphertext: str
    encrypted_sk: str
    sk_iv: str

    @field_validator("user_id")
    @classmethod
    def validate_uid(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("ephemeral_x25519_pub")
    @classmethod
    def validate_x25519(cls, v: str) -> str:
        return validate_base64(v, max_length=60)

    @field_validator("kem_ciphertext")
    @classmethod
    def validate_kem(cls, v: str) -> str:
        return validate_base64(v, max_length=1500)

    @field_validator("encrypted_sk")
    @classmethod
    def validate_encrypted_sk(cls, v: str) -> str:
        return validate_base64(v, max_length=68)

    @field_validator("sk_iv")
    @classmethod
    def validate_sk_iv(cls, v: str) -> str:
        return validate_base64(v, max_length=20)


class RotateKeysRequest(BaseModel):
    """Payload for a client-side PRE rotation.

    The team owner performs all BLS12-381 scalar multiplications in the browser
    (using @noble/curves) and submits:
      - New G2 public key (sk_new * G2)
      - Every file_team_keys row with its updated C1 (= rk * C1_old)
      - New user_team_keys entries wrapping sk_new for each remaining member
    """
    pre_public_key_new: str             # G2 point, base64
    file_keys: list[_RotatedFileKeyIn]
    members: list[_RotatedMemberIn]

    @field_validator("pre_public_key_new")
    @classmethod
    def validate_pk(cls, v: str) -> str:
        return validate_g2_point(v)

    @field_validator("file_keys")
    @classmethod
    def validate_file_keys_count(cls, v: list) -> list:
        if len(v) > ROTATION_MAX_FILE_KEYS:
            raise ValueError(f"Cannot rotate more than {ROTATION_MAX_FILE_KEYS} file keys at once")
        return v

    @field_validator("members")
    @classmethod
    def validate_members(cls, v: list) -> list:
        if not v:
            raise ValueError("members list must not be empty after rotation")
        return v


# ---------------------------------------------------------------------------
# Access control helpers
# ---------------------------------------------------------------------------

def _role_rank(role: str) -> int:
    """Return privilege rank: lower index = higher privilege."""
    try:
        return TEAM_ROLE_HIERARCHY.index(role)
    except ValueError:
        return len(TEAM_ROLE_HIERARCHY)


async def _get_team_or_404(db, team_id: str):
    team = await get_team(db, team_id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return team


async def _require_team_role(db, team_id: str, user: AuthenticatedUser, min_role: str):
    """Raise 403 if the user does not hold at least min_role in the team."""
    role = await get_team_member_role(db, team_id, user.id)
    if role is None:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    if _role_rank(role) > _role_rank(min_role):
        raise HTTPException(status_code=403, detail="Insufficient team role")
    return role


# ---------------------------------------------------------------------------
# Teams CRUD
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
async def create_team(
    body: CreateTeamRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Create a new team. Creator becomes team_owner automatically."""
    team_id = str(uuid.uuid4())
    ur_id   = str(uuid.uuid4())
    utk_id  = str(uuid.uuid4())

    await db.execute(
        "INSERT INTO teams (id, name, description, owner_id, pre_public_key) "
        "VALUES (?, ?, ?, ?, ?)",
        (team_id, body.name, body.description, user.id, body.pre_public_key),
    )
    # Grant team_owner role (scoped)
    await db.execute(
        "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by) "
        "VALUES (?, ?, 'team_owner', 'team', ?, ?)",
        (ur_id, user.id, team_id, user.id),
    )
    # Store owner's wrapped team key
    await db.execute(
        "INSERT INTO user_team_keys "
        "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (utk_id, team_id, user.id, body.ephemeral_x25519_pub,
         body.kem_ciphertext, body.encrypted_sk, body.sk_iv),
    )
    # Auto-create the team's shared folder and register it
    folder_id = str(uuid.uuid4())
    tf_id     = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO folders (id, name, parent_id, owner_id) VALUES (?, ?, NULL, ?)",
        (folder_id, body.name, user.id),
    )
    await db.execute(
        "INSERT INTO team_folders (id, team_id, folder_id, added_by) VALUES (?, ?, ?, ?)",
        (tf_id, team_id, folder_id, user.id),
    )
    await db.commit()
    logger.info("Team %s (%s) created by user %s", body.name, team_id, user.id)
    return {"team_id": team_id, "folder_id": folder_id}


@router.get("")
async def list_my_teams(
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """List all teams the authenticated user belongs to."""
    teams = await get_user_teams(db, user.id)
    return {"teams": teams}


@router.get("/{team_id}")
async def get_team_detail(
    team_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Return team details including members and folders."""
    team_id = validate_uuid(team_id)
    team = await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    members = await get_team_members(db, team_id)
    folders = await get_team_folders(db, team_id)

    return {
        "team": team.to_dict(),
        "members": [m.to_dict() for m in members],
        "folders": [f.to_dict() for f in folders],
    }


@router.put("/{team_id}")
async def update_team(
    team_id: str,
    body: UpdateTeamRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Update team name and/or description. Requires owner or supervisor."""
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_SUPERVISOR)

    if body.name is None and body.description is None:
        raise HTTPException(status_code=422, detail="Nothing to update")

    if body.name is not None:
        # Check uniqueness: same owner can't have two teams with the same name
        cursor = await db.execute(
            "SELECT id FROM teams WHERE owner_id = ? AND name = ? AND id != ?",
            (user.id, body.name, team_id),
        )
        if await cursor.fetchone():
            raise HTTPException(status_code=409, detail="You already have a team with that name")
        await db.execute(
            "UPDATE teams SET name = ?, updated_at = unixepoch() WHERE id = ?",
            (body.name, team_id),
        )

    if body.description is not None:
        await db.execute(
            "UPDATE teams SET description = ?, updated_at = unixepoch() WHERE id = ?",
            (body.description, team_id),
        )

    await db.commit()
    return {"ok": True}


@router.delete("/{team_id}", status_code=204)
async def delete_team(
    team_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Delete a team and all associated data. Owner only."""
    team_id = validate_uuid(team_id)
    team = await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_OWNER)

    # Collect team folder IDs before cascade wipes team_folders
    cursor = await db.execute(
        "SELECT folder_id FROM team_folders WHERE team_id = ?", (team_id,)
    )
    team_folder_ids = [r["folder_id"] for r in await cursor.fetchall()]

    # Cascade deletes handle user_team_keys, file_team_keys, team_folders.
    # user_roles scoped to this team must be deleted explicitly.
    await db.execute(
        "DELETE FROM user_roles WHERE scope_type = 'team' AND scope_id = ?", (team_id,)
    )
    await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))

    # Delete the team's owned folders (cascades to files and file_team_keys)
    for fid in team_folder_ids:
        await db.execute("DELETE FROM folders WHERE id = ?", (fid,))

    await db.commit()
    logger.info("Team %s (%s) deleted by user %s", team.name, team_id, user.id)


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------

@router.get("/{team_id}/members")
async def list_members(
    team_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)
    members = await get_team_members(db, team_id)
    return {"members": [m.to_dict() for m in members]}


@router.post("/{team_id}/members", status_code=201)
async def invite_member(
    team_id: str,
    body: InviteMemberRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Invite a user to the team with a pre-wrapped copy of the team key.

    The caller must have already:
      1. Fetched the invitee's X25519 + ML-KEM-768 public keys.
      2. Wrapped sk_team for them using the hybrid KEM.
      3. Included the KEM outputs in this request body.
    """
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_SUPERVISOR)

    # Enforce member cap
    count = await get_team_member_count(db, team_id)
    if count >= TEAM_MAX_MEMBERS:
        raise HTTPException(status_code=422, detail=f"Team has reached the member limit ({TEAM_MAX_MEMBERS})")

    # Resolve invitee
    cursor = await db.execute(
        "SELECT id, x25519_public_key FROM users WHERE username = ? AND is_active = 1",
        (body.username,),
    )
    invitee = await cursor.fetchone()
    if not invitee:
        raise HTTPException(status_code=404, detail="User not found or inactive")

    invitee_id = invitee["id"]

    # Reject if invitee has no asymmetric keys registered
    if not invitee["x25519_public_key"]:
        raise HTTPException(
            status_code=422,
            detail="Invitee has not set up sharing keys yet — they must log in at least once"
        )

    # Reject if already a member
    existing = await get_team_member_role(db, team_id, invitee_id)
    if existing:
        raise HTTPException(status_code=409, detail="User is already a member of this team")

    ur_id  = str(uuid.uuid4())
    utk_id = str(uuid.uuid4())

    await db.execute(
        "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by) "
        "VALUES (?, ?, ?, 'team', ?, ?)",
        (ur_id, invitee_id, body.role, team_id, user.id),
    )
    await db.execute(
        "INSERT INTO user_team_keys "
        "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (utk_id, team_id, invitee_id, body.ephemeral_x25519_pub,
         body.kem_ciphertext, body.encrypted_sk, body.sk_iv),
    )
    await db.execute(
        "UPDATE teams SET updated_at = unixepoch() WHERE id = ?", (team_id,)
    )
    await db.commit()
    logger.info("User %s invited %s to team %s with role %s", user.id, invitee_id, team_id, body.role)
    return {"user_id": invitee_id}


@router.put("/{team_id}/members/{target_user_id}")
async def update_member_role(
    team_id: str,
    target_user_id: str,
    body: UpdateMemberRoleRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Change a member's role. Only owners may change roles."""
    team_id        = validate_uuid(team_id)
    target_user_id = validate_uuid(target_user_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_OWNER)

    if target_user_id == user.id:
        raise HTTPException(status_code=422, detail="Owner cannot change their own role")

    current_role = await get_team_member_role(db, team_id, target_user_id)
    if not current_role:
        raise HTTPException(status_code=404, detail="User is not a member of this team")
    if current_role == TEAM_ROLE_OWNER:
        raise HTTPException(status_code=422, detail="Cannot change the owner's role")

    await db.execute(
        "UPDATE user_roles SET role_id = ? "
        "WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (body.role, target_user_id, team_id),
    )
    await db.commit()
    return {"ok": True}


@router.delete("/{team_id}/members/{target_user_id}", status_code=204)
async def remove_member(
    team_id: str,
    target_user_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Remove a member from the team.

    Marks the team rotation_pending=1 and deletes the removed member's
    user_team_key entry so they can no longer decrypt new file keys.
    The owner must subsequently call POST /rotate to complete the rotation.
    """
    team_id        = validate_uuid(team_id)
    target_user_id = validate_uuid(target_user_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_SUPERVISOR)

    current_role = await get_team_member_role(db, team_id, target_user_id)
    if not current_role:
        raise HTTPException(status_code=404, detail="User is not a member of this team")
    if current_role == TEAM_ROLE_OWNER:
        raise HTTPException(status_code=422, detail="Cannot remove the team owner")

    # Supervisors can only remove members (not other supervisors)
    caller_role = await get_team_member_role(db, team_id, user.id)
    if caller_role == TEAM_ROLE_SUPERVISOR and current_role == TEAM_ROLE_SUPERVISOR:
        raise HTTPException(status_code=403, detail="Supervisors cannot remove other supervisors")

    await db.execute(
        "DELETE FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (target_user_id, team_id),
    )
    await db.execute(
        "DELETE FROM user_team_keys WHERE team_id = ? AND user_id = ?",
        (team_id, target_user_id),
    )
    # Flag rotation pending — existing file_team_keys are still decryptable with
    # the old sk_team, but the removed member's user_team_key has been deleted so
    # they cannot obtain the key. The owner should rotate to be safe.
    await db.execute(
        "UPDATE teams SET rotation_pending = 1, updated_at = unixepoch() WHERE id = ?",
        (team_id,),
    )
    await db.commit()
    logger.info("User %s removed member %s from team %s", user.id, target_user_id, team_id)


# ---------------------------------------------------------------------------
# My team key
# ---------------------------------------------------------------------------

@router.get("/{team_id}/my-key")
async def get_my_team_key(
    team_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Return the calling user's KEM-wrapped team key entry."""
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    cursor = await db.execute(
        "SELECT ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv "
        "FROM user_team_keys WHERE team_id = ? AND user_id = ?",
        (team_id, user.id),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Team key not found for this user")

    return {
        "ephemeral_x25519_pub": row["ephemeral_x25519_pub"],
        "kem_ciphertext": row["kem_ciphertext"],
        "encrypted_sk": row["encrypted_sk"],
        "sk_iv": row["sk_iv"],
    }


# ---------------------------------------------------------------------------
# Team folders
# ---------------------------------------------------------------------------

@router.get("/{team_id}/folders")
async def list_team_folders(
    team_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)
    folders = await get_team_folders(db, team_id)
    return {"folders": [f.to_dict() for f in folders]}


@router.post("/{team_id}/folders", status_code=201)
async def add_team_folder(
    team_id: str,
    body: AddTeamFolderRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Add a folder to the team. Caller must own the folder."""
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_SUPERVISOR)

    # Verify folder exists and caller owns it
    cursor = await db.execute(
        "SELECT id FROM folders WHERE id = ? AND owner_id = ?",
        (body.folder_id, user.id),
    )
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail="Folder not found or not owned by you")

    # Check for duplicate
    cursor = await db.execute(
        "SELECT 1 FROM team_folders WHERE team_id = ? AND folder_id = ?",
        (team_id, body.folder_id),
    )
    if await cursor.fetchone():
        raise HTTPException(status_code=409, detail="Folder is already in this team")

    tf_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO team_folders (id, team_id, folder_id, added_by) VALUES (?, ?, ?, ?)",
        (tf_id, team_id, body.folder_id, user.id),
    )
    await db.commit()
    return {"ok": True}


@router.delete("/{team_id}/folders/{folder_id}", status_code=204)
async def remove_team_folder(
    team_id: str,
    folder_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Remove a folder from the team."""
    team_id   = validate_uuid(team_id)
    folder_id = validate_uuid(folder_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_SUPERVISOR)

    await db.execute(
        "DELETE FROM team_folders WHERE team_id = ? AND folder_id = ?",
        (team_id, folder_id),
    )
    changes = await db.execute("SELECT changes()")
    row = await changes.fetchone()
    if row[0] == 0:
        raise HTTPException(status_code=404, detail="Folder is not in this team")
    await db.commit()


# ---------------------------------------------------------------------------
# File keys (PRE ciphertexts)
# ---------------------------------------------------------------------------

@router.get("/{team_id}/file-keys")
async def list_file_keys(
    team_id: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Return all PRE-encrypted file keys for the team.

    Members use these to decrypt team files after unwrapping sk_team via KEM.
    """
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    cursor = await db.execute(
        "SELECT team_id, file_id, pre_c1, encrypted_file_key, key_iv "
        "FROM file_team_keys WHERE team_id = ?",
        (team_id,),
    )
    rows = await cursor.fetchall()
    return {
        "file_keys": [
            TeamFileKey(
                team_id=r["team_id"],
                file_id=r["file_id"],
                pre_c1=r["pre_c1"],
                encrypted_file_key=r["encrypted_file_key"],
                key_iv=r["key_iv"],
            ).to_dict()
            for r in rows
        ]
    }


@router.post("/{team_id}/file-keys", status_code=201)
async def add_file_keys(
    team_id: str,
    body: AddFileKeysRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Add or replace PRE-encrypted file keys for the team.

    The caller must be a team member and must own the files (i.e., have uploaded
    them). Each file key is an INSERT OR REPLACE so this is idempotent.
    """
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    file_ids = [fk.file_id for fk in body.file_keys]

    # Verify all file_ids exist and belong to the caller
    # Build a parameterized IN clause
    placeholders = ",".join("?" for _ in file_ids)
    cursor = await db.execute(
        f"SELECT id FROM files WHERE id IN ({placeholders}) AND owner_id = ?",
        (*file_ids, user.id),
    )
    owned = {row["id"] for row in await cursor.fetchall()}
    missing = [fid for fid in file_ids if fid not in owned]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"Files not found or not owned by you: {missing[:5]}"
        )

    for fk in body.file_keys:
        fk_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO file_team_keys "
            "(id, team_id, file_id, pre_c1, encrypted_file_key, key_iv) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(team_id, file_id) DO UPDATE SET "
            "    pre_c1 = excluded.pre_c1, "
            "    encrypted_file_key = excluded.encrypted_file_key, "
            "    key_iv = excluded.key_iv",
            (fk_id, team_id, fk.file_id, fk.pre_c1, fk.encrypted_file_key, fk.key_iv),
        )

    await db.commit()
    return {"added": len(body.file_keys)}


# ---------------------------------------------------------------------------
# PRE key rotation
# ---------------------------------------------------------------------------

@router.post("/{team_id}/rotate")
async def rotate_team_keys(
    team_id: str,
    body: RotateKeysRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Apply a client-computed PRE key rotation.

    The team owner must:
      1. Fetch their user_team_keys entry (GET /my-key) and unwrap sk_old.
      2. Generate sk_new, pk_new = sk_new * G2.
      3. Compute rk = sk_old * inv(sk_new) mod BLS_ORDER.
      4. For each file_team_key: compute C1_new = rk * C1_old using @noble/curves.
      5. Wrap sk_new for each remaining member via hybrid KEM.
      6. Submit this endpoint with: pk_new, [{file_id, C1_new}], [{user_id, ...KEM}].

    The server validates structure and atomically commits. Rotation clears
    rotation_pending.
    """
    team_id = validate_uuid(team_id)
    team = await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_OWNER)

    # --- Validate file_ids belong to this team ---
    if body.file_keys:
        file_ids = [fk.file_id for fk in body.file_keys]
        placeholders = ",".join("?" for _ in file_ids)
        cursor = await db.execute(
            f"SELECT file_id FROM file_team_keys WHERE team_id = ? AND file_id IN ({placeholders})",
            (team_id, *file_ids),
        )
        found_ids = {row["file_id"] for row in await cursor.fetchall()}
        # All submitted file IDs must already exist in file_team_keys for this team
        unknown = [fid for fid in file_ids if fid not in found_ids]
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"file_ids not in this team's file_team_keys: {unknown[:5]}"
            )
        # Submitted set must cover the full current set (no partial rotation)
        cursor2 = await db.execute(
            "SELECT COUNT(*) FROM file_team_keys WHERE team_id = ?", (team_id,)
        )
        total_row = await cursor2.fetchone()
        if total_row[0] != len(file_ids):
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Rotation must include all {total_row[0]} file keys; "
                    f"submitted {len(file_ids)}"
                )
            )

    # --- Validate members match current (non-owner) members minus any removed ones ---
    submitted_user_ids = {m.user_id for m in body.members}

    # The requester (owner) must be in the members list
    if user.id not in submitted_user_ids:
        raise HTTPException(
            status_code=422,
            detail="Rotation members list must include the owner themselves"
        )

    # Every submitted user_id must currently be a member
    cursor = await db.execute(
        "SELECT user_id FROM user_roles WHERE scope_type = 'team' AND scope_id = ?",
        (team_id,),
    )
    current_member_ids = {row["user_id"] for row in await cursor.fetchall()}
    non_members = submitted_user_ids - current_member_ids
    if non_members:
        raise HTTPException(
            status_code=422,
            detail=f"Submitted members include non-members: {list(non_members)[:5]}"
        )

    # --- Atomically apply the rotation ---
    # 1. Update each C1
    for fk in body.file_keys:
        await db.execute(
            "UPDATE file_team_keys SET pre_c1 = ? WHERE team_id = ? AND file_id = ?",
            (fk.pre_c1, team_id, fk.file_id),
        )

    # 2. Replace all user_team_keys for this team
    await db.execute("DELETE FROM user_team_keys WHERE team_id = ?", (team_id,))
    for m in body.members:
        utk_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO user_team_keys "
            "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (utk_id, team_id, m.user_id, m.ephemeral_x25519_pub,
             m.kem_ciphertext, m.encrypted_sk, m.sk_iv),
        )

    # 3. Update team public key and clear rotation_pending
    await db.execute(
        "UPDATE teams SET pre_public_key = ?, rotation_pending = 0, updated_at = unixepoch() "
        "WHERE id = ?",
        (body.pre_public_key_new, team_id),
    )
    await db.commit()
    logger.info(
        "PRE rotation committed for team %s by owner %s (%d files, %d members)",
        team_id, user.id, len(body.file_keys), len(body.members),
    )
    return {"ok": True, "rotated_files": len(body.file_keys)}
