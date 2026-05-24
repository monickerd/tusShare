"""Team management routes.

Endpoints:
    POST   /api/v1/teams                                        create team
    GET    /api/v1/teams                                        list my teams
    GET    /api/v1/teams/{team_id}                              team detail + members + folders
    PUT    /api/v1/teams/{team_id}                              update name/description
    DELETE /api/v1/teams/{team_id}                              delete team (owner only)

    GET    /api/v1/teams/{team_id}/members                      list members
    POST   /api/v1/teams/{team_id}/members                      invite member
    PUT    /api/v1/teams/{team_id}/members/{user_id}            change role
    DELETE /api/v1/teams/{team_id}/members/{user_id}            remove member

    GET    /api/v1/teams/{team_id}/my-key                       get my wrapped team key

    GET    /api/v1/teams/{team_id}/folders                      list team folders
    POST   /api/v1/teams/{team_id}/folders                      add folder
    DELETE /api/v1/teams/{team_id}/folders/{folder_id}          remove folder

    GET    /api/v1/teams/{team_id}/file-keys                    list PRE file keys
    POST   /api/v1/teams/{team_id}/file-keys                    add/update PRE file keys (batch)

    POST   /api/v1/teams/{team_id}/rotate                       apply PRE key rotation (DLEQ-verified)
    POST   /api/v1/teams/{team_id}/key-confirmation             Schnorr PoK confirming sk_new

    GET    /api/v1/teams/escrow-agents                          list escrow agent users + public keys

    GET    /api/v1/teams/{team_id}/pending-key-grants           list unfulfilled policy grants
    POST   /api/v1/teams/{team_id}/pending-key-grants/complete  fulfil pending key grants

    POST   /api/v1/teams/{team_id}/ephemeral-slots              create one-time invite link slot
    GET    /api/v1/teams/{team_id}/ephemeral-slots/{slot_id}    fetch slot (does not consume)
    POST   /api/v1/teams/{team_id}/ephemeral-join               consume slot + rotate keys
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Annotated

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
from app.database import Database, DuplicateError, get_db
from app.middleware.rate_limit import check_management_rate_limit
from app.util.bls_verify import (
    verify_rk_consistency,
    verify_batch_dleq,
    verify_schnorr_pok,
)
from app.models.policy import get_blocking_policies
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
from app.routes._access import get_folder_team_id
from app.services import event_bus
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.util.db import get_admin_setting
from app.validation.sanitizers import (
    sanitize_team_name,
    sanitize_username,
    validate_base64,
    validate_g1_point,
    validate_g2_point,
    validate_uuid,
)

_ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/teams",
    tags=["teams"],
)

# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class _MemberKeyIn(BaseModel):
    """KEM-wrapped team key fields for a single escrow member."""
    user_id: str
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
    # E4b: optional pre-wrapped key slots for escrow agents.
    # Client fetches GET /teams/escrow-agents, wraps sk_team for each, and includes here.
    # Each entry must identify a user holding can_act_as_escrow.
    escrow_members: list[_MemberKeyIn] = []

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
        if v not in VALID_TEAM_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_TEAM_ROLES))}")
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
    """Updated C1 value for a single file after PRE rotation.

    dleq_s / dleq_R1 / dleq_R2 carry the Chaum-Pedersen DLEQ proof that the
    same scalar rk was used for rk_point = rk×G1 and C1_new = rk×C1_old.
    All three proof fields are required (DLEQ verification is active).
    """
    file_id: str
    pre_c1: str
    dleq_s:  str   # Fiat-Shamir response scalar (32 bytes), base64
    dleq_R1: str   # G1 commitment r×G1 (48 bytes), base64
    dleq_R2: str   # G1 commitment r×C1_old (48 bytes), base64

    @field_validator("file_id")
    @classmethod
    def validate_fid(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("pre_c1")
    @classmethod
    def validate_c1(cls, v: str) -> str:
        return validate_g1_point(v)

    @field_validator("dleq_s", "dleq_R1", "dleq_R2")
    @classmethod
    def validate_dleq_fields(cls, v: str) -> str:
        # dleq_s is a 32-byte scalar; dleq_R1 and dleq_R2 are 48-byte G1 points
        return validate_base64(v, max_length=68)


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

    Any team member performs all BLS12-381 scalar multiplications in the browser
    (using @noble/curves) and submits:
      - New G2 public key (sk_new * G2)
      - rk_point = rk × G1 (server-side pairing consistency check)
      - Every file_team_keys row with its updated C1 (= rk * C1_old) + DLEQ proof
      - New user_team_keys entries wrapping sk_new for each remaining member

    rk_point and per-file DLEQ proofs are optional in this prereq phase
    (accept-without-verify); DLEQ verification is active.
    """
    pre_public_key_new: str              # G2 point, base64 — pk_new
    rk_point: str                        # G1 point, base64 — rk × G1 (required)
    file_keys: list[_RotatedFileKeyIn]
    members: list[_RotatedMemberIn]

    @field_validator("pre_public_key_new")
    @classmethod
    def validate_pk(cls, v: str) -> str:
        return validate_g2_point(v)

    @field_validator("rk_point")
    @classmethod
    def validate_rk_point(cls, v: str) -> str:
        return validate_g1_point(v)

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
        raise HTTPException(status_code=404, detail="Team not found")  # NOSONAR — helper; 404 documented in callers
    return team


async def _require_team_role(db, team_id: str, user: AuthenticatedUser, min_role: str):
    """Raise 403 if the user does not hold at least min_role in the team."""
    role = await get_team_member_role(db, team_id, user.id)
    if role is None:
        raise HTTPException(status_code=403, detail="Not a member of this team")  # NOSONAR — helper; 403 documented in callers
    if _role_rank(role) > _role_rank(min_role):
        raise HTTPException(status_code=403, detail="Insufficient team role")  # NOSONAR — helper; 403 documented in callers
    return role


# ---------------------------------------------------------------------------
# Teams CRUD
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Escrow agents (E4b)
# ---------------------------------------------------------------------------

@router.get("/escrow-agents")
async def list_escrow_agents(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return all users holding the escrow_agent role with their public keys.

    Used by clients when creating a new team to pre-wrap sk_team for all
    escrow agents (so no pending grants are needed at team creation time).
    Returns only agents who have completed key setup (x25519 + mlkem public keys present).
    """
    cursor = await db.execute(
        "SELECT u.id, u.username, u.x25519_public_key, u.mlkem768_public_key "
        "FROM users u "
        "JOIN user_roles ur ON ur.user_id = u.id "
        "WHERE ur.role_id = 'escrow_agent' AND ur.scope_type IS NULL "
        "AND u.x25519_public_key IS NOT NULL AND u.mlkem768_public_key IS NOT NULL "
        "ORDER BY u.username",
    )
    rows = await cursor.fetchall()
    return {
        "escrow_agents": [
            {
                "user_id":            r["id"],
                "username":           r["username"],
                "x25519_public_key":  r["x25519_public_key"],
                "mlkem768_public_key": r["mlkem768_public_key"],
            }
            for r in rows
        ]
    }


@router.post("", status_code=201, responses={400: {"description": "Bad Request"}, 409: {"description": "Conflict"}, 422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def create_team(
    body: CreateTeamRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create a new team. Creator becomes team_owner automatically.

    If escrow_members are provided, each must identify a user with can_act_as_escrow.
    Their wrapped key slots and team_member roles are written immediately — no pending
    grants needed.
    """
    # Validate escrow_members before any writes
    for em in body.escrow_members:
        cursor = await db.execute(
            "SELECT 1 FROM user_roles ur "
            "JOIN role_permissions rp ON rp.role_id = ur.role_id "
            "WHERE ur.user_id = ? AND ur.scope_type IS NULL "
            "AND rp.flag = 'can_act_as_escrow' AND rp.value = '1'",
            (em.user_id,),
        )
        if not await cursor.fetchone():
            raise HTTPException(
                status_code=400,
                detail=f"User {em.user_id} does not have can_act_as_escrow permission",
            )

    # enforce escrow_require_coverage
    cov_val = await get_admin_setting(db, "escrow_require_coverage")
    if cov_val == "1" and not body.escrow_members:
        raise HTTPException(
            status_code=422,
            detail=(
                "escrow_require_coverage is enabled for this organisation. "
                "Call GET /folders/{id}/effective-escrow-agents, wrap sk_team for "
                "each returned agent, and include them in escrow_members."
            ),
        )

    team_id = str(uuid.uuid4())
    ur_id   = str(uuid.uuid4())
    utk_id  = str(uuid.uuid4())

    try:
        await db.execute(
            "INSERT INTO teams (id, name, description, owner_id, pre_public_key) "
            "VALUES (?, ?, ?, ?, ?)",
            (team_id, body.name, body.description, user.id, body.pre_public_key),
        )
    except DuplicateError:
        raise HTTPException(status_code=409, detail="A team with this name already exists")
    # Grant team_owner role (scoped)
    await db.execute(
        "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by) "
        "VALUES (?, ?, 'team_admin', 'team', ?, ?)",
        (ur_id, user.id, team_id, user.id),
    )
    # Store owner's wrapped team key — key_confirmed=1 immediately: creator just generated the key
    await db.execute(
        "INSERT INTO user_team_keys "
        "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv, key_confirmed) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        (utk_id, team_id, user.id, body.ephemeral_x25519_pub,
         body.kem_ciphertext, body.encrypted_sk, body.sk_iv),
    )
    # E4b: write escrow agent key slots and team membership if provided
    for em in body.escrow_members:
        ea_ur_id  = str(uuid.uuid4())
        ea_utk_id = str(uuid.uuid4())
        # Grant team_member role to escrow agent
        await db.execute(
            "INSERT INTO user_roles "
            "(id, user_id, role_id, scope_type, scope_id, granted_by) "
            "VALUES (?, ?, 'team_member', 'team', ?, ?) "
            "ON CONFLICT DO NOTHING",
            (ea_ur_id, em.user_id, team_id, user.id),
        )
        # Write escrow agent's wrapped key slot (key_confirmed starts at 0)
        await db.execute(
            "INSERT INTO user_team_keys "
            "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv, key_confirmed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0) "
            "ON CONFLICT DO NOTHING",
            (ea_utk_id, team_id, em.user_id,
             em.ephemeral_x25519_pub, em.kem_ciphertext, em.encrypted_sk, em.sk_iv),
        )
    # Auto-create the team's shared folder and register it
    folder_id = str(uuid.uuid4())
    tf_id     = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO folders (id, name, parent_id, owner_id) VALUES (?, ?, NULL, ?)",
            (folder_id, body.name, user.id),
        )
    except DuplicateError:
        raise HTTPException(status_code=409, detail="A folder with this team name already exists")
    await db.execute(
        "INSERT INTO team_folders (id, team_id, folder_id, added_by) VALUES (?, ?, ?, ?)",
        (tf_id, team_id, folder_id, user.id),
    )
    await db.commit()
    logger.info(  # NOSONAR — server-side audit log; values are Pydantic-validated
        "Team %s (%s) created by user %s (escrow_members=%d)",
        body.name, team_id, user.id, len(body.escrow_members),
    )
    event_bus.emit(SecurityEvent(
        event_type="admin.team.created",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        target=EventTarget(type="team", id=team_id, name=body.name),
        detail={"escrow_member_count": len(body.escrow_members)},
    ))
    return {"team_id": team_id, "folder_id": folder_id}


@router.get("")
async def list_my_teams(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all teams the authenticated user belongs to."""
    teams = await get_user_teams(db, user.id)
    return {"teams": teams}


@router.get("/{team_id}")
async def get_team_detail(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return team details including members and folders."""
    team_id = validate_uuid(team_id)
    team = await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    members = await get_team_members(db, team_id)
    folders = await get_team_folders(db, team_id)

    allow_multi_owner = (await get_admin_setting(db, "allow_multi_team_owner")) == "true"

    return {
        "team": team.to_dict(),
        "members": [m.to_dict() for m in members],
        "folders": [f.to_dict() for f in folders],
        "allow_multi_team_owner": allow_multi_owner,
    }


@router.put("/{team_id}", responses={409: {"description": "Conflict"}, 422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def update_team(
    team_id: str,
    body: UpdateTeamRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
            "UPDATE teams SET name = ?, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
            (body.name, team_id),
        )

    if body.description is not None:
        await db.execute(
            "UPDATE teams SET description = ?, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
            (body.description, team_id),
        )

    await db.commit()
    return {"ok": True}


@router.delete("/{team_id}", status_code=204, dependencies=[Depends(check_management_rate_limit)])
async def delete_team(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
    logger.info("Team %s (%s) deleted by user %s", team.name, team_id, user.id)  # NOSONAR — server-side audit log; values are Pydantic-validated
    event_bus.emit(SecurityEvent(
        event_type="admin.team.deleted",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        target=EventTarget(type="team", id=team_id, name=team.name),
    ))


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------

@router.get("/{team_id}/members")
async def list_members(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)
    members = await get_team_members(db, team_id)
    return {"members": [m.to_dict() for m in members]}


@router.post("/{team_id}/members", status_code=201, responses={404: {"description": "Not Found"}, 409: {"description": "Conflict"}, 422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def invite_member(
    team_id: str,
    body: InviteMemberRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
        "UPDATE teams SET updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?", (team_id,)
    )
    await db.commit()
    logger.info("User %s invited %s to team %s with role %s", user.id, invitee_id, team_id, body.role)  # NOSONAR — server-side audit log; values are Pydantic-validated
    event_bus.emit(SecurityEvent(
        event_type="admin.team.member_added",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        target=EventTarget(type="team", id=team_id),
        detail={"target_user_id": invitee_id, "role": body.role},
    ))
    return {"user_id": invitee_id}


@router.put("/{team_id}/members/{target_user_id}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}, 422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def update_member_role(
    team_id: str,
    target_user_id: str,
    body: UpdateMemberRoleRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Change a member's role. Only owners may change roles.

    Promoting to team_admin requires the allow_multi_team_owner admin setting.
    Demoting an existing team_admin is allowed only when another owner remains.
    """
    team_id        = validate_uuid(team_id)
    target_user_id = validate_uuid(target_user_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_OWNER)

    if target_user_id == user.id:
        raise HTTPException(status_code=422, detail="Cannot change your own role")

    current_role = await get_team_member_role(db, team_id, target_user_id)
    if not current_role:
        raise HTTPException(status_code=404, detail="User is not a member of this team")

    # Promoting to owner requires the admin flag
    if body.role == TEAM_ROLE_OWNER:
        if (await get_admin_setting(db, "allow_multi_team_owner")) != "true":
            raise HTTPException(
                status_code=403,
                detail="Multi-owner teams are not enabled by the administrator",
            )

    # Demoting an existing owner is only allowed if another owner will remain
    if current_role == TEAM_ROLE_OWNER and body.role != TEAM_ROLE_OWNER:
        cnt_cur = await db.execute(
            "SELECT COUNT(*) AS cnt FROM user_roles "
            "WHERE scope_type = 'team' AND scope_id = ? AND role_id = ?",
            (team_id, TEAM_ROLE_OWNER),
        )
        cnt_row = await cnt_cur.fetchone()
        owner_count = cnt_row["cnt"] if cnt_row else 1
        if owner_count <= 1:
            raise HTTPException(
                status_code=422,
                detail="Cannot demote the only owner — promote another member first",
            )

    blocks = await get_blocking_policies(db, target_user_id, team_id)
    if blocks:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "This member's role is assigned by a policy. Create a policy exemption for this user before changing their role manually.",
                "blocked_by": blocks,
            },
        )

    await db.execute(
        "UPDATE user_roles SET role_id = ? "
        "WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (body.role, target_user_id, team_id),
    )
    await db.commit()
    logger.info(  # NOSONAR — server-side audit log; values are Pydantic-validated
        "User %s changed role of %s in team %s: %s → %s",
        user.id, target_user_id, team_id, current_role, body.role,
    )
    return {"ok": True}


@router.delete("/{team_id}/members/{target_user_id}", status_code=204, responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}, 422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def remove_member(
    team_id: str,
    target_user_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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

    blocks = await get_blocking_policies(db, target_user_id, team_id)
    if blocks:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "This membership is enforced by a policy. Create a policy exemption for this user before removing them.",
                "blocked_by": blocks,
            },
        )

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
        "UPDATE teams SET rotation_pending = 1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
        (team_id,),
    )
    await db.commit()
    logger.info("User %s removed member %s from team %s", user.id, target_user_id, team_id)  # NOSONAR — server-side audit log; values are Pydantic-validated
    event_bus.emit(SecurityEvent(
        event_type="admin.team.member_removed",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        target=EventTarget(type="team", id=team_id),
        detail={"target_user_id": target_user_id, "removed_role": current_role},
    ))


# ---------------------------------------------------------------------------
# My team key
# ---------------------------------------------------------------------------

@router.get("/{team_id}/my-key", responses={404: {"description": "Not Found"}})
async def get_my_team_key(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)
    folders = await get_team_folders(db, team_id)
    return {"folders": [f.to_dict() for f in folders]}


@router.post("/{team_id}/folders", status_code=201, responses={404: {"description": "Not Found"}, 409: {"description": "Conflict"}}, dependencies=[Depends(check_management_rate_limit)])
async def add_team_folder(
    team_id: str,
    body: AddTeamFolderRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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


@router.delete("/{team_id}/folders/{folder_id}", status_code=204, responses={404: {"description": "Not Found"}}, dependencies=[Depends(check_management_rate_limit)])
async def remove_team_folder(
    team_id: str,
    folder_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Remove a folder from the team."""
    team_id   = validate_uuid(team_id)
    folder_id = validate_uuid(folder_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_SUPERVISOR)

    result = await db.execute(
        "DELETE FROM team_folders WHERE team_id = ? AND folder_id = ? RETURNING id",
        (team_id, folder_id),
    )
    if await result.fetchone() is None:
        raise HTTPException(status_code=404, detail="Folder is not in this team")
    await db.commit()


# ---------------------------------------------------------------------------
# File keys (PRE ciphertexts)
# ---------------------------------------------------------------------------

@router.get("/{team_id}/file-keys")
async def list_file_keys(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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


@router.post("/{team_id}/file-keys", status_code=201, responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}})
async def add_file_keys(
    team_id: str,
    body: AddFileKeysRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Add or replace PRE-encrypted file keys for the team.

    The caller must be a team member and must own the files (i.e., have uploaded
    them). Each file key upserts via ON CONFLICT DO UPDATE so this is idempotent.
    """
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    file_ids = [fk.file_id for fk in body.file_keys]

    # Verify all file_ids exist, belong to the caller, and are in this team's folder tree
    placeholders = ",".join("?" for _ in file_ids)
    cursor = await db.execute(
        f"SELECT id, folder_id FROM files WHERE id IN ({placeholders}) AND owner_id = ?",
        (*file_ids, user.id),
    )
    owned_map = {row["id"]: row["folder_id"] for row in await cursor.fetchall()}
    missing = [fid for fid in file_ids if fid not in owned_map]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"Files not found or not owned by you: {missing[:5]}"
        )

    for fk in body.file_keys:
        file_folder_id = owned_map.get(fk.file_id)
        if not file_folder_id:
            raise HTTPException(
                status_code=400,
                detail=f"File {fk.file_id} is not in a team folder",
            )
        actual_team = await get_folder_team_id(db, file_folder_id)
        if actual_team != team_id:
            raise HTTPException(
                status_code=400,
                detail=f"File {fk.file_id} is not in this team's folder",
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

async def _require_all_members_confirmed(db, team_id: str) -> None:
    """Raise 422 if any interactive team member has not yet confirmed their current key.

    Escrow agents are system accounts that never submit Schnorr PoKs and are excluded
    from this check (identified by the global escrow_agent role with scope_type IS NULL).
    Rotating before all members have confirmed risks compounding a broken key slot.
    """
    cursor = await db.execute(
        "SELECT COUNT(*) FROM user_team_keys utk "
        "WHERE utk.team_id = ? "
        "  AND utk.key_confirmed = 0 "
        "  AND NOT EXISTS ("
        "    SELECT 1 FROM user_roles ur "
        "    WHERE ur.user_id = utk.user_id "
        "      AND ur.role_id = 'escrow_agent' "
        "      AND ur.scope_type IS NULL"
        "  )",
        (team_id,),
    )
    unconfirmed = (await cursor.fetchone())[0]
    if unconfirmed > 0:
        raise HTTPException(
            status_code=422,
            detail=f"{unconfirmed} member(s) have not yet confirmed their current team key; rotation blocked",
        )


async def _validate_escrow_coverage(db, submitted_user_ids: set) -> None:
    """Raise 422 if escrow_require_coverage is enabled and no escrow agent is in the rotation."""
    cov_val = await get_admin_setting(db, "escrow_require_coverage")
    if cov_val != "1":
        return
    raw_user_ids = await get_admin_setting(db, "escrow_default_user_ids")
    raw_role_ids = await get_admin_setting(db, "escrow_default_role_ids")
    escrow_user_ids: set[str] = set(json.loads(raw_user_ids or "[]"))
    role_ids: list[str] = json.loads(raw_role_ids or "[]")
    if role_ids:
        ph = ",".join("?" for _ in role_ids)
        cursor = await db.execute(
            f"SELECT DISTINCT user_id FROM user_roles "
            f"WHERE role_id IN ({ph}) AND scope_type IS NULL",
            role_ids,
        )
        for row in await cursor.fetchall():
            escrow_user_ids.add(row["user_id"])
    if escrow_user_ids and not (submitted_user_ids & escrow_user_ids):
        raise HTTPException(
            status_code=422,
            detail=(
                "escrow_require_coverage is enabled. Rotation must include at least "
                f"one configured escrow agent: {list(escrow_user_ids)[:5]}"
            ),
        )


async def _validate_rotation_inputs(db, team_id: str, user, body) -> None:
    """Validate file_keys and member list for a PRE key rotation."""
    if body.file_keys:
        file_ids = [fk.file_id for fk in body.file_keys]
        placeholders = ",".join("?" for _ in file_ids)
        cursor = await db.execute(
            f"SELECT file_id FROM file_team_keys WHERE team_id = ? AND file_id IN ({placeholders})",
            (team_id, *file_ids),
        )
        found_ids = {row["file_id"] for row in await cursor.fetchall()}
        unknown = [fid for fid in file_ids if fid not in found_ids]
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"file_ids not in this team's file_team_keys: {unknown[:5]}"
            )
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

    submitted_user_ids = {m.user_id for m in body.members}
    if user.id not in submitted_user_ids:
        raise HTTPException(
            status_code=422,
            detail="Rotation members list must include the requesting user"
        )

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

    missing = current_member_ids - submitted_user_ids
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Rotation must cover all current members: {list(missing)[:5]}"
        )

    await _validate_escrow_coverage(db, submitted_user_ids)
    await _require_all_members_confirmed(db, team_id)


@router.post("/{team_id}/rotate", responses={422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def rotate_team_keys(
    team_id: str,
    body: RotateKeysRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Apply a client-computed PRE key rotation.

    Any team member may execute the rotation (permission dropped from owner-only
    to member — DLEQ verification is the safety gate, not the role).

      1. Fetch their user_team_keys entry (GET /my-key) and unwrap sk_old.
      2. Generate sk_new, pk_new = sk_new * G2; compute rk = sk_old * inv(sk_new).
      3. For each file_team_key: compute C1_new = rk * C1_old; generate DLEQ proof.
      4. Wrap sk_new for each remaining member via hybrid KEM.
      5. Submit with: pk_new, rk_point, [{file_id, C1_new, dleq_*}], [{user_id, ...KEM}].

    The server validates structure and atomically commits. Rotation clears
    rotation_pending.
    """
    team_id = validate_uuid(team_id)
    team = await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)
    await _validate_rotation_inputs(db, team_id, user, body)

    # --- DLEQ / rk_consistency verification ---
    # Fetch current C1 values from DB so we can pass c1_old to DLEQ proofs.
    old_c1_map: dict[str, str] = {}
    if body.file_keys:
        file_ids = [fk.file_id for fk in body.file_keys]
        placeholders2 = ",".join("?" for _ in file_ids)
        cursor3 = await db.execute(
            f"SELECT file_id, pre_c1 FROM file_team_keys "
            f"WHERE team_id = ? AND file_id IN ({placeholders2})",
            (team_id, *file_ids),
        )
        for row in await cursor3.fetchall():
            old_c1_map[row["file_id"]] = row["pre_c1"]

    # Pairing check: e(rk_point, pk_new) == e(G1, pk_old)
    if not verify_rk_consistency(body.rk_point, team.pre_public_key, body.pre_public_key_new):
        raise HTTPException(status_code=422, detail="rk_point pairing consistency check failed")

    # Per-file DLEQ check
    if body.file_keys:
        dleq_inputs = [
            {
                "rk_point": body.rk_point,
                "c1_old":   old_c1_map[fk.file_id],
                "c1_new":   fk.pre_c1,
                "dleq_s":   fk.dleq_s,
                "dleq_r1":  fk.dleq_R1,
                "dleq_r2":  fk.dleq_R2,
            }
            for fk in body.file_keys
        ]
        if not verify_batch_dleq(dleq_inputs):
            raise HTTPException(status_code=422, detail="DLEQ proof verification failed")

    event_bus.emit(SecurityEvent(
        event_type="admin.team_key.rotation_started",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        target=EventTarget(type="team", id=team_id),
        detail={"file_count": len(body.file_keys), "member_count": len(body.members)},
    ))

    # --- Atomically apply the rotation ---
    # 1. Update each C1
    for fk in body.file_keys:
        await db.execute(
            "UPDATE file_team_keys SET pre_c1 = ? WHERE team_id = ? AND file_id = ?",
            (fk.pre_c1, team_id, fk.file_id),
        )

    # 2. Replace all user_team_keys for this team.
    #    key_confirmed resets to 0 — members submit Schnorr PoK on next login.
    await db.execute("DELETE FROM user_team_keys WHERE team_id = ?", (team_id,))
    for m in body.members:
        utk_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO user_team_keys "
            "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv, key_confirmed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (utk_id, team_id, m.user_id, m.ephemeral_x25519_pub,
             m.kem_ciphertext, m.encrypted_sk, m.sk_iv),
        )

    # 3. Update team public key and clear rotation_pending
    await db.execute(
        "UPDATE teams SET pre_public_key = ?, rotation_pending = 0, "
        "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
        (body.pre_public_key_new, team_id),
    )
    await db.commit()
    logger.info(  # NOSONAR — server-side audit log; values are Pydantic-validated
        "PRE rotation committed for team %s by user %s (%d files, %d members)",
        team_id, user.id, len(body.file_keys), len(body.members),
    )
    event_bus.emit(SecurityEvent(
        event_type="admin.team_key.rotation_completed",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=str(user.id), username=user.username),
        target=EventTarget(type="team", id=team_id),
        detail={"file_count": len(body.file_keys), "member_count": len(body.members)},
    ))

    # Detect policy-enrolled members omitted from the rotation payload.
    # Their user_team_keys were wiped by the rotation; mark grants as needing re-wrap.
    submitted_ids = {m.user_id for m in body.members}
    cursor = await db.execute(
        "SELECT DISTINCT user_id FROM user_roles "
        "WHERE scope_type = 'team' AND scope_id = ? AND policy_effect_id IS NOT NULL",
        (team_id,),
    )
    policy_member_ids = {r["user_id"] for r in await cursor.fetchall()}
    omitted = policy_member_ids - submitted_ids
    if omitted:
        for uid in omitted:
            await db.execute(
                "UPDATE policy_team_grants SET key_wrapped = 0 "
                "WHERE user_id = ? AND effect_id IN "
                "(SELECT id FROM policy_effects WHERE target_id = ?)",
                (uid, team_id),
            )
        await db.commit()
        return {
            "ok": True,
            "rotated_files": len(body.file_keys),
            "warning": f"{len(omitted)} policy-enrolled member(s) were not included in this rotation and will need their keys re-wrapped at next login.",
            "policy_members_omitted": list(omitted),
        }

    return {"ok": True, "rotated_files": len(body.file_keys)}


# ---------------------------------------------------------------------------
# Key confirmation (Schnorr PoK)
# ---------------------------------------------------------------------------

class KeyConfirmationRequest(BaseModel):
    """Schnorr PoK proving the caller holds sk_new after a rotation.

    Member computes: r = random; R = r × G2; c = Hash(pk_new, R); s = r - c × sk_new
    Server verifies:  s × G2 + c × pk_new == R
    """
    schnorr_R: str   # G2 point, base64
    schnorr_s: str   # scalar, base64

    @field_validator("schnorr_R")
    @classmethod
    def validate_R(cls, v: str) -> str:
        return validate_g2_point(v)

    @field_validator("schnorr_s")
    @classmethod
    def validate_s(cls, v: str) -> str:
        return validate_base64(v, max_length=60)


@router.post("/{team_id}/key-confirmation", responses={422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def confirm_team_key(
    team_id: str,
    body: KeyConfirmationRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Record that the caller has successfully decrypted their post-rotation team key.

    The member submits a Schnorr PoK proving they hold sk_new such that
    pk_new = sk_new × G2 matches the team's current pre_public_key.  On success
    the server sets user_team_keys.key_confirmed = 1 for this (team, user) pair.

    This is called automatically by the login background hook (_processPendingTeamOperations)
    for any team where my_key_confirmed = 0.
    """
    team_id = validate_uuid(team_id)
    team = await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    # Verify Schnorr PoK: s × G2 + c × pk_new == R  (c = SHA-256(pk_new ‖ R) mod Fr)
    if not verify_schnorr_pok(body.schnorr_R, body.schnorr_s, team.pre_public_key):
        raise HTTPException(status_code=422, detail="Invalid Schnorr PoK")

    await db.execute(
        "UPDATE user_team_keys SET key_confirmed = 1 WHERE team_id = ? AND user_id = ?",
        (team_id, user.id),
    )
    await db.commit()
    logger.info("Key confirmation accepted for user %s in team %s", user.id, team_id)  # NOSONAR — server-side audit log; values are Pydantic-validated
    return {"ok": True}


# ---------------------------------------------------------------------------
# E4a — Pending key grants (policy-granted members awaiting sk_team delivery)
# ---------------------------------------------------------------------------

class _CompleteKeyGrantIn(BaseModel):
    """Wrapped sk_team for a single policy-granted user."""
    grant_id: str
    user_id: str
    ephemeral_x25519_pub: str
    kem_ciphertext: str
    encrypted_sk: str
    sk_iv: str

    @field_validator("grant_id", "user_id")
    @classmethod
    def validate_ids(cls, v: str) -> str:
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


class CompleteKeyGrantsRequest(BaseModel):
    grants: list[_CompleteKeyGrantIn]

    @field_validator("grants")
    @classmethod
    def validate_grants(cls, v: list) -> list:
        if not v:
            raise ValueError("grants list must not be empty")
        if len(v) > TEAM_MAX_MEMBERS:
            raise ValueError(f"Cannot complete more than {TEAM_MAX_MEMBERS} grants at once")
        return v


@router.get("/{team_id}/pending-key-grants")
async def get_pending_key_grants(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return users waiting for sk_team delivery (policy_team_grants.key_wrapped=0).

    Called by the login background hook to discover who needs the team key
    wrapped for them.  Only returns users who have asymmetric keys registered;
    users with no public keys are silently skipped (retried on the next login).

    Requires existing team membership.
    """
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    cursor = await db.execute(
        "SELECT ptg.id AS grant_id, ptg.user_id, "
        "       u.x25519_public_key, u.mlkem768_public_key "
        "FROM policy_team_grants ptg "
        "JOIN policy_effects pe ON pe.id = ptg.effect_id "
        "JOIN users u ON u.id = ptg.user_id "
        "WHERE pe.target_id = ? AND ptg.key_wrapped = 0 AND u.is_active = 1",
        (team_id,),
    )
    rows = await cursor.fetchall()

    pending = []
    for r in rows:
        if not r["x25519_public_key"] or not r["mlkem768_public_key"]:
            # User hasn't completed key setup yet — skip, will be retried
            continue
        pending.append({
            "grant_id":            r["grant_id"],
            "user_id":             r["user_id"],
            "x25519_public_key":   r["x25519_public_key"],
            "mlkem768_public_key": r["mlkem768_public_key"],
        })

    return {"pending_grants": pending}


@router.post("/{team_id}/pending-key-grants/complete", status_code=201, responses={422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def complete_pending_key_grants(
    team_id: str,
    body: CompleteKeyGrantsRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Fulfil pending key grants by writing user_team_keys for each grantee.

    The caller (an existing team member) has already:
      1. Unwrapped their own sk_team via GET /my-key.
      2. For each pending grant, wrapped sk_team for the grantee's public keys.

    This endpoint atomically:
      - Inserts user_team_keys rows (ON CONFLICT DO NOTHING if a manual invite
        already gave them access).
      - Sets policy_team_grants.key_wrapped = 1 for each grant_id.
    """
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_MEMBER)

    # Verify all grant_ids belong to this team and are still pending
    grant_ids = [g.grant_id for g in body.grants]
    placeholders = ",".join("?" for _ in grant_ids)
    cursor = await db.execute(
        f"SELECT ptg.id, ptg.user_id FROM policy_team_grants ptg "
        f"JOIN policy_effects pe ON pe.id = ptg.effect_id "
        f"WHERE ptg.id IN ({placeholders}) AND pe.target_id = ? AND ptg.key_wrapped = 0",
        (*grant_ids, team_id),
    )
    grant_user_map: dict[str, str] = {}
    for row in await cursor.fetchall():
        grant_user_map[row["id"]] = row["user_id"]
    invalid = [gid for gid in grant_ids if gid not in grant_user_map]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid or already-fulfilled grant IDs: {invalid[:5]}"
        )

    # Cross-validate that each submitted user_id matches the grant's recorded recipient
    for g in body.grants:
        if grant_user_map[g.grant_id] != g.user_id:
            raise HTTPException(
                status_code=422,
                detail=f"grant_id {g.grant_id} does not belong to user {g.user_id}",
            )

    fulfilled = 0
    for g in body.grants:
        # ON CONFLICT DO NOTHING: if a manual invite already gave them a key slot,
        # leave it in place and just mark the policy grant as fulfilled.
        utk_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO user_team_keys "
            "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(team_id, user_id) DO NOTHING",
            (utk_id, team_id, g.user_id, g.ephemeral_x25519_pub,
             g.kem_ciphertext, g.encrypted_sk, g.sk_iv),
        )
        await db.execute(
            "UPDATE policy_team_grants SET key_wrapped = 1 WHERE id = ?",
            (g.grant_id,),
        )
        fulfilled += 1

    await db.commit()
    logger.info(  # NOSONAR — server-side audit log; values are Pydantic-validated
        "User %s fulfilled %d pending key grant(s) for team %s",
        user.id, fulfilled, team_id,
    )
    return {"fulfilled": fulfilled}


# ---------------------------------------------------------------------------
# E4c — Ephemeral invite slots
# ---------------------------------------------------------------------------

# Default slot lifetime in hours (configurable per-request up to this cap)
_EPHEMERAL_SLOT_MAX_HOURS = 72
_EPHEMERAL_SLOT_DEFAULT_HOURS = 24


class CreateEphemeralSlotRequest(BaseModel):
    """Admin creates a one-time invite slot.

    sk_wrapped = AES-GCM-256(k_ephemeral, sk_team_bytes)
    k_ephemeral is a 256-bit key kept only in the invite link fragment — never stored.
    """
    sk_wrapped:   str   # AES-GCM ciphertext of sk_team (48 bytes w/ tag → 64 base64 chars)
    sk_iv:        str   # AES-GCM IV (12 bytes)
    expires_hours: int = _EPHEMERAL_SLOT_DEFAULT_HOURS  # link lifetime

    @field_validator("sk_wrapped")
    @classmethod
    def validate_sk_wrapped(cls, v: str) -> str:
        return validate_base64(v, max_length=68)

    @field_validator("sk_iv")
    @classmethod
    def validate_sk_iv(cls, v: str) -> str:
        return validate_base64(v, max_length=20)

    @field_validator("expires_hours")
    @classmethod
    def validate_expires(cls, v: int) -> int:
        if v < 1 or v > _EPHEMERAL_SLOT_MAX_HOURS:
            raise ValueError(f"expires_hours must be between 1 and {_EPHEMERAL_SLOT_MAX_HOURS}")
        return v


class EphemeralJoinRequest(BaseModel):
    """New member completes join via ephemeral slot + immediate rotation.

    After fetching and decrypting the slot, the joining member:
      1. Generates sk_new / pk_new.
      2. Re-encrypts all file C1s with rk = sk_old * inv(sk_new).
      3. Wraps sk_new for every current member including themselves.
      4. Submits this payload atomically alongside slot_id so the server can
         consume the slot and commit all key material in one transaction.
    """
    slot_id:           str
    pre_public_key_new: str                # G2 point, base64 — pk_new
    rk_point:           str                # G1 point, base64 — rk × G1
    file_keys:          list[_RotatedFileKeyIn]
    members:            list[_RotatedMemberIn]

    @field_validator("slot_id")
    @classmethod
    def validate_slot(cls, v: str) -> str:
        return validate_uuid(v)

    @field_validator("pre_public_key_new")
    @classmethod
    def validate_pk(cls, v: str) -> str:
        return validate_g2_point(v)

    @field_validator("rk_point")
    @classmethod
    def validate_rk(cls, v: str) -> str:
        return validate_g1_point(v)

    @field_validator("members")
    @classmethod
    def validate_members(cls, v: list) -> list:
        if not v:
            raise ValueError("members list must not be empty after join rotation")
        return v


@router.post("/{team_id}/ephemeral-slots", status_code=201, responses={403: {"description": "Forbidden"}}, dependencies=[Depends(check_management_rate_limit)])
async def create_ephemeral_slot(
    team_id: str,
    body: CreateEphemeralSlotRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create a one-time invite slot for a new team member.

    The admin client:
      1. Unwraps their sk_team.
      2. Generates k_ephemeral (256-bit, stays in browser/link only).
      3. Computes sk_wrapped = AES-GCM(k_ephemeral, sk_team_bytes).
      4. Submits sk_wrapped + sk_iv here.
      5. Returns slot_id to the admin, who constructs:
           #/join/{team_id}/{slot_id}/{k_ephemeral_b64url}

    Requires supervisor role.  The allow_ephemeral_team_invites admin setting
    is checked before creating a slot.
    """
    team_id = validate_uuid(team_id)
    await _get_team_or_404(db, team_id)
    await _require_team_role(db, team_id, user, TEAM_ROLE_SUPERVISOR)

    # Check org setting
    if (await get_admin_setting(db, "allow_ephemeral_team_invites")) != "true":
        raise HTTPException(
            status_code=403,
            detail="Ephemeral team invite links are disabled. "
                   "Enable allow_ephemeral_team_invites in admin settings."
        )

    slot_id    = str(uuid.uuid4())
    now        = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=body.expires_hours)).strftime(_ISO_FMT)
    created_at = now.strftime(_ISO_FMT)

    await db.execute(
        "INSERT INTO team_ephemeral_slots "
        "(id, team_id, sk_wrapped, sk_iv, created_by, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (slot_id, team_id, body.sk_wrapped, body.sk_iv, user.id, created_at, expires_at),
    )
    await db.commit()
    logger.info(  # NOSONAR — server-side audit log; values are Pydantic-validated
        "Ephemeral slot %s created for team %s by user %s (expires %s)",
        slot_id, team_id, user.id, expires_at,
    )
    return {"slot_id": slot_id, "expires_at": expires_at}


@router.get("/{team_id}/ephemeral-slots/{slot_id}", responses={404: {"description": "Not Found"}, 410: {"description": "Gone"}})
async def get_ephemeral_slot(
    team_id: str,
    slot_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Fetch a slot's wrapped sk_team blob without consuming the slot.

    The joining client decrypts with k_ephemeral from the URL fragment, then
    immediately calls POST /ephemeral-join which rotates keys and consumes the slot.

    Does NOT require existing team membership (the joining user is not a member yet).
    """
    team_id = validate_uuid(team_id)
    slot_id = validate_uuid(slot_id)
    await _get_team_or_404(db, team_id)

    cursor = await db.execute(
        "SELECT sk_wrapped, sk_iv, expires_at, consumed "
        "FROM team_ephemeral_slots WHERE id = ? AND team_id = ?",
        (slot_id, team_id),
    )
    slot = await cursor.fetchone()
    if not slot:
        raise HTTPException(status_code=404, detail="Invite slot not found")
    if slot["consumed"]:
        raise HTTPException(status_code=410, detail="Invite slot has already been used")

    now_str = datetime.now(timezone.utc).strftime(_ISO_FMT)
    if slot["expires_at"] < now_str:
        raise HTTPException(status_code=410, detail="Invite slot has expired")

    return {"sk_wrapped": slot["sk_wrapped"], "sk_iv": slot["sk_iv"]}


async def _load_valid_slot(db, team_id: str, slot_id: str):
    """Fetch an ephemeral slot and raise 404/410 if invalid, consumed, or expired."""
    cursor = await db.execute(
        "SELECT expires_at, consumed FROM team_ephemeral_slots WHERE id = ? AND team_id = ?",
        (slot_id, team_id),
    )
    slot = await cursor.fetchone()
    if not slot:
        raise HTTPException(status_code=404, detail="Invite slot not found")
    if slot["consumed"]:
        raise HTTPException(status_code=410, detail="Invite slot has already been used")
    now_str = datetime.now(timezone.utc).strftime(_ISO_FMT)
    if slot["expires_at"] < now_str:
        raise HTTPException(status_code=410, detail="Invite slot has expired")


async def _validate_join_file_keys(db, team_id: str, body) -> None:
    """Verify submitted file_keys cover exactly the team's current file_team_keys."""
    if not body.file_keys:
        return
    file_ids = [fk.file_id for fk in body.file_keys]
    ph = ",".join("?" for _ in file_ids)
    c2 = await db.execute(
        f"SELECT COUNT(*) FROM file_team_keys WHERE team_id = ? AND file_id IN ({ph})",
        (team_id, *file_ids),
    )
    if (await c2.fetchone())[0] != len(file_ids):
        raise HTTPException(status_code=422, detail="file_ids mismatch for this team")
    c3 = await db.execute(
        "SELECT COUNT(*) FROM file_team_keys WHERE team_id = ?", (team_id,)
    )
    if (await c3.fetchone())[0] != len(file_ids):
        raise HTTPException(status_code=422, detail="Rotation must include all file keys")


@router.post("/{team_id}/ephemeral-join", status_code=201, responses={404: {"description": "Not Found"}, 409: {"description": "Conflict"}, 410: {"description": "Gone"}, 422: {"description": "Unprocessable Entity"}}, dependencies=[Depends(check_management_rate_limit)])
async def ephemeral_join(
    team_id: str,
    body: EphemeralJoinRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Complete an ephemeral slot join with immediate key rotation.

    The joining client has already:
      1. Fetched and decrypted the slot (sk_team = AES-GCM.decrypt(sk_wrapped, k_ephemeral)).
      2. Generated sk_new / pk_new.
      3. Computed rk = sk_old * inv(sk_new) and rk_point = rk × G1.
      4. Re-encrypted every file C1 with rk and generated per-file DLEQ proofs.
      5. Wrapped sk_new for every current member plus themselves.

    The server atomically:
      - Validates the slot is unexpired and unconsumed.
      - Verifies rk_consistency and all DLEQ proofs.
      - Writes the new user_roles + user_team_keys for the joining user.
      - Updates all file_team_keys C1 values.
      - Replaces all user_team_keys with new sk_new wraps.
      - Updates teams.pre_public_key and clears rotation_pending.
      - Marks the slot consumed = 1.
    """
    team_id = validate_uuid(team_id)
    slot_id = validate_uuid(body.slot_id)
    team    = await _get_team_or_404(db, team_id)

    # Caller must NOT already be a member
    existing_role = await get_team_member_role(db, team_id, user.id)
    if existing_role:
        raise HTTPException(status_code=409, detail="You are already a member of this team")

    # Enforce member cap (joining user will be added)
    count = await get_team_member_count(db, team_id)
    if count >= TEAM_MAX_MEMBERS:
        raise HTTPException(
            status_code=422,
            detail=f"Team has reached the member limit ({TEAM_MAX_MEMBERS})"
        )

    await _load_valid_slot(db, team_id, slot_id)
    await _validate_join_file_keys(db, team_id, body)
    await _require_all_members_confirmed(db, team_id)

    # Joining user must be in the members list (they wrap sk_new for themselves)
    submitted_user_ids = {m.user_id for m in body.members}
    if user.id not in submitted_user_ids:
        raise HTTPException(
            status_code=422, detail="members list must include the joining user"
        )

    # Fetch old C1 values for DLEQ verification
    old_c1_map: dict[str, str] = {}
    if body.file_keys:
        file_ids = [fk.file_id for fk in body.file_keys]
        ph = ",".join("?" for _ in file_ids)
        c4 = await db.execute(
            f"SELECT file_id, pre_c1 FROM file_team_keys WHERE team_id = ? AND file_id IN ({ph})",
            (team_id, *file_ids),
        )
        for row in await c4.fetchall():
            old_c1_map[row["file_id"]] = row["pre_c1"]

    # Verify rk_consistency and DLEQ proofs
    if not verify_rk_consistency(body.rk_point, team.pre_public_key, body.pre_public_key_new):
        raise HTTPException(status_code=422, detail="rk_point pairing consistency check failed")

    if body.file_keys:
        dleq_inputs = [
            {
                "rk_point": body.rk_point,
                "c1_old":   old_c1_map[fk.file_id],
                "c1_new":   fk.pre_c1,
                "dleq_s":   fk.dleq_s,
                "dleq_r1":  fk.dleq_R1,
                "dleq_r2":  fk.dleq_R2,
            }
            for fk in body.file_keys
        ]
        if not verify_batch_dleq(dleq_inputs):
            raise HTTPException(status_code=422, detail="DLEQ proof verification failed")

    # --- Atomically commit the join + rotation ---

    # 1. Grant joining user team_member role
    ur_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by) "
        "VALUES (?, ?, 'team_member', 'team', ?, ?)",
        (ur_id, user.id, team_id, user.id),
    )

    # 2. Update file C1 values
    for fk in body.file_keys:
        await db.execute(
            "UPDATE file_team_keys SET pre_c1 = ? WHERE team_id = ? AND file_id = ?",
            (fk.pre_c1, team_id, fk.file_id),
        )

    # 3. Replace all user_team_keys (key_confirmed resets to 0)
    await db.execute("DELETE FROM user_team_keys WHERE team_id = ?", (team_id,))
    for m in body.members:
        utk_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO user_team_keys "
            "(id, team_id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv, key_confirmed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (utk_id, team_id, m.user_id, m.ephemeral_x25519_pub,
             m.kem_ciphertext, m.encrypted_sk, m.sk_iv),
        )

    # 4. Update team public key, clear rotation_pending
    await db.execute(
        "UPDATE teams SET pre_public_key = ?, rotation_pending = 0, "
        "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
        (body.pre_public_key_new, team_id),
    )

    # 5. Consume the slot atomically
    await db.execute(
        "UPDATE team_ephemeral_slots SET consumed = 1 WHERE id = ?",
        (slot_id,),
    )

    await db.commit()
    logger.info(  # NOSONAR — server-side audit log; values are Pydantic-validated
        "Ephemeral join committed: user %s joined team %s via slot %s (%d files, %d members)",
        user.id, team_id, slot_id, len(body.file_keys), len(body.members),
    )
    return {"ok": True, "team_id": team_id}
