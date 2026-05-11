"""Admin routes for identity provider management.

Endpoints
─────────
GET    /admin/identity-providers            — list all providers (no secrets)
POST   /admin/identity-providers            — create a new provider
GET    /admin/identity-providers/{id}       — get one provider (secrets redacted)
PUT    /admin/identity-providers/{id}       — update (full replace of config)
DELETE /admin/identity-providers/{id}       — delete provider + linked users
POST   /admin/identity-providers/{id}/test  — test connection (LDAP bind or OIDC discovery)
GET    /admin/identity-providers/{id}/wizard — discover available attributes/claims

All endpoints require the `integration.ldap.configure` sensitive function
(step-up re-auth) because they expose or modify credential material.

The config_enc blob is never returned to the client.  The decrypted config dict
is returned with secrets replaced by the placeholder "••••••••" so the admin
can see what was configured without re-entering everything on every edit.
"""

from __future__ import annotations

import json
import logging
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.auth.idp_crypto import encrypt_idp_config, decrypt_idp_config
from app.auth.ldap_provider import validate_ldap_config, ldap_test_connection, ldap_fetch_attributes
from app.auth.oidc_provider import validate_oidc_config
from app.database import Database, DuplicateError, get_db
from app.validation.sanitizers import validate_uuid
from typing import Annotated


_ERR_PROVIDER_NOT_FOUND = "Provider not found"
_SQL_PROVIDER_BY_ID = "SELECT provider_type, config_enc FROM identity_providers WHERE id = ?"

logger = logging.getLogger(__name__)

router = APIRouter()

_REDACTED = "••••••••"
_SECRET_FIELDS = {"bind_password", "client_secret"}


def _redact_config(cfg: dict) -> dict:
    """Return a copy of cfg with secret fields replaced by the redaction placeholder."""
    return {k: (_REDACTED if k in _SECRET_FIELDS else v) for k, v in cfg.items()}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class LDAPConfigModel(BaseModel):
    server_uri: str
    bind_dn: str
    bind_password: str
    base_dn: str
    user_filter: str
    tls: str = "verify"
    username_attr: str = "sAMAccountName"

    @field_validator("server_uri")
    @classmethod
    def val_uri(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("ldap://", "ldaps://")):
            raise ValueError("server_uri must begin with ldap:// or ldaps://")
        return v

    @field_validator("bind_dn", "bind_password", "base_dn", "user_filter")
    @classmethod
    def val_nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field must not be empty")
        return v

    @field_validator("tls")
    @classmethod
    def val_tls(cls, v: str) -> str:
        if v not in ("verify", "starttls", "skip_verify"):
            raise ValueError("tls must be 'verify', 'starttls', or 'skip_verify'")
        return v


class OIDCConfigModel(BaseModel):
    issuer_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list[str] = ["openid", "email", "profile", "offline_access"]
    username_attr: str = "email"

    @field_validator("issuer_url")
    @classmethod
    def val_issuer(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v:
            raise ValueError("issuer_url must not be empty")
        return v

    @field_validator("client_id", "client_secret", "redirect_uri")
    @classmethod
    def val_nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field must not be empty")
        return v


class CreateProviderRequest(BaseModel):
    provider_type: str
    name: str
    is_active: bool = True
    claim_mode: str | None = None   # OIDC only: 'at_login' | 'live_refetch'
    config: dict                    # shape varies by provider_type

    @field_validator("provider_type")
    @classmethod
    def val_type(cls, v: str) -> str:
        if v not in ("ldap", "oidc"):
            raise ValueError("provider_type must be 'ldap' or 'oidc'")
        return v

    @field_validator("name")
    @classmethod
    def val_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("name must be 1–128 characters")
        return v

    @field_validator("claim_mode")
    @classmethod
    def val_claim_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in ("at_login", "live_refetch"):
            raise ValueError("claim_mode must be 'at_login' or 'live_refetch'")
        return v


class UpdateProviderRequest(BaseModel):
    name: str | None = None
    is_active: bool | None = None
    claim_mode: str | None = None
    config: dict | None = None

    @field_validator("name")
    @classmethod
    def val_name(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            if not v or len(v) > 128:
                raise ValueError("name must be 1–128 characters")
        return v

    @field_validator("claim_mode")
    @classmethod
    def val_claim_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in ("at_login", "live_refetch"):
            raise ValueError("claim_mode must be 'at_login' or 'live_refetch'")
        return v


# ---------------------------------------------------------------------------
# Config validation helper
# ---------------------------------------------------------------------------

def _validate_and_encrypt_config(provider_type: str, raw_config: dict) -> str:
    """Validate and AES-GCM encrypt a provider config dict."""
    if provider_type == "ldap":
        # Validate via pydantic model for field-level errors, then run domain rules
        LDAPConfigModel(**raw_config)
        validate_ldap_config(raw_config)
    else:
        OIDCConfigModel(**raw_config)
        validate_oidc_config(raw_config)
    return encrypt_idp_config(raw_config)


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

@router.get("")
async def list_providers(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all identity providers.  Config secrets are never returned."""
    cursor = await db.execute(
        "SELECT id, provider_type, name, is_active, claim_mode, created_at, updated_at "
        "FROM identity_providers ORDER BY name"
    )
    rows = await cursor.fetchall()
    return {"providers": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

@router.post("", responses={400: {"description": "Bad Request"}, 409: {"description": "Conflict"}})
async def create_provider(
    body: CreateProviderRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create a new identity provider.  Requires step-up (integration.ldap.configure)."""
    # Validate and encrypt config
    try:
        config_enc = _validate_and_encrypt_config(body.provider_type, body.config)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    provider_id = str(uuid.uuid4())
    now = int(time.time())

    claim_mode = body.claim_mode
    if body.provider_type == "ldap":
        claim_mode = None  # LDAP is always live; claim_mode doesn't apply

    try:
        await db.execute(
            "INSERT INTO identity_providers "
            "(id, provider_type, name, is_active, claim_mode, config_enc, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                provider_id,
                body.provider_type,
                body.name,
                1 if body.is_active else 0,
                claim_mode,
                config_enc,
                now, now,
            ),
        )
        await db.commit()
    except DuplicateError:
        raise HTTPException(status_code=409, detail="A provider with that name already exists")

    logger.info("IdP created: id=%s type=%s name=%r by admin=%s", provider_id, body.provider_type, body.name, admin.id)  # NOSONAR — server-side audit log; values are Pydantic-validated
    return {"id": provider_id, "provider_type": body.provider_type, "name": body.name, "is_active": body.is_active}


# ---------------------------------------------------------------------------
# Get one (redacted)
# ---------------------------------------------------------------------------

@router.get("/{provider_id}", responses={404: {"description": "Not Found"}})
async def get_provider(
    provider_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return a single provider.  Secret fields in config are replaced with ••••••••."""
    try:
        validate_uuid(provider_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    cursor = await db.execute(
        "SELECT id, provider_type, name, is_active, claim_mode, config_enc, created_at, updated_at "
        "FROM identity_providers WHERE id = ?",
        (provider_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    result = {k: row[k] for k in row if k != "config_enc"}
    try:
        cfg = decrypt_idp_config(row["config_enc"])
        result["config"] = _redact_config(cfg)
    except Exception:
        result["config"] = {}

    return result


def _build_merged_config_enc(provider_type: str, existing_enc: str | None, new_config: dict) -> str:
    try:
        existing_cfg = decrypt_idp_config(existing_enc)
    except Exception:
        existing_cfg = {}
    merged = dict(existing_cfg)
    for k, v in new_config.items():
        if k in _SECRET_FIELDS and v == _REDACTED:
            pass  # keep existing value
        else:
            merged[k] = v
    try:
        return _validate_and_encrypt_config(provider_type, merged)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

@router.put("/{provider_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}})
async def update_provider(
    provider_id: str,
    body: UpdateProviderRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Update a provider.  If config is supplied it replaces the stored config entirely.

    When updating config, secret fields set to the redaction placeholder are
    preserved from the existing stored config so the admin does not need to
    re-enter secrets they haven't changed.
    """
    try:
        validate_uuid(provider_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    cursor = await db.execute(
        _SQL_PROVIDER_BY_ID,
        (provider_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    provider_type = row["provider_type"]
    now = int(time.time())

    updates = []
    params = []

    if body.name is not None:
        updates.append("name = ?")
        params.append(body.name)

    if body.is_active is not None:
        updates.append("is_active = ?")
        params.append(1 if body.is_active else 0)

    if body.claim_mode is not None or (body.claim_mode is None and body.is_active is not None):
        if provider_type == "ldap":
            pass  # claim_mode never set for LDAP
        elif body.claim_mode is not None:
            updates.append("claim_mode = ?")
            params.append(body.claim_mode)

    if body.config is not None:
        updates.append("config_enc = ?")
        params.append(_build_merged_config_enc(provider_type, row["config_enc"], body.config))

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = ?")
    params.append(now)
    params.append(provider_id)

    try:
        await db.execute(
            f"UPDATE identity_providers SET {', '.join(updates)} WHERE id = ?",
            tuple(params),
        )
        await db.commit()
    except DuplicateError:
        raise HTTPException(status_code=409, detail="A provider with that name already exists")

    logger.info("IdP updated: id=%s by admin=%s", provider_id, admin.id)  # NOSONAR — server-side audit log; values are Pydantic-validated
    return {"ok": True}


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

@router.delete("/{provider_id}", responses={404: {"description": "Not Found"}})
async def delete_provider(
    provider_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete a provider and all associated user mappings.

    Users whose identity_provider_id points to this provider are de-linked
    (identity_provider_id set to NULL) but not deleted — they simply lose IdP
    authentication.  The identity_provider_users rows are cascade-deleted by
    the FK.
    """
    try:
        validate_uuid(provider_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    # De-link users before deleting the provider
    await db.execute(
        "UPDATE users SET identity_provider_id = NULL WHERE identity_provider_id = ?",
        (provider_id,),
    )
    result = await db.execute(
        "DELETE FROM identity_providers WHERE id = ? RETURNING id",
        (provider_id,),
    )
    row = await result.fetchone()
    if row is None:
        await db.rollback()
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)
    await db.commit()

    logger.info("IdP deleted: id=%s by admin=%s", provider_id, admin.id)  # NOSONAR — server-side audit log; values are Pydantic-validated
    return {"ok": True}


# ---------------------------------------------------------------------------
# Test connection
# ---------------------------------------------------------------------------

@router.post("/{provider_id}/test", responses={404: {"description": "Not Found"}})
async def test_provider(
    provider_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Test an identity provider's connectivity.

    LDAP: attempts a service-account bind only (no user lookup).
    OIDC: fetches the discovery document at {issuer_url}/.well-known/openid-configuration.

    Returns {"ok": true} or {"ok": false, "error": "<message>"}.
    """
    try:
        validate_uuid(provider_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    cursor = await db.execute(
        _SQL_PROVIDER_BY_ID,
        (provider_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    if row["provider_type"] == "ldap":
        result = await ldap_test_connection(row["config_enc"])
    else:
        result = await _test_oidc_discovery(row["config_enc"])

    return result


async def _test_oidc_discovery(config_enc: str) -> dict:
    """Attempt to fetch the OIDC discovery document."""
    try:
        import httpx
        cfg = decrypt_idp_config(config_enc)
        discovery_url = cfg["issuer_url"].rstrip("/") + "/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            resp = await client.get(discovery_url, timeout=10)
            resp.raise_for_status()
            metadata = resp.json()
        required_keys = ("authorization_endpoint", "token_endpoint", "jwks_uri")
        missing = [k for k in required_keys if k not in metadata]
        if missing:
            return {"ok": False, "error": f"Discovery document missing keys: {missing}"}
        return {"ok": True, "issuer": metadata.get("issuer", "unknown")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Attribute/claim wizard
# ---------------------------------------------------------------------------

@router.get("/{provider_id}/wizard", responses={404: {"description": "Not Found"}})
async def provider_wizard(
    provider_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return the available attributes / claims for this provider.

    LDAP: returns the attribute names returned for the admin's own account
          (using admin.username as the lookup value).
    OIDC: returns the claims available in the discovery document scopes plus
          an example from the admin's cached claims if available.

    The response is used by the frontend wizard to let admins select which
    attributes to register as policy_field_definitions.
    """
    try:
        validate_uuid(provider_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    cursor = await db.execute(
        _SQL_PROVIDER_BY_ID,
        (provider_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_PROVIDER_NOT_FOUND)

    if row["provider_type"] == "ldap":
        return await _ldap_wizard(row["config_enc"], admin.username)
    else:
        return await _oidc_wizard(row["config_enc"], admin.id, db)


async def _ldap_wizard(config_enc: str, admin_username: str) -> dict:
    """Return LDAP attribute names for the admin's own account."""
    attrs = await ldap_fetch_attributes(config_enc, admin_username)
    if attrs is None:
        return {
            "error": "Could not fetch attributes — check that the service account can "
                     "search and that the admin's username matches the user_filter template",
            "attributes": [],
        }
    return {
        "attributes": [
            {"name": k, "example_value": str(v)[:200]}
            for k, v in sorted(attrs.items())
        ]
    }


async def _oidc_wizard(_config_enc: str, admin_user_id: str, db) -> dict:
    """Return OIDC claim names from the admin's cached claims (if available)."""
    import json as _json
    cursor = await db.execute(
        "SELECT oidc_claims_cache FROM users WHERE id = ?", (admin_user_id,)
    )
    row = await cursor.fetchone()
    cache_raw = row["oidc_claims_cache"] if row else None

    if cache_raw:
        try:
            cached = _json.loads(cache_raw)
            return {
                "claims": [
                    {"name": k, "example_value": str(v)[:200]}
                    for k, v in sorted(cached.items())
                ]
            }
        except Exception:
            pass

    # No cached claims — return standard well-known claims as a hint
    return {
        "claims": [
            {"name": "sub",        "example_value": "(IdP subject ID — stable unique identifier)"},
            {"name": "email",      "example_value": "(user email address)"},
            {"name": "name",       "example_value": "(display name)"},
            {"name": "given_name", "example_value": "(first name)"},
            {"name": "family_name","example_value": "(last name)"},
            {"name": "groups",     "example_value": "(group membership array — provider-specific)"},
            {"name": "department", "example_value": "(org-specific; must be configured in IdP)"},
        ],
        "note": "Log in via this OIDC provider to populate live claim values here.",
    }
