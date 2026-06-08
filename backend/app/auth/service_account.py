"""Service account authentication.

Service accounts are rows in the `users` table with auth_method='service'.
They authenticate via a bearer token prefixed with 'sa_'.

Usage in routes — use the get_service_account dependency when you want to
accept ONLY service account tokens.  For the common case of accepting either
a human JWT or a service account token, see auth/dependencies.py —
get_current_user checks for the 'sa_' prefix automatically.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import HTTPException

from app.auth.interface import AuthenticatedUser
from app.database import db_session
from app.models.role import get_user_global_flags, get_user_global_role_ids
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import event_bus
from app.util.crypto import sha256_hex
from app.util.ip_restrict import is_allowed as ip_is_allowed

logger = logging.getLogger(__name__)

_PREFIX = "sa_"
_MIN_LEN = len(_PREFIX) + 20  # prefix + at least 20 chars of entropy

# Pending last_used_at timestamps — flushed in bulk by run_last_used_flush.
_last_used_pending: dict[str, datetime] = {}


async def _update_last_used(key_id: str) -> None:
    _last_used_pending[key_id] = datetime.now(timezone.utc)


async def run_last_used_flush(db_factory, interval: float = 60.0) -> None:
    """Periodic flush: write coalesced last_used_at values to the DB in one transaction."""
    global _last_used_pending
    while True:
        await asyncio.sleep(interval)
        if not _last_used_pending:
            continue
        pending = _last_used_pending
        _last_used_pending = {}
        try:
            async with db_factory() as db:
                for key_id, ts in pending.items():
                    await db.execute(
                        "UPDATE service_account_keys SET last_used_at = ? WHERE id = ?",
                        (ts.isoformat(), key_id),
                    )
                await db.commit()
        except Exception:
            logger.debug("service_account: failed to flush last_used_at for %d key(s)", len(pending))


async def authenticate_service_account(
    raw_token: str,
    *,
    client_ip: str | None = None,
) -> AuthenticatedUser:
    """Validate a raw service account bearer token.

    Raises HTTPException(401/403) on any failure.  Callers must only pass tokens
    that already have the 'sa_' prefix — check before calling.
    """
    if len(raw_token) < _MIN_LEN:
        raise HTTPException(status_code=401, detail="Invalid service account token")

    key_hash = sha256_hex(raw_token)
    now_iso = datetime.now(timezone.utc).isoformat()

    async with db_session() as db:
        cursor = await db.execute(
            """
            SELECT sak.id        AS key_id,
                   sak.expires_at,
                   sak.allowed_ips,
                   u.id          AS user_id,
                   u.username,
                   u.is_active,
                   u.auth_method
            FROM   service_account_keys sak
            JOIN   users u ON u.id = sak.service_account_id
            WHERE  sak.key_hash = ?
            """,
            (key_hash,),
        )
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid service account token")

    if not row["is_active"]:
        event_bus.emit(
            SecurityEvent(
                event_type="auth.service_account.rejected",
                severity="warning",
                outcome="failure",
                actor=EventActor(user_id=str(row["user_id"]), username=row["username"], auth_method="service"),
                detail={"reason": "inactive"},
            )
        )
        raise HTTPException(status_code=401, detail="Service account is inactive")

    if row["expires_at"] and row["expires_at"] < now_iso:
        event_bus.emit(
            SecurityEvent(
                event_type="auth.service_account.rejected",
                severity="warning",
                outcome="failure",
                actor=EventActor(user_id=str(row["user_id"]), username=row["username"], auth_method="service"),
                detail={"reason": "key_expired"},
            )
        )
        raise HTTPException(status_code=401, detail="Service account key has expired")

    if not ip_is_allowed(client_ip, row["allowed_ips"]):
        logger.warning(
            "service_account: request from disallowed IP %s for account %s",
            client_ip,
            row["username"],
        )
        event_bus.emit(
            SecurityEvent(
                event_type="auth.service_account.rejected",
                severity="warning",
                outcome="failure",
                actor=EventActor(user_id=str(row["user_id"]), username=row["username"], auth_method="service"),
                detail={"reason": "ip_not_allowed", "client_ip": client_ip},
            )
        )
        raise HTTPException(status_code=403, detail="Request source IP is not in this account's allowlist")

    # Load RBAC state
    async with db_session() as db:
        roles = await get_user_global_role_ids(db, row["user_id"])
        flags = await get_user_global_flags(db, row["user_id"])

    event_bus.emit(
        SecurityEvent(
            event_type="auth.service_account.authenticated",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=str(row["user_id"]), username=row["username"], auth_method="service"),
            detail={"key_prefix": raw_token[:12]},
        )
    )

    await _update_last_used(row["key_id"])

    return AuthenticatedUser(
        id=row["user_id"],
        username=row["username"],
        auth_method="service",
        roles=roles,
        flags=flags,
        session_id=None,
    )
