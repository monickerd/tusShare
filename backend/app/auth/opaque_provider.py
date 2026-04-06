"""OPAQUE aPAKE authentication provider.

Handles user creation for OPAQUE-registered accounts.  Login is intentionally
NOT routed through AuthProvider.authenticate() — the two-round OPAQUE exchange
lives in routes/opaque_auth.py which calls this provider's helpers directly.

The PyO3 module `tusshare_opaque` is imported lazily so that startup doesn't
fail if the wheel is absent in a non-Docker dev environment (it will fail loudly
at the first actual OPAQUE operation instead).
"""

import asyncio
import uuid

from app.auth.interface import AuthCredentials, AuthenticatedUser, AuthProvider
from app.database import DuplicateError
from app.models.role import ROLE_ADMIN, ROLE_USER, get_user_global_role_ids, grant_role
from app.validation.sanitizers import sanitize_username

# Columns shared between all OPAQUE queries
_USER_COLUMNS = (
    "id, username, auth_method, is_active, "
    "wrapped_master_key, wrapped_master_key_iv, recovery_key_wrapped, recovery_key_iv, "
    "x25519_public_key, mlkem768_public_key, x25519_private_wrapped, "
    "mlkem768_private_wrapped, asymmetric_key_iv"
)


def _row_to_user(row, roles: set[str]) -> AuthenticatedUser:
    return AuthenticatedUser(
        id=row["id"],
        username=row["username"],
        auth_method=row["auth_method"],
        roles=roles,
        wrapped_master_key=row["wrapped_master_key"],
        wrapped_master_key_iv=row["wrapped_master_key_iv"],
        recovery_key_wrapped=row["recovery_key_wrapped"],
        recovery_key_iv=row["recovery_key_iv"],
        x25519_public_key=row["x25519_public_key"],
        mlkem768_public_key=row["mlkem768_public_key"],
        x25519_private_wrapped=row["x25519_private_wrapped"],
        mlkem768_private_wrapped=row["mlkem768_private_wrapped"],
        asymmetric_key_iv=row["asymmetric_key_iv"],
    )


class OPAQUEAuthProvider(AuthProvider):
    """Auth provider for OPAQUE-registered users.

    authenticate() is not implemented — OPAQUE login is a two-round protocol
    handled by dedicated routes.  All other AuthProvider methods work normally.
    """

    def __init__(self, db):
        self._db = db

    async def authenticate(self, credentials: AuthCredentials) -> AuthenticatedUser | None:
        # OPAQUE login cannot be reduced to a single authenticate() call.
        # Callers should use the /auth/opaque/login/start+finish routes instead.
        raise NotImplementedError(
            "OPAQUEAuthProvider.authenticate() is not supported. "
            "Use the OPAQUE login routes."
        )

    async def create_user(
        self,
        username: str,
        password: str | None = None,
        role: str = ROLE_USER,
        **kwargs,
    ) -> AuthenticatedUser:
        """Create a new OPAQUE user.

        `password` is intentionally ignored — the OPAQUE registration record
        (already computed via the register/start+finish exchange) must be
        supplied as `opaque_registration_record` in kwargs.
        """
        username = sanitize_username(username)

        opaque_record: bytes | None = kwargs.get("opaque_registration_record")
        if not opaque_record:
            raise ValueError("opaque_registration_record is required for OPAQUE users")

        user_id = str(uuid.uuid4())
        is_admin_flag = 1 if role == ROLE_ADMIN else 0

        wrapped_master_key = kwargs.get("wrapped_master_key")
        wrapped_master_key_iv = kwargs.get("wrapped_master_key_iv")
        recovery_key_wrapped = kwargs.get("recovery_key_wrapped")
        recovery_key_iv = kwargs.get("recovery_key_iv")
        recovery_key_hash = kwargs.get("recovery_key_hash")
        x25519_public_key = kwargs.get("x25519_public_key")
        mlkem768_public_key = kwargs.get("mlkem768_public_key")
        x25519_private_wrapped = kwargs.get("x25519_private_wrapped")
        mlkem768_private_wrapped = kwargs.get("mlkem768_private_wrapped")
        asymmetric_key_iv = kwargs.get("asymmetric_key_iv")

        try:
            await self._db.execute(
                "INSERT INTO users ("
                "  id, username, auth_method, opaque_registration_record, is_admin, "
                "  wrapped_master_key, wrapped_master_key_iv, "
                "  recovery_key_wrapped, recovery_key_iv, recovery_key_hash, "
                "  x25519_public_key, mlkem768_public_key, "
                "  x25519_private_wrapped, mlkem768_private_wrapped, asymmetric_key_iv"
                ") VALUES (?, ?, 'opaque', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    user_id, username, opaque_record, is_admin_flag,
                    wrapped_master_key, wrapped_master_key_iv,
                    recovery_key_wrapped, recovery_key_iv, recovery_key_hash,
                    x25519_public_key, mlkem768_public_key,
                    x25519_private_wrapped, mlkem768_private_wrapped, asymmetric_key_iv,
                ),
            )
            await grant_role(self._db, user_id, role)
            await self._db.commit()
        except DuplicateError:
            await self._db.rollback()
            raise ValueError("Username already exists")
        except Exception:
            await self._db.rollback()
            raise

        return AuthenticatedUser(
            id=user_id,
            username=username,
            auth_method="opaque",
            roles={role},
            wrapped_master_key=wrapped_master_key,
            wrapped_master_key_iv=wrapped_master_key_iv,
            recovery_key_wrapped=recovery_key_wrapped,
            recovery_key_iv=recovery_key_iv,
            x25519_public_key=x25519_public_key,
            mlkem768_public_key=mlkem768_public_key,
            x25519_private_wrapped=x25519_private_wrapped,
            mlkem768_private_wrapped=mlkem768_private_wrapped,
            asymmetric_key_iv=asymmetric_key_iv,
        )

    async def get_user_by_id(self, user_id: str) -> AuthenticatedUser | None:
        cursor = await self._db.execute(
            f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?",
            (user_id,),
        )
        row = await cursor.fetchone()
        if row is None or not row["is_active"]:
            return None
        roles = await get_user_global_role_ids(self._db, user_id)
        return _row_to_user(row, roles)

    async def get_user_by_username(self, username: str) -> AuthenticatedUser | None:
        try:
            username = sanitize_username(username)
        except ValueError:
            return None
        cursor = await self._db.execute(
            f"SELECT {_USER_COLUMNS} FROM users WHERE LOWER(username) = LOWER(?)",
            (username,),
        )
        row = await cursor.fetchone()
        if row is None or not row["is_active"]:
            return None
        roles = await get_user_global_role_ids(self._db, row["id"])
        return _row_to_user(row, roles)

    # ------------------------------------------------------------------
    # OPAQUE-specific helpers (called directly by opaque_auth routes)
    # ------------------------------------------------------------------

    async def get_registration_record(self, username: str) -> bytes | None:
        """Return the stored opaque_registration_record for a username, or None."""
        cursor = await self._db.execute(
            "SELECT opaque_registration_record, auth_method, is_active "
            "FROM users WHERE LOWER(username) = LOWER(?)",
            (username,),
        )
        row = await cursor.fetchone()
        if row is None or not row["is_active"] or row["auth_method"] != "opaque":
            return None
        return row["opaque_registration_record"]

    async def store_login_session(
        self,
        session_id: str,
        username: str,
        server_state: bytes,
        ttl_seconds: int = 60,
    ) -> None:
        """Persist an in-flight OPAQUE login session."""
        await self._db.execute(
            "INSERT INTO opaque_login_sessions (id, username, server_state, expires_at) "
            "VALUES (?, ?, ?, NOW() + (? * INTERVAL '1 second'))",
            (session_id, username, server_state, ttl_seconds),
        )
        await self._db.commit()

    async def consume_login_session(
        self, session_id: str
    ) -> tuple[str, bytes] | None:
        """Atomically fetch and delete an unexpired login session.

        Returns (username, server_state) or None if expired / not found.
        """
        cursor = await self._db.execute(
            "DELETE FROM opaque_login_sessions "
            "WHERE id = ? AND expires_at > NOW() "
            "RETURNING username, server_state",
            (session_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return row["username"], bytes(row["server_state"])

    async def sweep_expired_sessions(self) -> int:
        """Delete all expired login sessions. Returns the number of rows removed."""
        result = await self._db.execute(
            "DELETE FROM opaque_login_sessions WHERE expires_at <= NOW()"
        )
        await self._db.commit()
        return result.rowcount
