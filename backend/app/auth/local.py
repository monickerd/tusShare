"""Local username/password authentication provider."""

import secrets
import uuid

import bcrypt

from app.auth.interface import (
    AuthCredentials,
    AuthenticatedUser,
    AuthProvider,
    LocalCredentials,
)
from app.conf.auth import BCRYPT_ROUNDS, ENCRYPTION_SALT_BYTES, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH
from app.models.role import ROLE_ADMIN, ROLE_USER, get_user_global_role_ids, grant_role
from app.validation.sanitizers import sanitize_username

# Pre-computed dummy hash at the correct work factor for timing-safe user-not-found
_DUMMY_HASH = bcrypt.hashpw(b"dummy-timing-padding", bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

# Columns needed from users table (roles come from user_roles)
_USER_COLUMNS = (
    "id, username, password_hash, is_active, encryption_salt, "
    "wrapped_master_key, wrapped_master_key_iv, recovery_key_wrapped, recovery_key_iv, "
    "x25519_public_key, mlkem768_public_key, x25519_private_wrapped, "
    "mlkem768_private_wrapped, asymmetric_key_iv"
)

_USER_COLUMNS_NO_PW = (
    "id, username, is_active, encryption_salt, "
    "wrapped_master_key, wrapped_master_key_iv, recovery_key_wrapped, recovery_key_iv, "
    "x25519_public_key, mlkem768_public_key, x25519_private_wrapped, "
    "mlkem768_private_wrapped, asymmetric_key_iv"
)


def _row_to_user(row, roles: set[str]) -> AuthenticatedUser:
    """Build an AuthenticatedUser from a DB row + loaded roles."""
    return AuthenticatedUser(
        id=row["id"],
        username=row["username"],
        encryption_salt=row["encryption_salt"],
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


class LocalAuthProvider(AuthProvider):
    """Authenticates users against bcrypt-hashed passwords in SQLite."""

    def __init__(self, db):
        self._db = db

    async def authenticate(self, credentials: AuthCredentials) -> AuthenticatedUser | None:
        if not isinstance(credentials, LocalCredentials):
            return None

        # Validate username format before querying
        try:
            username = sanitize_username(credentials.username)
        except ValueError:
            return None

        cursor = await self._db.execute(
            f"SELECT {_USER_COLUMNS} FROM users WHERE username = ?",
            (username,),
        )
        row = await cursor.fetchone()

        if row is None:
            # Constant-time: check against pre-computed dummy to prevent timing oracle
            bcrypt.checkpw(b"dummy-timing-padding", _DUMMY_HASH)
            return None

        if not row["is_active"]:
            # Constant-time: still run dummy check so inactive accounts are
            # indistinguishable from non-existent ones via timing
            bcrypt.checkpw(b"dummy-timing-padding", _DUMMY_HASH)
            return None

        # Verify password (bcrypt handles salt internally)
        if not bcrypt.checkpw(
            credentials.password.encode("utf-8"),
            row["password_hash"].encode("utf-8"),
        ):
            return None

        roles = await get_user_global_role_ids(self._db, row["id"])
        return _row_to_user(row, roles)

    async def create_user(
        self,
        username: str,
        password: str | None = None,
        role: str = ROLE_USER,
        **kwargs,
    ) -> AuthenticatedUser:
        """Create a new user and assign them a global role.

        role should be ROLE_USER for regular users or ROLE_ADMIN for admin-only accounts.
        """
        username = sanitize_username(username)

        if password is None:
            raise ValueError("Password is required for local auth")

        if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
            raise ValueError(f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters")

        user_id = str(uuid.uuid4())
        # Accept a client-provided salt (needed for self-registration where the
        # client generates the salt before wrapping the master key). Fall back to
        # server-generated for admin-created accounts that supply no crypto material.
        encryption_salt = kwargs.get("encryption_salt") or secrets.token_hex(ENCRYPTION_SALT_BYTES)
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        ).decode("utf-8")

        # Accept optional key wrapping blobs from the client
        wrapped_master_key = kwargs.get("wrapped_master_key")
        wrapped_master_key_iv = kwargs.get("wrapped_master_key_iv")
        recovery_key_wrapped = kwargs.get("recovery_key_wrapped")
        recovery_key_iv = kwargs.get("recovery_key_iv")
        recovery_key_hash = kwargs.get("recovery_key_hash")

        # Asymmetric key material (Phase 5b — optional at creation, set on first login)
        x25519_public_key = kwargs.get("x25519_public_key")
        mlkem768_public_key = kwargs.get("mlkem768_public_key")
        x25519_private_wrapped = kwargs.get("x25519_private_wrapped")
        mlkem768_private_wrapped = kwargs.get("mlkem768_private_wrapped")
        asymmetric_key_iv = kwargs.get("asymmetric_key_iv")

        # Determine is_admin for backward compat column (kept in sync with roles)
        is_admin_flag = 1 if role == ROLE_ADMIN else 0

        try:
            await self._db.execute(
                "INSERT INTO users (id, username, password_hash, encryption_salt, is_admin, "
                "wrapped_master_key, wrapped_master_key_iv, recovery_key_wrapped, recovery_key_iv, recovery_key_hash, "
                "x25519_public_key, mlkem768_public_key, x25519_private_wrapped, mlkem768_private_wrapped, asymmetric_key_iv) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, username, password_hash, encryption_salt, is_admin_flag,
                 wrapped_master_key, wrapped_master_key_iv, recovery_key_wrapped, recovery_key_iv, recovery_key_hash,
                 x25519_public_key, mlkem768_public_key, x25519_private_wrapped, mlkem768_private_wrapped, asymmetric_key_iv),
            )

            # Grant the assigned role
            await grant_role(self._db, user_id, role)

            await self._db.commit()
        except Exception as e:
            await self._db.rollback()
            if "UNIQUE constraint failed" in str(e):
                raise ValueError("Username already exists")
            raise

        roles = {role}
        return AuthenticatedUser(
            id=user_id,
            username=username,
            encryption_salt=encryption_salt,
            roles=roles,
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
            f"SELECT {_USER_COLUMNS_NO_PW} FROM users WHERE id = ?",
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
            f"SELECT {_USER_COLUMNS_NO_PW} FROM users WHERE username = ?",
            (username,),
        )
        row = await cursor.fetchone()
        if row is None or not row["is_active"]:
            return None
        roles = await get_user_global_role_ids(self._db, row["id"])
        return _row_to_user(row, roles)
