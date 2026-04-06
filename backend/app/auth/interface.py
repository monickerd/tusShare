"""Abstract authentication interface — SSO-ready.

All auth providers implement AuthProvider. Routes use get_current_user
which reads the local JWT regardless of which provider created the user.
To add SSO (e.g. OIDC), create a new provider class and register it
via AUTH_PROVIDER config — no route changes needed.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AuthCredentials:
    """Base class for authentication credentials."""
    pass


@dataclass
class AuthenticatedUser:
    """Minimal user representation returned by auth providers."""
    id: str
    username: str
    auth_method: str  # 'opaque'
    roles: set[str] = None  # set of global role IDs (e.g. {"role_admin", "role_user"})
    wrapped_master_key: str | None = None
    wrapped_master_key_iv: str | None = None
    recovery_key_wrapped: str | None = None
    recovery_key_iv: str | None = None
    # Hybrid X25519 + ML-KEM-768 asymmetric key material (Phase 5b)
    x25519_public_key: str | None = None
    mlkem768_public_key: str | None = None
    x25519_private_wrapped: str | None = None
    mlkem768_private_wrapped: str | None = None
    asymmetric_key_iv: str | None = None

    def __post_init__(self):
        if self.roles is None:
            self.roles = set()

    @property
    def is_admin(self) -> bool:
        from app.models.role import ROLE_ADMIN
        return ROLE_ADMIN in self.roles

    @property
    def is_user(self) -> bool:
        from app.models.role import ROLE_USER
        return ROLE_USER in self.roles

    @property
    def is_admin_only(self) -> bool:
        """True if this account has admin role but NOT user role — management-only account."""
        return self.is_admin and not self.is_user


class AuthProvider(ABC):
    """Abstract authentication provider.

    Implementations must handle:
    - Authenticating credentials → user
    - Creating new users
    - Looking up users by ID
    """

    @abstractmethod
    async def authenticate(self, credentials: AuthCredentials) -> AuthenticatedUser | None:
        """Validate credentials and return the user, or None if invalid."""
        ...

    @abstractmethod
    async def create_user(
        self,
        username: str,
        password: str | None = None,
        is_admin: bool = False,
        **kwargs,
    ) -> AuthenticatedUser:
        """Create a new user. Raises ValueError on conflict."""
        ...

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> AuthenticatedUser | None:
        """Look up a user by ID."""
        ...

    @abstractmethod
    async def get_user_by_username(self, username: str) -> AuthenticatedUser | None:
        """Look up a user by username."""
        ...
