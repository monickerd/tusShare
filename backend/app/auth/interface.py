"""Abstract authentication interface — SSO-ready.

All auth providers implement AuthProvider. Routes use get_current_user
which reads the local JWT regardless of which provider created the user.
To add SSO (e.g. OIDC), create a new provider class and register it
via AUTH_PROVIDER config — no route changes needed.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


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
    roles: Optional[set[str]] = None   # set of global role IDs
    flags: Optional[dict[str, str]] = None  # effective permission flags from global roles {flag: value}
    # Scoped role entries: list of {role_id, scope_type, scope_id, flags} dicts.
    # Populated at auth time; used by has_flag_in_scope and get_team_ids_with_flag.
    scoped_roles: Optional[list[dict]] = None
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
    # Session-level flags — populated from JWT claims, not from the DB.
    is_public_device: bool = False
    # sid from the access token's JWT "sid" claim — used to bind step-up tokens to a specific session.
    session_id: str | None = None

    def __post_init__(self):
        if self.roles is None:
            self.roles = set()
        if self.flags is None:
            self.flags = {}
        if self.scoped_roles is None:
            self.scoped_roles = []

    def has_flag(self, flag: str) -> bool:
        """Return True if this user's effective permissions include the given flag.

        Checks global (unscoped) flags first, then any scoped role that grants
        the flag — allowing a team-scoped admin to pass a global has_flag check
        before the scope guard narrows down which teams they can actually touch.
        """
        if self.flags.get(flag, "0") not in ("0", "", "false", "False", "no"):
            return True
        # Any scoped role that grants this flag also counts for panel access.
        return any(
            entry["flags"].get(flag, "0") not in ("0", "", "false", "False", "no")
            for entry in self.scoped_roles
        )

    def has_flag_in_scope(self, flag: str, scope_type: str, scope_id: str) -> bool:
        """Return True if this user holds *flag* within the given scope.

        A global grant of the flag (scope_type IS NULL) also satisfies any
        scoped check — org-wide admins can always act within any team.
        """
        if self.flags.get(flag, "0") not in ("0", "", "false", "False", "no"):
            return True
        return any(
            entry["scope_type"] == scope_type
            and entry["scope_id"] == scope_id
            and entry["flags"].get(flag, "0") not in ("0", "", "false", "False", "no")
            for entry in self.scoped_roles
        )

    def get_team_ids_with_flag(self, flag: str) -> set[str] | None:
        """Return the set of team IDs where this user holds *flag*.

        Returns None (sentinel) if the user holds the flag globally (org-wide),
        meaning no scope restriction applies.  Returns an empty set if the user
        holds no grant for this flag at any scope.
        """
        if self.flags.get(flag, "0") not in ("0", "", "false", "False", "no"):
            return None  # org-wide: no restriction
        return {
            entry["scope_id"]
            for entry in self.scoped_roles
            if entry["scope_type"] == "team"
            and entry["flags"].get(flag, "0") not in ("0", "", "false", "False", "no")
        }

    @property
    def is_admin(self) -> bool:
        from app.models.role import ADMIN_ROLE_IDS
        if bool(self.roles & ADMIN_ROLE_IDS):
            return True
        # Scoped team admins (team_admin/team_manager roles in a team scope) are
        # also admins — they can access the admin panel within their scope.
        return any(
            entry["role_id"] in ADMIN_ROLE_IDS or entry["role_id"] is None
            for entry in self.scoped_roles
            if entry["flags"].get("admin_panel_view", "0") not in ("0", "", "false", "False", "no")
        )

    @property
    def is_user(self) -> bool:
        from app.models.role import ROLE_USER
        return ROLE_USER in self.roles

    @property
    def is_admin_only(self) -> bool:
        """True if this account has an admin role but NOT the user role — management-only account."""
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
