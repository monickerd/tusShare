"""User model."""

from dataclasses import dataclass, field


@dataclass
class User:
    id: str
    username: str
    auth_method: str
    is_admin: bool
    is_active: bool
    disk_used: int
    created_at: str
    updated_at: str
    # Per-user limits
    max_file_size: int | None = None
    disk_quota: int | None = None
    bandwidth_limit: int | None = None
    # Symmetric key material
    wrapped_master_key: str | None = None
    wrapped_master_key_iv: str | None = None
    recovery_key_wrapped: str | None = None
    recovery_key_iv: str | None = None
    recovery_key_hash: str | None = None
    # Asymmetric PQ keys
    x25519_public_key: str | None = None
    mlkem768_public_key: str | None = None
    x25519_private_wrapped: str | None = None
    mlkem768_private_wrapped: str | None = None
    asymmetric_key_iv: str | None = None
    # Identity provider (migration 006)
    identity_provider_id: str | None = None

    @classmethod
    def from_row(cls, row) -> "User":
        return cls(
            id=row["id"],
            username=row["username"],
            auth_method=row["auth_method"],
            is_admin=bool(row["is_admin"]),
            is_active=bool(row["is_active"]),
            disk_used=row["disk_used"],
            created_at=str(row["created_at"]) if row["created_at"] else "",
            updated_at=str(row["updated_at"]) if row["updated_at"] else "",
            max_file_size=row["max_file_size"],
            disk_quota=row["disk_quota"],
            bandwidth_limit=row["bandwidth_limit"],
            wrapped_master_key=row["wrapped_master_key"] if "wrapped_master_key" in row.keys() else None,
            wrapped_master_key_iv=row["wrapped_master_key_iv"] if "wrapped_master_key_iv" in row.keys() else None,
            recovery_key_wrapped=row["recovery_key_wrapped"] if "recovery_key_wrapped" in row.keys() else None,
            recovery_key_iv=row["recovery_key_iv"] if "recovery_key_iv" in row.keys() else None,
            recovery_key_hash=row["recovery_key_hash"] if "recovery_key_hash" in row.keys() else None,
            x25519_public_key=row["x25519_public_key"] if "x25519_public_key" in row.keys() else None,
            mlkem768_public_key=row["mlkem768_public_key"] if "mlkem768_public_key" in row.keys() else None,
            x25519_private_wrapped=row["x25519_private_wrapped"] if "x25519_private_wrapped" in row.keys() else None,
            mlkem768_private_wrapped=row["mlkem768_private_wrapped"] if "mlkem768_private_wrapped" in row.keys() else None,
            asymmetric_key_iv=row["asymmetric_key_iv"] if "asymmetric_key_iv" in row.keys() else None,
            identity_provider_id=row["identity_provider_id"] if "identity_provider_id" in row.keys() else None,
        )

    def to_public_dict(self) -> dict:
        """Return user data safe to send to the client."""
        return {
            "id": self.id,
            "username": self.username,
            "auth_method": self.auth_method,
            "is_admin": self.is_admin,
            "is_active": self.is_active,
            "max_file_size": self.max_file_size,
            "disk_quota": self.disk_quota,
            "bandwidth_limit": self.bandwidth_limit,
            "disk_used": self.disk_used,
            "created_at": self.created_at,
            "identity_provider_id": self.identity_provider_id,
        }
