"""User model."""

from dataclasses import dataclass


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    encryption_salt: str
    is_admin: bool
    is_active: bool
    max_file_size: int | None
    disk_quota: int | None
    bandwidth_limit: int | None
    disk_used: int
    created_at: str
    updated_at: str
    wrapped_master_key: str | None = None
    wrapped_master_key_iv: str | None = None
    recovery_key_wrapped: str | None = None
    recovery_key_iv: str | None = None
    recovery_key_hash: str | None = None

    @classmethod
    def from_row(cls, row) -> "User":
        return cls(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            encryption_salt=row["encryption_salt"],
            is_admin=bool(row["is_admin"]),
            is_active=bool(row["is_active"]),
            max_file_size=row["max_file_size"],
            disk_quota=row["disk_quota"],
            bandwidth_limit=row["bandwidth_limit"],
            disk_used=row["disk_used"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            wrapped_master_key=row["wrapped_master_key"] if "wrapped_master_key" in row.keys() else None,
            wrapped_master_key_iv=row["wrapped_master_key_iv"] if "wrapped_master_key_iv" in row.keys() else None,
            recovery_key_wrapped=row["recovery_key_wrapped"] if "recovery_key_wrapped" in row.keys() else None,
            recovery_key_iv=row["recovery_key_iv"] if "recovery_key_iv" in row.keys() else None,
            recovery_key_hash=row["recovery_key_hash"] if "recovery_key_hash" in row.keys() else None,
        )

    def to_public_dict(self) -> dict:
        """Return user data safe to send to the client (no password_hash or recovery_key_hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "encryption_salt": self.encryption_salt,
            "is_admin": self.is_admin,
            "is_active": self.is_active,
            "max_file_size": self.max_file_size,
            "disk_quota": self.disk_quota,
            "bandwidth_limit": self.bandwidth_limit,
            "disk_used": self.disk_used,
            "created_at": self.created_at,
        }
