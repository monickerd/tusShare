"""Permission model."""

from dataclasses import dataclass


@dataclass
class Permission:
    id: str
    resource_type: str  # 'file', 'folder'
    resource_id: str
    user_id: str
    access_level: str  # 'read', 'write', 'admin'
    recursive: bool
    granted_by: str
    created_at: str

    @classmethod
    def from_row(cls, row) -> "Permission":
        return cls(
            id=row["id"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            user_id=row["user_id"],
            access_level=row["permission"],
            recursive=bool(row["recursive"]),
            granted_by=row["granted_by"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "user_id": self.user_id,
            "permission": self.access_level,
            "recursive": self.recursive,
            "granted_by": self.granted_by,
            "created_at": self.created_at,
        }


# Permission level ordering for comparison
PERMISSION_LEVELS = {"read": 1, "write": 2, "admin": 3}


def permission_gte(held: str, required: str) -> bool:
    """Check if held permission level is >= required level."""
    return PERMISSION_LEVELS.get(held, 0) >= PERMISSION_LEVELS.get(required, 0)
