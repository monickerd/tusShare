"""Access log model."""

from dataclasses import dataclass


@dataclass
class AccessLog:
    id: str
    file_id: str | None
    user_id: str | None
    share_id: str | None
    ip_address: str
    user_agent: str | None
    action: str  # 'view', 'download', 'upload', 'delete', 'share'
    timestamp: str

    @classmethod
    def from_row(cls, row) -> "AccessLog":
        return cls(
            id=row["id"],
            file_id=row["file_id"],
            user_id=row["user_id"],
            share_id=row["share_id"],
            ip_address=row["ip_address"],
            user_agent=row["user_agent"],
            action=row["action"],
            timestamp=row["timestamp"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file_id": self.file_id,
            "user_id": self.user_id,
            "share_id": self.share_id,
            "ip_address": self.ip_address,
            "action": self.action,
            "timestamp": self.timestamp,
        }


@dataclass
class Upload:
    id: str
    file_id: str
    user_id: str
    total_size: int
    current_offset: int
    next_chunk: int
    metadata_json: str | None
    expires_at: str
    created_at: str

    @classmethod
    def from_row(cls, row) -> "Upload":
        return cls(
            id=row["id"],
            file_id=row["file_id"],
            user_id=row["user_id"],
            total_size=row["total_size"],
            current_offset=row["current_offset"],
            next_chunk=row["next_chunk"],
            metadata_json=row["metadata_json"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
        )
