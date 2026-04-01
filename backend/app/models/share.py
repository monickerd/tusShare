"""Share, ShareItem, and ShortLink models."""

from dataclasses import dataclass


@dataclass
class Share:
    id: str
    token: str
    created_by: str
    share_type: str  # 'link', 'user', 'short'
    target_user_id: str | None
    expires_at: str | None
    is_active: bool
    password_hash: str | None
    max_downloads: int | None
    download_count: int
    created_at: str

    @classmethod
    def from_row(cls, row) -> "Share":
        return cls(
            id=row["id"],
            token=row["token"],
            created_by=row["created_by"],
            share_type=row["share_type"],
            target_user_id=row["target_user_id"],
            expires_at=row["expires_at"],
            is_active=bool(row["is_active"]),
            password_hash=row["password_hash"],
            max_downloads=row["max_downloads"],
            download_count=row["download_count"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "share_type": self.share_type,
            "target_user_id": self.target_user_id,
            "expires_at": self.expires_at,
            "is_active": self.is_active,
            "has_password": self.password_hash is not None,
            "max_downloads": self.max_downloads,
            "download_count": self.download_count,
            "created_at": self.created_at,
        }


@dataclass
class ShareItem:
    id: str
    share_id: str
    resource_type: str  # 'file', 'folder'
    resource_id: str
    encrypted_file_key: str | None
    key_iv: str | None

    @classmethod
    def from_row(cls, row) -> "ShareItem":
        return cls(
            id=row["id"],
            share_id=row["share_id"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            encrypted_file_key=row["encrypted_file_key"],
            key_iv=row["key_iv"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "encrypted_file_key": self.encrypted_file_key,
            "key_iv": self.key_iv,
        }


@dataclass
class ShortLink:
    id: str
    slug: str
    share_id: str
    expires_at: str
    created_at: str

    @classmethod
    def from_row(cls, row) -> "ShortLink":
        return cls(
            id=row["id"],
            slug=row["slug"],
            share_id=row["share_id"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "share_id": self.share_id,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }
