"""File and Folder models."""

from dataclasses import dataclass


@dataclass
class Folder:
    id: str
    name: str
    parent_id: str | None
    owner_id: str
    is_shared: bool
    restrict_permissions: bool
    created_at: str
    updated_at: str
    deleted_at: str | None = None
    deleted_by: str | None = None

    @classmethod
    def from_row(cls, row) -> "Folder":
        return cls(
            id=row["id"],
            name=row["name"],
            parent_id=row["parent_id"],
            owner_id=row["owner_id"],
            is_shared=bool(row["is_shared"]),
            restrict_permissions=bool(row["restrict_permissions"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            deleted_at=row.get("deleted_at"),
            deleted_by=row.get("deleted_by"),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "parent_id": self.parent_id,
            "owner_id": self.owner_id,
            "is_shared": self.is_shared,
            "restrict_permissions": self.restrict_permissions,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "deleted_at": self.deleted_at,
        }


@dataclass
class File:
    id: str
    original_name: str
    sanitized_name: str
    storage_key: str
    folder_id: str | None
    owner_id: str
    mime_type: str
    size_bytes: int
    encrypted_size: int
    chunk_size: int
    total_chunks: int
    encrypted_file_key: str
    key_iv: str
    checksum_sha256: str | None
    upload_complete: bool
    created_at: str
    updated_at: str
    deleted_at: str | None = None
    deleted_by: str | None = None
    last_modified_ms: int | None = None

    @classmethod
    def from_row(cls, row) -> "File":
        return cls(
            id=row["id"],
            original_name=row["original_name"],
            sanitized_name=row["sanitized_name"],
            storage_key=row["storage_key"],
            folder_id=row["folder_id"],
            owner_id=row["owner_id"],
            mime_type=row["mime_type"],
            size_bytes=row["size_bytes"],
            encrypted_size=row["encrypted_size"],
            chunk_size=row["chunk_size"],
            total_chunks=row["total_chunks"],
            encrypted_file_key=row["encrypted_file_key"],
            key_iv=row["key_iv"],
            checksum_sha256=row["checksum_sha256"],
            upload_complete=bool(row["upload_complete"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            deleted_at=row.get("deleted_at"),
            deleted_by=row.get("deleted_by"),
            last_modified_ms=row.get("last_modified_ms"),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "original_name": self.original_name,
            "sanitized_name": self.sanitized_name,
            "folder_id": self.folder_id,
            "owner_id": self.owner_id,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "encrypted_size": self.encrypted_size,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "encrypted_file_key": self.encrypted_file_key,
            "key_iv": self.key_iv,
            "checksum_sha256": self.checksum_sha256,
            "upload_complete": self.upload_complete,
            "created_at": self.created_at,
            "deleted_at": self.deleted_at,
            "last_modified_ms": self.last_modified_ms,
        }


@dataclass
class FileChunk:
    id: str
    file_id: str
    chunk_index: int
    iv: str
    size_bytes: int
    offset: int

    @classmethod
    def from_row(cls, row) -> "FileChunk":
        return cls(
            id=row["id"],
            file_id=row["file_id"],
            chunk_index=row["chunk_index"],
            iv=row["iv"],
            size_bytes=row["size_bytes"],
            offset=row["offset"],
        )

    def to_dict(self) -> dict:
        return {
            "chunk_index": self.chunk_index,
            "iv": self.iv,
            "size_bytes": self.size_bytes,
            "offset": self.offset,
        }
