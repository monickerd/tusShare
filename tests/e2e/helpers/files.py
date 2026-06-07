"""
File and folder operation helpers.

File upload requires client-side encryption (AES-GCM + chunked TUS), which
runs in the browser. Download access checks are done at the API layer —
we verify HTTP status codes rather than decrypting content.

Folder CRUD and metadata operations can be driven entirely via the API.
"""

from __future__ import annotations

import io
import os
from typing import Any, Optional

import httpx

from tests.e2e.helpers.admin import ApiClient

APP_URL = os.getenv("TEST_APP_URL", "http://localhost:8001")
API     = f"{APP_URL}/api/v1"

# ---------------------------------------------------------------------------
# Folder helpers
# ---------------------------------------------------------------------------


async def create_folder(
    client: ApiClient,
    name:   str,
    parent_id: Optional[str] = None,
) -> dict:
    """Create a folder and return the response JSON."""
    payload: dict[str, Any] = {"name": name}
    if parent_id:
        payload["parent_id"] = parent_id
    r = await client.post("/folders", json=payload)
    r.raise_for_status()
    return r.json()["folder"]


async def create_folder_with_key(
    client:    ApiClient,
    name:      str,
    parent_id: Optional[str] = None,
) -> dict:
    """Create a personal folder with stub folder_key_ct/iv fields set.

    POST /folders only returns {id, name, parent_id}; this helper does a
    follow-up GET /folders/{id}/all-subfolders to retrieve the full folder
    object including the stored crypto fields.
    """
    from tests.e2e.helpers.crypto_stubs import fake_aes256_key, fake_iv_12
    payload: dict[str, Any] = {
        "name":          name,
        "folder_key_ct": fake_aes256_key(),
        "folder_key_iv": fake_iv_12(),
    }
    if parent_id:
        payload["parent_id"] = parent_id
    r = await client.post("/folders", json=payload)
    r.raise_for_status()
    folder_id = r.json()["folder"]["id"]

    # POST only returns {id, name, parent_id}; fetch the full record so callers
    # can assert on folder_key_ct / folder_key_iv.
    subtree = await client.get(f"/folders/{folder_id}/all-subfolders")
    subtree.raise_for_status()
    folders = subtree.json().get("folders", [])
    full = next((f for f in folders if f["id"] == folder_id), None)
    return full if full else r.json()["folder"]


async def get_folder_subtree(client: ApiClient, folder_id: str) -> dict:
    """Return the all-subfolders subtree for folder_id."""
    r = await client.get(f"/folders/{folder_id}/all-subfolders")
    r.raise_for_status()
    return r.json()


async def list_root(client: ApiClient) -> dict:
    """List root-level folders and files."""
    r = await client.get("/folders")
    r.raise_for_status()
    return r.json()


async def get_folder(client: ApiClient, folder_id: str) -> dict:
    r = await client.get(f"/folders/{folder_id}")
    r.raise_for_status()
    return r.json()


async def rename_folder(
    client:    ApiClient,
    folder_id: str,
    new_name:  str,
) -> dict:
    r = await client.put(f"/folders/{folder_id}", json={"name": new_name})
    r.raise_for_status()
    return r.json()["folder"]


async def move_folder(
    client:    ApiClient,
    folder_id: str,
    parent_id: Optional[str],
) -> dict:
    payload = {"parent_id": parent_id} if parent_id else {"move_to_root": True}
    r = await client.put(f"/folders/{folder_id}", json=payload)
    r.raise_for_status()
    return r.json()["folder"]


async def delete_folder(client: ApiClient, folder_id: str) -> None:
    r = await client.delete(f"/folders/{folder_id}")
    r.raise_for_status()


# ---------------------------------------------------------------------------
# File metadata helpers (non-upload)
# ---------------------------------------------------------------------------


async def get_file(client: ApiClient, file_id: str) -> dict:
    r = await client.get(f"/files/{file_id}")
    r.raise_for_status()
    return r.json()["file"]


async def rename_file(
    client:   ApiClient,
    file_id:  str,
    new_name: str,
) -> dict:
    r = await client.put(f"/files/{file_id}", json={"original_name": new_name})
    r.raise_for_status()
    return await get_file(client, file_id)


async def delete_file(client: ApiClient, file_id: str) -> None:
    r = await client.delete(f"/files/{file_id}")
    r.raise_for_status()


async def move_file_to_root(client: ApiClient, file_id: str) -> dict:
    """Move a file to the root (no parent folder) using the single-file PUT endpoint."""
    r = await client.put(f"/files/{file_id}", json={"move_to_root": True})
    r.raise_for_status()
    return await get_file(client, file_id)


async def batch_move_files(
    client:    ApiClient,
    file_ids:  list[str],
    folder_id: str,
) -> dict:
    r = await client.post(
        "/files/batch-move",
        json={"files": [{"id": fid} for fid in file_ids], "destination_folder_id": folder_id},
    )
    r.raise_for_status()
    return r.json()


async def batch_copy_files(
    client:    ApiClient,
    file_ids:  list[str],
    folder_id: str,
    file_items: Optional[list[dict]] = None,
) -> dict:
    """Copy files to destination_folder_id.

    For personal→personal copies (paths 1 and 2) no crypto fields are needed and
    file_ids is sufficient.  For cross-boundary copies, pass file_items directly
    (list of dicts with file_id + optional pre_c1/encrypted_file_key/key_iv).
    The test suite uses stub encryption so key fields are faked.
    """
    if file_items is None:
        file_items = [{"file_id": fid} for fid in file_ids]
    r = await client.post(
        "/files/batch-copy",
        json={"files": file_items, "destination_folder_id": folder_id},
    )
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Access check helpers — verify HTTP status without decrypting
# ---------------------------------------------------------------------------


async def can_get_file_meta(client: ApiClient, file_id: str) -> bool:
    """Return True if the client can read file metadata (200), False on 403/404."""
    r = await client.get(f"/files/{file_id}")
    return r.status_code == 200


async def can_download_file(client: ApiClient, file_id: str) -> bool:
    """
    Return True if the client gets a 200 on the content endpoint.

    We don't verify the decrypted bytes — the server returns the encrypted
    blob regardless; what we're checking is whether access is granted at all.
    """
    r = await client.get(f"/files/{file_id}/content")
    return r.status_code == 200


async def can_list_folder(client: ApiClient, folder_id: str) -> bool:
    r = await client.get(f"/folders/{folder_id}")
    return r.status_code == 200


async def can_list_root(client: ApiClient) -> bool:
    r = await client.get("/folders")
    return r.status_code == 200


# ---------------------------------------------------------------------------
# Admin-panel access checks
# ---------------------------------------------------------------------------


async def can_access_admin(client: ApiClient) -> bool:
    r = await client.get("/admin/settings")
    return r.status_code == 200


async def can_list_users(client: ApiClient) -> bool:
    r = await client.get("/admin/users")
    return r.status_code == 200


async def can_manage_roles(client: ApiClient) -> bool:
    r = await client.get("/admin/roles")
    return r.status_code == 200


# ---------------------------------------------------------------------------
# Share helpers
# ---------------------------------------------------------------------------


async def create_link_share(
    client:   ApiClient,
    file_ids: list[str],
    folder_ids: Optional[list[str]] = None,
    password: Optional[str] = None,
    max_downloads: Optional[int] = None,
) -> dict:
    """
    Create a public link share.

    Note: the share itself is created via the API, but the encrypted share
    keys need to be added by the frontend JS (since key wrapping happens
    client-side). This helper only creates the share record; use the browser
    for full share-with-keys flows.
    """
    payload: dict[str, Any] = {
        "share_type": "link",
        "file_ids":   file_ids,
        "folder_ids": folder_ids or [],
    }
    if password:
        payload["password"] = password
    if max_downloads is not None:
        payload["max_downloads"] = max_downloads

    r = await client.post("/shares", json=payload)
    r.raise_for_status()
    return r.json()


_SERVER_DEFAULT_CHUNK_SIZE = 5_242_880  # must match settings.DEFAULT_CHUNK_SIZE


async def tus_create_request(
    client:    ApiClient,
    folder_id: str,
    filename:  str = "test.bin",
    size:      int = 4,
) -> "httpx.Response":
    """Attempt to start a TUS upload (POST /uploads) and return the raw response.

    Use this to test upload access control without actually sending any data.
    """
    import base64 as _b64mod
    from tests.e2e.helpers.crypto_stubs import fake_aes256_key, fake_iv_12

    def _enc(s: str) -> str:
        return _b64mod.b64encode(s.encode()).decode()

    metadata = ", ".join([
        f"filename {_enc(filename)}",
        f"filetype {_enc('application/octet-stream')}",
        f"encrypted_file_key {_enc(fake_aes256_key())}",
        f"key_iv {_enc(fake_iv_12())}",
        f"chunk_size {_enc(str(_SERVER_DEFAULT_CHUNK_SIZE))}",
        f"original_size {_enc(str(size))}",
        f"folder_id {_enc(folder_id)}",
    ])
    return await client.post(
        "/uploads",
        headers={
            "Tus-Resumable": "1.0.0",
            "Upload-Length": str(size),
            "Upload-Metadata": metadata,
            "Content-Length": "0",
        },
    )


async def upload_file_api(
    client:      ApiClient,
    filename:    str,
    content:     bytes,
    folder_id:   Optional[str] = None,
    chunk_size:  int = _SERVER_DEFAULT_CHUNK_SIZE,
    key_version: Optional[str] = None,
) -> dict:
    """Upload a file via TUS using stub AES-GCM metadata.

    No real encryption is performed — content bytes are sent as-is.  The
    server stores whatever blob it receives; tests only verify HTTP status
    codes and metadata, never decrypt content.

    Pass key_version='v2-folder' to simulate an upload into a folder-key folder.

    Returns the file metadata dict from GET /files/{file_id}.
    """
    import base64 as _b64mod
    from tests.e2e.helpers.crypto_stubs import fake_aes256_key, fake_iv_12, chunk_hash

    def _enc(s: str) -> str:
        return _b64mod.b64encode(s.encode()).decode()

    metadata_parts = [
        f"filename {_enc(filename)}",
        f"filetype {_enc('application/octet-stream')}",
        f"encrypted_file_key {_enc(fake_aes256_key())}",
        f"key_iv {_enc(fake_iv_12())}",
        f"chunk_size {_enc(str(chunk_size))}",
        f"original_size {_enc(str(len(content)))}",
    ]
    if folder_id:
        metadata_parts.append(f"folder_id {_enc(folder_id)}")
    if key_version:
        metadata_parts.append(f"key_version {_enc(key_version)}")

    # Step 1 — POST to create the upload record
    r = await client.post(
        "/uploads",
        headers={
            "Tus-Resumable": "1.0.0",
            "Upload-Length":   str(len(content)),
            "Upload-Metadata": ", ".join(metadata_parts),
            "Content-Length":  "0",
        },
    )
    r.raise_for_status()

    location  = r.headers["location"]
    upload_id = location.rstrip("/").split("/")[-1]

    # Step 2 — PATCH to send the single chunk
    r2 = await client.patch(
        f"/uploads/{upload_id}",
        content=content,
        headers={
            "Tus-Resumable":  "1.0.0",
            "Content-Type":   "application/offset+octet-stream",
            "Upload-Offset":  "0",
            "X-Chunk-IV":     fake_iv_12(),
            "X-Chunk-Hash":   chunk_hash(content),
            "Content-Length": str(len(content)),
        },
    )
    r2.raise_for_status()

    file_id = r2.headers.get("x-file-id") or r2.headers.get("X-File-ID")
    if not file_id:
        raise RuntimeError(
            f"Upload finished but X-File-ID missing in response headers: {dict(r2.headers)}"
        )

    # Step 3 — return file metadata dict (unwrapped from {"file": {...}} envelope)
    r3 = await client.get(f"/files/{file_id}")
    r3.raise_for_status()
    return r3.json()["file"]


# ---------------------------------------------------------------------------
# Pending-upload helpers
# ---------------------------------------------------------------------------


async def list_pending_uploads(client: ApiClient) -> list[dict]:
    """Return the caller's incomplete TUS uploads from GET /uploads/pending."""
    r = await client.get("/uploads/pending")
    r.raise_for_status()
    return r.json().get("pending_uploads", [])


async def tus_upload_begin(
    client:               ApiClient,
    filename:             str,
    total_encrypted_size: int,
    original_size:        int,
    chunk_size:           int = _SERVER_DEFAULT_CHUNK_SIZE,
    folder_id:            Optional[str] = None,
) -> tuple[str, str]:
    """Create a TUS upload record without sending any data.

    Returns *(upload_id, location)*.  Pass the location to
    :func:`tus_upload_chunk` to send individual encrypted chunks.
    """
    import base64 as _b64mod
    from tests.e2e.helpers.crypto_stubs import fake_aes256_key, fake_iv_12

    def _enc(s: str) -> str:
        return _b64mod.b64encode(s.encode()).decode()

    metadata_parts = [
        f"filename {_enc(filename)}",
        f"filetype {_enc('application/octet-stream')}",
        f"encrypted_file_key {_enc(fake_aes256_key())}",
        f"key_iv {_enc(fake_iv_12())}",
        f"chunk_size {_enc(str(chunk_size))}",
        f"original_size {_enc(str(original_size))}",
    ]
    if folder_id:
        metadata_parts.append(f"folder_id {_enc(folder_id)}")

    r = await client.post(
        "/uploads",
        headers={
            "Tus-Resumable":   "1.0.0",
            "Upload-Length":   str(total_encrypted_size),
            "Upload-Metadata": ", ".join(metadata_parts),
            "Content-Length":  "0",
        },
    )
    r.raise_for_status()
    location  = r.headers["location"]
    upload_id = location.rstrip("/").split("/")[-1]
    return upload_id, location


async def tus_upload_chunk(
    client:    ApiClient,
    upload_id: str,
    chunk_data: bytes,
    offset:    int,
) -> tuple[int, Optional[str]]:
    """Send one encrypted chunk via PATCH.

    Returns *(new_offset, file_id)* where *file_id* is non-``None`` only when
    this chunk completes the upload and the server assigns a file ID.
    """
    from tests.e2e.helpers.crypto_stubs import fake_iv_12, chunk_hash

    r = await client.patch(
        f"/uploads/{upload_id}",
        content=chunk_data,
        headers={
            "Tus-Resumable":  "1.0.0",
            "Content-Type":   "application/offset+octet-stream",
            "Upload-Offset":  str(offset),
            "X-Chunk-IV":     fake_iv_12(),
            "X-Chunk-Hash":   chunk_hash(chunk_data),
            "Content-Length": str(len(chunk_data)),
        },
    )
    r.raise_for_status()
    new_offset = int(r.headers.get("Upload-Offset", offset + len(chunk_data)))
    file_id    = r.headers.get("x-file-id") or r.headers.get("X-File-ID")
    return new_offset, file_id or None


async def delete_share(client: ApiClient, share_id: str) -> None:
    r = await client.delete(f"/shares/{share_id}")
    r.raise_for_status()


async def list_shares(client: ApiClient) -> list[dict]:
    r = await client.get("/shares")
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Trash helpers
# ---------------------------------------------------------------------------


async def list_trash(client: ApiClient) -> dict:
    """Return {"files": [...], "folders": [...]} for all soft-deleted items."""
    r = await client.get("/trash")
    r.raise_for_status()
    return r.json()


async def restore_file_from_trash(client: ApiClient, file_id: str) -> dict:
    r = await client.post(f"/trash/files/{file_id}/restore")
    r.raise_for_status()
    return r.json()


async def restore_folder_from_trash(client: ApiClient, folder_id: str) -> dict:
    r = await client.post(f"/trash/folders/{folder_id}/restore")
    r.raise_for_status()
    return r.json()


async def permanently_delete_file_from_trash(client: ApiClient, file_id: str) -> None:
    r = await client.delete(f"/trash/files/{file_id}")
    r.raise_for_status()


async def permanently_delete_folder_from_trash(client: ApiClient, folder_id: str) -> None:
    r = await client.delete(f"/trash/folders/{folder_id}")
    r.raise_for_status()


async def empty_trash(client: ApiClient) -> dict:
    r = await client.delete("/trash")
    r.raise_for_status()
    return r.json()
