"""
Share operation helpers.

Uses the correct CreateShareRequest format: items list with per-file or
per-folder encrypted_file_key and key_iv (stub values — server stores but
never decrypts).
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from tests.e2e.helpers.admin import ApiClient
from tests.e2e.helpers.crypto_stubs import fake_aes256_key, fake_iv_12, fake_kem_bundle, fake_x25519_pub

APP_URL = os.getenv("TEST_APP_URL", "http://localhost:8001")


def _build_link_item(file_id: str) -> dict:
    return {
        "resource_type": "file",
        "resource_id":   file_id,
        "encrypted_file_key": fake_aes256_key(),
        "key_iv":             fake_iv_12(),
    }


def _build_folder_item(folder_id: str) -> dict:
    """Build a folder-key share item (folderKey wrapped with shareKey stub)."""
    return {
        "resource_type": "folder",
        "resource_id":   folder_id,
        "encrypted_file_key": fake_aes256_key(),
        "key_iv":             fake_iv_12(),
    }


async def create_link_share(
    client:        ApiClient,
    file_ids:      list[str],
    max_downloads: Optional[int] = None,
) -> dict:
    """Create a public link share. Returns the full share dict including token."""
    payload: dict = {
        "share_type": "link",
        "items":      [_build_link_item(fid) for fid in file_ids],
    }
    if max_downloads is not None:
        payload["max_downloads"] = max_downloads
    r = await client.post("/shares", json=payload)
    r.raise_for_status()
    return r.json()


async def create_folder_key_share(
    client:        ApiClient,
    folder_ids:    list[str],
    max_downloads: Optional[int] = None,
    expiry_hours:  Optional[int] = None,
) -> dict:
    """Create a folder-key link share. Returns the full share dict including token."""
    payload: dict = {
        "share_type": "link",
        "items":      [_build_folder_item(fid) for fid in folder_ids],
    }
    if max_downloads is not None:
        payload["max_downloads"] = max_downloads
    if expiry_hours is not None:
        payload["expiry_hours"] = expiry_hours
    r = await client.post("/shares", json=payload)
    r.raise_for_status()
    return r.json()


async def list_share_exclusions(client: ApiClient, share_id: str) -> list[str]:
    """Return the list of excluded folder ID strings for a share."""
    r = await client.get(f"/shares/{share_id}/exclusions")
    r.raise_for_status()
    return r.json().get("excluded_folder_ids", [])


async def add_share_exclusion(client: ApiClient, share_id: str, folder_id: str) -> dict:
    """Add a folder to a share's exclusion list. Returns the created exclusion."""
    r = await client.post(f"/shares/{share_id}/exclusions", json={"folder_id": folder_id})
    r.raise_for_status()
    return r.json()


async def remove_share_exclusion(client: ApiClient, share_id: str, folder_id: str) -> None:
    """Remove a folder from a share's exclusion list."""
    r = await client.delete(f"/shares/{share_id}/exclusions/{folder_id}")
    r.raise_for_status()


async def list_shares(client: ApiClient) -> list[dict]:
    r = await client.get("/shares")
    r.raise_for_status()
    return r.json().get("shares", r.json())


async def delete_share(client: ApiClient, share_id: str) -> None:
    r = await client.delete(f"/shares/{share_id}")
    r.raise_for_status()


async def resolve_share_public(token: str) -> httpx.Response:
    """Resolve a share token as an anonymous client. Returns the raw response."""
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        return await client.get(f"/api/v1/s/{token}")


async def download_share_content_public(
    token:         str,
    file_id:       str,
    session_token: str,
) -> httpx.Response:
    """Download share content anonymously using the share_session_token from resolve."""
    async with httpx.AsyncClient(base_url=APP_URL) as client:
        return await client.get(
            f"/s/{token}/files/{file_id}/content",
            headers={"Authorization": f"Bearer {session_token}"},
        )


async def download_share_content_authed(
    client:  ApiClient,
    token:   str,
    file_id: str,
) -> httpx.Response:
    """Download share content as an authenticated user (bypasses share session token)."""
    return await client.get(f"/s/{token}/files/{file_id}/content")
