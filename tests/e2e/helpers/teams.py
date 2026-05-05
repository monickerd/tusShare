"""
Team operation helpers.

Team creation and most member management is done via the API.
Key delivery (the encrypted team key exchange) happens client-side in the
browser, so tests that need confirmed key delivery use Playwright.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from tests.e2e.helpers.admin import ApiClient

APP_URL = os.getenv("TEST_APP_URL", "http://localhost:8001")


# ---------------------------------------------------------------------------
# Team CRUD
# ---------------------------------------------------------------------------


async def create_team(client: ApiClient, name: str, description: str = "") -> dict:
    """Create a new team using stub crypto material and return the full team dict."""
    from tests.e2e.helpers.crypto_stubs import fake_g2_point, fake_kem_bundle
    payload = {
        "name":           name,
        "description":    description,
        "pre_public_key": fake_g2_point(),
        **fake_kem_bundle(),
    }
    r = await client.post("/teams", json=payload)
    r.raise_for_status()
    team_id = r.json()["team_id"]
    return await get_team(client, team_id)


async def get_team(client: ApiClient, team_id: str) -> dict:
    r = await client.get(f"/teams/{team_id}")
    r.raise_for_status()
    return r.json()["team"]


async def list_teams(client: ApiClient) -> list[dict]:
    r = await client.get("/teams")
    r.raise_for_status()
    return r.json()["teams"]


async def update_team(client: ApiClient, team_id: str, **fields: Any) -> dict:
    r = await client.put(f"/teams/{team_id}", json=fields)
    r.raise_for_status()
    return await get_team(client, team_id)


async def delete_team(client: ApiClient, team_id: str) -> None:
    r = await client.delete(f"/teams/{team_id}")
    r.raise_for_status()


# ---------------------------------------------------------------------------
# Team members
# ---------------------------------------------------------------------------


async def add_member(
    client:   ApiClient,
    team_id:  str,
    username: str,
    role:     str = "team_member",     # "team_manager" | "team_member"
) -> dict:
    """Invite a user to the team.  Uses stub KEM material (server stores but never decrypts)."""
    from tests.e2e.helpers.crypto_stubs import fake_kem_bundle
    r = await client.post(
        f"/teams/{team_id}/members",
        json={"username": username, "role": role, **fake_kem_bundle()},
    )
    r.raise_for_status()
    return r.json()


async def list_members(client: ApiClient, team_id: str) -> list[dict]:
    r = await client.get(f"/teams/{team_id}/members")
    r.raise_for_status()
    return r.json()["members"]


async def change_member_role(
    client:         ApiClient,
    team_id:        str,
    target_user_id: str,
    new_role:       str,
) -> dict:
    r = await client.put(
        f"/teams/{team_id}/members/{target_user_id}",
        json={"role": new_role},
    )
    r.raise_for_status()
    return r.json()


async def remove_member(
    client:         ApiClient,
    team_id:        str,
    target_user_id: str,
) -> None:
    r = await client.delete(f"/teams/{team_id}/members/{target_user_id}")
    r.raise_for_status()


async def is_member(client: ApiClient, team_id: str, user_id: str) -> bool:
    members = await list_members(client, team_id)
    return any(m["user_id"] == user_id for m in members)


# ---------------------------------------------------------------------------
# Team folders
# ---------------------------------------------------------------------------


async def add_file_team_keys(
    client:   ApiClient,
    team_id:  str,
    file_ids: list[str],
) -> dict:
    """Register stub PRE file keys for the given files in a team.

    Must be called by the file owner after uploading to a team folder.
    The server stores key material verbatim (never decrypts), so stub values work.
    """
    from tests.e2e.helpers.crypto_stubs import fake_g1_point, fake_aes256_key, fake_iv_12
    file_keys = [
        {
            "file_id":            fid,
            "pre_c1":             fake_g1_point(),
            "encrypted_file_key": fake_aes256_key(),
            "key_iv":             fake_iv_12(),
        }
        for fid in file_ids
    ]
    r = await client.post(f"/teams/{team_id}/file-keys", json={"file_keys": file_keys})
    r.raise_for_status()
    return r.json()


async def add_team_folder(
    client:    ApiClient,
    team_id:   str,
    folder_id: str,
) -> dict:
    r = await client.post(
        f"/teams/{team_id}/folders",
        json={"folder_id": folder_id},
    )
    r.raise_for_status()
    return r.json()


async def list_team_folders(client: ApiClient, team_id: str) -> list[dict]:
    r = await client.get(f"/teams/{team_id}/folders")
    r.raise_for_status()
    return r.json()["folders"]


async def remove_team_folder(
    client:    ApiClient,
    team_id:   str,
    folder_id: str,
) -> None:
    r = await client.delete(f"/teams/{team_id}/folders/{folder_id}")
    r.raise_for_status()


# ---------------------------------------------------------------------------
# Team custom roles
# ---------------------------------------------------------------------------


async def create_team_role(
    client:      ApiClient,
    team_id:     str,
    name:        str,
    description: str = "",
) -> dict:
    r = await client.post(
        f"/teams/{team_id}/custom-roles",
        json={"name": name, "description": description},
    )
    r.raise_for_status()
    role_id = r.json()["role_id"]
    r2 = await client.get(f"/teams/{team_id}/custom-roles/{role_id}")
    r2.raise_for_status()
    return r2.json()["role"]


async def list_team_roles(client: ApiClient, team_id: str) -> list[dict]:
    r = await client.get(f"/teams/{team_id}/custom-roles")
    r.raise_for_status()
    return r.json()["roles"]


async def set_team_role_permissions(
    client:  ApiClient,
    team_id: str,
    role_id: str,
    flags:   dict[str, bool],
) -> dict:
    perms = {k: ("1" if v else "0") for k, v in flags.items()}
    r = await client.put(
        f"/teams/{team_id}/custom-roles/{role_id}/permissions",
        json={"permissions": perms},
    )
    r.raise_for_status()
    return r.json()


async def assign_team_role(
    client:         ApiClient,
    team_id:        str,
    role_id:        str,
    target_user_id: str,
) -> dict:
    r = await client.post(
        f"/teams/{team_id}/custom-roles/{role_id}/assignments",
        json={"user_id": target_user_id},
    )
    r.raise_for_status()
    return r.json()


async def unassign_team_role(
    client:         ApiClient,
    team_id:        str,
    role_id:        str,
    target_user_id: str,
) -> None:
    r = await client.delete(
        f"/teams/{team_id}/custom-roles/{role_id}/assignments/{target_user_id}"
    )
    r.raise_for_status()


async def delete_team_role(
    client:  ApiClient,
    team_id: str,
    role_id: str,
) -> None:
    r = await client.delete(f"/teams/{team_id}/custom-roles/{role_id}")
    r.raise_for_status()
