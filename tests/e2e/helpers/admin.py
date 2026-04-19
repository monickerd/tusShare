"""
Admin API helpers.

These talk directly to the backend API via httpx rather than driving the
browser UI. This is intentional: CRUD operations on admin resources are
most efficiently tested at the API layer, while the browser is reserved for
flows that require client-side crypto (auth, file upload).

All mutating requests include the X-CSRF-Token header (double-submit cookie
pattern — see app/middleware/csrf.py).

Usage:
    from tests.e2e.helpers.admin import AdminClient
    admin = AdminClient.from_session(session)   # session = UserSession
    invite_url = await admin.create_invite()
    await admin.set_setting("open_registration", "false")
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

APP_URL = os.getenv("TEST_APP_URL", "http://localhost:8001")
API     = f"{APP_URL}/api/v1"


class AdminClient:
    """
    Thin httpx wrapper that carries auth cookies and CSRF token for one user.

    Create with AdminClient.from_session(session) after the user has logged in
    via the browser (so auth cookies exist in the Playwright context).
    """

    def __init__(self, cookies: dict[str, str]) -> None:
        self._cookies = cookies
        self._csrf    = cookies.get("__Host-csrf_token", "")
        self._client  = httpx.AsyncClient(
            base_url=APP_URL,
            cookies=cookies,
            headers={"X-CSRF-Token": self._csrf},
            timeout=15.0,
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    @classmethod
    def from_session(cls, session: Any) -> "AdminClient":
        """Build from a helpers.auth.UserSession."""
        return cls(session.cookies)

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    #  Context manager support                                             #
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "AdminClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ #
    #  Settings                                                            #
    # ------------------------------------------------------------------ #

    async def get_settings(self) -> dict[str, str]:
        r = await self._client.get(f"{API}/admin/settings")
        r.raise_for_status()
        return r.json()["settings"]

    async def set_setting(self, key: str, value: str) -> None:
        r = await self._client.put(
            f"{API}/admin/settings",
            json={"settings": {key: value}},
        )
        r.raise_for_status()

    async def set_settings(self, settings: dict[str, str]) -> None:
        r = await self._client.put(f"{API}/admin/settings", json={"settings": settings})
        r.raise_for_status()

    # ------------------------------------------------------------------ #
    #  Invites                                                             #
    # ------------------------------------------------------------------ #

    async def create_invite(self) -> dict[str, Any]:
        """Create a single-use invite. Returns the full response JSON."""
        r = await self._client.post(f"{API}/admin/invites")
        r.raise_for_status()
        return r.json()

    async def create_invite_url(self) -> str:
        """
        Create an invite and return the full /register/{token} URL
        suitable for passing to register_via_invite().
        """
        data = await self.create_invite()
        token = data["token"]
        return f"{APP_URL}/register/{token}"

    async def list_invites(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/invites")
        r.raise_for_status()
        return r.json()["invites"]

    async def revoke_invite(self, invite_id: str) -> None:
        r = await self._client.delete(f"{API}/admin/invites/{invite_id}")
        r.raise_for_status()

    # ------------------------------------------------------------------ #
    #  Users                                                              #
    # ------------------------------------------------------------------ #

    async def list_users(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/users")
        r.raise_for_status()
        return r.json()["users"]

    async def get_user(self, user_id: str) -> dict:
        r = await self._client.get(f"{API}/admin/users/{user_id}")
        r.raise_for_status()
        return r.json()["user"]

    async def find_user_by_username(self, username: str) -> Optional[dict]:
        users = await self.list_users()
        for u in users:
            if u["username"].lower() == username.lower():
                return u
        return None

    async def update_user(self, user_id: str, **fields: Any) -> dict:
        """Update user fields: is_active, disk_quota, bandwidth_limit, max_file_size."""
        r = await self._client.put(f"{API}/admin/users/{user_id}", json=fields)
        r.raise_for_status()
        return r.json()

    async def set_user_active(self, user_id: str, active: bool) -> None:
        await self.update_user(user_id, is_active=active)

    async def delete_user(self, user_id: str) -> None:
        r = await self._client.delete(f"{API}/admin/users/{user_id}")
        r.raise_for_status()

    # ------------------------------------------------------------------ #
    #  Roles                                                              #
    # ------------------------------------------------------------------ #

    async def list_roles(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/roles")
        r.raise_for_status()
        return r.json()["roles"]

    async def create_role(self, name: str, description: str = "", role_id: Optional[str] = None) -> dict:
        """Create a custom role. role_id defaults to slugified name."""
        rid = role_id or name.lower().replace(" ", "_").replace("-", "_")
        r = await self._client.post(
            f"{API}/admin/roles",
            json={"id": rid, "name": name, "description": description},
        )
        r.raise_for_status()
        return await self.get_role(rid)

    async def get_role(self, role_id: str) -> dict:
        r = await self._client.get(f"{API}/admin/roles/{role_id}")
        r.raise_for_status()
        return r.json()["role"]

    async def update_role(self, role_id: str, **fields: Any) -> dict:
        r = await self._client.patch(f"{API}/admin/roles/{role_id}", json=fields)
        r.raise_for_status()
        return await self.get_role(role_id)

    async def delete_role(self, role_id: str) -> None:
        r = await self._client.delete(f"{API}/admin/roles/{role_id}")
        r.raise_for_status()

    async def set_role_permissions(self, role_id: str, flags: dict[str, bool]) -> dict:
        """Replace the full permission flag set for a role. Returns {flag: bool} dict."""
        str_flags = {k: ("1" if v else "0") for k, v in flags.items()}
        r = await self._client.put(
            f"{API}/admin/roles/{role_id}/permissions",
            json={"permissions": str_flags},
        )
        r.raise_for_status()
        role = await self.get_role(role_id)
        return {k: (v == "1") for k, v in role.get("permissions", {}).items()}

    async def get_user_roles(self, user_id: str) -> list[dict]:
        r = await self._client.get(f"{API}/admin/users/{user_id}/roles")
        r.raise_for_status()
        return r.json()["roles"]

    async def grant_role(self, user_id: str, role_id: str) -> None:
        r = await self._client.post(f"{API}/admin/users/{user_id}/roles/{role_id}")
        r.raise_for_status()

    async def revoke_role(self, user_id: str, role_id: str) -> None:
        r = await self._client.delete(f"{API}/admin/users/{user_id}/roles/{role_id}")
        r.raise_for_status()

    # ------------------------------------------------------------------ #
    #  Policy fields                                                      #
    # ------------------------------------------------------------------ #

    async def list_policy_fields(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/policy-fields")
        r.raise_for_status()
        return r.json()["fields"]

    async def create_policy_field(
        self,
        name:          str,
        display_label: str,
        source:        str,          # "internal" | "ldap" | "oidc"
        data_type:     str = "string",
        claim_path:    str = "",
    ) -> dict:
        r = await self._client.post(
            f"{API}/admin/policy-fields",
            json={
                "name":          name,
                "display_label": display_label,
                "source":        source,
                "data_type":     data_type,
                "claim_path":    claim_path or name,
            },
        )
        r.raise_for_status()
        return r.json()

    async def delete_policy_field(self, name: str) -> None:
        r = await self._client.delete(f"{API}/admin/policy-fields/{name}")
        r.raise_for_status()

    # ------------------------------------------------------------------ #
    #  Policies                                                           #
    # ------------------------------------------------------------------ #

    async def list_policies(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/policies")
        r.raise_for_status()
        return r.json()["policies"]

    async def create_policy(
        self,
        name:       str,
        scope_type: str = "org",
        scope_id:   Optional[str] = None,
    ) -> dict:
        payload: dict[str, Any] = {"name": name, "scope_type": scope_type}
        if scope_id:
            payload["scope_id"] = scope_id
        r = await self._client.post(f"{API}/admin/policies", json=payload)
        r.raise_for_status()
        policy_id = r.json()["id"]
        return await self.get_policy(policy_id)

    async def get_policy(self, policy_id: str) -> dict:
        r = await self._client.get(f"{API}/admin/policies/{policy_id}")
        r.raise_for_status()
        return r.json()["policy"]

    async def delete_policy(self, policy_id: str) -> None:
        r = await self._client.delete(f"{API}/admin/policies/{policy_id}")
        r.raise_for_status()

    async def add_policy_condition(
        self,
        policy_id: str,
        field:     str,
        operator:  str,   # "=" | "!=" | "contains" | "starts_with" | "in"
        value:     str,
    ) -> dict:
        r = await self._client.post(
            f"{API}/admin/policies/{policy_id}/conditions",
            json={"field": field, "operator": operator, "value": value},
        )
        r.raise_for_status()
        return r.json()

    async def delete_policy_condition(self, policy_id: str, cond_id: str) -> None:
        r = await self._client.delete(
            f"{API}/admin/policies/{policy_id}/conditions/{cond_id}"
        )
        r.raise_for_status()

    async def list_policy_effects(self, policy_id: str) -> list[dict]:
        r = await self._client.get(f"{API}/admin/policies/{policy_id}/effects")
        r.raise_for_status()
        return r.json()["effects"]

    async def create_policy_effect(
        self,
        policy_id:   str,
        effect_type: str,                   # 'folder_acl' | 'team_member' | 'team_escrow'
        target_id:   str,                   # folder_id or team_id
        permission:  Optional[str] = None,  # 'read' | 'write' | 'admin' for folder_acl
        role_level:  Optional[str] = None,  # role name for team_member
        recursive:   bool = True,
    ) -> dict:
        payload: dict[str, Any] = {
            "effect_type": effect_type,
            "target_id":   target_id,
            "recursive":   recursive,
        }
        if permission is not None:
            payload["permission"] = permission
        if role_level is not None:
            payload["role_level"] = role_level
        r = await self._client.post(
            f"{API}/admin/policies/{policy_id}/effects",
            json=payload,
        )
        r.raise_for_status()
        return r.json()

    async def delete_policy_effect(self, policy_id: str, effect_id: str) -> None:
        r = await self._client.delete(
            f"{API}/admin/policies/{policy_id}/effects/{effect_id}"
        )
        r.raise_for_status()

    # ------------------------------------------------------------------ #
    #  Disk usage                                                         #
    # ------------------------------------------------------------------ #

    async def get_disk_usage(self) -> dict:
        r = await self._client.get(f"{API}/admin/disk-usage")
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------ #
    #  Identity Providers (E6)                                            #
    # ------------------------------------------------------------------ #

    async def list_idp_providers(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/identity-providers")
        r.raise_for_status()
        return r.json()["providers"]

    async def create_idp_provider(
        self,
        provider_type: str,
        name: str,
        config: dict,
        claim_mode: Optional[str] = None,
        is_active: bool = True,
    ) -> dict:
        payload: dict[str, Any] = {
            "provider_type": provider_type,
            "name": name,
            "config": config,
            "is_active": is_active,
        }
        if claim_mode is not None:
            payload["claim_mode"] = claim_mode
        r = await self._client.post(f"{API}/admin/identity-providers", json=payload)
        r.raise_for_status()
        return r.json()

    async def get_idp_provider(self, provider_id: str) -> dict:
        r = await self._client.get(f"{API}/admin/identity-providers/{provider_id}")
        r.raise_for_status()
        return r.json()

    async def update_idp_provider(self, provider_id: str, **fields: Any) -> dict:
        r = await self._client.put(
            f"{API}/admin/identity-providers/{provider_id}", json=fields
        )
        r.raise_for_status()
        return r.json()

    async def delete_idp_provider(self, provider_id: str) -> None:
        r = await self._client.delete(f"{API}/admin/identity-providers/{provider_id}")
        r.raise_for_status()

    async def test_idp_provider(self, provider_id: str) -> dict:
        r = await self._client.post(
            f"{API}/admin/identity-providers/{provider_id}/test"
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------ #
    #  Emergency revocation (F2)                                          #
    # ------------------------------------------------------------------ #

    async def emergency_revoke(
        self,
        user_id: str,
        reason: str = "test revocation",
        scope: str = "owned_only",
        notify_escrow: bool = False,
    ) -> dict:
        """POST /admin/users/{user_id}/emergency-revoke. Returns result dict."""
        r = await self._client.post(
            f"{API}/admin/users/{user_id}/emergency-revoke",
            json={"reason": reason, "scope": scope, "notify_escrow": notify_escrow},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------ #
    #  Audit log + SIEM (E7)                                              #
    # ------------------------------------------------------------------ #

    async def query_audit_logs(self, **params: Any) -> dict:
        """GET /admin/audit/logs with optional query parameters."""
        r = await self._client.get(f"{API}/admin/audit/logs", params=params)
        r.raise_for_status()
        return r.json()

    async def export_audit_logs_raw(self, **params: Any) -> "httpx.Response":
        """GET /admin/audit/logs/export — returns raw response for header checks."""
        r = await self._client.get(f"{API}/admin/audit/logs/export", params=params)
        r.raise_for_status()
        return r

    async def list_siem_destinations(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/audit/siem")
        r.raise_for_status()
        return r.json()["destinations"]

    async def create_siem_destination(self, **fields: Any) -> dict:
        r = await self._client.post(f"{API}/admin/audit/siem", json=fields)
        r.raise_for_status()
        return r.json()

    async def update_siem_destination(self, dest_id: str, **fields: Any) -> dict:
        r = await self._client.put(f"{API}/admin/audit/siem/{dest_id}", json=fields)
        r.raise_for_status()
        return r.json()

    async def delete_siem_destination(self, dest_id: str) -> None:
        r = await self._client.delete(f"{API}/admin/audit/siem/{dest_id}")
        r.raise_for_status()

    async def test_siem_destination(self, dest_id: str) -> dict:
        r = await self._client.post(f"{API}/admin/audit/siem/{dest_id}/test")
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------ #
    #  Storage volumes (F3)                                               #
    # ------------------------------------------------------------------ #

    async def list_storage_volumes(self) -> list[dict]:
        r = await self._client.get(f"{API}/admin/storage/volumes")
        r.raise_for_status()
        return r.json()  # returns list directly

    async def get_storage_volume(self, volume_id: str) -> dict:
        r = await self._client.get(f"{API}/admin/storage/volumes/{volume_id}")
        r.raise_for_status()
        return r.json()  # returns volume dict directly

    async def get_storage_usage(self) -> dict:
        r = await self._client.get(f"{API}/admin/storage/usage")
        r.raise_for_status()
        return r.json()

    async def test_storage_volume(self, volume_id: str) -> dict:
        r = await self._client.post(f"{API}/admin/storage/volumes/{volume_id}/test")
        r.raise_for_status()
        return r.json()

    async def trigger_tiering_pass(self) -> dict:
        r = await self._client.post(f"{API}/admin/storage/tiering/trigger")
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Generic authenticated API client (for non-admin users)
# ---------------------------------------------------------------------------

class ApiClient:
    """
    Authenticated httpx client for any logged-in user (not just admins).

    Use this to test access control: create one for each user under test,
    then check what each can and cannot reach.
    """

    def __init__(self, cookies: dict[str, str]) -> None:
        self._cookies = cookies
        self._csrf    = cookies.get("__Host-csrf_token", "")
        self._client  = httpx.AsyncClient(
            base_url=APP_URL,
            cookies=cookies,
            headers={"X-CSRF-Token": self._csrf},
            timeout=15.0,
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    @classmethod
    def from_session(cls, session: Any) -> "ApiClient":
        return cls(session.cookies)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._client.get(f"{API}{path}", **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._client.post(f"{API}{path}", **kwargs)

    async def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._client.put(f"{API}{path}", **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._client.patch(f"{API}{path}", **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._client.delete(f"{API}{path}", **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "ApiClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass  # shared client — call aclose() explicitly when done
