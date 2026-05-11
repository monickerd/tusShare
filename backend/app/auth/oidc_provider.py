"""OIDC (OpenID Connect) authentication provider.

Flow summary
────────────
1. begin_oidc_flow() — generates a cryptographically random state nonce,
   stores it in oidc_states, then returns the authorization URL to redirect
   the browser to the IdP.

2. handle_oidc_callback() — exchanges the authorization code for tokens,
   decodes and validates the ID token, optionally calls UserInfo, caches
   claims, and returns the IdP user identity dict.

3. oidc_fetch_claims() — called during policy evaluation (live_refetch mode):
   exchanges the stored encrypted refresh token for a fresh access token,
   then calls UserInfo.  Falls back to oidc_claims_cache on failure.

SSRF / security notes
─────────────────────
- issuer_url must be HTTPS, validated in validate_oidc_config() at config-save
  time (prevents cleartext MITM on the key-material discovery fetch).
- The state nonce is 32 random bytes (URL-safe base64) — prevents CSRF on the
  callback endpoint.
- authlib's JWT decoder validates iss, aud, exp, iat, and signature against the
  IdP's JWKS endpoint (fetched via the discovery document, HTTPS-only).
- redirect_uri is generated/stored server-side; the callback endpoint ignores
  any client-supplied redirect target (stored in oidc_states.redirect_to, which
  is the app-internal post-auth destination, not sent to the IdP).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlparse

from app.auth.idp_crypto import decrypt_idp_config, encrypt_token, decrypt_token
from app.services import live_settings
from app.util.ssrf import validate_endpoint_url

logger = logging.getLogger(__name__)

_OIDC_STATE_TTL = 600  # 10 minutes
_ERR_AUTHLIB_MISSING = "authlib is not installed"


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def validate_oidc_config(cfg: dict[str, Any]) -> None:
    """Validate an OIDC config dict.  Raises ValueError on problems.

    Checks:
    - Required fields present and non-empty.
    - issuer_url uses HTTPS unless TUSSHARE_ALLOW_HTTP_IDP=true is set.
      HTTPS is required by default to protect the discovery and JWKS fetches
      (which deliver the public keys the server uses to verify every ID token)
      from network-level MITM attacks.  Set ALLOW_HTTP_IDP=true for internal
      deployments that cannot provide TLS on the OIDC provider.
    - redirect_uri is a non-empty string.
    """
    from app.config import settings as _settings

    required = ("issuer_url", "client_id", "client_secret", "redirect_uri")
    for field in required:
        if not cfg.get(field):
            raise ValueError(f"OIDC config missing required field: {field}")

    parsed = urlparse(cfg["issuer_url"])
    if parsed.scheme not in ("https", "http"):
        raise ValueError("issuer_url must use http or https scheme")
    if parsed.scheme == "http" and not live_settings.get_bool("allow_http_idp", _settings.ALLOW_HTTP_IDP):
        raise ValueError(
            "issuer_url must use HTTPS to protect discovery and JWKS fetches "
            "from MITM attacks.  To allow HTTP for internal deployments, set "
            "TUSSHARE_ALLOW_HTTP_IDP=true in your environment."
        )


# ---------------------------------------------------------------------------
# OIDC client (authlib AsyncOAuth2Client)
# ---------------------------------------------------------------------------

async def _get_oidc_client(cfg: dict[str, Any]):
    """Build an authlib AsyncOAuth2Client with loaded server metadata."""
    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
    except ImportError as exc:
        raise RuntimeError(_ERR_AUTHLIB_MISSING) from exc

    import httpx
    from app.config import settings as _s

    discovery_url = cfg["issuer_url"].rstrip("/") + "/.well-known/openid-configuration"
    # When ALLOW_HTTP_IDP is set the deployment is explicitly on-premises, so
    # the IdP may resolve to a RFC 1918 address — skip the private-IP check too.
    await validate_endpoint_url(
        discovery_url,
        allow_http=live_settings.get_bool("allow_http_idp", _s.ALLOW_HTTP_IDP),
        allow_private=live_settings.get_bool("allow_http_idp", _s.ALLOW_HTTP_IDP),
    )
    # follow_redirects=False: a redirect could bypass the HTTPS/IP check above.
    async with httpx.AsyncClient(follow_redirects=False) as discovery_http:
        resp = await discovery_http.get(discovery_url, timeout=10)
        resp.raise_for_status()
        metadata = resp.json()

    scopes = cfg.get("scopes", ["openid", "email", "profile"])
    client = AsyncOAuth2Client(
        client_id=cfg["client_id"],
        client_secret=cfg["client_secret"],
        scope=" ".join(scopes),
        redirect_uri=cfg["redirect_uri"],
    )
    client.server_metadata = metadata
    return client


# ---------------------------------------------------------------------------
# Begin OIDC flow: generate state + return authorization URL
# ---------------------------------------------------------------------------

async def begin_oidc_flow(
    db,
    provider_id: str,
    config_enc: str,
    redirect_to: str | None = None,
) -> str:
    """Generate a state nonce, store it in oidc_states, and return the auth URL.

    redirect_to is an optional app-internal path (e.g. '/files') to send the
    user after successful authentication.  It is stored in oidc_states and
    must NOT be forwarded to the IdP as a redirect_uri parameter.
    """
    cfg = decrypt_idp_config(config_enc)
    validate_oidc_config(cfg)

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    now = int(time.time())
    expires_at = now + _OIDC_STATE_TTL

    await db.execute(
        "INSERT INTO oidc_states (id, provider_id, redirect_to, nonce, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (state, provider_id, redirect_to, nonce, now, expires_at),
    )
    await db.commit()

    client = await _get_oidc_client(cfg)
    uri, _ = client.create_authorization_url(
        client.server_metadata["authorization_endpoint"],
        state=state,
        nonce=nonce,
    )
    await client.aclose()
    return uri


# ---------------------------------------------------------------------------
# Handle OIDC callback: exchange code → tokens → user identity
# ---------------------------------------------------------------------------

async def handle_oidc_callback(
    db,
    provider_id: str,
    config_enc: str,
    code: str,
    state: str,
) -> dict[str, Any] | None:
    """Exchange authorization code for tokens and return a user identity dict.

    Returns None if the state is invalid/expired.
    Raises on IdP communication or JWT validation errors.

    Returned dict keys:
      sub           — IdP subject identifier (stable unique ID)
      username_attr — value of the configured username attribute (for display)
      claims        — full dict of ID token + UserInfo claims
      refresh_token — raw OIDC refresh token if offline_access was granted, else None
    """
    now = int(time.time())

    # Consume the state nonce atomically; retrieve nonce for ID token binding.
    cursor = await db.execute(
        "DELETE FROM oidc_states WHERE id = ? AND provider_id = ? AND expires_at > ? "
        "RETURNING redirect_to, nonce",
        (state, provider_id, now),
    )
    row = await cursor.fetchone()
    if row is None:
        logger.warning("OIDC callback: unknown/expired state=%s provider=%s", state, provider_id)  # NOSONAR — server-side audit log; values are Pydantic-validated
        return None

    expected_nonce = row["nonce"]  # may be None for pre-014 rows

    cfg = decrypt_idp_config(config_enc)

    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
        from authlib.jose import JsonWebToken
    except ImportError as exc:
        raise RuntimeError(_ERR_AUTHLIB_MISSING) from exc

    client = await _get_oidc_client(cfg)
    try:
        token_response = await client.fetch_token(
            client.server_metadata["token_endpoint"],
            grant_type="authorization_code",
            code=code,
            redirect_uri=cfg["redirect_uri"],
        )
    finally:
        await client.aclose()

    id_token_str = token_response.get("id_token")
    if not id_token_str:
        raise ValueError("OIDC token response missing id_token")

    from app.config import settings as _s

    # Validate URLs from the discovery doc before using them (RT-01).
    # jwks_uri and userinfo_endpoint are server-controlled and may differ from issuer_url.
    jwks_uri = client.server_metadata.get("jwks_uri")
    if not jwks_uri:
        raise ValueError("OIDC server metadata missing jwks_uri")
    await validate_endpoint_url(jwks_uri, allow_http=_s.ALLOW_HTTP_IDP, allow_private=_s.ALLOW_HTTP_IDP)

    userinfo_endpoint = client.server_metadata.get("userinfo_endpoint")
    if userinfo_endpoint:
        await validate_endpoint_url(userinfo_endpoint, allow_http=_s.ALLOW_HTTP_IDP, allow_private=_s.ALLOW_HTTP_IDP)

    # Validate ID token against IdP's JWKS, including nonce binding.
    claims = await asyncio.to_thread(
        _validate_id_token, id_token_str, cfg, client.server_metadata, expected_nonce
    )

    # Optionally call UserInfo to get additional claims
    if userinfo_endpoint:
        try:
            userinfo = await _fetch_userinfo(
                userinfo_endpoint,
                token_response.get("access_token", ""),
            )
            claims.update(userinfo)
        except Exception as exc:
            logger.warning("OIDC UserInfo fetch failed (non-fatal): %s", exc)

    sub = claims.get("sub")
    if not sub:
        raise ValueError("OIDC claims missing 'sub'")

    username_attr_name = cfg.get("username_attr", "email")
    username_val = claims.get(username_attr_name) or claims.get("email") or sub

    return {
        "sub": sub,
        "username_attr": str(username_val),
        "claims": claims,
        "refresh_token": token_response.get("refresh_token"),
    }


def _validate_id_token(
    id_token_str: str,
    cfg: dict[str, Any],
    server_metadata: dict[str, Any],
    expected_nonce: str | None = None,
) -> dict[str, Any]:
    """Validate an ID token JWT against the IdP's JWKS.  Returns claims dict."""
    from authlib.jose import JsonWebToken, JsonWebKey
    import httpx

    jwks_uri = server_metadata.get("jwks_uri")
    if not jwks_uri:
        raise ValueError("OIDC server metadata missing jwks_uri")

    # Fetch JWKS synchronously (runs in thread pool); redirects disabled (RT-02).
    resp = httpx.get(jwks_uri, timeout=10, follow_redirects=False)
    resp.raise_for_status()
    jwks = resp.json()

    # Validate iss against the issuer in the discovery document (the exact string the
    # IdP embeds in tokens). Fall back to cfg["issuer_url"] if metadata omits it.
    expected_issuer = server_metadata.get("issuer") or cfg["issuer_url"].rstrip("/")
    claims_options: dict[str, Any] = {
        "iss": {"essential": True, "value": expected_issuer},
        "aud": {"essential": True, "value": cfg["client_id"]},
    }
    # Bind nonce to prevent ID token replay across separate authorization flows.
    if expected_nonce is not None:
        claims_options["nonce"] = {"essential": True, "value": expected_nonce}

    jwt = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"])
    claims = jwt.decode(id_token_str, JsonWebKey.import_key_set(jwks), claims_options=claims_options)
    claims.validate()

    return dict(claims)


async def _fetch_userinfo(userinfo_endpoint: str, access_token: str) -> dict[str, Any]:
    """Call the UserInfo endpoint and return the claims dict."""
    import httpx
    # follow_redirects=False: a redirect could bypass the SSRF check done before this call (RT-02).
    async with httpx.AsyncClient(follow_redirects=False) as client:
        resp = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Live-refetch: exchange refresh token for fresh claims
# ---------------------------------------------------------------------------

async def oidc_fetch_claims(
    config_enc: str,
    oidc_refresh_token_enc: str,
    oidc_claims_cache: str | None,
) -> dict[str, Any]:
    """Return current OIDC claims for a user (live_refetch mode).

    Exchanges the encrypted refresh token for a fresh access token, then
    calls UserInfo.  Falls back to oidc_claims_cache on any failure so
    policy evaluation is never blocked by IdP unavailability.
    """
    import json as _json

    cfg = decrypt_idp_config(config_enc)

    try:
        refresh_token = decrypt_token(oidc_refresh_token_enc)
    except Exception as exc:
        logger.warning("Failed to decrypt OIDC refresh token: %s", exc)
        return _json.loads(oidc_claims_cache) if oidc_claims_cache else {}

    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
    except ImportError as exc:
        raise RuntimeError(_ERR_AUTHLIB_MISSING) from exc

    client = await _get_oidc_client(cfg)
    try:
        token_response = await client.fetch_token(
            client.server_metadata["token_endpoint"],
            grant_type="refresh_token",
            refresh_token=refresh_token,
        )
        access_token = token_response.get("access_token", "")
    except Exception as exc:
        logger.warning("OIDC refresh token exchange failed: %s — falling back to cache", exc)
        return _json.loads(oidc_claims_cache) if oidc_claims_cache else {}
    finally:
        await client.aclose()

    userinfo_endpoint = client.server_metadata.get("userinfo_endpoint")
    if not userinfo_endpoint:
        return _json.loads(oidc_claims_cache) if oidc_claims_cache else {}

    try:
        from app.config import settings as _s
        await validate_endpoint_url(userinfo_endpoint, allow_http=_s.ALLOW_HTTP_IDP, allow_private=_s.ALLOW_HTTP_IDP)
        claims = await _fetch_userinfo(userinfo_endpoint, access_token)
        return claims
    except Exception as exc:
        logger.warning("OIDC UserInfo failed after refresh: %s — falling back to cache", exc)
        return _json.loads(oidc_claims_cache) if oidc_claims_cache else {}


async def sweep_expired_oidc_states(db) -> int:
    """Delete oidc_states rows past their expiry; return count removed."""
    now = int(time.time())
    result = await db.execute(
        "DELETE FROM oidc_states WHERE expires_at <= ?", (now,)
    )
    await db.commit()
    return result.rowcount or 0
