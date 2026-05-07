"""LDAP authentication and attribute-fetch provider.

Injection protection
────────────────────
Three layers prevent the app from acting as an unconstrained LDAP proxy:

1. Username whitelist (before the filter is built):
   Only characters in LDAP_USERNAME_CHARS are accepted (alphanumeric plus a
   small set of safe punctuation: . _ @ -).  Max length 64.  Inputs that fail
   this check are rejected with 401 before any LDAP connection is opened.

2. RFC-4515 escape (before substitution into the filter template):
   ldap3's escape_filter_chars() escapes the five special filter characters
   (*, (, ), \\, NUL) so a compliant LDAP server cannot misinterpret the value
   even if the whitelist were somehow bypassed.

3. Single-result assertion (after the search):
   After a successful bind + search, we assert len(entries) == 1.  Zero or
   more-than-one results are treated as authentication failure.  This prevents
   an injected wildcard from returning every user and "succeeding".

Admin-configurable filter template
────────────────────────────────────
Admins may customise user_filter (e.g. multi-condition filters for AD).
The template must contain exactly one {username} token, validated at config-
save time by validate_ldap_config().  The documentation warns that omitting
the {username} token or using wildcards in the static part of the filter
risks matching unintended accounts.

LDAP users and the KEK gap
──────────────────────────
LDAP-authenticated users do not have an OPAQUE-derived KEK, so personal file
encryption is unavailable to them.  wrapped_master_key is NULL.  Team files
and user-share KEM files are fully accessible because those key paths use
per-member PRE ciphertext / hybrid KEM, which does not depend on a personal KEK.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from app.auth.idp_crypto import decrypt_idp_config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Username input validation — applied before building any LDAP filter
# ---------------------------------------------------------------------------

_LDAP_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._@\-]{1,64}$')
_LDAPS_SCHEME = "ldaps://"

# Minimum attribute set fetched on every LDAP auth/fetch.
# Covers common AD and OpenLDAP schemas without pulling sensitive fields.
# Admins extend this per-provider via cfg["extra_attrs"].
_DEFAULT_LDAP_ATTRS = [
    "uid", "sAMAccountName",           # primary usernames
    "mail", "userPrincipalName",       # email
    "cn", "displayName", "name",       # display name
    "memberOf",                        # group membership (role mapping)
    "department", "departmentNumber",  # department (AD & inetOrgPerson schemas)
    "title", "ou",                     # title/org-unit — common policy fields
]


def _validate_ldap_username(username: str) -> str:
    """Return username if it passes the whitelist, else raise ValueError.

    This is the primary injection guard.  The character set is intentionally
    narrow: if an org uses usernames with characters not in this set (e.g.
    spaces, slashes, equal-signs), the admin should contact support — it would
    be unusual, and allowing those characters widens the injection surface.
    """
    if not _LDAP_USERNAME_RE.match(username):
        raise ValueError(
            "Username contains characters not permitted for LDAP authentication"
        )
    return username


def _validate_extra_attrs(extra) -> None:
    """Raise ValueError if extra_attrs is present but not a list of non-empty strings."""
    if extra is None:
        return
    if not isinstance(extra, list):
        raise ValueError("extra_attrs must be a list of attribute name strings")
    for attr in extra:
        if not isinstance(attr, str) or not attr.strip():
            raise ValueError("extra_attrs entries must be non-empty strings")


def _check_plaintext_ldap_tls(uri: str, tls: str) -> None:
    """Raise ValueError if plaintext ldap:// is used without STARTTLS (unless env override)."""
    import os
    if uri.startswith("ldap://") and tls != "starttls":
        if os.environ.get("TUSSHARE_ALLOW_HTTP_IDP", "").lower() not in ("1", "true", "yes"):
            raise ValueError(
                "Plaintext LDAP (ldap://) requires tls='starttls' to encrypt credentials in transit. "
                "Use ldaps:// for implicit TLS, or set tls='starttls' for a STARTTLS upgrade."
            )


def _collect_ldap_attrs(entry: dict) -> dict[str, Any]:
    """Build a flat attribute dict from an ldap3 searchResEntry."""
    raw: dict[str, Any] = {}
    for attr_name, attr_val in entry.get("attributes", {}).items():
        if isinstance(attr_val, list) and len(attr_val) == 1:
            raw[attr_name] = str(attr_val[0])
        elif isinstance(attr_val, list):
            raw[attr_name] = [str(v) for v in attr_val]
        else:
            raw[attr_name] = str(attr_val)
    return raw


def validate_ldap_config(cfg: dict[str, Any]) -> None:
    """Validate an LDAP config dict before saving.  Raises ValueError on problems.

    Checks:
    - Required fields present and non-empty.
    - user_filter contains exactly one {username} placeholder.
    - tls is one of the known values.
    - server_uri begins with ldap:// or ldaps://.
    """
    required = ("server_uri", "bind_dn", "bind_password", "base_dn", "user_filter")
    for field in required:
        if not cfg.get(field):
            raise ValueError(f"LDAP config missing required field: {field}")

    uri = cfg["server_uri"]
    if not (uri.startswith("ldap://") or uri.startswith(_LDAPS_SCHEME)):
        raise ValueError("server_uri must begin with ldap:// or ldaps://")

    filt = cfg["user_filter"]
    placeholders = re.findall(r'\{username\}', filt)
    if len(placeholders) != 1:
        raise ValueError(
            "user_filter must contain exactly one {username} placeholder "
            f"(found {len(placeholders)})"
        )

    tls = cfg.get("tls", "verify")
    if tls not in ("verify", "starttls", "skip_verify"):
        raise ValueError("tls must be 'verify', 'starttls', or 'skip_verify'")

    _validate_extra_attrs(cfg.get("extra_attrs"))

    # tls='verify' and tls='skip_verify' only activate on an ldaps:// socket — they
    # have no effect on a plaintext ldap:// connection and would silently transmit
    # credentials unencrypted.  Require starttls for plaintext-scheme URIs unless
    # TUSSHARE_ALLOW_HTTP_IDP=true (test environments where the LDAP server has no TLS).
    _check_plaintext_ldap_tls(uri, tls)


# ---------------------------------------------------------------------------
# LDAP authentication
# ---------------------------------------------------------------------------

async def ldap_authenticate(
    config_enc: str,
    username: str,
    password: str,
) -> dict[str, Any] | None:
    """Authenticate a user against the LDAP server.

    Returns a dict of raw LDAP attribute values on success, or None on failure.
    Never raises on auth failure — only on configuration/connection errors.

    Steps:
    1. Whitelist-validate the username (injection guard layer 1).
    2. Decrypt config_enc and build a Server + Connection.
    3. Service-account bind to search for the user entry.
    4. Build the search filter, substituting the RFC-4515-escaped username
       (injection guard layer 2).
    5. Search — assert exactly one result (injection guard layer 3).
    6. Re-bind as the found user entry with the supplied password to verify it.
    7. Return the entry's attribute dict.
    """
    try:
        _validate_ldap_username(username)
    except ValueError:
        logger.warning("LDAP auth rejected: username failed whitelist check")
        return None

    cfg = decrypt_idp_config(config_enc)

    return await asyncio.to_thread(_ldap_authenticate_sync, cfg, username, password)


def _ldap_authenticate_sync(
    cfg: dict[str, Any],
    username: str,
    password: str,
) -> dict[str, Any] | None:
    """Synchronous LDAP auth — runs in a thread pool via asyncio.to_thread."""
    try:
        from ldap3 import (
            Server, Connection, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND,
            SYNC, Tls, SUBTREE, NONE as GET_INFO_NONE,
        )
        from ldap3.utils.conv import escape_filter_chars
        import ssl
    except ImportError as exc:
        raise RuntimeError("ldap3 is not installed") from exc

    server_uri: str = cfg["server_uri"]
    bind_dn: str = cfg["bind_dn"]
    bind_password: str = cfg["bind_password"]
    base_dn: str = cfg["base_dn"]
    user_filter_tpl: str = cfg["user_filter"]
    tls_mode: str = cfg.get("tls", "verify")

    # Build Tls object
    if tls_mode == "skip_verify":
        tls_obj = Tls(validate=ssl.CERT_NONE)
    else:
        tls_obj = Tls(validate=ssl.CERT_REQUIRED)

    use_ssl = server_uri.startswith(_LDAPS_SCHEME)
    # get_info=NONE suppresses schema-discovery round-trips on every connection,
    # which eliminates two extra LDAP ops and the associated log noise.
    server = Server(server_uri, use_ssl=use_ssl, tls=tls_obj, connect_timeout=5, get_info=GET_INFO_NONE)

    # AUTO_BIND_TLS_BEFORE_BIND: negotiates STARTTLS *before* sending credentials.
    # AUTO_BIND_NO_TLS: used for ldaps:// (TLS is implicit in the socket layer).
    # Sending the bind before TLS is established would expose credentials in cleartext.
    svc_auto_bind = AUTO_BIND_TLS_BEFORE_BIND if tls_mode == "starttls" else AUTO_BIND_NO_TLS

    # --- Service-account bind ---
    try:
        svc_conn = Connection(
            server,
            user=bind_dn,
            password=bind_password,
            auto_bind=svc_auto_bind,
            client_strategy=SYNC,
            read_only=True,
            receive_timeout=10,
        )
        # auto_bind already bound the connection; just verify it succeeded
        if not svc_conn.bound:
            logger.error(
                "LDAP service-account bind failed — server=%s dn=%s result=%s",
                server_uri, bind_dn, svc_conn.result,
            )
            return None
    except Exception as exc:
        logger.error("LDAP service-account connect/bind error — server=%s: %s", server_uri, exc)
        return None

    try:
        # --- Layer 2: RFC-4515 escape before filter substitution ---
        safe_username = escape_filter_chars(username)
        search_filter = user_filter_tpl.replace("{username}", safe_username)
        logger.debug("LDAP search — server=%s base=%s filter=%s", server_uri, base_dn, search_filter)

        extra_attrs = cfg.get("extra_attrs") or []
        fetch_attrs = list(dict.fromkeys(_DEFAULT_LDAP_ATTRS + extra_attrs))
        svc_conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=fetch_attrs,
        )
        result_entries = [
            e for e in (svc_conn.response or [])
            if isinstance(e, dict) and e.get("type") == "searchResEntry"
        ]

        # --- Layer 3: assert exactly one result ---
        if len(result_entries) != 1:
            logger.warning(
                "LDAP search returned %d entries for user=%s (expected 1) — server=%s filter=%s — auth denied",
                len(result_entries), username, server_uri, search_filter,
            )
            return None

        user_dn = result_entries[0]["dn"]
        raw_attrs: dict[str, Any] = _collect_ldap_attrs(result_entries[0])

        logger.debug(
            "LDAP found user=%s dn=%s attrs=%s",
            username, user_dn, sorted(raw_attrs.keys()),
        )

    finally:
        try:
            svc_conn.unbind()
        except Exception:
            pass

    # --- User-DN re-bind: verify the password ---
    user_auto_bind = AUTO_BIND_TLS_BEFORE_BIND if tls_mode == "starttls" else AUTO_BIND_NO_TLS
    try:
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=user_auto_bind,
            client_strategy=SYNC,
            receive_timeout=10,
        )
        if not user_conn.bound:
            logger.info("LDAP password verify failed — user=%s dn=%s", username, user_dn)
            return None
        user_conn.unbind()
    except Exception as exc:
        logger.warning("LDAP user bind error — user=%s dn=%s: %s", username, user_dn, exc)
        return None

    logger.info("LDAP auth succeeded — user=%s server=%s", username, server_uri)
    return raw_attrs


async def ldap_fetch_attributes(
    config_enc: str,
    username: str,
) -> dict[str, Any] | None:
    """Fetch LDAP attributes for an already-authenticated user (policy re-eval).

    Uses the service account bind only (no password verification).
    Applies the same whitelist + escape + single-result guards.
    Returns None if the user cannot be found or the connection fails.
    """
    try:
        _validate_ldap_username(username)
    except ValueError:
        return None

    cfg = decrypt_idp_config(config_enc)
    return await asyncio.to_thread(_ldap_fetch_sync, cfg, username)


def _ldap_fetch_sync(cfg: dict[str, Any], username: str) -> dict[str, Any] | None:
    """Synchronous attribute fetch — runs in thread pool."""
    try:
        from ldap3 import (
            Server, Connection, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND,
            SYNC, Tls, SUBTREE, NONE as GET_INFO_NONE,
        )
        from ldap3.utils.conv import escape_filter_chars
        import ssl
    except ImportError as exc:
        raise RuntimeError("ldap3 is not installed") from exc

    server_uri = cfg["server_uri"]
    bind_dn = cfg["bind_dn"]
    bind_password = cfg["bind_password"]
    base_dn = cfg["base_dn"]
    user_filter_tpl = cfg["user_filter"]
    tls_mode = cfg.get("tls", "verify")

    use_ssl = server_uri.startswith(_LDAPS_SCHEME)
    tls_obj = Tls(validate=ssl.CERT_NONE if tls_mode == "skip_verify" else ssl.CERT_REQUIRED)
    server = Server(server_uri, use_ssl=use_ssl, tls=tls_obj, connect_timeout=5, get_info=GET_INFO_NONE)

    auto_bind = AUTO_BIND_TLS_BEFORE_BIND if tls_mode == "starttls" else AUTO_BIND_NO_TLS
    try:
        conn = Connection(
            server,
            user=bind_dn,
            password=bind_password,
            auto_bind=auto_bind,
            client_strategy=SYNC,
            read_only=True,
            receive_timeout=10,
        )
        if not conn.bound:
            logger.warning("LDAP fetch: service-account bind failed — server=%s dn=%s", server_uri, bind_dn)
            return None

        safe_username = escape_filter_chars(username)
        search_filter = user_filter_tpl.replace("{username}", safe_username)
        logger.debug("LDAP fetch — server=%s base=%s filter=%s", server_uri, base_dn, search_filter)
        extra_attrs = cfg.get("extra_attrs") or []
        fetch_attrs = list(dict.fromkeys(_DEFAULT_LDAP_ATTRS + extra_attrs))
        conn.search(base_dn, search_filter, search_scope=SUBTREE, attributes=fetch_attrs)
        result_entries = [
            e for e in (conn.response or [])
            if isinstance(e, dict) and e.get("type") == "searchResEntry"
        ]

        if len(result_entries) != 1:
            logger.debug(
                "LDAP fetch returned %d entries for user=%s (expected 1) — server=%s",
                len(result_entries), username, server_uri,
            )
            return None

        raw_attrs: dict[str, Any] = _collect_ldap_attrs(result_entries[0])

        logger.debug("LDAP fetch succeeded — user=%s attrs=%s", username, sorted(raw_attrs.keys()))
        return raw_attrs
    except Exception as exc:
        logger.warning("LDAP attribute fetch error — server=%s user=%s: %s", server_uri, username, exc)
        return None
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


async def ldap_test_connection(config_enc: str) -> dict[str, Any]:
    """Test an LDAP config: service-account bind only.

    Returns {"ok": True} or {"ok": False, "error": "<message>"}.
    Never raises.
    """
    try:
        cfg = decrypt_idp_config(config_enc)
        validate_ldap_config(cfg)
    except Exception as exc:
        return {"ok": False, "error": f"Config validation failed: {exc}"}

    return await asyncio.to_thread(_ldap_test_sync, cfg)


def _ldap_test_sync(cfg: dict[str, Any]) -> dict[str, Any]:
    try:
        from ldap3 import (
            Server, Connection, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND,
            SYNC, Tls, NONE as GET_INFO_NONE,
        )
        import ssl
    except ImportError as exc:
        return {"ok": False, "error": "ldap3 not installed"}

    tls_mode = cfg.get("tls", "verify")
    use_ssl = cfg["server_uri"].startswith(_LDAPS_SCHEME)
    tls_obj = Tls(validate=ssl.CERT_NONE if tls_mode == "skip_verify" else ssl.CERT_REQUIRED)
    server = Server(cfg["server_uri"], use_ssl=use_ssl, tls=tls_obj, connect_timeout=5, get_info=GET_INFO_NONE)

    auto_bind = AUTO_BIND_TLS_BEFORE_BIND if tls_mode == "starttls" else AUTO_BIND_NO_TLS
    try:
        conn = Connection(
            server,
            user=cfg["bind_dn"],
            password=cfg["bind_password"],
            auto_bind=auto_bind,
            client_strategy=SYNC,
            receive_timeout=10,
        )
        bound = conn.bound
        conn.unbind()
        if bound:
            return {"ok": True}
        return {"ok": False, "error": "Service-account bind failed — check bind_dn and bind_password"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
