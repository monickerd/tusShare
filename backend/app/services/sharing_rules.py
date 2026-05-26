"""Sharing restrictions: behavioral flag check + identity-scoped rule evaluation.

Two-layer enforcement called from POST /shares:
  1. check_sharing_flags()  — synchronous, fast; blocks on missing capability flag.
  2. evaluate_sharing_rules() — async; applies identity-scoped rules in priority order.

Attribute resolution
────────────────────
attribute_path format: '<source>.<attribute_name>'

  internal.{col}   users table column (username, email, display_name, created_at)
  ldap.{attr}      LDAP attribute from users.oidc_claims_cache (auth_method='ldap')
  oidc.{claim}     OIDC claim from users.oidc_claims_cache (auth_method='oidc')

Both ldap and oidc attributes are stored in the same users.oidc_claims_cache JSON
column; the auth_method column gates which source is permitted.

Evaluation model
────────────────
Rules are evaluated in ascending priority order (lower number = first evaluated).
First matching rule wins: if effect='deny' → 403; if effect='allow' → permit.
If no rule fires → permit (open by default).
All conditions within a rule are AND-ed together.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException

from app.models.role import (
    FLAG_SHARES_FOLDER_CREATE,
    FLAG_SHARES_LINK_CREATE,
    FLAG_SHARES_UPLOAD_GRANT_CREATE,
    FLAG_SHARES_USER_CREATE,
)
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus

logger = logging.getLogger(__name__)

_VALID_INTERNAL_COLS: frozenset[str] = frozenset({"username", "email", "display_name", "created_at"})
_CROSS_OPERATORS: frozenset[str] = frozenset({"cross_eq", "cross_neq"})

# Thread pool for regex evaluation with timeout (prevents ReDoS blocking the event loop)
_regex_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="re-eval")


# ---------------------------------------------------------------------------
# Layer 1 — behavioral flag check (synchronous)
# ---------------------------------------------------------------------------


def check_sharing_flags(
    actor,
    share_type: str,
    allow_upload: bool = False,
    has_items: bool = True,
    target_folder_id: str | None = None,
) -> None:
    """Raise 403 if actor lacks the required capability flag for the requested share type.

    Called at the very start of POST /shares, before any DB writes.
    """
    if share_type == "link" and not actor.has_flag(FLAG_SHARES_LINK_CREATE):
        raise HTTPException(
            status_code=403,
            detail="Link share creation is not permitted for your role",
        )
    if share_type == "user" and not actor.has_flag(FLAG_SHARES_USER_CREATE):
        raise HTTPException(
            status_code=403,
            detail="User share creation is not permitted for your role",
        )
    if allow_upload and not actor.has_flag(FLAG_SHARES_UPLOAD_GRANT_CREATE):
        raise HTTPException(
            status_code=403,
            detail="Enabling upload access on a share is not permitted for your role",
        )
    # Upload-only folder share: no items, just a target_folder_id
    if not has_items and target_folder_id and not actor.has_flag(FLAG_SHARES_FOLDER_CREATE):
        raise HTTPException(
            status_code=403,
            detail="Creating folder shares is not permitted for your role",
        )


# ---------------------------------------------------------------------------
# Layer 2 — identity-scoped rule evaluation (async)
# ---------------------------------------------------------------------------


async def _resolve_ldap_oidc_attribute(db, user_id: str, source: str, attr_name: str):
    cursor = await db.execute("SELECT oidc_claims_cache, auth_method FROM users WHERE id = ?", (user_id,))
    row = await cursor.fetchone()
    if not row or not row["oidc_claims_cache"]:
        return None
    if row["auth_method"] != source:
        return None
    try:
        claims = json.loads(row["oidc_claims_cache"])
    except (ValueError, TypeError):
        return None
    val = claims.get(attr_name)
    return val if val is not None else None


async def _resolve_attribute(db, user_id: str, attribute_path: str):
    """Resolve attribute_path for user_id. Returns the value or None if missing."""
    if "." not in attribute_path:
        return None
    source, _, attr_name = attribute_path.partition(".")

    if source == "internal":
        if attr_name not in _VALID_INTERNAL_COLS:
            return None
        cursor = await db.execute(f"SELECT {attr_name} FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        if row is None or row[attr_name] is None:
            return None
        return str(row[attr_name])

    if source in ("ldap", "oidc"):
        return await _resolve_ldap_oidc_attribute(db, user_id, source, attr_name)

    return None


def _coerce_str(value) -> str:
    if isinstance(value, list):
        return json.dumps(value)
    return str(value)


def _value_in_list(attr_value, json_list_str: str) -> bool:
    try:
        items = json.loads(json_list_str)
        if not isinstance(items, list):
            return False
    except (ValueError, TypeError):
        return False
    if isinstance(attr_value, list):
        item_strs = {str(i) for i in items}
        return any(str(v) in item_strs for v in attr_value)
    return str(attr_value) in {str(i) for i in items}


def _run_regex(pattern: str, subject: str) -> bool:
    return bool(re.search(pattern, subject))


async def _match_scalar(resolved, operator: str, value: str | None, timeout_ms: int) -> bool:
    """Apply a non-cross operator. resolved is already confirmed non-None by caller."""
    s = _coerce_str(resolved)
    if operator == "eq":
        return s == str(value)
    if operator == "neq":
        return s != str(value)
    if operator == "contains":
        return str(value) in s
    if operator == "not_contains":
        return str(value) not in s
    if operator == "starts_with":
        return s.startswith(str(value))
    if operator == "ends_with":
        return s.endswith(str(value))
    if operator == "in":
        return _value_in_list(resolved, str(value))
    if operator == "not_in":
        return not _value_in_list(resolved, str(value))
    if operator == "matches_re":
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(_regex_pool, _run_regex, str(value), s)
            return await asyncio.wait_for(future, timeout=timeout_ms / 1000.0)
        except (asyncio.TimeoutError, re.error):
            return False
    return False


async def _evaluate_condition(
    db,
    cond: dict,
    rule_subject: str,
    sender_id: str,
    recipient_id: str | None,
    timeout_ms: int,
) -> bool:
    """Evaluate one condition. Returns True if it matches (should affect the rule outcome)."""
    operator = cond["operator"]
    attribute_path = cond["attribute_path"]
    block_on_missing = bool(cond.get("block_on_missing_attribute", True))

    if operator in _CROSS_OPERATORS:
        if recipient_id is None:
            return block_on_missing
        sender_val = await _resolve_attribute(db, sender_id, attribute_path)
        recv_path = cond.get("attribute_path2") or attribute_path
        recipient_val = await _resolve_attribute(db, recipient_id, recv_path)
        if sender_val is None or recipient_val is None:
            return block_on_missing
        sv = _coerce_str(sender_val)
        rv = _coerce_str(recipient_val)
        if operator == "cross_eq":
            return sv == rv
        if operator == "cross_neq":
            return sv != rv
        return False

    # Single-party: which side to resolve depends on the rule subject
    if rule_subject == "recipient":
        target_id = recipient_id
    else:
        target_id = sender_id

    if target_id is None:
        return block_on_missing

    resolved = await _resolve_attribute(db, target_id, attribute_path)
    if resolved is None:
        return block_on_missing

    return await _match_scalar(resolved, operator, cond.get("value"), timeout_ms)


async def _conditions_all_match(
    db,
    conditions: list,
    subject: str,
    actor_id: str,
    recipient_id: str | None,
    timeout_ms: int,
) -> bool:
    for cond in conditions:
        matched = await _evaluate_condition(db, dict(cond), subject, actor_id, recipient_id, timeout_ms)
        if not matched:
            return False
    return True


async def _get_timeout_ms(db) -> int:
    cursor = await db.execute("SELECT value FROM admin_settings WHERE key = 'regex_match_timeout_ms'")
    row = await cursor.fetchone()
    try:
        return int(row["value"]) if row and row["value"] else 500
    except (ValueError, TypeError):
        return 500


async def evaluate_sharing_rules(
    db,
    actor,
    recipient_id: str | None,
    share_type: str,
    actor_ip: str | None = None,
) -> None:
    """Evaluate active sharing rules in priority order.

    Raises HTTPException(403) if a deny rule fires, returns silently otherwise.
    Called after flag check, before the DB transaction in POST /shares.
    """
    count_cursor = await db.execute("SELECT COUNT(*) FROM sharing_rules WHERE is_active = TRUE")
    count_row = await count_cursor.fetchone()
    if not count_row or count_row[0] == 0:
        return

    timeout_ms = await _get_timeout_ms(db)

    cursor = await db.execute(
        """
        SELECT id, name, subject, effect
        FROM sharing_rules
        WHERE is_active = TRUE
          AND (applies_to_share_type IS NULL OR applies_to_share_type = ?)
        ORDER BY priority ASC
        """,
        (share_type,),
    )
    rules = await cursor.fetchall()

    for rule in rules:
        subject = rule["subject"]

        # Recipient and cross rules only apply when there is a known recipient
        if subject in ("recipient", "cross") and recipient_id is None:
            continue

        cond_cursor = await db.execute(
            "SELECT * FROM sharing_rule_conditions WHERE rule_id = ? ORDER BY id",
            (rule["id"],),
        )
        conditions = await cond_cursor.fetchall()

        if not await _conditions_all_match(db, conditions, subject, actor.id, recipient_id, timeout_ms):
            continue

        # Rule fires
        if rule["effect"] == "deny":
            event_bus.emit(
                SecurityEvent(
                    event_type="share.blocked",
                    severity="info",
                    outcome="failure",
                    actor=EventActor(user_id=actor.id, username=actor.username, ip=actor_ip),
                    target=EventTarget(type="user", id=recipient_id or "", name=None) if recipient_id else None,
                    detail={
                        "block_reason": "rule",
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "share_type": share_type,
                    },
                )
            )
            raise HTTPException(
                status_code=403,
                detail=f"Share blocked by policy: {rule['name']}",
            )
        elif rule["effect"] == "allow":
            return  # explicit allow — stop evaluation


async def simulate_sharing_rules(
    db,
    sender_id: str,
    recipient_id: str | None,
    share_type: str,
) -> list[dict]:
    """Dry-run rule evaluation. Returns list of rules that would fire (for admin test endpoint).

    Never raises; never emits events.  Returns all matching rules in evaluation order,
    stopping at the first allow (same first-match-wins semantics as the live path).
    """
    timeout_ms = await _get_timeout_ms(db)

    cursor = await db.execute(
        """
        SELECT id, name, subject, effect, priority
        FROM sharing_rules
        WHERE is_active = TRUE
          AND (applies_to_share_type IS NULL OR applies_to_share_type = ?)
        ORDER BY priority ASC
        """,
        (share_type,),
    )
    rules = await cursor.fetchall()

    results = []
    for rule in rules:
        subject = rule["subject"]
        if subject in ("recipient", "cross") and recipient_id is None:
            continue

        cond_cursor = await db.execute(
            "SELECT * FROM sharing_rule_conditions WHERE rule_id = ? ORDER BY id",
            (rule["id"],),
        )
        conditions = await cond_cursor.fetchall()

        matched_conditions = []
        all_match = True
        for cond in conditions:
            m = await _evaluate_condition(db, dict(cond), subject, sender_id, recipient_id, timeout_ms)
            matched_conditions.append(
                {
                    "attribute_path": cond["attribute_path"],
                    "operator": cond["operator"],
                    "matched": m,
                }
            )
            if not m:
                all_match = False
                break

        if not all_match:
            continue

        results.append(
            {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "priority": rule["priority"],
                "effect": rule["effect"],
                "matched_conditions": matched_conditions,
            }
        )

        if rule["effect"] == "allow":
            break  # first-match-wins

    return results
