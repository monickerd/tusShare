"""Daily maintenance sweep.

Runs once at startup then every 24 hours.  Handles low-volume housekeeping
that the frequent short-interval workers miss.

Auto-fixed (safe deletes):
  - Expired unused registration invites
  - Short-links past their expiry date (normally CASCADE-deleted with the share,
    but catches any survivors from edge cases)
  - bandwidth_log rows older than op_event_retention_days (default 30 days)
  - pending_share_keying rows older than 90 days (the share is gone or expired;
    these rows will never be fulfilled)

Flagged for manual review (warning log + security event, no auto-fix):
  - Teams whose owner is inactive (is_active=0) or scheduled for deletion
    (scheduled_delete_at IS NOT NULL).  Transferring team ownership requires
    re-keying PRE material and must be done by an admin through the UI.

Self-healing:
  - users.disk_used drift vs. actual SUM(files.encrypted_size).  Any mismatch
    is corrected atomically; the correction is logged at WARNING level so it
    appears in SIEM output.
"""

import asyncio
import logging

from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus
from app.util.db import get_admin_setting

logger = logging.getLogger(__name__)

_STALE_SHARE_KEYING_DAYS = 90


# ---------------------------------------------------------------------------
# Auto-fixed sweeps
# ---------------------------------------------------------------------------

async def _sweep_expired_invites(db) -> int:
    """Delete registration invites that expired without being used."""
    result = await db.execute(
        "DELETE FROM invites WHERE expires_at < NOW() AND used_at IS NULL"
    )
    return result.rowcount


async def _sweep_stale_short_links(db) -> int:
    """Delete short-links past their expiry.

    Normally removed by CASCADE when the parent share is deleted or expires,
    but orphaned rows can accumulate if shares are hard-deleted out-of-band.
    """
    result = await db.execute("DELETE FROM short_links WHERE expires_at < NOW()")
    return result.rowcount


async def _sweep_bandwidth_log(db) -> int:
    """Delete bandwidth_log rows older than op_event_retention_days (default 30)."""
    retention_days = await get_admin_setting(db, "op_event_retention_days", 30, dtype=int)
    result = await db.execute(
        "DELETE FROM bandwidth_log WHERE timestamp < NOW() - (? || ' days')::interval",
        (str(retention_days),),
    )
    return result.rowcount


async def _sweep_stale_pending_share_keying(db) -> int:
    """Delete pending_share_keying rows older than 90 days.

    These rows are created when a file is uploaded into a shared folder so
    the share recipient can re-key the file.  After 90 days the share is
    almost certainly expired or deleted; the rows are safe to remove.
    """
    result = await db.execute(
        "DELETE FROM pending_share_keying "
        "WHERE created_at < NOW() - INTERVAL '90 days'"
    )
    return result.rowcount


# ---------------------------------------------------------------------------
# Manual-review flags
# ---------------------------------------------------------------------------

async def _flag_ownerless_teams(db) -> int:
    """Warn about teams whose owner is inactive or scheduled for deletion.

    Team ownership transfer requires crypto re-keying and cannot be automated.
    Each affected team emits a security event so it appears in the audit log.
    Returns the number of affected teams.
    """
    cursor = await db.execute(
        """
        SELECT t.id, t.name, u.id AS owner_id, u.username AS owner_username,
               u.is_active, u.scheduled_delete_at
        FROM   teams t
        JOIN   users u ON t.owner_id = u.id
        WHERE  u.is_active = 0
           OR  u.scheduled_delete_at IS NOT NULL
        """
    )
    rows = await cursor.fetchall()

    for row in rows:
        reason = (
            "owner is inactive"
            if not row["is_active"]
            else "owner is scheduled for deletion"
        )
        logger.warning(
            "Team '%s' (%s) has no active owner: %s (%s) — %s. "
            "An admin must transfer ownership via the admin panel.",
            row["name"], row["id"],
            row["owner_username"], row["owner_id"],
            reason,
        )
        event_bus.emit(
            SecurityEvent(
                event_type="system.team.ownerless",
                severity="warning",
                outcome="none",
                actor=EventActor(user_id="system", username="system"),
                target=EventTarget(type="team", id=row["id"], name=row["name"]),
                detail={
                    "owner_id": row["owner_id"],
                    "owner_username": row["owner_username"],
                    "reason": reason,
                },
            )
        )

    return len(rows)


# ---------------------------------------------------------------------------
# Self-healing
# ---------------------------------------------------------------------------

async def _reconcile_disk_usage(db) -> int:
    """Correct users.disk_used when it diverges from actual file storage.

    Uses a single aggregation query to find all drifted users, then corrects
    each one atomically.  Any correction is logged at WARNING level.
    Returns the number of users corrected.
    """
    cursor = await db.execute(
        """
        SELECT u.id,
               u.username,
               u.disk_used,
               COALESCE(SUM(f.encrypted_size), 0) AS actual_used
        FROM   users u
        LEFT JOIN files f
               ON  f.owner_id = u.id
               AND f.upload_complete = 1
               AND f.deleted_at IS NULL
        GROUP  BY u.id, u.username, u.disk_used
        HAVING u.disk_used != COALESCE(SUM(f.encrypted_size), 0)
        """
    )
    rows = await cursor.fetchall()

    for row in rows:
        user_id   = row["id"]
        username  = row["username"]
        recorded  = row["disk_used"]
        actual    = row["actual_used"]
        logger.warning(
            "disk_used drift for user %s (%s): recorded=%d actual=%d — correcting",
            username, user_id, recorded, actual,
        )
        await db.execute(
            "UPDATE users SET disk_used = GREATEST(0, ?) WHERE id = ?",
            (actual, user_id),
        )

    if rows:
        await db.commit()

    return len(rows)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def run_daily_maintenance(db_factory, interval: float = 86400.0) -> None:
    """Periodic background task — runs all maintenance sweeps once per day.

    Sleeps first so startup latency doesn't delay the first request cycle.
    Each sweep runs in its own try/except so one failure doesn't skip the rest.
    """
    while True:
        await asyncio.sleep(interval)
        logger.info("Daily maintenance sweep starting")

        async with db_factory() as db:
            try:
                n = await _sweep_expired_invites(db)
                await db.commit()
                if n:
                    logger.info("Maintenance: removed %d expired invite(s)", n)
            except Exception:
                logger.exception("Maintenance: expired invite sweep failed")

        async with db_factory() as db:
            try:
                n = await _sweep_stale_short_links(db)
                await db.commit()
                if n:
                    logger.info("Maintenance: removed %d stale short-link(s)", n)
            except Exception:
                logger.exception("Maintenance: short-link sweep failed")

        async with db_factory() as db:
            try:
                n = await _sweep_bandwidth_log(db)
                await db.commit()
                if n:
                    logger.info("Maintenance: removed %d old bandwidth_log row(s)", n)
            except Exception:
                logger.exception("Maintenance: bandwidth_log sweep failed")

        async with db_factory() as db:
            try:
                n = await _sweep_stale_pending_share_keying(db)
                await db.commit()
                if n:
                    logger.info("Maintenance: removed %d stale pending_share_keying row(s)", n)
            except Exception:
                logger.exception("Maintenance: pending_share_keying sweep failed")

        async with db_factory() as db:
            try:
                n = await _flag_ownerless_teams(db)
                if n:
                    logger.info("Maintenance: flagged %d ownerless team(s) for manual review", n)
            except Exception:
                logger.exception("Maintenance: ownerless team check failed")

        async with db_factory() as db:
            try:
                n = await _reconcile_disk_usage(db)
                if n:
                    logger.info("Maintenance: corrected disk_used for %d user(s)", n)
            except Exception:
                logger.exception("Maintenance: disk usage reconciliation failed")

        logger.info("Daily maintenance sweep complete")
