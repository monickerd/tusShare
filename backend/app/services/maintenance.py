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
  - Orphaned permissions / resource_role_grants rows whose file or folder no
    longer exists (resource_id has no FK so these are never auto-cascaded)

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
from datetime import datetime, timezone

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
    """Delete bandwidth_log rows older than op_event_retention_days (default 30).

    Falls back to row-level DELETE for deployments where bandwidth_log is not
    yet partitioned; the partition manager below handles the DROP TABLE path.
    """
    retention_days = await get_admin_setting(db, "op_event_retention_days", 30, dtype=int)
    result = await db.execute(
        "DELETE FROM bandwidth_log WHERE timestamp < NOW() - (? || ' days')::interval",
        (str(retention_days),),
    )
    return result.rowcount


# ---------------------------------------------------------------------------
# Partition management for RANGE-partitioned audit tables
# ---------------------------------------------------------------------------

_PARTITIONED_AUDIT_TABLES = ("access_logs", "security_events", "bandwidth_log")

# Trigger functions to apply to each new monthly partition.
_PARTITION_TRIGGER_SQL: dict[str, str] = {
    "access_logs": "EXECUTE FUNCTION _prevent_access_log_mutation()",
    "security_events": "EXECUTE FUNCTION _prevent_security_event_mutation()",
}


async def _is_partitioned(db, table: str) -> bool:
    """Return True if the named table is a PostgreSQL partitioned table (relkind='p')."""
    row = await db.execute(
        "SELECT relkind FROM pg_class WHERE relname = ? AND relkind IN ('r', 'p')",
        (table,),
    )
    r = await row.fetchone()
    return bool(r and r["relkind"] == "p")


async def _create_partition(db, table: str, year: int, month: int) -> bool:
    """Create a monthly partition for *table* if it doesn't already exist.

    Returns True if a new partition was created.
    """
    suffix = f"{year:04d}_{month:02d}"
    partition_name = f"{table}_{suffix}"

    # Compute range boundaries
    from_dt = f"{year:04d}-{month:02d}-01"
    if month == 12:
        to_dt = f"{year + 1:04d}-01-01"
    else:
        to_dt = f"{year:04d}-{month + 1:02d}-01"

    # Skip if already exists
    r = await db.execute("SELECT 1 FROM pg_class WHERE relname = ?", (partition_name,))
    if await r.fetchone():
        return False

    await db.execute(
        f"CREATE TABLE {partition_name} PARTITION OF {table} "
        f"FOR VALUES FROM ('{from_dt}') TO ('{to_dt}')"
    )

    # Add immutability triggers to append-only partitions
    if table in _PARTITION_TRIGGER_SQL:
        fn = _PARTITION_TRIGGER_SQL[table]
        await db.execute(
            f"CREATE TRIGGER prevent_{table}_{suffix}_update "
            f"BEFORE UPDATE ON {partition_name} FOR EACH ROW {fn}"
        )
        await db.execute(
            f"CREATE TRIGGER prevent_{table}_{suffix}_delete "
            f"BEFORE DELETE ON {partition_name} FOR EACH ROW {fn}"
        )

    return True


async def _drop_expired_partition(db, table: str, year: int, month: int) -> bool:
    """Drop an expired monthly partition for *table* if it exists.

    DROP TABLE bypasses the immutability triggers — this is the intended
    retention mechanism for partitioned audit tables.
    Returns True if a partition was dropped.
    """
    suffix = f"{year:04d}_{month:02d}"
    partition_name = f"{table}_{suffix}"
    r = await db.execute("SELECT 1 FROM pg_class WHERE relname = ?", (partition_name,))
    if not await r.fetchone():
        return False
    await db.execute(f"DROP TABLE {partition_name}")
    return True


async def _manage_audit_partitions(db, retention_days: int = 30) -> dict[str, int]:
    """Create upcoming monthly partitions and drop expired ones.

    Creates partitions for the current month and the next 2 months for each
    partitioned audit table.  Drops partitions older than retention_days.

    Returns a dict with 'created' and 'dropped' counts.
    """
    created = 0
    dropped = 0

    now = datetime.now(timezone.utc)
    current_year, current_month = now.year, now.month

    def _month_offset(base_year: int, base_month: int, delta: int):
        """Return (year, month) for base + delta months (delta can be negative)."""
        total = base_year * 12 + (base_month - 1) + delta
        return total // 12, (total % 12) + 1

    for table in _PARTITIONED_AUDIT_TABLES:
        if not await _is_partitioned(db, table):
            continue

        # Create current + next 2 months
        for delta in range(3):
            y, m = _month_offset(current_year, current_month, delta)
            if await _create_partition(db, table, y, m):
                created += 1

        # Drop partitions older than retention_days.
        # Walk back month-by-month (max 10 years = 120 months).
        for months_back in range(1, 121):
            y, m = _month_offset(current_year, current_month, -months_back)
            if y < 2020:
                break
            # Partition end = start of the following month.
            end_y, end_m = _month_offset(y, m, 1)
            cutoff = datetime(end_y, end_m, 1, tzinfo=timezone.utc)
            age_days = (now - cutoff).days
            if age_days <= retention_days:
                continue  # still within retention window
            if await _drop_expired_partition(db, table, y, m):
                dropped += 1

    return {"created": created, "dropped": dropped}


async def ensure_audit_partitions(db_factory) -> None:
    """Create current + upcoming monthly partitions for all partitioned audit tables.

    Called once at startup so that new events always have a partition to land in.
    The default partition catches any rows that fall outside a specific partition.
    """
    try:
        async with db_factory() as db:
            result = await _manage_audit_partitions(db, retention_days=99999)  # no drops at startup
            await db.commit()
            if result["created"]:
                logger.info("Partition startup: created %d monthly partition(s)", result["created"])
    except Exception:
        logger.exception("Partition startup: failed to create initial partitions")


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


async def _sweep_orphaned_acl_rows(db) -> int:
    """Delete permissions / resource_role_grants rows whose resource no longer exists.

    resource_id is a plain TEXT column with no FK, so these rows are never
    auto-cascaded on file or folder deletion.  The deletion paths now clean
    them explicitly, but this sweep catches any pre-existing orphans and acts
    as a belt-and-suspenders backstop for unexpected code paths.
    """
    r1 = await db.execute(
        "DELETE FROM permissions"
        " WHERE resource_type = 'file'"
        "   AND resource_id NOT IN (SELECT id FROM files)"
    )
    r2 = await db.execute(
        "DELETE FROM permissions"
        " WHERE resource_type = 'folder'"
        "   AND resource_id NOT IN (SELECT id FROM folders)"
    )
    r3 = await db.execute(
        "DELETE FROM resource_role_grants"
        " WHERE resource_type = 'file'"
        "   AND resource_id NOT IN (SELECT id FROM files)"
    )
    r4 = await db.execute(
        "DELETE FROM resource_role_grants"
        " WHERE resource_type = 'folder'"
        "   AND resource_id NOT IN (SELECT id FROM folders)"
    )
    return r1.rowcount + r2.rowcount + r3.rowcount + r4.rowcount


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
                retention_days = await get_admin_setting(db, "op_event_retention_days", 30, dtype=int)
                result = await _manage_audit_partitions(db, retention_days=retention_days)
                await db.commit()
                if result["created"] or result["dropped"]:
                    logger.info(
                        "Maintenance: audit partitions — created %d, dropped %d",
                        result["created"], result["dropped"],
                    )
            except Exception:
                logger.exception("Maintenance: audit partition management failed")

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
                n = await _sweep_orphaned_acl_rows(db)
                await db.commit()
                if n:
                    logger.info("Maintenance: removed %d orphaned ACL row(s)", n)
            except Exception:
                logger.exception("Maintenance: orphaned ACL row sweep failed")

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
