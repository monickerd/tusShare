"""SQLite database connection manager and migration runner."""

import logging
from pathlib import Path

import aiosqlite

from app.config import settings

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "sql" / "migrations"

# Singleton connection — set during app lifespan
_db: aiosqlite.Connection | None = None


async def get_db() -> aiosqlite.Connection:
    """FastAPI dependency that returns the active database connection."""
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


async def init_db() -> aiosqlite.Connection:
    """Open the database, enforce pragmas, and run pending migrations."""
    global _db

    # Ensure data directory exists
    settings.DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    db = await aiosqlite.connect(str(settings.DB_PATH))
    db.row_factory = aiosqlite.Row

    # Enforce safety pragmas on every connection
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    await db.execute("PRAGMA busy_timeout=5000")

    await _run_migrations(db)

    _db = db
    logger.info("Database initialized at %s", settings.DB_PATH)
    return db


async def close_db() -> None:
    """Close the database connection."""
    global _db
    if _db is not None:
        await _db.close()
        _db = None
        logger.info("Database connection closed")


async def _run_migrations(db: aiosqlite.Connection) -> None:
    """Apply pending SQL migration files in sorted order.

    Tracks applied migrations in a `_migrations` table. Each migration
    file is executed atomically — if it fails, the transaction is rolled back
    and the migration is not recorded as applied.
    """
    # Create migrations tracking table if it doesn't exist
    await db.execute("""
        CREATE TABLE IF NOT EXISTS _migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
    """)
    await db.commit()

    # Get already-applied migrations
    cursor = await db.execute("SELECT name FROM _migrations ORDER BY name")
    applied = {row[0] for row in await cursor.fetchall()}

    # Find and sort migration files
    if not MIGRATIONS_DIR.exists():
        logger.warning("Migrations directory not found: %s", MIGRATIONS_DIR)
        return

    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))

    for migration_file in migration_files:
        name = migration_file.name
        if name in applied:
            continue

        logger.info("Applying migration: %s", name)
        sql = migration_file.read_text(encoding="utf-8")

        try:
            await db.executescript(sql)
            await db.execute(
                "INSERT INTO _migrations (name) VALUES (?)",
                (name,),
            )
            await db.commit()
            logger.info("Migration applied: %s", name)
        except Exception:
            logger.exception("Migration failed: %s", name)
            raise
