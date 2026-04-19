"""PostgreSQL database connection manager and migration runner."""

import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import asyncpg

from app.config import settings

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "sql" / "migrations"

_pool: asyncpg.Pool | None = None

# Translate ? placeholders to $1, $2, ...
_QMARK_RE = re.compile(r'\?')
# Detect ISO-8601 datetime strings for parameter coercion to Python datetime
_ISO_DT_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')


class DuplicateError(Exception):
    """Raised when a UNIQUE constraint is violated (wraps asyncpg.UniqueViolationError)."""


def _pg_params(query: str) -> str:
    """Translate ? placeholders to $1, $2, ... for asyncpg."""
    counter = 0

    def _replace(_m: re.Match) -> str:
        nonlocal counter
        counter += 1
        return f'${counter}'

    return _QMARK_RE.sub(_replace, query)


def _coerce_params(params: tuple) -> tuple:
    """Convert ISO datetime strings to Python datetime objects for TIMESTAMPTZ params."""
    result = []
    for v in params:
        if isinstance(v, str) and _ISO_DT_RE.match(v):
            try:
                result.append(datetime.fromisoformat(v.replace('Z', '+00:00')))
                continue
            except ValueError:
                pass
        result.append(v)
    return tuple(result)


def _parse_rowcount(status: str) -> int:
    """Parse rowcount from asyncpg command tag (e.g. 'UPDATE 3', 'DELETE 0')."""
    try:
        return int(status.split()[-1])
    except (IndexError, ValueError):
        return -1


class _Row(dict):
    """dict-like row that normalises datetime → ISO string and supports integer index access."""

    def __init__(self, record: asyncpg.Record):
        items: dict[str, Any] = {}
        for k in record.keys():
            v = record[k]
            if isinstance(v, datetime):
                items[k] = v.strftime('%Y-%m-%dT%H:%M:%SZ')
            else:
                items[k] = v
        super().__init__(items)
        self._keys_list = list(items.keys())

    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(self._keys_list[key])
        return super().__getitem__(key)


class _Result:
    """Cursor-like wrapper around asyncpg query results."""

    def __init__(self, rows: list[asyncpg.Record] | None = None, rowcount: int = -1):
        self._rows = [_Row(r) for r in (rows or [])]
        self.rowcount = rowcount

    async def fetchone(self) -> _Row | None:
        return self._rows[0] if self._rows else None

    async def fetchall(self) -> list[_Row]:
        return self._rows


class Database:
    """Thin adapter wrapping an asyncpg connection with a cursor-style API.

    Translates:
      - ? placeholders  → $1, $2, ...
      - ISO datetime strings in params → Python datetime objects (for TIMESTAMPTZ)
      - asyncpg.UniqueViolationError → DuplicateError
      - asyncpg.Record rows → _Row dicts (datetime → ISO string, index access)
    """

    def __init__(self, conn: asyncpg.Connection):
        self._conn = conn

    async def execute(self, query: str, params: tuple = ()) -> _Result:
        pg_query = _pg_params(query)
        pg_params = _coerce_params(params)
        try:
            q_upper = query.strip().upper()
            if q_upper.startswith('SELECT') or 'RETURNING' in q_upper:
                rows = await self._conn.fetch(pg_query, *pg_params)
                return _Result(rows)
            else:
                status = await self._conn.execute(pg_query, *pg_params)
                return _Result([], rowcount=_parse_rowcount(status))
        except asyncpg.UniqueViolationError as exc:
            raise DuplicateError(str(exc)) from exc

    async def commit(self) -> None:
        if self._conn.is_in_transaction():
            await self._conn.execute('COMMIT')

    async def rollback(self) -> None:
        if self._conn.is_in_transaction():
            try:
                await self._conn.execute('ROLLBACK')
            except Exception:
                pass


async def get_db():
    """FastAPI dependency: yield a Database wrapping a pooled connection."""
    if _pool is None:
        raise RuntimeError('Database pool not initialized')
    async with _pool.acquire() as conn:
        yield Database(conn)


@asynccontextmanager
async def db_session():
    """Async context manager for background tasks: yields a Database."""
    if _pool is None:
        raise RuntimeError('Database pool not initialized')
    async with _pool.acquire() as conn:
        yield Database(conn)


async def seed_admin_settings(db: Database) -> None:
    """Insert admin_settings defaults from config on first run.

    Uses INSERT ... ON CONFLICT DO NOTHING so existing values set via the
    admin UI are never overwritten.  config.py (+ env vars) is the single
    source of truth for what the defaults are; the database stores overrides.
    """
    defaults = {
        'open_registration':           'true' if settings.OPEN_REGISTRATION else 'false',
        'global_max_file_size':        str(settings.GLOBAL_MAX_FILE_SIZE),
        'global_bandwidth_limit':      str(settings.GLOBAL_BANDWIDTH_LIMIT),
        'disk_warning_threshold':      str(settings.DISK_WARNING_THRESHOLD),
        'default_chunk_size':          str(settings.DEFAULT_CHUNK_SIZE),
        'allow_ephemeral_team_invites': 'false',
    }
    for key, value in defaults.items():
        await db.execute(
            "INSERT INTO admin_settings (key, value) VALUES (?, ?) ON CONFLICT DO NOTHING",
            (key, value),
        )
    await db.commit()


async def init_db() -> None:
    """Create the connection pool, run pending migrations, and seed defaults."""
    global _pool

    _pool = await asyncpg.create_pool(
        settings.DATABASE_URL,
        min_size=2,
        max_size=10,
    )

    async with _pool.acquire() as conn:
        db = Database(conn)
        await _run_migrations(db, conn)
        await seed_admin_settings(db)

    logger.info('Database pool initialised: %s', settings.DATABASE_URL)


async def close_db() -> None:
    """Close the connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info('Database connection pool closed')


def _split_statements(sql: str) -> list[str]:
    """Split a PostgreSQL SQL script into individual executable statements.

    Handles PostgreSQL dollar-quoting ($$...$$) so PL/pgSQL function bodies
    containing semicolons are not split mid-statement.
    """
    stmts: list[str] = []
    buf: list[str] = []
    dollar_depth = 0

    for line in sql.splitlines():
        stripped = line.strip()
        # Skip blank lines and comments when outside dollar-quotes
        if not stripped or (stripped.startswith('--') and dollar_depth == 0):
            continue

        # Track $$ pairs to know when we're inside a dollar-quoted body
        dollar_depth += stripped.count('$$')
        buf.append(line)

        # Statement boundary: line ends with ';' and we're not inside a quote
        if stripped.endswith(';') and dollar_depth % 2 == 0:
            stmt = '\n'.join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []

    return stmts


async def _run_migrations(db: Database, conn: asyncpg.Connection) -> None:
    """Apply pending SQL migration files in sorted order.

    Uses a _migrations tracking table.  Each migration runs inside its own
    transaction — if it fails the transaction is rolled back and the migration
    is not recorded as applied.
    """
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS _migrations (
            name       TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    rows = await conn.fetch('SELECT name FROM _migrations ORDER BY name')
    applied = {r['name'] for r in rows}

    if not MIGRATIONS_DIR.exists():
        logger.warning('Migrations directory not found: %s', MIGRATIONS_DIR)
        return

    for migration_file in sorted(MIGRATIONS_DIR.glob('*.sql')):
        name = migration_file.name
        if name in applied:
            continue

        logger.info('Applying migration: %s', name)
        sql = migration_file.read_text(encoding='utf-8')
        statements = _split_statements(sql)

        try:
            async with conn.transaction():
                if statements:
                    # Join into one simple-query call.  Sending a batch avoids
                    # the asyncpg bug where executing a single CREATE FUNCTION
                    # with a $$ body returns a None command tag, and also skips
                    # conn.execute() entirely for tombstone/comment-only files
                    # (which would trigger an EmptyQueryResponse from postgres).
                    await conn.execute('\n'.join(statements))
                await conn.execute(
                    "INSERT INTO _migrations (name) VALUES ($1)", name
                )
            logger.info('Migration applied: %s', name)
        except Exception:
            logger.exception('Migration failed: %s', name)
            raise
