"""PostgreSQL database connection manager."""

import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import asyncpg

from app.config import settings

logger = logging.getLogger(__name__)

SETUP_DIR = Path(__file__).parent / "sql" / "setup"

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

    async def fetchone(self) -> _Row | None:  # NOSONAR — async for interface consistency with real cursors
        return self._rows[0] if self._rows else None

    async def fetchall(self) -> list[_Row]:  # NOSONAR — async for interface consistency with real cursors
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
            # WITH [RECURSIVE] ... SELECT ... CTEs start with WITH, not SELECT.
            is_query = (
                q_upper.startswith('SELECT')
                or q_upper.startswith('WITH')
                or 'RETURNING' in q_upper
            )
            if is_query:
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
    """Create the connection pool, initialise the schema, and seed defaults."""
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


async def _run_migrations(_db: Database, conn: asyncpg.Connection) -> None:
    """Initialise the schema on a fresh install.

    Runs setup/schema.sql once and records 'schema_v1' in _migrations.
    Subsequent startups see the sentinel and skip the setup step.
    """
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS _migrations (
            name       TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    rows = await conn.fetch('SELECT name FROM _migrations ORDER BY name')
    applied = {r['name'] for r in rows}

    # Fresh install: no migrations have run yet — initialise from setup schema.
    setup_sentinel = 'schema_v1'
    if setup_sentinel not in applied and not applied:
        setup_file = SETUP_DIR / 'schema.sql'
        if not setup_file.exists():
            raise RuntimeError(f'Setup schema not found: {setup_file}')
        logger.info('Fresh database — initialising from %s', setup_file.name)
        sql = setup_file.read_text(encoding='utf-8')
        statements = _split_statements(sql)
        async with conn.transaction():
            if statements:
                await conn.execute('\n'.join(statements))
            await conn.execute("INSERT INTO _migrations (name) VALUES ($1)", setup_sentinel)
        logger.info('Schema initialised: %s', setup_sentinel)
        applied.add(setup_sentinel)

    # Incremental migrations — applied in order to existing databases.
    _INCREMENTAL_MIGRATIONS: list[tuple[str, list[str]]] = [
        ("migrate_trash_v1", [
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL",
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS deleted_by TEXT REFERENCES users(id) ON DELETE SET NULL DEFAULT NULL",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS deleted_by TEXT REFERENCES users(id) ON DELETE SET NULL DEFAULT NULL",
            "CREATE INDEX IF NOT EXISTS idx_files_deleted_at   ON files(deleted_at)   WHERE deleted_at IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_folders_deleted_at ON folders(deleted_at) WHERE deleted_at IS NOT NULL",
            "INSERT INTO admin_settings (key, value) VALUES ('trash_enabled', 'true') ON CONFLICT DO NOTHING",
            "INSERT INTO admin_settings (key, value) VALUES ('trash_retention_days', '30') ON CONFLICT DO NOTHING",
        ]),
        ("migrate_settings_v2", [
            "INSERT INTO admin_settings (key, value) VALUES ('can_delete_owned_shared', 'false') ON CONFLICT DO NOTHING",
        ]),
        ("migrate_copy_v1", [
            # Allow multiple files to share the same blob (blob ref-counting for copies)
            "ALTER TABLE files DROP CONSTRAINT IF EXISTS files_storage_key_key",
            # can_copy_files permission flag
            "INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES ('can_copy_files', 'May copy files within copy_boundary policy', 'files', 0) ON CONFLICT DO NOTHING",
            "INSERT INTO role_permissions (role_id, flag, value) VALUES ('server_admin',      'can_copy_files', '1') ON CONFLICT DO NOTHING",
            "INSERT INTO role_permissions (role_id, flag, value) VALUES ('org_admin',         'can_copy_files', '1') ON CONFLICT DO NOTHING",
            "INSERT INTO role_permissions (role_id, flag, value) VALUES ('operational_admin', 'can_copy_files', '1') ON CONFLICT DO NOTHING",
            "INSERT INTO role_permissions (role_id, flag, value) VALUES ('team_admin',        'can_copy_files', '1') ON CONFLICT DO NOTHING",
            "INSERT INTO role_permissions (role_id, flag, value) VALUES ('team_manager',      'can_copy_files', '1') ON CONFLICT DO NOTHING",
            "INSERT INTO role_permissions (role_id, flag, value) VALUES ('role_admin',        'can_copy_files', '1') ON CONFLICT DO NOTHING",
            "INSERT INTO role_permissions (role_id, flag, value) VALUES ('role_user',         'can_copy_files', '1') ON CONFLICT DO NOTHING",
            # copy_boundary admin setting (any | same_team | disabled)
            "INSERT INTO admin_settings (key, value) VALUES ('copy_boundary', 'any') ON CONFLICT DO NOTHING",
        ]),
        # Phase 1 permissions overhaul — foundation schema
        ("migrate_phase1_permissions_v1", [
            # Configurable team-role → folder permission level mapping.
            # One row per (team, role) pair where the default has been overridden.
            # Missing rows fall back to the hardcoded default in _access.py.
            """
            CREATE TABLE IF NOT EXISTS team_folder_role_levels (
                team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
                role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                level      TEXT NOT NULL DEFAULT 'write'
                               CHECK (level IN ('admin', 'write', 'read', 'none')),
                updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (team_id, role_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_tfrl_team ON team_folder_role_levels(team_id)",
            # Extend permissions.permission to support fine-grained grants and explicit deny.
            # Preserves existing read/write/admin semantics (read still implies download).
            "ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_permission_check",
            """
            ALTER TABLE permissions ADD CONSTRAINT permissions_permission_check
                CHECK (permission IN (
                    'read', 'write', 'admin',
                    'download', 'delete', 'rename', 'manage_permissions',
                    'deny'
                ))
            """,
            # Scoped admin flag grants: allow users to hold admin permission flags
            # limited to a specific team scope without holding the flag org-wide.
            # One row per (user, flag, scope) triple — supplements role_permissions
            # for delegated admins whose authority is narrower than org-wide.
            """
            CREATE TABLE IF NOT EXISTS admin_scope_grants (
                id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                flag       TEXT NOT NULL REFERENCES role_permission_flags(flag) ON DELETE CASCADE,
                scope_type TEXT NOT NULL CHECK (scope_type IN ('team')),
                scope_id   TEXT NOT NULL,
                granted_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (user_id, flag, scope_type, scope_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_asg_user       ON admin_scope_grants(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_asg_scope      ON admin_scope_grants(scope_type, scope_id)",
            "CREATE INDEX IF NOT EXISTS idx_asg_user_flag  ON admin_scope_grants(user_id, flag)",
        ]),
    ]
    for name, stmts in _INCREMENTAL_MIGRATIONS:
        if name not in applied:
            async with conn.transaction():
                for stmt in stmts:
                    await conn.execute(stmt)
                await conn.execute("INSERT INTO _migrations (name) VALUES ($1)", name)
            applied.add(name)
            logger.info('Migration applied: %s', name)

