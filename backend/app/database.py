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
        # Rate limits (Phase 1)
        'rate_limit_login':              str(settings.RATE_LIMIT_LOGIN),
        'rate_limit_api':                str(settings.RATE_LIMIT_API),
        'rate_limit_share_create':       str(settings.RATE_LIMIT_SHARE_CREATE),
        'rate_limit_upload':             str(settings.RATE_LIMIT_UPLOAD),
        'rate_limit_management':         str(settings.RATE_LIMIT_MANAGEMENT),
        'rate_limit_error_threshold':    str(settings.RATE_LIMIT_ERROR_THRESHOLD),
        'rate_limit_error_window':       str(settings.RATE_LIMIT_ERROR_WINDOW),
        'rate_limit_escalated_max':      str(settings.RATE_LIMIT_ESCALATED_MAX),
        'rate_limit_escalated_window':   str(settings.RATE_LIMIT_ESCALATED_WINDOW),
        'rate_limit_escalated_duration': str(settings.RATE_LIMIT_ESCALATED_DURATION),
        # Session & auth policy (Phase 2)
        'access_token_expire_minutes':        str(settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        'refresh_token_expire_days':          str(settings.REFRESH_TOKEN_EXPIRE_DAYS),
        'session_idle_timeout_minutes':       str(settings.SESSION_IDLE_TIMEOUT_MINUTES),
        'share_session_expire_hours':         str(settings.SHARE_SESSION_EXPIRE_HOURS),
        'public_device_refresh_minutes':      str(settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES),
        'mfa_pending_token_ttl':              str(settings.MFA_PENDING_TOKEN_TTL),
        'step_up_window_seconds':             str(settings.STEP_UP_WINDOW_SECONDS),
        'step_up_max_failures':               str(settings.STEP_UP_MAX_FAILURES),
        # Operational tuning (Phase 3)
        'tus_upload_expiry_hours':  str(settings.TUS_UPLOAD_EXPIRY_HOURS),
        'upload_evict_stride_mb':   str(settings.UPLOAD_EVICT_STRIDE_MB),
        'webauthn_rp_name':         settings.WEBAUTHN_RP_NAME,
        'allow_http_idp':           'true' if settings.ALLOW_HTTP_IDP else 'false',
    }
    for key, value in defaults.items():
        await db.execute(
            "INSERT INTO admin_settings (key, value) VALUES (?, ?) ON CONFLICT DO NOTHING",
            (key, value),
        )
    await db.commit()


async def seed_policy_fields(db: Database) -> None:
    """Ensure built-in internal policy fields are present.

    Safe to re-run on every startup: uses INSERT ... ON CONFLICT DO NOTHING.
    Keeps existing installs in sync when new internal fields are added.
    """
    fields = [
        ('totp_enabled',        'TOTP MFA Enabled',               'internal', 'boolean'),
        ('webauthn_enabled',    'WebAuthn Enabled',               'internal', 'boolean'),
        ('mfa_enabled',         'MFA Enabled (TOTP or WebAuthn)', 'internal', 'boolean'),
        ('mfa_reset_required',  'MFA Reset Required',             'internal', 'boolean'),
        ('auth_provider',       'Auth Provider',                  'internal', 'string'),
        ('auth_method',         'Auth Method',                    'internal', 'string'),
        ('identity_provider',   'Identity Provider',              'internal', 'string'),
        ('role',                'Global Role',                    'internal', 'string'),
        ('is_active',           'Account Active',                 'internal', 'boolean'),
        ('has_recovery_key',    'Recovery Key Enrolled',          'internal', 'boolean'),
        ('has_asymmetric_keys', 'PQ-KEM Keys Generated',         'internal', 'boolean'),
    ]
    for name, label, source, data_type in fields:
        await db.execute(
            "INSERT INTO policy_field_definitions "
            "(name, display_label, source, data_type, claim_path) "
            "VALUES (?, ?, ?, ?, NULL) ON CONFLICT DO NOTHING",
            (name, label, source, data_type),
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
        await seed_policy_fields(db)

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

    # G22: add actor_auth_method to audit tables for service-account / human distinction.
    if 'add_actor_auth_method' not in applied and setup_sentinel in applied:
        async with conn.transaction():
            await conn.execute(
                "ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS actor_auth_method TEXT"
            )
            await conn.execute(
                "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS actor_auth_method TEXT"
            )
            await conn.execute(
                "INSERT INTO _migrations (name) VALUES ($1)", 'add_actor_auth_method'
            )
        logger.info('Migration applied: add_actor_auth_method')
        applied.add('add_actor_auth_method')

