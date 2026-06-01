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
_QMARK_RE = re.compile(r"\?")
# Detect ISO-8601 datetime strings for parameter coercion to Python datetime
_ISO_DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class DuplicateError(Exception):
    """Raised when a UNIQUE constraint is violated (wraps asyncpg.UniqueViolationError)."""


def _pg_params(query: str) -> str:
    """Translate ? placeholders to $1, $2, ... for asyncpg."""
    counter = 0

    def _replace(_m: re.Match) -> str:
        nonlocal counter
        counter += 1
        return f"${counter}"

    return _QMARK_RE.sub(_replace, query)


def _coerce_params(params: tuple) -> tuple:
    """Convert ISO datetime strings to Python datetime objects for TIMESTAMPTZ params."""
    result = []
    for v in params:
        if isinstance(v, str) and _ISO_DT_RE.match(v):
            try:
                result.append(datetime.fromisoformat(v.replace("Z", "+00:00")))
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
                items[k] = v.strftime("%Y-%m-%dT%H:%M:%SZ")
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
            is_query = q_upper.startswith("SELECT") or q_upper.startswith("WITH") or "RETURNING" in q_upper
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
            await self._conn.execute("COMMIT")

    async def rollback(self) -> None:
        if self._conn.is_in_transaction():
            try:
                await self._conn.execute("ROLLBACK")
            except Exception:
                pass


async def get_db():
    """FastAPI dependency: yield a Database wrapping a pooled connection."""
    if _pool is None:
        raise RuntimeError("Database pool not initialized")
    async with _pool.acquire() as conn:
        yield Database(conn)


@asynccontextmanager
async def db_session():
    """Async context manager for background tasks: yields a Database."""
    if _pool is None:
        raise RuntimeError("Database pool not initialized")
    async with _pool.acquire() as conn:
        yield Database(conn)


async def seed_admin_settings(db: Database) -> None:
    """Insert admin_settings defaults from config on first run.

    Uses INSERT ... ON CONFLICT DO NOTHING so existing values set via the
    admin UI are never overwritten.  config.py (+ env vars) is the single
    source of truth for what the defaults are; the database stores overrides.
    """
    defaults = {
        "open_registration": "true" if settings.OPEN_REGISTRATION else "false",
        "global_max_file_size": str(settings.GLOBAL_MAX_FILE_SIZE),
        "global_bandwidth_limit": str(settings.GLOBAL_BANDWIDTH_LIMIT),
        "disk_warning_threshold": str(settings.DISK_WARNING_THRESHOLD),
        "default_chunk_size": str(settings.DEFAULT_CHUNK_SIZE),
        "allow_ephemeral_team_invites": "false",
        # Rate limits (Phase 1)
        "rate_limit_login": str(settings.RATE_LIMIT_LOGIN),
        "rate_limit_api": str(settings.RATE_LIMIT_API),
        "rate_limit_share_create": str(settings.RATE_LIMIT_SHARE_CREATE),
        "rate_limit_upload": str(settings.RATE_LIMIT_UPLOAD),
        "rate_limit_management": str(settings.RATE_LIMIT_MANAGEMENT),
        "rate_limit_error_threshold": str(settings.RATE_LIMIT_ERROR_THRESHOLD),
        "rate_limit_error_window": str(settings.RATE_LIMIT_ERROR_WINDOW),
        "rate_limit_escalated_max": str(settings.RATE_LIMIT_ESCALATED_MAX),
        "rate_limit_escalated_window": str(settings.RATE_LIMIT_ESCALATED_WINDOW),
        "rate_limit_escalated_duration": str(settings.RATE_LIMIT_ESCALATED_DURATION),
        # Session & auth policy (Phase 2)
        "access_token_expire_minutes": str(settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "refresh_token_expire_days": str(settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "session_idle_timeout_minutes": str(settings.SESSION_IDLE_TIMEOUT_MINUTES),
        "share_session_expire_hours": str(settings.SHARE_SESSION_EXPIRE_HOURS),
        "public_device_refresh_minutes": str(settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES),
        "mfa_pending_token_ttl": str(settings.MFA_PENDING_TOKEN_TTL),
        "step_up_window_seconds": str(settings.STEP_UP_WINDOW_SECONDS),
        "step_up_max_failures": str(settings.STEP_UP_MAX_FAILURES),
        # Operational tuning (Phase 3)
        "tus_upload_expiry_hours": str(settings.TUS_UPLOAD_EXPIRY_HOURS),
        "upload_evict_stride_mb": str(settings.UPLOAD_EVICT_STRIDE_MB),
        "webauthn_rp_name": settings.WEBAUTHN_RP_NAME,
        "allow_http_idp": "true" if settings.ALLOW_HTTP_IDP else "false",
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
        ("totp_enabled", "TOTP MFA Enabled", "internal", "boolean"),
        ("webauthn_enabled", "WebAuthn Enabled", "internal", "boolean"),
        ("mfa_enabled", "MFA Enabled (TOTP or WebAuthn)", "internal", "boolean"),
        ("mfa_reset_required", "MFA Reset Required", "internal", "boolean"),
        ("auth_provider", "Auth Provider", "internal", "string"),
        ("auth_method", "Auth Method", "internal", "string"),
        ("identity_provider", "Identity Provider", "internal", "string"),
        ("role", "Global Role", "internal", "string"),
        ("is_active", "Account Active", "internal", "boolean"),
        ("has_recovery_key", "Recovery Key Enrolled", "internal", "boolean"),
        ("has_asymmetric_keys", "PQ-KEM Keys Generated", "internal", "boolean"),
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
        min_size=5,
        max_size=50,
        statement_cache_size=0,   # required for PgBouncer transaction-mode pooling
    )

    async with _pool.acquire() as conn:
        db = Database(conn)
        await _run_migrations(db, conn)
        await seed_admin_settings(db)
        await seed_policy_fields(db)

    logger.info("Database pool initialised: %s", settings.DATABASE_URL)


async def close_db() -> None:
    """Close the connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database connection pool closed")


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
        if not stripped or (stripped.startswith("--") and dollar_depth == 0):
            continue

        # Track $$ pairs to know when we're inside a dollar-quoted body
        dollar_depth += stripped.count("$$")
        buf.append(line)

        # Statement boundary: line ends with ';' and we're not inside a quote
        if stripped.endswith(";") and dollar_depth % 2 == 0:
            stmt = "\n".join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []

    return stmts


async def _run_migrations(_db: Database, conn: asyncpg.Connection) -> None:
    """Initialise the schema on a fresh install and apply idempotent additions.

    Checks whether the database is empty (no 'users' table) and runs
    setup/schema.sql if so.  Assumes a clean-slate install — no incremental
    migrations are supported.

    After the fresh-install block, idempotent DDL runs on every startup so
    new tables added to the codebase appear on existing databases without a
    full reinstall.
    """
    table_exists = await conn.fetchval(
        "SELECT EXISTS ("
        "  SELECT 1 FROM information_schema.tables"
        "  WHERE table_schema = 'public' AND table_name = 'users'"
        ")"
    )
    if not table_exists:
        setup_file = SETUP_DIR / "schema.sql"
        if not setup_file.exists():
            raise RuntimeError(f"Setup schema not found: {setup_file}")
        logger.info("Fresh database — initialising from %s", setup_file.name)
        sql = setup_file.read_text(encoding="utf-8")
        statements = _split_statements(sql)
        async with conn.transaction():
            if statements:
                await conn.execute("\n".join(statements))
        logger.info("Schema initialised.")

    # Idempotent additions — run on every startup to handle existing databases.
    # Each block must use CREATE TABLE/INDEX IF NOT EXISTS.
    async with conn.transaction():
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_share_keying (
                id          TEXT        PRIMARY KEY,
                share_id    TEXT        NOT NULL REFERENCES shares(id)  ON DELETE CASCADE,
                file_id     TEXT        NOT NULL REFERENCES files(id)   ON DELETE CASCADE,
                folder_id   TEXT        NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(share_id, file_id)
            );
            CREATE INDEX IF NOT EXISTS idx_pending_share_keying_folder
                ON pending_share_keying(folder_id);
            CREATE INDEX IF NOT EXISTS idx_pending_share_keying_share
                ON pending_share_keying(share_id);
        """)

    # ---------------------------------------------------------------------------
    # Permission flag rename + split migration — idempotent; safe to run on every boot.
    #
    # Strategy:
    #   1. INSERT new flag definitions (ON CONFLICT DO NOTHING).
    #   2. For renamed flags: INSERT successor rows for all roles that held the old
    #      flag, then DELETE the old rows.
    #   3. For split flags (USERS, INTEGRATIONS, POLICIES, FILES_ACCESS_ALL):
    #      INSERT all successor rows for roles that held the retired flag, then
    #      DELETE the retired flag rows and definition.
    #   4. Seed new admin_settings keys.
    # ---------------------------------------------------------------------------
    async with conn.transaction():
        await conn.execute("""
            -- ── New flag definitions ──────────────────────────────────────────
            INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
                ('admin_panel_view',                  'Access the admin panel',                                             'admin',         0),
                ('system_settings_manage',            'Configure server-level settings (disk, logging, startup)',           'admin',         0),
                ('org_settings_manage',               'Configure org-level settings (branding, org policies)',              'admin',         0),
                ('users_view',                        'List users and view profile / MFA status / activity (read-only)',    'admin',         0),
                ('users_manage',                      'Create, edit, suspend, and force-MFA-reset users; implies view',     'admin',         0),
                ('users_delete',                      'Permanently delete user accounts (irreversible); requires manage',   'admin',         0),
                ('users_invite_manage',               'Create and revoke platform-level registration invite links',         'admin',         0),
                ('users_mfa_manage',                  'View and remove MFA credentials for other users (admin)',            'security',      1),
                ('teams_manage',                      'Create, delete, and configure teams',                                'admin',         0),
                ('teams_members_manage',              'Invite and remove members within a team',                            'admin',         0),
                ('roles_manage',                      'Define roles and grant or revoke role assignments',                  'roles',         0),
                ('roles_create',                      'Create custom roles (permission set capped to creator''s own)',      'roles',         0),
                ('roles_cross_team_create',           'Create roles that span multiple teams',                              'roles',         0),
                ('disk_usage_view',                   'View disk usage statistics',                                         'observability', 0),
                ('audit_log_view',                    'View the server-wide audit trail',                                   'audit',         0),
                ('audit_log_export',                  'Export the audit trail to CSV or TXT',                               'audit',         0),
                ('integrations_idp_manage',           'Configure LDAP / OIDC identity providers',                          'integrations',  0),
                ('integrations_notifications_manage', 'Configure SIEM webhooks and notification channels',                 'integrations',  0),
                ('policies_view',                     'Read all policies and conditions (audit / troubleshooting)',         'policy',        0),
                ('policies_manage',                   'Create, edit, and delete policies and conditions; implies view',    'policy',        0),
                ('policies_fields_manage',            'Register new LDAP/OIDC attribute fields for policy conditions',    'policy',        0),
                ('files_access_all_read',             'Bypass ACL for reads and downloads (audit mode)',                   'files',         1),
                ('files_access_all_write',            'Bypass ACL for writes and deletes; implies files_access_all_read', 'files',         1),
                ('files_copy',                        'May copy files within copy_boundary policy',                        'files',         0),
                ('escrow_manage',                     'Manage org-level escrow defaults and folder-level escrow policies', 'security',      1),
                ('sharing_manage',                    'Manage sharing restriction flags and identity-scoped sharing rules','security',      0),
                ('service_accounts_manage',           'Create, rotate, and delete machine-identity service accounts',     'admin',         0),
                ('shares_link_create',                'May create anonymous link shares',                                  'sharing',       0),
                ('shares_user_create',                'May create user-to-user KEM shares',                                'sharing',       0),
                ('shares_upload_grant_create',        'May enable upload access on a share',                               'sharing',       0),
                ('shares_folder_create',              'May create upload-only folder shares',                              'sharing',       0)
            ON CONFLICT (flag) DO NOTHING;

            -- ── Simple renames: migrate role_permissions rows then delete old defs ──

            -- can_view_admin_panel → admin_panel_view
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'admin_panel_view', value FROM role_permissions WHERE flag = 'can_view_admin_panel'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_view_admin_panel';
            DELETE FROM role_permission_flags WHERE flag = 'can_view_admin_panel';

            -- can_manage_system_settings → system_settings_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'system_settings_manage', value FROM role_permissions WHERE flag = 'can_manage_system_settings'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_system_settings';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_system_settings';

            -- can_manage_org_settings → org_settings_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'org_settings_manage', value FROM role_permissions WHERE flag = 'can_manage_org_settings'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_org_settings';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_org_settings';

            -- can_manage_invites → users_invite_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'users_invite_manage', value FROM role_permissions WHERE flag = 'can_manage_invites'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_invites';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_invites';

            -- can_manage_user_mfa → users_mfa_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'users_mfa_manage', value FROM role_permissions WHERE flag = 'can_manage_user_mfa'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_user_mfa';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_user_mfa';

            -- can_manage_teams → teams_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'teams_manage', value FROM role_permissions WHERE flag = 'can_manage_teams'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_teams';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_teams';

            -- can_manage_team_members → teams_members_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'teams_members_manage', value FROM role_permissions WHERE flag = 'can_manage_team_members'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_team_members';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_team_members';

            -- can_manage_roles → roles_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'roles_manage', value FROM role_permissions WHERE flag = 'can_manage_roles'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_roles';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_roles';

            -- can_create_roles → roles_create
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'roles_create', value FROM role_permissions WHERE flag = 'can_create_roles'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_create_roles';
            DELETE FROM role_permission_flags WHERE flag = 'can_create_roles';

            -- can_create_cross_team_roles → roles_cross_team_create
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'roles_cross_team_create', value FROM role_permissions WHERE flag = 'can_create_cross_team_roles'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_create_cross_team_roles';
            DELETE FROM role_permission_flags WHERE flag = 'can_create_cross_team_roles';

            -- can_view_disk_usage → disk_usage_view
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'disk_usage_view', value FROM role_permissions WHERE flag = 'can_view_disk_usage'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_view_disk_usage';
            DELETE FROM role_permission_flags WHERE flag = 'can_view_disk_usage';

            -- can_view_audit_log → audit_log_view
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'audit_log_view', value FROM role_permissions WHERE flag = 'can_view_audit_log'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_view_audit_log';
            DELETE FROM role_permission_flags WHERE flag = 'can_view_audit_log';

            -- can_export_audit_log → audit_log_export
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'audit_log_export', value FROM role_permissions WHERE flag = 'can_export_audit_log'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_export_audit_log';
            DELETE FROM role_permission_flags WHERE flag = 'can_export_audit_log';

            -- can_define_policy_fields → policies_fields_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'policies_fields_manage', value FROM role_permissions WHERE flag = 'can_define_policy_fields'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_define_policy_fields';
            DELETE FROM role_permission_flags WHERE flag = 'can_define_policy_fields';

            -- can_manage_escrow → escrow_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'escrow_manage', value FROM role_permissions WHERE flag = 'can_manage_escrow'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_escrow';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_escrow';

            -- can_manage_sharing → sharing_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'sharing_manage', value FROM role_permissions WHERE flag = 'can_manage_sharing'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_sharing';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_sharing';

            -- can_manage_service_accounts → service_accounts_manage
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'service_accounts_manage', value FROM role_permissions WHERE flag = 'can_manage_service_accounts'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_service_accounts';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_service_accounts';

            -- can_copy_files → files_copy
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'files_copy', value FROM role_permissions WHERE flag = 'can_copy_files'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_copy_files';
            DELETE FROM role_permission_flags WHERE flag = 'can_copy_files';

            -- can_create_link_shares → shares_link_create
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'shares_link_create', value FROM role_permissions WHERE flag = 'can_create_link_shares'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_create_link_shares';
            DELETE FROM role_permission_flags WHERE flag = 'can_create_link_shares';

            -- can_create_user_shares → shares_user_create
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'shares_user_create', value FROM role_permissions WHERE flag = 'can_create_user_shares'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_create_user_shares';
            DELETE FROM role_permission_flags WHERE flag = 'can_create_user_shares';

            -- can_create_upload_grants → shares_upload_grant_create
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'shares_upload_grant_create', value FROM role_permissions WHERE flag = 'can_create_upload_grants'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_create_upload_grants';
            DELETE FROM role_permission_flags WHERE flag = 'can_create_upload_grants';

            -- can_share_folders → shares_folder_create
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'shares_folder_create', value FROM role_permissions WHERE flag = 'can_share_folders'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_share_folders';
            DELETE FROM role_permission_flags WHERE flag = 'can_share_folders';

            -- ── Split: can_manage_users → users_view + users_manage + users_delete ──
            -- Roles that held '1' get all three successors; roles with '0' get '0'.
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'users_view', value FROM role_permissions WHERE flag = 'can_manage_users'
                ON CONFLICT DO NOTHING;
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'users_manage', value FROM role_permissions WHERE flag = 'can_manage_users'
                ON CONFLICT DO NOTHING;
            -- users_delete: only grant '1' where manage was '1' (same value for now;
            -- admins can revoke it post-migration if they want finer control).
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'users_delete', value FROM role_permissions WHERE flag = 'can_manage_users'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_users';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_users';

            -- ── Split: can_manage_integrations → idp + notifications ──
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'integrations_idp_manage', value FROM role_permissions WHERE flag = 'can_manage_integrations'
                ON CONFLICT DO NOTHING;
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'integrations_notifications_manage', value FROM role_permissions WHERE flag = 'can_manage_integrations'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_integrations';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_integrations';

            -- ── Split: can_manage_policies → policies_view + policies_manage ──
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'policies_view', value FROM role_permissions WHERE flag = 'can_manage_policies'
                ON CONFLICT DO NOTHING;
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'policies_manage', value FROM role_permissions WHERE flag = 'can_manage_policies'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_manage_policies';
            DELETE FROM role_permission_flags WHERE flag = 'can_manage_policies';

            -- ── Split: can_access_all_files → files_access_all_read + files_access_all_write ──
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'files_access_all_read', value FROM role_permissions WHERE flag = 'can_access_all_files'
                ON CONFLICT DO NOTHING;
            INSERT INTO role_permissions (role_id, flag, value)
                SELECT role_id, 'files_access_all_write', value FROM role_permissions WHERE flag = 'can_access_all_files'
                ON CONFLICT DO NOTHING;
            DELETE FROM role_permissions WHERE flag = 'can_access_all_files';
            DELETE FROM role_permission_flags WHERE flag = 'can_access_all_files';

            -- ── Role flag back-fills ──────────────────────────────────────────
            -- server_admin should be eligible as an escrow agent on all installs
            INSERT INTO role_permissions (role_id, flag, value)
                VALUES ('server_admin', 'can_act_as_escrow', '1')
                ON CONFLICT DO NOTHING;

            -- ── New admin_settings seeds ──────────────────────────────────────
            INSERT INTO admin_settings (key, value) VALUES ('link_share_max_expiry_days', '0')
                ON CONFLICT (key) DO NOTHING;
        """)

    # Soft-delete columns for users and teams — idempotent; added on every startup.
    async with conn.transaction():
        await conn.execute("""
            ALTER TABLE users ADD COLUMN IF NOT EXISTS scheduled_delete_at TIMESTAMPTZ DEFAULT NULL;
            CREATE INDEX IF NOT EXISTS idx_users_scheduled_delete
                ON users(scheduled_delete_at) WHERE scheduled_delete_at IS NOT NULL;
            ALTER TABLE teams ADD COLUMN IF NOT EXISTS scheduled_delete_at TIMESTAMPTZ DEFAULT NULL;
            CREATE INDEX IF NOT EXISTS idx_teams_scheduled_delete
                ON teams(scheduled_delete_at) WHERE scheduled_delete_at IS NOT NULL;
        """)

    # av_scan_queue — durable AV scan task queue replacing fire-and-forget asyncio.create_task.
    async with conn.transaction():
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS av_scan_queue (
                file_id           TEXT        NOT NULL PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
                status            TEXT        NOT NULL DEFAULT 'pending'
                                              CHECK (status IN ('pending', 'scanning', 'completed', 'failed')),
                attempts          INTEGER     NOT NULL DEFAULT 0,
                last_attempted_at TIMESTAMPTZ,
                created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_av_scan_queue_pending
                ON av_scan_queue(created_at) WHERE status = 'pending';
        """)

    # root_folder_id on folders — denormalised root pointer for O(1) team lookup.
    async with conn.transaction():
        await conn.execute("""
            ALTER TABLE folders ADD COLUMN IF NOT EXISTS root_folder_id TEXT REFERENCES folders(id);
            CREATE INDEX IF NOT EXISTS idx_folders_root_folder ON folders(root_folder_id);
        """)
    # Backfill root_folder_id for all existing rows (no-op when already populated).
    # Runs outside the DDL transaction so the new column is visible.
    await conn.execute("""
        WITH RECURSIVE tree AS (
            SELECT id, id AS root_id FROM folders WHERE parent_id IS NULL
            UNION ALL
            SELECT f.id, t.root_id FROM folders f JOIN tree t ON f.parent_id = t.id
        )
        UPDATE folders SET root_folder_id = tree.root_id
        FROM tree WHERE folders.id = tree.id AND folders.root_folder_id IS NULL
    """)

    # Recent folder activity — added as idempotent block so existing DBs gain the table.
    async with conn.transaction():
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS user_folder_recent (
                user_id       TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                folder_id     TEXT        NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                team_id       TEXT        REFERENCES teams(id) ON DELETE CASCADE,
                folder_name   TEXT        NOT NULL DEFAULT '',
                team_name     TEXT,
                interacted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (user_id, folder_id)
            );
            CREATE INDEX IF NOT EXISTS idx_user_folder_recent_user
                ON user_folder_recent(user_id, interacted_at DESC);
        """)
