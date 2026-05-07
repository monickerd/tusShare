"""tusShare — FastAPI application entry point."""

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.auth.jwt import run_token_cleanup
from app.routes.uploads import run_upload_cleanup
from app.services.trash import run_trash_cleanup
from app.services.sse_broker import run_redis_listener
from app.config import settings
from app.services import event_bus, op_bus, notification_emitter, siem_syslog, siem_webhook
import app.storage.manager as storage
from app.database import Database, db_session, get_db, init_db, close_db
import app.sensitive_config as sensitive_config
from app.middleware.csrf import CSRFMiddleware
from app.middleware.https_redirect import HttpsRedirectMiddleware
from app.middleware.rate_limit import run_rate_limit_cleanup
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.sanitize import InputSanitizationMiddleware
from app.schemas.security_event import EventActor, SecurityEvent
from app.util.integrity import check_integrity, get_result as get_integrity_result
from app.util.sri import inject_sri
from app.util.theme import inject_theme

def _configure_logging() -> None:
    if settings.LOG_JSON:
        import json as _json
        import traceback as _tb

        class _JSONFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                obj: dict = {
                    "ts":      self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
                    "level":   record.levelname,
                    "logger":  record.name,
                    "msg":     record.getMessage(),
                }
                if record.exc_info:
                    obj["exc"] = _tb.format_exception(*record.exc_info)
                return _json.dumps(obj, separators=(",", ":"))

        handler = logging.StreamHandler()
        handler.setFormatter(_JSONFormatter())
        logging.root.handlers = [handler]
        logging.root.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    else:
        logging.basicConfig(
            level=logging.DEBUG if settings.DEBUG else logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )


_configure_logging()
logger = logging.getLogger(__name__)


def _actor_from_request(request: Request) -> EventActor:
    """Best-effort JWT extraction for SIEM event actor attribution.

    Reads from the httpOnly access-token cookie or Authorization Bearer header,
    falling back to IP-only if the token is absent or invalid.
    """
    import jwt as _pyjwt
    from app.auth.jwt import verify_access_token
    from app.conf.auth import COOKIE_ACCESS

    ip = request.client.host if request.client else None
    token = request.cookies.get(COOKIE_ACCESS)
    if token is None:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if token is None:
        return EventActor(ip=ip)
    try:
        payload = verify_access_token(token)
        return EventActor(user_id=payload.get("sub"), session_id=payload.get("sid"), ip=ip)
    except _pyjwt.PyJWTError:
        return EventActor(ip=ip)


async def _run_opaque_session_cleanup(db_session_factory, interval: int = 120) -> None:
    """Sweep expired OPAQUE login and recovery sessions every `interval` seconds.

    Login sessions have a 60-second TTL; recovery sessions have a 90-second TTL.
    This task removes any survivors abandoned before the finish call (e.g. client crash).
    """
    while True:
        await asyncio.sleep(interval)
        try:
            async with db_session_factory() as db:
                from app.auth.opaque_provider import OPAQUEAuthProvider
                provider = OPAQUEAuthProvider(db)
                removed = await provider.sweep_expired_sessions()
                if removed:
                    logger.debug("Swept %d expired OPAQUE login session(s)", removed)
                removed_recovery = await provider.sweep_expired_recovery_sessions()
                if removed_recovery:
                    logger.debug("Swept %d expired OPAQUE recovery session(s)", removed_recovery)
        except Exception:
            logger.exception("Error in OPAQUE session cleanup task")


async def _run_oidc_state_cleanup(db_session_factory, interval: int = 300) -> None:
    """Sweep expired OIDC state nonces every 5 minutes."""
    while True:
        await asyncio.sleep(interval)
        try:
            async with db_session_factory() as db:
                from app.auth.oidc_provider import sweep_expired_oidc_states
                removed = await sweep_expired_oidc_states(db)
                if removed:
                    logger.debug("Swept %d expired OIDC state nonce(s)", removed)
        except Exception:
            logger.exception("Error in OIDC state cleanup task")


async def _run_mfa_cleanup(db_session_factory, interval: int = 120) -> None:
    """Sweep expired MFA pending tokens and stale WebAuthn challenges every 2 minutes."""
    while True:
        await asyncio.sleep(interval)
        try:
            async with db_session_factory() as db:
                from app.auth.mfa import sweep_expired_pending_tokens, sweep_expired_webauthn_challenges
                removed_pt = await sweep_expired_pending_tokens(db)
                removed_wc = await sweep_expired_webauthn_challenges(db)
                if removed_pt or removed_wc:
                    logger.debug(
                        "MFA cleanup: %d pending token(s), %d WebAuthn challenge(s) swept",
                        removed_pt, removed_wc,
                    )
        except Exception:
            logger.exception("Error in MFA cleanup task")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # Refuse to start with an empty or placeholder JWT secret
    if not settings.JWT_SECRET or settings.JWT_SECRET == "CHANGE-ME-IN-PRODUCTION":
        raise RuntimeError(
            "TUSSHARE_JWT_SECRET must be set to a strong random value. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )

    # Ensure data directories exist (used by the default local storage volume)
    settings.FILES_DIR.mkdir(parents=True, exist_ok=True)
    settings.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize database
    await init_db()

    # Load and verify the sensitive function config (must run before routes handle requests)
    async with db_session() as db:
        await sensitive_config.load(db, settings.DATA_DIR, settings.SUPERUSER_URL)

    # Initialize storage manager (loads volume configs from DB)
    async with db_session() as db:
        storage_manager = await storage.init(db, db_session)

    # Bootstrap admin user on first run
    async with db_session() as db:
        await _bootstrap_admin(db)

    # Start background tasks
    rate_limit_task         = asyncio.create_task(run_rate_limit_cleanup())
    token_cleanup_task      = asyncio.create_task(run_token_cleanup(db_session))
    upload_cleanup_task     = asyncio.create_task(run_upload_cleanup(db_session))
    trash_cleanup_task      = asyncio.create_task(run_trash_cleanup(db_session))
    redis_sse_task          = asyncio.create_task(run_redis_listener())
    opaque_session_cleanup  = asyncio.create_task(_run_opaque_session_cleanup(db_session))
    mfa_cleanup_task        = asyncio.create_task(_run_mfa_cleanup(db_session))
    oidc_state_cleanup_task = asyncio.create_task(_run_oidc_state_cleanup(db_session))
    storage_tiering_task    = asyncio.create_task(storage_manager.run_tiering_task())
    storage_reconcile_task  = asyncio.create_task(storage_manager.run_reconciliation_task())

    event_bus.init(db_session)
    event_bus_task = event_bus.start()

    op_bus.init(db_session)
    op_bus_task = op_bus.start()

    notification_emitter.init(db_session)
    notif_task = notification_emitter.start()

    siem_syslog.init(db_session)
    siem_syslog_task = siem_syslog.start()

    siem_webhook.init(db_session)
    siem_webhook_task = siem_webhook.start()

    from app.schemas.op_event import OperationalEvent as _OpEvent
    op_bus.emit(_OpEvent(event_type="system.startup", severity="info", source="system"))

    if settings.FORCE_HTTPS:
        logger.info("HTTPS enforcement active — HTTP requests will be redirected (X-Forwarded-Proto)")
    elif not settings.DEBUG:
        logger.warning(
            "TUSSHARE_FORCE_HTTPS is not set. Ensure your reverse proxy enforces HTTPS "
            "and that the application port is not directly internet-accessible."
        )

    # Inject theme CSS variable overrides into index.html.  Runs before
    # SRI so the style block is in place when hashes are computed.  Skipped in
    # DEBUG mode; no-ops silently when DATA_DIR/theme.json is absent.
    if not settings.DEBUG:
        _frontend_dir = Path(__file__).parent.parent / "frontend"
        if _frontend_dir.exists():
            inject_theme(_frontend_dir, settings.DATA_DIR)

    # Inject SRI hashes into index.html so every <script>/<link> tag carries
    # an integrity= attribute.  Skipped in DEBUG mode so a server restart isn't
    # required after every frontend edit.
    if not settings.DEBUG:
        _frontend_dir = Path(__file__).parent.parent / "frontend"
        if _frontend_dir.exists():
            inject_sri(_frontend_dir)

    # Verify artifact integrity against manifest.json.  SRI injection
    # runs first because it rewrites index.html — the manifest does not track
    # index.html (SRI covers that side).
    if not settings.DEBUG:
        check_integrity()

    logger.info("%s v%s started", settings.APP_NAME, settings.APP_VERSION)
    yield

    # Shutdown — cancel background tasks
    for task in (rate_limit_task, token_cleanup_task, upload_cleanup_task, trash_cleanup_task, redis_sse_task, opaque_session_cleanup, mfa_cleanup_task, oidc_state_cleanup_task, event_bus_task, op_bus_task, notif_task, siem_syslog_task, siem_webhook_task, storage_tiering_task, storage_reconcile_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:  # NOSONAR — awaiting deliberately cancelled tasks in shutdown sequence
            pass
    from app import redis_client
    await redis_client.close()
    await close_db()
    logger.info("%s stopped", settings.APP_NAME)


async def _bootstrap_admin(db) -> None:
    """On first run (empty users table), generate a one-time OPAQUE bootstrap token.

    The token is logged at CRITICAL level and stored as a SHA-256 hash in
    admin_settings under the key 'bootstrap_token_hash'.  The operator uses
    it with POST /api/v1/auth/opaque/bootstrap/start+finish to register the
    initial admin account via OPAQUE.  The token is consumed (deleted) on
    successful registration.

    ADMIN_USERNAME and ADMIN_PASSWORD env vars are no longer used — OPAQUE
    means the server never handles the plaintext password.
    """
    import hashlib
    import secrets

    cursor = await db.execute("SELECT COUNT(*) FROM users")
    row = await cursor.fetchone()
    if row[0] > 0:
        return

    # If a token is already pending (e.g. container restarted before use),
    # don't regenerate — just warn so the operator knows to reuse the first one.
    cursor = await db.execute(
        "SELECT value FROM admin_settings WHERE key = 'bootstrap_token_hash'"
    )
    if await cursor.fetchone() is not None:
        logger.warning(
            "Bootstrap token already pending (no users registered yet). "
            "Use the previously logged token, or wipe admin_settings to regenerate."
        )
        return

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    await db.execute(
        "INSERT INTO admin_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        ("bootstrap_token_hash", token_hash),
    )
    await db.commit()

    logger.critical(
        "\n"
        "================================================================\n"
        "  TUSSHARE FIRST-RUN BOOTSTRAP\n"
        "  Register the initial admin account with this one-time token:\n"
        "\n"
        "  %s\n"
        "\n"
        "  POST to /api/v1/auth/opaque/bootstrap/start then /finish\n"
        "  This token is single-use and consumed on successful registration.\n"
        "================================================================",
        token,
    )


_SPA_INDEX_PATH: str = ""  # set by create_app when the frontend dir is found
_SLUG_RE = re.compile(r"^[A-Z][a-z]{2,11}[A-Z][a-z]{2,11}[A-Z][a-z]{2,11}$")


def _on_401(request: Request, exc: HTTPException):
    event_bus.emit(SecurityEvent(
        event_type="auth.unauthorized",
        severity="warning",
        outcome="failure",
        actor=_actor_from_request(request),
        detail={"path": request.url.path, "method": request.method},
    ))
    return JSONResponse({"detail": exc.detail}, status_code=401)


def _on_403(request: Request, exc: HTTPException):
    is_step_up_challenge = (
        isinstance(exc.detail, dict) and exc.detail.get("error") == "step_up_required"
    )
    if not is_step_up_challenge:
        event_bus.emit(SecurityEvent(
            event_type="auth.forbidden",
            severity="warning",
            outcome="failure",
            actor=_actor_from_request(request),
            detail={"path": request.url.path, "method": request.method},
        ))
    return JSONResponse({"detail": exc.detail}, status_code=403)


def _on_404(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        event_bus.emit(SecurityEvent(
            event_type="auth.probe_404",
            severity="info",
            outcome="failure",
            actor=_actor_from_request(request),
            detail={"path": request.url.path, "method": request.method},
        ))
    return JSONResponse({"detail": exc.detail}, status_code=404)


def _on_405(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        event_bus.emit(SecurityEvent(
            event_type="auth.probe_405",
            severity="info",
            outcome="failure",
            actor=_actor_from_request(request),
            detail={"path": request.url.path, "method": request.method},
        ))
    return JSONResponse({"detail": exc.detail}, status_code=405)


def _on_429(request: Request, exc: HTTPException):
    event_bus.emit(SecurityEvent(
        event_type="auth.rate_limited",
        severity="warning",
        outcome="failure",
        actor=_actor_from_request(request),
        detail={"path": request.url.path, "method": request.method},
    ))
    headers = exc.headers or {}
    return JSONResponse({"detail": exc.detail}, status_code=429, headers=headers)


def _health_check():
    integrity = get_integrity_result()
    if integrity is None:
        return {"status": "ok"}
    if integrity.manifest_missing:
        return {"status": "ok", "integrity": "no_manifest"}
    if not integrity.ok:
        return {
            "status": "degraded",
            "integrity": "fail",
            "missing": integrity.missing,
            "tampered": integrity.tampered,
        }
    return {"status": "ok", "integrity": "ok", "files_verified": integrity.total}


def _spa_register(token: str):
    return FileResponse(_SPA_INDEX_PATH)


def _spa_share(token: str):
    return FileResponse(_SPA_INDEX_PATH)


def _spa_shortlink(slug: str):
    return FileResponse(_SPA_INDEX_PATH)


async def _shortlink_redirect(slug: str, db: Annotated[Database, Depends(get_db)]):
    """Redirect root-level short link slugs to /s/<token>#<shareKey>.

    Only intercepts paths that look like a 3-word PascalCase slug.
    All other single-segment paths (e.g. index.html) fall through to
    the SPA HTML so client-side routing can handle them.
    """
    if not _SLUG_RE.match(slug):
        return FileResponse(_SPA_INDEX_PATH)

    now = datetime.now(timezone.utc).isoformat()

    invite_cursor = await db.execute(
        "SELECT token FROM invite_short_links WHERE slug = ? AND expires_at > ?",
        (slug, now),
    )
    invite_row = await invite_cursor.fetchone()
    if invite_row is not None:
        return RedirectResponse(url=f"/register/{invite_row['token']}", status_code=302)

    cursor = await db.execute(
        """
        SELECT sl.share_key, s.token
        FROM   short_links sl
        JOIN   shares s ON sl.share_id = s.id
        WHERE  sl.slug = ?
          AND  sl.expires_at > ?
          AND  sl.share_key IS NOT NULL
          AND  s.is_active = 1
          AND (s.expires_at IS NULL OR s.expires_at > ?)
        """,
        (slug, now, now),
    )
    row = await cursor.fetchone()
    if row is None:
        return FileResponse(_SPA_INDEX_PATH)

    return RedirectResponse(url=f"/s/{row['token']}#{row['share_key']}", status_code=302)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url=None,
        lifespan=lifespan,
    )

    # --- Middleware (outermost first) ---
    # HttpsRedirectMiddleware must be outermost so it intercepts requests before
    # any other middleware can process or respond to them.
    if settings.FORCE_HTTPS:
        app.add_middleware(HttpsRedirectMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(InputSanitizationMiddleware)
    app.add_middleware(CSRFMiddleware)

    _AUTH_PREFIX  = "/api/v1/auth"
    _ADMIN_PREFIX = "/api/v1/admin"

    # --- API routes ---
    from app.routes.auth import router as auth_router
    from app.routes.opaque_auth import router as opaque_auth_router
    from app.routes.users import router as users_router
    from app.routes.folders import router as folders_router
    from app.routes.files import router as files_router
    from app.routes.uploads import router as uploads_router
    from app.routes.shares import router as shares_router
    from app.routes.teams import router as teams_router
    from app.routes.admin import router as admin_router
    from app.routes.admin_roles import router as admin_roles_router
    from app.routes.team_roles import router as team_roles_router
    from app.routes.access_logs import router as access_logs_router
    from app.routes.events import router as events_router
    from app.routes.theme import router as theme_router
    from app.routes.policy_fields import router as policy_fields_router
    from app.routes.admin_scopes import router as admin_scopes_router
    from app.routes.policies import router as policies_router
    from app.routes.mfa import router as mfa_router
    from app.routes.admin_mfa import router as admin_mfa_router
    from app.routes.idp_auth import router as idp_auth_router
    from app.routes.idp_admin import router as idp_admin_router
    from app.routes.admin_emergency import router as admin_emergency_router
    from app.routes.admin_audit import router as admin_audit_router
    from app.routes.admin_storage import router as admin_storage_router
    from app.routes.admin_notifications import router as admin_notifications_router
    from app.routes.admin_notifications import api_keys_router as admin_api_keys_router
    from app.routes.op_events import router as op_events_router
    from app.routes.admin_escrow import router as admin_escrow_router
    from app.routes.admin_sharing import router as admin_sharing_router
    from app.routes.admin_service_accounts import router as admin_service_accounts_router
    from app.routes.admin_profiles import router as admin_profiles_router
    from app.routes.trash import router as trash_router

    app.include_router(auth_router, prefix=_AUTH_PREFIX, tags=["auth"])
    app.include_router(opaque_auth_router, prefix="/api/v1/auth/opaque", tags=["auth-opaque"])
    app.include_router(users_router, prefix="/api/v1/admin/users", tags=["admin-users"])
    app.include_router(admin_router, prefix=_ADMIN_PREFIX, tags=["admin"])
    app.include_router(admin_roles_router, prefix="/api/v1/admin/roles", tags=["admin-roles"])
    app.include_router(folders_router, prefix="/api/v1/folders", tags=["folders"])
    app.include_router(files_router, prefix="/api/v1/files", tags=["files"])
    app.include_router(uploads_router, prefix="/api/v1/uploads", tags=["uploads"])
    app.include_router(shares_router, tags=["shares"])
    app.include_router(teams_router, tags=["teams"])
    app.include_router(team_roles_router, prefix="/api/v1/teams", tags=["team-roles"])
    app.include_router(access_logs_router, prefix="/api/v1/access-logs", tags=["logs"])
    app.include_router(events_router, prefix="/api/v1", tags=["events"])
    app.include_router(theme_router, prefix="/api/v1", tags=["theme"])
    app.include_router(policy_fields_router, prefix="/api/v1/admin/policy-fields", tags=["policy"])
    app.include_router(admin_scopes_router,  prefix="/api/v1/admin/scopes",         tags=["policy"])
    app.include_router(policies_router,      prefix="/api/v1/admin/policies",       tags=["policy"])
    app.include_router(mfa_router,           prefix=_AUTH_PREFIX,                 tags=["mfa"])
    app.include_router(admin_mfa_router,     prefix=_ADMIN_PREFIX,                tags=["admin-mfa"])
    app.include_router(idp_auth_router,      prefix=_AUTH_PREFIX,                 tags=["idp-auth"])
    app.include_router(idp_admin_router,     prefix="/api/v1/admin/identity-providers", tags=["idp-admin"])
    app.include_router(admin_emergency_router, prefix=_ADMIN_PREFIX,               tags=["admin-emergency"])
    app.include_router(admin_audit_router,    prefix="/api/v1/admin/audit",          tags=["admin-audit"])
    app.include_router(admin_storage_router,       prefix="/api/v1/admin/storage",      tags=["admin-storage"])
    app.include_router(admin_notifications_router, prefix="/api/v1/admin/notifications", tags=["admin-notifications"])
    app.include_router(admin_api_keys_router,      prefix=_ADMIN_PREFIX,               tags=["admin-api-keys"])
    app.include_router(op_events_router,           prefix="/api/v1/op-events",           tags=["op-events"])
    app.include_router(admin_escrow_router,         prefix="/api/v1/admin/escrow",          tags=["admin-escrow"])
    app.include_router(admin_sharing_router,        prefix="/api/v1/admin/sharing",         tags=["admin-sharing"])
    app.include_router(admin_service_accounts_router, prefix=_ADMIN_PREFIX,                tags=["admin-service-accounts"])
    app.include_router(admin_profiles_router,         prefix=_ADMIN_PREFIX,                tags=["admin-profiles"])
    app.include_router(trash_router,                  prefix="/api/v1/trash",                tags=["trash"])

    # --- SIEM HTTP error event handlers ---
    # Legitimate users should not regularly encounter these codes, so each
    # occurrence on an API path is worth recording as a security signal.
    # Step-up challenge 403s are deliberately excluded — see _on_403 above.
    app.add_exception_handler(401, _on_401)
    app.add_exception_handler(403, _on_403)
    app.add_exception_handler(404, _on_404)
    app.add_exception_handler(405, _on_405)
    app.add_exception_handler(429, _on_429)  # Catches HTTPException(429) only

    # --- Health check ---
    app.add_api_route("/api/v1/health", _health_check, methods=["GET"])

    # --- Static files (SPA) — must be last so /api routes take priority ---
    frontend_dir = Path(__file__).parent.parent / "frontend"
    if frontend_dir.exists():
        global _SPA_INDEX_PATH
        _SPA_INDEX_PATH = str(frontend_dir / "index.html")

        # Path-based SPA routes: serve index.html so the client-side router
        # can handle them. These must be declared before the StaticFiles mount.
        app.add_api_route("/register/{token}", _spa_register, methods=["GET"])
        app.add_api_route("/s/{token}", _spa_share, methods=["GET"])
        app.add_api_route("/l/{slug}", _spa_shortlink, methods=["GET"])
        app.add_api_route("/{slug}", _shortlink_redirect, methods=["GET"])

        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="static")

    return app


app = create_app()
