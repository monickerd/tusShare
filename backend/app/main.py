"""tusShare — FastAPI application entry point."""

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.auth.jwt import run_token_cleanup
from app.routes.uploads import run_upload_cleanup
from app.config import settings
from app.database import db_session, get_db, init_db, close_db
import app.sensitive_config as sensitive_config
from app.middleware.csrf import CSRFMiddleware
from app.middleware.https_redirect import HttpsRedirectMiddleware
from app.middleware.rate_limit import run_rate_limit_cleanup
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.sanitize import InputSanitizationMiddleware

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # Refuse to start with an empty or placeholder JWT secret
    if not settings.JWT_SECRET or settings.JWT_SECRET == "CHANGE-ME-IN-PRODUCTION":
        raise RuntimeError(
            "TUSSHARE_JWT_SECRET must be set to a strong random value. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )

    # Ensure data directories exist
    settings.FILES_DIR.mkdir(parents=True, exist_ok=True)
    settings.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize database and run migrations
    await init_db()

    # Load and verify the sensitive function config (must run before routes handle requests)
    async with db_session() as db:
        await sensitive_config.load(db, settings.DATA_DIR)

    # Bootstrap admin user on first run
    async with db_session() as db:
        await _bootstrap_admin(db)

    # Start background tasks
    rate_limit_task     = asyncio.create_task(run_rate_limit_cleanup())
    token_cleanup_task  = asyncio.create_task(run_token_cleanup(db_session))
    upload_cleanup_task = asyncio.create_task(run_upload_cleanup(db_session))

    if settings.FORCE_HTTPS:
        logger.info("HTTPS enforcement active — HTTP requests will be redirected (X-Forwarded-Proto)")
    elif not settings.DEBUG:
        logger.warning(
            "TUSSHARE_FORCE_HTTPS is not set. Ensure your reverse proxy enforces HTTPS "
            "and that the application port is not directly internet-accessible."
        )

    logger.info("%s v%s started", settings.APP_NAME, settings.APP_VERSION)
    yield

    # Shutdown — cancel background tasks
    for task in (rate_limit_task, token_cleanup_task, upload_cleanup_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    await close_db()
    logger.info("%s stopped", settings.APP_NAME)


async def _bootstrap_admin(db) -> None:
    """Create the initial admin user if the users table is empty and
    ADMIN_USERNAME + ADMIN_PASSWORD env vars are set."""
    if not settings.ADMIN_USERNAME or not settings.ADMIN_PASSWORD:
        return

    cursor = await db.execute("SELECT COUNT(*) FROM users")
    row = await cursor.fetchone()
    if row[0] > 0:
        return

    # Import here to avoid circular dependency at module level
    from app.auth.local import LocalAuthProvider
    from app.models.role import ROLE_ADMIN

    provider = LocalAuthProvider(db)
    user = await provider.create_user(
        username=settings.ADMIN_USERNAME,
        password=settings.ADMIN_PASSWORD,
        role=ROLE_ADMIN,
    )
    logger.info("Bootstrapped admin user: %s (id=%s)", user.username, user.id)


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

    # --- API routes ---
    from app.routes.auth import router as auth_router
    from app.routes.users import router as users_router
    from app.routes.folders import router as folders_router
    from app.routes.files import router as files_router
    from app.routes.uploads import router as uploads_router
    from app.routes.shares import router as shares_router
    from app.routes.teams import router as teams_router
    from app.routes.admin import router as admin_router
    from app.routes.access_logs import router as access_logs_router
    from app.routes.events import router as events_router

    app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(users_router, prefix="/api/v1/admin/users", tags=["admin-users"])
    app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])
    app.include_router(folders_router, prefix="/api/v1/folders", tags=["folders"])
    app.include_router(files_router, prefix="/api/v1/files", tags=["files"])
    app.include_router(uploads_router, prefix="/api/v1/uploads", tags=["uploads"])
    app.include_router(shares_router, tags=["shares"])
    app.include_router(teams_router, tags=["teams"])
    app.include_router(access_logs_router, prefix="/api/v1/access-logs", tags=["logs"])
    app.include_router(events_router, prefix="/api/v1", tags=["events"])

    # --- Health check ---
    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    # --- Static files (SPA) — must be last so /api routes take priority ---
    frontend_dir = Path(__file__).parent.parent / "frontend"
    if frontend_dir.exists():
        index = str(frontend_dir / "index.html")

        # Path-based SPA routes: serve index.html so the client-side router
        # can handle them. These must be declared before the StaticFiles mount.
        # Regex: three concatenated PascalCase words, e.g. "LimaCharlieTango"
        _SLUG_RE = re.compile(r"^[A-Z][a-z]{2,11}[A-Z][a-z]{2,11}[A-Z][a-z]{2,11}$")

        @app.get("/register/{token}")
        async def _spa_register(token: str):
            return FileResponse(index)

        @app.get("/s/{token}")
        async def _spa_share(token: str):
            return FileResponse(index)

        @app.get("/l/{slug}")
        async def _spa_shortlink(slug: str):
            return FileResponse(index)

        @app.get("/{slug}")
        async def _shortlink_redirect(slug: str, db=Depends(get_db)):
            """Redirect root-level short link slugs to /s/<token>#<shareKey>.

            Only intercepts paths that look like a 3-word PascalCase slug.
            All other single-segment paths (e.g. index.html) fall through to
            the SPA HTML so client-side routing can handle them.
            """
            if not _SLUG_RE.match(slug):
                return FileResponse(index)

            now = datetime.now(timezone.utc).isoformat()

            # Check invite short links first — redirect to registration page
            invite_cursor = await db.execute(
                "SELECT token FROM invite_short_links WHERE slug = ? AND expires_at > ?",
                (slug, now),
            )
            invite_row = await invite_cursor.fetchone()
            if invite_row is not None:
                return RedirectResponse(
                    url=f"/register/{invite_row['token']}",
                    status_code=302,
                )

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
                # Slug not found or has no server-side key — serve SPA (will show 404)
                return FileResponse(index)

            return RedirectResponse(
                url=f"/s/{row['token']}#{row['share_key']}",
                status_code=302,
            )

        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="static")

    return app


app = create_app()
