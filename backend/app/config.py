"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "tusShare"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8080

    # Data paths
    DATA_DIR: Path = Path("/data")
    FILES_DIR: Path = Path("/data/files")
    UPLOADS_DIR: Path = Path("/data/uploads")

    # Database
    DATABASE_URL: str = "postgresql://tusshare:tusshare@postgres:5432/tusshare"
    # Superuser URL used only for first-run sensitive_config schema bootstrap.
    # Needs CREATEROLE + schema creation privileges on the app database.
    # Safe to remove from the environment after initial startup.
    SUPERUSER_URL: str = ""

    # Auth
    AUTH_PROVIDER: str = "local"  # "local" | future: "oidc"
    JWT_SECRET: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 5
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # Sessions inactive for longer than this are revoked by the cleanup task.
    # Checked every minute. A truly idle session will be unusable within
    # SESSION_IDLE_TIMEOUT_MINUTES + ACCESS_TOKEN_EXPIRE_MINUTES at most.
    SESSION_IDLE_TIMEOUT_MINUTES: int = 10

    # Admin bootstrap (first run only)
    ADMIN_USERNAME: str = ""
    ADMIN_PASSWORD: str = ""

    # Upload defaults
    DEFAULT_CHUNK_SIZE: int = 5_242_880  # 5 MB
    TUS_UPLOAD_EXPIRY_HOURS: int = 24
    # Page-cache eviction stride for upload staging blobs (MiB).
    # After every UPLOAD_EVICT_STRIDE_MB written, the staging blob is
    # fdatasync'd and the OS is advised to evict its pages from RAM.
    # Peak cache ≈ stride × concurrent uploads.
    # Tune for your storage:
    #   0          — disabled (let the OS manage cache; fine for NVMe/high-RAM hosts)
    #   8–32 MiB   — local SSD or RAM-constrained hosts
    #   64–256 MiB — network volumes (NFS/SMB) where fdatasync is a round-trip
    UPLOAD_EVICT_STRIDE_MB: int = 32

    # Admin panel defaults — these seed admin_settings on first run.
    # Once written to the database they can be overridden via the admin UI.
    OPEN_REGISTRATION: bool = False
    GLOBAL_MAX_FILE_SIZE: int = 0      # bytes; 0 = no global limit
    GLOBAL_BANDWIDTH_LIMIT: int = 0    # bytes/s; 0 = no global limit
    DISK_WARNING_THRESHOLD: int = 65   # filesystem usage % that triggers admin alert

    # Rate limiting (requests per window)
    RATE_LIMIT_LOGIN: int = 5          # per 15 min per IP
    RATE_LIMIT_API: int = 60           # per min per user
    RATE_LIMIT_SHARE_CREATE: int = 5   # per min per user
    RATE_LIMIT_UPLOAD: int = 10        # per min per user
    RATE_LIMIT_MANAGEMENT: int = 120   # per min per user (folder/share CRUD, non-file actions)

    # Error-rate escalation (brute-force / scanning detection)
    # When a single IP accumulates >= ERROR_THRESHOLD non-429 4xx/5xx responses
    # within ERROR_WINDOW seconds, it is escalated to aggressive throttling:
    # ESCALATED_MAX requests per ESCALATED_WINDOW seconds for ESCALATED_DURATION seconds.
    # Set ERROR_THRESHOLD=0 to disable escalation entirely.
    RATE_LIMIT_ERROR_THRESHOLD: int = 5    # errors before escalation
    RATE_LIMIT_ERROR_WINDOW: int = 60      # seconds over which errors are counted
    RATE_LIMIT_ESCALATED_MAX: int = 1      # max requests allowed per escalated window
    RATE_LIMIT_ESCALATED_WINDOW: int = 1   # seconds per escalated request slot (1 req/s)
    RATE_LIMIT_ESCALATED_DURATION: int = 300  # seconds the IP stays in escalated mode (5 min)

    # Public / shared device sessions (B4)
    # Refresh token TTL for sessions where the user checked "Public Device" at login.
    # Intentionally much shorter than the normal REFRESH_TOKEN_EXPIRE_DAYS to limit
    # the exposure window if the user forgets to log out.
    # TODO (Phase D): expose this in theme.json so admins can tune it without a restart.
    PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES: int = 60  # 1 hour

    # Share session tokens
    SHARE_SESSION_EXPIRE_HOURS: int = 2  # short-lived IP-bound JWT for public share access

    # Step-up authentication (sensitive action re-auth)
    # STEP_UP_WINDOW_SECONDS: how long a granted elevation lasts (sudo window).
    #   0 = single-use (token is bound to the exact payload_hash it was issued for).
    #   >0 = any sensitive action within the window is accepted without re-auth.
    STEP_UP_WINDOW_SECONDS: int = 300     # default: 5 minute sudo window
    STEP_UP_MAX_FAILURES: int = 3         # failed attempts before session lockout

    # Trusted proxy header (set to X-Real-IP or X-Forwarded-For if behind nginx)
    TRUSTED_IP_HEADER: str = "X-Real-IP"

    # HTTPS enforcement
    # When True, requests with X-Forwarded-Proto: http are redirected to https.
    # Only enable this when the app port is NOT directly internet-accessible —
    # traffic must route exclusively through a TLS-terminating proxy (nginx, etc.)
    # so that X-Forwarded-Proto cannot be spoofed by external clients.
    FORCE_HTTPS: bool = False

    model_config = {"env_prefix": "TUSSHARE_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
