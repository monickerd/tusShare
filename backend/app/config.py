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
    DB_PATH: Path = Path("/data/tusshare.db")
    FILES_DIR: Path = Path("/data/files")
    UPLOADS_DIR: Path = Path("/data/uploads")

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

    # Rate limiting (requests per window)
    RATE_LIMIT_LOGIN: int = 5          # per 15 min per IP
    RATE_LIMIT_API: int = 60           # per min per user
    RATE_LIMIT_SHARE_CREATE: int = 5   # per min per user
    RATE_LIMIT_UPLOAD: int = 10        # per min per user
    RATE_LIMIT_MANAGEMENT: int = 120   # per min per user (folder/share CRUD, non-file actions)

    # Share session tokens
    SHARE_SESSION_EXPIRE_HOURS: int = 2  # short-lived IP-bound JWT for public share access

    # Trusted proxy header (set to X-Real-IP or X-Forwarded-For if behind nginx)
    TRUSTED_IP_HEADER: str = "X-Real-IP"

    model_config = {"env_prefix": "TUSSHARE_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
