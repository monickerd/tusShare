"""Public theme API endpoints.

GET /api/v1/theme         — brand name, logo and favicon availability (no auth required)
GET /api/v1/theme/logo    — serve org logo file from DATA_DIR (no auth required)
GET /api/v1/theme/favicon — serve org favicon file from DATA_DIR (no auth required)

Both asset endpoints are intentionally public: brand name, logo, and favicon must be
visible on the login page before the user authenticates.
"""

import mimetypes

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.config import settings
from app.util.theme import get_logo_filename_re, get_theme_config, get_ui_flags

router = APIRouter()

_NOT_FOUND = "Logo file not found on disk"
_FAVICON_NOT_FOUND = "Favicon file not found on disk"

# Only serve recognised image MIME types for the logo.  SVG excluded: it can
# contain scripts that execute when served from the app's same origin.
_ALLOWED_IMAGE_TYPES: frozenset[str] = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
    }
)


@router.get("/theme")
async def get_theme():
    """Return active theme brand configuration.

    Consumed by the SPA before authentication to apply org branding on the
    login page and throughout the authenticated shell.
    """
    config = get_theme_config()
    return {
        "brand_name": config.get("brand_name"),
        "logo_url": "/api/v1/theme/logo" if "logo_path" in config else None,
        "favicon_url": "/api/v1/theme/favicon" if "favicon_path" in config else None,
        "ui": get_ui_flags(),
        "public_device_banner_text": config.get("public_device_banner_text"),
    }


@router.get("/theme/logo", responses={404: {"description": "Not Found"}})
async def get_theme_logo():
    """Serve the configured org logo from DATA_DIR.

    Restricted to image MIME types and files that exist directly under
    DATA_DIR (no subdirectory traversal).
    """
    config = get_theme_config()
    filename = config.get("logo_path")
    if not filename:
        raise HTTPException(status_code=404, detail="No logo configured")

    # Re-validate at request time (defence-in-depth; load_theme validated at startup)
    if not get_logo_filename_re().match(filename):
        raise HTTPException(status_code=404, detail=_NOT_FOUND)

    logo_path = settings.DATA_DIR / filename
    try:
        resolved = logo_path.resolve()
        # relative_to raises ValueError if resolved is outside DATA_DIR
        resolved.relative_to(settings.DATA_DIR.resolve())
    except (OSError, ValueError):
        raise HTTPException(status_code=404, detail=_NOT_FOUND)

    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="Logo file not found on disk")

    content_type, _ = mimetypes.guess_type(str(resolved))
    if content_type not in _ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)

    return FileResponse(
        str(resolved),
        media_type=content_type,
        headers={"Cache-Control": "public, max-age=3600"},
    )


_ALLOWED_FAVICON_TYPES: frozenset[str] = frozenset(
    {
        "image/png",
        "image/x-icon",
        "image/vnd.microsoft.icon",
    }
)


@router.get("/theme/favicon", responses={404: {"description": "Not Found"}})
async def get_theme_favicon():
    """Serve the configured org favicon from DATA_DIR."""
    config = get_theme_config()
    filename = config.get("favicon_path")
    if not filename:
        raise HTTPException(status_code=404, detail="No favicon configured")

    if not get_logo_filename_re().match(filename):
        raise HTTPException(status_code=404, detail=_FAVICON_NOT_FOUND)

    favicon_path = settings.DATA_DIR / filename
    try:
        resolved = favicon_path.resolve()
        resolved.relative_to(settings.DATA_DIR.resolve())
    except (OSError, ValueError):
        raise HTTPException(status_code=404, detail=_FAVICON_NOT_FOUND)

    if not resolved.is_file():
        raise HTTPException(status_code=404, detail=_FAVICON_NOT_FOUND)

    content_type, _ = mimetypes.guess_type(str(resolved))
    if content_type not in _ALLOWED_FAVICON_TYPES:
        raise HTTPException(status_code=404, detail=_FAVICON_NOT_FOUND)

    return FileResponse(
        str(resolved),
        media_type=content_type,
        headers={"Cache-Control": "public, max-age=3600"},
    )
