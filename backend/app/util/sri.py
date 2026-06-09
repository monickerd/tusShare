"""SRI hash injection for frontend/index.html.

Computes SHA-384 hashes for every <script src="..."> and
<link rel="stylesheet" href="..."> asset referenced in index.html and writes
integrity="sha384-..." crossorigin="anonymous" attributes back to the file.

Called once at server startup (skipped when DEBUG=True so developers don't
need a restart after every JS/CSS edit).  Idempotent: re-reading asset bytes
on each startup keeps hashes correct after an asset update + server restart.
"""

import base64
import hashlib
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Match <script src="..."> tags regardless of existing integrity/crossorigin attrs.
_SCRIPT_RE = re.compile(r'<script\b[^>]*\bsrc="([^"]+)"[^>]*></script>')

# Match an existing build-id meta tag so it can be updated in place.
_BUILD_ID_RE = re.compile(r'<meta\s+name="build-id"[^>]*/?\s*>', re.IGNORECASE)

# Match <link rel="stylesheet" href="..."> tags.  Lookahead requires rel="stylesheet"
# so favicon/preload links are never touched; href is captured wherever it appears.
_LINK_RE = re.compile(r'<link\b(?=[^>]*rel="stylesheet")[^>]*href="([^"]+)"[^>]*>')


def _sha384(path: Path) -> str:
    digest = hashlib.sha384(path.read_bytes()).digest()
    return "sha384-" + base64.b64encode(digest).decode()


def inject_sri(frontend_dir: Path) -> None:
    """Inject SHA-384 integrity attributes into frontend/index.html.

    Assets that don't exist on disk (e.g. paths resolved elsewhere) are left
    unchanged with a warning rather than raising.
    """
    index_path = frontend_dir / "index.html"
    if not index_path.exists():
        logger.warning("SRI injection skipped: index.html not found at %s", index_path)
        return

    html = index_path.read_text(encoding="utf-8")

    def _replace_script(m: re.Match) -> str:
        src = m.group(1)
        asset_path = frontend_dir / src.lstrip("/")
        if not asset_path.exists():
            logger.warning("SRI: asset not found, skipping: %s", asset_path)
            return m.group(0)
        return f'<script src="{src}" integrity="{_sha384(asset_path)}" crossorigin="anonymous"></script>'

    def _replace_link(m: re.Match) -> str:
        href = m.group(1)
        asset_path = frontend_dir / href.lstrip("/")
        if not asset_path.exists():
            logger.warning("SRI: asset not found, skipping: %s", asset_path)
            return m.group(0)
        return f'<link rel="stylesheet" href="{href}" integrity="{_sha384(asset_path)}" crossorigin="anonymous">'

    new_html = _SCRIPT_RE.sub(_replace_script, html)
    new_html = _LINK_RE.sub(_replace_link, new_html)

    if new_html == html:
        logger.debug("SRI: index.html integrity hashes already current")
    else:
        index_path.write_text(new_html, encoding="utf-8")
        logger.info("SRI: index.html updated with fresh integrity hashes")


def inject_build_id(frontend_dir: Path, build_id: str) -> None:
    """Inject or update <meta name="build-id"> in index.html.

    Replaces the existing tag if present; otherwise inserts before </head>.
    Skipped silently when index.html is absent (e.g. non-frontend deployments).
    """
    index_path = frontend_dir / "index.html"
    if not index_path.exists():
        logger.warning("Build-ID injection skipped: index.html not found at %s", index_path)
        return

    html = index_path.read_text(encoding="utf-8")
    tag = f'<meta name="build-id" content="{build_id}">'

    if _BUILD_ID_RE.search(html):
        new_html = _BUILD_ID_RE.sub(tag, html)
    else:
        new_html = html.replace("</head>", f"    {tag}\n</head>", 1)

    if new_html != html:
        index_path.write_text(new_html, encoding="utf-8")
        logger.info("Build-ID: index.html stamped with build_id=%s", build_id)
