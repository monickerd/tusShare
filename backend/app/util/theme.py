"""Theme configuration loader and HTML injector.

Reads DATA_DIR/theme.json at startup and on hot-reload.  Validated color
variable overrides are injected as an inline <style> block into
frontend/index.html so that CSS custom properties take effect immediately
without touching the theme CSS files (which carry SRI hashes).

theme.json schema (all fields optional):
    {
        "brand_name": "Acme Corp Files",   // 1-64 chars
        "logo_path":  "logo.png",          // filename under DATA_DIR
        "colors": {
            "--color-primary": "#ff5500",  // whitelisted CSS variable names only
            ...
        },
        "ui": {
            // Boolean feature flags.  The frontend applies each flag as a
            // data-ui-<flag-name> attribute on <body> (snake → kebab).
            // CSS targets body[data-ui-<flag>="false"] to suppress elements.
            "admin_transparency_banner": true   // default true when absent
        }
    }
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

# Only variables defined in themes/default/colors.css may be overridden via
# theme.json.  Restricting to this whitelist prevents arbitrary CSS injection.
_ALLOWED_COLOR_VARS: frozenset[str] = frozenset({
    "--color-bg",
    "--color-surface",
    "--color-surface-hover",
    "--color-surface-active",
    "--color-border",
    "--color-border-light",
    "--color-text",
    "--color-text-muted",
    "--color-text-inverse",
    "--color-primary",
    "--color-primary-hover",
    "--color-primary-muted",
    "--color-danger",
    "--color-danger-hover",
    "--color-danger-muted",
    "--color-success",
    "--color-success-hover",
    "--color-success-muted",
    "--color-warning",
    "--color-warning-hover",
    "--color-warning-muted",
    "--color-info",
    "--color-info-muted",
    "--color-overlay",
    "--color-scrollbar-track",
    "--color-scrollbar-thumb",
    "--color-scrollbar-hover",
    "--shadow-toast",
    "--shadow-modal",
    "--shadow-dropdown",
})

# CSS color value: hex, rgb/rgba, hsl/hsla, or 'transparent'.
# No semicolons, braces, or quotes — prevents CSS injection through values.
_CSS_VALUE_RE = re.compile(
    r'^(?:'
    r'#[0-9a-fA-F]{3,8}'              # #rgb  #rgba  #rrggbb  #rrggbbaa
    r'|rgba?\(\s*[\d.,\s%]+\)'        # rgb(…) / rgba(…)
    r'|hsla?\(\s*[\d.,\s%]+\)'        # hsl(…) / hsla(…)
    r'|transparent'
    r')$'
)

# Logo filename: alphanumeric start, then alphanumeric + safe punctuation.
# No slashes, dots at start, or traversal sequences.
_LOGO_FILENAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$')

_BRAND_NAME_MAX = 64

# UI feature flag keys: lowercase letters, digits, underscores; 1-64 chars.
_UI_FLAG_RE = re.compile(r'^[a-z][a-z0-9_]{0,63}$')

# Recognised UI flags and their defaults (used when theme.json omits the key).
# Add new UI flags here as features are introduced.
_UI_FLAG_DEFAULTS: dict[str, bool] = {
    "admin_transparency_banner": True,
}

# ---------------------------------------------------------------------------
# HTML injection markers
# ---------------------------------------------------------------------------

_MARKER_START = "<!-- theme:start -->"
_MARKER_END   = "<!-- theme:end -->"
_BLOCK_RE = re.compile(
    r"\s*" + re.escape(_MARKER_START) + r".*?" + re.escape(_MARKER_END),
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Module-level state (populated by load_theme / inject_theme)
# ---------------------------------------------------------------------------

_config: dict[str, Any] = {}


def load_theme(data_dir: Path) -> dict[str, Any]:
    """Read and validate DATA_DIR/theme.json.  Returns {} if absent or invalid."""
    global _config

    path = data_dir / "theme.json"
    if not path.exists():
        _config = {}
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Theme: failed to read %s: %s", path, exc)
        _config = {}
        return {}

    if not isinstance(raw, dict):
        logger.warning("Theme: theme.json root must be a JSON object")
        _config = {}
        return {}

    config: dict[str, Any] = {}

    # --- brand_name ---
    brand = raw.get("brand_name")
    if brand is not None:
        if isinstance(brand, str) and 1 <= len(brand) <= _BRAND_NAME_MAX:
            config["brand_name"] = brand
        else:
            logger.warning(
                "Theme: brand_name must be 1–%d chars, ignoring", _BRAND_NAME_MAX
            )

    # --- logo_path ---
    logo = raw.get("logo_path")
    if logo is not None:
        if isinstance(logo, str) and _LOGO_FILENAME_RE.match(logo):
            config["logo_path"] = logo
        else:
            logger.warning(
                "Theme: logo_path must be a simple filename with no path separators, ignoring"
            )

    # --- colors ---
    colors_raw = raw.get("colors")
    if colors_raw is not None:
        if not isinstance(colors_raw, dict):
            logger.warning("Theme: 'colors' must be a JSON object, ignoring")
        else:
            colors: dict[str, str] = {}
            for var, val in colors_raw.items():
                if var not in _ALLOWED_COLOR_VARS:
                    logger.warning("Theme: unknown CSS variable %r, ignoring", var)
                    continue
                if not isinstance(val, str) or not _CSS_VALUE_RE.match(val.strip()):
                    logger.warning(
                        "Theme: invalid color value for %r: %r, ignoring", var, val
                    )
                    continue
                colors[var] = val.strip()
            config["colors"] = colors

    # --- ui feature flags ---
    ui_raw = raw.get("ui")
    if ui_raw is not None:
        if not isinstance(ui_raw, dict):
            logger.warning("Theme: 'ui' must be a JSON object, ignoring")
        else:
            flags: dict[str, bool] = {}
            for key, val in ui_raw.items():
                if not isinstance(key, str) or not _UI_FLAG_RE.match(key):
                    logger.warning("Theme: invalid ui flag key %r, ignoring", key)
                    continue
                if key not in _UI_FLAG_DEFAULTS:
                    logger.warning("Theme: unknown ui flag %r, ignoring", key)
                    continue
                if not isinstance(val, bool):
                    logger.warning(
                        "Theme: ui flag %r value must be true/false, ignoring", key
                    )
                    continue
                flags[key] = val
            config["ui"] = flags

    _config = config
    logger.info(
        "Theme: loaded — %d color override(s)%s%s%s",
        len(config.get("colors", {})),
        f", brand={config['brand_name']!r}" if "brand_name" in config else "",
        ", logo configured" if "logo_path" in config else "",
        f", {len(config.get('ui', {}))} ui flag(s)" if config.get("ui") else "",
    )
    return config


def get_theme_config() -> dict[str, Any]:
    """Return the currently active (validated) theme config."""
    return _config


def get_ui_flags() -> dict[str, bool]:
    """Return effective UI feature flags (theme overrides merged onto defaults).

    Flags not specified in theme.json fall back to _UI_FLAG_DEFAULTS so the
    frontend always receives a complete, stable set of flags.
    """
    overrides = _config.get("ui", {})
    return {**_UI_FLAG_DEFAULTS, **overrides}


def get_logo_filename_re() -> re.Pattern:
    """Expose the logo filename regex for route-level path traversal checks."""
    return _LOGO_FILENAME_RE


def inject_theme(frontend_dir: Path, data_dir: Path) -> None:
    """Inject CSS variable overrides as an inline <style> block into index.html.

    Replaces any previously injected block (delimited by marker comments) or
    inserts a new one before </head>.  Idempotent; safe to call on every
    startup and on hot-reload.  No-ops silently when theme.json is absent.
    """
    config = load_theme(data_dir)

    index_path = frontend_dir / "index.html"
    if not index_path.exists():
        logger.warning("Theme injection skipped: index.html not found at %s", index_path)
        return

    html = index_path.read_text(encoding="utf-8")

    # Build the replacement style block (empty string = remove existing block)
    colors = config.get("colors", {})
    if colors:
        vars_css = "\n".join(
            f"        {var}: {val};" for var, val in sorted(colors.items())
        )
        block = (
            f"{_MARKER_START}\n"
            f"    <style>:root {{\n{vars_css}\n    }}</style>\n"
            f"    {_MARKER_END}"
        )
    else:
        block = ""

    # Strip any existing injected block
    cleaned = _BLOCK_RE.sub("", html)

    # Insert new block (if non-empty) immediately before </head>
    if block:
        new_html = cleaned.replace("</head>", f"    {block}\n</head>", 1)
    else:
        new_html = cleaned

    if new_html != html:
        index_path.write_text(new_html, encoding="utf-8")
        if colors:
            logger.info(
                "Theme: index.html updated with %d CSS variable override(s)", len(colors)
            )
        else:
            logger.info("Theme: removed CSS override block from index.html")
    else:
        logger.debug("Theme: index.html already up-to-date")
