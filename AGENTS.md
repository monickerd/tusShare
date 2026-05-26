# AGENTS.md — tusShare Developer Guide

This file helps AI agents and new contributors get productive quickly. It covers
repo structure, how the key systems work, and the coding conventions in use.

---

## What this project is

**tusShare** is a self-hosted encrypted file transfer application. Files are
encrypted client-side before upload — the server stores ciphertext and never sees
plaintext. Team file sharing uses BLS12-381 proxy re-encryption (PRE). Auth uses
the OPAQUE protocol (zero-knowledge password; server never sees the password).

Stack: FastAPI backend · Vanilla JS SPA · SQLite (dev) / PostgreSQL (prod) ·
Multi-provider storage (local, S3, Azure, GCS).

---

## Repo layout

```
filexfer/
├── backend/
│   └── app/
│       ├── main.py              # FastAPI app, lifespan, router registration
│       ├── config.py            # Pydantic settings (env vars)
│       ├── database.py          # Async DB abstraction (sqlite/pg), migrations
│       ├── redis_client.py      # Optional Redis for rate-limit state
│       ├── sensitive_config.py  # Encrypted-at-rest sensitive settings
│       │
│       ├── auth/                # Auth providers and session management
│       │   ├── dependencies.py  # get_current_user, require_user_role Depends()
│       │   ├── interface.py     # AuthenticatedUser dataclass
│       │   ├── opaque_provider.py # OPAQUE login/register via PyO3 FFI
│       │   ├── stepup.py        # StepUpVerifier ABC, HMAC-based challenge
│       │   ├── jwt.py           # Access/refresh token helpers
│       │   ├── cookies.py       # Cookie set/clear, user_response_dict()
│       │   ├── mfa.py           # TOTP/WebAuthn credential helpers
│       │   ├── totp.py          # TOTP enroll/verify/recovery
│       │   ├── webauthn_helper.py
│       │   ├── ldap_provider.py
│       │   ├── oidc_provider.py
│       │   ├── idp_crypto.py    # Encrypt/decrypt stored IdP configs
│       │   ├── api_key.py       # Machine-to-machine API key auth
│       │   └── service_account.py
│       │
│       ├── routes/              # FastAPI routers (one file per domain)
│       │   ├── _access.py       # Shared permission helpers (see below)
│       │   ├── auth.py          # Logout, refresh, profile, step-up re-auth
│       │   ├── opaque_auth.py   # OPAQUE register/login (2-round protocol)
│       │   ├── mfa.py           # MFA enroll/verify endpoints
│       │   ├── idp_auth.py      # LDAP/OIDC login flow
│       │   ├── files.py         # File metadata + content serving
│       │   ├── folders.py       # Folder CRUD
│       │   ├── uploads.py       # TUS-compatible chunked upload
│       │   ├── shares.py        # Share creation and public resolution
│       │   ├── teams.py         # Team CRUD and membership
│       │   ├── team_roles.py    # Custom team role management
│       │   ├── users.py         # User profile and admin user ops
│       │   ├── policies.py      # Attribute-based policy engine
│       │   ├── trash.py         # Soft-delete and restore
│       │   ├── events.py        # SSE live-update stream
│       │   ├── access_logs.py   # Per-file access log API
│       │   ├── admin*.py        # Admin panel endpoints (split by domain)
│       │   └── theme.py         # Theme/branding settings
│       │
│       ├── models/              # Thin model helpers (no ORM, just helpers)
│       │   ├── role.py          # Permission flags, role tiers, grant/revoke
│       │   ├── user.py          # User row helpers
│       │   ├── file.py          # File/FileChunk row helpers
│       │   ├── share.py         # Share row helpers
│       │   ├── team.py / team_role.py
│       │   ├── permission.py    # ACL row helpers
│       │   └── policy.py        # Policy condition models
│       │
│       ├── services/            # Background services and cross-cutting logic
│       │   ├── event_bus.py     # Broadcasts DB-change events to SSE clients
│       │   ├── sse_broker.py    # Per-connection SSE channel registry
│       │   ├── op_bus.py        # Operational event bus (SIEM / notifications)
│       │   ├── notification_emitter.py # Webhook notification sender
│       │   ├── siem_webhook.py / siem_syslog.py / siem_filters.py
│       │   ├── sharing_rules.py # evaluate_sharing_rules() for POST /shares
│       │   ├── escrow.py        # Key escrow resolution helpers
│       │   ├── av_scanner.py    # AV webhook integration
│       │   ├── live_settings.py # Runtime-editable admin settings cache
│       │   └── trash.py         # Soft-delete and expiry helpers
│       │
│       ├── storage/             # Storage abstraction (F3)
│       │   ├── manager.py       # StorageManager: get_manager(), CRUD wrappers
│       │   ├── base.py          # StorageProvider ABC
│       │   ├── crypto.py        # Encrypt/decrypt blob streams
│       │   └── providers/       # local.py, s3.py, azure.py, gcs.py
│       │
│       ├── middleware/          # FastAPI middleware stack
│       │   ├── csrf.py          # CSRF token check on state-changing requests
│       │   ├── rate_limit.py    # Token-bucket rate limiter (Redis or in-proc)
│       │   ├── stepup.py        # require_step_up() Depends() factory
│       │   ├── security_headers.py
│       │   ├── bandwidth.py     # Upload/download bandwidth throttle
│       │   ├── https_redirect.py
│       │   └── sanitize.py      # Input sanitization middleware
│       │
│       ├── conf/                # Shared named constants (not env settings)
│       │   ├── auth.py          # Cookie names, token paths
│       │   ├── teams.py         # Team role names
│       │   ├── middleware.py    # Rate-limit bucket names
│       │   └── validation.py    # Input length limits
│       │
│       ├── util/                # Pure utility helpers
│       │   ├── crypto.py        # AES-GCM, HKDF, X25519, ML-KEM wrappers
│       │   ├── db.py            # get_admin_setting(), common DB helpers
│       │   ├── http.py          # Range header parsing, content-disposition
│       │   ├── ssrf.py          # validate_endpoint_url() for user-supplied URLs
│       │   ├── sri.py           # SRI hash injection for frontend scripts
│       │   ├── integrity.py     # Manifest check for tracked frontend files
│       │   ├── bls_verify.py    # BLS12-381 signature verification
│       │   └── theme.py         # Brand/theme helpers
│       │
│       └── validation/
│           ├── sanitizers.py    # validate_uuid(), sanitize_filename(), etc.
│           └── validators.py    # Pydantic validators and pagination helpers
│
├── frontend/
│   ├── index.html               # Single HTML shell; all routing is hash-based
│   ├── js/
│   │   ├── config.js            # Frozen Config object (all app constants)
│   │   ├── api.js               # Api module: all HTTP calls go here
│   │   ├── auth.js              # Auth + StepUp modules (login, MFA, OPAQUE)
│   │   ├── crypto.js            # Crypto module + standalone HMAC helpers
│   │   ├── app.js               # App module: SPA router, page rendering
│   │   ├── files.js             # Files module: file browser, upload dispatch
│   │   ├── upload.js            # Upload module: TUS chunked upload
│   │   ├── download.js          # Download module: decrypt + save
│   │   ├── teams.js             # Teams module
│   │   ├── shares.js            # Shares module
│   │   ├── admin.js             # Admin module: admin panel pages
│   │   ├── permissions.js       # Permissions editor stub
│   │   ├── access_logs.js       # Access log viewer stub
│   │   ├── transfer-manager.js  # TransferManager: progress UI
│   │   ├── wizard.js            # First-run setup wizard
│   │   ├── utils.js             # Utils module: el(), showToast(), modal, etc.
│   │   ├── theme-init.js        # Runs before DOM; applies saved theme
│   │   └── lib/                 # Vendored: opaque.js, noble-curves, noble-pq
│   ├── css/                     # main.css, components.css
│   └── themes/                  # CSS variable files (default, light)
│
├── tests/
│   ├── e2e/                     # Playwright + pytest end-to-end tests
│   │   ├── conftest.py          # Full DB wipe + app startup per run
│   │   └── test_00_*.py … test_35_*.py  # Ordered test groups
│   └── unit/                    # pytest unit tests
│
├── backend/scripts/
│   ├── build_manifest.py        # Must run before docker build when frontend changes
│   └── setup_sensitive_config.py
│
├── nginx/                       # nginx config for production
├── systemd/                     # systemd unit files
├── docker-compose.yml
├── pyproject.toml               # ruff linting config
└── eslint.config.js             # ESLint config for frontend/js/
```

---

## Key systems and how they work

### Authentication

Login is a 2-round OPAQUE protocol (opaque_auth.py):
1. Client calls `POST /auth/opaque/login/start` with a blinded password element.
2. Server responds; client calls `POST /auth/opaque/login/finish` with the result.
3. On success, server issues HttpOnly JWT access + refresh cookies.

If MFA is enrolled, step 2 returns a `pending_token` instead of cookies. The client
must verify MFA (`POST /auth/mfa/totp/verify` or WebAuthn) to exchange the pending
token for session cookies.

External IdPs (LDAP, OIDC) follow similar flows via `idp_auth.py` but skip OPAQUE.
Those users have no OPAQUE `export_key` and therefore no personal KEK — they can
only access team-shared files.

### Key hierarchy (end-to-end encryption)

```
OPAQUE export_key
  └─ HKDF → KEK (Key Encryption Key, derived client-side, never sent to server)
       └─ Wraps master_key (AES-GCM, stored as wrapped_master_key in DB)
            └─ Wraps per-file file_key (stored as encrypted_file_key + key_iv)
```

For team files, BLS12-381 PRE re-encrypts a team file key so any team member can
decrypt it using their own keypair without the server ever holding plaintext keys.

### Step-up auth

Sensitive routes are protected by `require_step_up("action.key")` (middleware/stepup.py).
When a request lacks a valid step-up token, the server returns 403 with:
```json
{"detail": {"error": "step_up_required", "action": "action.key", "challenge_type": "password"}}
```
The frontend's `Api` module intercepts this, runs the OPAQUE step-up flow
(`StepUp.challenge()`), attaches the resulting `X-Step-Up-Token` header, and retries.

### Access control

`routes/_access.py` is the shared permission evaluator used by files, folders, and
shares. The main entry point is:
```python
await check_data_permission(db, "file"|"folder", resource_id, user_id, action)
```
Evaluation order (first match wins, with ancestry walk):
1. Explicit deny in ACL → DENY
2. Explicit allow in ACL whose level covers the action → ALLOW
3. Team-based grant for any team the resource belongs to → ALLOW
4. Walk to parent folder and repeat
5. Default → DENY

Permission levels map to action sets via `_LEVEL_ACTIONS` (frozensets). Roles are
checked via `user.has_flag(FLAG_*)` from `models/role.py`.

### Storage (F3)

`storage/manager.py` provides a `StorageManager` with methods:
- `store_blob(db, file_id, stream)` → writes to primary provider + queues async replication
- `get_blob(file_id, storage_key)` → returns a stream
- `delete_blob(db, file_id, storage_key)` → ref-counted delete

Providers (local, S3, Azure, GCS) implement `StorageProvider` from `storage/base.py`.
Active provider is set via admin settings; replicas can be added.

### Frontend routing

`app.js` handles all routing via `window.location.hash`. Hash changes dispatch
to page-rendering functions in their respective modules. There is no build step —
scripts are served as-is. Script load order and SRI hashes are managed by
`backend/scripts/build_manifest.py`; run this before `docker build` whenever
any tracked frontend file changes.

### Live updates (SSE)

`routes/events.py` serves a Server-Sent Events stream. When files are uploaded,
renamed, deleted, or moved, `services/event_bus.py` broadcasts a change event.
The frontend subscribes per-folder and re-renders the file list on receipt.

---

## Backend coding conventions

### Response format

Return plain Python dicts. FastAPI serializes to JSON automatically.

```python
# Single resource
return {"file": file_row_dict}

# List
return {"files": [dict(r) for r in rows], "total": count}

# Simple confirmation
return {"message": "Deleted"}

# Created (use status_code=201)
@router.post("/things", status_code=201)
async def create_thing(...):
    return {"id": new_id, "name": body.name}
```

### Error handling

Always raise `HTTPException`. Use a plain string `detail` for most errors; use a
dict detail only when the client needs to inspect specific fields (e.g., step-up).

```python
_ERR_NOT_FOUND = "File not found"  # module-level constant

raise HTTPException(status_code=404, detail=_ERR_NOT_FOUND)
raise HTTPException(status_code=403, detail="Access denied")
raise HTTPException(status_code=409, detail="Name already exists")
```

Common status codes: 400 validation, 401 unauthenticated, 403 forbidden/step-up,
404 not found, 409 conflict, 451 AV gate.

### Dependency injection

Use `Annotated[Type, Depends(...)]` in every route signature:

```python
from typing import Annotated

async def my_route(
    body: MyRequestModel,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db:   Annotated[Database, Depends(get_db)],
):
```

For admin-only routes use `require_admin` or `require_user_role` instead of
`get_current_user`. For step-up gates add a `_stepup` parameter:

```python
_stepup: Annotated[None, Depends(require_step_up("admin.storage.configure"))],
```

### Naming

- `_underscore_prefix` for private module-level helpers and constants
- `_UPPER_SNAKE` for module-level string constants: `_ERR_NOT_FOUND`, `_SQL_FIND`
- `_bg_tasks: set = set()` at module level when the module spawns background tasks
- Public route handler names mirror the HTTP action: `list_files`, `get_file`, `create_file`, `update_file`, `delete_file`

### SQL

Raw parameterized SQL with `?` placeholders. Repeated queries go in module-level
constants. Multi-line queries use triple-quoted strings with alignment:

```python
_SQL_FILE = "SELECT * FROM files WHERE id = ? AND deleted_at IS NULL"

cursor = await db.execute(
    """
    SELECT f.*, u.username AS owner_name
    FROM   files f
    JOIN   users u ON f.owner_id = u.id
    WHERE  f.folder_id = ?
      AND  f.deleted_at IS NULL
    ORDER  BY f.created_at DESC
    """,
    (folder_id,),
)
rows = await cursor.fetchall()
```

Never use string formatting or f-strings to build SQL; always use parameterized queries.

### Background tasks

```python
_bg_tasks: set = set()   # module level; prevents premature GC

# Inside a route or service:
t = asyncio.create_task(_some_async_work(arg))
_bg_tasks.add(t)
t.add_done_callback(_bg_tasks.discard)
```

Long-running service loops in `main.py` use `while True` + `asyncio.sleep(interval)`
with `logger.exception(...)` to swallow errors without crashing the loop.

### Imports

Order: `from __future__ import annotations` (if used) → stdlib → third-party →
local (`from app.*`). Group with a blank line between each tier. Use absolute
imports only (`from app.routes._access import ...`, not relative).

### Logging

```python
logger = logging.getLogger(__name__)  # module level, after imports

logger.debug("Swept %d record(s)", count)   # routine periodic
logger.warning("OIDC callback: unknown state=%s", state)
logger.exception("Error in cleanup task")   # inside except block
```

### Module docstring

Every file starts with a triple-quoted docstring. Add an endpoint map for route
files:

```python
"""File metadata and content routes.

GET  /api/v1/files/{id}         — fetch metadata
GET  /api/v1/files/{id}/content — stream encrypted bytes (Range supported)
POST /api/v1/files/{id}         — update name or parent folder
"""
```

---

## Frontend coding conventions

### Module pattern

Every JS file exports one global via an IIFE. Private state and functions use a
leading underscore. The returned object is the public API:

```javascript
const MyModule = (() => {
    let _privateState = null;

    function _privateHelper() { ... }

    async function publicMethod(arg) {
        _privateState = await _privateHelper();
        return _privateState;
    }

    return { publicMethod };
})();
```

### API calls

All HTTP calls go through `Api`. Never call `fetch()` directly from feature modules:

```javascript
const data = await Api.get(`${Config.app.apiPrefix}/files/${id}`);
await Api.post(`${Config.app.apiPrefix}/files`, { name, folder_id });
await Api.put(`${Config.app.apiPrefix}/files/${id}`, { original_name: newName });
await Api.del(`${Config.app.apiPrefix}/files/${id}`);
```

`Api` handles CSRF headers, 401→refresh→retry, and step-up challenges automatically.

### DOM creation

Use `Utils.el(tag, attrs, children)` for all DOM elements. Never use `innerHTML`
or string concatenation to build HTML:

```javascript
const row = Utils.el('tr', { className: 'file-row', dataset: { id: file.id } }, [
    Utils.el('td', { textContent: file.name }),
    Utils.el('td', {}, [
        Utils.el('button', {
            className: 'btn btn-sm btn-danger',
            textContent: 'Delete',
            onClick: () => handleDelete(file.id),
        }),
    ]),
]);
container.appendChild(row);
```

Event handlers are passed as `onEventname` (camelCase) attributes to `Utils.el`.

### User-facing errors

```javascript
try {
    await Api.post(url, body);
    Utils.showToast('Done', 'success');
} catch (err) {
    Utils.showToast(err.message || 'An error occurred', 'error');
}
```

`showToast` type values: `'success'`, `'error'`, `'info'`, `'warning'`.

### Async style

Use `async/await` throughout. Reserve `.catch()` for non-fatal parallel work:

```javascript
// Non-fatal fire-and-forget
someAsyncWork().catch(err => console.warn('Non-critical failure', err));

// Parallel with tolerance for partial failure
await Promise.allSettled([taskA(), taskB()]);
```

### Config

All constants come from the frozen `Config` object. Never hardcode values that
belong in config:

```javascript
const prefix  = Config.app.apiPrefix;
const maxSize = Config.upload.maxFileSizeMb * 1024 * 1024;
const timeout = Config.upload.retryBaseDelay;
```

### Unused parameters

Stub functions that must match a required signature use `_` prefix for intentionally
unused parameters:

```javascript
function renderViewer(container, _type, _id) {
    container.textContent = 'Coming soon';
}
```

---

## What NOT to touch

- **`frontend/js/lib/`** — vendored libraries (opaque WASM, noble-curves, noble-pq).
  Never edit these; update via the process in `frontend/js/lib/DEPENDENCIES.md`.

- **`backend/scripts/build_manifest.py`** — regenerates `manifest.json` (SRI hashes
  for all tracked frontend files). Run it before `docker build` when any frontend
  file changes. The server validates hashes at startup.

- **`tusshare-opaque/`** — Rust/PyO3 extension for the OPAQUE protocol. Changes
  require a Rust toolchain and recompiling the `.so`/`.pyd`.

- **Access logs and security event tables** — these tables have Postgres BEFORE
  UPDATE/DELETE triggers that make them append-only. Any route that attempts to
  UPDATE or DELETE from `access_logs` or `security_events` will be silently blocked
  by the trigger. Admin UI over these tables must be read-only.

- **`sensitive_config.py`** — stored config is encrypted at rest. Use the admin UI
  or `scripts/setup_sensitive_config.py` to manage values; never write raw secrets
  into this file or any SQL migration.

---

## Running tests

```bash
# End-to-end (requires Docker or a running app instance)
pytest tests/e2e/ -v

# Unit tests only
pytest tests/unit/ -v

# Single test group
pytest tests/e2e/test_05_teams.py -v
```

E2E tests do a **full database wipe** before each run. Do not point them at a
production database.

## Linting

```bash
# Python — check only
python -m ruff check backend/app

# Python — fix + format
python -m ruff check backend/app --fix
python -m ruff format backend/app

# JavaScript
npx eslint frontend/js
```
