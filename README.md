# tusShare

Self-hosted, end-to-end encrypted file sharing. Files are encrypted in your browser
before they leave your device — the server never sees plaintext content.

---

## Features

### File management
- **Resumable uploads and downloads** — large uploads are chunked and can be paused
  and resumed across browser sessions. Downloads resume from where they left off using
  local browser storage (OPFS), surviving page refreshes and connection drops.
- **Batch download** — select multiple files or an entire folder and download them as
  a single ZIP without any server-side decompression.
- **Drag-and-drop upload** — drop files directly onto the file browser; progress is
  tracked per-file with real-time speed and ETA.
- **Folder organisation** — create nested folders, move and rename files and folders,
  with inline rename directly in the file browser.
- **Antivirus scanning** — files are scanned by the host OS AV engine on upload.
  Downloads are blocked until a clean verdict is recorded.

### Sharing
- **User shares** — share individual files or folders with specific users, with
  read-only or read-write access.
- **Team folders** — create teams with shared encrypted workspaces. Files uploaded
  to a team folder are accessible to all team members without the uploader needing
  to be online — re-encryption is handled cryptographically, not by copying the file.
- **Invite links** — generate time-limited invite links for external collaborators,
  optionally scoped to a specific folder.
- **Sharing restrictions** — administrators can restrict who users may share with
  (e.g. internal-only, domain-allow/block lists, maximum share duration).

### Authentication and access
- **OPAQUE password authentication** — passwords are never sent to the server, even
  in hashed form. The login protocol is zero-knowledge.
- **Multi-factor authentication** — TOTP (authenticator apps) and WebAuthn (hardware
  keys, passkeys, Face ID / Touch ID).
- **SSO integrations** — LDAP and OIDC/OAuth2 for organisations with an existing
  identity provider. Multiple identity providers can be active simultaneously.
- **Public device mode** — mark a login as "public device" to shorten session lifetime
  and keep key material in sessionStorage rather than localStorage.
- **Step-up authentication** — sensitive actions (changing security settings, deleting
  accounts, key management) require re-authentication even within an active session.

### Administration
- **Setup wizard** — guided first-run wizard covering branding, hardware tuning,
  security profile selection, and escrow agent assignment.
- **Security profiles** — choose from built-in profiles (High Security, Recommended,
  Open) or define a custom profile. Profiles can be exported and imported across
  deployments.
- **Theme and branding** — set your organisation's name, upload a logo, and toggle
  optional UI elements. Changes hot-reload without a restart.
- **Role-based access control** — six built-in admin tiers (Server Admin, Org Admin,
  Security Admin, Operational Admin, Role Admin, Audit Admin) plus custom per-team
  roles with fine-grained permission flags.
- **Service accounts** — machine-identity accounts with API key authentication for
  automation and integrations.
- **Policy engine** — org-level and team-level policies with attribute-based conditions
  and cascading overrides.
- **Immutable audit log** — all access and security events are written to append-only
  tables (enforced by database triggers). Logs are exportable and streamable via API
  key.

### Monitoring and integrations
- **SIEM integration** — security events can be forwarded to a syslog receiver,
  an HTTP webhook, or consumed via Server-Sent Events. Events carry a structured
  taxonomy with severity, outcome, and tier classification.
- **S3-compatible storage** — store files locally or on any S3-compatible backend
  (AWS S3, MinIO, Backblaze B2, Cloudflare R2). Hot/cold tiering and async
  replication between providers are supported.
- **Health endpoint** — `/api/v1/health` reports service status and manifest
  integrity for use with load balancers and uptime monitors.

---

## Deployment

tusShare is distributed as a Docker image. A PostgreSQL database is required;
everything else is optional.

### Quick start

```bash
cp .env.example .env
# Edit .env — at minimum set JWT secret, admin credentials, and DB passwords
docker compose up -d
```

The application will be available on `127.0.0.1:9050`. Put nginx or Cloudflare
in front for TLS termination. See the [nginx/](nginx/) directory for a reference
nginx configuration.

On first run, navigate to `/admin/setup` to complete the guided setup wizard.

### Configuration

All settings are controlled via environment variables in `.env`. The `.env.example`
file documents every available option with defaults and guidance.

Key settings to configure before going live:

| Variable | Purpose |
|---|---|
| `TUSSHARE_JWT_SECRET` | JWT signing key — generate a random 64-char hex string |
| `TUSSHARE_ADMIN_USERNAME` | Bootstrap admin account (first run only) |
| `TUSSHARE_ADMIN_PASSWORD` | Bootstrap admin password (first run only) |
| `TUSSHARE_PG_PASSWORD` | App database user password |
| `TUSSHARE_FORCE_HTTPS` | Set `true` when behind a reverse proxy |

### Storage

By default, uploaded files are stored in a Docker volume (`tusshare_data`).
To use S3-compatible object storage, configure a storage provider through the
admin panel after first run. Multiple providers can be active simultaneously
with automatic replication.

---

## License

[MIT](LICENSE) — see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for
third-party component attributions.
