# Security

This document describes tusShare's security architecture in an assessment-style
format: for each threat category, it states what protection is in place and what
the residual risk or limitations are.

## Human Statement

I'm a security analyst, but my focus is on the offensive security side. As such,
I tried to cover off as many avenues of attack as I could during the design.
That said, this was a fun side project to build out something useful and get
some experience using AI.

That means: I am some random guy on the internet with no track record, building
an entire app with AI. I heavily encourage you to do your own testing. I don't
have capacity to maintain this, so please feel free to create forks and update
to your heart's content.


---

## Threat model scope

**In scope:** the tusShare server application (FastAPI backend, PostgreSQL
database, frontend SPA), its deployment via Docker behind a reverse proxy, and
the cryptographic protocols used for file and key management.

**Out of scope:** the host operating system, the reverse proxy configuration,
the PostgreSQL server itself, and client device security.

---

## Authentication

### Password authentication (OPAQUE)

tusShare uses the OPAQUE password-authenticated key exchange (PAKE) protocol
for all local-account logins.

- The user's password is **never transmitted to the server**, even in hashed
  form. The login exchange is zero-knowledge: completing the protocol proves
  knowledge of the password without revealing it.
- The server stores an OPAQUE credential file (a random scalar masked by the
  password), not a password hash. A database dump does not yield crackable
  hashes.
- The OPAQUE exchange also derives the client-side key encryption key (KEK)
  used to unwrap the user's master key. The server has no access to the KEK or
  master key at any point.
- Argon2 is used as the slow hash within the OPAQUE protocol, with iteration
  counts tuned at setup time by the hardware scan probe.

**Residual risk:** OPAQUE protects against passive TLS interception and database
theft, but not against a fully compromised server that actively manipulates the
OPAQUE exchange (active MITM at the server). TLS is still required.

### Multi-factor authentication

TOTP (RFC 6238, 30-second window with replay protection) and WebAuthn (hardware
keys, passkeys, platform authenticators) are supported. Administrators can
mandate MFA for all users or specific roles.

### Password recovery

A one-time recovery key is generated client-side at registration and immediately
wraps the master key using AES-256-GCM. The SHA-256 hash of the recovery key is
stored server-side for proof-of-possession. Recovery is a two-round flow:
`recover/start` verifies the hash, `recover/finish` returns the wrapped master
key for client-side unwrap. The plaintext recovery key is shown once and must be
saved offline by the user.

**Residual risk:** The recovery key is an alternative path to the master key
independent of the OPAQUE password. A combination of recovery key file compromise
and database access yields full file decryption. Users should treat the recovery
key with the same care as a private key and store it offline or in a password
manager.

### SSO / identity providers

LDAP and OIDC/OAuth2 are supported. Identity provider users authenticate via
their external IdP; the server validates the returned assertion and enforces the
same session and step-up rules as local accounts.

**Note on key derivation for IdP users:** end-to-end encryption requires a
client-derived KEK. IdP users whose accounts were created without going through
the OPAQUE registration flow do not have a KEK and cannot access encrypted files
until the admin configures the escrow key grant pathway.

### Machine-to-machine access (API keys)

Long-lived API keys are available for automated and integration access. Keys are
scoped to specific operations: `audit_read` (log export), `ops_read` (status
monitoring), `notification_write`. Keys are stored as SHA-256 hashes in the
database — the plaintext is shown only once at creation. Last-used timestamps
are updated asynchronously (60-second flush interval) to avoid per-request
write amplification.

### Session management

- Access tokens are short-lived JWTs (default 5 minutes). Refresh tokens are
  httpOnly cookies (default 7 days, shorter on public-device logins).
- `SameSite=Strict` is set on all cookies to prevent cross-site request forgery
  via cookie submission.
- Session idle timeout is enforced server-side (default 10 minutes).
- The identity-watch SSE stream pushes an immediate logout to all open tabs when
  an admin revokes or deactivates an account.

---

## Authorisation

### Role-based access control

Six built-in admin tiers (Server Admin → Audit Admin) with a strict privilege
hierarchy. Each tier can hold only the flags permitted for that level; the UI
and API enforce this invariant.

Custom team roles allow per-team permission sets (upload, download, share,
manage members, etc.) defined by team owners.

### Step-up authentication

Sensitive operations — security settings changes, user deletion, key management,
profile application — require a fresh step-up token even within an active
session. The step-up token is scoped to a specific action key and short-lived
(default 5-minute window, configurable down to single-use).

### Policy engine

Org-level and team-level policies support attribute-based conditions (user
attributes, time, IP range) with cascade and override semantics. Sharing
restrictions (domain allow/block lists, maximum share duration, internal-only
sharing) are evaluated on every share creation.

---

## End-to-end encryption

### File encryption

Files are encrypted in the browser before upload using AES-256-GCM with a
random per-file key. The plaintext never reaches the server. Chunk boundaries
are authenticated independently; a corrupt or substituted chunk is detected
before decryption.

### Key hierarchy

```
Password → OPAQUE KEK → Master Key (AES-256) ─→ Folder Key (per folder) → File Key (v2-folder)
                                              └──────────────────────────→ File Key (v1-master, legacy)
```

The master key is stored on the server encrypted under the KEK; the server
cannot derive either without the user's password.

Each personal folder has its own AES-256-GCM folder key stored encrypted
(`folder_key_ct` / `folder_key_iv`) under the user's master key. Files
uploaded to a folder with a folder key use `key_version = 'v2-folder'`, where
the file key is wrapped with the folder key rather than directly with the master
key. Files created before folder keys existed retain `key_version = 'v1-master'`
and continue to be accessible via the original path.

### Folder-key sharing

Share links for folder trees use the folder-key model rather than per-file key
wrapping.

- **Share items** — the share carries one `resource_type = 'folder'` item per
  folder in scope. Each item stores the folder's folder key wrapped with the
  share key (`key_model = 'folder-key'`). v2-folder files within those folders
  require no individual share_items; they are covered automatically by the folder
  key.
- **Legacy per-file items** — files with `key_version = 'v1-master'` still use a
  `resource_type = 'file'` share item carrying the file key wrapped with the share
  key (`key_model = 'share-key'`). Both models co-exist transparently in a share.
- **Subfolder exclusion** — a `share_exclusions` table (`share_id`, `folder_id`)
  acts as a server-enforced denylist. The server filters excluded folders from
  `_get_items_with_files` and from `_verify_file_in_share`. Adding a row
  immediately stops access to that folder's contents without changing any key
  material; removing the row reinstates access.
- **Efficiency** — share creation is O(subfolder count) not O(file count). A
  folder tree with thousands of files is shared by wrapping a handful of folder
  keys, not by individually re-wrapping every file key.

**Residual risk:** the share_exclusions check is an ACL, not a cryptographic
gate — an attacker who obtains the raw share token and the share items can still
derive folder keys. Exclusion is an operational revocation mechanism, not a
forward-secrecy boundary. For permanent removal of access, delete the share and
create a new one.

### Metadata encryption (file and folder names)

File and folder names in a user's personal namespace are encrypted client-side
before being stored. The encryption uses two sub-keys derived from the user's
master key via HKDF-SHA-256 with a fixed salt (`tusShare-meta-v1`):

- **`nameKey`** (`info = "filename-enc"`) — AES-256-GCM key used to encrypt the
  name. A random 12-byte IV is prepended to the ciphertext; the combined blob is
  base64-encoded and stored in the `name_ct` column.
- **`searchKey`** (`info = "filename-search"`) — HMAC-SHA-256 key used to produce
  a keyed digest of the lowercased, trimmed name. The 32-byte hex digest is stored
  in the `name_idx` column and allows exact-match server-side search without
  revealing the plaintext.

The server stores only ciphertext and an HMAC tag; it cannot derive either sub-key
or recover any name.

**Backward compatibility**: rows with `name_ct = NULL` fall back to the legacy
`original_name` / `name` columns. On first login after the feature is deployed, the
client fetches all unmigrated rows and re-uploads them with encrypted names in the
background (at most 200 rows per request).

**Team folder limitation**: names in team folders remain unencrypted. Each member's
personal `nameKey` is derived from their own master key, which is not shared with
other team members, so a single shared name key would require a separate key
agreement step. This is a known limitation and is tracked for a future release.

### Team sharing (Proxy Re-Encryption)

Team folders use BLS12-381 proxy re-encryption (AFGH scheme). A re-encryption
key derived from the uploader's key and the team's key allows the server to
transform a ciphertext for a new recipient without ever seeing the plaintext.
The server performs the re-encryption operation but cannot decrypt the result.

### User-to-user sharing (KEM)

Direct file shares use an ephemeral ECDH key encapsulation mechanism. The
sender encrypts the file key under the recipient's public key; only the
recipient can unwrap it.

### Password-protected share links

Share links can optionally be protected with a password chosen at creation time.

- The share key is wrapped with AES-256-GCM using a KEK derived from the password
  via PBKDF2-SHA-256 (100,000 iterations, 16-byte random salt). The salt, GCM IV,
  and wrapped key (48 bytes including authentication tag) are encoded into the URL
  fragment as a `pw1`-prefixed base64url blob.
- The server stores only the sentinel string `'pw1'` in the `password_hash` column
  to signal that protection is active. It never receives, stores, or verifies the
  password.
- The cryptographic gate is the AES-GCM authentication tag. A wrong password
  causes an irrecoverable `DOMException` in the browser's `SubtleCrypto.unwrapKey`
  call before any file key material is accessible — this is not a UI-layer check
  that can be bypassed by a modified client.
- The protected fragment is in the URL hash (`#...`) and is therefore never
  transmitted to the server, even via short-link redirects.
- If a short link is created for a password-protected share, the protected fragment
  is stored in the `short_links` table as the `share_key` value. An attacker with
  database access obtains the encrypted blob but still requires the password to
  derive the KEK and unwrap the share key.

**Residual risk:** password strength determines offline brute-force cost. PBKDF2 at
100,000 iterations raises the cost relative to a raw hash, but short or common
passwords remain vulnerable if an attacker obtains the URL fragment. Users should
choose passwords that are not easily guessable and treat the password as a secret
channel separate from the link itself.

### Key escrow

When escrow is configured, the system moves from a strict zero-knowledge model
to "E2EE with organizational key recovery": the escrow agent can access files
without user participation. This is intentional for enterprise recovery
scenarios but changes the trust boundary — the server is no longer unable to
access file content; the escrow agent is.

Administrators may designate escrow agents who hold a re-encryption key
allowing recovery of files if the original owner is unavailable. Escrow key
grants are proven correct with DLEQ (discrete log equality) proofs, preventing
a malicious server from issuing an incorrect grant that silently points to the
wrong key.

---

## Transport security

### TLS

tusShare binds to `127.0.0.1` only and is designed to sit behind nginx or
Cloudflare for TLS termination. HSTS (`max-age=31536000; includeSubDomains`)
is set on all responses.

**Configuration note:** `TUSSHARE_FORCE_HTTPS=true` should be enabled only
when the application port is not directly internet-accessible, so the
`X-Forwarded-Proto` header cannot be spoofed by external clients.

### Cross-origin isolation

All responses carry:

| Header | Value |
|---|---|
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Resource-Policy` | `same-origin` |

These prevent Spectre-class side-channel attacks and XS-Leak techniques that
depend on cross-origin resource embedding.

---

## XSS

### Content Security Policy

A strict CSP is applied to all HTML responses:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:;
connect-src 'self';
font-src 'self';
media-src 'none'; object-src 'none';
worker-src 'none'; frame-src 'none'; frame-ancestors 'none';
base-uri 'self'; form-action 'self';
upgrade-insecure-requests
```

`'wasm-unsafe-eval'` is required for the OPAQUE WebAssembly module.
`'unsafe-inline'` in `style-src` is a known limitation (runtime pixel
calculations in JS); script execution is unaffected.

### Subresource Integrity (SRI)

All `<script>` and `<link>` tags in `index.html` carry `integrity=` SRI hashes
injected at server startup. A tampered or substituted static asset will be
rejected by the browser before execution.

### DOM hygiene

The SPA does not use `innerHTML`, `document.write`, or `eval` for user-supplied
content. File names, user names, and other dynamic values are inserted via
`textContent` or `createElement` assignments.

### Additional headers

`X-Content-Type-Options: nosniff` prevents MIME-type confusion attacks.
`X-Frame-Options: DENY` and `frame-ancestors 'none'` in CSP prevent clickjacking.

---

## CSRF

All state-changing API requests (`POST`, `PUT`, `PATCH`, `DELETE`) require a
`X-CSRF-Token` header that must match a value stored in a `SameSite=Strict`
session cookie (double-submit pattern). The header cannot be set by a
cross-origin page due to the browser's CORS same-origin restrictions on custom
headers.

Unauthenticated endpoints (login, registration, OPAQUE pre-auth) are exempt
because no session cookie exists at that point — login-CSRF risk is low, as a
valid credential must be supplied.

---

## Injection

### SQL

All database queries use parameterised statements with positional placeholders.
String formatting and f-strings are never used to construct SQL. Input values are
never interpolated into query strings.

### Filename and input sanitization

File names are sanitized through a dedicated layer (`validation/sanitizers.py`)
before storage: path traversal sequences are stripped, null bytes are rejected,
and names are truncated to configured limits. All other user-supplied string
fields (usernames, team names, share labels) have explicit maximum-length
constraints enforced in Pydantic request models before the value reaches any
storage layer.

---

## SSRF

The application makes outbound connections to admin-configured destinations only.
No URL is fetched based on user-supplied input at runtime. The outbound surfaces
are:

1. **SIEM webhook** — security events delivered to an admin-configured HTTPS endpoint
2. **Notification webhooks** — file-share notifications to admin-configured HTTPS endpoints
3. **Storage provider endpoints** — S3-compatible, Azure Blob, and GCS APIs
4. **OIDC discovery** — fetches the IdP's `.well-known/openid-configuration`
5. **AV scanner webhook** — file scan requests to an admin-configured endpoint

All admin-configured HTTP(S) URLs are validated at save time by
`validate_endpoint_url()`, which DNS-resolves the hostname and rejects any
address in a private or reserved range: loopback (`127.0.0.0/8`), RFC 1918
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local
(`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), and IPv6 equivalents. Non-HTTP(S)
schemes are also rejected.

**Residual risk:** DNS rebinding — a hostname that resolves to a public IP at
validation time could rebind to a private IP before the actual connection. This
is a known TOCTOU limitation of DNS-based SSRF prevention. Network-level egress
filtering (see `docker-compose.yml` comments) is the recommended additional
mitigation for operators with strict isolation requirements.

LDAP connections (admin-configured IdP testing) are TCP, not HTTP, and are not
subject to URL validation. Operators should restrict the application container's
outbound network access to known LDAP server addresses at the firewall level.

---

## On-path attacks

### Passive interception

All API traffic requires TLS. The OPAQUE protocol provides an additional layer:
even if TLS is broken passively, the password is not exposed because it is never
transmitted. File content is end-to-end encrypted and cannot be decrypted by a
passive observer.

### Active interception (TLS MITM)

Requires a trusted certificate. HSTS and `upgrade-insecure-requests` in the CSP
reduce the window for HTTP-based downgrade attacks. Certificate pinning is not
implemented (out of scope for a self-hosted application where the operator
controls the CA).

---

## Server compromise

### What an attacker with full database access obtains

| Data | Protected? |
|---|---|
| Passwords | Yes — OPAQUE credential files are not crackable hashes |
| File plaintext | Yes — files are stored encrypted; the server holds no KEK |
| File keys | Yes — file keys are encrypted under folder keys (v2-folder) or master keys (v1-master) |
| Folder keys | Yes — folder keys are encrypted under the user's master key |
| Master keys | Yes — master keys are encrypted under the user's KEK |
| File and folder names | **Partially** — names are encrypted client-side (AES-256-GCM) before storage; team folder names remain plaintext (see below) |
| File sizes, share relationships, timestamps | **No** — stored in plaintext |

### What an attacker with full server (OS-level) access obtains

- All of the above.
- The ability to intercept OPAQUE exchanges going forward (active MITM).
- Access to session tokens in memory (until they expire).
- The `TUSSHARE_JWT_SECRET` from the environment — allows minting arbitrary JWTs
  until rotated.

File plaintexts remain protected unless the attacker also compromises a client
device that has a decrypted master key in memory.

### Escrow transparency

When key escrow is active, an admin transparency banner is shown to all users by
default (suppressible by org policy, which is itself logged as an audit event).

### Immutable audit trail

Security events and access logs are written to PostgreSQL tables protected by
`BEFORE UPDATE` and `BEFORE DELETE` triggers that raise exceptions, making the
log append-only from the application's perspective. A compromised application
account cannot silently delete or alter log entries (a superuser-level DB
compromise would still be required).

### Privilege abuse (rogue admin)

An administrator with sufficient privilege can create a new user account and
then create or modify a team membership policy to add that account to every team
folder. The next time a legitimate team member authenticates, the server performs
the proxy re-encryption step and the rogue account gains read access to those
team files.

This attack is architecturally constrained to being **highly visible**:

- Every user creation, role grant, and policy change is written to the immutable
  audit log and triggers SIEM events.
- Re-encryption key grants require a step-up authentication challenge and are
  individually logged with the granting admin's identity.
- Key escrow grants carry DLEQ proofs that can be independently verified; an
  incorrect grant that silently redirects to the wrong key is detectable.
- Admin role separation limits which tiers can create users, manage team policies,
  and approve key grants — a single compromised admin account is less likely to
  hold all three capabilities simultaneously.

**Residual risk:** No technical control prevents a sufficiently privileged (or
colluding) admin from executing this attack. Mitigation relies on the audit trail
being reviewed. Team owners are alerted when their team membership or key
material changes (see team activity notifications). Operators with strict
requirements should restrict admin account access and configure SIEM alerting on
policy and key-grant events.

---

## Rate limiting and brute-force protection

- Login, registration, and password-change endpoints are rate-limited to 5
  requests per 15-minute window per IP.
- API endpoints are limited to 60 requests per minute per authenticated user.
- An error-rate escalation layer detects scanning behaviour: IPs that accumulate
  repeated 4xx/5xx responses within a configurable window are throttled to 1
  request per second for a cooldown period.

---

## Supply-chain integrity

- All Python dependencies are pinned to exact versions in `requirements.txt`.
  A hash-pinned variant (`requirements-hashed.txt`) can be generated for
  builds that require `--require-hashes`.
- All vendored JavaScript libraries carry bundled license and copyright notices;
  their SRI hashes are verified by the browser on load.
- The application verifies its own static asset manifest at startup (SHA-256
  hashes of all JS/CSS files). A mismatch halts startup and is reported via the
  health endpoint.

---

## Known limitations

| Item | Detail |
|---|---|
| `style-src 'unsafe-inline'` | Runtime pixel calculations prevent a fully strict CSP; tracked for a future nonce-based refactor |
| Team folder names not encrypted | File and folder names in a user's personal namespace are encrypted client-side (see below). Names in *team* folders are stored in plaintext because the team name key derives from the personal master key, which team members do not share with each other. File sizes, share relationships, folder structure, and access timestamps are still stored in plaintext. |
| LDAP users and E2E encryption | IdP-authenticated users require an admin-configured escrow path to access encrypted files |
| Certificate pinning | Not implemented; relies on the operator's PKI |
| Redis optional | Rate-limit counters, SSE state, and upload-chunk offsets are in-process by default; set `TUSSHARE_REDIS_URL` to share state across workers in a multi-container deployment |
| Master key in sessionStorage | The unwrapped master key is held in `sessionStorage` for the tab lifetime so the OPFS download pipeline can access raw key bytes without re-running OPAQUE on every operation. An XSS exploit that bypasses CSP during an active session would expose it. **Mitigation for WebAuthn users**: users with a compatible hardware key (YubiKey 5+, Chrome/Firefox/Safari platform authenticators) can enable *PRF key binding* in MFA settings. When enrolled the key is never written to the browser; each page refresh re-derives it via a physical authenticator tap using the WebAuthn PRF extension — an XSS cannot invoke PRF silently. For non-PRF users: strict CSP, SRI on all scripts, all `innerHTML` paths removed. The master key remains `extractable: true` (a future refactor target) to support the password-change and share-key-derivation flows. |
| OPAQUE ServerSetup backup | The `opaque.server_setup` value in `sensitive_config` is the OPRF seed from which all user credential files are derived. Loss of this value makes every OPAQUE-authenticated account permanently inaccessible — there is no recovery path. It must be backed up securely and independently of the database. If the seed is exfiltrated rather than lost, an attacker who also obtains a user's OPAQUE credential record can perform an offline attack to recover that user's KEK. |
