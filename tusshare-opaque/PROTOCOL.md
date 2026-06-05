# tusShare OPAQUE Protocol Reference

Implementation notes and verified facts about the OPAQUE integration.
Supplement to code comments — covers things that are not obvious from the
source alone and that took investigation to establish.

---

## Library versions

| Side     | Library                        | Version       |
|----------|--------------------------------|---------------|
| Backend  | `opaque-ke` (Rust, native)     | 4.0.1         |
| Frontend | `@serenity-kit/opaque` (WASM)  | 1.1.0         |

Both compile the same `opaque-ke` Rust crate. Wire format is therefore
byte-compatible as long as the CipherSuite matches.

---

## CipherSuite (must match on both sides)

```
OprfCs:      Ristretto255
KeyExchange: TripleDh<Ristretto255, SHA-512>
Ksf:         Argon2id (default parameters)
```

The serenity-kit library uses Ristretto255 by default (the P-256 variant is a
separate package: `@serenity-kit/opaque-p256`). No explicit cipher suite
configuration is needed on either side — defaults match.

### KSF (Key Stretching Function)

Argon2id is applied **client-side only**. The server never runs KSF —
`ServerRegistration::start` and `ServerLogin::start` only evaluate the OPRF.
The client applies KSF to the OPRF output during `finishRegistration` and
`finishLogin`. This means server-side Argon2 parameter tuning has no runtime
cost; it only affects wire format compatibility.

The `keyStretching` parameter exposed by `@serenity-kit/opaque` controls the
Argon2 parameters the WASM client uses. If not specified, it defaults to the
same `Argon2::default()` parameters as the Rust crate — so we leave it unset
and the defaults match. **Verify empirically on first test run.**

---

## `credential_identifier` vs `Identifiers`

These are two distinct concepts in opaque-ke v4 and easy to confuse.

### `credential_identifier`
- A per-user opaque byte string used to derive the user's OPRF key from the
  global OPRF seed stored in `ServerSetup`.
- Passed to `ServerRegistration::start(setup, request, &credential_identifier)`
  and `ServerLogin::start(…, &credential_identifier, params)`.
- We use `username.as_bytes()` (UTF-8) as the credential_identifier.
- Does **not** appear in the API surface of the registration response or login
  response — it is used only server-side for key material derivation.

### `Identifiers { client, server }`
- Cryptographically bound into the OPAQUE envelope during `finishRegistration`.
- Verified by the server during `ServerLogin::start` via the masking MAC.
- Must be identical across registration and login or the login MAC fails.
- Our values: `{ client: username_bytes, server: b"tusshare" }` (Rust) /
  `{ client: username, server: 'tusshare' }` (JS — UTF-8 equivalent).

**Note**: the `ServerRegistration::start` call does **not** take an `Identifiers`
param. The identifiers are bound client-side in `finishRegistration` and are
part of the `RegistrationRecord` the server stores. `ServerLogin::start` reads
them back out of the record and re-binds them into the KE.

---

## `@serenity-kit/opaque` API surface (verified from `index.d.ts`, v1.1.0)

### Client methods

```typescript
// Registration round 1
opaque.client.startRegistration({ password: string })
  → { clientRegistrationState: string, registrationRequest: string }

// Registration round 2
opaque.client.finishRegistration({
  clientRegistrationState: string,
  registrationResponse: string,
  password: string,
  identifiers?: { client?: string, server?: string },
  keyStretching?: KeyStretchingFunctionConfig,
})
  → { registrationRecord: string, exportKey: string, serverStaticPublicKey: string }

// Login round 1
opaque.client.startLogin({ password: string })
  → { clientLoginState: string, startLoginRequest: string }

// Login round 2
opaque.client.finishLogin({
  clientLoginState: string,
  loginResponse: string,
  password: string,
  identifiers?: { client?: string, server?: string },
  keyStretching?: KeyStretchingFunctionConfig,
})
  → { finishLoginRequest: string, sessionKey: string, exportKey: string,
      serverStaticPublicKey: string }
  | undefined  (undefined = wrong password / MAC failure)
```

All string fields use **base64url encoding with no `=` padding** (`-` and `_`
instead of `+` and `/`). The backend uses `base64.urlsafe_b64encode` /
`base64.urlsafe_b64decode` throughout; the JS library emits and accepts the same
format. Do not use `atob()` / `btoa()` on these values — they handle standard
base64 only and will throw on `-` / `_` characters.

`exportKey` is the OPRF output, 64 bytes (SHA-512 sized). The server **never**
sees it. We HKDF it into the KEK.

`sessionKey` is the 3DH session key, 64 bytes. Both client and server derive the
same value. Used as the HMAC root for step-up v2 (`"tusShare-stepup-v2"`).
The server gets it from `ServerLoginFinishResult.session_key`.

`finishLoginRequest` is the KE3 message (MAC). Send it to `/login/finish` as
`client_login_finish`.

### Initialization

```javascript
const mod = await import('/js/lib/opaque.js');
await mod.ready;  // waits for WASM instantiation
```

The WASM is inlined as a base64 data blob in the ESM bundle. No external fetch
needed. Bundle size: ~435 KB.

---

## Key derivation chain

```
password
  │
  ▼ OPAQUE OPRF exchange (2 round trips)
exportKey  (64 bytes, client-only, derived from OPRF output)
  │
  ▼ HKDF-SHA256(salt="tusShare-opaque", info="tusShare-KEK-v1")
KEK  (AES-256-GCM)
  │
  ▼ AES-256-GCM unwrap
masterKey  (AES-256-GCM, random, permanent per account)
  │
  ├─▶ wraps per-file fileKeys
  └─▶ wraps asymmetric private keys (X25519, ML-KEM-768)


sessionKey  (64 bytes, both parties derive identically)
  │
  ▼ HKDF-SHA256(salt=actionKey, info="tusShare-stepup-v2")
signing_key  (HMAC-SHA256, 256 bits)
  │
  ▼ HMAC-SHA256(actionKey|payloadHash|timestampBucket)
step-up HMAC  → X-Step-Up-Token JWT
```

---

## Backend API endpoints

All under `/api/v1/auth/opaque/`:

| Endpoint               | Auth req?         | Purpose                                      |
|------------------------|-------------------|----------------------------------------------|
| `POST /register/start`  | No (invite token) | Server evaluates OPRF for registration       |
| `POST /register/finish` | No (invite token) | Stores RegistrationRecord, creates user, sets cookies |
| `POST /login/start`     | No                | Server evaluates OPRF for login              |
| `POST /login/finish`    | No                | Verifies KE3 MAC, sets auth cookies          |
| `POST /step-up/start`   | Yes               | Server evaluates OPRF for step-up challenge  |
| `POST /migrate/start`   | Yes (legacy user) | Server evaluates OPRF for in-place migration |
| `POST /migrate/finish`  | Yes (legacy user) | Atomically upgrades account to OPAQUE        |

`/login/start` always returns a credential response even for non-existent users
(fake response → MAC fails at finish). Prevents user-enumeration timing attacks.

Login sessions stored in `opaque_login_sessions` (60s TTL, consumed atomically
on `/login/finish`). Step-up sessions use 30s TTL.

### `register/finish` atomicity

The invite mark-used and the user INSERT happen in a single transaction.
The OPAQUE `server_finish_registration` computation (pure CPU, no DB) runs
**before** the transaction starts so DB lock time is minimised.

If the user INSERT fails (e.g. duplicate username via race), the transaction
rolls back — the invite is **not** consumed. The client can retry with a
different username using the same invite token.

---

## Input validation bounds

All OPAQUE protocol fields have tight base64 length caps in the Pydantic
request models (`opaque_auth.py`). These cap at approximately 2× the
theoretical maximum serialized size for the given cipher suite:

| Field                        | Max b64 chars | Rationale |
|------------------------------|---------------|-----------|
| `client_registration_request` | 128          | RegistrationRequest ~32 bytes |
| `client_registration_record`  | 512          | RegistrationUpload ~256 bytes |
| `client_login_start`          | 128          | CredentialRequest ~32 bytes |
| `client_login_finish`         | 512          | CredentialFinalization ~256 bytes |
| `wrapped_master_key`          | 128          | AES-256-GCM ciphertext ~48 bytes |
| IV fields                     | 64           | 12–24 byte IVs |

`session_id` fields are validated as UUID format (not just length) on all
endpoints that accept them (`/login/finish`, `/step-up`, `/migrate/*`).

---

## `Api.js` error handling gotcha

`Api._handleResponse` extracts the error detail with:
```javascript
detail = data.error?.message || data.detail || detail;
```

If `data.detail` is an **object** (e.g. `{"code": "opaque_required", "message": "…"}`),
`data.detail` coerces to `"[object Object]"` as the error message. The caller
cannot distinguish this from a literal string error.

**Pattern used in `_handleLogin`**: use raw `fetch` instead of `Api.post` for the
initial legacy login probe, then inspect `body.detail.code` directly from the
parsed JSON before it's stringified into an error object.

---

## Session cache for OPAQUE users

The master key cache in `sessionStorage` (`Config.auth.sessionStorageKey`):
```json
{ "salt": null, "keyB64url": "<base64url-masterKey>", "cachedAt": 1234567890 }
```

`salt` is `null` for OPAQUE users (no `encryption_salt`). The restore path
(`_restoreCachedMasterKey`) only uses `keyB64url` — it does not need salt and
works unchanged. The key prompt for OPAQUE users re-runs the full OPAQUE login
challenge (2 round trips) rather than re-deriving from password+salt.
