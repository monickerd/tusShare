# Third-Party Licenses

tusShare incorporates open-source components listed below.
Each component is used under its original license.

---

## Python dependencies (backend)

| Package | Version | License | Project |
|---|---|---|---|
| fastapi | 0.136.3 | MIT | https://github.com/fastapi/fastapi |
| uvicorn | 0.48.0 | BSD-3-Clause | https://github.com/encode/uvicorn |
| asyncpg | 0.31.0 | Apache-2.0 | https://github.com/MagicStack/asyncpg |
| bcrypt | 5.0.0 | Apache-2.0 | https://github.com/pyca/bcrypt |
| python-multipart | 0.0.29 | Apache-2.0 | https://github.com/Kludex/python-multipart |
| pydantic-settings | 2.14.1 | MIT | https://github.com/pydantic/pydantic-settings |
| filetype | 1.2.0 | MIT | https://github.com/h2non/filetype.py |
| py_ecc | 8.0.0 | MIT | https://github.com/ethereum/py_ecc |
| cryptography | 48.0.0 | Apache-2.0 / BSD-3-Clause | https://github.com/pyca/cryptography |
| qrcode | 8.2 | MIT | https://github.com/lincolnloop/python-qrcode |
| webauthn | 2.7.1 | BSD-2-Clause | https://github.com/duo-labs/py_webauthn |
| authlib | 1.7.2 | BSD-3-Clause | https://github.com/lepture/authlib |
| httpx | 0.28.1 | BSD-3-Clause | https://github.com/encode/httpx |
| aioboto3 | 15.5.0 | Apache-2.0 | https://github.com/terrycain/aioboto3 |
| redis | 7.4.0 | MIT | https://github.com/redis/redis-py |
| azure-storage-blob | 12.29.0 | MIT | https://github.com/Azure/azure-sdk-for-python |
| google-cloud-storage | 3.10.1 | Apache-2.0 | https://github.com/googleapis/python-storage |

### ldap3 — LGPL-3.0

| Package | Version | License | Project |
|---|---|---|---|
| ldap3 | 2.9.1 | **LGPL-3.0** | https://github.com/cannatag/ldap3 |

ldap3 is used unmodified as a dynamically-loaded library for optional LDAP
identity-provider integration. Under LGPL-3.0 section 4, use of an unmodified
LGPL library via dynamic linking does not affect the license of the application
using it. The LGPL-3.0 license text is available at:
https://www.gnu.org/licenses/lgpl-3.0.txt

---

## Vendored JavaScript libraries (frontend)

These files are bundled in `frontend/js/lib/` and compiled into the client-side
application.

### @noble/post-quantum — MIT

```
@noble/post-quantum 0.6.0
Copyright (c) 2024 Paul Miller (https://paulmillr.com)
MIT License
```

### @noble/curves — MIT

```
@noble/curves (bls12-381 bundle)
Copyright (c) 2022 Paul Miller (https://paulmillr.com)
MIT License
```

### @noble/hashes — MIT

```
@noble/hashes
Copyright (c) 2022 Paul Miller (https://paulmillr.com)
MIT License
```

(Bundled as a transitive dependency of @noble/post-quantum and @noble/curves.)

Full MIT license text for all three noble packages:

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

---

## Rust crates (backend extension — tusshare-opaque)

The backend uses a native Python extension (`tusshare_opaque.so`) built from the
`tusshare-opaque` Rust crate using PyO3. It provides the server-side OPAQUE
protocol implementation. The frontend `opaque.js` is a separate bundle from
`@serenity-kit/opaque` (listed above under vendored JavaScript libraries) and is
not built from this crate, though both use the same underlying `opaque-ke` library.

| Crate | Version | License |
|---|---|---|
| opaque-ke | 4.0.1 | MIT / Apache-2.0 |
| argon2 | 0.5.3 | MIT / Apache-2.0 |
| sha2 | 0.10.9 | MIT / Apache-2.0 |
| pyo3 | 0.24.2 | MIT |
| rand | 0.8.6 | MIT / Apache-2.0 |
| bincode | 1.3.3 | MIT |
| serde | 1.0.228 | MIT / Apache-2.0 |

All Rust crates are used under their MIT license option.

**Security monitoring:** The `opaque-ke` and `pyo3` crates are not covered by
automated dependency scanning (Dependabot covers the Cargo.lock but only flags
advisories published to the RustSec advisory database). Review the RustSec
advisories for these crates whenever the backend extension is rebuilt.
