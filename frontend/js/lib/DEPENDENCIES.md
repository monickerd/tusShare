# Self-hosted JS dependencies

This directory contains vendored/bundled third-party libraries served directly
from the app to avoid CDN supply-chain risk.  Each file is a self-contained ESM
bundle with no external imports.

---

## noble-post-quantum.js

| Field        | Value |
|--------------|-------|
| Package      | `@noble/post-quantum@0.6.0` |
| Source file  | `node_modules/@noble/post-quantum/ml-kem.js` |
| Bundle date  | 2026-04-01 |
| SHA-256      | `418086d60d6f32c1c1b72505fff06247b553dfaf930dea589fa3b8845a155aa4` |
| npm integrity (sha512) | `sha512-rv4UfzjtlwrGFBso6IiofY3j4XhLrvjX6Q/w2bVWUoiPvKDIadeW7+xti0c0zND7K+yk62A2XYSLFlQZVHb5Mg==` |
| Exports      | `ml_kem512`, `ml_kem768`, `ml_kem1024` |

### What it is

ML-KEM (formerly Kyber) post-quantum key encapsulation, used for the hybrid
X25519 + ML-KEM-768 scheme that wraps per-file keys in user-type shares.

### Monitoring for updates

- **GitHub releases**: https://github.com/paulmillr/noble-post-quantum/releases
- **GitHub security advisories**: https://github.com/paulmillr/noble-post-quantum/security/advisories
- **npm advisories**: `npm audit` — run periodically from the frontend directory

Subscribe to GitHub release notifications for the repository to get email
alerts on new releases and security patches.

### Update process

1. Check the release notes at the releases page above for breaking API changes.
2. Install the new version:
   ```
   npm install @noble/post-quantum@<new-version>
   ```
3. Regenerate the bundle:
   ```
   npx esbuild node_modules/@noble/post-quantum/ml-kem.js \
     --bundle --format=esm --minify \
     --outfile=frontend/js/lib/noble-post-quantum.js
   ```
4. Verify the export name is still `ml_kem768` (check README or inspect bundle).
   If it changed, update the import in `frontend/js/crypto.js` → `_getMLKEM768`.
5. Compute the new SHA-256 of the bundle output:
   ```
   sha256sum frontend/js/lib/noble-post-quantum.js
   ```
6. Update the SHA-256 in the header comment of `noble-post-quantum.js`
   and the table above.
7. Verify npm package integrity from the lockfile:
   ```
   cat package-lock.json | grep -A5 '"@noble/post-quantum"'
   ```
   Copy the `integrity` field value and update the table above.
8. Clean up npm artifacts if not already in `.gitignore`:
   ```
   rm -rf node_modules package.json package-lock.json
   ```

---

## noble-curves-bls12381.js

| Field        | Value |
|--------------|-------|
| Package      | `@noble/curves@1.8.1` |
| Source file  | `node_modules/@noble/curves/bls12-381.js` |
| Bundle date  | 2026-04-01 |
| SHA-256      | `9198b49400a9e4c2fb220281a14c4ddb8a839a6d407b2d74cada093a128f3c2e` |
| npm integrity (sha512) | `sha512-warwspo+UYUPep0Q+vtdVB4Ugn8GGQj8iyB3gnRWsztmUHTI3S1nhdiWNsPUGL0vud7JlRRk1XEu7Lq1KGTnMQ==` |
| Exports      | `bls12_381` |

### What it is

BLS12-381 elliptic-curve operations — G1/G2 point arithmetic and bilinear pairings —
used for the AFGH Proxy Re-Encryption scheme that encrypts per-file keys for teams
(Phase 6). Pairing-based PRE allows key rotation (C1 re-encryption) without
re-downloading or re-uploading any encrypted file content.

### First-time setup

Run from the project root (requires Node.js):

```
npm install @noble/curves@1.8.1
# The source is CJS, so we need a wrapper to produce a named ESM export.
printf 'import bls from "./node_modules/@noble/curves/bls12-381.js";\nexport const bls12_381 = bls.bls12_381 ?? bls;\n' > bls-entry.tmp.js
npx esbuild --bundle --format=esm --minify --platform=browser \
  bls-entry.tmp.js \
  --outfile=frontend/js/lib/noble-curves-bls12381.js
rm bls-entry.tmp.js
```

Then verify and record the bundle hash:

```
sha256sum frontend/js/lib/noble-curves-bls12381.js
cat package-lock.json | grep -A5 '"@noble/curves"'
```

Update the SHA-256 and npm integrity fields in the table above, and add a header
comment to the bundle file (see `noble-post-quantum.js` for the format).

### Monitoring for updates

- **GitHub releases**: https://github.com/paulmillr/noble-curves/releases
- **GitHub security advisories**: https://github.com/paulmillr/noble-curves/security/advisories
- **npm advisories**: `npm audit`

### Update process

1. Check release notes for API changes — specifically the `bls12_381` export shape,
   `G1.ProjectivePoint`, `G2.ProjectivePoint`, `pairing()`, and `fields.Fp12.toBytes`.
2. Install:
   ```
   npm install @noble/curves@<new-version>
   ```
3. Regenerate the bundle using the same esbuild wrapper command in **First-time setup** above.
4. Verify the export is still named `bls12_381` (check `mod.bls12_381` in `teams.js`
   → `_getBLS()`). If renamed, update `_getBLS()` in `frontend/js/teams.js`.
5. Verify `bls12_381.fields.Fp12.toBytes(gt)` still exists — this serializes the
   576-byte GT element used as HKDF input. If the API changed, update `_keyFromGT`.
6. Compute and record the new SHA-256.
7. Clean up: `rm -rf node_modules package.json package-lock.json`
