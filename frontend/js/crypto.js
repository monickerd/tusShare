/**
 * tusShare — E2E Encryption engine via Web Crypto API.
 *
 * Key hierarchy:
 *   password + salt → PBKDF2 → KEK (Key Encryption Key)
 *   KEK wraps → masterKey (random, permanent per account)
 *   masterKey wraps → per-file fileKeys
 *   fileKey encrypts → file chunks (per-chunk IV)
 *
 * Password changes re-wrap the masterKey under a new KEK.
 * The masterKey itself never changes, so all fileKeys remain valid.
 *
 * A one-time recovery key can also unwrap the masterKey if the
 * password is forgotten.
 *
 * The server never sees the raw masterKey, KEK, or recovery key.
 */
const Crypto = (() => {

    function _cfg() { return Config.crypto; }

    // ===================================================================
    // KEK derivation (replaces the old deriveMasterKey)
    // ===================================================================

    /**
     * Derive a KEK (Key Encryption Key) from password + salt via PBKDF2.
     * The KEK is used to wrap/unwrap the real masterKey.
     */
    async function deriveKEK(password, saltHex) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        );
        const salt = _hexToBytes(saltHex);
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: _cfg().pbkdf2Iterations, hash: _cfg().hashAlgorithm },
            keyMaterial,
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            false,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    /**
     * @deprecated Use deriveKEK instead. Kept for backward compat during migration.
     */
    async function deriveMasterKey(password, saltHex) {
        return deriveKEK(password, saltHex);
    }

    // ===================================================================
    // Master key generation and wrapping
    // ===================================================================

    /**
     * Generate a random AES-256-GCM master key (extractable so it can be wrapped).
     */
    async function generateMasterKey() {
        return crypto.subtle.generateKey(
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    /**
     * Wrap (encrypt) a masterKey with a wrapping key (KEK or recovery key).
     * Returns { wrappedKeyB64, ivB64 }.
     */
    async function wrapMasterKey(masterKey, wrappingKey) {
        const iv = crypto.getRandomValues(new Uint8Array(_cfg().ivLength));
        const rawKey = await crypto.subtle.exportKey('raw', masterKey);
        const wrapped = await crypto.subtle.encrypt(
            { name: _cfg().algorithm, iv },
            wrappingKey,
            rawKey
        );
        return {
            wrappedKeyB64: _arrayBufToBase64(wrapped),
            ivB64: _arrayBufToBase64(iv.buffer),
        };
    }

    /**
     * Unwrap (decrypt) a masterKey using a wrapping key (KEK or recovery key).
     * Returns a CryptoKey.
     */
    async function unwrapMasterKey(wrappedKeyB64, ivB64, wrappingKey) {
        const wrapped = _base64ToArrayBuf(wrappedKeyB64);
        const iv = _base64ToArrayBuf(ivB64);
        const rawKey = await crypto.subtle.decrypt(
            { name: _cfg().algorithm, iv: new Uint8Array(iv) },
            wrappingKey,
            wrapped
        );
        return crypto.subtle.importKey(
            'raw', rawKey,
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    // ===================================================================
    // Recovery key
    // ===================================================================

    /**
     * Generate a recovery key — a random AES-256 key exported as a
     * human-readable base64url string the user writes down.
     *
     * Returns { recoveryKey: CryptoKey, recoveryKeyString: string }.
     */
    async function generateRecoveryKey() {
        const key = await crypto.subtle.generateKey(
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
        const raw = await crypto.subtle.exportKey('raw', key);
        const keyString = _arrayBufToBase64url(raw);
        return { recoveryKey: key, recoveryKeyString: keyString };
    }

    /**
     * Import a recovery key from the base64url string the user entered.
     */
    async function importRecoveryKey(recoveryKeyString) {
        const raw = _base64urlToArrayBuf(recoveryKeyString);
        return crypto.subtle.importKey(
            'raw', raw,
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    /**
     * Hash a recovery key string with SHA-256 for server-side storage.
     * The server stores only the hash — never the raw key.
     */
    async function hashRecoveryKey(recoveryKeyString) {
        const enc = new TextEncoder();
        const digest = await crypto.subtle.digest('SHA-256', enc.encode(recoveryKeyString));
        return _arrayBufToHex(digest);
    }

    // ===================================================================
    // Full registration bundle
    // ===================================================================

    /**
     * Generate everything needed for a new account's E2E encryption setup.
     *
     * Called client-side during registration. Returns all the wrapped blobs
     * and the plaintext recovery key (shown once to the user).
     *
     * @param {string} password - The user's chosen password.
     * @param {string} saltHex  - Hex-encoded salt (generated server-side or client-side).
     * @returns {object} { masterKey, wrappedMasterKeyB64, wrappedMasterKeyIvB64,
     *                      recoveryKeyString, recoveryWrappedB64, recoveryIvB64,
     *                      recoveryKeyHash }
     */
    async function generateRegistrationBundle(password, saltHex) {
        // 1. Generate the permanent master key
        const masterKey = await generateMasterKey();

        // 2. Derive KEK from password + salt, wrap master key
        const kek = await deriveKEK(password, saltHex);
        const { wrappedKeyB64: wrappedMasterKeyB64, ivB64: wrappedMasterKeyIvB64 } =
            await wrapMasterKey(masterKey, kek);

        // 3. Generate recovery key, wrap master key with it
        const { recoveryKey, recoveryKeyString } = await generateRecoveryKey();
        const { wrappedKeyB64: recoveryWrappedB64, ivB64: recoveryIvB64 } =
            await wrapMasterKey(masterKey, recoveryKey);

        // 4. Hash recovery key for server-side verification
        const recoveryKeyHash = await hashRecoveryKey(recoveryKeyString);

        return {
            masterKey,
            wrappedMasterKeyB64,
            wrappedMasterKeyIvB64,
            recoveryKeyString,
            recoveryWrappedB64,
            recoveryIvB64,
            recoveryKeyHash,
        };
    }

    /**
     * Re-wrap the master key after a password change.
     *
     * @param {string} oldPassword - Current password.
     * @param {string} newPassword - New password.
     * @param {string} oldSaltHex  - Current salt.
     * @param {string} newSaltHex  - New salt (rotated on password change).
     * @param {string} wrappedMasterKeyB64 - Current wrapped master key.
     * @param {string} wrappedMasterKeyIvB64 - Current wrapping IV.
     * @returns {object} { masterKey, newWrappedKeyB64, newIvB64 }
     */
    async function rewrapMasterKeyForPasswordChange(
        oldPassword, newPassword, oldSaltHex, newSaltHex,
        wrappedMasterKeyB64, wrappedMasterKeyIvB64
    ) {
        // Unwrap with old KEK
        const oldKEK = await deriveKEK(oldPassword, oldSaltHex);
        const masterKey = await unwrapMasterKey(wrappedMasterKeyB64, wrappedMasterKeyIvB64, oldKEK);

        // Re-wrap with new KEK
        const newKEK = await deriveKEK(newPassword, newSaltHex);
        const { wrappedKeyB64: newWrappedKeyB64, ivB64: newIvB64 } =
            await wrapMasterKey(masterKey, newKEK);

        // Round-trip verify: unwrap the new blob immediately and compare raw bytes.
        // Catches logic bugs (wrong key passed to wrapMasterKey) before they reach the server.
        // AES-GCM auth tag ensures tampered ciphertext would throw here; this adds a
        // belt-and-suspenders byte-level check on top of that.
        const verifiedMasterKey = await unwrapMasterKey(newWrappedKeyB64, newIvB64, newKEK);
        const [origRaw, verRaw] = await Promise.all([
            crypto.subtle.exportKey('raw', masterKey),
            crypto.subtle.exportKey('raw', verifiedMasterKey),
        ]);
        const origBytes = new Uint8Array(origRaw);
        const verBytes  = new Uint8Array(verRaw);
        if (origBytes.length !== verBytes.length || origBytes.some((b, i) => b !== verBytes[i])) {
            throw new Error('Master key re-wrap verification failed: round-trip byte mismatch');
        }

        return { masterKey, newWrappedKeyB64, newIvB64 };
    }

    // ===================================================================
    // Per-file key operations (unchanged)
    // ===================================================================

    /**
     * Generate a random AES-256-GCM file key (extractable).
     */
    async function generateFileKey() {
        return crypto.subtle.generateKey(
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt a file key with the master key.
     */
    async function encryptFileKey(fileKey, masterKey) {
        const iv = crypto.getRandomValues(new Uint8Array(_cfg().ivLength));
        const rawKey = await crypto.subtle.exportKey('raw', fileKey);
        const encrypted = await crypto.subtle.encrypt(
            { name: _cfg().algorithm, iv },
            masterKey,
            rawKey
        );
        return {
            encryptedKeyB64: _arrayBufToBase64(encrypted),
            ivB64: _arrayBufToBase64(iv.buffer),
        };
    }

    /**
     * Decrypt a file key using the master key.
     */
    async function decryptFileKey(encryptedKeyB64, ivB64, masterKey) {
        const encrypted = _base64ToArrayBuf(encryptedKeyB64);
        const iv = _base64ToArrayBuf(ivB64);
        const rawKey = await crypto.subtle.decrypt(
            { name: _cfg().algorithm, iv: new Uint8Array(iv) },
            masterKey,
            encrypted
        );
        return crypto.subtle.importKey(
            'raw', rawKey,
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true, ['encrypt', 'decrypt']
        );
    }

    // ===================================================================
    // Chunk encryption/decryption (unchanged)
    // ===================================================================

    async function encryptChunk(plaintext, fileKey) {
        const iv = crypto.getRandomValues(new Uint8Array(_cfg().ivLength));
        const ciphertext = await crypto.subtle.encrypt(
            { name: _cfg().algorithm, iv },
            fileKey,
            plaintext
        );
        return {
            ciphertext,
            ivB64: _arrayBufToBase64(iv.buffer),
        };
    }

    async function decryptChunk(ciphertext, ivB64, fileKey) {
        const iv = _base64ToArrayBuf(ivB64);
        return crypto.subtle.decrypt(
            { name: _cfg().algorithm, iv: new Uint8Array(iv) },
            fileKey,
            ciphertext
        );
    }

    // ===================================================================
    // Share key operations (unchanged)
    // ===================================================================

    async function generateShareKey() {
        return crypto.subtle.generateKey(
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    async function exportKeyToBase64url(key) {
        const raw = await crypto.subtle.exportKey('raw', key);
        return _arrayBufToBase64url(raw);
    }

    async function importKeyFromBase64url(b64url) {
        const raw = _base64urlToArrayBuf(b64url);
        return crypto.subtle.importKey(
            'raw', raw,
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        );
    }

    async function wrapFileKeyForShare(fileKey, shareKey) {
        const iv = crypto.getRandomValues(new Uint8Array(_cfg().ivLength));
        const rawKey = await crypto.subtle.exportKey('raw', fileKey);
        const wrapped = await crypto.subtle.encrypt(
            { name: _cfg().algorithm, iv },
            shareKey,
            rawKey
        );
        return {
            wrappedKeyB64: _arrayBufToBase64(wrapped),
            ivB64: _arrayBufToBase64(iv.buffer),
        };
    }

    async function unwrapFileKeyFromShare(wrappedKeyB64, ivB64, shareKey) {
        const wrapped = _base64ToArrayBuf(wrappedKeyB64);
        const iv = _base64ToArrayBuf(ivB64);
        const rawKey = await crypto.subtle.decrypt(
            { name: _cfg().algorithm, iv: new Uint8Array(iv) },
            shareKey,
            wrapped
        );
        return crypto.subtle.importKey(
            'raw', rawKey,
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true, ['encrypt', 'decrypt']
        );
    }

    // ===================================================================
    // Hybrid X25519 + ML-KEM-768 asymmetric key operations (Phase 5b)
    //
    // Key pair is generated once per account at first login.
    // Private keys are wrapped with masterKey (AES-GCM) before storage.
    // The raw private keys are only ever held in memory, never persisted raw.
    //
    // KEM-based file key wrapping for user shares:
    //   Sender:
    //     1. Generate ephemeral X25519 key pair
    //     2. X25519 DH: ephemeral_priv × recipient_x25519_pub → ss1 (32 bytes)
    //     3. ML-KEM-768 encapsulate(recipient_mlkem_pub) → (kem_ct, ss2)
    //     4. HKDF-SHA-256(ss1 || ss2, info="tusShare-filekey-v1") → wrapping_key
    //     5. AES-GCM encrypt(fileKey, wrapping_key) → { wrapped_key, iv }
    //     Store: ephemeral_x25519_pub, kem_ct, wrapped_key, iv
    //
    //   Recipient:
    //     1. X25519 DH: recipient_x25519_priv × ephemeral_x25519_pub → ss1
    //     2. ML-KEM-768 decapsulate(recipient_mlkem_priv, kem_ct) → ss2
    //     3. HKDF-SHA-256(ss1 || ss2, info="tusShare-filekey-v1") → wrapping_key
    //     4. AES-GCM decrypt(wrapped_key, iv, wrapping_key) → fileKey
    // ===================================================================

    // Lazy-loaded ML-KEM-768 module (loaded from self-hosted bundle on first use).
    // noble-post-quantum.js is a self-contained ESM bundle of @noble/post-quantum@0.6.0
    // generated via: npx esbuild node_modules/@noble/post-quantum/ml-kem.js --bundle --format=esm
    // See /js/lib/DEPENDENCIES.md for version info and update instructions.
    let _mlkem768Module = null;

    // Browsers use incompatible X25519 algorithm names:
    //   Chrome: { name: 'ECDH', namedCurve: 'X25519' }
    //   Firefox 130+ / standard: { name: 'X25519' }
    // Detected once on first use and cached.
    let _x25519AlgoName = null;

    async function _ensureX25519Algo() {
        if (_x25519AlgoName !== null) return;
        try {
            await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
            _x25519AlgoName = 'X25519';
        } catch {
            _x25519AlgoName = 'ECDH';
        }
    }

    function _x25519KeyParams() {
        return _x25519AlgoName === 'X25519'
            ? { name: 'X25519' }
            : { name: 'ECDH', namedCurve: 'X25519' };
    }

    function _x25519DeriveParams(publicKey) {
        return _x25519AlgoName === 'X25519'
            ? { name: 'X25519', public: publicKey }
            : { name: 'ECDH', public: publicKey };
    }

    async function _getMLKEM768() {
        if (!_mlkem768Module) {
            try {
                const mod = await import('/js/lib/noble-post-quantum.js');
                _mlkem768Module = mod.ml_kem768;
                if (!_mlkem768Module) {
                    throw new Error('ml_kem768 export not found in noble-post-quantum.js');
                }
            } catch (err) {
                throw new Error(
                    `Failed to load ML-KEM-768 library: ${err.message}. ` +
                    'Check that /js/lib/noble-post-quantum.js is present and being served.'
                );
            }
        }
        return _mlkem768Module;
    }

    /**
     * Generate a hybrid X25519 + ML-KEM-768 key pair.
     *
     * Returns { x25519KeyPair, mlkem768KeyPair } where:
     *   x25519KeyPair  — { publicKey: CryptoKey, privateKey: CryptoKey }
     *   mlkem768KeyPair — { publicKey: Uint8Array, secretKey: Uint8Array }
     */
    async function generateAsymmetricKeyPair() {
        const mlkem = await _getMLKEM768();
        await _ensureX25519Algo();

        // X25519: native WebCrypto — Chrome: ECDH+namedCurve, Firefox 130+: standalone X25519
        const x25519KeyPair = await crypto.subtle.generateKey(
            _x25519KeyParams(),
            true,
            ['deriveBits']
        );

        // ML-KEM-768: random bytes → deterministic keygen
        const seed = crypto.getRandomValues(new Uint8Array(64));
        const mlkem768KeyPair = mlkem.keygen(seed);

        return { x25519KeyPair, mlkem768KeyPair };
    }

    /**
     * Export the public keys as base64 strings for server storage.
     * Returns { x25519PublicKeyB64, mlkem768PublicKeyB64 }
     */
    async function exportAsymmetricPublicKeys(x25519KeyPair, mlkem768KeyPair) {
        const x25519Raw = await crypto.subtle.exportKey('raw', x25519KeyPair.publicKey);
        return {
            x25519PublicKeyB64: _arrayBufToBase64(x25519Raw),
            mlkem768PublicKeyB64: _arrayBufToBase64(mlkem768KeyPair.publicKey.buffer),
        };
    }

    /**
     * Wrap the asymmetric private keys with masterKey (AES-GCM).
     *
     * Each key gets its own random IV to prevent (key, IV) reuse — reusing the
     * same IV under the same AES-GCM key for two different plaintexts is a
     * catastrophic failure that allows ciphertext XOR and auth-key recovery.
     *
     * The stored IV field (asymmetric_key_iv) carries both IVs concatenated:
     *   bytes 0–11  → IV for x25519 private key
     *   bytes 12–23 → IV for ML-KEM-768 secret key
     *
     * Returns { x25519PrivWrappedB64, mlkem768PrivWrappedB64, asymKeyIvB64 }
     */
    async function wrapAsymmetricPrivateKeys(x25519KeyPair, mlkem768KeyPair, masterKey) {
        const ivX25519 = crypto.getRandomValues(new Uint8Array(_cfg().ivLength));
        const ivMlkem  = crypto.getRandomValues(new Uint8Array(_cfg().ivLength));

        // JWK export works in all browsers; raw private key export is not spec'd for X25519.
        // The 'd' field is the raw 32-byte scalar — same plaintext as the old raw export.
        const x25519Jwk = await crypto.subtle.exportKey('jwk', x25519KeyPair.privateKey);
        const x25519Wrapped = await crypto.subtle.encrypt(
            { name: _cfg().algorithm, iv: ivX25519 },
            masterKey,
            _base64urlToArrayBuf(x25519Jwk.d)
        );

        const mlkem768Wrapped = await crypto.subtle.encrypt(
            { name: _cfg().algorithm, iv: ivMlkem },
            masterKey,
            mlkem768KeyPair.secretKey.buffer
        );

        // Pack both 12-byte IVs into a single 24-byte field so the DB schema is unchanged
        const combinedIv = new Uint8Array(ivX25519.length + ivMlkem.length);
        combinedIv.set(ivX25519, 0);
        combinedIv.set(ivMlkem, ivX25519.length);

        return {
            x25519PrivWrappedB64: _arrayBufToBase64(x25519Wrapped),
            mlkem768PrivWrappedB64: _arrayBufToBase64(mlkem768Wrapped),
            asymKeyIvB64: _arrayBufToBase64(combinedIv.buffer),
        };
    }

    /**
     * Unwrap the asymmetric private keys using the masterKey.
     *
     * asymKeyIvB64 encodes 24 bytes: the first 12 are the X25519 IV,
     * the next 12 are the ML-KEM-768 IV (packed by wrapAsymmetricPrivateKeys).
     *
     * Returns { x25519PrivateKey: CryptoKey, mlkem768SecretKey: Uint8Array }
     */
    async function unwrapAsymmetricPrivateKeys(
        x25519PrivWrappedB64, mlkem768PrivWrappedB64, asymKeyIvB64, masterKey,
        x25519PublicKeyB64
    ) {
        const mlkem = await _getMLKEM768();
        await _ensureX25519Algo();
        const ivBytes = new Uint8Array(_base64ToArrayBuf(asymKeyIvB64));
        const ivLen = _cfg().ivLength;

        // New format: 24-byte field = two distinct IVs (ivLen each).
        // Legacy format: 12-byte field = one IV shared for both keys (pre-IV-reuse fix).
        // Detect by total length: if only one IV worth of bytes, use it for both.
        const ivX25519 = ivBytes.slice(0, ivLen);
        const ivMlkem  = ivBytes.length >= ivLen * 2 ? ivBytes.slice(ivLen, ivLen * 2) : ivX25519;

        const x25519RawBuf = await crypto.subtle.decrypt(
            { name: _cfg().algorithm, iv: ivX25519 },
            masterKey,
            _base64ToArrayBuf(x25519PrivWrappedB64)
        );
        // Raw private key import is not spec'd for X25519 — use JWK instead.
        // 'd' = base64url of the raw 32-byte private scalar (same bytes stored by wrapAsymmetricPrivateKeys).
        // 'x' = public key, required by spec for OKP JWK private key import.
        const dB64url = _arrayBufToBase64url(x25519RawBuf);
        const xB64url = x25519PublicKeyB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const x25519PrivateKey = await crypto.subtle.importKey(
            'jwk',
            { kty: 'OKP', crv: 'X25519', d: dB64url, x: xB64url },
            _x25519KeyParams(),
            false,
            ['deriveBits']
        );

        const mlkem768RawBuf = await crypto.subtle.decrypt(
            { name: _cfg().algorithm, iv: ivMlkem },
            masterKey,
            _base64ToArrayBuf(mlkem768PrivWrappedB64)
        );
        const mlkem768SecretKey = new Uint8Array(mlkem768RawBuf);

        return { x25519PrivateKey, mlkem768SecretKey };
    }

    const _HKDF_INFO_FILEKEY = new TextEncoder().encode('tusShare-filekey-v1');

    /**
     * Derive a 256-bit AES-GCM wrapping key from two shared secrets via HKDF.
     * Implements the hybrid KEM: HKDF-SHA-256(ss1 || ss2, info="tusShare-filekey-v1")
     */
    async function _deriveWrappingKeyFromSecrets(ss1Bytes, ss2Bytes) {
        const combined = new Uint8Array(ss1Bytes.byteLength + ss2Bytes.byteLength);
        combined.set(new Uint8Array(ss1Bytes), 0);
        combined.set(new Uint8Array(ss2Bytes), ss1Bytes.byteLength);

        const hkdfKey = await crypto.subtle.importKey(
            'raw', combined, 'HKDF', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(32),  // all-zero salt (key material is already strong)
                info: _HKDF_INFO_FILEKEY,
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Wrap a fileKey for a specific recipient using hybrid X25519 + ML-KEM-768.
     *
     * @param {CryptoKey}  fileKey               - The file key to wrap.
     * @param {string}     recipientX25519PubB64 - Recipient's X25519 public key (base64).
     * @param {string}     recipientMLKEM768PubB64 - Recipient's ML-KEM-768 public key (base64).
     * @returns {{ wrappedFileKeyB64, keyIvB64, ephemeralX25519PubB64, kemCiphertextB64 }}
     */
    async function encapsulateFileKeyForUser(fileKey, recipientX25519PubB64, recipientMLKEM768PubB64) {
        const mlkem = await _getMLKEM768();
        await _ensureX25519Algo();

        // Import recipient's X25519 public key
        const recipientX25519Pub = await crypto.subtle.importKey(
            'raw', _base64ToArrayBuf(recipientX25519PubB64),
            _x25519KeyParams(),
            false,
            []
        );

        // Generate ephemeral X25519 key pair
        const ephemeralX25519 = await crypto.subtle.generateKey(
            _x25519KeyParams(),
            true,
            ['deriveBits']
        );

        // X25519 DH: ephemeral_priv × recipient_pub → ss1
        const ss1 = await crypto.subtle.deriveBits(
            _x25519DeriveParams(recipientX25519Pub),
            ephemeralX25519.privateKey,
            256
        );

        // ML-KEM-768 encapsulate: recipient_pub → (kem_ciphertext, ss2)
        const recipientMLKEM768Pub = new Uint8Array(_base64ToArrayBuf(recipientMLKEM768PubB64));
        const { cipherText: kemCiphertext, sharedSecret: ss2 } = mlkem.encapsulate(recipientMLKEM768Pub);

        // Derive AES-GCM wrapping key via HKDF
        const wrappingKey = await _deriveWrappingKeyFromSecrets(ss1, ss2);

        // Wrap the file key
        const iv = crypto.getRandomValues(new Uint8Array(_cfg().ivLength));
        const rawFileKey = await crypto.subtle.exportKey('raw', fileKey);
        const wrapped = await crypto.subtle.encrypt(
            { name: _cfg().algorithm, iv },
            wrappingKey,
            rawFileKey
        );

        // Export ephemeral X25519 public key
        const ephemeralPubRaw = await crypto.subtle.exportKey('raw', ephemeralX25519.publicKey);

        return {
            wrappedFileKeyB64: _arrayBufToBase64(wrapped),
            keyIvB64: _arrayBufToBase64(iv.buffer),
            ephemeralX25519PubB64: _arrayBufToBase64(ephemeralPubRaw),
            kemCiphertextB64: _arrayBufToBase64(kemCiphertext.buffer),
        };
    }

    /**
     * Unwrap a fileKey received in a user share using the recipient's private keys.
     *
     * @param {string}     wrappedFileKeyB64      - Wrapped file key (base64).
     * @param {string}     keyIvB64               - AES-GCM IV (base64).
     * @param {string}     ephemeralX25519PubB64  - Sender's ephemeral X25519 pub (base64).
     * @param {string}     kemCiphertextB64       - ML-KEM-768 ciphertext (base64).
     * @param {CryptoKey}  myX25519PrivateKey     - Recipient's X25519 private key (CryptoKey).
     * @param {Uint8Array} myMLKEM768SecretKey    - Recipient's ML-KEM-768 secret key.
     * @returns {CryptoKey} The decrypted file key.
     */
    async function decapsulateFileKeyFromUser(
        wrappedFileKeyB64, keyIvB64,
        ephemeralX25519PubB64, kemCiphertextB64,
        myX25519PrivateKey, myMLKEM768SecretKey
    ) {
        const mlkem = await _getMLKEM768();
        await _ensureX25519Algo();

        // Step 1: Import sender's ephemeral X25519 public key
        let ephemeralX25519Pub;
        try {
            ephemeralX25519Pub = await crypto.subtle.importKey(
                'raw', _base64ToArrayBuf(ephemeralX25519PubB64),
                _x25519KeyParams(),
                false,
                []
            );
        } catch (e) {
            throw new Error(`KEM step 1 (import ephemeral X25519): ${e.message}`);
        }

        // Step 2: X25519 DH: my_priv × ephemeral_pub → ss1
        let ss1;
        try {
            ss1 = await crypto.subtle.deriveBits(
                _x25519DeriveParams(ephemeralX25519Pub),
                myX25519PrivateKey,
                256
            );
        } catch (e) {
            throw new Error(`KEM step 2 (X25519 DH): ${e.message}`);
        }

        // Step 3: ML-KEM-768 decapsulate: my_secret_key + kem_ciphertext → ss2
        const kemCiphertext = new Uint8Array(_base64ToArrayBuf(kemCiphertextB64));
        let ss2;
        try {
            ss2 = mlkem.decapsulate(kemCiphertext, myMLKEM768SecretKey);
        } catch (e) {
            throw new Error(
                `KEM step 3 (ML-KEM decapsulate): ${e.message} ` +
                `[ct=${kemCiphertext.length}B sk=${myMLKEM768SecretKey?.length}B]`
            );
        }

        // Step 4: Derive AES-GCM wrapping key via HKDF
        let wrappingKey;
        try {
            wrappingKey = await _deriveWrappingKeyFromSecrets(ss1, ss2);
        } catch (e) {
            throw new Error(`KEM step 4 (HKDF): ${e.message}`);
        }

        // Step 5: AES-GCM decrypt the wrapped key
        const iv = _base64ToArrayBuf(keyIvB64);
        let rawFileKey;
        try {
            rawFileKey = await crypto.subtle.decrypt(
                { name: _cfg().algorithm, iv: new Uint8Array(iv) },
                wrappingKey,
                _base64ToArrayBuf(wrappedFileKeyB64)
            );
        } catch (e) {
            throw new Error(
                `KEM step 5 (AES-GCM decrypt — key mismatch?): ${e.message} ` +
                `[ss1=${new Uint8Array(ss1).length}B ss2=${ss2.length}B` +
                ` ss2buf=${ss2.buffer.byteLength}B ct=${kemCiphertext.length}B` +
                ` sk=${myMLKEM768SecretKey?.length}B]`
            );
        }

        return crypto.subtle.importKey(
            'raw', rawFileKey,
            { name: _cfg().algorithm, length: _cfg().aesKeyLength },
            true, ['encrypt', 'decrypt']
        );
    }

    // ===================================================================
    // Internal helpers
    // ===================================================================

    function _hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    function _arrayBufToHex(buffer) {
        const bytes = new Uint8Array(buffer);
        let hex = '';
        for (const b of bytes) hex += b.toString(16).padStart(2, '0');
        return hex;
    }

    function _arrayBufToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (const b of bytes) binary += String.fromCharCode(b);
        return btoa(binary);
    }

    function _base64ToArrayBuf(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function _arrayBufToBase64url(buffer) {
        return _arrayBufToBase64(buffer)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    function _base64urlToArrayBuf(b64url) {
        let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        return _base64ToArrayBuf(b64);
    }

    return {
        // KEK / master key wrapping
        deriveKEK,
        deriveMasterKey,  // deprecated alias
        generateMasterKey,
        wrapMasterKey,
        unwrapMasterKey,
        // Recovery key
        generateRecoveryKey,
        importRecoveryKey,
        hashRecoveryKey,
        // Convenience bundles
        generateRegistrationBundle,
        rewrapMasterKeyForPasswordChange,
        // File keys
        generateFileKey,
        encryptFileKey,
        decryptFileKey,
        // Chunks
        encryptChunk,
        decryptChunk,
        // Link share keys
        generateShareKey,
        exportKeyToBase64url,
        importKeyFromBase64url,
        wrapFileKeyForShare,
        unwrapFileKeyFromShare,
        // Hybrid X25519 + ML-KEM-768 asymmetric keys (Phase 5b)
        generateAsymmetricKeyPair,
        exportAsymmetricPublicKeys,
        wrapAsymmetricPrivateKeys,
        unwrapAsymmetricPrivateKeys,
        encapsulateFileKeyForUser,
        decapsulateFileKeyFromUser,
    };
})();
