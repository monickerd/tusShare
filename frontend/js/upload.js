/**
 * tusShare — tus upload client with client-side AES-GCM encryption.
 *
 * Flow per file:
 *   1. Generate per-file fileKey.
 *   2. Encrypt fileKey with masterKey → store on server.
 *   3. POST to /uploads with metadata (tus create).
 *   4. For each chunk: encrypt with fileKey (unique IV) → PATCH.
 *   5. On completion, server returns X-File-ID header.
 *
 * Resuming an in-progress upload:
 *   HEAD → get current encrypted offset → compute starting chunk index →
 *   continue PATCHing with fresh IVs (chunked re-encryption from that point).
 *
 * Upload control (ctrl parameter):
 *   Pass a ctrl object to uploadFile/resumeUpload to support pause/stop.
 *   Shape: { onCreated?(uploadId), waitIfPaused?(): Promise, isStopped?(): boolean }
 *   When isStopped() returns true, the loop throws UploadAbortedError carrying
 *   the upload location so the caller can issue DELETE for server-side cleanup.
 */

class UploadAbortedError extends Error {
    constructor(location) {
        super('Upload cancelled');
        this.name = 'UploadAbortedError';
        this.location = location;
    }
}

const Upload = (() => {
    const _cfg = () => Config.upload;
    const _prefix = () => Config.app.apiPrefix;

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Upload a file with E2E encryption.
     *
     * @param {File}       file       - Browser File object.
     * @param {string|null} folderId  - Target folder UUID, or null for root.
     * @param {CryptoKey}  masterKey  - Decrypted master key.
     * @param {function}   onProgress - Called with (bytesEncrypted, totalEncryptedBytes).
     * @param {object}    [ctrl]      - Optional control object for pause/stop.
     *   ctrl.onCreated(uploadId)     - Called immediately after the upload is created on the server.
     *   ctrl.waitIfPaused(): Promise - Resolves when the upload is no longer paused.
     *   ctrl.isStopped(): boolean    - Returns true when the upload should abort.
     * @returns {Promise<{fileId: string, location: string}>}
     * @throws {UploadAbortedError}  When ctrl signals a stop.
     */
    async function uploadFile(file, folderId, masterKey, onProgress, ctrl = null) {
        const chunkSize = _cfg().defaultChunkSize;
        const totalChunks = Math.ceil(file.size / chunkSize);

        // Total encrypted size = sum of (plainChunkSize + 16) for each chunk
        let totalEncryptedSize = 0;
        for (let i = 0; i < totalChunks; i++) {
            const plain = Math.min(chunkSize, file.size - i * chunkSize);
            totalEncryptedSize += plain + 16;
        }

        // Generate a per-file key and wrap it with the master key
        const fileKey = await Crypto.generateFileKey();
        const { encryptedKeyB64, ivB64: keyIvB64 } = await Crypto.encryptFileKey(fileKey, masterKey);

        // Build tus Upload-Metadata header
        const meta = _buildMetadata({
            filename:           file.name,
            filetype:           file.type || 'application/octet-stream',
            folder_id:          folderId || '',
            encrypted_file_key: encryptedKeyB64,
            key_iv:             keyIvB64,
            chunk_size:         String(chunkSize),
            original_size:      String(file.size),
        });

        // POST — create the upload (retry once on 401 to handle expired access tokens)
        const _createHeaders = () => ({
            'Tus-Resumable':   '1.0.0',
            'Upload-Length':   String(totalEncryptedSize),
            'Upload-Metadata': meta,
            'X-CSRF-Token':    _csrf(),
        });

        let createResp = await fetch(`${_prefix()}/uploads`, {
            method: 'POST',
            headers: _createHeaders(),
            credentials: 'same-origin',
        });

        if (createResp.status === 401) {
            const refreshed = await Api.refreshTokens();
            if (!refreshed) throw new Error('Session expired. Please log in and try again.');
            createResp = await fetch(`${_prefix()}/uploads`, {
                method: 'POST',
                headers: _createHeaders(),
                credentials: 'same-origin',
            });
        }

        if (!createResp.ok) {
            const body = await createResp.json().catch(() => ({}));
            throw new Error(body.detail || `Upload create failed (${createResp.status})`);
        }

        const location = createResp.headers.get('Location');
        if (!location) throw new Error('Server did not return an upload location');

        // Notify caller of the server-assigned upload ID so it can be tracked
        // (e.g., to suppress the static pending-upload row while active)
        const uploadId = location.split('/').pop();
        ctrl?.onCreated?.(uploadId);

        // PATCH — send each encrypted chunk
        const integrityTracker = _makeIntegrityTracker(totalChunks);
        let encryptedOffset = 0;
        for (let i = 0; i < totalChunks; i++) {
            // Pause/stop checks happen at chunk boundaries (before encrypting the next chunk).
            // Any in-flight PATCH is always allowed to finish before we abort.
            if (ctrl) {
                await ctrl.waitIfPaused?.();
                if (ctrl.isStopped?.()) throw new UploadAbortedError(location);
            }
            const start = i * chunkSize;
            const end   = Math.min(start + chunkSize, file.size);
            const plain = await file.slice(start, end).arrayBuffer();

            const { ciphertext, ivB64: chunkIvB64 } = await Crypto.encryptChunk(plain, fileKey);
            const chunkHash = await _sha256Hex(ciphertext);

            let attempt = 0;
            while (true) {
                const patchResp = await fetch(location, {
                    method: 'PATCH',
                    headers: {
                        'Tus-Resumable':  '1.0.0',
                        'Content-Type':   'application/offset+octet-stream',
                        'Upload-Offset':  String(encryptedOffset),
                        'X-Chunk-IV':     chunkIvB64,
                        'X-Chunk-Hash':   `sha256:${chunkHash}`,
                        'X-CSRF-Token':   _csrf(),
                    },
                    body: ciphertext,
                    credentials: 'same-origin',
                });

                if (patchResp.ok) {
                    const serverOffset = parseInt(patchResp.headers.get('Upload-Offset') || '0', 10);
                    encryptedOffset = serverOffset;
                    Auth.touchKeyCache();
                    if (onProgress) onProgress(encryptedOffset, totalEncryptedSize);

                    // Final chunk — server includes X-File-ID
                    if (i === totalChunks - 1) {
                        const fileId = patchResp.headers.get('X-File-ID') || null;
                        return { fileId, location };
                    }
                    break;
                }

                // 401 — access token expired mid-upload; refresh once and retry the chunk
                // (does not count against maxRetries since it's not a data error)
                if (patchResp.status === 401) {
                    const refreshed = await Api.refreshTokens();
                    if (!refreshed) {
                        throw new Error('Session expired during upload. Please log in and try again.');
                    }
                    continue;
                }

                // Read body once — Response body can only be consumed once
                const errBody = await patchResp.json().catch(() => ({}));

                // 409 Conflict — server offset doesn't match; re-sync via HEAD
                if (patchResp.status === 409) {
                    const headResp = await fetch(location, {
                        method: 'HEAD',
                        headers: { 'Tus-Resumable': '1.0.0' },
                        credentials: 'same-origin',
                    });
                    if (headResp.ok) {
                        const serverOffset = parseInt(headResp.headers.get('Upload-Offset') || '0', 10);
                        if (serverOffset > encryptedOffset) {
                            // Server is ahead — this chunk was already committed
                            encryptedOffset = serverOffset;
                            break;
                        }
                    }
                }

                // 400 hash mismatch — track repeated failures and abort if threshold exceeded
                if (patchResp.status === 400 && errBody.detail?.includes('hash mismatch')) {
                    integrityTracker.recordHashFailure(i); // throws if threshold exceeded
                }

                attempt++;
                if (attempt >= _cfg().maxRetries) {
                    throw new Error(errBody.detail || `Chunk ${i} failed after ${attempt} retries`);
                }
                await _sleep(_cfg().retryBaseDelay * Math.pow(2, attempt - 1));
            }
        }

        return { fileId: null, location };
    }

    /**
     * Resume an in-progress upload from the current server offset.
     *
     * Suitable for network interruptions within the same page session.
     * The fileKey must already be decrypted (caller holds it from uploadFile).
     *
     * @param {string}   location   - Upload URL from the Location header.
     * @param {File}     file       - Original File object (same file).
     * @param {CryptoKey} fileKey   - Decrypted per-file key.
     * @param {function} onProgress - Called with (bytesEncrypted, totalEncryptedBytes).
     * @param {object}  [ctrl]      - Optional control object (same shape as uploadFile).
     *   ctrl.waitIfPaused(): Promise - Resolves when not paused.
     *   ctrl.isStopped(): boolean    - Returns true when the upload should abort.
     * @returns {Promise<{fileId: string|null, location: string}>}
     * @throws {UploadAbortedError}  When ctrl signals a stop.
     */
    async function resumeUpload(location, file, fileKey, onProgress, ctrl = null) {
        const chunkSize = _cfg().defaultChunkSize;
        const totalChunks = Math.ceil(file.size / chunkSize);

        // Calculate total encrypted size
        let totalEncryptedSize = 0;
        for (let i = 0; i < totalChunks; i++) {
            const plain = Math.min(chunkSize, file.size - i * chunkSize);
            totalEncryptedSize += plain + 16;
        }

        // HEAD — find where server left off
        const headResp = await fetch(location, {
            method: 'HEAD',
            headers: { 'Tus-Resumable': '1.0.0' },
            credentials: 'same-origin',
        });
        if (!headResp.ok) {
            throw new Error(`Resume HEAD failed (${headResp.status})`);
        }
        let encryptedOffset = parseInt(headResp.headers.get('Upload-Offset') || '0', 10);

        // Map encrypted offset → starting chunk index
        let startChunk = 0;
        let cumulativeEnc = 0;
        for (let i = 0; i < totalChunks; i++) {
            const plain = Math.min(chunkSize, file.size - i * chunkSize);
            const enc   = plain + 16;
            if (cumulativeEnc + enc > encryptedOffset) break;
            cumulativeEnc += enc;
            startChunk = i + 1;
        }

        if (startChunk >= totalChunks) {
            // Already complete
            return { fileId: null, location };
        }

        // Continue from startChunk with fresh IVs (re-encrypt from plaintext offset)
        const integrityTracker = _makeIntegrityTracker(totalChunks);
        for (let i = startChunk; i < totalChunks; i++) {
            if (ctrl) {
                await ctrl.waitIfPaused?.();
                if (ctrl.isStopped?.()) throw new UploadAbortedError(location);
            }
            const start = i * chunkSize;
            const end   = Math.min(start + chunkSize, file.size);
            const plain = await file.slice(start, end).arrayBuffer();

            const { ciphertext, ivB64: chunkIvB64 } = await Crypto.encryptChunk(plain, fileKey);
            const chunkHash = await _sha256Hex(ciphertext);

            let attempt = 0;
            while (true) {
                const patchResp = await fetch(location, {
                    method: 'PATCH',
                    headers: {
                        'Tus-Resumable': '1.0.0',
                        'Content-Type':  'application/offset+octet-stream',
                        'Upload-Offset': String(encryptedOffset),
                        'X-Chunk-IV':    chunkIvB64,
                        'X-Chunk-Hash':  `sha256:${chunkHash}`,
                        'X-CSRF-Token':  _csrf(),
                    },
                    body: ciphertext,
                    credentials: 'same-origin',
                });

                if (patchResp.ok) {
                    encryptedOffset = parseInt(patchResp.headers.get('Upload-Offset') || '0', 10);
                    Auth.touchKeyCache();
                    if (onProgress) onProgress(encryptedOffset, totalEncryptedSize);

                    if (i === totalChunks - 1) {
                        const fileId = patchResp.headers.get('X-File-ID') || null;
                        return { fileId, location };
                    }
                    break;
                }

                // 401 — access token expired mid-upload; refresh once and retry the chunk
                if (patchResp.status === 401) {
                    const refreshed = await Api.refreshTokens();
                    if (!refreshed) {
                        throw new Error('Session expired during upload. Please log in and try again.');
                    }
                    continue;
                }

                // Read body once — Response body can only be consumed once
                const errBody = await patchResp.json().catch(() => ({}));

                // 400 hash mismatch — track repeated failures and abort if threshold exceeded
                if (patchResp.status === 400 && errBody.detail?.includes('hash mismatch')) {
                    integrityTracker.recordHashFailure(i); // throws if threshold exceeded
                }

                attempt++;
                if (attempt >= _cfg().maxRetries) {
                    throw new Error(errBody.detail || `Resume chunk ${i} failed after ${attempt} retries`);
                }
                await _sleep(_cfg().retryBaseDelay * Math.pow(2, attempt - 1));
            }
        }

        return { fileId: null, location };
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    function _csrf() {
        return Utils.parseCookie(Config.auth.cookieCsrfName) || '';
    }

    /**
     * Build a tus Upload-Metadata header value from a plain object.
     * Values are UTF-8 encoded and then base64-encoded per the tus spec.
     */
    function _buildMetadata(obj) {
        return Object.entries(obj)
            .map(([k, v]) => `${k} ${_utf8ToBase64(v)}`)
            .join(',');
    }

    /**
     * Base64-encode a string that may contain non-ASCII (Unicode) characters.
     * Uses TextEncoder to produce correct UTF-8 bytes before base64-encoding.
     */
    function _utf8ToBase64(str) {
        const bytes = new TextEncoder().encode(str);
        let binary = '';
        for (const b of bytes) binary += String.fromCharCode(b);
        return btoa(binary);
    }

    /**
     * Create a fresh integrity failure tracker for one upload session.
     *
     * Uses two independent thresholds — both must be respected:
     *
     *   Per-chunk (absolute): if the same chunk fails N times in a row,
     *   that chunk specifically is problematic regardless of file size.
     *
     *   Total (rate-based): abort if more than X% of all chunks have failures.
     *   A minimum floor prevents a near-zero threshold on very small files.
     *   e.g. with rate=0.02 and floor=2:
     *     5 chunks  → threshold 2  (floor, since 5×0.02=0.1)
     *     100 chunks → threshold 2  (still floor)
     *     500 chunks → threshold 10
     *     1000 chunks → threshold 20
     *
     * @param {number} totalChunks - Total chunk count for this upload.
     */
    function _makeIntegrityTracker(totalChunks) {
        const cfg = _cfg();
        const rateThreshold = Math.max(
            cfg.maxHashFailuresMin,
            Math.ceil(totalChunks * cfg.maxHashFailureRate),
        );
        const perChunk = {};
        let total = 0;
        return {
            recordHashFailure(chunkIndex) {
                perChunk[chunkIndex] = (perChunk[chunkIndex] || 0) + 1;
                total++;
                if (perChunk[chunkIndex] >= cfg.maxHashFailuresPerChunk) {
                    throw new Error(
                        `Upload aborted: chunk ${chunkIndex} failed the integrity check ` +
                        `${perChunk[chunkIndex]} time(s). ` +
                        `Possible corrupted network path or hardware issue.`
                    );
                }
                if (total >= rateThreshold) {
                    const pct = (total / totalChunks * 100).toFixed(1);
                    throw new Error(
                        `Upload aborted: ${total} of ${totalChunks} chunks (${pct}%) ` +
                        `failed the integrity check. ` +
                        `Possible network instability or hardware issue.`
                    );
                }
            },
        };
    }

    /**
     * Return the SHA-256 digest of an ArrayBuffer as a lowercase hex string.
     * Used to send X-Chunk-Hash with each PATCH so the server can verify
     * receipt integrity at the application layer.
     */
    async function _sha256Hex(buffer) {
        const digest = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(digest))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    function _sleep(ms) {
        return new Promise(r => setTimeout(r, ms));
    }

    return { uploadFile, resumeUpload, AbortedError: UploadAbortedError };
})();
