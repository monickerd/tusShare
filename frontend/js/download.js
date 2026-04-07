/**
 * tusShare — Download client with client-side AES-GCM decryption.
 *
 * Flow per file:
 *   1. GET /files/{id}/chunks (paginated) → chunk manifest
 *      (encrypted_file_key, key_iv, per-chunk offset/size/IV)
 *   2. Decrypt file key with the master key.
 *   3. For each chunk: Range-fetch the encrypted bytes, decrypt in-browser.
 *   4. Concatenate plaintext chunks, build a Blob, trigger save dialog.
 *
 * Note: all decrypted chunks accumulate in memory before the Blob is
 * assembled.  This is acceptable for the expected file sizes (well below
 * browser memory limits for a private file-transfer tool).
 */
const Download = (() => {
    const _prefix = () => Config.app.apiPrefix;

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Download and decrypt a file.
     *
     * @param {string}   fileId     - File UUID.
     * @param {CryptoKey} masterKey  - Decrypted master key (from Auth).
     * @param {function} onProgress  - Called with (chunksDecrypted, totalChunks).
     * @param {AbortSignal} [signal] - Optional AbortSignal to cancel the download.
     *   When aborted, the in-flight fetch throws an AbortError which propagates to the caller.
     */
    async function downloadFile(fileId, masterKey, onProgress, signal = null) {
        // 1. Fetch full chunk manifest (handles pagination internally)
        const manifest = await _fetchManifest(fileId);

        // Verify the manifest is complete before touching any crypto
        if (manifest.chunks.length !== manifest.total_chunks) {
            throw new Error(
                `Manifest incomplete: expected ${manifest.total_chunks} chunks, got ${manifest.chunks.length}`
            );
        }

        // 2. Decrypt the per-file key
        const fileKey = await Crypto.decryptFileKey(
            manifest.encrypted_file_key,
            manifest.key_iv,
            masterKey,
        );

        // 3. Fetch + decrypt each chunk sequentially
        const totalChunks = manifest.chunks.length;
        const decryptedChunks = [];
        let totalBytes = 0;

        for (let i = 0; i < totalChunks; i++) {
            const chunk = manifest.chunks[i];
            const rangeStart = chunk.offset;
            const rangeEnd   = chunk.offset + chunk.size_bytes - 1;

            const resp = await fetch(`${_prefix()}/files/${fileId}/content`, {
                headers: { Range: `bytes=${rangeStart}-${rangeEnd}` },
                credentials: 'same-origin',
                signal,
            });

            // 206 Partial Content is the expected success code for Range requests
            if (resp.status !== 206 && !resp.ok) {
                const body = await resp.json().catch(() => ({}));
                throw new Error(body.detail || `Fetch failed (${resp.status})`);
            }

            const encryptedBuf = await resp.arrayBuffer();

            // AES-GCM decryption verifies the 16-byte auth tag for every chunk.
            // Any bit-level corruption (disk, network, or server-side) causes this to throw.
            let plainBuf;
            try {
                plainBuf = await Crypto.decryptChunk(encryptedBuf, chunk.iv, fileKey);
            } catch (_) {
                throw new Error(
                    `Chunk ${i + 1}/${totalChunks} failed integrity check — ` +
                    `the data may be corrupted (offset ${chunk.offset})`
                );
            }

            decryptedChunks.push(new Uint8Array(plainBuf));
            totalBytes += plainBuf.byteLength;

            if (onProgress) onProgress(i + 1, totalChunks);
        }

        // 4. Verify total plaintext size matches the file record (server-declared original size)
        if (manifest.size_bytes !== undefined && totalBytes !== manifest.size_bytes) {
            throw new Error(
                `Integrity check failed: expected ${manifest.size_bytes} plaintext bytes, got ${totalBytes}`
            );
        }

        // 5. Assemble all chunks into a single Uint8Array, then save
        const combined = new Uint8Array(totalBytes);
        let pos = 0;
        for (const chunk of decryptedChunks) {
            combined.set(chunk, pos);
            pos += chunk.byteLength;
        }

        const mimeType  = manifest.mime_type  || 'application/octet-stream';
        const fileName  = manifest.original_name || 'download';
        const blob = new Blob([combined], { type: mimeType });
        _saveBlob(blob, fileName);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /**
     * Fetch the full chunk manifest from GET /files/{id}/chunks.
     * Paginates automatically so callers always get every chunk.
     */
    async function _fetchManifest(fileId) {
        const limit = 500;
        let offset = 0;
        let base = null;
        const allChunks = [];

        while (true) {
            const data = await Api.get(
                `${_prefix()}/files/${fileId}/chunks?offset=${offset}&limit=${limit}`,
            );
            if (!base) base = data;
            allChunks.push(...data.chunks);
            offset += data.chunks.length;
            // Stop when we have all chunks, or if server returned an empty page
            if (allChunks.length >= data.total_chunks || data.chunks.length === 0) break;
        }

        return { ...base, chunks: allChunks };
    }

    /**
     * Trigger a browser save-file dialog via a temporary object URL.
     * The URL is revoked after a short delay to free memory.
     */
    function _saveBlob(blob, fileName) {
        const url = URL.createObjectURL(blob);
        const a   = document.createElement('a');
        a.href    = url;
        a.download = fileName;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // Give the browser time to start the download before revoking
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    return { downloadFile };
})();
