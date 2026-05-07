/**
 * tusShare — Download client with client-side AES-GCM decryption.
 *
 * Normal flow per file:
 *   1. GET /files/{id}/chunks (paginated) → chunk manifest
 *   2. Decrypt file key with the master key.
 *   3. For each chunk: Range-fetch the encrypted bytes, decrypt in-browser.
 *   4. Write plaintext chunk to OPFS; record progress in IndexedDB.
 *   5. Assemble all chunks, trigger save dialog, clean up OPFS + IndexedDB.
 *
 * Resume flow (after re-login / interrupted session):
 *   Same as above, but already-written OPFS chunks are skipped.
 *   onProgress starts at the number of chunks already completed.
 *   Stale state (total chunk count changed) is discarded automatically.
 *
 * Fallback: if OPFS or IndexedDB is unavailable, all chunks accumulate in
 * memory and no resume state is persisted (original behaviour).
 */
const Download = (() => {
    const _prefix = () => Config.app.apiPrefix;

    // ------------------------------------------------------------------
    // IndexedDB helpers  (DB: tusshare_dl, store: dl_state)
    // ------------------------------------------------------------------

    const _IDB_NAME    = 'tusshare_dl';
    const _IDB_VERSION = 1;
    const _IDB_STORE   = 'dl_state';

    function _openDb() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(_IDB_NAME, _IDB_VERSION);
            req.onupgradeneeded = e => {
                e.target.result.createObjectStore(_IDB_STORE, { keyPath: 'fileId' });
            };
            req.onsuccess = e => resolve(e.target.result);
            req.onerror   = ()  => reject(req.error);
        });
    }

    function _idbGet(db, fileId) {
        return new Promise((resolve, reject) => {
            const tx  = db.transaction(_IDB_STORE, 'readonly');
            const req = tx.objectStore(_IDB_STORE).get(fileId);
            req.onsuccess = () => resolve(req.result || null);
            req.onerror   = () => reject(req.error);
        });
    }

    function _idbPut(db, record) {
        return new Promise((resolve, reject) => {
            const tx  = db.transaction(_IDB_STORE, 'readwrite');
            const req = tx.objectStore(_IDB_STORE).put(record);
            req.onsuccess = () => resolve();
            req.onerror   = () => reject(req.error);
        });
    }

    function _idbDel(db, fileId) {
        return new Promise((resolve, reject) => {
            const tx  = db.transaction(_IDB_STORE, 'readwrite');
            const req = tx.objectStore(_IDB_STORE).delete(fileId);
            req.onsuccess = () => resolve();
            req.onerror   = () => reject(req.error);
        });
    }

    function _idbGetAll(db) {
        return new Promise((resolve, reject) => {
            const tx  = db.transaction(_IDB_STORE, 'readonly');
            const req = tx.objectStore(_IDB_STORE).getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror   = () => reject(req.error);
        });
    }

    // ------------------------------------------------------------------
    // OPFS helpers
    // ------------------------------------------------------------------

    async function _getOpfsDir() {
        return navigator.storage.getDirectory();
    }

    function _chunkName(fileId, idx) {
        return `dl_${fileId}_${idx}`;
    }

    async function _writeChunk(dir, fileId, idx, buf) {
        const handle   = await dir.getFileHandle(_chunkName(fileId, idx), { create: true });
        const writable = await handle.createWritable();
        await writable.write(buf);
        await writable.close();
    }

    async function _readChunk(dir, fileId, idx) {
        const handle = await dir.getFileHandle(_chunkName(fileId, idx));
        const file   = await handle.getFile();
        return file.arrayBuffer();
    }

    async function _clearChunks(dir, fileId, totalChunks) {
        for (let i = 0; i < totalChunks; i++) {
            try { await dir.removeEntry(_chunkName(fileId, i)); } catch { /* may not exist */ }
        }
    }

    // ------------------------------------------------------------------
    // Feature detection
    // ------------------------------------------------------------------

    function _opfsAvailable() {
        return (
            typeof indexedDB !== 'undefined' &&
            typeof navigator !== 'undefined' &&
            typeof navigator.storage?.getDirectory === 'function'
        );
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Download and decrypt a file.
     * Writes chunks to OPFS and tracks progress in IndexedDB so the download
     * can resume after a page reload or re-login.  Falls back to the original
     * in-memory path when OPFS / IndexedDB are not available.
     *
     * @param {string}      fileId     - File UUID.
     * @param {CryptoKey}   masterKey  - Decrypted master key (from Auth).
     * @param {function}    onProgress - Called with (chunksDecrypted, totalChunks).
     * @param {AbortSignal} [signal]   - Optional AbortSignal to cancel the download.
     */
    async function downloadFile(fileId, masterKey, onProgress, signal = null) {
        if (_opfsAvailable()) {
            return _downloadWithOpfs(fileId, masterKey, onProgress, signal);
        }
        return _downloadInMemory(fileId, masterKey, onProgress, signal);
    }

    /**
     * List files that have partial download state persisted in IndexedDB.
     * Returns [] if OPFS is unavailable or on any error.
     *
     * @returns {Promise<Array<{fileId:string, totalChunks:number, doneCount:number}>>}
     */
    async function listPartialDownloads() {
        if (!_opfsAvailable()) return [];
        try {
            const db = await _openDb();
            const rows = await _idbGetAll(db);
            return rows.map(r => ({
                fileId:      r.fileId,
                totalChunks: r.totalChunks,
                doneCount:   r.done.length,
            }));
        } catch {
            return [];
        }
    }

    /**
     * Discard OPFS chunk files and IndexedDB state for a given file.
     * Best-effort — errors are silently swallowed.
     *
     * @param {string} fileId
     */
    async function clearPartialDownload(fileId) {
        if (!_opfsAvailable()) return;
        try {
            const db  = await _openDb();
            const dir = await _getOpfsDir();
            const s   = await _idbGet(db, fileId);
            if (s) await _clearChunks(dir, fileId, s.totalChunks);
            await _idbDel(db, fileId);
        } catch { /* best-effort */ }
    }

    // ------------------------------------------------------------------
    // OPFS-backed download
    // ------------------------------------------------------------------

    async function _fetchAndCacheChunks(dir, db, fileId, totalChunks, chunks, fileKey, ctx) {
        const { done, onProgress, signal } = ctx;
        for (let i = 0; i < totalChunks; i++) {
            if (signal?.aborted) {
                const err = new Error('Aborted');
                err.name  = 'AbortError';
                throw err;
            }
            if (done.has(i)) continue;
            const plainBuf = await _fetchDecryptChunk(fileId, chunks[i], i, totalChunks, fileKey, signal);
            await _writeChunk(dir, fileId, i, plainBuf);
            done.add(i);
            await _idbPut(db, { fileId, totalChunks, done: [...done] });
            if (onProgress) onProgress(done.size, totalChunks);
        }
    }

    async function _downloadWithOpfs(fileId, masterKey, onProgress, signal) {
        const db  = await _openDb();
        const dir = await _getOpfsDir();

        // 1. Fetch full chunk manifest (always fresh — authoritative source of truth)
        const manifest = await _fetchManifest(fileId);

        if (manifest.chunks.length !== manifest.total_chunks) {
            throw new Error(
                `Manifest incomplete: expected ${manifest.total_chunks} chunks, got ${manifest.chunks.length}`
            );
        }

        const totalChunks = manifest.total_chunks;

        // 2. Load existing partial state; discard if chunk count changed (file replaced)
        let state = await _idbGet(db, fileId);
        if (state && state.totalChunks !== totalChunks) {
            await _clearChunks(dir, fileId, state.totalChunks);
            await _idbDel(db, fileId);
            state = null;
        }

        const done = new Set(state ? state.done : []);

        if (!state) {
            await _idbPut(db, { fileId, totalChunks, done: [] });
        }

        // Report progress for chunks already written in a prior session
        if (done.size > 0 && onProgress) onProgress(done.size, totalChunks);

        // 3. Decrypt the per-file key
        const fileKey = await Crypto.decryptFileKey(
            manifest.encrypted_file_key,
            manifest.key_iv,
            masterKey,
        );

        // 4. Fetch + decrypt + write each chunk not yet persisted to OPFS
        await _fetchAndCacheChunks(dir, db, fileId, totalChunks, manifest.chunks, fileKey, { done, onProgress, signal });

        // 5. Read all chunks from OPFS and assemble
        let totalBytes = 0;
        const chunks = [];
        for (let i = 0; i < totalChunks; i++) {
            const buf = await _readChunk(dir, fileId, i);
            chunks.push(new Uint8Array(buf));
            totalBytes += buf.byteLength;
        }

        if (manifest.size_bytes !== undefined && totalBytes !== manifest.size_bytes) {
            throw new Error(
                `Integrity check failed: expected ${manifest.size_bytes} plaintext bytes, got ${totalBytes}`
            );
        }

        const combined = new Uint8Array(totalBytes);
        let pos = 0;
        for (const c of chunks) { combined.set(c, pos); pos += c.byteLength; }

        const mimeType = manifest.mime_type  || 'application/octet-stream';
        const fileName = manifest.original_name || 'download';
        _saveBlob(new Blob([combined], { type: mimeType }), fileName);

        // 6. Clean up OPFS + IndexedDB on success
        await _clearChunks(dir, fileId, totalChunks);
        await _idbDel(db, fileId);
    }

    // ------------------------------------------------------------------
    // In-memory fallback (original behaviour for browsers without OPFS)
    // ------------------------------------------------------------------

    async function _downloadInMemory(fileId, masterKey, onProgress, signal) {
        const manifest = await _fetchManifest(fileId);

        if (manifest.chunks.length !== manifest.total_chunks) {
            throw new Error(
                `Manifest incomplete: expected ${manifest.total_chunks} chunks, got ${manifest.chunks.length}`
            );
        }

        const fileKey = await Crypto.decryptFileKey(
            manifest.encrypted_file_key,
            manifest.key_iv,
            masterKey,
        );

        const totalChunks     = manifest.chunks.length;
        const decryptedChunks = [];
        let   totalBytes      = 0;

        for (let i = 0; i < totalChunks; i++) {
            const plainBuf = await _fetchDecryptChunk(fileId, manifest.chunks[i], i, totalChunks, fileKey, signal);
            decryptedChunks.push(new Uint8Array(plainBuf));
            totalBytes += plainBuf.byteLength;
            if (onProgress) onProgress(i + 1, totalChunks);
        }

        if (manifest.size_bytes !== undefined && totalBytes !== manifest.size_bytes) {
            throw new Error(
                `Integrity check failed: expected ${manifest.size_bytes} plaintext bytes, got ${totalBytes}`
            );
        }

        const combined = new Uint8Array(totalBytes);
        let pos = 0;
        for (const c of decryptedChunks) { combined.set(c, pos); pos += c.byteLength; }

        const mimeType = manifest.mime_type  || 'application/octet-stream';
        const fileName = manifest.original_name || 'download';
        _saveBlob(new Blob([combined], { type: mimeType }), fileName);
    }

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    /**
     * Range-fetch and decrypt one chunk of an authenticated file.
     *
     * @param {string}   fileId
     * @param {{offset:number, size_bytes:number, iv:string}} chunk
     * @param {number}   chunkIdx    - Zero-based index (used in error message).
     * @param {number}   totalChunks
     * @param {CryptoKey} fileKey
     * @param {AbortSignal|null} signal
     * @returns {Promise<ArrayBuffer>} Decrypted plaintext buffer.
     */
    async function _fetchDecryptChunk(fileId, chunk, chunkIdx, totalChunks, fileKey, signal) {
        const resp = await fetch(`${_prefix()}/files/${fileId}/content`, {
            headers:     { Range: `bytes=${chunk.offset}-${chunk.offset + chunk.size_bytes - 1}` },
            credentials: 'same-origin',
            signal,
        });
        if (resp.status !== 206 && !resp.ok) {
            const body = await resp.json().catch(() => ({}));
            throw new Error(body.detail || `Fetch failed (${resp.status})`);
        }
        const encBuf = await resp.arrayBuffer();
        try {
            return await Crypto.decryptChunk(encBuf, chunk.iv, fileKey);
        } catch {
            throw new Error(
                `Chunk ${chunkIdx + 1}/${totalChunks} failed integrity check — ` +
                `the data may be corrupted (offset ${chunk.offset})`
            );
        }
    }

    async function _fetchManifest(fileId) {
        const limit = 500;
        let offset  = 0;
        let base    = null;
        const allChunks = [];

        while (true) {
            const data = await Api.get(
                `${_prefix()}/files/${fileId}/chunks?offset=${offset}&limit=${limit}`,
            );
            if (!base) base = data;
            allChunks.push(...data.chunks);
            offset += data.chunks.length;
            if (allChunks.length >= data.total_chunks || data.chunks.length === 0) break;
        }

        return { ...base, chunks: allChunks };
    }

    function _saveBlob(blob, fileName) {
        const url = URL.createObjectURL(blob);
        const a   = document.createElement('a');
        a.href     = url;
        a.download = fileName;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    // ------------------------------------------------------------------
    // ZIP assembler (STORE method — no compression, valid ZIP format)
    // ------------------------------------------------------------------

    // Encode a string as UTF-8 bytes
    function _utf8(s) { return new TextEncoder().encode(s); }

    // Write a little-endian uint16 / uint32 into a DataView at offset
    function _u16(view, off, v) { view.setUint16(off, v, true); }
    function _u32(view, off, v) { view.setUint32(off, v, true); }

    // CRC-32 table (ISO 3309)
    const _CRC32_TABLE = (() => {
        const t = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            t[i] = c;
        }
        return t;
    })();

    function _crc32(data) {
        let crc = 0xFFFFFFFF;
        for (const byte of data) {
            crc = _CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
        }
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    /**
     * Build a ZIP archive (STORE method) from an array of {path, data} objects.
     *
     * @param {Array<{path: string, data: Uint8Array}>} entries
     * @returns {Blob} ZIP blob
     */
    function _buildZip(entries) {
        const centralDir    = [];
        const parts         = [];
        let   offset        = 0;

        for (const { path, data } of entries) {
            const nameBytes = _utf8(path);
            const crc       = _crc32(data);
            const size      = data.length;

            // Local file header (30 bytes + name)
            const lh = new ArrayBuffer(30 + nameBytes.length);
            const lv = new DataView(lh);
            _u32(lv,  0, 0x04034B50); // local file header sig
            _u16(lv,  4, 20);          // version needed: 2.0
            _u16(lv,  6, 0x0800);      // general flags: UTF-8 filename
            _u16(lv,  8, 0);           // compression: STORE
            _u16(lv, 10, 0);           // last mod time
            _u16(lv, 12, 0);           // last mod date
            _u32(lv, 14, crc);
            _u32(lv, 18, size);        // compressed size
            _u32(lv, 22, size);        // uncompressed size
            _u16(lv, 26, nameBytes.length);
            _u16(lv, 28, 0);           // extra field length
            new Uint8Array(lh).set(nameBytes, 30);

            // Central directory entry (46 bytes + name)
            const cd = new ArrayBuffer(46 + nameBytes.length);
            const cv = new DataView(cd);
            _u32(cv,  0, 0x02014B50); // central dir sig
            _u16(cv,  4, 20);          // version made by
            _u16(cv,  6, 20);          // version needed
            _u16(cv,  8, 0x0800);      // general flags
            _u16(cv, 10, 0);           // compression: STORE
            _u16(cv, 12, 0);           // last mod time
            _u16(cv, 14, 0);           // last mod date
            _u32(cv, 16, crc);
            _u32(cv, 20, size);
            _u32(cv, 24, size);
            _u16(cv, 28, nameBytes.length);
            _u16(cv, 30, 0);           // extra
            _u16(cv, 32, 0);           // comment
            _u16(cv, 34, 0);           // disk start
            _u16(cv, 36, 0);           // internal attr
            _u32(cv, 38, 0);           // external attr
            _u32(cv, 42, offset);      // local header offset
            new Uint8Array(cd).set(nameBytes, 46);

            parts.push(new Uint8Array(lh), data);
            centralDir.push(new Uint8Array(cd));
            offset += lh.byteLength + size;
        }

        const cdOffset = offset;
        const cdSize   = centralDir.reduce((s, b) => s + b.length, 0);

        // End of central directory record
        const eocd = new ArrayBuffer(22);
        const ev   = new DataView(eocd);
        _u32(ev,  0, 0x06054B50); // EOCD sig
        _u16(ev,  4, 0);           // disk number
        _u16(ev,  6, 0);           // disk with CD
        _u16(ev,  8, entries.length);
        _u16(ev, 10, entries.length);
        _u32(ev, 12, cdSize);
        _u32(ev, 16, cdOffset);
        _u16(ev, 20, 0);           // comment length

        return new Blob([...parts, ...centralDir, new Uint8Array(eocd)], {
            type: 'application/zip',
        });
    }

    // ------------------------------------------------------------------
    // ZIP filename
    // ------------------------------------------------------------------

    function _zipName(items, folderTree, ts) {
        // ts: "YYYY-MM-DD-HH-MM"
        if (items.length === 1 && items[0].type === 'folder') {
            return `${items[0].name}_${ts}.zip`;
        }
        const parentIds = new Set(items.map(i => i.parentFolderId || null));
        if (parentIds.size === 1) {
            const pid = [...parentIds][0];
            const parentName = pid ? (folderTree[pid]?.name || 'files') : 'files';
            return `${parentName}_${ts}.zip`;
        }
        return `download_${ts}.zip`;
    }

    function _nowTs() {
        const d = new Date();
        const pad = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}-${pad(d.getHours())}-${pad(d.getMinutes())}`;
    }

    // ------------------------------------------------------------------
    // Batch IDB helpers  (store: batch_dl_state, key: batchId)
    // ------------------------------------------------------------------

    const _BATCH_STORE = 'batch_dl_state';
    const _IDB_BATCH_VERSION = 2;

    function _openBatchDb() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(_IDB_NAME, _IDB_BATCH_VERSION);
            req.onupgradeneeded = e => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(_IDB_STORE)) {
                    db.createObjectStore(_IDB_STORE, { keyPath: 'fileId' });
                }
                if (!db.objectStoreNames.contains(_BATCH_STORE)) {
                    db.createObjectStore(_BATCH_STORE, { keyPath: 'batchId' });
                }
            };
            req.onsuccess = e => resolve(e.target.result);
            req.onerror   = () => reject(req.error);
        });
    }

    function _batchGet(idb, batchId) {
        return new Promise((resolve, reject) => {
            const tx  = idb.transaction(_BATCH_STORE, 'readonly');
            const req = tx.objectStore(_BATCH_STORE).get(batchId);
            req.onsuccess = () => resolve(req.result || null);
            req.onerror   = () => reject(req.error);
        });
    }

    function _batchPut(idb, record) {
        return new Promise((resolve, reject) => {
            const tx  = idb.transaction(_BATCH_STORE, 'readwrite');
            const req = tx.objectStore(_BATCH_STORE).put(record);
            req.onsuccess = () => resolve();
            req.onerror   = () => reject(req.error);
        });
    }

    function _batchDel(idb, batchId) {
        return new Promise((resolve, reject) => {
            const tx  = idb.transaction(_BATCH_STORE, 'readwrite');
            const req = tx.objectStore(_BATCH_STORE).delete(batchId);
            req.onsuccess = () => resolve();
            req.onerror   = () => reject(req.error);
        });
    }

    // ------------------------------------------------------------------
    // Folder tree expansion
    // ------------------------------------------------------------------

    /**
     * Expand a mixed list of files/folders into a flat list of
     * {fileId, path, parentFolderId} objects with full ZIP paths.
     *
     * @param {Array<{type:'file'|'folder', id:string, name:string, parentFolderId?:string}>} items
     * @returns {Promise<Array<{fileId:string, path:string, parentFolderId:string|null}>>}
     */
    async function _expandItems(items) {
        const result = [];

        async function walkFolder(folderId, folderName, pathPrefix) {
            const data = await Api.get(`${_prefix()}/folders/${folderId}`);
            for (const file of (data.files || [])) {
                result.push({
                    fileId:         file.id,
                    path:           pathPrefix + file.original_name,
                    parentFolderId: folderId,
                });
            }
            for (const sub of (data.child_folders || [])) {
                await walkFolder(sub.id, sub.name, pathPrefix + sub.name + '/');
            }
        }

        for (const item of items) {
            if (item.type === 'file') {
                result.push({
                    fileId:         item.id,
                    path:           item.name,
                    parentFolderId: item.parentFolderId || null,
                });
            } else if (item.type === 'folder') {
                await walkFolder(item.id, item.name, item.name + '/');
            }
        }
        return result;
    }

    // ------------------------------------------------------------------
    // Batch download coordinator
    // ------------------------------------------------------------------

    const BATCH_DOWNLOAD_CONCURRENCY = 3;

    /**
     * Download multiple files/folders, assembling a ZIP and saving via _saveBlob.
     * OPFS-first: each file is staged in OPFS before ZIP assembly begins.
     * Resumes automatically if the page is reloaded mid-batch.
     *
     * @param {Array<{type:'file'|'folder', id:string, name:string, parentFolderId?:string}>} items
     * @param {CryptoKey}   masterKey
     * @param {function}    onProgress  - (doneCount, totalCount) called per-file completion
     * @param {AbortSignal} [signal]
     */
    async function downloadBatch(items, masterKey, onProgress, signal = null) {
        if (!_opfsAvailable()) {
            return _downloadBatchInMemory(items, masterKey, onProgress, signal);
        }

        const ts      = _nowTs();
        const zipName = _zipName(items, {}, ts);

        // 1. Expand folders → flat file list
        const fileEntries = await _expandItems(items);
        if (fileEntries.length === 0) throw new Error('No files to download');

        // Single file → just download normally (no ZIP)
        if (fileEntries.length === 1) {
            return downloadFile(fileEntries[0].fileId, masterKey, onProgress, signal);
        }

        const batchId = fileEntries.map(e => e.fileId).sort((a, b) => a.localeCompare(b)).join(',');
        const idb     = await _openBatchDb();
        const dir     = await _getOpfsDir();

        // 2. Load or create batch state
        let state = await _batchGet(idb, batchId);
        if (state && state.totalFiles !== fileEntries.length) {
            // File list changed — discard stale state and start fresh
            await _cleanBatchOpfs(dir, state.fileIds || []);
            await _batchDel(idb, batchId);
            state = null;
        }

        if (!state) {
            state = {
                batchId,
                totalFiles: fileEntries.length,
                fileIds:    fileEntries.map(e => e.fileId),
                done:       [],
            };
            await _batchPut(idb, state);
        }

        const doneSet = new Set(state.done);

        // 3. Download each file to OPFS with concurrency limit
        const pending = fileEntries.filter(e => !doneSet.has(e.fileId));
        let   active  = 0;
        let   pIdx    = 0;
        let   doneCount = doneSet.size;

        await new Promise((resolve, reject) => {
            function startNext() {
                while (active < BATCH_DOWNLOAD_CONCURRENCY && pIdx < pending.length) {
                    const entry = pending[pIdx++];
                    active++;
                    _downloadFileToBatchOpfs(entry.fileId, masterKey, dir, idb, signal)
                        .then(() => { // NOSONAR — closure inside while/startNext/Promise; unavoidable nesting
                            doneSet.add(entry.fileId);
                            state.done = [...doneSet];
                            doneCount++;
                            _batchPut(idb, state).catch(() => {});
                            if (onProgress) onProgress(doneCount, fileEntries.length);
                            active--;
                            if (signal?.aborted) return reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
                            if (doneCount >= fileEntries.length) resolve();
                            else startNext();
                        })
                        .catch(err => { // NOSONAR
                            active--;
                            reject(err);
                        });
                }
            }
            startNext();
            if (pending.length === 0) resolve();
        });

        if (signal?.aborted) {
            const err = new Error('Aborted');
            err.name  = 'AbortError';
            throw err;
        }

        // 4. Read all files from OPFS and build ZIP
        const zipEntries = [];
        for (const entry of fileEntries) {
            const manifest = await _fetchManifest(entry.fileId);
            const totalChunks = manifest.total_chunks;
            const chunks = [];
            for (let i = 0; i < totalChunks; i++) {
                const buf = await _readChunk(dir, entry.fileId, i);
                chunks.push(new Uint8Array(buf));
            }
            const combined = _concatChunks(chunks);
            zipEntries.push({ path: entry.path, data: combined });
        }

        const zipBlob = _buildZip(zipEntries);

        // 5. Save
        _saveBlob(zipBlob, zipName);

        // 6. Cleanup OPFS + IDB
        await _cleanBatchOpfs(dir, fileEntries.map(e => e.fileId));
        for (const entry of fileEntries) {
            const s = await _idbGet(idb, entry.fileId).catch(() => null);
            if (s) await _clearChunks(dir, entry.fileId, s.totalChunks);
            await _idbDel(idb, entry.fileId);
        }
        await _batchDel(idb, batchId);
    }

    async function _downloadFileToBatchOpfs(fileId, masterKey, dir, idb, signal) {
        // Reuse the per-file OPFS download logic; assembly happens later in batch flow
        const manifest   = await _fetchManifest(fileId);
        const totalChunks = manifest.total_chunks;

        let state = await _idbGet(idb, fileId);
        if (state && state.totalChunks !== totalChunks) {
            await _clearChunks(dir, fileId, state.totalChunks);
            await _idbDel(idb, fileId);
            state = null;
        }

        const done = new Set(state ? state.done : []);
        if (!state) await _idbPut(idb, { fileId, totalChunks, done: [] });

        const fileKey = await Crypto.decryptFileKey(
            manifest.encrypted_file_key,
            manifest.key_iv,
            masterKey,
        );

        for (let i = 0; i < totalChunks; i++) {
            if (signal?.aborted) throw Object.assign(new Error('Aborted'), { name: 'AbortError' });
            if (done.has(i)) continue;

            const plainBuf = await _fetchDecryptChunk(fileId, manifest.chunks[i], i, totalChunks, fileKey, signal);
            await _writeChunk(dir, fileId, i, plainBuf);
            done.add(i);
            await _idbPut(idb, { fileId, totalChunks, done: [...done] });
        }
    }

    async function _cleanBatchOpfs(dir, fileIds) {
        for (const fileId of fileIds) {
            try {
                // Attempt to remove any OPFS chunks left for this file.
                // We don't know totalChunks here so try up to 10000 chunks.
                const root = dir;
                for (let i = 0; i < 10000; i++) {
                    try { await root.removeEntry(_chunkName(fileId, i)); } catch { break; }
                }
            } catch { /* best-effort */ }
        }
    }

    function _concatChunks(chunks) {
        const total = chunks.reduce((s, c) => s + c.length, 0);
        const out   = new Uint8Array(total);
        let   pos   = 0;
        for (const c of chunks) { out.set(c, pos); pos += c.length; }
        return out;
    }

    // ------------------------------------------------------------------
    // In-memory batch fallback (for browsers without OPFS)
    // ------------------------------------------------------------------

    async function _downloadBatchInMemory(items, masterKey, onProgress, signal) {
        const ts      = _nowTs();
        const zipName = _zipName(items, {}, ts);

        const fileEntries = await _expandItems(items);
        if (fileEntries.length === 0) throw new Error('No files to download');

        if (fileEntries.length === 1) {
            return _downloadInMemory(fileEntries[0].fileId, masterKey, onProgress, signal);
        }

        const zipEntries = [];
        let   done       = 0;

        for (const entry of fileEntries) {
            if (signal?.aborted) throw Object.assign(new Error('Aborted'), { name: 'AbortError' });
            const manifest = await _fetchManifest(entry.fileId);
            const fileKey  = await Crypto.decryptFileKey(
                manifest.encrypted_file_key, manifest.key_iv, masterKey,
            );
            const chunks = [];
            for (let i = 0; i < manifest.chunks.length; i++) {
                const plain = await _fetchDecryptChunk(entry.fileId, manifest.chunks[i], i, manifest.chunks.length, fileKey, signal);
                chunks.push(new Uint8Array(plain));
            }
            zipEntries.push({ path: entry.path, data: _concatChunks(chunks) });
            done++;
            if (onProgress) onProgress(done, fileEntries.length);
        }

        _saveBlob(_buildZip(zipEntries), zipName);
    }

    return { downloadFile, downloadBatch, listPartialDownloads, clearPartialDownload };
})();
