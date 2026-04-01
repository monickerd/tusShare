/**
 * tusShare — Sharing UI (create dialog, management page, public share view).
 *
 * Three entry points:
 *   openShareDialog(selectedFiles)         — authenticated: create a link share
 *   renderSharesPage(container)            — authenticated: manage existing shares
 *   renderPublicSharePage(container, token, shareKeyB64url)  — public: view + download
 *   renderShortLinkPage(container, slug, shareKeyB64url)     — public: resolve short link
 *
 * Share URL format:  /s/<token>#<shareKeyBase64url>
 * Short link format: /l/<slug>#<shareKeyBase64url>
 * The shareKey is in the URL fragment — never sent to the server, never logged.
 *
 * SessionStorage key persistence:
 *   When a share is created the shareKey is stored in sessionStorage under
 *   Config.share.keyStoragePrefix + share_id.  The key is available for the
 *   duration of the session so the owner can copy the URL from My Shares.
 *   Once the session ends, the shareKey is gone — the owner should copy the
 *   URL immediately after creation.
 */
const Shares = (() => {
    const _prefix = () => Config.app.apiPrefix;

    // -----------------------------------------------------------------------
    // SessionStorage helpers for shareKey persistence
    // -----------------------------------------------------------------------

    function _storeShareKey(shareId, shareKeyB64url) {
        try {
            sessionStorage.setItem(Config.share.keyStoragePrefix + shareId, shareKeyB64url);
        } catch {
            // Storage full or unavailable — non-fatal
        }
    }

    function _loadShareKey(shareId) {
        try {
            return sessionStorage.getItem(Config.share.keyStoragePrefix + shareId) || null;
        } catch {
            return null;
        }
    }

    function _removeShareKey(shareId) {
        try {
            sessionStorage.removeItem(Config.share.keyStoragePrefix + shareId);
        } catch {}
    }

    // -----------------------------------------------------------------------
    // Share URL construction
    // -----------------------------------------------------------------------

    function _buildShareUrl(token, shareKeyB64url) {
        return `${window.location.origin}/s/${token}#${shareKeyB64url}`;
    }

    function _buildShortLinkUrl(slug, shareKeyB64url) {
        return `${window.location.origin}/l/${slug}#${shareKeyB64url}`;
    }

    // -----------------------------------------------------------------------
    // Default expiry helper
    // -----------------------------------------------------------------------

    function _defaultExpiryIso() {
        const d = new Date();
        d.setDate(d.getDate() + Config.share.defaultExpiryDays);
        // Round to midnight to give a clean date for the date-picker default
        d.setHours(23, 59, 59, 0);
        return d.toISOString().slice(0, 16);  // "YYYY-MM-DDTHH:MM"
    }

    // -----------------------------------------------------------------------
    // Copy-to-clipboard helper
    // -----------------------------------------------------------------------

    async function _copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Public download helpers (used by the public share view)
    // -----------------------------------------------------------------------

    /**
     * Fetch the full chunk manifest for a file in a share (handles pagination).
     * @param {string}      token        - Share token.
     * @param {string}      fileId       - File UUID.
     * @param {string|null} sessionToken - share_session_token from resolve response, or null for auth'd users.
     */
    async function _fetchSharedManifest(token, fileId, sessionToken = null) {
        const pageSize = 500;
        let offset = 0;
        let manifest = null;
        const allChunks = [];

        const headers = {};
        if (sessionToken) headers['Authorization'] = `Bearer ${sessionToken}`;

        while (true) {
            const url = `/s/${token}/files/${fileId}/chunks?offset=${offset}&limit=${pageSize}`;
            const resp = await fetch(url, { credentials: 'same-origin', headers });
            if (!resp.ok) {
                const body = await resp.json().catch(() => ({}));
                throw new Error(body.detail || `HTTP ${resp.status}`);
            }
            const data = await resp.json();
            if (!manifest) manifest = data;
            allChunks.push(...data.chunks);
            if (allChunks.length >= data.total_chunks) break;
            offset += pageSize;
        }

        return { ...manifest, chunks: allChunks };
    }

    /**
     * Download and decrypt a file from a public share.
     *
     * @param {string}      token         - Share token (from URL path).
     * @param {object}      fileInfo      - { resource_id, file_name, encrypted_file_key, key_iv }
     * @param {CryptoKey}   shareKey      - Decrypted share key (from URL fragment).
     * @param {function}    onProgress    - Called with (chunksDecrypted, totalChunks).
     * @param {string|null} sessionToken  - share_session_token for unauthenticated access.
     */
    async function _downloadSharedFile(token, fileInfo, shareKey, onProgress, sessionToken = null) {
        // 1. Decrypt file key using shareKey
        const fileKey = await Crypto.unwrapFileKeyFromShare(
            fileInfo.encrypted_file_key,
            fileInfo.key_iv,
            shareKey,
        );

        // 2. Fetch chunk manifest
        const manifest = await _fetchSharedManifest(token, fileInfo.resource_id, sessionToken);

        if (manifest.chunks.length !== manifest.total_chunks) {
            throw new Error(
                `Manifest incomplete: expected ${manifest.total_chunks} chunks, ` +
                `got ${manifest.chunks.length}`
            );
        }

        // 3. Fetch + decrypt each chunk
        const totalChunks = manifest.chunks.length;
        const decryptedChunks = [];
        let totalBytes = 0;

        for (let i = 0; i < totalChunks; i++) {
            const chunk = manifest.chunks[i];
            const rangeStart = chunk.offset;
            const rangeEnd   = chunk.offset + chunk.size_bytes - 1;

            const chunkHeaders = { Range: `bytes=${rangeStart}-${rangeEnd}` };
            if (sessionToken) chunkHeaders['Authorization'] = `Bearer ${sessionToken}`;
            const resp = await fetch(`/s/${token}/files/${fileInfo.resource_id}/content`, {
                headers: chunkHeaders,
                credentials: 'same-origin',
            });

            if (resp.status === 410) {
                throw new Error('Download limit reached — this share is no longer available.');
            }
            if (!resp.ok) {
                const body = await resp.json().catch(() => ({}));
                throw new Error(body.detail || `Failed to fetch chunk ${i + 1}: HTTP ${resp.status}`);
            }

            const ciphertext = await resp.arrayBuffer();

            let plaintext;
            try {
                plaintext = await Crypto.decryptChunk(ciphertext, chunk.iv, fileKey);
            } catch {
                throw new Error(
                    `Chunk ${i + 1}/${totalChunks} failed integrity check — ` +
                    `data may be corrupted (offset ${rangeStart})`
                );
            }

            decryptedChunks.push(plaintext);
            totalBytes += plaintext.byteLength;

            if (onProgress) onProgress(i + 1, totalChunks);
        }

        // 4. Post-decryption size check
        if (manifest.size_bytes > 0 && totalBytes !== manifest.size_bytes) {
            throw new Error(
                `Size mismatch after decryption: expected ${manifest.size_bytes} bytes, ` +
                `got ${totalBytes} bytes`
            );
        }

        // 5. Assemble and save
        const blob = new Blob(decryptedChunks.map(ab => new Uint8Array(ab)));
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = fileInfo.file_name || 'download';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    // -----------------------------------------------------------------------
    // Share creation dialog (authenticated owner)
    // -----------------------------------------------------------------------

    /**
     * Open a modal dialog to create a link share for the given files.
     *
     * @param {Array} selectedFiles - File objects from the file browser, each with:
     *   { id, original_name, size_bytes, encrypted_file_key, key_iv }
     */
    async function openShareDialog(selectedFiles) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        const files = selectedFiles.filter(f => f.encrypted_file_key && f.key_iv);
        if (files.length === 0) {
            Utils.showToast('No shareable files selected.', 'info');
            return;
        }
        if (files.length > Config.share.maxItems) {
            Utils.showToast(`Too many files selected (max ${Config.share.maxItems}).`, 'error');
            return;
        }

        const overlay = Utils.el('div', { className: 'modal-overlay' });
        const dialog  = Utils.el('div', { className: 'modal share-dialog' });

        function _closeDialog() {
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        }

        // --- File list ---
        const fileList = Utils.el('ul', { className: 'share-file-list' });
        for (const f of files) {
            fileList.appendChild(Utils.el('li', {
                textContent: `${f.original_name} (${Utils.formatBytes(f.size_bytes)})`,
            }));
        }

        // --- Expiry field ---
        const expiryInput = Utils.el('input', {
            type: 'datetime-local',
            className: 'input',
            value: _defaultExpiryIso(),
        });

        // --- Max downloads field ---
        const maxDlInput = Utils.el('input', {
            type: 'number',
            className: 'input',
            placeholder: 'Unlimited',
            min: '1',
            max: '10000',
        });

        // --- Status area (shows URL after creation) ---
        const statusArea = Utils.el('div', { className: 'share-status' });

        // --- Buttons ---
        const createBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Create link',
        });
        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Cancel',
            onClick: _closeDialog,
        });

        createBtn.addEventListener('click', async () => {
            createBtn.disabled = true;
            createBtn.textContent = 'Creating…';
            _clearEl(statusArea);

            try {
                const shareKeyB64url = await _doCreateShare(
                    files, masterKey, expiryInput.value, maxDlInput.value, statusArea
                );
                if (shareKeyB64url) {
                    // Hide create controls, show close button
                    createBtn.style.display = 'none';
                    cancelBtn.textContent = 'Close';
                }
            } catch (err) {
                statusArea.appendChild(Utils.el('p', {
                    className: 'share-error',
                    textContent: `Failed: ${err.message}`,
                }));
                createBtn.disabled = false;
                createBtn.textContent = 'Create link';
            }
        });

        dialog.appendChild(Utils.el('h3', { textContent: 'Share files' }));
        dialog.appendChild(fileList);
        dialog.appendChild(Utils.el('label', {}, [
            Utils.el('span', { textContent: 'Expires at' }),
            expiryInput,
        ]));
        dialog.appendChild(Utils.el('label', {}, [
            Utils.el('span', { textContent: 'Max downloads (optional)' }),
            maxDlInput,
        ]));
        dialog.appendChild(statusArea);
        dialog.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, createBtn]));

        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
    }

    /**
     * Perform the actual share creation: generate shareKey, re-wrap each file
     * key, POST to API, store shareKey in sessionStorage.
     * Returns the shareKeyB64url on success.
     */
    async function _doCreateShare(files, masterKey, expiresAtLocal, maxDlStr, statusArea) {
        // Convert local datetime-local value to ISO 8601 UTC
        let expiresAt = null;
        if (expiresAtLocal) {
            const d = new Date(expiresAtLocal);
            if (isNaN(d.getTime())) throw new Error('Invalid expiry date');
            expiresAt = d.toISOString();
        }

        const maxDownloads = maxDlStr ? parseInt(maxDlStr, 10) : null;
        if (maxDownloads !== null && (isNaN(maxDownloads) || maxDownloads < 1)) {
            throw new Error('Max downloads must be a positive number');
        }

        // Generate a random AES-256 shareKey (never leaves the browser raw)
        const shareKey = await Crypto.generateShareKey();
        const shareKeyB64url = await Crypto.exportKeyToBase64url(shareKey);

        // Re-wrap each file key with shareKey
        const items = [];
        for (const f of files) {
            const fileKey = await Crypto.decryptFileKey(
                f.encrypted_file_key, f.key_iv, masterKey
            );
            const { wrappedKeyB64, ivB64 } = await Crypto.wrapFileKeyForShare(fileKey, shareKey);
            items.push({
                resource_type: 'file',
                resource_id: f.id,
                encrypted_file_key: wrappedKeyB64,
                key_iv: ivB64,
            });
        }

        // POST to API
        const resp = await Api.post(`${_prefix()}/shares`, {
            items,
            expires_at: expiresAt,
            max_downloads: maxDownloads,
        });

        // Persist shareKey for the session so the owner can copy the URL later
        _storeShareKey(resp.share_id, shareKeyB64url);

        // Build and display the share URL
        const shareUrl = _buildShareUrl(resp.token, shareKeyB64url);
        _renderShareUrlBox(statusArea, shareUrl);

        Utils.showToast('Share link created', 'success');
        return shareKeyB64url;
    }

    // -----------------------------------------------------------------------
    // "My Shares" management page (authenticated owner)
    // -----------------------------------------------------------------------

    async function renderSharesPage(container) {
        _clearEl(container);

        const page = Utils.el('div', { className: 'page-content' });
        page.appendChild(Utils.el('h2', { textContent: 'My Shares' }));

        const listEl = Utils.el('div', { className: 'shares-list', textContent: 'Loading…' });
        page.appendChild(listEl);
        container.appendChild(page);

        try {
            const data = await Api.get(`${_prefix()}/shares`);
            _renderSharesList(listEl, data.shares);
        } catch (err) {
            listEl.textContent = `Failed to load shares: ${err.message}`;
        }
    }

    function _renderSharesList(container, shares) {
        _clearEl(container);

        if (shares.length === 0) {
            container.appendChild(Utils.el('p', {
                className: 'text-muted',
                textContent: 'No shares yet. Select files and choose "Share" to create one.',
            }));
            return;
        }

        for (const share of shares) {
            container.appendChild(_createShareCard(share));
        }
    }

    function _createShareCard(share) {
        const card = Utils.el('div', {
            className: 'share-card' + (share.is_active ? '' : ' share-inactive'),
        });

        // Header: file count + status badges
        const header = Utils.el('div', { className: 'share-card-header' });
        const fileCount = (share.items || []).length;
        header.appendChild(Utils.el('span', {
            className: 'share-card-title',
            textContent: `${fileCount} file${fileCount !== 1 ? 's' : ''}`,
        }));
        if (!share.is_active) {
            header.appendChild(Utils.el('span', { className: 'badge badge-muted', textContent: 'Inactive' }));
        }
        if (share.expires_at) {
            const expired = new Date(share.expires_at) < new Date();
            header.appendChild(Utils.el('span', {
                className: 'badge ' + (expired ? 'badge-danger' : 'badge-info'),
                textContent: expired ? 'Expired' : `Expires ${Utils.timeAgo(share.expires_at)}`,
            }));
        }
        if (share.max_downloads) {
            header.appendChild(Utils.el('span', {
                className: 'badge badge-info',
                textContent: `${share.download_count}/${share.max_downloads} downloads`,
            }));
        }
        card.appendChild(header);

        // File list
        const fileList = Utils.el('ul', { className: 'share-file-list' });
        for (const item of (share.items || [])) {
            if (item.file_name) {
                fileList.appendChild(Utils.el('li', {
                    textContent: `${item.file_name} (${Utils.formatBytes(item.size_bytes)})`,
                }));
            }
        }
        if (fileList.children.length > 0) card.appendChild(fileList);

        // Share URL (if shareKey available in sessionStorage)
        const shareKeyB64url = _loadShareKey(share.id);
        if (shareKeyB64url) {
            const urlBox = Utils.el('div', { className: 'share-url-box' });
            _renderShareUrlBox(urlBox, _buildShareUrl(share.token, shareKeyB64url));
            card.appendChild(urlBox);
        } else {
            card.appendChild(Utils.el('p', {
                className: 'text-muted share-key-gone',
                textContent: 'Share URL not available — key is only accessible during the session it was created.',
            }));
        }

        // Short links
        for (const sl of (share.short_links || [])) {
            if (shareKeyB64url) {
                const slBox = Utils.el('div', { className: 'share-url-box' });
                _renderShareUrlBox(slBox, _buildShortLinkUrl(sl.slug, shareKeyB64url), sl.slug);
                card.appendChild(slBox);
            }
        }

        // Action buttons
        const actions = Utils.el('div', { className: 'share-card-actions' });

        if (share.is_active && shareKeyB64url) {
            const addSlBtn = Utils.el('button', {
                className: 'btn btn-secondary btn-sm',
                textContent: 'Add short link',
                onClick: () => _promptCreateShortLink(share, shareKeyB64url, card),
            });
            actions.appendChild(addSlBtn);
        }

        const deleteBtn = Utils.el('button', {
            className: 'btn btn-danger btn-sm',
            textContent: 'Delete',
            onClick: async () => {
                const ok = await Utils.showConfirm('Delete this share? Recipients will lose access immediately.');
                if (!ok) return;
                try {
                    await Api.del(`${_prefix()}/shares/${share.id}`);
                    _removeShareKey(share.id);
                    card.remove();
                    Utils.showToast('Share deleted', 'success');
                } catch (err) {
                    Utils.showToast(`Delete failed: ${err.message}`, 'error');
                }
            },
        });
        actions.appendChild(deleteBtn);

        card.appendChild(actions);
        return card;
    }

    async function _promptCreateShortLink(share, shareKeyB64url, card) {
        const defaultExpiry = _defaultExpiryIso();
        const expiryStr = prompt(`Short link expiry (YYYY-MM-DDTHH:MM):`, defaultExpiry);
        if (!expiryStr) return;

        const d = new Date(expiryStr);
        if (isNaN(d.getTime()) || d <= new Date()) {
            Utils.showToast('Invalid or past expiry date', 'error');
            return;
        }

        try {
            const resp = await Api.post(`${_prefix()}/shares/${share.id}/short-link`, {
                expires_at: d.toISOString(),
            });
            const slUrl = _buildShortLinkUrl(resp.slug, shareKeyB64url);
            Utils.showToast(`Short link created: ${resp.slug}`, 'success');

            // Append the new short link URL box to the card
            const urlBox = Utils.el('div', { className: 'share-url-box' });
            _renderShareUrlBox(urlBox, slUrl, resp.slug);
            // Insert before the action buttons
            const actionsEl = card.querySelector('.share-card-actions');
            if (actionsEl) card.insertBefore(urlBox, actionsEl);
            else card.appendChild(urlBox);
        } catch (err) {
            Utils.showToast(`Failed: ${err.message}`, 'error');
        }
    }

    // -----------------------------------------------------------------------
    // Public share view (no authentication required)
    // -----------------------------------------------------------------------

    /**
     * Render the public share access page.
     *
     * @param {HTMLElement} container      - Root element.
     * @param {string}      token          - Share token (from URL path).
     * @param {string}      shareKeyB64url - ShareKey as base64url (from URL fragment).
     */
    async function renderPublicSharePage(container, token, shareKeyB64url) {
        _clearEl(container);

        const page = Utils.el('div', { className: 'page-content public-share-page' });
        page.appendChild(Utils.el('h2', { textContent: 'Shared files' }));
        const status = Utils.el('p', { textContent: 'Loading…' });
        page.appendChild(status);
        container.appendChild(page);

        if (!shareKeyB64url) {
            status.textContent = 'Invalid share link — the encryption key is missing from the URL fragment.';
            return;
        }

        let shareKey;
        try {
            shareKey = await Crypto.importKeyFromBase64url(shareKeyB64url);
        } catch {
            status.textContent = 'Invalid share link — the encryption key could not be imported.';
            return;
        }

        let shareData;
        let shareSessionToken = null;
        try {
            const resp = await fetch(`/api/v1/s/${token}`, { credentials: 'same-origin' });
            if (resp.status === 404) {
                status.textContent = 'This share link has expired or been deleted.';
                return;
            }
            if (!resp.ok) {
                status.textContent = `Error loading share: HTTP ${resp.status}`;
                return;
            }
            shareData = await resp.json();
            shareSessionToken = shareData.share_session_token || null;
        } catch (err) {
            status.textContent = `Failed to load share: ${err.message}`;
            return;
        }

        _clearEl(page);
        page.appendChild(Utils.el('div', { className: 'app-header public-header' }, [
            Utils.el('div', { className: 'header-brand', textContent: Config.app.name }),
        ]));
        page.appendChild(Utils.el('h2', { textContent: 'Shared files' }));

        // Metadata badges
        const meta = Utils.el('div', { className: 'share-meta' });
        if (shareData.expires_at) {
            meta.appendChild(Utils.el('span', {
                className: 'badge badge-info',
                textContent: `Expires ${Utils.formatDate(shareData.expires_at)}`,
            }));
        }
        if (shareData.max_downloads) {
            meta.appendChild(Utils.el('span', {
                className: 'badge badge-info',
                textContent: `${shareData.download_count}/${shareData.max_downloads} downloads used`,
            }));
        }
        if (meta.children.length > 0) page.appendChild(meta);

        if (!shareData.files || shareData.files.length === 0) {
            page.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No files in this share.' }));
            return;
        }

        // File list with per-file download buttons
        const table = Utils.el('table', { className: 'file-table' }, [
            Utils.el('thead', {}, [
                Utils.el('tr', {}, [
                    Utils.el('th', { textContent: 'File' }),
                    Utils.el('th', { textContent: 'Size' }),
                    Utils.el('th', { textContent: '' }),
                ]),
            ]),
        ]);
        const tbody = Utils.el('tbody');

        for (const fileInfo of shareData.files) {
            const row = Utils.el('tr');
            row.appendChild(Utils.el('td', { textContent: fileInfo.file_name || fileInfo.resource_id }));
            row.appendChild(Utils.el('td', { textContent: Utils.formatBytes(fileInfo.size_bytes) }));

            const dlBtn = Utils.el('button', {
                className: 'btn btn-primary btn-sm',
                textContent: 'Download',
            });
            dlBtn.addEventListener('click', () =>
                _handlePublicDownload(dlBtn, token, fileInfo, shareKey, shareSessionToken)
            );
            row.appendChild(Utils.el('td', {}, [dlBtn]));
            tbody.appendChild(row);
        }

        table.appendChild(tbody);
        page.appendChild(table);
    }

    async function _handlePublicDownload(btn, token, fileInfo, shareKey, sessionToken = null) {
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = '0%';

        try {
            await _downloadSharedFile(token, fileInfo, shareKey, (done, total) => {
                const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                btn.textContent = `${pct}%`;
            }, sessionToken);
            btn.textContent = 'Done';
        } catch (err) {
            btn.disabled = false;
            btn.textContent = origText;
            Utils.showToast(`Download failed: ${err.message}`, 'error');
        }
    }

    // -----------------------------------------------------------------------
    // Short link resolution (public)
    // -----------------------------------------------------------------------

    /**
     * Resolve a short link slug and render the public share page.
     *
     * @param {HTMLElement} container      - Root element.
     * @param {string}      slug           - 3-word PascalCase slug (from URL path).
     * @param {string}      shareKeyB64url - ShareKey from URL fragment.
     */
    async function renderShortLinkPage(container, slug, shareKeyB64url) {
        _clearEl(container);
        const page = Utils.el('div', { className: 'page-content public-share-page' });
        page.appendChild(Utils.el('div', { className: 'app-header public-header' }, [
            Utils.el('div', { className: 'header-brand', textContent: Config.app.name }),
        ]));
        page.appendChild(Utils.el('h2', { textContent: 'Shared files' }));
        const status = Utils.el('p', { textContent: 'Loading…' });
        page.appendChild(status);
        container.appendChild(page);

        if (!shareKeyB64url) {
            status.textContent = 'Invalid share link — the encryption key is missing from the URL fragment.';
            return;
        }

        // Resolve slug → share data (includes the token for download URLs)
        let shareData;
        try {
            const resp = await fetch(`/api/v1/l/${slug}`, { credentials: 'same-origin' });
            if (resp.status === 404) {
                status.textContent = 'This short link has expired or been deleted.';
                return;
            }
            if (!resp.ok) {
                status.textContent = `Error resolving short link: HTTP ${resp.status}`;
                return;
            }
            shareData = await resp.json();
        } catch (err) {
            status.textContent = `Failed to resolve short link: ${err.message}`;
            return;
        }

        // Delegate to public share rendering using the resolved token
        // Replace the URL so future refreshes use the canonical /s/ path
        if (history.replaceState) {
            history.replaceState(null, '', `/s/${shareData.token}#${shareKeyB64url}`);
        }

        // Re-render as a public share page with the resolved token
        await renderPublicSharePage(container, shareData.token, shareKeyB64url);
    }

    // -----------------------------------------------------------------------
    // DOM helpers
    // -----------------------------------------------------------------------

    function _clearEl(el) {
        while (el.firstChild) el.removeChild(el.firstChild);
    }

    /**
     * Render a URL display box with a copy button inside `container`.
     *
     * @param {HTMLElement} container - Element to render into.
     * @param {string}      url       - The full share URL.
     * @param {string}      [label]   - Optional prefix label (e.g., short slug).
     */
    function _renderShareUrlBox(container, url, label) {
        const urlInput = Utils.el('input', {
            type: 'text',
            className: 'input share-url-input',
            value: url,
            readonly: '',
            onClick: () => urlInput.select(),
        });

        const copyBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Copy',
        });
        copyBtn.addEventListener('click', async () => {
            const ok = await _copyToClipboard(url);
            copyBtn.textContent = ok ? 'Copied!' : 'Copy failed';
            setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
        });

        const row = Utils.el('div', { className: 'share-url-row' });
        if (label) {
            row.appendChild(Utils.el('span', { className: 'share-url-label', textContent: label }));
        }
        row.appendChild(urlInput);
        row.appendChild(copyBtn);
        container.appendChild(row);
    }

    // -----------------------------------------------------------------------
    // Folder share (Phase 5b) — enumerate files recursively then share
    // -----------------------------------------------------------------------

    /**
     * Share all files within a folder (recursively enumerated server-side).
     * Creates a link share with all discovered files, same as openShareDialog.
     *
     * @param {{ id: string, name: string }} folder - Folder to share.
     */
    async function openFolderShareDialog(folder) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        let files;
        try {
            const data = await Api.get(
                `${_prefix()}/folders/${folder.id}/files?limit=${Config.share.maxItems}`
            );
            files = data.files || [];
        } catch (err) {
            Utils.showToast(`Failed to enumerate folder: ${err.message}`, 'error');
            return;
        }

        if (files.length === 0) {
            Utils.showToast('This folder contains no files to share.', 'info');
            return;
        }
        if (files.length >= Config.share.maxItems) {
            Utils.showToast(
                `Folder contains ${Config.share.maxItems}+ files. Only the first ${Config.share.maxItems} will be shared.`,
                'warning'
            );
        }

        openShareDialog(files);
    }

    // -----------------------------------------------------------------------
    // Username share dialog (Phase 5b) — PQ-KEM direct-user share
    // -----------------------------------------------------------------------

    /**
     * Open a dialog to share files directly with a named user via PQ-KEM.
     * No public URL is generated — only the recipient can decrypt.
     *
     * @param {Array} selectedFiles - File objects with encrypted_file_key + key_iv.
     */
    async function openUserShareDialog(selectedFiles) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        const files = selectedFiles.filter(f => f.encrypted_file_key && f.key_iv);
        if (files.length === 0) {
            Utils.showToast('No shareable files selected.', 'info');
            return;
        }
        if (files.length > Config.share.maxItems) {
            Utils.showToast(`Too many files selected (max ${Config.share.maxItems}).`, 'error');
            return;
        }

        const overlay = Utils.el('div', { className: 'modal-overlay' });
        const dialog  = Utils.el('div', { className: 'modal share-dialog' });

        function _closeDialog() {
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        }

        const fileList = Utils.el('ul', { className: 'share-file-list' });
        for (const f of files) {
            fileList.appendChild(Utils.el('li', {
                textContent: `${f.original_name} (${Utils.formatBytes(f.size_bytes)})`,
            }));
        }

        const recipientInput = Utils.el('input', {
            type: 'text',
            className: 'input',
            placeholder: 'Username',
            autocomplete: 'off',
        });

        const expiryInput = Utils.el('input', {
            type: 'datetime-local',
            className: 'input',
            value: _defaultExpiryIso(),
        });

        const statusArea = Utils.el('div', { className: 'share-status' });

        const createBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Send',
        });
        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Cancel',
            onClick: _closeDialog,
        });

        createBtn.addEventListener('click', async () => {
            const username = recipientInput.value.trim();
            if (!username) {
                Utils.showToast('Enter a username', 'error');
                return;
            }

            createBtn.disabled = true;
            createBtn.textContent = 'Sending…';
            _clearEl(statusArea);

            try {
                await _doCreateUserShare(files, masterKey, username, expiryInput.value, statusArea);
                createBtn.style.display = 'none';
                cancelBtn.textContent = 'Close';
            } catch (err) {
                statusArea.appendChild(Utils.el('p', {
                    className: 'share-error',
                    textContent: `Failed: ${err.message}`,
                }));
                createBtn.disabled = false;
                createBtn.textContent = 'Send';
            }
        });

        dialog.appendChild(Utils.el('h3', { textContent: 'Share with user' }));
        dialog.appendChild(fileList);
        dialog.appendChild(Utils.el('label', {}, [
            Utils.el('span', { textContent: 'Recipient username' }),
            recipientInput,
        ]));
        dialog.appendChild(Utils.el('label', {}, [
            Utils.el('span', { textContent: 'Expires at' }),
            expiryInput,
        ]));
        dialog.appendChild(statusArea);
        dialog.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, createBtn]));

        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
    }

    async function _doCreateUserShare(files, masterKey, recipientUsername, expiresAtLocal, statusArea) {
        // 1. Fetch recipient's public keys
        let pubKeys;
        try {
            pubKeys = await Api.get(
                `${Config.app.apiPrefix}/auth/users/${encodeURIComponent(recipientUsername)}/public-keys`
            );
        } catch (err) {
            if (err.message && err.message.includes('404')) {
                throw new Error(
                    `User "${recipientUsername}" not found or hasn't set up sharing keys yet. ` +
                    'They need to log in at least once to activate sharing.'
                );
            }
            throw err;
        }

        // 2. Convert local expiry
        let expiresAt = null;
        if (expiresAtLocal) {
            const d = new Date(expiresAtLocal);
            if (isNaN(d.getTime())) throw new Error('Invalid expiry date');
            expiresAt = d.toISOString();
        }

        // 3. Re-wrap each file key for the recipient via KEM
        const items = [];
        for (const f of files) {
            const fileKey = await Crypto.decryptFileKey(
                f.encrypted_file_key, f.key_iv, masterKey
            );
            const {
                wrappedFileKeyB64, keyIvB64,
                ephemeralX25519PubB64, kemCiphertextB64,
            } = await Crypto.encapsulateFileKeyForUser(
                fileKey,
                pubKeys.x25519_public_key,
                pubKeys.mlkem768_public_key
            );
            items.push({
                resource_type: 'file',
                resource_id: f.id,
                encrypted_file_key: wrappedFileKeyB64,
                key_iv: keyIvB64,
                ephemeral_x25519_pub: ephemeralX25519PubB64,
                kem_ciphertext: kemCiphertextB64,
            });
        }

        // 4. POST share
        await Api.post(`${_prefix()}/shares`, {
            share_type: 'user',
            recipient_username: recipientUsername,
            items,
            expires_at: expiresAt,
        });

        statusArea.appendChild(Utils.el('p', {
            className: 'text-muted',
            textContent: `Files shared with ${recipientUsername}.`,
        }));
        Utils.showToast(`Files shared with ${recipientUsername}`, 'success');
    }

    // -----------------------------------------------------------------------
    // Received shares page (Phase 5b) — user shares sent to the current user
    // -----------------------------------------------------------------------

    async function renderReceivedSharesPage(container) {
        _clearEl(container);
        const page = Utils.el('div', { className: 'page-content' });
        page.appendChild(Utils.el('h2', { textContent: 'Received Shares' }));

        const listEl = Utils.el('div', { className: 'shares-list', textContent: 'Loading…' });
        page.appendChild(listEl);
        container.appendChild(page);

        try {
            const data = await Api.get(`${_prefix()}/shares/received`);
            _renderReceivedList(listEl, data.shares);
        } catch (err) {
            listEl.textContent = `Failed to load: ${err.message}`;
        }
    }

    function _renderReceivedList(container, shares) {
        _clearEl(container);

        if (shares.length === 0) {
            container.appendChild(Utils.el('p', {
                className: 'text-muted',
                textContent: 'No shares received yet.',
            }));
            return;
        }

        for (const share of shares) {
            container.appendChild(_createReceivedShareCard(share));
        }
    }

    function _createReceivedShareCard(share) {
        const card = Utils.el('div', { className: 'share-card' });

        const header = Utils.el('div', { className: 'share-card-header' });
        const fileCount = (share.files || []).length;
        header.appendChild(Utils.el('span', {
            className: 'share-card-title',
            textContent: `${fileCount} file${fileCount !== 1 ? 's' : ''} from ${share.sender_username || 'unknown'}`,
        }));
        if (share.expires_at) {
            const expired = new Date(share.expires_at) < new Date();
            header.appendChild(Utils.el('span', {
                className: 'badge ' + (expired ? 'badge-danger' : 'badge-info'),
                textContent: expired ? 'Expired' : `Expires ${Utils.timeAgo(share.expires_at)}`,
            }));
        }
        card.appendChild(header);

        // File list with per-file download buttons
        const fileList = Utils.el('ul', { className: 'share-file-list' });
        for (const fileInfo of (share.files || [])) {
            if (!fileInfo.file_name) continue;
            const li = Utils.el('li');

            const nameSpan = Utils.el('span', {
                textContent: `${fileInfo.file_name} (${Utils.formatBytes(fileInfo.size_bytes)})`,
                style: 'flex:1;',
            });
            const dlBtn = Utils.el('button', {
                className: 'btn btn-primary btn-sm',
                textContent: 'Download',
                style: 'float:right;margin-left:8px',
            });
            dlBtn.addEventListener('click', () =>
                _handleUserShareDownload(dlBtn, share, fileInfo)
            );

            li.appendChild(nameSpan);
            li.appendChild(dlBtn);
            fileList.appendChild(li);
        }
        if (fileList.children.length > 0) card.appendChild(fileList);

        return card;
    }

    async function _handleUserShareDownload(btn, share, fileInfo) {
        const asymKeys = Auth.getAsymmetricKeys();
        if (!asymKeys) {
            Utils.showToast('Sharing keys not available — please re-enter your password.', 'error');
            return;
        }

        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = '0%';

        try {
            await _downloadUserSharedFile(share.token, fileInfo, asymKeys, (done, total) => {
                const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                btn.textContent = `${pct}%`;
            });
            btn.textContent = 'Done';
        } catch (err) {
            btn.disabled = false;
            btn.textContent = origText;
            Utils.showToast(`Download failed: ${err.message}`, 'error');
        }
    }

    /**
     * Download and decrypt a file received via a user share (PQ-KEM).
     */
    async function _downloadUserSharedFile(token, fileInfo, asymKeys, onProgress) {
        // Decapsulate file key using recipient's private keys + KEM ciphertext
        const fileKey = await Crypto.decapsulateFileKeyFromUser(
            fileInfo.encrypted_file_key,
            fileInfo.key_iv,
            fileInfo.ephemeral_x25519_pub,
            fileInfo.kem_ciphertext,
            asymKeys.x25519PrivateKey,
            asymKeys.mlkem768SecretKey,
        );

        // Fetch chunk manifest and decrypt (same as public share download)
        const manifest = await _fetchSharedManifest(token, fileInfo.resource_id);

        if (manifest.chunks.length !== manifest.total_chunks) {
            throw new Error(
                `Manifest incomplete: expected ${manifest.total_chunks} chunks, ` +
                `got ${manifest.chunks.length}`
            );
        }

        const totalChunks = manifest.chunks.length;
        const decryptedChunks = [];
        let totalBytes = 0;

        for (let i = 0; i < totalChunks; i++) {
            const chunk = manifest.chunks[i];
            const resp = await fetch(`/s/${token}/files/${fileInfo.resource_id}/content`, {
                headers: { Range: `bytes=${chunk.offset}-${chunk.offset + chunk.size_bytes - 1}` },
                credentials: 'same-origin',
            });

            if (!resp.ok) {
                const body = await resp.json().catch(() => ({}));
                throw new Error(body.detail || `HTTP ${resp.status}`);
            }

            const ciphertext = await resp.arrayBuffer();
            let plaintext;
            try {
                plaintext = await Crypto.decryptChunk(ciphertext, chunk.iv, fileKey);
            } catch {
                throw new Error(
                    `Chunk ${i + 1}/${totalChunks} failed integrity check (offset ${chunk.offset})`
                );
            }

            decryptedChunks.push(plaintext);
            totalBytes += plaintext.byteLength;
            if (onProgress) onProgress(i + 1, totalChunks);
        }

        if (manifest.size_bytes > 0 && totalBytes !== manifest.size_bytes) {
            throw new Error(
                `Size mismatch: expected ${manifest.size_bytes}, got ${totalBytes} bytes`
            );
        }

        const blob = new Blob(decryptedChunks.map(ab => new Uint8Array(ab)));
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = fileInfo.file_name || 'download';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    return {
        openShareDialog,
        openFolderShareDialog,
        openUserShareDialog,
        renderSharesPage,
        renderReceivedSharesPage,
        renderPublicSharePage,
        renderShortLinkPage,
    };
})();
