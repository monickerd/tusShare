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
        return `${globalThis.location.origin}/s/${token}#${shareKeyB64url}`;
    }

    // Short links now redirect at root level: /LimaCharlieTango
    // The key is stored server-side — no fragment needed.
    function _buildShortLinkUrl(slug) {
        return `${globalThis.location.origin}/${slug}`;
    }

    // -----------------------------------------------------------------------
    // Expiry helpers
    // -----------------------------------------------------------------------

    function _defaultExpiryIso() {
        const d = new Date();
        d.setDate(d.getDate() + Config.share.defaultExpiryDays);
        d.setHours(23, 59, 59, 0);
        return d.toISOString().slice(0, 16);  // "YYYY-MM-DDTHH:MM"
    }

    /** Resolve expiry from dialog state. Returns ISO string or null. */
    function _resolveExpiry(preset, dateVal, timeVal) {
        if (preset === '24h') {
            const d = new Date();
            d.setHours(d.getHours() + 24);
            return d.toISOString();
        }
        if (preset === '1w') {
            const d = new Date();
            d.setDate(d.getDate() + 7);
            d.setHours(23, 59, 59, 0);
            return d.toISOString();
        }
        // Custom
        if (!dateVal) return null;
        const time = timeVal || '00:00';
        const d = new Date(`${dateVal}T${time}:00`);
        return Number.isNaN(d.getTime()) ? null : d.toISOString();
    }

    /** Default custom date value: 7 days from today (YYYY-MM-DD). */
    function _defaultCustomDate() {
        const d = new Date();
        d.setDate(d.getDate() + 7);
        return d.toISOString().slice(0, 10);
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
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    // -----------------------------------------------------------------------
    // Share creation dialog (authenticated owner)
    // -----------------------------------------------------------------------

    /**
     * Build the expiry section of the share dialog.
     * Returns { el, getExpiresAt } where getExpiresAt() → ISO string or null.
     */
    function _buildExpirySection() {
        let activePreset = '1w';

        const quickRow = Utils.el('div', { className: 'expiry-quick-pick' });
        const customRow = Utils.el('div', { className: 'expiry-custom-row' });
        customRow.hidden = true;

        const dateInput = Utils.el('input', {
            type: 'date',
            className: 'input input-date',
            value: _defaultCustomDate(),
        });
        const timeInput = Utils.el('input', {
            type: 'time',
            className: 'input input-time',
            value: '00:00',
        });
        customRow.appendChild(dateInput);
        customRow.appendChild(timeInput);

        const presets = [
            { id: '24h', label: '24 h' },
            { id: '1w',  label: '1 week' },
            { id: 'custom', label: 'Custom' },
        ];

        for (const p of presets) {
            const btn = Utils.el('button', {
                type: 'button',
                className: 'expiry-quick-btn' + (p.id === activePreset ? ' active' : ''),
                textContent: p.label,
            });
            btn.addEventListener('click', () => {
                activePreset = p.id;
                quickRow.querySelectorAll('.expiry-quick-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                customRow.hidden = (p.id !== 'custom');
            });
            quickRow.appendChild(btn);
        }

        const wrapper = Utils.el('div', { className: 'share-dialog-section' });
        wrapper.appendChild(Utils.el('span', { className: 'share-dialog-label', textContent: 'Expires' }));
        wrapper.appendChild(quickRow);
        wrapper.appendChild(customRow);

        return {
            el: wrapper,
            getExpiresAt: () => _resolveExpiry(activePreset, dateInput.value, timeInput.value),
        };
    }

    /**
     * Open a modal dialog to create a link share for the given files.
     *
     * @param {Array}       selectedFiles - File objects: { id, original_name, size_bytes, encrypted_file_key, key_iv }
     * @param {object|null} folderCtx     - { id, name } when sharing a whole folder; null for file shares.
     */
    async function openShareDialog(selectedFiles, folderCtx = null) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        const files = selectedFiles.filter(f => f.encrypted_file_key && f.key_iv);
        if (files.length === 0 && !folderCtx) {
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
            if (overlay.parentNode) overlay.remove();
        }

        // --- File / folder list ---
        const fileList = Utils.el('ul', { className: 'share-file-list' });
        if (folderCtx) {
            fileList.appendChild(Utils.el('li', {
                textContent: `📁 ${folderCtx.name} (${files.length} file${files.length === 1 ? '' : 's'})`,
            }));
        } else {
            for (const f of files) {
                fileList.appendChild(Utils.el('li', {
                    textContent: `${f.original_name} (${Utils.formatBytes(f.size_bytes)})`,
                }));
            }
        }

        // --- Expiry section ---
        const expiry = _buildExpirySection();

        // --- Options row (checkboxes left, max downloads right) ---
        const shortLinkChk = Utils.el('input', { type: 'checkbox' });
        const shortLinkRow = Utils.el('label', { className: 'share-dialog-check-row' }, [
            shortLinkChk,
            Utils.el('span', { textContent: 'Generate short link' }),
        ]);

        const checkboxCol = Utils.el('div', { className: 'share-dialog-checkboxes' }, [shortLinkRow]);

        // Allow Upload only for folder shares
        let allowUploadChk = null;
        if (folderCtx) {
            allowUploadChk = Utils.el('input', { type: 'checkbox' });
            const allowUploadRow = Utils.el('label', { className: 'share-dialog-check-row' }, [
                allowUploadChk,
                Utils.el('span', { textContent: 'Allow upload (Download + Upload)' }),
            ]);
            checkboxCol.appendChild(allowUploadRow);
        }

        // Max downloads — small input on the right
        const maxDlInput = Utils.el('input', {
            type: 'number',
            className: 'input input-maxdl',
            placeholder: '∞',
            max: '10000',
            title: 'Max downloads (leave blank for unlimited)',
        });
        // When the spinner reaches 0 (down-arrow from 1), snap back to ∞ (empty)
        maxDlInput.addEventListener('change', () => {
            const v = Number.parseInt(maxDlInput.value, 10);
            if (maxDlInput.value !== '' && (Number.isNaN(v) || v < 1)) {
                maxDlInput.value = '';
            }
        });
        const maxDlCol = Utils.el('div', { className: 'share-dialog-maxdl' }, [
            Utils.el('span', { textContent: 'Max downloads' }),
            maxDlInput,
        ]);

        const optionsRow = Utils.el('div', { className: 'share-dialog-options' }, [checkboxCol, maxDlCol]);

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
            const expiresAt = expiry.getExpiresAt();
            if (!expiresAt) {
                Utils.showToast('Please set an expiry date.', 'error');
                return;
            }

            createBtn.disabled = true;
            createBtn.textContent = 'Creating…';
            _clearEl(statusArea);

            try {
                const shareKeyB64url = await _doCreateShare(files, masterKey, {
                    expiresAt,
                    maxDownloads: maxDlInput.value ? Number.parseInt(maxDlInput.value, 10) : null,
                    generateShortLink: shortLinkChk.checked,
                    allowUpload: allowUploadChk ? allowUploadChk.checked : false,
                    folderId: folderCtx ? folderCtx.id : null,
                }, statusArea);
                if (shareKeyB64url) {
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

        dialog.appendChild(Utils.el('h3', { textContent: folderCtx ? `Share folder` : 'Share files' }));
        dialog.appendChild(fileList);
        dialog.appendChild(expiry.el);
        dialog.appendChild(optionsRow);
        dialog.appendChild(statusArea);
        dialog.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, createBtn]));

        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
    }

    /**
     * Perform the actual share creation: generate shareKey, re-wrap each file
     * key, POST to API, store shareKey in sessionStorage, optionally create short link.
     *
     * @param {Array}  files     - Shareable file objects.
     * @param {object} masterKey - Owner's AES master key.
     * @param {object} opts      - { expiresAt, maxDownloads, generateShortLink, allowUpload, folderId }
     * @param {HTMLElement} statusArea - Element to render result URLs into.
     * Returns the shareKeyB64url on success.
     */
    async function _doCreateShare(files, masterKey, opts, statusArea) {
        const { expiresAt, maxDownloads, generateShortLink, allowUpload, folderId } = opts;

        if (maxDownloads !== null && maxDownloads !== undefined &&
            (Number.isNaN(maxDownloads) || maxDownloads < 1)) {
            throw new Error('Max downloads must be a positive number');
        }

        // Generate a token client-side, then derive the share key from it.
        // This makes the key permanently re-derivable by the owner (masterKey + token)
        // so new files added to the folder can be auto-keyed without storing anything extra.
        const token = Crypto.generateShareToken();
        const shareKey = await Crypto.deriveShareKey(masterKey, token);
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

        // POST to API — client_token tells the server to use our pre-generated token
        // so key_type = 'hkdf-v1' is recorded and the URL is permanently reproducible.
        const resp = await Api.post(`${_prefix()}/shares`, {
            items,
            expires_at: expiresAt,
            max_downloads: maxDownloads || null,
            allow_upload: allowUpload || false,
            target_folder_id: folderId || null,
            client_token: token,
        });

        // Persist shareKey for the session so the owner can copy the URL later
        _storeShareKey(resp.share_id, shareKeyB64url);

        // Build and display the full share URL
        const shareUrl = _buildShareUrl(resp.token, shareKeyB64url);
        _renderShareUrlBox(statusArea, shareUrl);

        // Optionally create a short link (key stored server-side for root-level redirect)
        if (generateShortLink && expiresAt) {
            try {
                const slResp = await Api.post(`${_prefix()}/shares/${resp.share_id}/short-link`, {
                    expires_at: expiresAt,
                    share_key: shareKeyB64url,
                });
                const slUrl = _buildShortLinkUrl(slResp.slug);
                _renderShareUrlBox(statusArea, slUrl, 'Short link');
            } catch (slErr) {
                statusArea.appendChild(Utils.el('p', {
                    className: 'share-error',
                    textContent: `Short link failed: ${slErr.message}`,
                }));
            }
        }

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
            const masterKey = Auth.getMasterKeyObj();
            const data = await Api.get(`${_prefix()}/shares`);
            _renderSharesList(listEl, data.shares, masterKey);
        } catch (err) {
            listEl.textContent = `Failed to load shares: ${err.message}`;
        }
    }

    function _renderSharesList(container, shares, masterKey) {
        _clearEl(container);

        if (shares.length === 0) {
            container.appendChild(Utils.el('p', {
                className: 'text-muted',
                textContent: 'No shares yet. Select files and choose "Share" to create one.',
            }));
            return;
        }

        for (const share of shares) {
            container.appendChild(_createShareCard(share, masterKey));
        }
    }

    /**
     * Build and show the unified share detail modal.
     *
     * @param {object}      share      - Share object (from list_shares or GET /shares/{id})
     * @param {object|null} masterKey  - Owner's CryptoKey for HKDF URL derivation; null for recipients
     * @param {boolean}     [canManage=true] - Show management actions (delete, remove files, expiry)
     * @param {HTMLElement} [cardEl]   - Optional card element to remove when share is deleted
     */
    async function openSingleShareDetailModal(share, masterKey, canManage = true, cardEl) {
        const overlay = Utils.el('div', { className: 'modal-overlay' });
        overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

        const dialog = Utils.el('div', { className: 'modal share-detail-modal' });

        // Title: best available folder name as a link, or file count
        const fileCount = (share.items || []).length;
        const displayFolderId = share.target_folder_id || share.items?.[0]?.folder_id;
        const displayFolderName = share.folder_name || share.items?.[0]?.folder_name;

        let titleEl;
        if (displayFolderId && displayFolderName) {
            titleEl = Utils.el('h3', {}, [
                Utils.el('a', {
                    href: `#/files/${displayFolderId}`,
                    textContent: displayFolderName,
                    className: 'folder-link',
                    onClick: () => overlay.remove(),
                }),
            ]);
        } else {
            titleEl = Utils.el('h3', { textContent: `${fileCount} file${fileCount === 1 ? '' : 's'}` });
        }
        dialog.appendChild(titleEl);

        // Meta: created, expiry, downloads
        const metaEl = Utils.el('p', { className: 'share-entry-meta text-muted' });
        const parts = [];
        if (share.creator_username) parts.push(`Shared by ${share.creator_username}`);
        parts.push(`Created ${Utils.formatDate(share.created_at)}`);
        if (share.expires_at) {
            const expired = new Date(share.expires_at) < new Date();
            parts.push(expired ? 'Expired' : `Expires ${Utils.formatDate(share.expires_at)}`);
        } else {
            parts.push('No expiry');
        }
        if (share.max_downloads) parts.push(`${share.download_count}/${share.max_downloads} downloads`);
        metaEl.textContent = parts.join(' · ');
        dialog.appendChild(metaEl);

        // URL row (link shares only)
        if (share.share_type !== 'user') {
            const urlRow = Utils.el('div', { className: 'share-entry-url-row', style: 'margin-bottom:8px' });
            const storedKey = _loadShareKey(share.id);
            const keyB64 = storedKey || (share.key_type === 'hkdf-v1' && masterKey
                ? await Crypto.deriveShareKey(masterKey, share.token).then(k => Crypto.exportKeyToBase64url(k)).catch(() => null)
                : null);
            if (keyB64) {
                _appendUrlCopyPair(urlRow, _buildShareUrl(share.token, keyB64), 'Link copied');
            } else {
                urlRow.appendChild(Utils.el('span', { className: 'text-muted', textContent: 'Share URL not available — key is tied to the original session.' }));
            }
            dialog.appendChild(urlRow);

            // Short links
            for (const sl of (share.short_links || [])) {
                const slRow = Utils.el('div', { className: 'share-entry-shortlink-row', style: 'margin-bottom:8px' });
                _appendUrlCopyPair(slRow, _buildShortLinkUrl(sl.slug), 'Short link copied');
                dialog.appendChild(slRow);
            }

            // Management: add short link
            if (canManage && share.is_active && keyB64) {
                const addSlBtn = Utils.el('button', {
                    className: 'btn btn-secondary btn-sm',
                    textContent: 'Add short link',
                    onClick: () => _promptCreateShortLink(share, keyB64, dialog),
                });
                dialog.appendChild(addSlBtn);
            }
        }

        // File list section — remove allowed for anyone who can manage
        const fileSection = _buildShareFileListSection(share.items || [], share.id, canManage, (removedId) => {
            share.items = (share.items || []).filter(it => it.resource_id !== removedId);
            if (!share.target_folder_id && !displayFolderId) {
                titleEl.textContent = `${share.items.length} file${share.items.length === 1 ? '' : 's'}`;
            }
        });
        dialog.appendChild(fileSection);

        // Management action buttons
        if (canManage) {
            const actionsRow = Utils.el('div', { className: 'share-entry-actions', style: 'margin-top:12px' });

            const updateExpiryBtn = Utils.el('button', {
                className: 'btn btn-secondary btn-sm',
                textContent: 'Update expiry…',
                onClick: () => _openUpdateExpiryDialog({ share_id: share.id, expires_at: share.expires_at }, dialog, overlay),
            });
            actionsRow.appendChild(updateExpiryBtn);

            const deleteBtn = Utils.el('button', {
                className: 'btn btn-danger btn-sm',
                textContent: 'Delete share',
                onClick: async () => {
                    if (!await Utils.showConfirm('Delete this share? Recipients will lose access immediately.')) return;
                    try {
                        await Api.del(`${_prefix()}/shares/${share.id}`);
                        _removeShareKey(share.id);
                        overlay.remove();
                        if (cardEl) cardEl.remove();
                        document.dispatchEvent(new CustomEvent('folder-shares-changed'));
                        Utils.showToast('Share deleted', 'success');
                    } catch (err) {
                        Utils.showToast(`Delete failed: ${err.message}`, 'error');
                    }
                },
            });
            actionsRow.appendChild(deleteBtn);

            dialog.appendChild(actionsRow);
        }

        const closeBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Close',
            onClick: () => overlay.remove(),
        });
        dialog.appendChild(Utils.el('div', { className: 'modal-actions', style: 'margin-top:8px' }, [closeBtn]));

        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
    }

    /**
     * Build a scrollable file list section grouped by folder, with optional remove buttons.
     *
     * @param {Array}    items      - File items with file_name, size_bytes, folder_id, folder_name, resource_id
     * @param {string}   shareId    - Share ID (for remove calls)
     * @param {boolean}  canRemove  - Show Remove button per file
     * @param {Function} onRemove   - Called with resource_id after successful removal
     */
    function _buildShareFileListSection(items, shareId, canRemove, onRemove) {
        const section = Utils.el('div', { className: 'share-file-section' });

        if (!items.length) {
            section.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No files in this share.' }));
            return section;
        }

        // Filter bar
        const filterInput = Utils.el('input', {
            type: 'text',
            className: 'input-sm',
            placeholder: 'Filter files…',
            style: 'width:100%;margin-bottom:8px',
        });
        section.appendChild(filterInput);

        // Group files by folder
        const byFolder = new Map();
        for (const item of items) {
            const key  = item.folder_id  || '__root__';
            const name = item.folder_name || '(root)';
            if (!byFolder.has(key)) byFolder.set(key, { name, files: [] });
            byFolder.get(key).files.push(item);
        }

        const listWrap = Utils.el('div', { className: 'share-file-list-wrap', style: 'max-height:300px;overflow-y:auto' });

        for (const [, { name: folderName, files }] of byFolder) {
            const groupEl = Utils.el('div', { className: 'share-file-group' });

            // Folder header (collapsible) with optional "Remove Folder" button
            const folderHeader = Utils.el('div', {
                className: 'share-file-folder-header',
                style: 'cursor:pointer;display:flex;align-items:center;gap:6px;padding:4px 0;font-weight:600',
            });
            const arrow = Utils.el('span', { textContent: '▼', style: 'font-size:10px' });
            folderHeader.appendChild(arrow);
            folderHeader.appendChild(Utils.el('span', { textContent: `📁 ${folderName} (${files.length})`, style: 'flex:1' }));
            if (canRemove) {
                const folderId = files[0]?.folder_id;
                const removeFolderBtn = Utils.el('button', {
                    className: 'btn btn-danger btn-xs',
                    textContent: 'Remove Folder',
                });
                removeFolderBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    if (!await Utils.showConfirm(`Remove all files in "${folderName}" from this share?`)) return;
                    try {
                        if (folderId) {
                            await Api.del(`${_prefix()}/shares/${shareId}/folder-items/${folderId}`);
                        } else {
                            for (const item of files) {
                                await Api.del(`${_prefix()}/shares/${shareId}/items/${item.resource_id}`);
                            }
                        }
                        groupEl.remove();
                        if (onRemove) files.forEach(f => onRemove(f.resource_id));
                        Utils.showToast(`Folder "${folderName}" removed from share`, 'success');
                    } catch (err) {
                        Utils.showToast(`Remove failed: ${err.message}`, 'error');
                    }
                });
                folderHeader.appendChild(removeFolderBtn);
            }
            groupEl.appendChild(folderHeader);

            const fileList = Utils.el('ul', { className: 'share-file-sublist', style: 'list-style:none;padding:0 0 0 18px;margin:0' });
            for (const item of files) {
                if (!item.file_name) continue;
                const li = Utils.el('li', {
                    className: 'share-file-item',
                    style: 'display:flex;align-items:center;gap:6px;padding:3px 0',
                    dataset: { name: item.file_name.toLowerCase() },
                });
                li.appendChild(Utils.el('span', {
                    textContent: `${item.file_name} (${Utils.formatBytes(item.size_bytes)})`,
                    style: 'flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap',
                }));
                if (canRemove) {
                    const removeBtn = Utils.el('button', {
                        className: 'btn btn-danger btn-xs',
                        textContent: 'Remove',
                    });
                    removeBtn.addEventListener('click', async () => {
                        if (!await Utils.showConfirm(`Remove "${item.file_name}" from this share?`)) return;
                        try {
                            await Api.del(`${_prefix()}/shares/${shareId}/items/${item.resource_id}`);
                            li.remove();
                            Utils.showToast(`"${item.file_name}" removed from share`, 'success');
                            if (onRemove) onRemove(item.resource_id);
                        } catch (err) {
                            Utils.showToast(`Remove failed: ${err.message}`, 'error');
                        }
                    });
                    li.appendChild(removeBtn);
                }
                fileList.appendChild(li);
            }
            groupEl.appendChild(fileList);

            // Collapse toggle
            folderHeader.addEventListener('click', () => {
                const collapsed = fileList.style.display === 'none';
                fileList.style.display = collapsed ? '' : 'none';
                arrow.textContent = collapsed ? '▼' : '▶';
            });

            listWrap.appendChild(groupEl);
        }

        section.appendChild(listWrap);

        // Filter wires to all file item rows
        filterInput.addEventListener('input', () => {
            const term = filterInput.value.toLowerCase();
            for (const li of listWrap.querySelectorAll('.share-file-item')) {
                const name = li.dataset.name || '';
                li.style.display = !term || name.includes(term) ? '' : 'none';
            }
        });

        return section;
    }

    function _createShareCard(share, masterKey) {
        const card = Utils.el('div', {
            className: 'share-card' + (share.is_active ? '' : ' share-inactive'),
        });

        // Header: best available folder name as link, or file count
        const fileCount = (share.items || []).length;
        const displayFolderId = share.target_folder_id || share.items?.[0]?.folder_id;
        const displayFolderName = share.folder_name || share.items?.[0]?.folder_name;
        const header = Utils.el('div', { className: 'share-card-header' });

        let titleEl;
        if (displayFolderId && displayFolderName) {
            titleEl = Utils.el('a', {
                href: `#/files/${displayFolderId}`,
                className: 'share-card-title folder-link',
                textContent: displayFolderName,
            });
        } else {
            titleEl = Utils.el('span', { className: 'share-card-title', textContent: 'Shared Files' });
        }
        header.appendChild(titleEl);

        // File count as clickable link
        const fileCountBtn = Utils.el('button', {
            className: 'btn-link share-card-file-count',
            textContent: `${fileCount} file${fileCount === 1 ? '' : 's'}`,
            onClick: () => openSingleShareDetailModal(share, masterKey, true, card),
        });
        header.appendChild(fileCountBtn);

        // Badges
        if (!share.is_active) {
            header.appendChild(Utils.el('span', { className: 'badge badge-muted', textContent: 'Inactive' }));
        }
        if (share.expires_at) {
            const expired = new Date(share.expires_at) < new Date();
            header.appendChild(Utils.el('span', {
                className: 'badge ' + (expired ? 'badge-danger' : 'badge-info'),
                textContent: expired ? 'Expired' : `Expires ${Utils.formatDate(share.expires_at)}`,
            }));
        }
        if (share.max_downloads) {
            header.appendChild(Utils.el('span', {
                className: 'badge badge-info',
                textContent: `${share.download_count}/${share.max_downloads} downloads`,
            }));
        }
        if (share.allow_upload) {
            header.appendChild(Utils.el('span', { className: 'badge badge-upload', textContent: 'Upload enabled' }));
        }
        card.appendChild(header);

        // Share URL — derive inline for HKDF shares, use stored key otherwise
        const urlBox = Utils.el('div', { className: 'share-url-box' });
        card.appendChild(urlBox);
        const shareKeyB64url = _loadShareKey(share.id);
        if (shareKeyB64url) {
            _renderShareUrlBox(urlBox, _buildShareUrl(share.token, shareKeyB64url));
        } else if (share.key_type === 'hkdf-v1' && masterKey) {
            Crypto.deriveShareKey(masterKey, share.token)
                .then(k => Crypto.exportKeyToBase64url(k))
                .then(keyB64 => _renderShareUrlBox(urlBox, _buildShareUrl(share.token, keyB64)))
                .catch(() => { urlBox.remove(); });
        } else {
            urlBox.remove();
            card.appendChild(Utils.el('p', {
                className: 'text-muted share-key-gone',
                textContent: 'Share URL not available — key is only accessible during the session it was created.',
            }));
        }

        // Short links
        for (const sl of (share.short_links || [])) {
            const slBox = Utils.el('div', { className: 'share-url-box' });
            _renderShareUrlBox(slBox, _buildShortLinkUrl(sl.slug), sl.slug);
            card.appendChild(slBox);
        }

        // Action buttons
        const actions = Utils.el('div', { className: 'share-card-actions' });

        const detailsBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'More Details…',
            onClick: () => openSingleShareDetailModal(share, masterKey, true, card),
        });
        actions.appendChild(detailsBtn);

        const deleteBtn = Utils.el('button', {
            className: 'btn btn-danger btn-sm',
            textContent: 'Delete',
            onClick: async () => {
                if (!await Utils.showConfirm('Delete this share? Recipients will lose access immediately.')) return;
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
        if (Number.isNaN(d.getTime()) || d <= new Date()) {
            Utils.showToast('Invalid or past expiry date', 'error');
            return;
        }

        try {
            const resp = await Api.post(`${_prefix()}/shares/${share.id}/short-link`, {
                expires_at: d.toISOString(),
                share_key: shareKeyB64url,
            });
            // Key stored server-side — URL has no fragment
            const slUrl = _buildShortLinkUrl(resp.slug);
            Utils.showToast(`Short link created: ${resp.slug}`, 'success');

            const urlBox = Utils.el('div', { className: 'share-url-box' });
            _renderShareUrlBox(urlBox, slUrl, resp.slug);
            const actionsEl = card.querySelector('.share-card-actions');
            if (actionsEl) actionsEl.before(urlBox);
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
        } else {
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

        // Upload section — shown when the share owner enabled upload
        if (shareData.allow_upload && shareData.share_id) {
            page.appendChild(_buildPublicUploadSection(
                shareData.share_id, shareKey, shareSessionToken
            ));
        }
    }

    /**
     * Build the upload drop-area shown on upload-enabled public share pages.
     *
     * Files are encrypted client-side with the share key before sending, so
     * the server only ever sees ciphertext. The share key comes from the URL
     * fragment (passed in as a CryptoKey object).
     */
    function _buildPublicUploadSection(shareId, shareKey, sessionToken) {
        const section = Utils.el('div', { className: 'share-upload-section' });
        section.appendChild(Utils.el('h3', { textContent: 'Upload files' }));
        section.appendChild(Utils.el('p', {
            className: 'text-muted',
            textContent: 'Files are encrypted in your browser before upload.',
        }));

        const fileInput = Utils.el('input', {
            type: 'file',
            className: 'share-upload-input',
            multiple: '',
        });

        const uploadBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Choose files & upload',
        });
        uploadBtn.addEventListener('click', () => fileInput.click());

        const resultEl = Utils.el('div', { className: 'share-upload-results' });

        fileInput.addEventListener('change', async () => {
            const chosen = Array.from(fileInput.files || []);
            if (chosen.length === 0) return;

            uploadBtn.disabled = true;
            _clearEl(resultEl);

            for (const file of chosen) {
                const row = Utils.el('p', { textContent: `Uploading ${file.name}…` });
                resultEl.appendChild(row);
                try {
                    await _encryptAndUploadToShare(shareId, shareKey, sessionToken, file);
                    row.textContent = `✓ ${file.name} uploaded`;
                    row.className = 'share-upload-ok';
                } catch (err) {
                    row.textContent = `✗ ${file.name}: ${err.message}`;
                    row.className = 'share-error';
                }
            }

            uploadBtn.disabled = false;
            fileInput.value = '';
        });

        section.appendChild(uploadBtn);
        section.appendChild(fileInput);
        section.appendChild(resultEl);
        return section;
    }

    async function _encryptAndUploadToShare(shareId, shareKey, sessionToken, file) {
        const plaintext = new Uint8Array(await file.arrayBuffer());

        // Generate a fresh per-file key, encrypt, then wrap the key with shareKey
        const fileKey = await Crypto.generateFileKey();
        const { ciphertext, ivB64: chunkIv } = await Crypto.encryptChunk(plaintext, fileKey);
        const { wrappedKeyB64, ivB64: keyIv } = await Crypto.wrapFileKeyForShare(fileKey, shareKey);

        const form = new FormData();
        form.append('file_name', file.name);
        form.append('encrypted_file_key', wrappedKeyB64);
        form.append('key_iv', keyIv);
        form.append('chunk_iv', chunkIv);
        form.append('size_bytes', String(plaintext.byteLength));
        form.append('file', new Blob([ciphertext]), file.name);

        const headers = {};
        if (sessionToken) headers['Authorization'] = `Bearer ${sessionToken}`;

        const resp = await fetch(`/s/${shareId}/upload`, {
            method: 'POST',
            credentials: 'same-origin',
            headers,
            body: form,
        });
        if (!resp.ok) {
            const body = await resp.json().catch(() => ({}));
            throw new Error(body.detail || `HTTP ${resp.status}`);
        }
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

        // Invite short links redirect straight to the registration page
        if (shareData.type === 'invite') {
            globalThis.location.replace(`/register/${shareData.token}`);
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
        while (el.firstChild) el.firstChild.remove();
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
     * Share a folder: enumerate its files then open the share dialog with
     * folder context (exposes the Allow Upload toggle).
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

        if (files.length >= Config.share.maxItems) {
            Utils.showToast(
                `Folder contains ${Config.share.maxItems}+ files. Only the first ${Config.share.maxItems} will be shared.`,
                'warning'
            );
        }

        openShareDialog(files, { id: folder.id, name: folder.name });
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
            if (overlay.parentNode) overlay.remove();
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
            if (err.message?.includes('404')) {
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
            if (Number.isNaN(d.getTime())) throw new Error('Invalid expiry date');
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

        // Header: folder name link (from first item's folder) or file count
        const items = share.items || [];
        const fileCount = items.length;
        const displayFolderId = share.target_folder_id || items[0]?.folder_id;
        const displayFolderName = share.folder_name || items[0]?.folder_name;
        const header = Utils.el('div', { className: 'share-card-header' });

        let titleEl;
        if (displayFolderId && displayFolderName) {
            titleEl = Utils.el('a', {
                href: `#/files/${displayFolderId}`,
                className: 'share-card-title folder-link',
                textContent: displayFolderName,
            });
        } else {
            titleEl = Utils.el('span', { className: 'share-card-title', textContent: 'Shared Files' });
        }
        header.appendChild(titleEl);

        // File count button opens detail modal
        const fileCountBtn = Utils.el('button', {
            className: 'btn-link share-card-file-count',
            textContent: `${fileCount} file${fileCount === 1 ? '' : 's'}`,
            onClick: () => _openReceivedShareModal(share),
        });
        header.appendChild(fileCountBtn);

        // Sender + expiry badges
        if (share.sender_username) {
            header.appendChild(Utils.el('span', { className: 'badge badge-muted', textContent: `from ${share.sender_username}` }));
        }
        if (share.expires_at) {
            const expired = new Date(share.expires_at) < new Date();
            header.appendChild(Utils.el('span', {
                className: 'badge ' + (expired ? 'badge-danger' : 'badge-info'),
                textContent: expired ? 'Expired' : `Expires ${Utils.formatDate(share.expires_at)}`,
            }));
        }
        card.appendChild(header);

        // Action buttons
        const actions = Utils.el('div', { className: 'share-card-actions' });
        actions.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'More Details…',
            onClick: () => _openReceivedShareModal(share),
        }));
        card.appendChild(actions);

        return card;
    }

    function _openReceivedShareModal(share) {
        const overlay = Utils.el('div', { className: 'modal-overlay' });
        overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

        const dialog = Utils.el('div', { className: 'modal share-detail-modal' });

        // Title
        const items = share.items || [];
        const displayFolderId = share.target_folder_id || items[0]?.folder_id;
        const displayFolderName = share.folder_name || items[0]?.folder_name;
        if (displayFolderId && displayFolderName) {
            dialog.appendChild(Utils.el('h3', {}, [
                Utils.el('a', {
                    href: `#/files/${displayFolderId}`,
                    textContent: displayFolderName,
                    className: 'folder-link',
                    onClick: () => overlay.remove(),
                }),
            ]));
        } else {
            dialog.appendChild(Utils.el('h3', { textContent: `${items.length} shared file${items.length === 1 ? '' : 's'}` }));
        }

        // Meta
        const parts = [];
        if (share.sender_username) parts.push(`From ${share.sender_username}`);
        parts.push(`Created ${Utils.formatDate(share.created_at)}`);
        if (share.expires_at) {
            const expired = new Date(share.expires_at) < new Date();
            parts.push(expired ? 'Expired' : `Expires ${Utils.formatDate(share.expires_at)}`);
        } else {
            parts.push('No expiry');
        }
        dialog.appendChild(Utils.el('p', { className: 'share-entry-meta text-muted', textContent: parts.join(' · ') }));

        // File list with download buttons (read-only, no remove)
        const section = Utils.el('div', { className: 'share-file-section' });
        const listWrap = Utils.el('div', { className: 'share-file-list-wrap', style: 'max-height:300px;overflow-y:auto' });

        const byFolder = new Map();
        for (const item of items) {
            const key  = item.folder_id  || '__root__';
            const name = item.folder_name || '(root)';
            if (!byFolder.has(key)) byFolder.set(key, { name, files: [] });
            byFolder.get(key).files.push(item);
        }

        for (const [, { name: folderName, files }] of byFolder) {
            const groupEl = Utils.el('div', { className: 'share-file-group' });
            const arrow = Utils.el('span', { textContent: '▼', style: 'font-size:10px' });
            const folderHeader = Utils.el('div', {
                className: 'share-file-folder-header',
                style: 'cursor:pointer;display:flex;align-items:center;gap:6px;padding:4px 0;font-weight:600',
            }, [arrow, Utils.el('span', { textContent: `📁 ${folderName} (${files.length})` })]);
            groupEl.appendChild(folderHeader);

            const fileList = Utils.el('ul', { className: 'share-file-sublist', style: 'list-style:none;padding:0 0 0 18px;margin:0' });
            for (const item of files) {
                if (!item.file_name) continue;
                const li = Utils.el('li', {
                    style: 'display:flex;align-items:center;gap:6px;padding:3px 0',
                });
                li.appendChild(Utils.el('span', {
                    textContent: `${item.file_name} (${Utils.formatBytes(item.size_bytes)})`,
                    style: 'flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap',
                }));
                const dlBtn = Utils.el('button', { className: 'btn btn-primary btn-xs', textContent: 'Download' });
                dlBtn.addEventListener('click', () => _handleUserShareDownload(dlBtn, share, item));
                li.appendChild(dlBtn);
                fileList.appendChild(li);
            }
            groupEl.appendChild(fileList);
            folderHeader.addEventListener('click', () => {
                const collapsed = fileList.style.display === 'none';
                fileList.style.display = collapsed ? '' : 'none';
                arrow.textContent = collapsed ? '▼' : '▶';
            });
            listWrap.appendChild(groupEl);
        }
        section.appendChild(listWrap);
        dialog.appendChild(section);

        const closeBtn = Utils.el('button', { className: 'btn btn-secondary', textContent: 'Close', onClick: () => overlay.remove() });
        dialog.appendChild(Utils.el('div', { className: 'modal-actions', style: 'margin-top:8px' }, [closeBtn]));
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
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
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    // -----------------------------------------------------------------------
    // Embeddable content builders — used by the combined share dialog in
    // files.js so both tabs live inside one modal overlay.
    // Each function returns { contentEl, actionBtn } with no overlay of their own.
    // -----------------------------------------------------------------------

    function buildLinkShareContent(files, masterKey, folderCtx, onSuccess) {
        const fileList = Utils.el('ul', { className: 'share-file-list' });
        if (folderCtx) {
            fileList.appendChild(Utils.el('li', {
                textContent: `📁 ${folderCtx.name} (${files.length} file${files.length === 1 ? '' : 's'})`,
            }));
        } else {
            for (const f of files) {
                fileList.appendChild(Utils.el('li', {
                    textContent: `${f.original_name} (${Utils.formatBytes(f.size_bytes)})`,
                }));
            }
        }

        const expiry = _buildExpirySection();

        const shortLinkChk = Utils.el('input', { type: 'checkbox' });
        const checkboxCol  = Utils.el('div', { className: 'share-dialog-checkboxes' }, [
            Utils.el('label', { className: 'share-dialog-check-row' }, [shortLinkChk, Utils.el('span', { textContent: 'Generate short link' })]),
        ]);

        let allowUploadChk = null;
        if (folderCtx) {
            allowUploadChk = Utils.el('input', { type: 'checkbox' });
            checkboxCol.appendChild(Utils.el('label', { className: 'share-dialog-check-row' }, [
                allowUploadChk, Utils.el('span', { textContent: 'Allow upload (Download + Upload)' }),
            ]));
        }

        const maxDlInput = Utils.el('input', {
            type: 'number', className: 'input input-maxdl',
            placeholder: '∞', max: '10000',
            title: 'Max downloads (leave blank for unlimited)',
        });
        maxDlInput.addEventListener('change', () => {
            const v = Number.parseInt(maxDlInput.value, 10);
            if (maxDlInput.value !== '' && (Number.isNaN(v) || v < 1)) maxDlInput.value = '';
        });

        const statusArea = Utils.el('div', { className: 'share-status' });

        const actionBtn = Utils.el('button', { className: 'btn btn-primary', textContent: 'Create link' });
        actionBtn.addEventListener('click', async () => {
            const expiresAt = expiry.getExpiresAt();
            if (!expiresAt) { Utils.showToast('Please set an expiry date.', 'error'); return; }
            actionBtn.disabled = true;
            actionBtn.textContent = 'Creating…';
            _clearEl(statusArea);
            try {
                const key = await _doCreateShare(files, masterKey, {
                    expiresAt,
                    maxDownloads: maxDlInput.value ? Number.parseInt(maxDlInput.value, 10) : null,
                    generateShortLink: shortLinkChk.checked,
                    allowUpload: allowUploadChk ? allowUploadChk.checked : false,
                    folderId: folderCtx ? folderCtx.id : null,
                }, statusArea);
                if (key) { actionBtn.style.display = 'none'; if (onSuccess) onSuccess(); }
            } catch (err) {
                statusArea.appendChild(Utils.el('p', { className: 'share-error', textContent: `Failed: ${err.message}` }));
                actionBtn.disabled = false;
                actionBtn.textContent = 'Create link';
            }
        });

        const contentEl = Utils.el('div', {}, [
            fileList,
            expiry.el,
            Utils.el('div', { className: 'share-dialog-options' }, [
                checkboxCol,
                Utils.el('div', { className: 'share-dialog-maxdl' }, [Utils.el('span', { textContent: 'Max downloads' }), maxDlInput]),
            ]),
            statusArea,
        ]);
        return { contentEl, actionBtn };
    }

    function buildUserShareContent(files, masterKey, onSuccess) {
        const fileList = Utils.el('ul', { className: 'share-file-list' });
        for (const f of files) {
            fileList.appendChild(Utils.el('li', {
                textContent: `${f.original_name} (${Utils.formatBytes(f.size_bytes)})`,
            }));
        }

        const recipientInput = Utils.el('input', {
            type: 'text', className: 'input',
            placeholder: 'Username', autocomplete: 'off',
        });
        const expiryInput = Utils.el('input', {
            type: 'datetime-local', className: 'input', value: _defaultExpiryIso(),
        });
        const statusArea = Utils.el('div', { className: 'share-status' });

        const actionBtn = Utils.el('button', { className: 'btn btn-primary', textContent: 'Send' });
        actionBtn.addEventListener('click', async () => {
            const username = recipientInput.value.trim();
            if (!username) { Utils.showToast('Enter a username', 'error'); return; }
            actionBtn.disabled = true;
            actionBtn.textContent = 'Sending…';
            _clearEl(statusArea);
            try {
                await _doCreateUserShare(files, masterKey, username, expiryInput.value, statusArea);
                actionBtn.style.display = 'none';
                if (onSuccess) onSuccess();
            } catch (err) {
                statusArea.appendChild(Utils.el('p', { className: 'share-error', textContent: `Failed: ${err.message}` }));
                actionBtn.disabled = false;
                actionBtn.textContent = 'Send';
            }
        });

        const contentEl = Utils.el('div', {}, [
            fileList,
            Utils.el('label', {}, [Utils.el('span', { textContent: 'Recipient username' }), recipientInput]),
            Utils.el('label', {}, [Utils.el('span', { textContent: 'Expires at' }), expiryInput]),
            statusArea,
        ]);
        return { contentEl, actionBtn };
    }

    // -----------------------------------------------------------------------
    // Folder share banner modal
    // -----------------------------------------------------------------------

    /** Append a read-only URL input and a Copy button to container. */
    function _appendUrlCopyPair(container, url, toastMsg) {
        const input = Utils.el('input', { type: 'text', readOnly: true, value: url, className: 'share-url-input' });
        const btn = Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Copy' });
        btn.addEventListener('click', () =>
            navigator.clipboard.writeText(url).then(() => Utils.showToast(toastMsg, 'success'))
        );
        container.appendChild(input);
        container.appendChild(btn);
    }

    /** Build the URL row element for one share entry. */
    async function _buildShareUrlRow(s, masterKey) {
        const row = Utils.el('div', { className: 'share-entry-url-row' });
        if (s.key_type === 'hkdf-v1' && masterKey) {
            try {
                const shareKey = await Crypto.deriveShareKey(masterKey, s.token);
                const shareKeyB64url = await Crypto.exportKeyToBase64url(shareKey);
                _appendUrlCopyPair(row, _buildShareUrl(s.token, shareKeyB64url), 'Link copied');
            } catch {
                row.appendChild(Utils.el('span', { className: 'text-muted', textContent: 'Could not derive share URL.' }));
            }
        } else {
            const storedKey = _loadShareKey(s.share_id);
            if (storedKey) {
                _appendUrlCopyPair(row, _buildShareUrl(s.token, storedKey), 'Link copied');
            } else {
                row.appendChild(Utils.el('span', {
                    className: 'text-muted',
                    textContent: 'Share URL only available in the original session. Re-create to get a persistent link.',
                }));
            }
        }
        return row;
    }

    /**
     * Build and show the "This folder is being shared" detail modal.
     *
     * @param {Array}  shares    - Array from GET /api/v1/folders/{id}/shares
     * @param {object} masterKey - Owner's CryptoKey, used to re-derive share URLs
     */
    async function openFolderShareDetailModal(shares, masterKey) {
        const overlay = Utils.el('div', { className: 'modal-overlay' });
        overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

        const dialog = Utils.el('div', { className: 'modal share-detail-modal' });
        dialog.appendChild(Utils.el('h3', { textContent: 'Folder shares' }));

        const listEl = Utils.el('div', { className: 'folder-share-list' });

        for (let i = 0; i < shares.length; i++) {
            const s = shares[i];
            if (i > 0) listEl.appendChild(Utils.el('hr', { className: 'share-entry-divider' }));

            const entry = Utils.el('div', { className: 'share-entry' });

            entry.appendChild(await _buildShareUrlRow(s, masterKey));

            // --- Short link row ---
            if (s.short_link_slug) {
                const slRow = Utils.el('div', { className: 'share-entry-shortlink-row' });
                _appendUrlCopyPair(slRow, _buildShortLinkUrl(s.short_link_slug), 'Short link copied');
                entry.appendChild(slRow);
            }

            // --- Meta line: created by, when, expiry ---
            const expText = s.expires_at
                ? `Expires ${Utils.formatDate(s.expires_at)}`
                : 'No expiry';
            entry.appendChild(Utils.el('p', {
                className: 'share-entry-meta text-muted',
                textContent: `Created by ${s.creator_username} · ${Utils.formatDate(s.created_at)} · ${expText}`,
            }));

            // --- Action buttons (only if can_manage) ---
            if (s.can_manage) {
                const actionsRow = Utils.el('div', { className: 'share-entry-actions' });

                // Update expiry button
                const updateBtn = Utils.el('button', {
                    className: 'btn btn-secondary btn-sm',
                    textContent: 'Update expiry…',
                });
                updateBtn.addEventListener('click', () =>
                    _openUpdateExpiryDialog(s, entry, overlay)
                );

                // Delete button
                const deleteBtn = Utils.el('button', {
                    className: 'btn btn-danger btn-sm',
                    textContent: 'Delete',
                });
                deleteBtn.addEventListener('click', async () => {
                    if (!confirm('Delete this share link? Recipients will lose access immediately.')) return;
                    try {
                        await Api.del(`${_prefix()}/shares/${s.share_id}`);
                        Utils.showToast('Share deleted', 'success');
                        overlay.remove();
                        // Re-render banner (files.js listens for this event)
                        document.dispatchEvent(new CustomEvent('folder-shares-changed'));
                    } catch (err) {
                        Utils.showToast(err.message, 'error');
                    }
                });

                actionsRow.appendChild(updateBtn);
                actionsRow.appendChild(deleteBtn);
                entry.appendChild(actionsRow);
            }

            listEl.appendChild(entry);
        }

        const closeBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Close',
        });
        closeBtn.addEventListener('click', () => overlay.remove());

        dialog.appendChild(listEl);
        dialog.appendChild(Utils.el('div', { className: 'modal-actions' }, [closeBtn]));
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
    }

    function _openUpdateExpiryDialog(share, entryEl, parentOverlay) {
        const overlay = Utils.el('div', { className: 'modal-overlay' });
        overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

        const dialog = Utils.el('div', { className: 'modal' });
        dialog.appendChild(Utils.el('h3', { textContent: 'Update expiry' }));

        const { el: pickerEl, getExpiresAt } = _buildExpiryPicker(share.expires_at);
        dialog.appendChild(pickerEl);

        const statusEl = Utils.el('p', { className: 'text-muted' });
        dialog.appendChild(statusEl);

        const saveBtn = Utils.el('button', { className: 'btn btn-primary', textContent: 'Save' });
        const cancelBtn = Utils.el('button', { className: 'btn btn-secondary', textContent: 'Cancel' });
        cancelBtn.addEventListener('click', () => overlay.remove());

        saveBtn.addEventListener('click', async () => {
            const expiresAt = getExpiresAt();
            const now = new Date();
            const isPast = expiresAt && new Date(expiresAt) <= now;

            if (isPast) {
                statusEl.textContent = '';
                const warnP = Utils.el('p', {
                    className: 'share-error',
                    textContent: 'That date is already in the past — the share would be immediately expired.',
                });
                const deleteInsteadBtn = Utils.el('button', {
                    className: 'btn btn-danger btn-sm',
                    textContent: 'Delete share instead',
                });
                deleteInsteadBtn.addEventListener('click', async () => {
                    try {
                        await Api.del(`${_prefix()}/shares/${share.share_id}`);
                        Utils.showToast('Share deleted', 'success');
                        overlay.remove();
                        parentOverlay.remove();
                        document.dispatchEvent(new CustomEvent('folder-shares-changed'));
                    } catch (err) {
                        Utils.showToast(err.message, 'error');
                    }
                });
                statusEl.appendChild(warnP);
                statusEl.appendChild(deleteInsteadBtn);
                return;
            }

            saveBtn.disabled = true;
            try {
                await Api.put(`${_prefix()}/shares/${share.share_id}`, { expires_at: expiresAt });
                Utils.showToast('Expiry updated', 'success');
                overlay.remove();
                parentOverlay.remove();
                document.dispatchEvent(new CustomEvent('folder-shares-changed'));
            } catch (err) {
                Utils.showToast(err.message, 'error');
                saveBtn.disabled = false;
            }
        });

        dialog.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, saveBtn]));
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
    }

    function _buildExpiryPicker(currentExpiresAt) {
        const wrapper = Utils.el('div', { className: 'expiry-picker' });

        const label = Utils.el('label', { textContent: 'New expiry date/time (leave blank for no expiry):' });
        const dateInput = Utils.el('input', { type: 'datetime-local', className: 'form-input' });

        if (currentExpiresAt) {
            const d = new Date(currentExpiresAt);
            const pad = n => String(n).padStart(2, '0');
            dateInput.value = `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        }

        wrapper.appendChild(label);
        wrapper.appendChild(dateInput);

        return {
            el: wrapper,
            getExpiresAt: () => dateInput.value ? new Date(dateInput.value).toISOString() : null,
        };
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    return {
        openShareDialog,
        openFolderShareDialog,
        openUserShareDialog,
        buildLinkShareContent,
        buildUserShareContent,
        renderSharesPage,
        renderReceivedSharesPage,
        renderPublicSharePage,
        renderShortLinkPage,
        openFolderShareDetailModal,
        openSingleShareDetailModal,
    };
})();
