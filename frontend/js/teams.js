/**
 * tusShare — Teams management UI and BLS12-381 PRE crypto.
 *
 * Teams use a two-layer key scheme:
 *
 *   Layer 1 — fileKey → team  (BLS12-381 Proxy Re-Encryption, AFGH scheme)
 *     Each team has a keypair: sk_team ∈ Fr, pk_team = sk_team * G2.
 *     Encryptor (any team member): r ← Fr; C1 = r*G1; gt = pairing(C1, pk_team);
 *       wrapping_key = HKDF(gt_bytes, info="tusShare-teamkey-v1");
 *       encrypted_file_key = AES-GCM(fileKey, wrapping_key)
 *     Decryptor (any member who has sk_team):
 *       gt = pairing(sk_team * C1, G2_base); same HKDF → wrapping_key → decrypt.
 *     PRE rotation (owner, client-side):
 *       rk = sk_old * inv(sk_new) mod BLS_ORDER;  C1_new = rk * C1_old (G1 scalar mul).
 *       C2 (encrypted_file_key) is unchanged.  Members get sk_new via Layer 2.
 *     Classical-only: no production PQ-PRE library for BLS12-381.  Known limitation.
 *     BLS12-381 ≈ 128-bit classical security.
 *
 *   Layer 2 — sk_team → member  (Hybrid X25519 + ML-KEM-768 KEM, same as Phase 5b)
 *     sk_team (32 bytes) is wrapped as if it were a file key via
 *     Crypto.encapsulateFileKeyForUser().  Stored per-member in user_team_keys.
 *
 * BLS12-381 library: @noble/curves, self-hosted at /js/lib/noble-curves-bls12381.js.
 * Bundle command (run from project root):
 *   npm install @noble/curves@1.8.1
 *   npx esbuild --bundle --format=esm --minify \
 *     node_modules/@noble/curves/bls12-381.js \
 *     --outfile=frontend/js/lib/noble-curves-bls12381.js
 * See /js/lib/DEPENDENCIES.md for full instructions.
 */
const Teams = (() => {
    // =========================================================================
    // BLS12-381 helpers
    // =========================================================================

    let _blsModule = null;

    async function _getBLS() {
        if (_blsModule) return _blsModule;
        try {
            const mod = await import('/js/lib/noble-curves-bls12381.js');
            _blsModule = mod.bls12_381;
            if (!_blsModule) throw new Error('bls12_381 export not found');
        } catch (err) {
            throw new Error(
                `Failed to load BLS12-381 library: ${err.message}. ` +
                'Bundle noble-curves-bls12381.js — see /js/lib/DEPENDENCIES.md.'
            );
        }
        return _blsModule;
    }

    // BLS12-381 scalar field order (Fr)
    const _BLS_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

    function _bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function _b64ToBytes(b64) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function _bytesToB64(bytes) {
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    }

    function _bigintTo32Bytes(n) {
        const hex = n.toString(16).padStart(64, '0');
        const out = new Uint8Array(32);
        for (let i = 0; i < 32; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }

    // Fast modular exponentiation (BigInt)
    function _modpow(base, exp, mod) {
        let result = 1n;
        base = ((base % mod) + mod) % mod;
        while (exp > 0n) {
            if (exp & 1n) result = result * base % mod;
            exp >>= 1n;
            base = base * base % mod;
        }
        return result;
    }

    // Modular inverse via Fermat's little theorem (order is prime)
    function _modinv(a, mod) {
        return _modpow(((a % mod) + mod) % mod, mod - 2n, mod);
    }

    // HKDF domain separator for team file key wrapping
    const _HKDF_INFO_TEAMKEY = new TextEncoder().encode(Config.teams.hkdfInfo);

    // Derive AES-256-GCM wrapping key from a 576-byte GT element (Fp12).
    async function _keyFromGT(gtBytes) {
        const hkdf = await crypto.subtle.importKey('raw', gtBytes, 'HKDF', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: _HKDF_INFO_TEAMKEY },
            hkdf,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate a fresh BLS12-381 team keypair.
     * sk_team ∈ Fr (32 bytes);  pk_team = sk_team * G2 (96 bytes compressed).
     *
     * @returns {{ sk_bigint: BigInt, sk_bytes: Uint8Array, pk_bytes: Uint8Array }}
     */
    async function _generateTeamKey() {
        const bls = await _getBLS();
        const rand = crypto.getRandomValues(new Uint8Array(32));
        const sk   = bls.fields.Fr.create(BigInt('0x' + _bytesToHex(rand)));
        const pk   = bls.G2.ProjectivePoint.BASE.multiply(sk);
        return {
            sk_bigint: sk,
            sk_bytes:  _bigintTo32Bytes(sk),
            pk_bytes:  pk.toRawBytes(true),   // 96 bytes, compressed G2
        };
    }

    /**
     * Encrypt a file's raw key bytes for a team using the PRE scheme.
     *
     * @param {Uint8Array} fileKeyBytes  Raw 32-byte file key (exportKey('raw')).
     * @param {string}     pkTeamB64    Base64-encoded G2 compressed point (96 bytes).
     * @returns {{ pre_c1, encrypted_file_key, key_iv }}  All base64.
     */
    async function encryptFileKeyForTeam(fileKeyBytes, pkTeamB64) {
        const bls  = await _getBLS();
        const rand = crypto.getRandomValues(new Uint8Array(32));
        const r    = bls.fields.Fr.create(BigInt('0x' + _bytesToHex(rand)));

        // C1 = r * G1 (48 bytes compressed)
        const C1      = bls.G1.ProjectivePoint.BASE.multiply(r);
        const C1bytes = C1.toRawBytes(true);

        // pk_team as G2 point
        const pkPoint = bls.G2.ProjectivePoint.fromHex(_b64ToBytes(pkTeamB64));

        // GT = pairing(C1, pk_team) = e(G1,G2)^{r * sk_team}
        const gt      = bls.pairing(C1, pkPoint);
        const gtBytes = bls.fields.Fp12.toBytes(gt);

        // Derive AES-GCM key and encrypt fileKey
        const wrapKey = await _keyFromGT(gtBytes);
        const iv      = crypto.getRandomValues(new Uint8Array(12));
        const enc     = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, fileKeyBytes);

        return {
            pre_c1:             _bytesToB64(C1bytes),
            encrypted_file_key: _bytesToB64(new Uint8Array(enc)),
            key_iv:             _bytesToB64(iv),
        };
    }

    /**
     * Decrypt a file key from a PRE ciphertext using the member's sk_team.
     *
     * @param {string}  pre_c1_b64             Base64 G1 point (48 bytes).
     * @param {string}  encrypted_file_key_b64 Base64 AES-GCM ciphertext.
     * @param {string}  key_iv_b64             Base64 IV (12 bytes).
     * @param {BigInt}  skBigInt               sk_team scalar.
     * @returns {CryptoKey}  Decrypted AES-256-GCM file key.
     */
    async function decryptFileKeyFromTeam(pre_c1_b64, encrypted_file_key_b64, key_iv_b64, skBigInt) {
        const bls = await _getBLS();

        // GT = pairing(sk_team * C1, G2_base) = e(G1,G2)^{sk_team * r}
        const C1     = bls.G1.ProjectivePoint.fromHex(_b64ToBytes(pre_c1_b64));
        const C1sc   = C1.multiply(skBigInt);
        const gt     = bls.pairing(C1sc, bls.G2.ProjectivePoint.BASE);
        const gtBytes= bls.fields.Fp12.toBytes(gt);

        const wrapKey = await _keyFromGT(gtBytes);
        const iv      = _b64ToBytes(key_iv_b64);
        const enc     = _b64ToBytes(encrypted_file_key_b64);
        const raw     = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrapKey, enc);
        return crypto.subtle.importKey(
            'raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
    }

    /**
     * Apply PRE re-encryption to a C1 point.
     * rk = sk_old * inv(sk_new) mod BLS_ORDER.
     *
     * @param {string}  pre_c1_b64  Base64 G1 point.
     * @param {BigInt}  rkBigInt    Re-encryption scalar.
     * @returns {string}  New base64 G1 point.
     */
    async function applyPRERotation(pre_c1_b64, rkBigInt) {
        const bls   = await _getBLS();
        const C1    = bls.G1.ProjectivePoint.fromHex(_b64ToBytes(pre_c1_b64));
        const C1new = C1.multiply(rkBigInt);
        return _bytesToB64(C1new.toRawBytes(true));
    }

    /**
     * Compute the PRE re-encryption scalar from old and new sk_team bytes.
     * rk = sk_old * inv(sk_new) mod BLS_ORDER.
     *
     * @param {Uint8Array} skOldBytes  32-byte old sk_team.
     * @param {Uint8Array} skNewBytes  32-byte new sk_team.
     * @returns {BigInt}
     */
    function computeRKScalar(skOldBytes, skNewBytes) {
        const skOld = BigInt('0x' + _bytesToHex(skOldBytes));
        const skNew = BigInt('0x' + _bytesToHex(skNewBytes));
        return skOld * _modinv(skNew, _BLS_ORDER) % _BLS_ORDER;
    }

    // =========================================================================
    // Layer 2: wrap/unwrap sk_team via hybrid KEM (reuses Crypto module)
    // =========================================================================

    /**
     * Wrap sk_team bytes for a recipient using hybrid X25519 + ML-KEM-768.
     * Reuses Crypto.encapsulateFileKeyForUser() by importing sk_team as an AES key.
     *
     * @param {Uint8Array} skBytes               32-byte sk_team.
     * @param {string}     recipientX25519PubB64
     * @param {string}     recipientMLKEM768PubB64
     * @returns {{ ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv }}
     */
    async function wrapTeamKeyForMember(skBytes, recipientX25519PubB64, recipientMLKEM768PubB64) {
        // Import sk_team as an extractable AES-256-GCM key so encapsulateFileKeyForUser can wrap it
        const skKey = await crypto.subtle.importKey(
            'raw', skBytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
        const result = await Crypto.encapsulateFileKeyForUser(
            skKey, recipientX25519PubB64, recipientMLKEM768PubB64
        );
        return {
            ephemeral_x25519_pub: result.ephemeralX25519PubB64,
            kem_ciphertext:       result.kemCiphertextB64,
            encrypted_sk:         result.wrappedFileKeyB64,
            sk_iv:                result.keyIvB64,
        };
    }

    /**
     * Unwrap sk_team bytes from a user_team_keys entry.
     *
     * @param {{ ephemeral_x25519_pub, kem_ciphertext, encrypted_sk, sk_iv }} entry
     * @param {CryptoKey}  myX25519PrivKey
     * @param {Uint8Array} myMLKEM768SecretKey
     * @returns {{ sk_bytes: Uint8Array, sk_bigint: BigInt }}
     */
    async function unwrapTeamKey(entry, myX25519PrivKey, myMLKEM768SecretKey) {
        const skKey = await Crypto.decapsulateFileKeyFromUser(
            entry.encrypted_sk,
            entry.sk_iv,
            entry.ephemeral_x25519_pub,
            entry.kem_ciphertext,
            myX25519PrivKey,
            myMLKEM768SecretKey
        );
        const raw = await crypto.subtle.exportKey('raw', skKey);
        const sk_bytes  = new Uint8Array(raw);
        const sk_bigint = BigInt('0x' + _bytesToHex(sk_bytes));
        return { sk_bytes, sk_bigint };
    }

    // =========================================================================
    // API helpers
    // =========================================================================

    const _api = Config.app.apiPrefix;

    function _getMyPublicKeys() {
        const user = Auth.getCurrentUser();
        if (!user || !user.x25519_public_key || !user.mlkem768_public_key) {
            throw new Error('Sharing keys not set up — please re-login');
        }
        return { x25519_public_key: user.x25519_public_key, mlkem768_public_key: user.mlkem768_public_key };
    }

    function _getMyPrivateKeys() {
        const keys = Auth.getAsymmetricKeys();
        if (!keys) throw new Error('Private keys not available — re-login required');
        return keys;  // { x25519PrivateKey: CryptoKey, mlkem768SecretKey: Uint8Array }
    }

    // =========================================================================
    // UI renderers
    // =========================================================================

    function _clearEl(el) {
        while (el.firstChild) el.removeChild(el.firstChild);
    }

    /**
     * Render the Teams list page into container.
     */
    async function renderTeamsPage(container) {
        _clearEl(container);
        container.appendChild(Utils.el('h2', { textContent: 'My Teams' }));

        let teams;
        try {
            const data = await Api.get(`${_api}/teams`);
            teams = data.teams || [];
        } catch (err) {
            container.appendChild(Utils.el('p', { textContent: 'Failed to load teams: ' + err.message }));
            return;
        }

        // Create team button
        const createBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'New Team',
            onClick: () => _openCreateTeamDialog(container),
        });
        container.appendChild(createBtn);

        if (teams.length === 0) {
            container.appendChild(Utils.el('p', {
                className: 'empty-state',
                textContent: 'You have no teams yet.',
            }));
            return;
        }

        const list = Utils.el('div', { className: 'team-list' });
        for (const team of teams) {
            list.appendChild(_createTeamCard(team));
        }
        container.appendChild(list);
    }

    function _createTeamCard(team) {
        const roleLabel = {
            team_owner:      'Owner',
            team_supervisor: 'Supervisor',
            team_member:     'Member',
        }[team.my_role] || team.my_role;

        const card = Utils.el('div', { className: 'team-card' }, [
            Utils.el('div', { className: 'team-card-header' }, [
                Utils.el('a', {
                    href: `#/teams/${team.id}`,
                    className: 'team-card-name',
                    textContent: team.name,
                }),
                Utils.el('span', { className: 'team-role-badge', textContent: roleLabel }),
            ]),
        ]);

        if (team.description) {
            card.appendChild(Utils.el('p', { className: 'team-card-desc', textContent: team.description }));
        }
        if (team.rotation_pending) {
            card.appendChild(Utils.el('p', {
                className: 'team-rotation-warn',
                textContent: 'Key rotation pending — a member was recently removed.',
            }));
        }
        return card;
    }

    /**
     * Render the Team detail page (members, folders, key management).
     */
    async function renderTeamDetailPage(container, teamId) {
        _clearEl(container);

        let data;
        try {
            data = await Api.get(`${_api}/teams/${teamId}`);
        } catch (err) {
            container.appendChild(Utils.el('p', { textContent: 'Failed to load team: ' + err.message }));
            return;
        }

        const { team, members, folders } = data;
        const user        = Auth.getCurrentUser();
        const myMember    = members.find(m => m.user_id === user.id);
        const myRole      = myMember ? myMember.role : null;
        const isOwner     = myRole === 'team_owner';
        const isSupervisor= myRole === 'team_supervisor' || isOwner;

        // Header
        container.appendChild(Utils.el('h2', { textContent: team.name }));
        if (team.description) {
            container.appendChild(Utils.el('p', { textContent: team.description }));
        }
        if (team.rotation_pending) {
            container.appendChild(Utils.el('div', {
                className: 'alert alert-warn',
                textContent: 'Key rotation pending. A member was removed. Rotate keys to complete the security update.',
            }));
        }

        // ---- Members section ----
        const membersSection = Utils.el('section', { className: 'team-section' });
        membersSection.appendChild(Utils.el('h3', { textContent: 'Members' }));
        const memberTable = _buildMemberTable(team, members, myRole, teamId, container);
        membersSection.appendChild(memberTable);

        if (isSupervisor) {
            membersSection.appendChild(Utils.el('button', {
                className: 'btn btn-secondary btn-sm',
                textContent: 'Invite Member',
                onClick: () => _openInviteMemberDialog(teamId, members, container),
            }));
        }
        container.appendChild(membersSection);

        // ---- Folders section ----
        const foldersSection = Utils.el('section', { className: 'team-section' });
        foldersSection.appendChild(Utils.el('h3', { textContent: 'Folders' }));
        if (folders.length === 0) {
            foldersSection.appendChild(Utils.el('p', { textContent: 'No folders assigned to this team.' }));
        } else {
            const ul = Utils.el('ul', { className: 'team-folder-list' });
            for (const f of folders) {
                const li = Utils.el('li', {}, [
                    Utils.el('a', {
                        href: `#/files/${f.folder_id}`,
                        className: 'team-folder-link',
                        textContent: f.folder_name,
                    }),
                ]);
                if (isSupervisor) {
                    li.appendChild(Utils.el('button', {
                        className: 'btn btn-danger btn-xs',
                        textContent: 'Remove',
                        onClick: async () => {
                            if (!confirm(`Remove folder "${f.folder_name}" from this team?`)) return;
                            try {
                                await Api.del(`${_api}/teams/${teamId}/folders/${f.folder_id}`);
                                renderTeamDetailPage(container, teamId);
                            } catch (e) {
                                Utils.showToast('Failed to remove folder: ' + e.message, 'error');
                            }
                        },
                    }));
                }
                ul.appendChild(li);
            }
            foldersSection.appendChild(ul);
        }
        if (isSupervisor) {
            foldersSection.appendChild(Utils.el('button', {
                className: 'btn btn-secondary btn-sm',
                textContent: 'Add Folder',
                onClick: () => _openAddFolderDialog(teamId, container),
            }));
        }
        container.appendChild(foldersSection);

        // ---- Owner actions ----
        if (isOwner) {
            const actionsSection = Utils.el('section', { className: 'team-section' });
            actionsSection.appendChild(Utils.el('h3', { textContent: 'Key Management' }));

            if (team.rotation_pending) {
                actionsSection.appendChild(Utils.el('button', {
                    className: 'btn btn-primary',
                    textContent: 'Rotate Keys Now',
                    onClick: () => _triggerRotation(teamId, team, container),
                }));
            }

            actionsSection.appendChild(Utils.el('hr'));
            actionsSection.appendChild(Utils.el('button', {
                className: 'btn btn-danger',
                textContent: 'Delete Team',
                onClick: async () => {
                    if (!confirm(`Delete team "${team.name}"? This cannot be undone.`)) return;
                    try {
                        await Api.del(`${_api}/teams/${teamId}`);
                        Utils.showToast('Team deleted', 'success');
                        window.location.hash = '#/teams';
                    } catch (e) {
                        Utils.showToast('Failed to delete team: ' + e.message, 'error');
                    }
                },
            }));
            container.appendChild(actionsSection);
        }
    }

    function _buildMemberTable(team, members, myRole, teamId, container) {
        const user     = Auth.getCurrentUser();
        const isOwner  = myRole === 'team_owner';
        const isSupervisor = myRole === 'team_supervisor' || isOwner;

        const thead = Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Username' }),
                Utils.el('th', { textContent: 'Role' }),
                ...(isSupervisor ? [Utils.el('th', { textContent: 'Actions' })] : []),
            ]),
        ]);
        const tbody = Utils.el('tbody');

        for (const m of members) {
            const roleLabel = { team_owner: 'Owner', team_supervisor: 'Supervisor', team_member: 'Member' }[m.role] || m.role;
            const isSelf    = m.user_id === user.id;
            const isTargetOwner = m.role === 'team_owner';

            const actions = [];
            if (isSupervisor && !isSelf && !isTargetOwner) {
                actions.push(Utils.el('button', {
                    className: 'btn btn-danger btn-xs',
                    textContent: 'Remove',
                    onClick: async () => {
                        if (!confirm(`Remove ${m.username} from the team?`)) return;
                        try {
                            await Api.del(`${_api}/teams/${teamId}/members/${m.user_id}`);
                            Utils.showToast(`${m.username} removed. Key rotation is now pending.`, 'info');
                            renderTeamDetailPage(container, teamId);
                        } catch (e) {
                            Utils.showToast('Failed to remove member: ' + e.message, 'error');
                        }
                    },
                }));
            }

            tbody.appendChild(Utils.el('tr', {}, [
                Utils.el('td', { textContent: m.username }),
                Utils.el('td', { textContent: roleLabel }),
                ...(isSupervisor ? [Utils.el('td', {}, actions)] : []),
            ]));
        }

        return Utils.el('table', { className: 'team-member-table' }, [thead, tbody]);
    }

    // =========================================================================
    // Dialogs
    // =========================================================================

    async function _openCreateTeamDialog(refreshContainer) {
        let myPubs;
        try {
            myPubs = _getMyPublicKeys();
        } catch (err) {
            Utils.showToast(err.message, 'error');
            return;
        }

        const overlay = _createModalOverlay();
        const modal   = Utils.el('div', { className: 'modal' });

        modal.appendChild(Utils.el('h3', { textContent: 'New Team' }));

        const nameInput = Utils.el('input', { type: 'text', placeholder: 'Team name', className: 'input' });
        const descInput = Utils.el('input', { type: 'text', placeholder: 'Description (optional)', className: 'input' });
        modal.appendChild(nameInput);
        modal.appendChild(descInput);

        const errEl = Utils.el('p', { className: 'form-error', textContent: '' });
        modal.appendChild(errEl);

        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Cancel',
            onClick: () => overlay.remove(),
        });
        const createBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Create',
            onClick: async () => {
                const name = nameInput.value.trim();
                const desc = descInput.value.trim();
                if (!name) { errEl.textContent = 'Team name is required'; return; }

                createBtn.disabled = true;
                createBtn.textContent = 'Creating…';
                try {
                    const { sk_bytes, pk_bytes } = await _generateTeamKey();
                    const wrappedKey = await wrapTeamKeyForMember(
                        sk_bytes, myPubs.x25519_public_key, myPubs.mlkem768_public_key
                    );
                    await Api.post(`${_api}/teams`, {
                        name,
                        description: desc,
                        pre_public_key:        _bytesToB64(pk_bytes),
                        ephemeral_x25519_pub:  wrappedKey.ephemeral_x25519_pub,
                        kem_ciphertext:        wrappedKey.kem_ciphertext,
                        encrypted_sk:          wrappedKey.encrypted_sk,
                        sk_iv:                 wrappedKey.sk_iv,
                    });
                    overlay.remove();
                    Utils.showToast(`Team "${name}" created`, 'success');
                    renderTeamsPage(refreshContainer);
                } catch (err) {
                    errEl.textContent = err.message;
                    createBtn.disabled = false;
                    createBtn.textContent = 'Create';
                }
            },
        });

        modal.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, createBtn]));
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
        nameInput.focus();
    }

    async function _openInviteMemberDialog(teamId, currentMembers, refreshContainer) {
        const overlay = _createModalOverlay();
        const modal   = Utils.el('div', { className: 'modal' });
        modal.appendChild(Utils.el('h3', { textContent: 'Invite Member' }));

        const usernameInput = Utils.el('input', { type: 'text', placeholder: 'Username', className: 'input' });
        const roleSelect = Utils.el('select', { className: 'input' });
        roleSelect.appendChild(Utils.el('option', { value: 'team_member', textContent: 'Member' }));
        roleSelect.appendChild(Utils.el('option', { value: 'team_supervisor', textContent: 'Supervisor' }));
        modal.appendChild(usernameInput);
        modal.appendChild(roleSelect);

        const errEl = Utils.el('p', { className: 'form-error', textContent: '' });
        modal.appendChild(errEl);

        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Cancel',
            onClick: () => overlay.remove(),
        });
        const inviteBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Invite',
            onClick: async () => {
                const username = usernameInput.value.trim();
                const role     = roleSelect.value;
                if (!username) { errEl.textContent = 'Username is required'; return; }

                inviteBtn.disabled = true;
                inviteBtn.textContent = 'Inviting…';
                errEl.textContent = '';

                try {
                    // Fetch my team key to get sk_team
                    const privKeys = _getMyPrivateKeys();
                    const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
                    const { sk_bytes } = await unwrapTeamKey(
                        myKeyEntry,
                        privKeys.x25519PrivateKey,
                        privKeys.mlkem768SecretKey
                    );

                    // Fetch recipient public keys
                    const recipientPub = await Api.get(
                        `${Config.app.apiPrefix}/auth/users/${encodeURIComponent(username)}/public-keys`
                    );
                    if (!recipientPub.x25519_public_key || !recipientPub.mlkem768_public_key) {
                        throw new Error('User has not set up sharing keys yet');
                    }

                    // Wrap sk_team for recipient
                    const wrappedKey = await wrapTeamKeyForMember(
                        sk_bytes,
                        recipientPub.x25519_public_key,
                        recipientPub.mlkem768_public_key
                    );

                    await Api.post(`${_api}/teams/${teamId}/members`, {
                        username,
                        role,
                        ...wrappedKey,
                    });

                    overlay.remove();
                    Utils.showToast(`${username} invited`, 'success');
                    renderTeamDetailPage(refreshContainer, teamId);
                } catch (err) {
                    errEl.textContent = err.message;
                    inviteBtn.disabled = false;
                    inviteBtn.textContent = 'Invite';
                }
            },
        });

        modal.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, inviteBtn]));
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
        usernameInput.focus();
    }

    async function _openAddFolderDialog(teamId, refreshContainer) {
        let folders;
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders`);
            folders = data.folders || [];
        } catch (err) {
            Utils.showToast('Failed to load folders: ' + err.message, 'error');
            return;
        }

        if (folders.length === 0) {
            Utils.showToast('You have no folders to add', 'info');
            return;
        }

        const overlay = _createModalOverlay();
        const modal   = Utils.el('div', { className: 'modal' });
        modal.appendChild(Utils.el('h3', { textContent: 'Add Folder to Team' }));

        const select = Utils.el('select', { className: 'input' });
        for (const f of folders) {
            select.appendChild(Utils.el('option', { value: f.id, textContent: f.name }));
        }
        modal.appendChild(select);

        const errEl = Utils.el('p', { className: 'form-error', textContent: '' });
        modal.appendChild(errEl);

        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Cancel',
            onClick: () => overlay.remove(),
        });
        const addBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Add',
            onClick: async () => {
                addBtn.disabled = true;
                try {
                    await Api.post(`${_api}/teams/${teamId}/folders`, { folder_id: select.value });
                    overlay.remove();
                    Utils.showToast('Folder added to team', 'success');
                    renderTeamDetailPage(refreshContainer, teamId);
                } catch (err) {
                    errEl.textContent = err.message;
                    addBtn.disabled = false;
                }
            },
        });

        modal.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, addBtn]));
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
    }

    /**
     * Open "Add to Team" dialog, called from files.js context menus.
     * Encrypts fileKey(s) for the selected team and submits to /file-keys.
     *
     * @param {Array} files  Array of file objects { id, original_name, encrypted_file_key, key_iv }
     */
    async function openAddToTeamDialog(files) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) { Utils.showToast('Master key not available', 'error'); return; }

        let myTeams;
        try {
            const data = await Api.get(`${_api}/teams`);
            myTeams = (data.teams || []).filter(t => !t.rotation_pending);
        } catch (err) {
            Utils.showToast('Failed to load teams: ' + err.message, 'error');
            return;
        }

        if (myTeams.length === 0) {
            Utils.showToast('No teams available (or all teams have pending rotations)', 'info');
            return;
        }

        const overlay = _createModalOverlay();
        const modal   = Utils.el('div', { className: 'modal' });
        modal.appendChild(Utils.el('h3', { textContent: `Add ${files.length} file(s) to Team` }));

        const select = Utils.el('select', { className: 'input' });
        for (const t of myTeams) {
            select.appendChild(Utils.el('option', { value: t.id, textContent: t.name }));
        }
        modal.appendChild(select);

        const errEl = Utils.el('p', { className: 'form-error', textContent: '' });
        modal.appendChild(errEl);

        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary',
            textContent: 'Cancel',
            onClick: () => overlay.remove(),
        });
        const addBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Add to Team',
            onClick: async () => {
                const teamId  = select.value;
                const team    = myTeams.find(t => t.id === teamId);
                addBtn.disabled = true;
                addBtn.textContent = 'Encrypting…';
                errEl.textContent = '';

                try {
                    const fileKeys = [];
                    for (const file of files) {
                        // Decrypt fileKey using masterKey
                        const fileKey = await Crypto.decryptFileKey(
                            file.encrypted_file_key, file.key_iv, masterKey
                        );
                        const rawKey = await crypto.subtle.exportKey('raw', fileKey);
                        const entry  = await encryptFileKeyForTeam(
                            new Uint8Array(rawKey), team.pre_public_key
                        );
                        fileKeys.push({ file_id: file.id, ...entry });
                    }

                    // Batch submit
                    const batchMax = Config.teams.fileKeyBatchMax;
                    for (let i = 0; i < fileKeys.length; i += batchMax) {
                        await Api.post(`${_api}/teams/${teamId}/file-keys`, {
                            file_keys: fileKeys.slice(i, i + batchMax),
                        });
                    }

                    overlay.remove();
                    Utils.showToast(`${files.length} file(s) added to "${team.name}"`, 'success');
                } catch (err) {
                    errEl.textContent = err.message;
                    addBtn.disabled = false;
                    addBtn.textContent = 'Add to Team';
                }
            },
        });

        modal.appendChild(Utils.el('div', { className: 'modal-actions' }, [cancelBtn, addBtn]));
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
    }

    // =========================================================================
    // PRE rotation
    // =========================================================================

    async function _triggerRotation(teamId, team, refreshContainer) {
        let asymKeys;
        try { asymKeys = _getMyPrivateKeys(); } catch (e) {
            Utils.showToast(e.message, 'error'); return;
        }

        if (!confirm(
            'Rotate team keys?\n\n' +
            'This will re-encrypt all team file keys in your browser using BLS12-381 scalar multiplication. ' +
            'For large teams this may take a moment. Proceed?'
        )) return;

        const statusEl = Utils.el('div', { className: 'rotation-status', textContent: 'Preparing rotation…' });
        refreshContainer.appendChild(statusEl);

        try {
            // 1. Unwrap current sk_team
            statusEl.textContent = 'Unwrapping team key…';
            const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
            const { sk_bytes: skOldBytes } = await unwrapTeamKey(
                myKeyEntry, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
            );

            // 2. Generate new keypair
            statusEl.textContent = 'Generating new key pair…';
            const { sk_bytes: skNewBytes, pk_bytes: pkNewBytes } = await _generateTeamKey();
            const rk = computeRKScalar(skOldBytes, skNewBytes);

            // 3. Fetch all file keys and re-encrypt
            statusEl.textContent = 'Fetching file keys…';
            const fkData = await Api.get(`${_api}/teams/${teamId}/file-keys`);
            const oldFileKeys = fkData.file_keys || [];

            statusEl.textContent = `Re-encrypting ${oldFileKeys.length} file key(s)…`;
            const updatedFileKeys = [];
            for (let i = 0; i < oldFileKeys.length; i++) {
                const fk = oldFileKeys[i];
                const newC1 = await applyPRERotation(fk.pre_c1, rk);
                updatedFileKeys.push({ file_id: fk.file_id, pre_c1: newC1 });
                if (i % 50 === 0) {
                    statusEl.textContent = `Re-encrypting… ${i + 1}/${oldFileKeys.length}`;
                    await new Promise(r => setTimeout(r, 0)); // yield to UI
                }
            }

            // 4. Fetch remaining members and wrap sk_new for each
            statusEl.textContent = 'Wrapping new key for members…';
            const memberData = await Api.get(`${_api}/teams/${teamId}/members`);
            const members    = memberData.members || [];
            const wrappedMembers = [];

            for (const m of members) {
                // Fetch member's public keys
                const pub = await Api.get(
                    `${Config.app.apiPrefix}/auth/users/${encodeURIComponent(m.username)}/public-keys`
                );
                const wrapped = await wrapTeamKeyForMember(
                    skNewBytes, pub.x25519_public_key, pub.mlkem768_public_key
                );
                wrappedMembers.push({ user_id: m.user_id, ...wrapped });
            }

            // 5. Submit rotation
            statusEl.textContent = 'Committing rotation…';
            await Api.post(`${_api}/teams/${teamId}/rotate`, {
                pre_public_key_new: _bytesToB64(pkNewBytes),
                file_keys:          updatedFileKeys,
                members:            wrappedMembers,
            });

            statusEl.remove();
            Utils.showToast('Key rotation complete', 'success');
            renderTeamDetailPage(refreshContainer, teamId);

        } catch (err) {
            statusEl.textContent = 'Rotation failed: ' + err.message;
            Utils.showToast('Rotation failed: ' + err.message, 'error');
        }
    }

    // =========================================================================
    // File download with team key decryption
    // =========================================================================

    /**
     * Decrypt a file key using the team's PRE scheme.
     * Called by Download.downloadFile when downloading a team-shared file.
     *
     * @param {string} fileId
     * @param {string} teamId
     * @returns {CryptoKey} The decrypted AES-256-GCM file key.
     */
    async function decryptTeamFileKey(fileId, teamId) {
        const asymKeys = _getMyPrivateKeys();

        // Fetch my wrapped team key
        const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
        const { sk_bigint } = await unwrapTeamKey(
            myKeyEntry, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
        );

        // Fetch the PRE ciphertext for this file
        const fkData = await Api.get(`${_api}/teams/${teamId}/file-keys`);
        const entry  = (fkData.file_keys || []).find(fk => fk.file_id === fileId);
        if (!entry) throw new Error('File key not found in team');

        return decryptFileKeyFromTeam(
            entry.pre_c1, entry.encrypted_file_key, entry.key_iv, sk_bigint
        );
    }

    // =========================================================================
    // Utility
    // =========================================================================

    function _createModalOverlay() {
        const overlay = Utils.el('div', {
            className: 'modal-overlay',
            onClick: (e) => { if (e.target === overlay) overlay.remove(); },
        });
        return overlay;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    return {
        renderTeamsPage,
        renderTeamDetailPage,
        openAddToTeamDialog,
        decryptTeamFileKey,
        // Exposed for tests / other modules
        encryptFileKeyForTeam,
        decryptFileKeyFromTeam,
        wrapTeamKeyForMember,
        unwrapTeamKey,
    };
})();
