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
 *   npm install @noble/curves@2.2.0
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
            const mod = await import('/js/lib/noble-curves-bls12381.js'); // NOSONAR — web-root-relative URL, not a filesystem path
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
        for (let i = 0; i < bin.length; i++) out[i] = bin.codePointAt(i);
        return out;
    }

    function _bytesToB64(bytes) {
        let bin = '';
        for (const byte of bytes) bin += String.fromCodePoint(byte);
        return btoa(bin);
    }

    function _bytesToB64url(bytes) {
        return _bytesToB64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    }

    function _b64urlToBytes(b64url) {
        return _b64ToBytes(b64url.replaceAll('-', '+').replaceAll('_', '/'));
    }

    function _bigintTo32Bytes(n) {
        const hex = n.toString(16).padStart(64, '0');
        const out = new Uint8Array(32);
        for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.substr(i * 2, 2), 16);
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
        const pk   = bls.G2.Point.BASE.multiply(sk);
        return {
            sk_bigint: sk,
            sk_bytes:  _bigintTo32Bytes(sk),
            pk_bytes:  pk.toBytes(true),   // 96 bytes, compressed G2
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
        const C1      = bls.G1.Point.BASE.multiply(r);
        const C1bytes = C1.toBytes(true);

        // pk_team as G2 point
        const pkPoint = bls.G2.Point.fromBytes(_b64ToBytes(pkTeamB64));

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
        const C1     = bls.G1.Point.fromBytes(_b64ToBytes(pre_c1_b64));
        const C1sc   = C1.multiply(skBigInt);
        const gt     = bls.pairing(C1sc, bls.G2.Point.BASE);
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
        const C1    = bls.G1.Point.fromBytes(_b64ToBytes(pre_c1_b64));
        const C1new = C1.multiply(rkBigInt);
        return _bytesToB64(C1new.toBytes(true));
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

    // Fr field helpers for DLEQ arithmetic
    function _frMul(a, b) { return a * b % _BLS_ORDER; }
    function _frSub(a, b) { return ((a - b) % _BLS_ORDER + _BLS_ORDER) % _BLS_ORDER; }

    /**
     * Compute rk_point = rk × G1 for inclusion in the rotation payload.
     * The server uses this for the pairing consistency check: e(rk_point, pk_new) == e(G1, pk_old).
     *
     * @param {BigInt} rkBigInt  Re-encryption scalar.
     * @returns {string}  Base64 compressed G1 point (48 bytes).
     */
    async function _computeRkPoint(rkBigInt) {
        const bls = await _getBLS();
        return _bytesToB64(bls.G1.Point.BASE.multiply(rkBigInt).toBytes(true));
    }

    /**
     * Generate a Chaum-Pedersen DLEQ proof for a single C1 re-encryption.
     *
     * Proves the same scalar rk was used for both:
     *   rk_point = rk × G1  and  C1_new = rk × C1_old
     *
     * Fiat-Shamir (non-interactive):
     *   r  = random Fr element
     *   R1 = r × G1;  R2 = r × C1_old
     *   c  = SHA-256(G1 ‖ C1_old ‖ rk_point ‖ C1_new ‖ R1 ‖ R2) mod BLS_ORDER
     *   s  = r − c × rk  (mod BLS_ORDER)
     *
     * Verifier checks: s×G1 + c×rk_point == R1  and  s×C1_old + c×C1_new == R2
     *
     * @param {BigInt} rkBigInt     Re-encryption scalar.
     * @param {string} c1OldB64    Base64 G1 point — C1 before rotation.
     * @param {string} rkPointB64  Base64 G1 point — rk × G1 (precomputed).
     * @param {string} c1NewB64    Base64 G1 point — C1 after rotation.
     * @returns {{ dleq_s: string, dleq_R1: string, dleq_R2: string }}
     */
    async function _generateDleqProof(rkBigInt, c1OldB64, rkPointB64, c1NewB64) {
        const bls    = await _getBLS();
        const G1base = bls.G1.Point.BASE;
        const C1old  = bls.G1.Point.fromBytes(_b64ToBytes(c1OldB64));

        // Random blinding scalar r ∈ Fr
        const rRaw = crypto.getRandomValues(new Uint8Array(32));
        const r    = BigInt('0x' + _bytesToHex(rRaw)) % _BLS_ORDER;

        // R1 = r × G1,  R2 = r × C1_old
        const R1bytes = G1base.multiply(r).toBytes(true);
        const R2bytes = C1old.multiply(r).toBytes(true);

        // Fiat-Shamir challenge — concatenate all six G1 points (48 bytes each)
        const parts = [G1base.toBytes(true), _b64ToBytes(c1OldB64),
                       _b64ToBytes(rkPointB64), _b64ToBytes(c1NewB64), R1bytes, R2bytes];
        const msg = new Uint8Array(6 * 48);
        let off = 0;
        for (const chunk of parts) { msg.set(chunk, off); off += 48; }

        const cHash = await crypto.subtle.digest('SHA-256', msg);
        const c = BigInt('0x' + _bytesToHex(new Uint8Array(cHash))) % _BLS_ORDER;

        // s = r − c × rk  (mod BLS_ORDER)
        const s = _frSub(r, _frMul(c, rkBigInt));

        return {
            dleq_s:  _bytesToB64(_bigintTo32Bytes(s)),
            dleq_R1: _bytesToB64(R1bytes),
            dleq_R2: _bytesToB64(R2bytes),
        };
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
        if (!user?.x25519_public_key || !user.mlkem768_public_key) {
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
        while (el.firstChild) el.firstChild.remove();
    }

    /**
     * Render the Teams list page into container.
     */
    function _makeViewToggle(tileActive) {
        const tileBtn = Utils.el('button', {
            className: 'view-toggle-btn' + (tileActive ? ' active' : ''),
            title: 'Tile view',
        });
        tileBtn.appendChild(Utils.el('span', { className: 'view-toggle-grid-icon' }));

        const listBtn = Utils.el('button', {
            className: 'view-toggle-btn' + (tileActive ? '' : ' active'),
            title: 'List view',
        });
        listBtn.appendChild(Utils.el('span', { className: 'view-toggle-list-icon' }));

        return { tileBtn, listBtn };
    }

    function _sortedRoleLabels(team) {
        return [...(team.my_roles || [])].sort((a, b) => _ROLE_PRIORITY(a) - _ROLE_PRIORITY(b))
            .map(r => _ROLE_LABEL[r] || 'Custom');
    }

    function _teamStatusSortKey(team) {
        if (team.rotation_pending) return 'z';
        return team.my_key_confirmed ? 'a' : 'b';
    }

    function _teamStatusLabel(team) {
        if (team.rotation_pending) return 'Rotation pending';
        return team.my_key_confirmed ? 'Confirmed' : 'Pending';
    }

    function _buildTeamsListTable(teams) {
        let sortKey = 'name', sortAsc = true;
        const tbody = Utils.el('tbody');

        function _renderRows() {
            tbody.innerHTML = '';
            const sorted = [...teams].sort((a, b) => {
                let av, bv;
                if (sortKey === 'my_roles') {
                    av = _sortedRoleLabels(a).join(', ');
                    bv = _sortedRoleLabels(b).join(', ');
                } else if (sortKey === 'status') {
                    av = _teamStatusSortKey(a);
                    bv = _teamStatusSortKey(b);
                } else {
                    av = a[sortKey] ?? '';
                    bv = b[sortKey] ?? '';
                }
                const cmp = String(av).localeCompare(String(bv));
                return sortAsc ? cmp : -cmp;
            });
            for (const team of sorted) {
                const sortedRoles = [...(team.my_roles || [])].sort((a, b) => _ROLE_PRIORITY(a) - _ROLE_PRIORITY(b));
                const roleText = sortedRoles.map(r => _ROLE_LABEL[r] || 'Custom').join(', ') || '—';
                const status = _teamStatusLabel(team);
                tbody.appendChild(Utils.el('tr', { dataset: { name: team.name.toLowerCase() } }, [
                    Utils.el('td', {}, [Utils.el('a', {
                        href: `#/teams/${team.id}`,
                        className: 'teams-list-link',
                        textContent: team.name,
                    })]),
                    Utils.el('td', { textContent: roleText }),
                    Utils.el('td', { textContent: status }),
                ]));
            }
        }

        const thead = Utils.el('thead');
        const cols = [
            { label: 'Team Name', key: 'name' },
            { label: 'Roles',     key: 'my_roles' },
            { label: 'Key Status', key: 'status' },
        ];
        const headerRow = Utils.el('tr');
        for (const col of cols) {
            const th = Utils.el('th', { textContent: col.label, dataset: { key: col.key } });
            th.addEventListener('click', () => {
                if (sortKey === col.key) { sortAsc = !sortAsc; }
                else { sortKey = col.key; sortAsc = true; }
                for (const el of thead.querySelectorAll('th')) el.dataset.sort = '';
                th.dataset.sort = sortAsc ? 'asc' : 'desc';
                _renderRows();
            });
            headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);
        _renderRows();

        return Utils.el('table', { className: 'team-list-table' }, [thead, tbody]);
    }

    async function renderTeamsPage(container) {
        _clearEl(container);

        let teams, savedView;
        try {
            const [teamsData, prefsData] = await Promise.all([
                Api.get(`${_api}/teams`),
                Api.get(`${_api}/auth/me/prefs`).catch(() => ({ ui_prefs: {} })),
            ]);
            teams = teamsData.teams || [];
            savedView = prefsData.ui_prefs?.teams_view || 'tile';
        } catch (err) {
            container.appendChild(Utils.el('p', { textContent: 'Failed to load teams: ' + err.message }));
            return;
        }

        let view = savedView;
        const { tileBtn, listBtn } = _makeViewToggle(view === 'tile');

        const header = Utils.el('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px' });
        header.appendChild(Utils.el('div', { style: 'display:flex;align-items:center;gap:24px' }, [
            Utils.el('h2', { textContent: 'My Teams', style: 'margin:0' }),
            Utils.el('div', { style: 'display:flex;align-items:center;gap:4px' }, [tileBtn, listBtn]),
        ]));
        header.appendChild(Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: '+ New Team',
            onClick: () => _openCreateTeamDialog(container),
        }));
        container.appendChild(header);

        if (teams.length === 0) {
            container.appendChild(Utils.el('p', { className: 'empty-state', textContent: 'You have no teams yet.' }));
            return;
        }

        const filterInput = Utils.el('input', {
            type: 'text',
            className: 'input-sm',
            placeholder: 'Search teams…',
            style: 'width:240px;margin-bottom:12px',
        });
        container.appendChild(filterInput);

        const contentEl = Utils.el('div');
        container.appendChild(contentEl);

        function _renderContent() {
            contentEl.innerHTML = '';
            if (view === 'list') {
                const table = _buildTeamsListTable(teams);
                contentEl.appendChild(table);
                filterInput.oninput = () => {
                    const q = filterInput.value.toLowerCase();
                    for (const row of table.querySelectorAll('tbody tr')) {
                        row.style.display = !q || (row.dataset.name || '').includes(q) ? '' : 'none';
                    }
                };
            } else {
                const grid = Utils.el('div', { className: 'team-list', style: 'padding:8px 0' });
                for (const team of teams) grid.appendChild(_createTeamCard(team));
                contentEl.appendChild(grid);
                filterInput.oninput = () => {
                    const q = filterInput.value.toLowerCase();
                    for (const card of grid.querySelectorAll('.team-card')) {
                        card.style.display = !q || (card.dataset.name || '').toLowerCase().includes(q) ? '' : 'none';
                    }
                };
            }
            filterInput.value = '';
        }

        tileBtn.addEventListener('click', () => {
            if (view === 'tile') return;
            view = 'tile';
            tileBtn.classList.add('active');
            listBtn.classList.remove('active');
            _renderContent();
            Api.patch(`${_api}/auth/me/prefs`, { teams_view: 'tile' }).catch(() => {});
        });
        listBtn.addEventListener('click', () => {
            if (view === 'list') return;
            view = 'list';
            listBtn.classList.add('active');
            tileBtn.classList.remove('active');
            _renderContent();
            Api.patch(`${_api}/auth/me/prefs`, { teams_view: 'list' }).catch(() => {});
        });

        _renderContent();
    }

    const _ROLE_LABEL = { team_admin: 'Owner', team_manager: 'Supervisor', team_member: 'Member' };
    function _ROLE_PRIORITY(r) {
        if (r === 'team_admin') return 0;
        if (r === 'team_manager') return 1;
        if (r === 'team_member') return 9;
        return 5;
    }

    function _createTeamCard(team) {
        let roles;
        if (Array.isArray(team.my_roles)) roles = team.my_roles;
        else if (team.my_role) roles = [team.my_role];
        else roles = [];
        const sortedRoles = [...roles].sort((a, b) => _ROLE_PRIORITY(a) - _ROLE_PRIORITY(b));

        const card = Utils.el('a', {
            href: `#/teams/${team.id}`,
            className: 'team-card team-card-link',
            dataset: { name: team.name },
        });

        const badgesEl = Utils.el('span', { className: 'team-roles-badges' });
        const MAX_VISIBLE = 2;
        for (let i = 0; i < Math.min(sortedRoles.length, MAX_VISIBLE); i++) {
            const rid = sortedRoles[i];
            badgesEl.appendChild(Utils.el('span', {
                className: 'team-role-badge',
                textContent: _ROLE_LABEL[rid] || 'Custom',
            }));
        }
        if (sortedRoles.length > MAX_VISIBLE) {
            badgesEl.appendChild(Utils.el('span', {
                className: 'team-role-badge team-role-badge-more',
                textContent: `+${sortedRoles.length - MAX_VISIBLE}`,
            }));
        }

        const cardHeaderChildren = [
            Utils.el('span', { className: 'team-card-name', textContent: team.name }),
            badgesEl,
        ];
        if (team.has_updates) {
            cardHeaderChildren.push(Utils.el('span', {
                className: 'team-update-badge',
                textContent: 'Updated',
                title: 'This team has changed since you last reviewed it',
            }));
        }
        const cardHeader = Utils.el('div', { className: 'team-card-header' }, cardHeaderChildren);
        card.appendChild(cardHeader);

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

    function _buildFolderRow(f, isOwner) {
        const folderLink = Utils.el('a', {
            href: `#/team-folders/${f.folder_id}`,
            className: 'folder-link',
            textContent: f.folder_name,
        });
        const folderRow = Utils.el('div', { className: 'team-folder-row' }, [folderLink]);

        if (!isOwner) return folderRow;

        const editBtn = Utils.el('button', { className: 'btn btn-secondary btn-xs', textContent: '✎ Rename' });
        folderRow.appendChild(editBtn);

        editBtn.addEventListener('click', () => {
            const nameInput = Utils.el('input', { type: 'text', className: 'input input-xs', value: folderLink.textContent });
            const saveBtn   = Utils.el('button', { className: 'btn btn-primary btn-xs', textContent: 'Save' });
            const cancelBtn = Utils.el('button', { className: 'btn btn-secondary btn-xs', textContent: 'Cancel' });
            const editRow   = Utils.el('span', { className: 'folder-inline-edit' }, [nameInput, saveBtn, cancelBtn]);

            folderLink.replaceWith(editRow);
            editBtn.remove();
            nameInput.focus();
            nameInput.select();

            const restoreView = () => { editRow.replaceWith(folderLink); folderRow.appendChild(editBtn); };

            cancelBtn.addEventListener('click', restoreView);
            nameInput.addEventListener('keydown', e => { if (e.key === 'Escape') restoreView(); });
            saveBtn.addEventListener('click', async () => {
                const name = nameInput.value.trim();
                if (!name) return;
                saveBtn.disabled = true;
                try {
                    await Api.put(`${Config.app.apiPrefix}/folders/${f.folder_id}`, { name });
                    folderLink.textContent = name;
                    Utils.showToast('Folder renamed', 'success');
                    restoreView();
                } catch (err) {
                    Utils.showToast('Rename failed: ' + err.message, 'error');
                    saveBtn.disabled = false;
                }
            });
        });
        return folderRow;
    }

    function _appendSupervisorButtons(membersSection, teamId, members, container, allowEphemeralInvites) {
        membersSection.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Invite Member',
            onClick: () => _openInviteMemberDialog(teamId, members, container),
        }));
        membersSection.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Create Invite Link',
            disabled: !allowEphemeralInvites,
            title: allowEphemeralInvites ? '' : 'Ephemeral invite links are disabled by an administrator',
            onClick: allowEphemeralInvites ? () => _openCreateInviteLinkDialog(teamId) : null,
        }));
    }

    function _appendOwnerActionsSection(container, team, teamId) {
        const actionsSection = Utils.el('section', { className: 'team-section' });
        actionsSection.appendChild(Utils.el('h3', { textContent: 'Key Management' }));
        actionsSection.appendChild(Utils.el('button', {
            className: team.rotation_pending ? 'btn btn-primary' : 'btn btn-secondary',
            textContent: team.rotation_pending ? 'Rotate Keys Now' : 'Rotate Team Keys',
            onClick: () => _triggerRotation(teamId, team, container),
        }));
        actionsSection.appendChild(Utils.el('hr'));
        actionsSection.appendChild(Utils.el('button', {
            className: 'btn btn-danger',
            textContent: 'Delete Team',
            onClick: async () => {
                if (!confirm(`Delete team "${team.name}"? This cannot be undone.`)) return;
                try {
                    await Api.del(`${_api}/teams/${teamId}`);
                    Utils.showToast('Team deleted', 'success');
                    globalThis.location.hash = '#/teams';
                } catch (e) {
                    Utils.showToast('Failed to delete team: ' + e.message, 'error');
                }
            },
        }));
        container.appendChild(actionsSection);
    }

    /**
     * Render the Team detail page (members, folders, key management).
     */
    async function renderTeamDetailPage(container, teamId) {
        _clearEl(container);

        let data, allowEphemeralInvites = true;
        try {
            [data] = await Promise.all([
                Api.get(`${_api}/teams/${teamId}`),
                Api.get(`${_api}/admin/settings`).then(s => {
                    allowEphemeralInvites = s.settings?.allow_ephemeral_team_invites !== '0';
                }).catch(() => {}),
            ]);
        } catch (err) {
            container.appendChild(Utils.el('p', { textContent: 'Failed to load team: ' + err.message }));
            return;
        }

        const { team, members, folders, allow_multi_team_owner: allowMultiOwner } = data;
        const user        = Auth.getCurrentUser();
        const myMember    = members.find(m => m.user_id === user.id);
        const myRole      = myMember ? myMember.role : null;
        const isOwner     = myRole === 'team_admin';
        const isSupervisor= myRole === 'team_manager' || isOwner;

        // Clear any pending "Updated" badge for this manager.
        if (isSupervisor) {
            Api.post(`${_api}/teams/${teamId}/seen`, {}).catch(() => {});
        }

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
        membersSection.appendChild(Utils.el('h3', { textContent: `Members (${members.length})` }));

        // Live search filter
        const memberSearch = Utils.el('input', {
            type: 'search',
            className: 'team-member-search',
            placeholder: 'Filter members…',
        });
        membersSection.appendChild(memberSearch);

        const memberTable = _buildMemberTable(team, members, myRole, teamId, container, allowMultiOwner);
        membersSection.appendChild(memberTable);

        // Filter table rows as user types
        memberSearch.addEventListener('input', () => {
            const q = memberSearch.value.toLowerCase();
            for (const row of memberTable.querySelectorAll('tbody tr')) {
                const name = row.querySelector('td')?.textContent?.toLowerCase() ?? '';
                row.style.display = !q || name.includes(q) ? '' : 'none';
            }
        });

        if (isSupervisor) {
            _appendSupervisorButtons(membersSection, teamId, members, container, allowEphemeralInvites);
        }
        container.appendChild(membersSection);

        // ---- Team Folder section ----
        const foldersSection = Utils.el('section', { className: 'team-section' });
        foldersSection.appendChild(Utils.el('h3', { textContent: 'Team Folder' }));
        if (folders.length === 0) {
            foldersSection.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No folder associated with this team.' }));
        } else {
            foldersSection.appendChild(_buildFolderRow(folders[0], isOwner));
        }
        container.appendChild(foldersSection);

        // ---- Owner actions ----
        if (isOwner) {
            _appendOwnerActionsSection(container, team, teamId);
        }

        // ---- Custom Roles section (visible to team owners and global admins) ----
        if (isOwner || user.is_admin) {
            const rolesSection = Utils.el('section', { className: 'team-section' });
            rolesSection.appendChild(Utils.el('h3', { textContent: 'Custom Roles' }));
            container.appendChild(rolesSection);
            _renderTeamRolesSection(rolesSection, teamId, members, isOwner || user.is_admin);
        }

        // ---- Recent Activity (visible to supervisors and admins) ----
        if (isSupervisor || user.is_admin) {
            const activitySection = Utils.el('section', { className: 'team-section' });
            activitySection.appendChild(Utils.el('h3', { textContent: 'Recent Activity' }));
            container.appendChild(activitySection);
            _renderTeamActivitySection(activitySection, teamId);
        }
    }

    async function _renderTeamActivitySection(container, teamId) {
        const statusEl = Utils.el('p', { className: 'text-muted', textContent: 'Loading…' });
        container.appendChild(statusEl);

        let data;
        try {
            data = await Api.get(`${_api}/teams/${teamId}/activity`);
        } catch {
            statusEl.textContent = 'Could not load activity.';
            return;
        }

        statusEl.remove();
        const events = data.activity || [];
        if (events.length === 0) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No recent management activity.' }));
            return;
        }

        const _EVENT_LABELS = {
            'admin.team.member_added':             'Member added',
            'admin.team.member_removed':           'Member removed',
            'admin.team_key.rotation_started':     'Key rotation started',
            'admin.team_key.rotation_completed':   'Key rotation completed',
            'admin.team_role.assigned':            'Custom role assigned',
            'admin.team_role.revoked':             'Custom role revoked',
            'admin.team_role.created':             'Custom role created',
            'admin.team_role.updated':             'Custom role updated',
            'admin.team_role.deleted':             'Custom role deleted',
            'admin.team.delete_scheduled':         'Team deletion scheduled',
            'admin.team.delete_cancelled':         'Team deletion cancelled',
        };

        const list = Utils.el('ul', { className: 'team-activity-list' });
        for (const ev of events) {
            const label = _EVENT_LABELS[ev.event_type] || ev.event_type;
            const ts    = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '';
            const actor = ev.actor_username ? `by ${ev.actor_username}` : '';
            const li = Utils.el('li', { className: `team-activity-item team-activity-${ev.severity || 'info'}` });
            li.appendChild(Utils.el('span', { className: 'team-activity-label', textContent: label }));
            li.appendChild(Utils.el('span', { className: 'team-activity-meta', textContent: [actor, ts].filter(Boolean).join(' · ') }));
            list.appendChild(li);
        }
        container.appendChild(list);
    }

    // =========================================================================
    // Custom team roles management
    // =========================================================================

    async function _renderTeamRolesSection(container, teamId, members, canManage) {
        const statusEl = Utils.el('p', { className: 'text-muted', textContent: 'Loading…' });
        container.appendChild(statusEl);

        let rolesData;
        try {
            rolesData = await Api.get(`${_api}/teams/${teamId}/custom-roles`);
        } catch (err) {
            statusEl.textContent = 'Failed to load custom roles: ' + err.message;
            return;
        }

        statusEl.remove();

        const { roles, flags } = rolesData;

        if (canManage) {
            container.appendChild(Utils.el('button', {
                className: 'btn btn-secondary btn-sm team-roles-add-btn',
                textContent: '+ Create Custom Role',
                onClick: () => _showCreateTeamRoleModal(teamId, flags, () => {
                    container.innerHTML = '';
                    container.appendChild(Utils.el('h3', { textContent: 'Custom Roles' }));
                    _renderTeamRolesSection(container, teamId, members, canManage);
                }),
            }));
        }

        if (roles.length === 0) {
            container.appendChild(Utils.el('p', {
                className: 'text-muted',
                textContent: 'No custom roles defined for this team.',
            }));
            return;
        }

        const list = Utils.el('div', { className: 'team-roles-list' });
        for (const role of roles) {
            list.appendChild(
                _buildTeamRoleCard(role, flags, members, teamId, canManage, () => {
                    container.innerHTML = '';
                    container.appendChild(Utils.el('h3', { textContent: 'Custom Roles' }));
                    _renderTeamRolesSection(container, teamId, members, canManage);
                })
            );
        }
        container.appendChild(list);
    }

    function _buildTeamRoleCard(role, flags, members, teamId, canManage, refreshFn) {
        let bodyLoaded = false;
        const body = Utils.el('div', { className: 'role-card-body' });
        body.style.display = 'none';

        const toggle = Utils.el('button', {
            className: 'role-card-toggle collapsed',
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggle.classList.toggle('collapsed', open);
                if (!open && !bodyLoaded) {
                    bodyLoaded = true;
                    _populateTeamRoleCardBody(body, role, flags, members, teamId, canManage, refreshFn);
                }
            },
        });

        const badge = Utils.el('span', { className: 'role-card-badge badge-custom', textContent: 'custom' });
        const nameEl = Utils.el('span', { className: 'role-card-name', textContent: role.name });
        const header = Utils.el('div', { className: 'role-card-header' }, [toggle, nameEl, badge]);
        return Utils.el('div', { className: 'role-card' }, [header, body]);
    }

    function _populateTeamRoleCardBody(container, role, flags, members, teamId, canManage, refreshFn) {
        const content = Utils.el('div', { className: 'role-card-content' });

        // --- Name / Description form ---
        if (canManage) {
            const nameInput = Utils.el('input', { type: 'text', className: 'form-input', value: role.name });
            const descInput = Utils.el('input', { type: 'text', className: 'form-input', value: role.description });
            const saveBtn = Utils.el('button', {
                className: 'btn btn-primary btn-sm',
                textContent: 'Save Name/Desc',
                onClick: async () => {
                    try {
                        await Api.patch(`${_api}/teams/${teamId}/custom-roles/${role.id}`, {
                            name: nameInput.value.trim(),
                            description: descInput.value.trim(),
                        });
                        Utils.showToast('Role updated', 'success');
                        refreshFn();
                    } catch (e) {
                        Utils.showToast('Update failed: ' + e.message, 'error');
                    }
                },
            });
            const deleteBtn = Utils.el('button', {
                className: 'btn btn-danger btn-sm',
                textContent: 'Delete Role',
                onClick: async () => {
                    if (!confirm(`Delete role "${role.name}"? All assignments will be removed.`)) return;
                    try {
                        await Api.del(`${_api}/teams/${teamId}/custom-roles/${role.id}`);
                        Utils.showToast('Role deleted', 'success');
                        refreshFn();
                    } catch (e) {
                        Utils.showToast('Delete failed: ' + e.message, 'error');
                    }
                },
            });

            content.appendChild(Utils.el('div', { className: 'role-meta-form' }, [
                Utils.el('div', { className: 'role-meta-fields' }, [
                    Utils.el('label', { textContent: 'Name' }), nameInput,
                    Utils.el('label', { textContent: 'Description' }), descInput,
                ]),
                Utils.el('div', { className: 'role-meta-actions' }, [saveBtn, deleteBtn]),
            ]));
        }

        // --- Permission flags ---
        const flagChecks = {};
        const flagsDiv = Utils.el('div', { className: 'flag-category' }, [
            Utils.el('div', { className: 'flag-category-label', textContent: 'Move Permissions' }),
        ]);

        for (const flagMeta of flags) {
            const granted = role.permissions[flagMeta.flag] === '1';
            const cb = Utils.el('input', { type: 'checkbox' });
            cb.checked = granted;
            if (!canManage) cb.disabled = true;
            flagChecks[flagMeta.flag] = cb;

            flagsDiv.appendChild(Utils.el('div', { className: 'flag-row' }, [
                cb,
                Utils.el('div', { className: 'flag-label' }, [
                    Utils.el('span', { className: 'flag-name', textContent: flagMeta.flag }),
                    Utils.el('span', { className: 'flag-desc', textContent: flagMeta.description }),
                ]),
            ]));
        }
        content.appendChild(flagsDiv);

        if (canManage) {
            const savePermsBtn = Utils.el('button', {
                className: 'btn btn-primary btn-sm',
                textContent: 'Save Permissions',
                onClick: async () => {
                    const permissions = {};
                    for (const [f, cb] of Object.entries(flagChecks)) {
                        permissions[f] = cb.checked ? '1' : '0';
                    }
                    try {
                        await Api.put(`${_api}/teams/${teamId}/custom-roles/${role.id}/permissions`, { permissions });
                        Utils.showToast('Permissions saved', 'success');
                    } catch (e) {
                        Utils.showToast('Save failed: ' + e.message, 'error');
                    }
                },
            });
            content.appendChild(Utils.el('div', { className: 'role-flags-actions' }, [savePermsBtn]));
        }

        // --- Assignments ---
        const assignSection = Utils.el('div', { className: 'team-role-assignments' });
        content.appendChild(assignSection);
        _loadTeamRoleAssignments(assignSection, role, teamId, members, canManage);

        container.appendChild(content);
    }

    async function _loadTeamRoleAssignments(container, role, teamId, members, canManage) {
        container.appendChild(Utils.el('h4', { textContent: 'Members with this role' }));
        let data;
        try {
            data = await Api.get(`${_api}/teams/${teamId}/custom-roles/${role.id}/assignments`);
        } catch {
            container.appendChild(Utils.el('p', { textContent: 'Failed to load assignments.' }));
            return;
        }

        const refresh = () => {
            container.innerHTML = '';
            _loadTeamRoleAssignments(container, role, teamId, members, canManage);
        };

        const { assignments } = data;

        if (assignments.length === 0) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No members assigned.' }));
        } else {
            const list = Utils.el('ul', { className: 'team-role-assignment-list' });
            for (const a of assignments) {
                const li = Utils.el('li', { textContent: a.username });
                if (canManage) {
                    li.appendChild(Utils.el('button', {
                        className: 'btn btn-danger btn-xs',
                        textContent: 'Revoke',
                        onClick: async () => {
                            try {
                                await Api.del(`${_api}/teams/${teamId}/custom-roles/${role.id}/assignments/${a.user_id}`);
                                refresh();
                            } catch (e) {
                                Utils.showToast('Revoke failed: ' + e.message, 'error');
                            }
                        },
                    }));
                }
                list.appendChild(li);
            }
            container.appendChild(list);
        }

        if (canManage) {
            // Members not yet assigned this role
            const assigned = new Set(assignments.map(a => a.user_id));
            const eligible = members.filter(m => !assigned.has(m.user_id));

            if (eligible.length > 0) {
                const select = Utils.el('select', { className: 'form-select' });
                for (const m of eligible) {
                    select.appendChild(Utils.el('option', { value: m.user_id, textContent: m.username }));
                }
                const assignBtn = Utils.el('button', {
                    className: 'btn btn-secondary btn-sm',
                    textContent: 'Assign',
                    onClick: async () => {
                        try {
                            await Api.post(`${_api}/teams/${teamId}/custom-roles/${role.id}/assignments`, {
                                user_id: select.value,
                            });
                            refresh();
                        } catch (e) {
                            Utils.showToast('Assign failed: ' + e.message, 'error');
                        }
                    },
                });
                container.appendChild(Utils.el('div', { className: 'team-role-assign-row' }, [select, assignBtn]));
            }
        }
    }

    function _showCreateTeamRoleModal(teamId, flags, refreshFn) {
        const nameInput = Utils.el('input', { type: 'text', className: 'form-input', placeholder: 'Role name' });
        const descInput = Utils.el('input', { type: 'text', className: 'form-input', placeholder: 'Description (optional)' });
        const errorEl = Utils.el('p', { className: 'form-error', textContent: '' });
        errorEl.style.display = 'none';

        const flagChecks = {};
        const flagsDiv = Utils.el('div', { className: 'flag-category' }, [
            Utils.el('div', { className: 'flag-category-label', textContent: 'Move Permissions' }),
        ]);
        for (const flagMeta of flags) {
            const cb = Utils.el('input', { type: 'checkbox' });
            flagChecks[flagMeta.flag] = cb;
            flagsDiv.appendChild(Utils.el('div', { className: 'flag-row' }, [
                cb,
                Utils.el('div', { className: 'flag-label' }, [
                    Utils.el('span', { className: 'flag-name', textContent: flagMeta.flag }),
                    Utils.el('span', { className: 'flag-desc', textContent: flagMeta.description }),
                ]),
            ]));
        }

        // eslint-disable-next-line prefer-const -- forward reference: callbacks capture this before Utils.showModal() assigns it
        let closeModal;
        const createBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Create Role',
            onClick: async () => {
                errorEl.style.display = 'none';
                const name = nameInput.value.trim();
                if (!name) {
                    errorEl.textContent = 'Name is required.';
                    errorEl.style.display = '';
                    return;
                }
                const permissions = {};
                for (const [f, cb] of Object.entries(flagChecks)) {
                    permissions[f] = cb.checked ? '1' : '0';
                }
                try {
                    await Api.post(`${_api}/teams/${teamId}/custom-roles`, {
                        name,
                        description: descInput.value.trim(),
                        permissions,
                    });
                    closeModal();
                    refreshFn();
                } catch (e) {
                    errorEl.textContent = e.message || 'Failed to create role.';
                    errorEl.style.display = '';
                }
            },
        });

        const formContent = Utils.el('div', { className: 'create-role-form' }, [
            Utils.el('label', { textContent: 'Name' }), nameInput,
            Utils.el('label', { textContent: 'Description' }), descInput,
            flagsDiv,
            errorEl,
            Utils.el('div', { className: 'modal-actions' }, [
                createBtn,
                Utils.el('button', {
                    className: 'btn btn-secondary',
                    textContent: 'Cancel',
                    onClick: () => closeModal(),
                }),
            ]),
        ]);

        closeModal = Utils.showModal('Create Custom Role', formContent);
    }

    function _buildMemberNameCellParts(m) {
        const parts = [document.createTextNode(m.username)];
        if (m.key_delivery_pending) {
            parts.push(Utils.el('span', {
                className: 'badge badge-warn',
                textContent: 'awaiting key',
                title: 'Team key not yet delivered — will be fulfilled when an existing member next logs in',
            }));
        }
        if (m.key_confirmed === false) {
            parts.push(Utils.el('span', {
                className: 'badge badge-muted',
                textContent: 'confirming',
                title: 'Member has not yet submitted their Schnorr proof of key possession',
            }));
        }
        return parts;
    }

    function _buildMemberActions(m, { isOwner, isSupervisor, isSelf, isTargetOwner, ownerCount, allowMultiOwner, teamId, container }) {
        const actions = [];
        if (isOwner && !isSelf) {
            const roleOptions = [
                { value: 'team_member',  label: 'Member' },
                { value: 'team_manager', label: 'Supervisor' },
            ];
            if (allowMultiOwner) roleOptions.push({ value: 'team_admin', label: 'Owner' });

            const roleSelect = Utils.el('select', { className: 'input input-xs' });
            for (const opt of roleOptions) {
                const option = Utils.el('option', { value: opt.value, textContent: opt.label });
                if (opt.value === m.role) option.selected = true;
                roleSelect.appendChild(option);
            }
            const applyBtn = Utils.el('button', {
                className: 'btn btn-secondary btn-xs',
                textContent: 'Apply',
                onClick: async () => {
                    const newRole = roleSelect.value;
                    if (newRole === m.role) return;
                    if (isTargetOwner && ownerCount <= 1) {
                        Utils.showToast('Cannot demote the only owner — promote another member first.', 'error');
                        return;
                    }
                    applyBtn.disabled = true;
                    try {
                        await Api.put(`${_api}/teams/${teamId}/members/${m.user_id}`, { role: newRole });
                        Utils.showToast(`${m.username}'s role updated.`, 'success');
                        renderTeamDetailPage(container, teamId);
                    } catch (e) {
                        Utils.showToast('Failed to change role: ' + e.message, 'error');
                        applyBtn.disabled = false;
                    }
                },
            });
            actions.push(Utils.el('span', { className: 'member-role-change' }, [roleSelect, applyBtn]));
        }
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
        return actions;
    }

    function _buildMemberTable(team, members, myRole, teamId, container, allowMultiOwner) {
        const user         = Auth.getCurrentUser();
        const isOwner      = myRole === 'team_admin';
        const isSupervisor = myRole === 'team_manager' || isOwner;
        const ownerCount   = members.filter(m => m.role === 'team_admin').length;

        const thead = Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Username' }),
                Utils.el('th', { textContent: 'Role' }),
                ...(isSupervisor ? [Utils.el('th', { textContent: 'Actions' })] : []),
            ]),
        ]);
        const tbody = Utils.el('tbody');

        for (const m of members) {
            const roleLabel     = { team_admin: 'Owner', team_manager: 'Supervisor', team_member: 'Member' }[m.role] || m.role;
            const isTargetOwner = m.role === 'team_admin';
            const isSelf        = m.user_id === user.id;

            const actions = _buildMemberActions(m, { isOwner, isSupervisor, isSelf, isTargetOwner, ownerCount, allowMultiOwner, teamId, container });

            tbody.appendChild(Utils.el('tr', {}, [
                Utils.el('td', {}, _buildMemberNameCellParts(m)),
                Utils.el('td', { textContent: roleLabel }),
                ...(isSupervisor ? [Utils.el('td', {}, [Utils.el('div', { className: 'member-actions-wrap' }, actions)])] : []),
            ]));
        }

        return Utils.el('table', { className: 'team-member-table' }, [thead, tbody]);
    }

    // =========================================================================
    // Ephemeral invite link — create slot dialog (admin/supervisor side)
    // =========================================================================

    async function _openCreateInviteLinkDialog(teamId) {
        let asymKeys;
        try { asymKeys = _getMyPrivateKeys(); } catch (e) {
            Utils.showToast(e.message, 'error');
            return;
        }

        const overlay = _createModalOverlay();
        const modal   = Utils.el('div', { className: 'modal' });
        modal.appendChild(Utils.el('h3', { textContent: 'Create Invite Link' }));
        modal.appendChild(Utils.el('p', {
            className: 'form-error',
            textContent: 'Warning: this link contains key material in the URL fragment and will be ' +
                         'visible in browser history. Share only via a secure channel. The link is ' +
                         'one-time use and expires after 24 hours.',
        }));

        const statusEl = Utils.el('p', { textContent: 'Generating invite link…' });
        modal.appendChild(statusEl);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        try {
            // Unwrap sk_team
            const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
            const { sk_bytes: skBytes } = await unwrapTeamKey( // NOSONAR — async function defined in same IIFE scope
                myKeyEntry, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
            );

            // Generate k_ephemeral (256-bit, never sent to server)
            const kRaw = crypto.getRandomValues(new Uint8Array(32));
            const kKey = await crypto.subtle.importKey(
                'raw', kRaw, { name: 'AES-GCM' }, false, ['encrypt']
            );

            // Encrypt sk_team with k_ephemeral
            const iv        = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kKey, skBytes);

            // Create slot on server
            const resp = await Api.post(`${_api}/teams/${teamId}/ephemeral-slots`, {
                sk_wrapped: _bytesToB64(new Uint8Array(encrypted)),
                sk_iv:      _bytesToB64(iv),
            });

            const link = `${globalThis.location.origin}/#/join/${teamId}/${resp.slot_id}/${_bytesToB64url(kRaw)}`;

            statusEl.remove();
            const linkInput = Utils.el('input', {
                type: 'text', className: 'input', readOnly: true, value: link,
            });
            modal.appendChild(linkInput);

            const copyBtn = Utils.el('button', {
                className: 'btn btn-primary btn-sm',
                textContent: 'Copy Link',
                onClick: async () => {
                    try {
                        await navigator.clipboard.writeText(link);
                        copyBtn.textContent = 'Copied!';
                        setTimeout(() => { copyBtn.textContent = 'Copy Link'; }, 2000);
                    } catch {
                        linkInput.select();
                    }
                },
            });
            modal.appendChild(Utils.el('div', { className: 'modal-buttons' }, [
                copyBtn,
                Utils.el('button', {
                    className: 'btn btn-secondary',
                    textContent: 'Close',
                    onClick: () => overlay.remove(),
                }),
            ]));
        } catch (err) {
            statusEl.textContent = 'Failed: ' + err.message;
            modal.appendChild(Utils.el('button', {
                className: 'btn btn-secondary',
                textContent: 'Close',
                onClick: () => overlay.remove(),
            }));
        }
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
                    const { sk_bytes, pk_bytes } = await _generateTeamKey(); // NOSONAR — async function defined in same IIFE scope
                    const wrappedKey = await wrapTeamKeyForMember( // NOSONAR — async function defined in same IIFE scope
                        sk_bytes, myPubs.x25519_public_key, myPubs.mlkem768_public_key
                    );

                    // Fetch escrow agents and pre-wrap sk_team for each
                    let escrow_members = [];
                    try {
                        const agentsResp = await Api.get(`${_api}/teams/escrow-agents`);
                        const agents = agentsResp.escrow_agents || [];
                        for (const agent of agents) {
                            const agentWrap = await wrapTeamKeyForMember( // NOSONAR — async function defined in same IIFE scope
                                sk_bytes, agent.x25519_public_key, agent.mlkem768_public_key
                            );
                            escrow_members.push({
                                user_id:             agent.user_id,
                                ephemeral_x25519_pub: agentWrap.ephemeral_x25519_pub,
                                kem_ciphertext:       agentWrap.kem_ciphertext,
                                encrypted_sk:         agentWrap.encrypted_sk,
                                sk_iv:                agentWrap.sk_iv,
                            });
                        }
                    } catch {
                        // Escrow agents fetch failure is non-fatal; team creates without escrow slots
                        escrow_members = [];
                    }

                    await Api.post(`${_api}/teams`, {
                        name,
                        description: desc,
                        pre_public_key:        _bytesToB64(pk_bytes),
                        ephemeral_x25519_pub:  wrappedKey.ephemeral_x25519_pub,
                        kem_ciphertext:        wrappedKey.kem_ciphertext,
                        encrypted_sk:          wrappedKey.encrypted_sk,
                        sk_iv:                 wrappedKey.sk_iv,
                        escrow_members,
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
        roleSelect.appendChild(Utils.el('option', { value: 'team_manager', textContent: 'Supervisor' }));
        modal.appendChild(usernameInput);
        modal.appendChild(roleSelect);

        // Populate custom roles asynchronously
        Api.get(`${_api}/teams/${teamId}/custom-roles`).then(data => {
            (data.roles || []).forEach(r => {
                roleSelect.appendChild(Utils.el('option', { value: r.id, textContent: r.name }));
            });
        }).catch(() => { /* non-critical; built-in roles still available */ });

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
                errEl.textContent = '';

                const _setStatus = (msg) => {
                    inviteBtn.textContent = msg;
                    console.log('[tusShare invite]', msg);
                };

                try {
                    // Step 1: get private keys from memory
                    _setStatus('Step 1/5: getting private keys…');
                    const privKeys = _getMyPrivateKeys();
                    console.log('[tusShare invite] private keys present:', !!privKeys.x25519PrivateKey, !!privKeys.mlkem768SecretKey,
                        'sk length:', privKeys.mlkem768SecretKey?.length);

                    // Step 2: fetch my wrapped team key from server
                    _setStatus('Step 2/5: fetching my team key…');
                    const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
                    console.log('[tusShare invite] my key entry fields:', Object.keys(myKeyEntry),
                        'ct len:', myKeyEntry.kem_ciphertext?.length,
                        'ephem len:', myKeyEntry.ephemeral_x25519_pub?.length,
                        'enc_sk len:', myKeyEntry.encrypted_sk?.length,
                        'sk_iv len:', myKeyEntry.sk_iv?.length);

                    // Step 3: unwrap sk_team using my private keys
                    _setStatus('Step 3/5: unwrapping team key…');
                    const { sk_bytes } = await unwrapTeamKey( // NOSONAR — async function defined in same IIFE scope
                        myKeyEntry,
                        privKeys.x25519PrivateKey,
                        privKeys.mlkem768SecretKey
                    );
                    console.log('[tusShare invite] team key unwrapped, sk_bytes length:', sk_bytes?.length);

                    // Step 4: fetch recipient public keys
                    _setStatus('Step 4/5: fetching recipient keys…');
                    const recipientPub = await Api.get(
                        `${Config.app.apiPrefix}/auth/users/${encodeURIComponent(username)}/public-keys`
                    );
                    if (!recipientPub.x25519_public_key || !recipientPub.mlkem768_public_key) {
                        throw new Error('User has not set up sharing keys yet');
                    }
                    console.log('[tusShare invite] recipient pub key lengths — x25519:', recipientPub.x25519_public_key?.length,
                        'mlkem768:', recipientPub.mlkem768_public_key?.length);

                    // Step 5: wrap sk_team for recipient and POST
                    _setStatus('Step 5/5: wrapping and sending…');
                    const wrappedKey = await wrapTeamKeyForMember( // NOSONAR — async function defined in same IIFE scope
                        sk_bytes,
                        recipientPub.x25519_public_key,
                        recipientPub.mlkem768_public_key
                    );

                    const builtInRoles = new Set(['team_member', 'team_manager']);
                    const isCustomRole = !builtInRoles.has(role);
                    const baseRole = isCustomRole ? 'team_member' : role;

                    const inviteResult = await Api.post(`${_api}/teams/${teamId}/members`, {
                        username,
                        role: baseRole,
                        ...wrappedKey,
                    });

                    if (isCustomRole) {
                        await Api.post(
                            `${_api}/teams/${teamId}/custom-roles/${encodeURIComponent(role)}/assignments`,
                            { user_id: inviteResult.user_id },
                        );
                    }

                    overlay.remove();
                    Utils.showToast(`${username} invited`, 'success');
                    renderTeamDetailPage(refreshContainer, teamId);
                } catch (err) {
                    console.error('[tusShare invite] FAILED:', err.message);
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
                        const entry  = await encryptFileKeyForTeam( // NOSONAR — async function defined in same IIFE scope
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

    /**
     * Perform a PRE key rotation — headless (no UI).
     * Called by _triggerRotation (interactive) and _processPendingTeamOperations (background).
     *
     * @param {string} teamId
     * @param {{ x25519PrivateKey: CryptoKey, mlkem768SecretKey: Uint8Array }} asymKeys
     * @param {(msg: string) => void} [onProgress]  Optional progress callback.
     */
    async function _performRotation(teamId, asymKeys, onProgress) {
        const prog = onProgress || (() => {});

        // 1. Unwrap current sk_team
        prog('Unwrapping team key…');
        const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
        const { sk_bytes: skOldBytes } = await unwrapTeamKey( // NOSONAR — async function defined in same IIFE scope
            myKeyEntry, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
        );

        // 2. Generate new keypair; compute rk scalar and rk_point
        prog('Generating new key pair…');
        const { sk_bytes: skNewBytes, pk_bytes: pkNewBytes } = await _generateTeamKey(); // NOSONAR — async function defined in same IIFE scope
        const rk         = computeRKScalar(skOldBytes, skNewBytes);
        const rkPointB64 = await _computeRkPoint(rk); // NOSONAR — async function defined in same IIFE scope

        // 3. Fetch all file keys, re-encrypt, generate DLEQ proofs
        prog('Fetching file keys…');
        const fkData     = await Api.get(`${_api}/teams/${teamId}/file-keys`);
        const oldFileKeys = fkData.file_keys || [];

        prog(`Re-encrypting ${oldFileKeys.length} file key(s)…`);
        const updatedFileKeys = [];
        for (let i = 0; i < oldFileKeys.length; i++) {
            const fk      = oldFileKeys[i];
            const c1NewB64 = await applyPRERotation(fk.pre_c1, rk); // NOSONAR — async function defined in same IIFE scope
            const proof    = await _generateDleqProof(rk, fk.pre_c1, rkPointB64, c1NewB64); // NOSONAR — async function defined in same IIFE scope
            updatedFileKeys.push({ file_id: fk.file_id, pre_c1: c1NewB64, ...proof });
            if (i % 50 === 49) {
                prog(`Re-encrypting… ${i + 1}/${oldFileKeys.length}`);
                await new Promise(res => setTimeout(res, 0)); // yield to UI
            }
        }

        // 4. Wrap sk_new for each remaining member
        prog('Wrapping new key for members…');
        const memberData   = await Api.get(`${_api}/teams/${teamId}/members`);
        const wrappedMembers = [];
        for (const m of memberData.members || []) {
            const pub = await Api.get(
                `${Config.app.apiPrefix}/auth/users/${encodeURIComponent(m.username)}/public-keys`
            );
            const wrapped = await wrapTeamKeyForMember( // NOSONAR — async function defined in same IIFE scope
                skNewBytes, pub.x25519_public_key, pub.mlkem768_public_key
            );
            wrappedMembers.push({ user_id: m.user_id, ...wrapped });
        }

        // 5. Submit rotation
        prog('Committing rotation…');
        await Api.post(`${_api}/teams/${teamId}/rotate`, {
            pre_public_key_new: _bytesToB64(pkNewBytes),
            rk_point:           rkPointB64,
            file_keys:          updatedFileKeys,
            members:            wrappedMembers,
        });

        return _bytesToB64(pkNewBytes);
    }

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
            await _performRotation(teamId, asymKeys, msg => { statusEl.textContent = msg; });
            statusEl.remove();
            Utils.showToast('Key rotation complete', 'success');
            renderTeamDetailPage(refreshContainer, teamId);
        } catch (err) {
            statusEl.textContent = 'Rotation failed: ' + err.message;
            Utils.showToast('Rotation failed: ' + err.message, 'error');
        }
    }

    /**
     * Fulfil pending policy-granted key slots for a team.
     *
     * Fetches all policy_team_grants where key_wrapped=0 on this team, unwraps
     * our own sk_team, wraps it for each pending user's public keys, and submits.
     * Users with no asymmetric keys yet are silently skipped by the server.
     *
     * This is NOT a rotation — sk_team does not change.
     *
     * @param {string} teamId
     * @param {{ x25519PrivateKey: CryptoKey, mlkem768SecretKey: Uint8Array }} asymKeys
     */
    async function _fulfillPendingKeyGrants(teamId, asymKeys) {
        const data = await Api.get(`${_api}/teams/${teamId}/pending-key-grants`);
        const pending = data.pending_grants || [];
        if (pending.length === 0) return;

        // Unwrap our sk_team
        const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
        const { sk_bytes: skBytes } = await unwrapTeamKey( // NOSONAR — async function defined in same IIFE scope
            myKeyEntry, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
        );

        // Wrap sk_team for each pending grantee
        const grants = [];
        for (const grant of pending) {
            if (!grant.x25519_public_key || !grant.mlkem768_public_key) continue;
            const wrapped = await wrapTeamKeyForMember( // NOSONAR — async function defined in same IIFE scope
                skBytes, grant.x25519_public_key, grant.mlkem768_public_key
            );
            grants.push({ grant_id: grant.grant_id, user_id: grant.user_id, ...wrapped });
        }

        if (grants.length === 0) return;

        await Api.post(`${_api}/teams/${teamId}/pending-key-grants/complete`, { grants });
        console.log(`[teams] fulfilled ${grants.length} pending key grant(s) for team ${teamId}`);
    }

    /**
     * Submit a Schnorr PoK proving we hold sk_new for a team.
     *
     * Called post-rotation when my_key_confirmed=false.  Unwraps our user_team_keys
     * entry, generates a Schnorr PoK on G2, and POSTs to /key-confirmation.
     *
     * Protocol (must match server verify_schnorr_pok in bls_verify.py):
     *   r  = random Fr scalar
     *   R  = r × G2_base  (96 bytes compressed)
     *   c  = SHA-256(pk_new_96bytes ‖ R_96bytes) mod Fr
     *   s  = r - c × sk_new  (mod Fr)
     *
     * @param {string} teamId
     * @param {string} pkNewB64  Base64 G2 point — team's current pre_public_key.
     * @param {{ x25519PrivateKey: CryptoKey, mlkem768SecretKey: Uint8Array }} asymKeys
     */
    async function _submitSchnorrPoK(teamId, pkNewB64, asymKeys) {
        // Unwrap sk_new from our key slot
        const myKeyEntry = await Api.get(`${_api}/teams/${teamId}/my-key`);
        const { sk_bigint: skBigInt } = await unwrapTeamKey( // NOSONAR — async function defined in same IIFE scope
            myKeyEntry, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
        );

        const bls    = await _getBLS();
        const G2base = bls.G2.Point.BASE;

        // r ∈ Fr (random)
        const rRaw = crypto.getRandomValues(new Uint8Array(32));
        const r    = BigInt('0x' + _bytesToHex(rRaw)) % _BLS_ORDER;

        // R = r × G2  (96 bytes compressed)
        const RBytes = G2base.multiply(r).toBytes(true);

        // pk_new raw bytes (96 bytes)
        const pkNewBytes = _b64ToBytes(pkNewB64);

        // c = SHA-256(pk_new ‖ R) mod Fr
        const msg = new Uint8Array(192);
        msg.set(pkNewBytes, 0);
        msg.set(RBytes, 96);
        const cHash = await crypto.subtle.digest('SHA-256', msg);
        const c = BigInt('0x' + _bytesToHex(new Uint8Array(cHash))) % _BLS_ORDER;

        // s = r - c × sk_new  (mod Fr)
        const s = _frSub(r, _frMul(c, skBigInt));

        await Api.post(`${_api}/teams/${teamId}/key-confirmation`, {
            schnorr_R: _bytesToB64(RBytes),
            schnorr_s: _bytesToB64(_bigintTo32Bytes(s)),
        });
        console.log(`[teams] Schnorr PoK submitted for team ${teamId}`);
    }

    /**
     * Background hook — fires after login once private keys are in memory.
     *
     * Handles:
     *   (a) Teams with rotation_pending=1: any member silently executes the rotation.
     *   (b) Teams with has_pending_key_grants: fulfil sk_team delivery for policy grantees.
     *   (c) Teams with my_key_confirmed=false: submit Schnorr PoK for this member's slot.
     */
    async function _processOneTeamOps(team, asymKeys) {
        // pre_public_key may be updated by a rotation below — track any new value so the PoK
        // hash is computed against the current server key, not the stale value from the teams list.
        let currentPkB64 = team.pre_public_key;
        if (team.rotation_pending) {
            try {
                currentPkB64 = await _performRotation(team.id, asymKeys);
                console.log(`[teams] background rotation complete for team ${team.id}`);
            } catch (err) {
                console.warn(`[teams] background rotation failed for team ${team.id}:`, err.message);
            }
        }
        if (team.has_pending_key_grants) {
            try {
                await _fulfillPendingKeyGrants(team.id, asymKeys);
            } catch (err) {
                console.warn(`[teams] key grant fulfillment failed for team ${team.id}:`, err.message);
            }
        }
        if (team.my_key_confirmed === false) {
            try {
                await _submitSchnorrPoK(team.id, currentPkB64, asymKeys);
            } catch (err) {
                console.warn(`[teams] Schnorr PoK failed for team ${team.id}:`, err.message);
            }
        }
    }

    async function _processPendingTeamOperations() {
        let asymKeys;
        try { asymKeys = _getMyPrivateKeys(); } catch { return; }

        let teams;
        try {
            const data = await Api.get(`${_api}/teams`);
            teams = data.teams || [];
        } catch { return; }

        for (const team of teams) {
            await _processOneTeamOps(team, asymKeys);
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
        const { sk_bigint } = await unwrapTeamKey( // NOSONAR — async function defined in same IIFE scope
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
    // Team Folders page
    // =========================================================================

    function _buildFolderListTable(folderItems) {
        let sortKey = 'folderName', sortAsc = true;
        const tbody = Utils.el('tbody');

        function _renderRows() {
            tbody.innerHTML = '';
            const sorted = [...folderItems].sort((a, b) => {
                const av = a[sortKey] ?? '', bv = b[sortKey] ?? '';
                const cmp = String(av).localeCompare(String(bv));
                return sortAsc ? cmp : -cmp;
            });
            for (const item of sorted) {
                tbody.appendChild(Utils.el('tr', { dataset: { name: `${item.teamName} ${item.folderName}`.toLowerCase() } }, [
                    Utils.el('td', {}, [Utils.el('a', {
                        href: `#/team-folders/${item.folderId}`,
                        className: 'teams-list-link',
                        textContent: item.folderName,
                    })]),
                    Utils.el('td', { textContent: item.teamName }),
                    Utils.el('td', { textContent: item.ownerLabel }),
                ]));
            }
        }

        const thead = Utils.el('thead');
        const cols = [
            { label: 'Folder Name', key: 'folderName' },
            { label: 'Team',        key: 'teamName' },
            { label: 'Owner',       key: 'ownerLabel' },
        ];
        const headerRow = Utils.el('tr');
        for (const col of cols) {
            const th = Utils.el('th', { textContent: col.label, dataset: { key: col.key } });
            th.addEventListener('click', () => {
                if (sortKey === col.key) { sortAsc = !sortAsc; }
                else { sortKey = col.key; sortAsc = true; }
                for (const el of thead.querySelectorAll('th')) el.dataset.sort = '';
                th.dataset.sort = sortAsc ? 'asc' : 'desc';
                _renderRows();
            });
            headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);
        _renderRows();

        return Utils.el('table', { className: 'team-list-table' }, [thead, tbody]);
    }

    async function renderTeamFoldersPage(container) {
        _clearEl(container);
        container.appendChild(Utils.el('div', { className: 'empty-state', textContent: 'Loading team folders…' }));

        try {
            const [teamsData, prefsData] = await Promise.all([
                Api.get(`${_api}/teams`),
                Api.get(`${_api}/auth/me/prefs`).catch(() => ({ ui_prefs: {} })),
            ]);
            const teams = teamsData.teams || [];
            const savedView = prefsData.ui_prefs?.team_folders_view || 'tile';

            if (teams.length === 0) {
                _clearEl(container);
                container.appendChild(Utils.el('div', { className: 'empty-state', textContent: 'You are not a member of any teams.' }));
                return;
            }

            const details = await Promise.all(teams.map(t => Api.get(`${_api}/teams/${t.id}`)));

            // Flatten to one entry per folder
            const folderItems = [];
            for (const detail of details) {
                const members = detail.members || [];
                const teamName = detail.team.name;
                const teamDesc = detail.team.description || '';
                const ownerMember = members.find(m => m.user_id === detail.team.owner_id);
                const ownerLabel = ownerMember ? ownerMember.username : detail.team.owner_id;
                for (const f of detail.folders || []) {
                    folderItems.push({ folderId: f.folder_id, folderName: f.folder_name, teamName, ownerLabel, teamDesc });
                }
            }

            _clearEl(container);
            const page = Utils.el('div', { className: 'page-content' });

            let view = savedView;
            const { tileBtn, listBtn } = _makeViewToggle(view === 'tile');

            const header = Utils.el('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:8px' });
            header.appendChild(Utils.el('div', { style: 'display:flex;align-items:center;gap:24px' }, [
                Utils.el('h2', { textContent: 'Team Folders', style: 'margin:0' }),
                Utils.el('div', { style: 'display:flex;align-items:center;gap:4px' }, [tileBtn, listBtn]),
            ]));
            page.appendChild(header);

            const filterInput = Utils.el('input', {
                type: 'text',
                className: 'input-sm',
                placeholder: 'Search folders…',
                style: 'width:240px;margin-bottom:16px',
            });
            page.appendChild(filterInput);

            const contentEl = Utils.el('div');
            page.appendChild(contentEl);

            function _renderContent() {
                contentEl.innerHTML = '';
                if (folderItems.length === 0) {
                    contentEl.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No folders have been added to your teams yet.' }));
                    return;
                }
                if (view === 'list') {
                    const table = _buildFolderListTable(folderItems);
                    contentEl.appendChild(table);
                    filterInput.oninput = () => {
                        const q = filterInput.value.toLowerCase();
                        for (const row of table.querySelectorAll('tbody tr')) {
                            row.style.display = !q || (row.dataset.name || '').includes(q) ? '' : 'none';
                        }
                    };
                } else {
                    const grid = Utils.el('div', { className: 'team-list', style: 'padding:4px 0' });
                    for (const item of folderItems) {
                        const tile = Utils.el('a', {
                            href: `#/team-folders/${item.folderId}`,
                            className: 'team-card team-card-link',
                            dataset: { name: `${item.teamName} ${item.folderName}` },
                        });
                        tile.appendChild(Utils.el('div', { className: 'team-card-header' }, [
                            Utils.el('span', { className: 'team-card-name', textContent: item.folderName }),
                        ]));
                        const descParts = [`Owner: ${item.ownerLabel}`];
                        if (item.teamDesc) descParts.push(item.teamDesc);
                        tile.appendChild(Utils.el('p', { className: 'team-card-desc', textContent: descParts.join(' — ') }));
                        grid.appendChild(tile);
                    }
                    contentEl.appendChild(grid);
                    filterInput.oninput = () => {
                        const q = filterInput.value.toLowerCase();
                        for (const card of grid.querySelectorAll('.team-card')) {
                            card.style.display = !q || (card.dataset.name || '').toLowerCase().includes(q) ? '' : 'none';
                        }
                    };
                }
                filterInput.value = '';
            }

            tileBtn.addEventListener('click', () => {
                if (view === 'tile') return;
                view = 'tile';
                tileBtn.classList.add('active');
                listBtn.classList.remove('active');
                _renderContent();
                Api.patch(`${_api}/auth/me/prefs`, { team_folders_view: 'tile' }).catch(() => {});
            });
            listBtn.addEventListener('click', () => {
                if (view === 'list') return;
                view = 'list';
                listBtn.classList.add('active');
                tileBtn.classList.remove('active');
                _renderContent();
                Api.patch(`${_api}/auth/me/prefs`, { team_folders_view: 'list' }).catch(() => {});
            });

            _renderContent();
            container.appendChild(page);
        } catch (err) {
            _clearEl(container);
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'Failed to load team folders: ' + err.message }));
        }
    }

    // =========================================================================
    // Ephemeral invite link — join page (new member side)
    // =========================================================================

    /**
     * Execute the ephemeral join rotation and submit.
     *
     * The caller has already decrypted sk_old from the slot using k_ephemeral.
     * This function generates sk_new, re-encrypts all file C1s, wraps sk_new for
     * all current members + self, and POSTs to /ephemeral-join.
     *
     * @param {string} teamId
     * @param {string} slotId
     * @param {Uint8Array} skOldBytes  — sk_team decrypted from slot
     * @param {{ x25519PrivateKey: CryptoKey, mlkem768SecretKey: Uint8Array }} asymKeys
     * @param {(msg: string) => void} [onProgress]
     */
    async function _performEphemeralJoin(teamId, slotId, skOldBytes, asymKeys, onProgress) {
        const prog = onProgress || (() => {});

        // 1. Generate new keypair; compute rk scalar and rk_point
        prog('Generating new key pair…');
        const { sk_bytes: skNewBytes, pk_bytes: pkNewBytes } = await _generateTeamKey(); // NOSONAR — async function defined in same IIFE scope
        const rk         = computeRKScalar(skOldBytes, skNewBytes);
        const rkPointB64 = await _computeRkPoint(rk); // NOSONAR — async function defined in same IIFE scope

        // 2. Fetch all file keys for this team, re-encrypt, generate DLEQ proofs
        prog('Fetching file keys…');
        const fkData      = await Api.get(`${_api}/teams/${teamId}/file-keys`);
        const oldFileKeys = fkData.file_keys || [];

        prog(`Re-encrypting ${oldFileKeys.length} file key(s)…`);
        const updatedFileKeys = [];
        for (let i = 0; i < oldFileKeys.length; i++) {
            const fk       = oldFileKeys[i];
            const c1NewB64 = await applyPRERotation(fk.pre_c1, rk); // NOSONAR — async function defined in same IIFE scope
            const proof    = await _generateDleqProof(rk, fk.pre_c1, rkPointB64, c1NewB64); // NOSONAR — async function defined in same IIFE scope
            updatedFileKeys.push({ file_id: fk.file_id, pre_c1: c1NewB64, ...proof });
            if (i % 50 === 49) {
                prog(`Re-encrypting… ${i + 1}/${oldFileKeys.length}`);
                await new Promise(res => setTimeout(res, 0));
            }
        }

        // 3. Wrap sk_new for all current members
        prog('Wrapping new key for members…');
        const memberData     = await Api.get(`${_api}/teams/${teamId}/members`);
        const wrappedMembers = [];
        for (const m of memberData.members || []) {
            const pub = await Api.get(
                `${Config.app.apiPrefix}/auth/users/${encodeURIComponent(m.username)}/public-keys`
            );
            const wrapped = await wrapTeamKeyForMember( // NOSONAR — async function defined in same IIFE scope
                skNewBytes, pub.x25519_public_key, pub.mlkem768_public_key
            );
            wrappedMembers.push({ user_id: m.user_id, ...wrapped });
        }

        // 4. Wrap sk_new for ourselves (joining user is not yet in members list)
        const myPubs      = _getMyPublicKeys();
        const selfWrapped = await wrapTeamKeyForMember( // NOSONAR — async function defined in same IIFE scope
            skNewBytes, myPubs.x25519_public_key, myPubs.mlkem768_public_key
        );
        wrappedMembers.push({ user_id: Auth.getCurrentUser().id, ...selfWrapped });

        // 5. Submit ephemeral join
        prog('Committing join…');
        await Api.post(`${_api}/teams/${teamId}/ephemeral-join`, {
            slot_id:            slotId,
            pre_public_key_new: _bytesToB64(pkNewBytes),
            rk_point:           rkPointB64,
            file_keys:          updatedFileKeys,
            members:            wrappedMembers,
        });
    }

    /**
     * Render the ephemeral invite join page.
     *
     * Invoked by app.js when the user navigates to #/join/{teamId}/{slotId}/{kB64url}.
     * If the user is not authenticated, saves the hash to sessionStorage and redirects
     * to #/login; auth.js restores it after a successful login.
     *
     * @param {HTMLElement} container
     * @param {string} teamId
     * @param {string} slotId
     * @param {string} kEphemeralB64url  — 256-bit AES key, base64url encoded, from URL fragment
     */
    async function renderEphemeralJoinPage(container, teamId, slotId, kEphemeralB64url) {
        _clearEl(container);

        // Require authentication — save intent and redirect to login if not signed in
        if (!Auth.getCurrentUser()) {
            sessionStorage.setItem('pendingJoinHash', globalThis.location.hash);
            globalThis.location.hash = '#/login';
            return;
        }

        container.appendChild(Utils.el('h2', { textContent: 'Joining Team via Invite Link' }));
        const statusEl = Utils.el('p', { className: 'join-status', textContent: 'Fetching invite slot…' });
        container.appendChild(statusEl);

        try {
            // 1. Fetch slot from server (not consumed yet — read-only GET)
            const slot = await Api.get(`${_api}/teams/${teamId}/ephemeral-slots/${slotId}`);

            statusEl.textContent = 'Decrypting invite…';

            // 2. Decode k_ephemeral from URL fragment and import as AES-GCM key
            const kBytes = _b64urlToBytes(kEphemeralB64url);
            const kKey   = await crypto.subtle.importKey(
                'raw', kBytes, { name: 'AES-GCM' }, false, ['decrypt']
            );

            // 3. Decrypt sk_wrapped → sk_old (plaintext sk_team)
            const skWrappedBytes = _b64ToBytes(slot.sk_wrapped);
            const ivBytes        = _b64ToBytes(slot.sk_iv);
            const skOldBytes     = new Uint8Array(
                await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, kKey, skWrappedBytes)
            );

            // 4. Need private keys to wrap sk_new for self
            let asymKeys;
            try { asymKeys = _getMyPrivateKeys(); } catch (e) {
                throw new Error('Encryption keys are not ready — try again in a moment. (' + e.message + ')');
            }

            // 5. Perform join rotation and submit
            await _performEphemeralJoin(teamId, slotId, skOldBytes, asymKeys,
                msg => { statusEl.textContent = msg; });

            statusEl.textContent = 'Joined! Redirecting…';
            Utils.showToast('You have joined the team.', 'success');
            globalThis.location.hash = `#/teams/${teamId}`;
        } catch (err) {
            statusEl.textContent = '';
            container.appendChild(Utils.el('div', {
                className: 'alert alert-error',
                textContent: 'Failed to join team: ' + err.message,
            }));
            container.appendChild(Utils.el('a', {
                href: '#/teams',
                className: 'btn btn-secondary btn-sm',
                textContent: 'Back to Teams',
            }));
        }
    }

    // =========================================================================
    // Public API
    // =========================================================================

    return {
        renderTeamsPage,
        renderTeamDetailPage,
        renderTeamFoldersPage,
        renderEphemeralJoinPage,
        openAddToTeamDialog,
        decryptTeamFileKey,
        processPendingTeamOperations: _processPendingTeamOperations,
        // Exposed for tests / other modules
        encryptFileKeyForTeam,
        decryptFileKeyFromTeam,
        wrapTeamKeyForMember,
        unwrapTeamKey,
        // PRE scalar helpers — used by files.js for cross-team copy
        computeRKScalar,
        applyPRERotation,
    };
})();
