/**
 * tusShare — Shared utility functions.
 */
const Utils = (() => {
    /**
     * Format bytes to human-readable string.
     */
    function formatBytes(bytes, decimals = 1) {
        if (bytes === 0 || bytes == null) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
    }

    /**
     * Format ISO date string to local readable format.
     */
    function formatDate(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    /**
     * Relative time ago string.
     */
    function timeAgo(iso) {
        if (!iso) return '';
        const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
        if (seconds < Config.time.minute) return 'just now';
        if (seconds < Config.time.hour) return Math.floor(seconds / Config.time.minute) + 'm ago';
        if (seconds < Config.time.day) return Math.floor(seconds / Config.time.hour) + 'h ago';
        if (seconds < Config.time.week) return Math.floor(seconds / Config.time.day) + 'd ago';
        return formatDate(iso);
    }

    const _BOOL_PROPS = new Set(['checked', 'disabled', 'readOnly', 'selected']);

    function _applyDatasetAttr(elem, val) {
        for (const [dk, dv] of Object.entries(val)) {
            elem.dataset[dk] = dv;
        }
    }

    function _applyStyleAttr(elem, val) {
        for (const decl of String(val).split(';')) {
            const sep = decl.indexOf(':');
            if (sep < 1) continue;
            const prop = decl.slice(0, sep).trim();
            const value = decl.slice(sep + 1).trim();
            if (prop) elem.style.setProperty(prop, value);
        }
    }

    /**
     * Create a DOM element with attributes and children.
     */
    function el(tag, attrs = {}, children = []) {
        const elem = document.createElement(tag);
        for (const [key, val] of Object.entries(attrs)) {
            if (key === 'className') {
                elem.className = val;
            } else if (key === 'textContent') {
                elem.textContent = val;
            } else if (key.startsWith('on') && typeof val === 'function') {
                elem.addEventListener(key.slice(2).toLowerCase(), val);
            } else if (key === 'dataset') {
                _applyDatasetAttr(elem, val);
            } else if (_BOOL_PROPS.has(key)) {
                elem[key] = val;
            } else if (key === 'style') {
                _applyStyleAttr(elem, val);
            } else {
                elem.setAttribute(key, val);
            }
        }
        for (const child of (Array.isArray(children) ? children : [children])) {
            if (typeof child === 'string') {
                elem.appendChild(document.createTextNode(child));
            } else if (child instanceof Node) {
                elem.appendChild(child);
            }
        }
        return elem;
    }

    /**
     * Toast notification system — history, unread tracking, and auto-dismiss.
     */
    let _toastContainer = null;
    const _toastHistory = [];   // { message, type, timestamp } — session-scoped
    let _unreadCount = 0;
    let _unreadListener = null; // single listener (app.js header dot)

    function _notifyUnread() {
        if (_unreadListener) _unreadListener(_unreadCount);
    }

    function _ensureToastContainer() {
        if (!_toastContainer) {
            _toastContainer = el('div', {
                className: 'toast-container',
                role: 'status',
                'aria-live': 'polite',
                'aria-atomic': 'false',
            });
            document.body.appendChild(_toastContainer);
        }
        return _toastContainer;
    }

    function showToast(message, type = 'info') {
        _toastHistory.push({ message, type, timestamp: new Date() });
        _unreadCount++;
        _notifyUnread();

        const container = _ensureToastContainer();
        const dismiss = el('button', {
            className: 'toast-dismiss',
            type: 'button',
            'aria-label': 'Dismiss',
            textContent: '×',
        });
        const toast = el('div', { className: `toast toast-${type}` }, [
            el('span', { className: 'toast-message', textContent: message }),
            dismiss,
        ]);

        let autoTimer = null;
        const fadeAndRemove = () => {
            clearTimeout(autoTimer);
            toast.classList.remove('toast-visible');
            setTimeout(() => {
                if (toast.parentNode) toast.remove();
            }, Config.ui.toastFadeOutMs);
        };

        dismiss.addEventListener('click', fadeAndRemove);
        if (Config.ui.toastAutoHideMs > 0) {
            autoTimer = setTimeout(fadeAndRemove, Config.ui.toastAutoHideMs);
        }

        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('toast-visible'));
    }

    function getToastHistory() { return _toastHistory.slice(); }
    function getUnreadCount()  { return _unreadCount; }
    function markAllRead()     { _unreadCount = 0; _notifyUnread(); }
    function onUnreadChange(fn) { _unreadListener = fn; }
    function clearToastHistory() {
        _toastHistory.length = 0;
        _unreadCount = 0;
        _unreadListener = null;
        _notifyUnread();
    }

    let _modalIdCounter = 0;
    const _FOCUSABLE_SEL = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

    function _lockBackground()   { document.getElementById('app')?.setAttribute('inert', ''); }
    function _unlockBackground() { document.getElementById('app')?.removeAttribute('inert'); }

    function _trapFocus(dialogEl) {
        const handler = (e) => {
            if (e.key !== 'Tab') return;
            const focusable = [...dialogEl.querySelectorAll(_FOCUSABLE_SEL)];
            if (!focusable.length) { e.preventDefault(); return; }
            const first = focusable[0];
            const last  = focusable.at(-1);
            if (e.shiftKey) {
                if (document.activeElement === first) { e.preventDefault(); last.focus(); }
            } else if (document.activeElement === last) {
                e.preventDefault(); first.focus();
            }
        };
        dialogEl.addEventListener('keydown', handler);
        return () => dialogEl.removeEventListener('keydown', handler);
    }

    /**
     * Confirmation dialog — returns Promise<boolean>.
     */
    function showConfirm(message) {
        return new Promise((resolve) => {
            const labelId   = `modal-label-${++_modalIdCounter}`;
            const prevFocus = document.activeElement;
            let releaseTrap = () => {};
            let overlay = el('div', { className: 'modal-overlay' });
            const dismiss = (result) => {
                releaseTrap();
                _unlockBackground();
                if (overlay?.parentNode) overlay.remove();
                overlay = null;
                resolve(result);
                prevFocus?.focus();
            };
            overlay.addEventListener('keydown', (e) => { if (e.key === 'Escape') dismiss(false); });
            const cancelBtn = el('button', {
                className: 'btn btn-secondary',
                textContent: 'Cancel',
                onClick: () => dismiss(false),
            });
            const dialog = el('div', {
                className: 'modal confirm-dialog',
                role: 'dialog',
                'aria-modal': 'true',
                'aria-labelledby': labelId,
            }, [
                el('p', { id: labelId, textContent: message }),
                el('div', { className: 'modal-actions' }, [
                    cancelBtn,
                    el('button', {
                        className: 'btn btn-danger',
                        textContent: 'Confirm',
                        onClick: () => dismiss(true),
                    }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
            _lockBackground();
            releaseTrap = _trapFocus(dialog);
            cancelBtn.focus();
        });
    }

    /**
     * Prompt dialog with a text input — returns Promise<string|null>.
     */
    function showPrompt(title, placeholder = '') {
        return new Promise((resolve) => {
            const labelId   = `modal-label-${++_modalIdCounter}`;
            const prevFocus = document.activeElement;
            let releaseTrap = () => {};
            let overlay = el('div', { className: 'modal-overlay' });
            const dismiss = (result) => { // NOSONAR — identical shape to showConfirm.dismiss but closes over this function's overlay
                releaseTrap();
                _unlockBackground();
                if (overlay?.parentNode) overlay.remove();
                overlay = null;
                resolve(result);
                prevFocus?.focus();
            };
            const input = el('input', {
                className: 'prompt-dialog-input',
                type: 'text',
                placeholder,
            });
            const submit = () => {
                const val = input.value.trim();
                dismiss(val || null);
            };
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') submit();
                if (e.key === 'Escape') dismiss(null);
            });
            const dialog = el('div', {
                className: 'modal prompt-dialog',
                role: 'dialog',
                'aria-modal': 'true',
                'aria-labelledby': labelId,
            }, [
                el('h3', { id: labelId, textContent: title }),
                input,
                el('div', { className: 'modal-actions' }, [
                    el('button', {
                        className: 'btn btn-secondary',
                        textContent: 'Cancel',
                        onClick: () => dismiss(null),
                    }),
                    el('button', {
                        className: 'btn btn-primary',
                        textContent: 'Create',
                        onClick: submit,
                    }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
            _lockBackground();
            releaseTrap = _trapFocus(dialog);
            input.focus();
        });
    }

    /**
     * Generic content modal — displays arbitrary DOM content in an overlay.
     * Returns a close function.  Also exposed as Utils.closeModal() for callers
     * that don't have a reference to the returned close function.
     */
    let _activeModal = null;

    function showModal(title, contentEl) {
        closeModal();  // Dismiss any existing modal first
        const labelId   = `modal-label-${++_modalIdCounter}`;
        const prevFocus = document.activeElement;
        let releaseTrap = () => {};
        let overlay = el('div', { className: 'modal-overlay' });
        const close = () => {
            releaseTrap();
            _unlockBackground();
            if (overlay?.parentNode) overlay.remove();
            overlay = null;
            _activeModal = null;
            prevFocus?.focus();
        };
        overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
        overlay.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
        const dialog = el('div', {
            className: 'modal content-modal',
            role: 'dialog',
            'aria-modal': 'true',
            'aria-labelledby': labelId,
        }, [
            el('div', { className: 'modal-header' }, [
                el('h3', { id: labelId, textContent: title }),
                el('button', {
                    className: 'modal-close-btn',
                    'aria-label': 'Close',
                    textContent: '✕',
                    onClick: close,
                }),
            ]),
            el('div', { className: 'modal-body' }, [contentEl]),
        ]);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        _lockBackground();
        releaseTrap = _trapFocus(dialog);
        _activeModal = close;
        dialog.querySelector(_FOCUSABLE_SEL)?.focus();
        return close;
    }

    function closeModal() {
        if (_activeModal) {
            _activeModal();
            _activeModal = null;
        }
    }

    /**
     * Read a cookie by name.
     */
    function parseCookie(name) {
        const match = new RegExp('(^| )' + name + '=([^;]+)').exec(document.cookie);
        return match ? decodeURIComponent(match[2]) : null;
    }

    /**
     * Escape a string for safe insertion into HTML.
     */
    function escHtml(str) {
        if (str == null) return '';
        return String(str)
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }

    /**
     * Simple debounce.
     */
    function debounce(fn, ms) {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn(...args), ms);
        };
    }

    /**
     * Wire up a live-filter text input against a list of DOM rows.
     *
     * @param {HTMLInputElement} input   The filter text field.
     * @param {() => Element[]} getRows  Returns the current set of rows/items.
     * @param {(row: Element) => string} getText  Extracts searchable text from each row.
     */
    function inlineFilter(input, getRows, getText) {
        input.addEventListener('input', () => {
            const term = input.value.toLowerCase();
            for (const row of getRows()) {
                const visible = !term || getText(row).toLowerCase().includes(term);
                row.style.display = visible ? '' : 'none';
            }
        });
    }

    /**
     * Attach a long-press handler to a touch target.
     * Cancels if the finger moves more than `jitterPx` pixels (treats it as a scroll).
     * Returns a cleanup function that removes all listeners.
     *
     * @param {Element} elem       Target element.
     * @param {Function} callback  Called when the long-press fires.
     * @param {number} [ms=500]    Hold duration in ms.
     * @param {number} [jitterPx=10] Max displacement before treating as scroll.
     */
    function addLongPress(elem, callback, ms = 500, jitterPx = 10) {
        let timer = null;
        let startX = 0;
        let startY = 0;

        function _cancel() {
            if (timer !== null) { clearTimeout(timer); timer = null; }
        }

        function onStart(e) {
            const touch = e.touches[0];
            startX = touch.clientX;
            startY = touch.clientY;
            _cancel();
            timer = setTimeout(() => { timer = null; callback(e); }, ms);
        }

        function onMove(e) {
            const touch = e.touches[0];
            const dx = touch.clientX - startX;
            const dy = touch.clientY - startY;
            if (Math.sqrt(dx * dx + dy * dy) > jitterPx) _cancel();
        }

        elem.addEventListener('touchstart', onStart, { passive: true });
        elem.addEventListener('touchmove',  onMove,  { passive: true });
        elem.addEventListener('touchend',   _cancel);
        elem.addEventListener('touchcancel', _cancel);

        return () => {
            _cancel();
            elem.removeEventListener('touchstart', onStart);
            elem.removeEventListener('touchmove',  onMove);
            elem.removeEventListener('touchend',   _cancel);
            elem.removeEventListener('touchcancel', _cancel);
        };
    }

    // -----------------------------------------------------------------------
    // Password strength meter
    // Scoring: +1 each for lowercase/uppercase/digits/other chars;
    //          +1 each at 10/12/14 chars; -2 if in top-200 weak list or
    //          ends with [season/month][current YY or YYYY].
    // Sources: NordVPN 2025 top-200 list (frontend/data/weak-passwords.txt).
    // -----------------------------------------------------------------------

    let _weakPwCache = null;

    async function _loadWeakPasswords() {
        if (_weakPwCache) return _weakPwCache;
        const res  = await fetch('/data/weak-passwords.txt');
        const text = await res.text();
        _weakPwCache = new Set(
            text.split('\n').map(l => l.trim().toLowerCase()).filter(Boolean)
        );
        return _weakPwCache;
    }

    function _scorePassword(password, weakSet) {
        if (!password) return { score: 0, label: 'Weak', warn: false };

        const year4 = String(new Date().getFullYear());
        const year2 = year4.slice(2);
        const _TIMES = [
            'winter','spring','summer','fall','autumn',
            'january','february','march','april','may','june',
            'july','august','september','october','november','december',
        ];
        const timeRx = new RegExp(`(${_TIMES.join('|')})(${year2}|${year4})$`, 'i');

        let score = 0;
        let warn  = false;

        if (/[a-z]/.test(password))        score++;
        if (/[A-Z]/.test(password))        score++;
        if (/[0-9]/.test(password))        score++;
        if (/[^a-zA-Z0-9]/.test(password)) score++;
        if (password.length >= 10)         score++;
        if (password.length >= 12)         score++;
        if (password.length >= 14)         score++;

        if (weakSet && weakSet.has(password.toLowerCase())) { score -= 2; warn = true; }
        if (timeRx.test(password))                          { score -= 2; warn = true; }

        score = Math.max(0, Math.min(7, score));
        const label = score <= 3 ? 'Weak' : score <= 5 ? 'Medium' : 'Strong';
        return { score, label, warn };
    }

    /**
     * Attach a live password strength label + warning to a password input.
     * Inserts two elements immediately after `inputEl` in the DOM.
     * Call AFTER the form containing inputEl has been appended to the document.
     */
    function attachPasswordStrength(inputEl) {
        const meterEl   = el('span', { className: 'pw-strength-label pw-strength-hidden' });
        const warningEl = el('p',    { className: 'pw-strength-warning pw-strength-hidden' });
        // Insert in reverse order so final order is: input → meterEl → warningEl
        inputEl.insertAdjacentElement('afterend', warningEl);
        inputEl.insertAdjacentElement('afterend', meterEl);

        const weakSetPromise = _loadWeakPasswords();

        inputEl.addEventListener('input', async () => {
            const pw = inputEl.value;
            if (!pw) {
                meterEl.className   = 'pw-strength-label pw-strength-hidden';
                warningEl.className = 'pw-strength-warning pw-strength-hidden';
                return;
            }
            const weakSet = await weakSetPromise;
            const { label, warn } = _scorePassword(pw, weakSet);
            meterEl.textContent = label;
            meterEl.className   = `pw-strength-label pw-strength-${label.toLowerCase()}`;
            if (warn) {
                warningEl.textContent = 'This is a common password pattern, please consider using another password.';
                warningEl.className   = 'pw-strength-warning';
            } else {
                warningEl.className = 'pw-strength-warning pw-strength-hidden';
            }
        });
    }

    // -----------------------------------------------------------------------
    // mkPermTree — hierarchical checkbox tree for permission selection
    //
    // groups: [{label, items: [{flag, label, desc?}]}]
    // initialFlags: array of flag strings that should start checked
    //
    // Returns: { el, getFlags(), getPermString() }
    //   getFlags()      → string[] of currently-checked flags
    //   getPermString() → comma-joined string, or 'none' when nothing selected
    // -----------------------------------------------------------------------
    function mkPermTree(groups, initialFlags) {
        const selected = new Set(Array.isArray(initialFlags) ? initialFlags : []);
        const container = el('div', { className: 'perm-tree' });

        function _sync(parentCb, childCbs) {
            const n = childCbs.filter(c => c.checked).length;
            if (n === 0) {
                parentCb.indeterminate = false; parentCb.checked = false;
            } else if (n === childCbs.length) {
                parentCb.indeterminate = false; parentCb.checked = true;
            } else {
                parentCb.indeterminate = true; parentCb.checked = false;
            }
        }

        for (const group of groups) {
            const groupEl  = el('div', { className: 'perm-tree-group' });
            const parentCb = el('input', { type: 'checkbox', className: 'perm-tree-parent-cb' });
            const toggle   = el('button', { type: 'button', className: 'perm-tree-toggle', title: 'Collapse / expand', textContent: '▾' });
            const headerLbl = el('label', { className: 'perm-tree-header-label' });
            headerLbl.appendChild(parentCb);
            headerLbl.appendChild(document.createTextNode(' ' + group.label));
            const header = el('div', { className: 'perm-tree-header' });
            header.appendChild(headerLbl);
            header.appendChild(toggle);
            groupEl.appendChild(header);

            const childWrap = el('div', { className: 'perm-tree-children' });
            const childCbs  = [];

            for (const item of group.items) {
                const childCb = el('input', { type: 'checkbox', className: 'perm-tree-child-cb' });
                childCb.checked = selected.has(item.flag);
                childCbs.push(childCb);
                const lbl = el('label', { className: 'perm-tree-item' });
                lbl.appendChild(childCb);
                const body = el('span', { className: 'perm-tree-item-body' });
                body.appendChild(el('span', { className: 'perm-tree-item-name', textContent: item.label }));
                if (item.desc) body.appendChild(el('span', { className: 'perm-tree-item-desc', textContent: item.desc }));
                lbl.appendChild(body);
                childWrap.appendChild(lbl);
                childCb.addEventListener('change', () => {
                    if (childCb.checked) selected.add(item.flag); else selected.delete(item.flag);
                    _sync(parentCb, childCbs);
                });
            }

            groupEl.appendChild(childWrap);
            container.appendChild(groupEl);
            _sync(parentCb, childCbs);

            parentCb.addEventListener('click', () => {
                const newState = parentCb.checked; // browser already set it
                parentCb.indeterminate = false;
                childCbs.forEach((c, i) => {
                    c.checked = newState;
                    if (newState) selected.add(group.items[i].flag); else selected.delete(group.items[i].flag);
                });
            });

            toggle.addEventListener('click', () => {
                const collapsed = childWrap.classList.toggle('perm-tree-collapsed');
                toggle.textContent = collapsed ? '▸' : '▾';
            });
        }

        return {
            el: container,
            getFlags: ()      => [...selected],
            getPermString: () => selected.size ? [...selected].join(',') : 'none',
        };
    }

    return {
        formatBytes,
        formatDate,
        timeAgo,
        el,
        escHtml,
        showToast,
        getToastHistory,
        getUnreadCount,
        markAllRead,
        onUnreadChange,
        clearToastHistory,
        showConfirm,
        showPrompt,
        showModal,
        closeModal,
        parseCookie,
        debounce,
        inlineFilter,
        addLongPress,
        attachPasswordStrength,
        mkPermTree,
    };
})();
