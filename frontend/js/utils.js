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
            _toastContainer = el('div', { className: 'toast-container' });
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

    /**
     * Confirmation dialog — returns Promise<boolean>.
     */
    function showConfirm(message) {
        return new Promise((resolve) => {
            let overlay = el('div', { className: 'modal-overlay' });
            const dismiss = (result) => {
                if (overlay?.parentNode) overlay.remove();
                overlay = null;  // Release DOM reference for GC
                resolve(result);
            };
            const dialog = el('div', { className: 'modal confirm-dialog' }, [
                el('p', { textContent: message }),
                el('div', { className: 'modal-actions' }, [
                    el('button', {
                        className: 'btn btn-secondary',
                        textContent: 'Cancel',
                        onClick: () => dismiss(false),
                    }),
                    el('button', {
                        className: 'btn btn-danger',
                        textContent: 'Confirm',
                        onClick: () => dismiss(true),
                    }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
        });
    }

    /**
     * Prompt dialog with a text input — returns Promise<string|null>.
     */
    function showPrompt(title, placeholder = '') {
        return new Promise((resolve) => {
            let overlay = el('div', { className: 'modal-overlay' });
            const dismiss = (result) => { // NOSONAR — identical body to showConfirm.dismiss but closes over this function's overlay
                if (overlay?.parentNode) overlay.remove();
                overlay = null;
                resolve(result);
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
            const dialog = el('div', { className: 'modal prompt-dialog' }, [
                el('h3', { textContent: title }),
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

        let overlay = el('div', { className: 'modal-overlay' });
        const close = () => {
            if (overlay?.parentNode) overlay.remove();
            overlay = null;
            _activeModal = null;
        };
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) close();
        });
        const dialog = el('div', { className: 'modal content-modal' }, [
            el('div', { className: 'modal-header' }, [
                el('h3', { textContent: title }),
                el('button', {
                    className: 'modal-close-btn',
                    textContent: '✕',
                    onClick: close,
                }),
            ]),
            el('div', { className: 'modal-body' }, [contentEl]),
        ]);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        _activeModal = close;
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
            .replaceAll(/&/g, '&amp;')
            .replaceAll(/</g, '&lt;')
            .replaceAll(/>/g, '&gt;')
            .replaceAll(/"/g, '&quot;')
            .replaceAll(/'/g, '&#39;');
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
    };
})();
