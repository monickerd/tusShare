// Restore appearance preferences from localStorage before CSS renders.
// Loaded synchronously from <head> to prevent flash of wrong theme or text size.
(function () {
    var t = localStorage.getItem('tus_theme') || 'system';
    var s = localStorage.getItem('tus_text_size');
    document.documentElement.setAttribute('data-theme', t);
    if (s && s !== 'medium') {
        document.documentElement.setAttribute('data-text-size', s);
    }
})();
