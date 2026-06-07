/**
 * manifest-decrypt.js — Web Worker for bulk manifest name decryption.
 *
 * Input message:  { masterKeyRaw: ArrayBuffer, items: Array<{id, name_ct, original_name}> }
 * Output message: { results: Array<{id, displayName}> }
 *                 { error: string }  on fatal failure
 *
 * Derives nameKey from masterKeyRaw using the same HKDF parameters as
 * Crypto.deriveNameKeys() in crypto.js, then decrypts each name_ct in parallel.
 * The raw key bytes are zeroed immediately after HKDF import to limit exposure.
 */

function _b64ToBytes(b64) {
    const binary = atob(b64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.codePointAt(i);
    return buf;
}

self.onmessage = async ({ data }) => {
    const { masterKeyRaw, items } = data;
    try {
        const raw = new Uint8Array(masterKeyRaw);
        const hkdfKey = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
        raw.fill(0);

        const enc = new TextEncoder();
        const salt = enc.encode('tusShare-meta-v1');
        const nameKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('filename-enc') },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt'],
        );

        const results = await Promise.all(items.map(async (f) => {
            if (!f.name_ct) return { id: f.id, displayName: f.original_name || '' };
            try {
                const bytes = _b64ToBytes(f.name_ct);
                const iv = bytes.slice(0, 12);
                const ct = bytes.slice(12);
                const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, nameKey, ct);
                return { id: f.id, displayName: new TextDecoder().decode(plain) };
            } catch {
                return { id: f.id, displayName: f.original_name || '' };
            }
        }));

        self.postMessage({ results });
    } catch (err) {
        self.postMessage({ error: err.message });
    }
};
