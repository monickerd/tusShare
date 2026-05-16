"""Server-side antivirus webhook service.

Only active when TUSSHARE_ESCROW_PRIVATE_KEY is set and av_scan_endpoint is
configured in admin_settings.  Requires files to have been uploaded with
escrow-encrypted key fields (populated by the client when the server's escrow
public key is available).

Scan pipeline:
  1. Verify both escrow key and AV endpoint are configured.
  2. Read escrow_ephemeral_pk / escrow_encrypted_key / escrow_key_iv from files.
  3. ECDH (P-256) + HKDF-SHA256 → derive 256-bit wrap key.
  4. AES-GCM decrypt → raw file key bytes.
  5. Re-import as AES-GCM key; decrypt each chunk fetched from storage.
  6. POST multipart (file + metadata) to webhook, signed with HMAC-SHA256.
  7. Parse verdict; write av_scan_status / av_scanned_at; auto-lock on infected.
"""

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
from datetime import datetime, timezone

import httpcore
import httpx

from app.config import settings
from app.util.ssrf import resolve_validated_endpoint
import app.storage.manager as storage


class _PinnedDNSBackend(httpcore.AsyncNetworkBackend):
    """DNS-pinned network backend: routes `hostname` to a pre-validated `pinned_ip`.

    Prevents DNS rebinding TOCTOU attacks by bypassing OS DNS for the target
    hostname and connecting directly to the IP validated at scan start.
    The original hostname is still used for TLS SNI and certificate verification.
    """

    def __init__(self, hostname: str, pinned_ip: str) -> None:
        self._hostname = hostname
        self._pinned_ip = pinned_ip
        from httpcore._backends.auto import AutoBackend
        self._inner = AutoBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        actual_host = self._pinned_ip if host == self._hostname else host
        return await self._inner.connect_tcp(
            actual_host, port,
            timeout=timeout, local_address=local_address, socket_options=socket_options,
        )

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        return await self._inner.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    async def sleep(self, seconds):
        return await self._inner.sleep(seconds)

logger = logging.getLogger(__name__)

_ESCROW_HKDF_INFO = b"av-escrow"


# ---------------------------------------------------------------------------
# Escrow key helpers
# ---------------------------------------------------------------------------

def _load_escrow_private_key():
    """Return the P-256 private key object, or None if not configured."""
    if not settings.ESCROW_PRIVATE_KEY:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        der = base64.b64decode(settings.ESCROW_PRIVATE_KEY)
        return load_der_private_key(der, password=None)
    except Exception:
        logger.exception("Failed to load ESCROW_PRIVATE_KEY")
        return None


def get_escrow_public_key_b64() -> str | None:
    """Return the base64-encoded SPKI public key, or None if not configured.

    Called by the uploads endpoint to advertise the public key to clients.
    """
    key = _load_escrow_private_key()
    if key is None:
        return None
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_bytes = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(pub_bytes).decode()


# ---------------------------------------------------------------------------
# Crypto: derive file key via ECDH + HKDF + AES-GCM
# ---------------------------------------------------------------------------

def _derive_file_key(
    priv_key,
    escrow_ephemeral_pk_b64: str,
    escrow_encrypted_key_b64: str,
    escrow_key_iv_b64: str,
) -> bytes:
    """CPU-bound key derivation; run in a thread pool via asyncio.to_thread."""
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ephemeral_pub_key = load_der_public_key(base64.b64decode(escrow_ephemeral_pk_b64))
    shared_secret = priv_key.exchange(ECDH(), ephemeral_pub_key)

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=_ESCROW_HKDF_INFO,
    ).derive(shared_secret)

    enc_key_bytes = base64.b64decode(escrow_encrypted_key_b64)
    iv_bytes      = base64.b64decode(escrow_key_iv_b64)
    return AESGCM(derived).decrypt(iv_bytes, enc_key_bytes, None)


def _decrypt_chunks_sync(file_key_bytes: bytes, chunks: list[tuple[str, bytes]]) -> list[bytes]:
    """Decrypt a list of (iv_b64, ciphertext) tuples; run in a thread pool.

    Returns individual plaintext chunks rather than a single joined buffer so
    callers can stream to the webhook without materialising the full plaintext.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(file_key_bytes)
    return [aesgcm.decrypt(base64.b64decode(iv_b64), ct, None) for iv_b64, ct in chunks]


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

class _ChunkedFile(io.RawIOBase):
    """File-like wrapper over a list of plaintext chunks for httpx multipart streaming.

    httpx's FileField calls read(CHUNK_SIZE) in a loop.  This implementation
    serves bytes chunk-by-chunk so the full plaintext is never joined into a
    single large bytes object.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._it = iter(chunks)
        self._buf = b""

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:
        while not self._buf:
            try:
                self._buf = next(self._it)
            except StopIteration:
                return 0
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n


async def _call_webhook(
    endpoint: str,
    secret: str,
    decrypted_chunks: list[bytes],
    file_id: str,
    original_name: str,
    mime_type: str,
    *,
    pinned_hostname: str,
    pinned_ip: str,
) -> dict:
    """POST plaintext to the AV webhook; return parsed response dict.

    Accepts pre-decrypted chunks and streams them via _ChunkedFile so the full
    plaintext is never materialised as a single bytes object.  HMAC is computed
    via rolling update over the metadata prefix followed by each chunk in order.

    Uses a DNS-pinned transport so that the connection always goes to the IP
    that was validated at scan start, preventing DNS rebinding TOCTOU attacks.
    """
    total_size = sum(len(c) for c in decrypted_chunks)
    metadata = json.dumps({
        "file_id":       file_id,
        "original_name": original_name,
        "mime_type":     mime_type,
        "size_bytes":    total_size,
    })

    h = hmac.new(secret.encode(), metadata.encode(), hashlib.sha256)
    for chunk in decrypted_chunks:
        h.update(chunk)
    sig = h.hexdigest()

    transport = httpx.AsyncHTTPTransport(
        network_backend=_PinnedDNSBackend(pinned_hostname, pinned_ip),
    )
    async with httpx.AsyncClient(transport=transport, timeout=120.0) as client:
        resp = await client.post(
            endpoint,
            files={"file": (original_name, _ChunkedFile(decrypted_chunks), mime_type or "application/octet-stream")},
            data={"metadata": metadata},
            headers={"X-Signature": f"sha256={sig}"},
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Main scan task
# ---------------------------------------------------------------------------

async def scan_file(db, file_id: str) -> None:
    """Background scan for a single file after upload finalization.

    Called via asyncio.create_task() — runs concurrently with other requests.
    """
    # --- Load admin settings ---
    cursor = await db.execute(
        "SELECT key, value FROM admin_settings "
        "WHERE key IN ('av_scan_endpoint', 'av_scan_secret', 'av_scan_retry_attempts')"
    )
    rows = {r["key"]: r["value"] for r in await cursor.fetchall()}
    endpoint    = rows.get("av_scan_endpoint", "").strip()
    secret      = rows.get("av_scan_secret",   "").strip()
    max_attempts = int(rows.get("av_scan_retry_attempts", settings.AV_SCAN_RETRY_ATTEMPTS))

    if not endpoint:
        return

    try:
        pinned_hostname, pinned_ip = await resolve_validated_endpoint(endpoint)
    except Exception:
        logger.exception(
            "AV scan endpoint %r failed SSRF validation — scan aborted for file %s",
            endpoint, file_id,
        )
        await _write_status(db, file_id, "error")
        return

    priv_key = _load_escrow_private_key()
    if priv_key is None:
        logger.warning(
            "av_scan_endpoint is configured but TUSSHARE_ESCROW_PRIVATE_KEY is absent; "
            "cannot scan file %s", file_id,
        )
        return

    # --- Load file row ---
    cursor = await db.execute(
        "SELECT id, storage_key, original_name, mime_type, "
        "       escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv, "
        "       av_scan_status "
        "FROM files WHERE id = ?",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        logger.error("scan_file: file %s not found", file_id)
        return

    file_row = dict(row)
    if file_row.get("av_scan_status") in ("clean", "infected"):
        return  # already definitive; idempotent

    if not file_row.get("escrow_ephemeral_pk"):
        logger.info(
            "File %s uploaded without escrow key material; marking error. "
            "Re-upload after configuring TUSSHARE_ESCROW_PRIVATE_KEY.",
            file_id,
        )
        await _write_status(db, file_id, "error")
        return

    # --- Load chunk rows (DB, not storage) ---
    cursor = await db.execute(
        'SELECT chunk_index, iv, size_bytes, "offset" FROM file_chunks '
        "WHERE file_id = ? ORDER BY chunk_index",
        (file_id,),
    )
    chunk_rows = [dict(r) for r in await cursor.fetchall()]

    await _write_status(db, file_id, "pending")

    # --- Derive file key (CPU-bound) ---
    try:
        file_key_bytes = await asyncio.to_thread(
            _derive_file_key,
            priv_key,
            file_row["escrow_ephemeral_pk"],
            file_row["escrow_encrypted_key"],
            file_row["escrow_key_iv"],
        )
    except Exception:
        logger.exception("Escrow key derivation failed for file %s", file_id)
        await _write_status(db, file_id, "error")
        return

    # --- Fetch and decrypt chunks (async storage reads, sync AES) ---
    try:
        mgr = storage.get_manager()
        raw_chunks: list[tuple[str, bytes]] = []
        for cr in chunk_rows:
            start = cr["offset"]
            end   = cr["offset"] + cr["size_bytes"] - 1
            stream = await mgr.read_stream(db, file_id, file_row["storage_key"], start, end)
            data = b"".join([chunk async for chunk in stream])
            raw_chunks.append((cr["iv"], data))

        decrypted_chunks = await asyncio.to_thread(_decrypt_chunks_sync, file_key_bytes, raw_chunks)
        del raw_chunks  # release ciphertext before webhook; only decrypted chunks remain in memory
    except Exception:
        logger.exception("Chunk decryption failed for file %s", file_id)
        await _write_status(db, file_id, "error")
        return

    # --- Webhook with retry ---
    verdict = await _scan_with_retry(
        endpoint, secret, decrypted_chunks, file_id,
        file_row.get("original_name", "file"),
        file_row.get("mime_type", "application/octet-stream"),
        max_attempts,
        pinned_hostname=pinned_hostname,
        pinned_ip=pinned_ip,
    )

    await _write_status(db, file_id, verdict)

    if verdict == "infected":
        await _handle_infected(db, file_id, file_row.get("original_name", ""))

    logger.info("AV scan complete for file %s: verdict=%s", file_id, verdict)


async def _scan_with_retry(
    endpoint: str, secret: str, decrypted_chunks: list[bytes],
    file_id: str, original_name: str, mime_type: str,
    max_attempts: int,
    *,
    pinned_hostname: str,
    pinned_ip: str,
) -> str:
    verdict = "error"
    delay = 2.0
    for attempt in range(1, max_attempts + 1):
        try:
            result = await _call_webhook(
                endpoint, secret, decrypted_chunks, file_id, original_name, mime_type,
                pinned_hostname=pinned_hostname,
                pinned_ip=pinned_ip,
            )
            raw_verdict = result.get("verdict", "error")
            verdict = raw_verdict if raw_verdict in ("clean", "infected", "error") else "error"
            break
        except Exception as exc:
            logger.warning(
                "AV webhook attempt %d/%d failed for file %s: %s",
                attempt, max_attempts, file_id, exc,
            )
            if attempt < max_attempts:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)
    return verdict


async def _write_status(db, file_id: str, status: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        await db.execute(
            "UPDATE files SET av_scan_status = ?, av_scanned_at = ? WHERE id = ?",
            (status, now, file_id),
        )
        await db.commit()
    except Exception:
        logger.exception("Failed to write AV status for file %s", file_id)


async def _handle_infected(db, file_id: str, original_name: str) -> None:
    """Lock file and emit op_bus event — mirrors emergency lock pathway."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        await db.execute(
            "UPDATE files SET transfer_locked_at = ? "
            "WHERE id = ? AND transfer_locked_at IS NULL",
            (now, file_id),
        )
        await db.commit()
    except Exception:
        logger.exception("Failed to lock infected file %s", file_id)
        return

    try:
        from app.services import op_bus
        from app.schemas.op_event import OperationalEvent
        op_bus.emit(OperationalEvent(
            event_type="file.av.infected",
            severity="critical",
            source="av_scanner",
            data={"file_id": file_id, "original_name": original_name},
        ))
    except Exception:
        logger.exception("op_bus emit failed for infected file %s", file_id)
