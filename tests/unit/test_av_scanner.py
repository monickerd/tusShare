"""
Unit tests for the AV scanner service (F5).

Covers webhook HMAC signing, verdict parsing, retry logic, and early-exit
conditions (no endpoint, no escrow key, no escrow material on file).
All external I/O is mocked — no running server, database, or storage backend
required.

asyncio_mode = auto in pytest.ini; no @pytest.mark.asyncio decorators needed.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

_ENDPOINT  = "http://av.local/scan"
_SECRET    = "test-secret-xyz"
_FILE_ID   = "file-abc123"
_PLAINTEXT = b"This is the plaintext file content for AV scanning"
_NAME      = "report.pdf"
_MIME      = "application/pdf"

_SETTINGS_OK = [
    {"key": "av_scan_endpoint",       "value": _ENDPOINT},
    {"key": "av_scan_secret",         "value": _SECRET},
    {"key": "av_scan_retry_attempts", "value": "3"},
]
_SETTINGS_NO_ENDPOINT = [
    {"key": "av_scan_endpoint",       "value": ""},
    {"key": "av_scan_secret",         "value": ""},
    {"key": "av_scan_retry_attempts", "value": "3"},
]

_FILE_WITH_ESCROW = {
    "id":                   _FILE_ID,
    "storage_key":          f"files/{_FILE_ID}",
    "original_name":        _NAME,
    "mime_type":            _MIME,
    "escrow_ephemeral_pk":  "FAKE_PUB_KEY_B64",
    "escrow_encrypted_key": "FAKE_ENC_KEY_B64",
    "escrow_key_iv":        "FAKE_IV_B64",
    "av_scan_status":       None,
}
_FILE_NO_ESCROW = {
    **_FILE_WITH_ESCROW,
    "escrow_ephemeral_pk":  None,
    "escrow_encrypted_key": None,
    "escrow_key_iv":        None,
}


def _make_db(settings_rows, file_row=None, chunk_rows=None):
    """Return an AsyncMock DB that routes execute() calls to correct cursors.

    Routing is keyed on SQL content so call order does not matter.
    chunk_rows defaults to [] (empty — no real storage I/O needed).
    """
    db = AsyncMock()
    db.commit = AsyncMock()

    settings_cur = AsyncMock()
    settings_cur.fetchall = AsyncMock(return_value=settings_rows)

    file_cur = AsyncMock()
    file_cur.fetchone = AsyncMock(return_value=file_row)

    chunks_cur = AsyncMock()
    chunks_cur.fetchall = AsyncMock(return_value=chunk_rows or [])

    noop_cur = AsyncMock()

    async def _execute(sql, params=None):
        if "admin_settings" in sql:
            return settings_cur
        if "FROM files WHERE id" in sql:
            return file_cur
        if "FROM file_chunks" in sql:
            return chunks_cur
        return noop_cur

    db.execute = AsyncMock(side_effect=_execute)
    return db


def _update_calls(db):
    """Return execute call args for UPDATE statements."""
    return [c for c in db.execute.call_args_list if "UPDATE" in c.args[0]]


# ---------------------------------------------------------------------------
# Escrow key helper
# ---------------------------------------------------------------------------

class TestGetEscrowPublicKey:
    def test_returns_none_when_key_is_empty_string(self):
        with patch("app.services.av_scanner.settings") as mock_settings:
            mock_settings.ESCROW_PRIVATE_KEY = ""
            from app.services.av_scanner import get_escrow_public_key_b64
            assert get_escrow_public_key_b64() is None

    def test_returns_none_when_key_is_none(self):
        with patch("app.services.av_scanner.settings") as mock_settings:
            mock_settings.ESCROW_PRIVATE_KEY = None
            from app.services.av_scanner import get_escrow_public_key_b64
            assert get_escrow_public_key_b64() is None


# ---------------------------------------------------------------------------
# Webhook HMAC signing
# ---------------------------------------------------------------------------

class TestWebhookSigning:
    async def test_hmac_header_is_correct(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"verdict": "clean"}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("app.services.av_scanner.httpx.AsyncClient") as MockCls:
            MockCls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockCls.return_value.__aexit__ = AsyncMock(return_value=None)

            from app.services.av_scanner import _call_webhook
            result = await _call_webhook(_ENDPOINT, _SECRET, _PLAINTEXT, _FILE_ID, _NAME, _MIME)

        _, kwargs = mock_client.post.call_args
        header_val = kwargs["headers"]["X-Signature"]

        metadata_str = json.dumps({
            "file_id":       _FILE_ID,
            "original_name": _NAME,
            "mime_type":     _MIME,
            "size_bytes":    len(_PLAINTEXT),
        })
        expected_sig = _hmac.new(
            _SECRET.encode(), metadata_str.encode() + _PLAINTEXT, hashlib.sha256
        ).hexdigest()
        assert header_val == f"sha256={expected_sig}"

    async def test_returns_parsed_response_dict(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"verdict": "infected", "detail": "EICAR"}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("app.services.av_scanner.httpx.AsyncClient") as MockCls:
            MockCls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockCls.return_value.__aexit__ = AsyncMock(return_value=None)

            from app.services.av_scanner import _call_webhook
            result = await _call_webhook(_ENDPOINT, _SECRET, b"EICAR", _FILE_ID, "eicar.txt", "text/plain")

        assert result["verdict"] == "infected"
        assert result["detail"] == "EICAR"


# ---------------------------------------------------------------------------
# scan_file: early-exit conditions (no status write expected)
# ---------------------------------------------------------------------------

class TestScanFileEarlyExit:
    async def test_no_endpoint_returns_without_writing_status(self):
        db = _make_db(_SETTINGS_NO_ENDPOINT)
        with patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)
        assert not _update_calls(db), "Expected no UPDATE calls when endpoint not configured"

    async def test_no_escrow_key_returns_without_writing_status(self):
        db = _make_db(_SETTINGS_OK)
        with patch("app.services.av_scanner._load_escrow_private_key", return_value=None):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)
        assert not _update_calls(db), "Expected no UPDATE calls when escrow key absent"

    async def test_file_not_found_returns_without_writing_status(self):
        db = _make_db(_SETTINGS_OK, file_row=None)
        with patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)
        assert not _update_calls(db), "Expected no UPDATE calls when file row not found"


# ---------------------------------------------------------------------------
# scan_file: file uploaded without escrow material
# ---------------------------------------------------------------------------

class TestScanFileNoEscrowMaterial:
    async def test_sets_status_error_when_escrow_material_absent(self):
        db = _make_db(_SETTINGS_OK, file_row=_FILE_NO_ESCROW)
        with patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)

        updates = _update_calls(db)
        assert updates, "Expected an UPDATE for av_scan_status"
        written_status = updates[-1].args[1][0]
        assert written_status == "error"


# ---------------------------------------------------------------------------
# scan_file: verdict → status mapping
# ---------------------------------------------------------------------------

class TestScanFileVerdicts:
    @pytest.mark.parametrize("verdict,expected_status", [
        ("clean",    "clean"),
        ("infected", "infected"),
        ("error",    "error"),
        ("unknown",  "error"),   # unrecognised verdict normalised to "error"
    ])
    async def test_verdict_written_as_av_scan_status(self, verdict, expected_status):
        db = _make_db(_SETTINGS_OK, file_row=_FILE_WITH_ESCROW, chunk_rows=[])

        with (
            patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()),
            patch("app.services.av_scanner._derive_file_key", return_value=b"\x00" * 32),
            patch("app.services.av_scanner._decrypt_chunks_sync", return_value=_PLAINTEXT),
            patch("app.services.av_scanner._call_webhook", new=AsyncMock(return_value={"verdict": verdict})),
            patch("app.services.av_scanner.storage.get_manager", return_value=MagicMock()),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)

        av_status_updates = [
            c for c in db.execute.call_args_list if "av_scan_status" in c.args[0]
        ]
        final_status = av_status_updates[-1].args[1][0]
        assert final_status == expected_status

    async def test_infected_sets_transfer_locked_at(self):
        db = _make_db(_SETTINGS_OK, file_row=_FILE_WITH_ESCROW, chunk_rows=[])

        with (
            patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()),
            patch("app.services.av_scanner._derive_file_key", return_value=b"\x00" * 32),
            patch("app.services.av_scanner._decrypt_chunks_sync", return_value=_PLAINTEXT),
            patch("app.services.av_scanner._call_webhook", new=AsyncMock(return_value={"verdict": "infected"})),
            patch("app.services.av_scanner.storage.get_manager", return_value=MagicMock()),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)

        lock_updates = [
            c for c in db.execute.call_args_list if "transfer_locked_at" in c.args[0]
        ]
        assert lock_updates, "Expected transfer_locked_at UPDATE for infected verdict"

    async def test_clean_does_not_set_transfer_lock(self):
        db = _make_db(_SETTINGS_OK, file_row=_FILE_WITH_ESCROW, chunk_rows=[])

        with (
            patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()),
            patch("app.services.av_scanner._derive_file_key", return_value=b"\x00" * 32),
            patch("app.services.av_scanner._decrypt_chunks_sync", return_value=_PLAINTEXT),
            patch("app.services.av_scanner._call_webhook", new=AsyncMock(return_value={"verdict": "clean"})),
            patch("app.services.av_scanner.storage.get_manager", return_value=MagicMock()),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)

        lock_updates = [
            c for c in db.execute.call_args_list if "transfer_locked_at" in c.args[0]
        ]
        assert not lock_updates, "Expected no transfer_locked_at UPDATE for clean verdict"


# ---------------------------------------------------------------------------
# scan_file: retry behaviour
# ---------------------------------------------------------------------------

class TestScanFileRetry:
    async def test_retries_on_failure_and_succeeds_on_second_attempt(self):
        db = _make_db(_SETTINGS_OK, file_row=_FILE_WITH_ESCROW, chunk_rows=[])
        call_count = [0]

        async def _flaky(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise RuntimeError("connection refused")
            return {"verdict": "clean"}

        with (
            patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()),
            patch("app.services.av_scanner._derive_file_key", return_value=b"\x00" * 32),
            patch("app.services.av_scanner._decrypt_chunks_sync", return_value=_PLAINTEXT),
            patch("app.services.av_scanner._call_webhook", side_effect=_flaky),
            patch("app.services.av_scanner.storage.get_manager", return_value=MagicMock()),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)

        assert call_count[0] == 2

        av_status_updates = [
            c for c in db.execute.call_args_list if "av_scan_status" in c.args[0]
        ]
        assert av_status_updates[-1].args[1][0] == "clean"

    async def test_retry_exhaustion_writes_error_status(self):
        """All max_attempts attempts fail → final status is 'error'."""
        db = _make_db(_SETTINGS_OK, file_row=_FILE_WITH_ESCROW, chunk_rows=[])
        call_count = [0]

        async def _always_fail(*args, **kwargs):
            call_count[0] += 1
            raise RuntimeError("webhook permanently down")

        with (
            patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()),
            patch("app.services.av_scanner._derive_file_key", return_value=b"\x00" * 32),
            patch("app.services.av_scanner._decrypt_chunks_sync", return_value=_PLAINTEXT),
            patch("app.services.av_scanner._call_webhook", side_effect=_always_fail),
            patch("app.services.av_scanner.storage.get_manager", return_value=MagicMock()),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)

        # max_attempts = 3 from _SETTINGS_OK
        assert call_count[0] == 3

        av_status_updates = [
            c for c in db.execute.call_args_list if "av_scan_status" in c.args[0]
        ]
        assert av_status_updates[-1].args[1][0] == "error"

    async def test_sleep_is_called_between_retry_attempts(self):
        db = _make_db(_SETTINGS_OK, file_row=_FILE_WITH_ESCROW, chunk_rows=[])
        sleep_mock = AsyncMock()

        async def _fail_twice(*args, **kwargs):
            if not hasattr(_fail_twice, "_count"):
                _fail_twice._count = 0
            _fail_twice._count += 1
            if _fail_twice._count < 3:
                raise RuntimeError("transient")
            return {"verdict": "clean"}

        with (
            patch("app.services.av_scanner._load_escrow_private_key", return_value=MagicMock()),
            patch("app.services.av_scanner._derive_file_key", return_value=b"\x00" * 32),
            patch("app.services.av_scanner._decrypt_chunks_sync", return_value=_PLAINTEXT),
            patch("app.services.av_scanner._call_webhook", side_effect=_fail_twice),
            patch("app.services.av_scanner.storage.get_manager", return_value=MagicMock()),
            patch("asyncio.sleep", new=sleep_mock),
        ):
            from app.services.av_scanner import scan_file
            await scan_file(db, _FILE_ID)

        # Two failures → sleep called twice (after attempt 1 and attempt 2)
        assert sleep_mock.call_count == 2
