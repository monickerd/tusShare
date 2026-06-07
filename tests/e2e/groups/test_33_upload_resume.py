"""
Group 33 — Chunked upload resume and pending-upload discoverability.

Tests that an interrupted upload can be discovered via GET /uploads/pending
and resumed by a fresh client from the correct byte offset.  Also verifies
that pending entries are user-scoped and that Range-based downloads work.

Chunk-size strategy
-------------------
To keep test payloads small, the admin default_chunk_size is temporarily
lowered to 65536 bytes (the server-enforced minimum) for this module.
The original value is restored in fixture teardown regardless of outcome.

A 4-chunk file is used throughout (3 full non-final chunks + 1 smaller
final chunk), giving clear midpoints for the interruption scenario.

Tests
-----
33-01  Partial upload (first 2 of 4 chunks sent to a subfolder) is visible
       in GET /uploads/pending with the correct offset and folder_id
33-02  A fresh ApiClient (simulating a page reload) discovers the upload via
       GET /uploads/pending, reads the server-side offset, and resumes —
       sending the remaining 2 chunks to complete the file
33-03  After completion, GET /uploads/pending no longer lists the upload
       and the file record reports upload_complete = True
33-04  Pending uploads are user-scoped: user B's GET /uploads/pending is
       empty even when user A has an incomplete upload
33-05  GET /files/{id}/content with a Range header returns 206 Partial
       Content with a correct Content-Range header
"""

from __future__ import annotations

import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth import register_via_invite
from tests.e2e.helpers.files import (
    create_folder,
    get_file,
    list_pending_uploads,
    tus_upload_begin,
    tus_upload_chunk,
)
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"

# ---------------------------------------------------------------------------
# Chunk geometry — kept small so tests run quickly
# ---------------------------------------------------------------------------

_SMALL_CHUNK = 65536          # bytes of plaintext per non-final chunk
_CHUNK_ENC   = _SMALL_CHUNK + 16   # encrypted = plain + AES-GCM tag (65552)
_FINAL_ENC   = 116            # final chunk: 100 bytes plain + 16-byte tag
_TOTAL_ENC   = 3 * _CHUNK_ENC + _FINAL_ENC   # total encrypted upload size
_ORIGINAL    = 3 * _SMALL_CHUNK + (_FINAL_ENC - 16)  # original plaintext size

# ---------------------------------------------------------------------------
# Module-level state shared across tests
# ---------------------------------------------------------------------------

_user_a:        dict = {}
_user_b:        dict = {}
_subfolder:     dict = {}

# Set in 33-01, consumed by 33-02 / 33-03
_partial_upload_id: str = ""
_partial_offset:    int = 0

# Set in 33-02, consumed by 33-03 / 33-05
_completed_file_id: str = ""

_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


# ---------------------------------------------------------------------------
# Chunk data helpers
# ---------------------------------------------------------------------------

def _chunk(idx: int) -> bytes:
    """Deterministic fake encrypted non-final chunk (65552 bytes).

    Each chunk index maps to a distinct byte value so failures are easy to
    attribute to the correct chunk.
    """
    return bytes([idx & 0xFF]) * _CHUNK_ENC


def _final_chunk() -> bytes:
    return bytes([0xFF]) * _FINAL_ENC


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup(browser: Browser, admin_client: AdminClient):
    global _user_a, _user_b

    # Record and restore the admin chunk size around the whole module
    settings = await admin_client.get_settings()
    original_chunk_size = str(settings["default_chunk_size"])
    await admin_client.set_setting("default_chunk_size", str(_SMALL_CHUNK))

    url_a  = await admin_client.create_invite_url()
    sess_a = await register_via_invite(browser, url_a, "resume_user_a_33", "R3sume!PwdA")
    users  = await admin_client.list_users()
    ua     = next(x for x in users if x["username"].lower() == "resume_user_a_33")
    _user_a = {"id": ua["id"], "session": sess_a}

    url_b  = await admin_client.create_invite_url()
    sess_b = await register_via_invite(browser, url_b, "resume_user_b_33", "R3sume!PwdB")
    users  = await admin_client.list_users()
    ub     = next(x for x in users if x["username"].lower() == "resume_user_b_33")
    _user_b = {"id": ub["id"], "session": sess_b}

    yield

    await admin_client.set_setting("default_chunk_size", original_chunk_size)
    for sess in (sess_a, sess_b):
        try:
            await sess.ctx.close()
        except Exception:
            pass


# ===========================================================================
# 33-01  Partial upload visible in GET /uploads/pending
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_33_01_partial_upload_visible_in_pending():
    """Uploading the first 2 of 4 chunks into a subfolder leaves the upload
    in a resumable state that is visible (with correct metadata) via
    GET /uploads/pending."""
    global _subfolder, _partial_upload_id, _partial_offset

    api = ApiClient.from_session(_user_a["session"])
    async with api:
        _subfolder  = await create_folder(api, "resume_folder_33")
        upload_id, _ = await tus_upload_begin(
            api,
            filename             = "large_file.bin",
            total_encrypted_size = _TOTAL_ENC,
            original_size        = _ORIGINAL,
            chunk_size           = _SMALL_CHUNK,
            folder_id            = _subfolder["id"],
        )

        # Send chunks 0 and 1 — upload is now 50 % complete
        offset = 0
        for i in range(2):
            offset, _ = await tus_upload_chunk(api, upload_id, _chunk(i), offset)

        pending = await list_pending_uploads(api)

    # Exactly one pending upload visible
    assert len(pending) == 1, f"Expected 1 pending upload, got: {pending}"
    entry = pending[0]
    assert entry["upload_id"]      == upload_id,          f"Wrong upload_id: {entry}"
    assert entry["original_name"]  == "large_file.bin",   f"Wrong name: {entry}"
    assert entry["current_offset"] == 2 * _CHUNK_ENC,     f"Wrong offset: {entry}"
    assert entry["total_size"]     == _TOTAL_ENC,         f"Wrong total: {entry}"
    assert entry["folder_id"]      == _subfolder["id"],   f"Wrong folder_id: {entry}"

    _partial_upload_id = upload_id
    _partial_offset    = offset


# ===========================================================================
# 33-02  Fresh client resumes from the server-reported offset
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_33_02_fresh_client_resumes_and_completes():
    """A brand-new ApiClient (simulating a page reload that cleared JS state)
    discovers the interrupted upload via GET /uploads/pending, reads the
    server-side offset from that response, and sends the remaining two chunks
    to complete the file."""
    global _completed_file_id

    # New client instance — same session cookies, but no in-memory upload state
    api = ApiClient.from_session(_user_a["session"])
    async with api:
        # Step 1: discover the interrupted upload, just as the Transfers tab would
        pending = await list_pending_uploads(api)
        entry   = next(
            (p for p in pending if p["upload_id"] == _partial_upload_id), None
        )
        assert entry is not None, (
            "Fresh client could not find the interrupted upload in /uploads/pending"
        )

        # Step 2: use the server-reported offset as the resume point
        resume_offset = entry["current_offset"]
        assert resume_offset == _partial_offset, (
            f"Server offset {resume_offset} does not match expected {_partial_offset}"
        )

        # Step 3: send chunks 2 and 3 (final) from the resume offset
        offset  = resume_offset
        file_id = None
        offset, _       = await tus_upload_chunk(api, _partial_upload_id, _chunk(2), offset)
        offset, file_id = await tus_upload_chunk(api, _partial_upload_id, _final_chunk(), offset)

    assert file_id, "Expected X-File-ID header on the final chunk response"
    _completed_file_id = file_id


# ===========================================================================
# 33-03  Completed upload absent from /uploads/pending; file is accessible
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_33_03_completed_upload_removed_from_pending():
    """Once the upload finishes, it no longer appears in GET /uploads/pending
    and the file record is marked as complete."""
    api = ApiClient.from_session(_user_a["session"])
    async with api:
        pending   = await list_pending_uploads(api)
        file_meta = await get_file(api, _completed_file_id)

    pending_ids = [p["upload_id"] for p in pending]
    assert _partial_upload_id not in pending_ids, (
        "Completed upload still appears in /uploads/pending"
    )
    assert file_meta.get("upload_complete") is True, (
        f"File not marked complete: {file_meta}"
    )


# ===========================================================================
# 33-04  Pending uploads are user-scoped
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_33_04_pending_uploads_are_user_scoped():
    """User A creates a partial upload; User B's GET /uploads/pending returns
    an empty list — incomplete uploads from other users are never exposed."""
    api_a = ApiClient.from_session(_user_a["session"])
    api_b = ApiClient.from_session(_user_b["session"])

    async with api_a:
        upload_id_a, _ = await tus_upload_begin(
            api_a,
            filename             = "private_file.bin",
            total_encrypted_size = _TOTAL_ENC,
            original_size        = _ORIGINAL,
            chunk_size           = _SMALL_CHUNK,
        )
        # One chunk is enough to register a genuine incomplete upload
        await tus_upload_chunk(api_a, upload_id_a, _chunk(0), 0)

    async with api_b:
        pending_b = await list_pending_uploads(api_b)

    assert pending_b == [], (
        f"User B should see no pending uploads, got: {pending_b}"
    )


# ===========================================================================
# 33-05  Range download returns 206 Partial Content
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_33_05_range_download_returns_206():
    """GET /files/{id}/content with a Range header returns 206 Partial Content
    and a Content-Range header whose byte range matches the request."""
    api = ApiClient.from_session(_user_a["session"])
    async with api:
        # Use the file completed in 33-02 — no need to upload a new one
        r = await api.get(
            f"/files/{_completed_file_id}/content",
            headers={"Range": "bytes=0-9"},
        )

    assert r.status_code == 206, (
        f"Expected 206 Partial Content for Range request, "
        f"got {r.status_code}: {r.text[:200]}"
    )
    header_names = {k.lower() for k in r.headers}
    assert "content-range" in header_names, (
        f"Missing Content-Range header in 206 response, headers: {dict(r.headers)}"
    )
    content_range = r.headers.get("content-range", "")
    assert content_range.startswith("bytes 0-9/"), (
        f"Unexpected Content-Range value: {content_range!r}"
    )
    assert len(r.content) == 10, (
        f"Expected 10 bytes in response body, got {len(r.content)}"
    )


# ===========================================================================
# SIEM manifest
# ===========================================================================

@pytest.mark.asyncio(loop_scope="session")
async def test_33_99_siem_manifest():
    assert_manifest(_SIEM_MANIFEST)
