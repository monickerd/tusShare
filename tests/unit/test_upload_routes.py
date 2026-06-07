"""
Unit tests for GET /uploads/pending.

Tests the route handler function directly — no running server required.
The FastAPI dependency injection layer is bypassed; the user and database
objects are passed as plain mocks so the tests are fast and hermetic.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(user_id: str = "user-uuid-1") -> MagicMock:
    """Minimal AuthenticatedUser stand-in."""
    u = MagicMock()
    u.id = user_id
    return u


def _make_db(rows: list[dict]) -> MagicMock:
    """Database mock that returns *rows* from the next execute() call."""
    result = MagicMock()
    result.fetchall = AsyncMock(return_value=rows)

    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_pending_returns_pending_uploads_key():
    """Response is a dict with a 'pending_uploads' key."""
    from app.routes.uploads import list_pending_uploads

    response = await list_pending_uploads(user=_make_user(), db=_make_db([]))
    assert "pending_uploads" in response, f"Key missing: {response}"


@pytest.mark.asyncio
async def test_list_pending_empty_when_no_rows():
    """Empty DB result → pending_uploads is an empty list."""
    from app.routes.uploads import list_pending_uploads

    response = await list_pending_uploads(user=_make_user(), db=_make_db([]))
    assert response["pending_uploads"] == []


@pytest.mark.asyncio
async def test_list_pending_returns_all_row_fields():
    """Each row from the DB is included in the response as a dict."""
    from app.routes.uploads import list_pending_uploads

    row = {
        "upload_id":      "upload-abc",
        "original_name":  "document.pdf",
        "size_bytes":     1_048_576,
        "encrypted_file_key": "abc123==",
        "key_iv":         "iv==",
        "folder_id":      "folder-xyz",
        "current_offset": 524_304,
        "total_size":     1_048_592,
        "expires_at":     "2026-05-11T00:00:00+00:00",
    }
    response = await list_pending_uploads(user=_make_user(), db=_make_db([row]))

    assert len(response["pending_uploads"]) == 1
    returned = response["pending_uploads"][0]
    for key, value in row.items():
        assert returned[key] == value, f"Mismatch on field {key!r}: {returned}"


@pytest.mark.asyncio
async def test_list_pending_returns_multiple_rows():
    """Multiple incomplete uploads are all returned."""
    from app.routes.uploads import list_pending_uploads

    rows = [
        {"upload_id": f"upload-{i}", "original_name": f"file_{i}.bin"}
        for i in range(3)
    ]
    response = await list_pending_uploads(user=_make_user(), db=_make_db(rows))
    assert len(response["pending_uploads"]) == 3


@pytest.mark.asyncio
async def test_list_pending_query_filters_by_user_id():
    """The SQL query is executed with the caller's user_id as the only parameter."""
    from app.routes.uploads import list_pending_uploads

    user_id = "specific-user-uuid"
    db      = _make_db([])
    await list_pending_uploads(user=_make_user(user_id), db=db)

    db.execute.assert_called_once()
    positional_params = db.execute.call_args.args
    # The second argument to execute() is the params tuple: (user_id,)
    assert len(positional_params) == 2, (
        f"Expected (query, params) args, got: {positional_params}"
    )
    params = positional_params[1]
    assert params == (user_id,), (
        f"Expected params=('{user_id}',), got {params}"
    )


@pytest.mark.asyncio
async def test_list_pending_query_contains_user_id_filter():
    """The SQL string references the user_id column so rows are user-scoped."""
    from app.routes.uploads import list_pending_uploads

    db = _make_db([])
    await list_pending_uploads(user=_make_user(), db=db)

    sql: str = db.execute.call_args.args[0]
    assert "user_id" in sql.lower(), (
        f"Expected 'user_id' in SQL, got:\n{sql}"
    )


@pytest.mark.asyncio
async def test_list_pending_query_joins_files_table():
    """The query JOINs tus_uploads with files so original_name and folder_id
    are included — critical for the Transfers-tab folder navigation link."""
    from app.routes.uploads import list_pending_uploads

    db = _make_db([])
    await list_pending_uploads(user=_make_user(), db=db)

    sql: str = db.execute.call_args.args[0].lower()
    assert "tus_uploads" in sql, f"tus_uploads missing from SQL:\n{sql}"
    assert "join" in sql,        f"JOIN missing from SQL:\n{sql}"
    assert "folder_id" in sql,   f"folder_id missing from SQL:\n{sql}"
