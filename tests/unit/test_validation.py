"""Unit tests for input validation patterns.

Regression tests for commit 3c251d7 (Fix 4 bugs: folder comma support):
FOLDER_NAME_PATTERN rejected commas, making folder names like "Reports, Q2"
return 400.  Comma is valid on all supported platforms (Linux, macOS, Windows).

Run with: pytest tests/unit/
"""
from __future__ import annotations

import os

os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests-only")

import pytest

from app.conf.validation import FOLDER_NAME_PATTERN


def _ok(name: str) -> bool:
    return bool(FOLDER_NAME_PATTERN.fullmatch(name))


# ---------------------------------------------------------------------------
# Valid names
# ---------------------------------------------------------------------------

def test_simple_alphanumeric_accepted():
    assert _ok("Documents")


def test_name_with_spaces_accepted():
    assert _ok("My Documents")



def test_name_with_numbers_accepted():
    assert _ok("Project 2026")


def test_name_with_comma_accepted():
    """Regression: commas were rejected before commit 3c251d7."""
    assert _ok("Reports, Q2 2026")


def test_name_with_multiple_commas_accepted():
    assert _ok("A, B, C")


def test_name_comma_only_accepted():
    assert _ok(",")


def test_name_with_apostrophe_accepted():
    assert _ok("Alice's Files")


def test_name_with_ampersand_accepted():
    assert _ok("Finance & Accounting")


def test_name_with_parens_accepted():
    assert _ok("Archive (2025)")


def test_name_with_hyphen_accepted():
    assert _ok("Back-up")


def test_name_with_underscore_accepted():
    assert _ok("my_folder")


def test_name_with_dot_accepted():
    assert _ok("v1.0.0")


def test_name_with_exclamation_accepted():
    assert _ok("Important!")


@pytest.mark.parametrize("special", list(" _-.'!()&,"))
def test_every_allowed_special_char_accepted(special: str):
    assert _ok(f"a{special}b"), f"Special char {special!r} should be allowed"


def test_max_length_255_accepted():
    assert _ok("a" * 255)


# ---------------------------------------------------------------------------
# Invalid names
# ---------------------------------------------------------------------------

def test_empty_name_rejected():
    assert not _ok("")


def test_name_too_long_256_rejected():
    assert not _ok("a" * 256)


def test_name_with_forward_slash_rejected():
    assert not _ok("a/b")


def test_name_with_backslash_rejected():
    assert not _ok("a\\b")


def test_name_with_semicolon_rejected():
    assert not _ok("a;b")


def test_name_with_colon_rejected():
    assert not _ok("a:b")


def test_name_with_asterisk_rejected():
    assert not _ok("a*b")


def test_name_with_question_mark_rejected():
    assert not _ok("a?b")


def test_name_with_angle_bracket_rejected():
    assert not _ok("a<b")


def test_name_with_pipe_rejected():
    assert not _ok("a|b")


def test_name_with_null_byte_rejected():
    assert not _ok("a\x00b")


def test_name_with_newline_rejected():
    assert not _ok("a\nb")


def test_name_with_tab_rejected():
    assert not _ok("a\tb")
