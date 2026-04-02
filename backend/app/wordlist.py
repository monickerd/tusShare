"""Short link word list and slug generation.

Generates memorable 3-word PascalCase slugs like "AbleOctopusMartini"
for share short links. Uses cryptographic randomness via secrets.choice.

Word list is loaded from wordlist.txt in the same directory as this file.
To customize the list, edit wordlist.txt — one PascalCase word per line,
blank lines and lines starting with '#' are ignored.

Current list: 262 words.
Keyspace: 262^3 ≈ 17.98M combinations.

WARNING: With >10,000 concurrently active short links, birthday-paradox
collisions become more likely. For larger deployments, use 4-word slugs.
"""

import secrets
from pathlib import Path

_WORDLIST_PATH = Path(__file__).parent / "wordlist.txt"


def _load_words() -> list[str]:
    """Load words from wordlist.txt, ignoring blank lines and comments."""
    words = []
    with _WORDLIST_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    if len(words) < 10:
        raise RuntimeError(
            f"wordlist.txt at {_WORDLIST_PATH} contains fewer than 10 words — check the file."
        )
    return words


ALL_WORDS: list[str] = _load_words()


def generate_slug() -> str:
    """Generate a 3-word PascalCase slug using cryptographic randomness."""
    return "".join(secrets.choice(ALL_WORDS) for _ in range(3))


async def insert_short_link_with_unique_slug(
    db,
    link_id: str,
    share_id: str,
    created_by: str,
    expires_at: str,
    share_key: str | None = None,
    max_attempts: int = 10,
) -> str:
    """Atomically generate a unique slug and INSERT the short_links row.

    Eliminates the TOCTOU race in generate-then-check: the UNIQUE constraint
    on short_links.slug is the source of truth. On collision (IntegrityError),
    a new slug is generated and retried up to max_attempts times.

    share_key — when provided, the AES share key is stored server-side so
    root-level slug URLs (/LimaCharlieTango) can redirect to /s/<token>#<key>
    without the key appearing in the short link itself.

    Returns the slug on success. Raises ValueError if all attempts collide.
    """
    import sqlite3

    for _ in range(max_attempts):
        slug = generate_slug()
        try:
            await db.execute(
                "INSERT INTO short_links "
                "    (id, share_id, slug, created_by, expires_at, share_key) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (link_id, share_id, slug, created_by, expires_at, share_key),
            )
            await db.commit()
            return slug
        except sqlite3.IntegrityError:
            # Slug collision — retry with a new slug
            continue

    raise ValueError(
        "Failed to generate unique short link slug after "
        f"{max_attempts} attempts. Active short link count may be too high."
    )
