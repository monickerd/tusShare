"""Shared database query helpers used across route and service layers."""

from __future__ import annotations


async def get_admin_setting(db, key: str, default=None, *, dtype=None):
    """Fetch a single value from admin_settings by key.

    Returns the raw string value (or *dtype*-converted value when dtype is given),
    or *default* if the key is not set or its value is NULL/empty.
    """
    cursor = await db.execute(
        "SELECT value FROM admin_settings WHERE key = ?", (key,)
    )
    row = await cursor.fetchone()
    if row is None or not row["value"]:
        return default
    return dtype(row["value"]) if dtype is not None else row["value"]


def build_update(fields: dict, table: str, where_col: str, where_val) -> tuple[str, list]:
    """Build a parameterised UPDATE statement from a dict of {column: value} pairs.

    Only entries whose value is not None are included — callers should filter
    out omitted/optional fields before passing the dict.

    Returns (sql, params) where params is the positional list expected by
    aiosqlite's ``db.execute``.  Raises ValueError if *fields* is empty.
    """
    if not fields:
        raise ValueError("build_update called with no fields to update")

    assignments = [f"{col} = ?" for col in fields]
    params = list(fields.values()) + [where_val]
    sql = f"UPDATE {table} SET {', '.join(assignments)} WHERE {where_col} = ?"
    return sql, params
