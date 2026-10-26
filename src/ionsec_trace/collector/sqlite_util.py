"""Read-only SQLite helpers shared by collectors.

Collectors must never write to evidence, so every SQLite open is read-only
(mode=ro) and schema probing stays limited to table names and row counts.
"""

import sqlite3


def sqlite_counts(path: str) -> dict:
    """Return {table_name: row_count} for every table, or {} if unreadable."""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return {}
    try:
        tables = [row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        counts = {}
        for table in tables:
            counts[table] = con.execute(
                f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        return counts
    except sqlite3.Error:
        return {}
    finally:
        con.close()
