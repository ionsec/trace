"""Tests for OpenCodeCollector (collector/opencode.py)."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.opencode import OpenCodeCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="opencode",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def _make_db(path, sessions=2, messages=3):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY)")
    con.execute("CREATE TABLE messages (id TEXT PRIMARY KEY, session_id TEXT)")
    con.executemany("INSERT INTO sessions VALUES (?)", [(f"s{i}",) for i in range(sessions)])
    con.executemany("INSERT INTO messages VALUES (?, ?)",
                    [(f"m{i}", "s0") for i in range(messages)])
    con.commit()
    con.close()
    return path


def test_discover_false_when_absent(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    c = OpenCodeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_store_and_legacy_json(tmp_path, monkeypatch):
    db = _make_db(tmp_path / ".local/share/opencode/opencode.db")
    auth = _plant(tmp_path, ".local/share/opencode/auth.json", '{"token": "x"}')
    diff = _plant(tmp_path, ".local/share/opencode/storage/session_diff/ses_1.json", "{}")
    c = OpenCodeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    # config lives under ~/.config/opencode; redirect homes covers it
    cfg = _plant(tmp_path, ".config/opencode/opencode.json", '{"mcp": {}}')
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session_db", "credential", "session_diff", "config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (db, auth, diff, cfg):
        assert str(f) in paths


def test_parse_sqlite_counts(tmp_path):
    db = _make_db(tmp_path / "opencode.db", sessions=2, messages=3)
    c = OpenCodeCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "session_db"))
    a = c.parse()[0]
    assert a.data["tables"]["sessions"] == 2
    assert a.data["tables"]["messages"] == 3


def test_parse_unreadable_db_is_safe(tmp_path):
    f = _plant(tmp_path, "opencode.db", "not a sqlite file")
    c = OpenCodeCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session_db"))
    a = c.parse()[0]
    assert a.data["tables"] == {}
