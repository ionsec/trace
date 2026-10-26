"""Tests for ZedCollector (collector/zed.py)."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.zed import ZedCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="zed",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def _make_db(path, rows=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE threads (id TEXT PRIMARY KEY)")
    con.executemany("INSERT INTO threads VALUES (?)", [(f"t{i}",) for i in range(rows)])
    con.commit()
    con.close()
    return path


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = ZedCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_threads_db_and_legacy(tmp_path, monkeypatch):
    db = _make_db(tmp_path / ".local/share/zed/threads/threads.db")
    legacy = _plant(tmp_path, ".local/share/zed/conversations/c1.json", "{}")
    cfg = _plant(tmp_path, ".config/zed/settings.json", '{"context_servers": {}}')
    c = ZedCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "linux")
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"threads_db", "conversation_legacy", "config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (db, legacy, cfg):
        assert str(f) in paths


def test_collect_macos_data_root(tmp_path, monkeypatch):
    db = _make_db(tmp_path / "Library/Application Support/Zed/threads/threads.db")
    c = ZedCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "macos")
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(db)]


def test_parse_counts(tmp_path):
    db = _make_db(tmp_path / "threads.db", rows=3)
    c = ZedCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "threads_db"))
    assert c.parse()[0].data["tables"]["threads"] == 3
