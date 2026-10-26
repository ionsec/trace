"""Tests for OpenWebUICollector (collector/open_webui.py)."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.open_webui import OpenWebUICollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="open_webui",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def _make_db(path, chats=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE chat (id TEXT PRIMARY KEY)")
    con.execute("CREATE TABLE user (id TEXT PRIMARY KEY)")
    con.executemany("INSERT INTO chat VALUES (?)", [(f"c{i}",) for i in range(chats)])
    con.commit()
    con.close()
    return path


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = OpenWebUICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_db_and_secret(tmp_path, monkeypatch):
    db = _make_db(tmp_path / ".open-webui/webui.db", chats=2)
    secret = _plant(tmp_path, ".open-webui/.webui_secret_key", "abc")
    c = OpenWebUICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session_db", "credential"} <= types
    paths = {cf.original_path for cf in files}
    for f in (db, secret):
        assert str(f) in paths


def test_parse_db_counts(tmp_path):
    db = _make_db(tmp_path / "webui.db", chats=2)
    c = OpenWebUICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "session_db"))
    assert c.parse()[0].data["tables"]["chat"] == 2
