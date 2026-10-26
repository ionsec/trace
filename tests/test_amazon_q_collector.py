"""Tests for AmazonQCollector (collector/amazon_q.py)."""

import sqlite3

from ionsec_trace.collector.amazon_q import AmazonQCollector
from ionsec_trace.collector.base import CollectedFile


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="amazon_q",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def _make_db(path, rows=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY)")
    con.executemany("INSERT INTO conversations VALUES (?)", [(f"c{i}",) for i in range(rows)])
    con.commit()
    con.close()
    return path


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = AmazonQCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_chat_history_and_db(tmp_path, monkeypatch):
    hist = _plant(tmp_path, ".aws/amazonq/history/chat-history-abc.json",
                  '{"collections": [{"tabs": [{}, {}]}]}')
    no_ws = _plant(tmp_path, ".aws/amazonq/history/chat-history-no-workspace.json", "{}")
    db = _make_db(tmp_path / ".local/share/amazon-q/data.sqlite3")
    c = AmazonQCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"chat_history", "session_db"} <= types
    paths = {cf.original_path for cf in files}
    for f in (hist, no_ws, db):
        assert str(f) in paths


def test_parse_lokijs_history(tmp_path):
    f = _plant(tmp_path, "chat-history-abc.json",
               '{"collections": [{"tabs": [{}, {}]}]}')
    c = AmazonQCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "chat_history"))
    a = c.parse()[0]
    assert a.data["tabs"] == 2


def test_parse_unexpected_json_shape_is_safe(tmp_path):
    f = _plant(tmp_path, "chat-history-x.json", '["plain", "list"]')
    c = AmazonQCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "chat_history"))
    a = c.parse()[0]
    assert a.data["tabs"] == 0
