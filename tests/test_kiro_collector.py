"""Tests for KiroCollector (collector/kiro.py)."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.kiro import KiroCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="kiro",
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
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    c = KiroCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_sessions_and_db(tmp_path, monkeypatch):
    cli = _plant(tmp_path, ".kiro/sessions/cli/s1.jsonl", '{"a": 1}\n')
    msg = _plant(tmp_path, ".kiro/sessions/x/sess_1/messages.jsonl", '{"b": 2}\n{"c": 3}\n')
    mcp = _plant(tmp_path, ".kiro/settings/mcp.json", '{"mcpServers": {}}')
    db = _make_db(tmp_path / ".local/share/kiro-cli/data.sqlite3")
    c = KiroCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session", "config", "session_db"} <= types
    paths = {cf.original_path for cf in files}
    for f in (cli, msg, mcp, db):
        assert str(f) in paths


def test_parse_counts(tmp_path):
    f = _plant(tmp_path, "s1.jsonl", '{"a": 1}\n{"b": 2}\n{"c": 3}\n')
    db = _make_db(tmp_path / "data.sqlite3", rows=4)
    c = KiroCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session"))
    c.collected_files.append(_cf(db, "session_db"))
    arts = c.parse()
    assert arts[0].data["entries"] == 3
    assert arts[1].data["tables"]["conversations"] == 4
