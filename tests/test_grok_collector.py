"""Tests for GrokCollector (collector/grok.py)."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.grok import GrokCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="grok",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def _make_db(path, rows=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY)")
    con.executemany("INSERT INTO sessions VALUES (?)", [(f"s{i}",) for i in range(rows)])
    con.commit()
    con.close()
    return path


def test_discover_false_when_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("GROK_HOME", raising=False)
    c = GrokCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_sessions_and_db(tmp_path, monkeypatch):
    monkeypatch.delenv("GROK_HOME", raising=False)
    upd = _plant(tmp_path, ".grok/sessions/s1/updates.jsonl", '{"t": 1}\n{"t": 2}\n')
    db = _make_db(tmp_path / ".grok/grok.db", rows=3)
    c = GrokCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session", "session_db"} <= types
    paths = {cf.original_path for cf in files}
    for f in (upd, db):
        assert str(f) in paths


def test_collect_honors_grok_home(tmp_path, monkeypatch):
    home = tmp_path / "grokhome"
    upd = _plant(home, "sessions/s1/updates.jsonl", "{}\n")
    monkeypatch.setenv("GROK_HOME", str(home))
    c = GrokCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(upd)]


def test_parse_counts(tmp_path):
    upd = _plant(tmp_path, "updates.jsonl", '{"t": 1}\n{"t": 2}\n')
    db = _make_db(tmp_path / "grok.db", rows=2)
    c = GrokCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(upd, "session"))
    c.collected_files.append(_cf(db, "session_db"))
    arts = c.parse()
    assert arts[0].data["entries"] == 2
    assert arts[1].data["tables"]["sessions"] == 2
