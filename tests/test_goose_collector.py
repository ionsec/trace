"""Tests for GooseCollector (collector/goose.py)."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.goose import GooseCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="goose",
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
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    c = GooseCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_config_db_and_legacy(tmp_path, monkeypatch):
    cfg = _plant(tmp_path, ".config/goose/config.yaml", "provider: openai\n")
    hist = _plant(tmp_path, ".config/goose/history.txt", "hi\n")
    db = _make_db(tmp_path / ".local/share/goose/sessions/sessions.db")
    legacy = _plant(tmp_path, ".local/share/goose/sessions/s1.jsonl", '{"a": 1}\n')
    c = GooseCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"config", "session_db", "session_legacy"} <= types
    paths = {cf.original_path for cf in files}
    for f in (cfg, hist, db, legacy):
        assert str(f) in paths


def test_parse_config_flags_api_key(tmp_path):
    f = _plant(tmp_path, "config.yaml", "api_key: sk-123\n")
    c = GooseCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "config"))
    a = c.parse()[0]
    assert any(i["type"] == "api_key_in_config" for i in a.iocs)


def test_parse_sqlite_and_legacy_counts(tmp_path):
    db = _make_db(tmp_path / "sessions.db", rows=2)
    legacy = _plant(tmp_path, "s1.jsonl", '{"a": 1}\n{"b": 2}\n')
    c = GooseCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "session_db"))
    c.collected_files.append(_cf(legacy, "session_legacy"))
    arts = c.parse()
    assert arts[0].data["tables"]["sessions"] == 2
    assert arts[1].data["entries"] == 2
