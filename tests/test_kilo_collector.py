"""Tests for KiloCollector (collector/kilo.py) — CLI sqlite + extension tasks."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.kilo import KiloCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="kilo",
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
    c = KiloCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [])
    assert c.discover() is False


def test_collect_db_and_legacy_task(tmp_path, monkeypatch):
    db = _make_db(tmp_path / ".local/share/kilo/kilo.db", rows=3)
    gs = tmp_path / "globalStorage"
    task = _plant(gs, "kilocode.kilo-code/tasks/t1/api_conversation_history.json",
                  '[{"role": "user"}]')
    c = KiloCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [gs])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session_db", "session_legacy"} <= types
    paths = {cf.original_path for cf in files}
    for f in (db, task):
        assert str(f) in paths


def test_parse_counts(tmp_path):
    db = _make_db(tmp_path / "kilo.db", rows=2)
    task = _plant(tmp_path, "api_conversation_history.json", '[1, 2, 3]')
    c = KiloCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "session_db"))
    c.collected_files.append(_cf(task, "session_legacy"))
    arts = c.parse()
    assert arts[0].data["tables"]["sessions"] == 2
    assert arts[1].data["messages"] == 3
