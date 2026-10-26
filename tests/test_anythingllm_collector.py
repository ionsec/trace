"""Tests for AnythingLLMCollector (collector/anythingllm.py)."""

import sqlite3

from ionsec_trace.collector.anythingllm import AnythingLLMCollector
from ionsec_trace.collector.base import CollectedFile


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="anythingllm",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def _make_db(path, rows=2):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE workspaces (id TEXT PRIMARY KEY)")
    con.execute("CREATE TABLE workspace_threads (id TEXT PRIMARY KEY)")
    con.executemany("INSERT INTO workspaces VALUES (?)", [(f"w{i}",) for i in range(rows)])
    con.commit()
    con.close()
    return path


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = AnythingLLMCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "linux")
    assert c.discover() is False


def test_collect_db_and_config(tmp_path, monkeypatch):
    db = _make_db(tmp_path / ".config/anythingllm-desktop/storage/anythingllm.db", rows=2)
    cfg = _plant(tmp_path, ".config/anythingllm-desktop/storage/config.json", "{}")
    c = AnythingLLMCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "linux")
    files = c.collect()
    paths = {cf.original_path for cf in files}
    assert str(db) in paths
    assert str(cfg) in paths


def test_parse_db_counts(tmp_path):
    db = _make_db(tmp_path / "anythingllm.db", rows=3)
    c = AnythingLLMCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "session_db"))
    a = c.parse()[0]
    assert a.data["tables"]["workspaces"] == 3
