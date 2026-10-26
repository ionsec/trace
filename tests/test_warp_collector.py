"""Tests for WarpCollector (collector/warp.py)."""

import sqlite3

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.warp import WarpCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="warp",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def _make_db(path, agent=1, queries=2, blocks=3):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE agent_conversations (id TEXT PRIMARY KEY)")
    con.execute("CREATE TABLE ai_queries (id TEXT PRIMARY KEY)")
    con.execute("CREATE TABLE blocks (id TEXT PRIMARY KEY)")
    con.executemany("INSERT INTO agent_conversations VALUES (?)", [(f"a{i}",) for i in range(agent)])
    con.executemany("INSERT INTO ai_queries VALUES (?)", [(f"q{i}",) for i in range(queries)])
    con.executemany("INSERT INTO blocks VALUES (?)", [(f"b{i}",) for i in range(blocks)])
    con.commit()
    con.close()
    return path


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = WarpCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_config_and_db(tmp_path, monkeypatch):
    db = _make_db(tmp_path / ".warp/warp.sqlite")
    settings = _plant(tmp_path, ".warp/settings.toml", "theme = 'dark'\n")
    mcp = _plant(tmp_path, ".warp/.mcp.json", '{"mcpServers": {}}')
    c = WarpCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"terminal_db", "config", "mcp_config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (db, settings, mcp):
        assert str(f) in paths


def test_parse_db_counts(tmp_path):
    db = _make_db(tmp_path / "warp.sqlite", agent=1, queries=2, blocks=3)
    c = WarpCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "terminal_db"))
    a = c.parse()[0]
    assert a.data["tables"]["agent_conversations"] == 1
    assert a.data["tables"]["ai_queries"] == 2
    assert a.data["tables"]["blocks"] == 3
    assert "assistant response text is not stored" in a.data["note"]
