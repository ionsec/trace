"""Tests for CopilotCollector (collector/copilot.py) — CLI + VS Code Chat."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.copilot import CopilotCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="copilot",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    c = CopilotCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [])
    assert c.discover() is False


def test_collect_cli_and_chat_stores(tmp_path, monkeypatch):
    events = _plant(tmp_path, ".copilot/session-state/s1/events.jsonl",
                    '{"t": 1}\n{"t": 2}\n')
    mcp = _plant(tmp_path, ".copilot/mcp-config.json", '{"mcpServers": {}}')
    gs = tmp_path / "globalStorage"
    chat = _plant(gs, "github.copilot-chat/chat.json", '[{"id": 1}]')
    c = CopilotCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [gs])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session", "config", "chat"} <= types
    paths = {cf.original_path for cf in files}
    for f in (events, mcp, chat):
        assert str(f) in paths


def test_collect_workspace_transcripts(tmp_path, monkeypatch):
    gs = tmp_path / "globalStorage"
    ws = _plant(gs, "../workspaceStorage/hash/chatSessions/s1.jsonl",
                '{"a": 1}\n{"b": 2}\n{"c": 3}\n')
    c = CopilotCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [gs])
    files = c.collect()
    transcript = [cf for cf in files if cf.artifact_type == "transcript"]
    assert transcript and transcript[0].original_path == str(ws.resolve())


def test_parse_events_and_chat(tmp_path):
    events = _plant(tmp_path, "events.jsonl", '{"a": 1}\n{"b": 2}\n')
    chat = _plant(tmp_path, "chat.json", '[{"id": 1}, {"id": 2}]')
    c = CopilotCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(events, "session"))
    c.collected_files.append(_cf(chat, "chat"))
    arts = c.parse()
    assert arts[0].data["entries"] == 2
    assert arts[1].data["entries"] == 2


def test_discover_true_when_chat_dir(tmp_path, monkeypatch):
    gs = tmp_path / "globalStorage"
    (gs / "github.copilot-chat").mkdir(parents=True)
    c = CopilotCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [gs])
    assert c.discover() is True


def test_parse_chat_db_and_config(tmp_path):
    db = _plant(tmp_path, "state.vscdb", "x")
    cfg = _plant(tmp_path, "config.json", '{"mcpServers": {}}')
    c = CopilotCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(db, "chat_db"))
    c.collected_files.append(_cf(cfg, "config"))
    arts = c.parse()
    assert arts[0].data["bytes"] == 1
    assert arts[1].data["has_mcp_servers"] is True


def test_collect_cli_config_json(tmp_path, monkeypatch):
    cfg = _plant(tmp_path, ".copilot/config.json", "{}")
    c = CopilotCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [])
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(cfg)]
