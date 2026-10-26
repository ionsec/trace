"""Tests for DesktopChatCollector (collector/desktop_chat.py).

Desktop chat apps keep local stores separate from the browser stores that
browser_ai covers. Schemas are undocumented, so parse() reports presence and
sizes only — never dumps conversation content.
"""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.desktop_chat import DesktopChatCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="macos", platform="desktop_chat",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = DesktopChatCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "macos")
    assert c.discover() is False


def test_collect_chatgpt_and_claude_stores(tmp_path, monkeypatch):
    gpt = _plant(tmp_path, "Library/Application Support/com.openai.chat/store.db", "x")
    claude = _plant(tmp_path, "Library/Application Support/Claude/conversations.db", "y")
    mcp = _plant(tmp_path, "Library/Application Support/Claude/claude_desktop_config.json",
                 '{"mcpServers": {}}')
    c = DesktopChatCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "macos")
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"chatgpt_desktop", "claude_desktop", "mcp_config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (gpt, claude, mcp):
        assert str(f) in paths
    assert gpt.stat().st_size and claude.stat().st_size


def test_parse_reports_metadata_only(tmp_path):
    store = _plant(tmp_path, "store.db", "secret-ish bytes")
    c = DesktopChatCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(store, "chatgpt_desktop"))
    a = c.parse()[0]
    assert a.data["bytes"] == store.stat().st_size
    assert "content" not in a.data
