"""Tests for GeminiCLICollector (collector/gemini_cli.py)."""

from ionsec_trace.collector.base import CollectedFile, Severity
from ionsec_trace.collector.gemini_cli import GeminiCLICollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="gemini_cli",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    c = GeminiCLICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_both_session_generations(tmp_path, monkeypatch):
    cfg = _plant(tmp_path, ".gemini/settings.json", '{"mcpServers": {"x": {}}}')
    sess = _plant(
        tmp_path, ".gemini/tmp/proj/chats/s1.json",
        '{"sessionId": "s1", "startTime": "2026-10-01T00:00:00Z",'
        ' "lastUpdated": "2026-10-01T00:05:00Z", "messages": [{}, {}]}',
    )
    replay = _plant(tmp_path, ".gemini/tmp/proj/chats/s1.jsonl",
                    '{"metadata": {}}\n{"message": 1}\n')
    credits = _plant(tmp_path, ".gemini/mcp-oauth-tokens.json", '{"tok": "secret"}')
    c = GeminiCLICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"config", "session", "session_replay", "credential"} <= types
    paths = {cf.original_path for cf in files}
    for f in (cfg, sess, replay, credits):
        assert str(f) in paths


def test_parse_session_json(tmp_path):
    f = _plant(tmp_path, "s1.json",
               '{"sessionId": "s1", "messages": [{}, {}, {}]}')
    c = GeminiCLICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session"))
    a = c.parse()[0]
    assert a.data["session_id"] == "s1"
    assert a.data["messages"] == 3
    assert a.severity == Severity.LOW


def test_parse_replay_line_count(tmp_path):
    f = _plant(tmp_path, "s1.jsonl", '{"a": 1}\n{"b": 2}\n')
    c = GeminiCLICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session_replay"))
    assert c.parse()[0].data["entries"] == 2


def test_parse_credential_existence_only(tmp_path):
    f = _plant(tmp_path, "mcp-oauth-tokens.json", '{"access_token": "leak"}')
    c = GeminiCLICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "credential"))
    a = c.parse()[0]
    assert a.artifact_type == "credential"
    assert "leak" not in str(a.data)
