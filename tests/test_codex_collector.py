"""Tests for CodexCLICollector (collector/codex.py).

Fixtures mirror the real rollout format observed on 2026-10-24:
top-level line types are session_meta / response_item / event_msg /
turn_context, and messages live under payload.type == "message".
"""

from ionsec_trace.collector.base import CollectedFile, Severity
from ionsec_trace.collector.codex import CodexCLICollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path),
        source_os="linux",
        platform="codex_cli",
        artifact_type=artifact_type,
        size_bytes=path.stat().st_size,
        sha256="a" * 64,
        collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    c = CodexCLICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_discover_true_when_dir_present(tmp_path, monkeypatch):
    (tmp_path / ".codex").mkdir()
    c = CodexCLICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is True


def test_collect_picks_up_config_and_sessions(tmp_path, monkeypatch):
    cfg = _plant(
        tmp_path,
        ".codex/config.toml",
        'model_provider = "openai"\n[mcp_servers.github]\ncommand = "npx"\n',
    )
    sess = _plant(
        tmp_path,
        ".codex/sessions/2026/10/24/rollout-abc.jsonl",
        '{"type":"session_meta","payload":{"id":"abc"}}\n'
        '{"type":"response_item","payload":{"type":"message","role":"user"}}\n',
    )
    c = CodexCLICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    by_type = {cf.artifact_type for cf in files}
    assert "config" in by_type
    assert "session" in by_type
    paths = {cf.original_path for cf in files}
    assert str(cfg) in paths
    assert str(sess) in paths


def test_parse_session_extracts_meta_and_counts_messages(tmp_path):
    f = _plant(
        tmp_path,
        "rollout.jsonl",
        '{"type":"session_meta","payload":{"id":"abc","cwd":"/proj",'
        '"cli_version":"0.164.0","model_provider":"openai"}}\n'
        '{"type":"response_item","payload":{"type":"message","role":"user"}}\n'
        '{"type":"response_item","payload":{"type":"message","role":"assistant"}}\n'
        '{"type":"event_msg","payload":{"type":"token_count"}}\n',
    )
    c = CodexCLICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session"))
    arts = c.parse()
    assert len(arts) == 1
    a = arts[0]
    assert a.artifact_type == "session"
    assert a.severity == Severity.LOW
    assert a.data["messages"] == 2
    assert a.data["roles"] == {"user": 1, "assistant": 1}
    assert a.data["event_count"] == 1
    assert a.data["session_meta"]["cwd"] == "/proj"
    assert a.data["session_meta"]["cli_version"] == "0.164.0"


def test_parse_config_flags_mcp(tmp_path):
    f = _plant(tmp_path, "config.toml", '[mcp_servers.x]\ncommand = "npx"\n')
    c = CodexCLICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "config"))
    arts = c.parse()
    assert arts[0].data["has_mcp_servers"] is True


def test_parse_credential_is_existence_only(tmp_path):
    f = _plant(tmp_path, "auth.json", '{"token":"should-never-be-read"}')
    c = CodexCLICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "credential"))
    arts = c.parse()
    assert arts[0].artifact_type == "credential"
    assert "token" not in str(arts[0].data).lower()


def test_parse_history_counts_lines(tmp_path):
    f = _plant(tmp_path, "history.jsonl", '{"cmd":"ls"}\n{"cmd":"pwd"}\n')
    c = CodexCLICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "history"))
    arts = c.parse()
    assert arts[0].data["entries"] == 2
