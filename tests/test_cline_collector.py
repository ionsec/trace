"""Tests for ClineCollector (collector/cline.py) — Cline v4 + legacy + Roo."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.cline import ClineCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="cline",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    c = ClineCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [])
    assert c.discover() is False


def test_collect_modern_session(tmp_path, monkeypatch):
    modern = _plant(tmp_path, ".cline/data/sessions/s1/s1.messages.json",
                    '[{"role": "user"}, {"role": "assistant"}]')
    c = ClineCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [])
    files = c.collect()
    assert [cf.artifact_type for cf in files] == ["session_modern"]
    assert files[0].original_path == str(modern)


def test_collect_legacy_cline_and_roo(tmp_path, monkeypatch):
    gs = tmp_path / "globalStorage"
    cline = _plant(gs, "saoudrizwan.claude-dev/tasks/t1/api_conversation_history.json",
                   '[{"role": "user"}]')
    roo = _plant(gs, "rooveterinaryinc.roo-cline/tasks/t2/api_conversation_history.json",
                 '[{"role": "user"}, {"role": "assistant"}]')
    c = ClineCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [gs])
    files = c.collect()
    paths = {cf.original_path for cf in files}
    assert str(cline) in paths
    assert str(roo) in paths
    assert all(cf.artifact_type == "session_legacy" for cf in files)


def test_parse_counts_messages(tmp_path):
    f = _plant(tmp_path, "s1.messages.json", '[1, 2, 3]')
    c = ClineCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session_modern"))
    assert c.parse()[0].data["messages"] == 3


def test_discover_true_when_modern_sessions_dir(tmp_path, monkeypatch):
    (tmp_path / ".cline/data/sessions").mkdir(parents=True)
    c = ClineCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [])
    assert c.discover() is True


def test_parse_mcp_config_and_legacy_dict(tmp_path):
    mcp = _plant(tmp_path, "cline_mcp_settings.json", '{"mcpServers": {}}')
    legacy = _plant(tmp_path, "api_conversation_history.json", '{"messages": [1, 2]}')
    c = ClineCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(mcp, "mcp_config"))
    c.collected_files.append(_cf(legacy, "session_legacy"))
    arts = c.parse()
    assert arts[0].artifact_type == "mcp_config"
    assert arts[1].data["messages"] == 2


def test_collect_roo_cli_mock_tasks(tmp_path, monkeypatch):
    f = _plant(tmp_path, ".vscode-mock/global-storage/tasks/t/api_conversation_history.json", "[]")
    c = ClineCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_global_storage_roots", lambda: [])
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(f)]
