"""Tests for ContinueCollector (collector/continue_dev.py)."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.continue_dev import ContinueCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="continue",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = ContinueCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_config_sessions_mcp(tmp_path, monkeypatch):
    cfg = _plant(tmp_path, ".continue/config.yaml", "models:\n  - name: x\n")
    sess = _plant(tmp_path, ".continue/sessions/s1.json", '{"history": [{}, {}]}')
    mcp = _plant(tmp_path, ".continue/mcpServers/github.json", '{"mcpServers": {}}')
    c = ContinueCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"config", "session", "mcp_config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (cfg, sess, mcp):
        assert str(f) in paths


def test_parse_config_flags_api_key_and_session_count(tmp_path):
    cfg = _plant(tmp_path, "config.yaml", "api_key: sk-123\n")
    sess = _plant(tmp_path, "s1.json", '{"history": [{}, {}]}')
    c = ContinueCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(cfg, "config"))
    c.collected_files.append(_cf(sess, "session"))
    arts = c.parse()
    assert any(i["type"] == "api_key_in_config" for i in arts[0].iocs)
    assert arts[1].data["messages"] == 2
