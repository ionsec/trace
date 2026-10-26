"""Tests for MCP config detection across client dialects (JSON / TOML / YAML)."""

from ionsec_trace.collector.ai_providers import MCP_CONFIG_FILES
from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.code_scanner import CodeScannerCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="code_scanner",
        artifact_type="mcp_config", size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_new_client_paths_registered():
    for rel in (
        ".vscode/mcp.json",
        ".codex/config.toml",
        ".gemini/settings.json",
        ".copilot/mcp-config.json",
        ".devin/mcp_config.json",
        "claude_desktop_config.json",
        "smithery.yaml",
    ):
        assert rel in MCP_CONFIG_FILES


def test_parse_codex_toml(tmp_path):
    f = _plant(tmp_path, "config.toml",
               '[mcp_servers.github]\ncommand = "npx"\n\n[mcp_servers.files]\ncommand = "mcp-files"\n')
    c = CodeScannerCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f))
    a = c.parse()[0]
    assert a.data["config"]["format"] == "toml"
    assert a.data["config"]["mcp_servers"] == ["files", "github"]


def test_parse_vscode_json(tmp_path):
    f = _plant(tmp_path, "mcp.json", '{"servers": {"github": {}}}')
    c = CodeScannerCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f))
    a = c.parse()[0]
    assert "servers" in a.data["config"]


def test_parse_smithery_yaml(tmp_path):
    f = _plant(tmp_path, "smithery.yaml", "name: example\nstartCommand:\n  type: http\n")
    c = CodeScannerCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f))
    a = c.parse()[0]
    assert a.data["config"]["format"] == "smithery"


def test_parse_non_mcp_toml_is_skipped(tmp_path):
    f = _plant(tmp_path, "config.toml", 'model = "gpt-5"\n')
    c = CodeScannerCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f))
    assert c.parse() == []


def test_collect_finds_home_level_mcp_configs(tmp_path, monkeypatch):
    cursor = _plant(tmp_path, ".cursor/mcp.json", '{"mcpServers": {}}')
    codex = _plant(tmp_path, ".codex/config.toml", "[mcp_servers.x]\ncommand = \"npx\"\n")
    c = CodeScannerCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "_scan_dirs", lambda: [])
    files = c.collect()
    paths = {cf.original_path for cf in files}
    assert str(cursor) in paths
    assert str(codex) in paths
    assert all(cf.artifact_type == "mcp_config" for cf in files)
