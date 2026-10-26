"""Tests for QwenCodeCollector (collector/qwen_code.py) — config only."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.qwen_code import QwenCodeCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def test_discover_false_when_absent(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    c = QwenCodeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_and_parse_settings(tmp_path, monkeypatch):
    cfg = _plant(tmp_path, ".qwen/settings.json", '{"mcpServers": {"x": {}}}')
    c = QwenCodeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(cfg)]
    c.collected_files.append(CollectedFile(
        original_path=str(cfg), source_os="linux", platform="qwen_code",
        artifact_type="config", size_bytes=cfg.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    ))
    assert c.parse()[0].data["has_mcp_servers"] is True
