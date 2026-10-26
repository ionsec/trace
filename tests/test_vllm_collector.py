"""Tests for VLLMCollector (collector/vllm.py) — config surface only."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.vllm import VLLMCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="vllm",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = VLLMCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_config_files(tmp_path, monkeypatch):
    cfg = _plant(tmp_path, ".config/vllm/settings.json", '{"api_key": "sk-x"}')
    c = VLLMCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(cfg)]
    assert files[0].artifact_type == "config"


def test_parse_flags_api_key(tmp_path):
    f = _plant(tmp_path, "settings.json", '{"api_key": "sk-x"}')
    c = VLLMCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "config"))
    a = c.parse()[0]
    assert any(i["type"] == "api_key_in_config" for i in a.iocs)
