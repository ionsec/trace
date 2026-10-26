"""Tests for LocalAICollector (collector/localai.py)."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.localai import LocalAICollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="localai",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = LocalAICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_model_configs_and_keys(tmp_path, monkeypatch):
    model = _plant(tmp_path, ".localai/models/llama.yaml", "name: llama\nbackend: llama-cpp\n")
    keys = _plant(tmp_path, ".localai/configuration/api_keys.json", '["key1"]')
    env = _plant(tmp_path, ".config/localai.env", "OPENAI_API_KEY=x\n")
    c = LocalAICollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"model_config", "api_keys", "env"} <= types
    paths = {cf.original_path for cf in files}
    for f in (model, keys, env):
        assert str(f) in paths


def test_parse_model_config(tmp_path):
    f = _plant(tmp_path, "llama.yaml", "name: llama\n")
    c = LocalAICollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "model_config"))
    assert c.parse()[0].data["name"] == "llama"
