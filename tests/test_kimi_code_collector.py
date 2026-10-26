"""Tests for KimiCodeCollector (collector/kimi_code.py)."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.kimi_code import KimiCodeCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="kimi_code",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    c = KimiCodeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_wire_and_config(tmp_path, monkeypatch):
    wire = _plant(tmp_path, ".kimi-code/sessions/p/s/agents/main/wire.jsonl",
                  '{"t": 1}\n{"t": 2}\n')
    cfg = _plant(tmp_path, ".kimi/config.toml", 'model = "kimi"\n')
    c = KimiCodeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session", "config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (wire, cfg):
        assert str(f) in paths


def test_parse_counts(tmp_path):
    f = _plant(tmp_path, "wire.jsonl", '{"t": 1}\n{"t": 2}\n{"t": 3}\n')
    c = KimiCodeCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session"))
    assert c.parse()[0].data["entries"] == 3
