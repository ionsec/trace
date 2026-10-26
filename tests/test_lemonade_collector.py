"""Tests for LemonadeCollector (collector/lemonade.py)."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.lemonade import LemonadeCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="lemonade",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = LemonadeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_config_and_models(tmp_path, monkeypatch):
    cfg = _plant(tmp_path, ".config/lemonade/config.json", '{"port": 13305}')
    models = _plant(tmp_path, ".config/lemonade/user_models.json", '{"models": []}')
    c = LemonadeCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    paths = {cf.original_path for cf in files}
    assert str(cfg) in paths
    assert str(models) in paths


def test_parse_config_keys(tmp_path):
    f = _plant(tmp_path, "config.json", '{"port": 13305}')
    c = LemonadeCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "config"))
    assert "port" in c.parse()[0].data["keys"]
