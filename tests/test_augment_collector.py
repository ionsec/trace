"""Tests for AugmentCollector (collector/augment.py)."""

from ionsec_trace.collector.augment import AugmentCollector
from ionsec_trace.collector.base import CollectedFile


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="augment",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = AugmentCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_sessions_history_settings(tmp_path, monkeypatch):
    sess = _plant(tmp_path, ".augment/sessions/c1.json", '{"turns": [{}, {}, {}]}')
    hist = _plant(tmp_path, ".augment/prompt-history.jsonl", '{"p": 1}\n')
    cfg = _plant(tmp_path, ".augment/settings.json", "{}")
    c = AugmentCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"session", "history", "config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (sess, hist, cfg):
        assert str(f) in paths


def test_parse_counts(tmp_path):
    sess = _plant(tmp_path, "c1.json", '{"turns": [{}, {}, {}]}')
    hist = _plant(tmp_path, "prompt-history.jsonl", '{"p": 1}\n{"p": 2}\n')
    c = AugmentCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(sess, "session"))
    c.collected_files.append(_cf(hist, "history"))
    arts = c.parse()
    assert arts[0].data["turns"] == 3
    assert arts[1].data["entries"] == 2
