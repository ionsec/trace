"""Tests for JanCollector (collector/jan.py)."""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.jan import JanCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="jan",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = JanCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "linux")
    assert c.discover() is False


def test_collect_threads_and_config(tmp_path, monkeypatch):
    msg = _plant(tmp_path, ".local/share/Jan/data/threads/t1/messages.jsonl",
                 '{"role": "user"}\n{"role": "assistant"}\n')
    meta = _plant(tmp_path, ".local/share/Jan/data/threads/t1/thread.json", "{}")
    store = _plant(tmp_path, ".local/share/Jan/data/store.json", "{}")
    c = JanCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    monkeypatch.setattr(c, "detect_os", lambda: "linux")
    files = c.collect()
    types = {cf.artifact_type for cf in files}
    assert {"thread", "thread_meta", "config"} <= types
    paths = {cf.original_path for cf in files}
    for f in (msg, meta, store):
        assert str(f) in paths


def test_parse_thread_entries(tmp_path):
    f = _plant(tmp_path, "messages.jsonl", '{"role": "user"}\n{"role": "assistant"}\n')
    c = JanCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "thread"))
    assert c.parse()[0].data["entries"] == 2
