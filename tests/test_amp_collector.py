"""Tests for AmpCollector (collector/amp.py)."""

from ionsec_trace.collector.amp import AmpCollector
from ionsec_trace.collector.base import CollectedFile


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="amp",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    c = AmpCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_threads(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    t = _plant(tmp_path, ".local/share/amp/threads/t1.json", '{"messages": [{}, {}]}')
    c = AmpCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(t)]
    assert files[0].artifact_type == "thread"


def test_collect_honors_xdg_data_home(tmp_path, monkeypatch):
    xdg = tmp_path / "xdg"
    t = _plant(xdg, "amp/threads/t1.json", "{}")
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    c = AmpCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    assert [cf.original_path for cf in files] == [str(t)]


def test_parse_thread_messages(tmp_path):
    t = _plant(tmp_path, "t1.json", '{"messages": [{}, {}]}')
    c = AmpCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(t, "thread"))
    assert c.parse()[0].data["messages"] == 2
