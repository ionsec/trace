"""Tests for PiFamilyCollector (collector/pi_family.py).

One parser covers pi, MiniMax Code, omp and senpi — all write pi-style tree
JSONL session stores under their own home dirs.
"""

from ionsec_trace.collector.base import CollectedFile
from ionsec_trace.collector.pi_family import PiFamilyCollector


def _plant(home, rel, content):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _cf(path, artifact_type):
    return CollectedFile(
        original_path=str(path), source_os="linux", platform="pi_family",
        artifact_type=artifact_type, size_bytes=path.stat().st_size,
        sha256="a" * 64, collected_at="2026-10-24T00:00:00+00:00",
    )


def test_discover_false_when_absent(tmp_path, monkeypatch):
    c = PiFamilyCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    assert c.discover() is False


def test_collect_all_family_roots(tmp_path, monkeypatch):
    pi = _plant(tmp_path, ".pi/agent/sessions/a.jsonl", '{"t": 1}\n')
    mm = _plant(tmp_path, ".minimax/v2/sessions/2026/10/24/s1/messages.jsonl", '{"t": 1}\n')
    omp = _plant(tmp_path, ".omp/agent/sessions/b.jsonl", '{"t": 1}\n')
    senpi = _plant(tmp_path, ".senpi/agent/sessions/c.jsonl", '{"t": 1}\n')
    c = PiFamilyCollector(output_dir=str(tmp_path))
    monkeypatch.setattr(c, "get_user_home_dirs", lambda: [tmp_path])
    files = c.collect()
    paths = {cf.original_path for cf in files}
    for f in (pi, mm, omp, senpi):
        assert str(f) in paths
    assert all(cf.artifact_type == "session" for cf in files)


def test_tool_attribution(tmp_path):
    assert PiFamilyCollector._tool_for("/home/u/.pi/agent/sessions/a.jsonl") == "pi"
    assert PiFamilyCollector._tool_for(
        "/home/u/.minimax/v2/sessions/2026/10/24/s1/messages.jsonl") == "minimax"
    assert PiFamilyCollector._tool_for("/home/u/.omp/agent/sessions/b.jsonl") == "omp"
    assert PiFamilyCollector._tool_for("/home/u/.senpi/agent/sessions/c.jsonl") == "senpi"


def test_parse_line_counts_and_tool(tmp_path):
    f = _plant(tmp_path, "a.jsonl", '{"t": 1}\n{"t": 2}\n')
    c = PiFamilyCollector(output_dir=str(tmp_path))
    c.collected_files.append(_cf(f, "session"))
    a = c.parse()[0]
    assert a.data["entries"] == 2
    assert a.data["tool"] in ("pi", "minimax", "omp", "senpi", "unknown")
