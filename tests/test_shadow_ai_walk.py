"""Tests for the Shadow AI collector walk layer (D2 depth + D3 file cap).

Covers:
  - D2: transcript/session files (.jsonl/.json) are walked to any depth so
    deep sub-agent transcripts are captured, while non-transcript config
    trees stay bounded by the configured depth.
  - D3: the per-tool file cap is configurable, truncation is counted and
    recorded (self.truncations), and a warning is emitted.
"""

import logging

import pytest

from ionsec_trace.collector.shadow_ai import ShadowAICollector


@pytest.fixture
def collector(tmp_path):
    return ShadowAICollector(output_dir=str(tmp_path))


def _write(path, content="{}"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestDepthWalk:
    """D2: transcript trees walked fully, config trees bounded."""

    def test_deep_subagent_transcript_is_collected(self, tmp_path, collector):
        # .claude/projects/<slug>/<uuid>/subagents/<lvl1>/<lvl2>/agent-1.jsonl
        # is 7 parts deep relative to the config dir — beyond the old max_depth=3.
        deep = tmp_path / "projects" / "slug" / "uuid" / "subagents" / "lvl1" / "lvl2"
        transcript = _write(deep / "agent-1.jsonl", '{"role":"assistant"}')
        # A deep non-transcript config file at the same depth must be excluded.
        _write(deep / "settings.yaml", "key: value")

        collected = collector._collect_config_dir(tmp_path)

        paths = {cf.original_path for cf in collected}
        assert str(transcript) in paths, "deep sub-agent transcript should be collected"
        assert not any(p.endswith("settings.yaml") for p in paths), (
            "deep non-transcript config should still be depth-bounded"
        )

    def test_codex_rollout_transcript_is_collected(self, tmp_path, collector):
        # .codex/sessions/YYYY/MM/DD/rollout-1.jsonl is 5 parts deep.
        rollout = _write(
            tmp_path / "sessions" / "2026" / "08" / "15" / "rollout-1.jsonl",
            '{"type":"response"}',
        )
        collected = collector._collect_config_dir(tmp_path)
        assert str(rollout) in {cf.original_path for cf in collected}

    def test_shallow_config_still_collected(self, tmp_path, collector):
        cfg = _write(tmp_path / "settings.json", "{}")
        collected = collector._collect_config_dir(tmp_path)
        assert str(cfg) in {cf.original_path for cf in collected}

    def test_transcript_artifact_type(self, tmp_path, collector):
        _write(tmp_path / "projects" / "s" / "u" / "subagents" / "agent-1.jsonl", "{}")
        collected = collector._collect_config_dir(tmp_path)
        assert any(cf.artifact_type == "transcript" for cf in collected)


class TestFileCap:
    """D3: configurable cap, truncation counted and recorded."""

    def test_cap_is_configurable_and_records_truncation(self, tmp_path):
        collector = ShadowAICollector(
            output_dir=str(tmp_path), max_files_per_tool=3
        )
        for i in range(10):
            _write(tmp_path / f"file{i}.json", "{}")

        collected = collector._collect_config_dir(tmp_path)

        assert len(collected) == 3, "cap should limit collected files"
        assert collector.truncations, "truncation should be recorded"
        trunc = collector.truncations[0]
        assert trunc["platform"] == "shadow_ai"
        assert trunc["max_files"] == 3
        assert trunc["skipped"] == 7
        assert trunc["directory"] == str(tmp_path)

    def test_no_truncation_when_under_cap(self, tmp_path, collector):
        for i in range(5):
            _write(tmp_path / f"file{i}.json", "{}")
        collector._collect_config_dir(tmp_path)
        assert not getattr(collector, "truncations", None)

    def test_warning_emitted_on_truncation(self, tmp_path, caplog):
        collector = ShadowAICollector(
            output_dir=str(tmp_path), max_files_per_tool=2
        )
        for i in range(5):
            _write(tmp_path / f"file{i}.json", "{}")
        with caplog.at_level(logging.WARNING, logger="ionsec_trace.collector.shadow_ai"):
            collector._collect_config_dir(tmp_path)
        assert any("truncated" in r.message for r in caplog.records)

    def test_env_var_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRACE_MAX_FILES_PER_TOOL", "4")
        collector = ShadowAICollector(output_dir=str(tmp_path))
        assert collector.max_files_per_tool == 4
