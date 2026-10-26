"""Characterization tests for the unified timeline."""

import json

import pytest

from ionsec_trace.analyzer.timeline import TimelineEvent, UnifiedTimeline
from ionsec_trace.collector.base import Severity


def test_event_to_dict_drops_none_and_serialises_severity():
    ev = TimelineEvent(
        timestamp="2026-01-01T00:00:00+00:00",
        platform="ollama",
        artifact_type="config",
        description="collected config",
        severity=Severity.HIGH,
        source_path="/evidence/ollama/config.json",
    )
    d = ev.to_dict()
    assert d["severity"] == "high"
    assert d["platform"] == "ollama"
    assert "user" not in d


@pytest.mark.parametrize("name,expected", [
    ("config.json", "config"),
    ("settings.yaml", "config"),
    ("chat_history.md", "conversation"),
    ("conversation.jsonl", "conversation"),
    ("model_manifest.json", "config"),
    ("model.yml", "model_manifest"),
    ("server.log", "log"),
    ("credentials.json", "config"),
    ("api_key.txt", "credential"),
    ("auth.token", "credential"),
    ("store.sqlite", "session_database"),
    ("opencode.db", "session_database"),
    ("rollout.jsonl", "session_log"),
    ("blob.bin", "unknown"),
])
def test_guess_artifact_type(name, expected):
    assert UnifiedTimeline._guess_artifact_type(name) == expected


def test_load_minimal_evidence_dir(minimal_evidence_dir):
    timeline = UnifiedTimeline(str(minimal_evidence_dir))
    assert timeline.load() is timeline
    assert timeline.events == []


def test_load_fake_evidence_dir(fake_evidence_dir):
    timeline = UnifiedTimeline(str(fake_evidence_dir))
    timeline.load()
    assert isinstance(timeline.events, list)
    assert timeline.events, "expected collection-time events for two collected files"
    for event in timeline.events:
        assert isinstance(event, TimelineEvent)


def test_discover_fallback_without_custody(tmp_path):
    platform_dir = tmp_path / "ollama"
    platform_dir.mkdir()
    (platform_dir / "config.json").write_text(json.dumps({"model": "llama3"}))
    timeline = UnifiedTimeline(str(tmp_path))
    timeline.load()
    assert timeline.events
    assert {e.platform for e in timeline.events} == {"ollama"}
