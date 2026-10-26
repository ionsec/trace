"""Tests for ConversationParser entrypoints and small data classes."""

import json

from ionsec_trace.analyzer.conversation_parser import (
    ConversationParser,
    ConversationTurn,
)


def _turn(ts, role="user"):
    return ConversationTurn(
        timestamp=ts, platform="ollama", role=role, content="hi",
        model="llama3", session_id="s1", source_file="/x", metadata={},
    )


def test_minimal_dir_yields_empty_lists(minimal_evidence_dir):
    parser = ConversationParser.from_evidence_dir(str(minimal_evidence_dir))
    assert parser.turns == []
    assert parser.sessions == []
    assert parser.findings == []


def test_fake_dir_returns_lists(fake_evidence_dir):
    parser = ConversationParser.from_evidence_dir(str(fake_evidence_dir))
    assert isinstance(parser.turns, list)
    assert isinstance(parser.sessions, list)
    assert isinstance(parser.findings, list)


def test_fallback_walk_without_custody(tmp_path):
    platform_dir = tmp_path / "ollama"
    platform_dir.mkdir()
    (platform_dir / "chat.jsonl").write_text(
        json.dumps({"role": "user", "content": "hello"}) + "\n")
    parser = ConversationParser.from_evidence_dir(str(tmp_path))
    assert isinstance(parser.turns, list)
    assert isinstance(parser.sessions, list)


def test_turns_sorted_by_timestamp():
    parser = ConversationParser()
    parser._turns = [_turn("2026-01-02T00:00:00+00:00"), _turn("2026-01-01T00:00:00+00:00")]
    assert [t.timestamp for t in parser.turns] == [
        "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"]


def test_turn_to_dict_keeps_tool_fields():
    turn = _turn("2026-01-01T00:00:00+00:00")
    turn.tool_command = "ls -la"
    turn.tool_input = '{"path": "."}'
    d = turn.to_dict()
    assert d["tool_command"] == "ls -la"
    assert d["tool_input"] == '{"path": "."}'
    assert d["also_in_tools"] == []
