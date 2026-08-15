"""Tests for D4 — tool-call extraction from nested Claude Code content blocks
and OpenAI Codex function_call records.

These tests parse the shared fixture corpus under
``tests/fixtures/transcripts/`` and assert EXACT tool-call counts, so a
regression that silently drops tool calls fails loudly.
"""

from pathlib import Path

from ionsec_trace.analyzer.conversation_parser import (
    ConversationParser,
    _extract_tool_calls,
)

FIXTURES = Path(__file__).parent / "fixtures" / "transcripts"


def _count_tool_calls(parser: ConversationParser) -> int:
    """Count tool invocations extracted from the parsed turns.

    - Claude Code: each ``tool_use`` block preserved in a turn's
      ``content_blocks`` metadata is one invocation.
    - Codex: each ``function_call`` turn is one invocation.
    """
    total = 0
    for t in parser.turns:
        if t.platform == "claude_code":
            blocks = t.metadata.get("content_blocks", [])
            total += sum(1 for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use")
        elif t.platform == "codex":
            if t.metadata.get("type") == "function_call":
                total += 1
    return total


def _parse_fixture(name: str, platform: str) -> ConversationParser:
    """Parse a single fixture file through the parser's JSONL routing."""
    parser = ConversationParser()
    parser._parse_jsonl(str(FIXTURES / name), platform, {})
    return parser


class TestClaudeCodeNestedToolUse:
    def test_extracts_exactly_three_tool_use_calls(self):
        parser = _parse_fixture("claude_code_tool_use.jsonl", "claude_code")
        # 3 tool_use blocks: Bash 'ls -la', Read, Write
        assert _count_tool_calls(parser) == 3

    def test_bash_command_promoted_to_first_class_field(self):
        parser = _parse_fixture("claude_code_tool_use.jsonl", "claude_code")
        commands = sorted(t.tool_command for t in parser.turns if t.tool_command)
        assert commands == ["ls -la"]

    def test_nested_blocks_are_unwrapped(self):
        parser = _parse_fixture("claude_code_tool_use.jsonl", "claude_code")
        # The Bash tool_use lives inside message.content, not at top level.
        calls = _extract_tool_calls({
            "message": {
                "content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": "ls -la"}},
                ]
            }
        })
        assert len(calls) == 1
        assert calls[0]["name"] == "Bash"
        assert calls[0]["command"] == "ls -la"
        assert calls[0]["type"] == "tool_use"


class TestCodexFunctionCall:
    def test_extracts_exactly_one_function_call(self):
        parser = _parse_fixture("codex_function_call.jsonl", "codex")
        # 1 function_call (Bash 'pwd'); function_call_output and
        # exec_command_end are results, not invocations.
        assert _count_tool_calls(parser) == 1

    def test_function_call_command_promoted(self):
        parser = _parse_fixture("codex_function_call.jsonl", "codex")
        fc_turns = [t for t in parser.turns if t.metadata.get("type") == "function_call"]
        assert len(fc_turns) == 1
        assert fc_turns[0].tool_command == "pwd"

    def test_codex_dispatch_used(self):
        parser = _parse_fixture("codex_function_call.jsonl", "codex")
        assert all(t.platform == "codex" for t in parser.turns)


class TestNestedSubagent:
    def test_extracts_exactly_two_tool_use_calls(self):
        parser = _parse_fixture("nested_subagent.jsonl", "claude_code")
        # 2 tool_use blocks (both Bash); the thinking block is not a tool call.
        assert _count_tool_calls(parser) == 2

    def test_thinking_block_not_counted_as_tool_call(self):
        parser = _parse_fixture("nested_subagent.jsonl", "claude_code")
        commands = sorted(t.tool_command for t in parser.turns if t.tool_command)
        assert commands == ["git log --oneline -3", "git status"]
