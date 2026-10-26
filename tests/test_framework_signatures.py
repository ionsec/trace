"""Tests for 2026 framework import signatures."""

from ionsec_trace.collector.ai_providers import classify_import


def test_openai_agents_sdk_beats_generic_openai():
    info = classify_import("openai.agents")
    assert info is not None
    assert info["framework"] == "OpenAI Agents SDK"


def test_claude_agent_sdk_new_name():
    info = classify_import("claude_agent_sdk")
    assert info is not None
    assert info["framework"] == "Claude Agent SDK"


def test_claude_code_sdk_legacy_name_still_detected():
    info = classify_import("claude_code_sdk")
    assert info is not None
    assert "legacy" in info["framework"]


def test_google_adk():
    info = classify_import("google.adk.tools")
    assert info is not None
    assert info["framework"] == "Google ADK"


def test_ag2_and_agent_framework():
    assert classify_import("ag2")["framework"] == "AG2 (AutoGen)"
    assert classify_import("agent_framework")["framework"] == "Microsoft Agent Framework"


def test_plain_agents_import_not_matched():
    # Too generic to classify — avoids false positives on unrelated packages.
    assert classify_import("agents") is None
