package analyze

import (
	"path/filepath"
	"testing"
)

// fixtureDir resolves the shared transcript fixture corpus. Tests run with the
// package directory as the working directory, so the path walks up to the repo
// root and into tests/fixtures/transcripts.
func fixtureDir() string {
	return filepath.Join("..", "..", "..", "tests", "fixtures", "transcripts")
}

// countToolCalls parses a transcript fixture and returns the number of turns
// that carry tool evidence (a non-empty ToolCommand or ToolInput).
func countToolCalls(t *testing.T, name string) int {
	t.Helper()
	p := &ConversationParser{}
	p.parseFile(filepath.Join(fixtureDir(), name), "test")
	n := 0
	for _, turn := range p.Turns {
		if turn.ToolCommand != "" || turn.ToolInput != "" {
			n++
		}
	}
	return n
}

// TestClaudeCodeToolUseExtraction pins the exact tool-call count for the
// Claude Code shape, where tool calls are nested content blocks one level down
// from the message object. Regression for D4: tool calls were never extracted.
func TestClaudeCodeToolUseExtraction(t *testing.T) {
	if got := countToolCalls(t, "claude_code_tool_use.jsonl"); got != 3 {
		t.Fatalf("claude_code_tool_use.jsonl: got %d tool calls, want exactly 3 (Bash, Read, Write)", got)
	}
}

// TestCodexFunctionCallExtraction pins the exact tool-call count for the
// OpenAI Codex shape (function_call / function_call_output / exec_command_end).
func TestCodexFunctionCallExtraction(t *testing.T) {
	if got := countToolCalls(t, "codex_function_call.jsonl"); got != 1 {
		t.Fatalf("codex_function_call.jsonl: got %d tool calls, want exactly 1 (Bash)", got)
	}
}

// TestNestedSubagentExtraction pins the exact tool-call count for nested
// content blocks that mix thinking and tool_use.
func TestNestedSubagentExtraction(t *testing.T) {
	if got := countToolCalls(t, "nested_subagent.jsonl"); got != 2 {
		t.Fatalf("nested_subagent.jsonl: got %d tool calls, want exactly 2", got)
	}
}

// TestClaudeCodeToolCommands verifies the promoted command and tool name are
// populated from the nested tool_use blocks, not just counted.
func TestClaudeCodeToolCommands(t *testing.T) {
	p := &ConversationParser{}
	p.parseFile(filepath.Join(fixtureDir(), "claude_code_tool_use.jsonl"), "test")
	var commands []string
	for _, turn := range p.Turns {
		if turn.ToolCommand != "" {
			commands = append(commands, turn.ToolCommand)
		}
	}
	// Only the Bash tool_use carries a command; Read/Write have no command field.
	if len(commands) != 1 || commands[0] != "ls -la" {
		t.Fatalf("Bash command not promoted: got %v, want [ls -la]", commands)
	}
}

// TestCodexFunctionCallCommand verifies the Codex function_call command is
// promoted from the arguments object.
func TestCodexFunctionCallCommand(t *testing.T) {
	p := &ConversationParser{}
	p.parseFile(filepath.Join(fixtureDir(), "codex_function_call.jsonl"), "test")
	for _, turn := range p.Turns {
		if turn.ToolCommand == "pwd" {
			return
		}
	}
	t.Fatal("Codex function_call command 'pwd' not promoted")
}
