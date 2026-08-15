# Shared transcript fixtures

Transcripts used by **both** builds' tests, so the Python and Go parsers are
asserted against identical input and identical expected numbers. A parity claim
that isn't tested against one corpus isn't a claim, it's a hope.

| file | shape |
|---|---|
| `claude_code_tool_use.jsonl` | Claude Code records nesting `tool_use` blocks inside `message.content`, including a record carrying two invocations. |
| `codex_function_call.jsonl` | OpenAI Codex typed events: `function_call` and `function_call_output`. |
| `nested_subagent.jsonl` | A Claude Code sub-agent transcript mixing `thinking` and `tool_use` blocks. |
| `dsh_session.jsonl` | DeepSeek Harness envelope records: header, user message, assistant message with a nested `tool-call` block and token usage, a standalone `tool/call`, a `tool/result`, and a `token_count` record that must produce no turn. |
| `dsh_subagent.jsonl` | A dsh sub-agent session (`origin: subagent`, `parentSession` set) carrying a prompt-injection string. |

Each shape exists because a parser once got it wrong:

- Tool calls nested in `message.content` were invisible to both builds, which
  reported zero tool calls on a host that had made thousands.
- dsh envelopes carry no top-level `role`, so a role/content parser reads
  nothing from them at all.
- dsh names every transcript `session.jsonl`, which a filename-keyed dispatch
  will happily hand to the wrong platform's parser.

The dsh fixtures are stored uncompressed. dsh writes `session.jsonl.zstd` by
default, appending **one Zstandard frame per write batch**, so the tests
compress these into multi-frame streams at runtime — a decoder that stops after
the first frame reads only the header and silently loses the session.

The fixtures deliberately contain **no** strings that look like live
credentials — a repository carrying realistic key shapes trips secret scanners
and invites mistakes. Tests that need a detectable credential assemble one at
runtime instead, so the detection path stays covered without the literal ever
being committed.
