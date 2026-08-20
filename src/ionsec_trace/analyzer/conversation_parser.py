"""
ConversationParser — extracts actual conversation content from collected AI
artifacts and detects high-value DFIR patterns (jailbreaks, prompt extraction,
credential harvesting, data exfiltration, privilege escalation, indirect
injection).

While the UnifiedTimeline records *metadata-level* events like "config
collected: config.json", this module walks the raw artifact files and parses
out the prompts, responses, tool calls, and reasoning chains that analysts
need for a real investigation.

Supported platforms / formats
------------------------------
- Ollama SQLite DB (chats + messages tables)
- Hermes Agent JSONL session files
- LM Studio LevelDB / session JSON
- text-generation-webui JSON chat logs
- Cursor workspace_state.json / SQLite conversation DBs
- Claude Code JSONL conversation logs
- Generic JSON/JSONL with role/content patterns
"""

from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ionsec_trace.collector.base import Finding, Severity

# ======================================================================
# Data models
# ======================================================================


def _row_get(row, key, default=None):
    """Read a column from a sqlite3.Row by name.

    sqlite3.Row supports mapping-style indexing but has no ``.get``, and raises
    IndexError for columns a schema does not have — which varies widely across
    the app databases TRACE collects.
    """
    try:
        value = row[key]
    except (IndexError, KeyError):
        return default
    return default if value is None else value


@dataclass
class ConversationTurn:
    """A single turn in a conversation — one message from one role.

    Tool-call evidence (``tool_command`` / ``tool_input`` / ``tool_description``)
    is promoted to first-class fields so analysts can review the exact shell
    command and structured arguments an AI assistant invoked, rather than
    digging through opaque ``metadata``.
    """

    timestamp: str          # ISO 8601
    platform: str           # ollama, hermes, lm_studio, etc.
    role: str               # user, assistant, system, tool
    content: str            # actual text content
    model: str              # model name if available
    session_id: str         # conversation / chat session ID
    source_file: str        # path to source artifact
    metadata: dict          # platform-specific extras
    # --- First-class tool-call evidence ---
    tool_command: str = ""          # exact recorded command value
    tool_input: str = ""            # structured args (JSON string) for the call
    tool_description: str = ""      # purpose/description of the invoked tool
    workspace: str = ""            # project / cwd / repo context when available
    also_in_tools: list = field(default_factory=list)  # other platforms with same prompt

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class ConversationSession:
    """A grouped set of turns belonging to one conversation session."""

    session_id: str
    platform: str
    model: str
    turns: list[ConversationTurn]
    start_time: str
    end_time: str
    source_files: list[str]
    metadata: dict

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ======================================================================
# DFIR pattern definitions
# ======================================================================

_SYSTEM_PROMPT_EXTRACTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("reveal instructions", re.compile(
        r"(?i)(reveal|show|display|print|output|repeat|recite|write\s+out)\s+"
        r"(your|the|my|system|initial|original|secret|hidden)\s*"
        r"(instructions?|prompts?|directives?|rules?|guidelines?|constraints?)",
    )),
    ("what are your prompts", re.compile(
        r"(?i)what\s+(are|is)\s+(your|the|my)\s+"
        r"(system|initial|original|secret|hidden|base)\s*"
        r"(prompt|instruction|directive|rule)",
    )),
    ("ignore previous instructions", re.compile(
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|past)\s*"
        r"(instructions?|prompts?|directives?|rules?|constraints?)",
    )),
    ("system prompt extraction", re.compile(
        r"(?i)(system\s*prompt|initial\s*prompt|base\s*prompt|secret\s*prompt)\s*"
        r"(extraction|leak|dump|read|reveal|output)",
    )),
    ("pretend/forget instructions", re.compile(
        r"(?i)(pretend|act\s+as|forget|disregard)\s+"
        r"(your|the|all)\s*(previous|prior|above|normal|original)\s*"
        r"(instructions?|rules?|constraints?)",
    )),
]

_JAILBREAK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("DAN mode", re.compile(
        r"(?i)(do\s+anything\s+now|DAN\s*mode|you\s+are\s+now\s+DAN|"
        r"enable\s+DAN|DAN\s+jailbreak|"
        r"act\s+as\s+DAN|become\s+DAN)",
    )),
    ("roleplay bypass", re.compile(
        r"(?i)(you\s+are\s+now\s+(?:an?\s+)?unrestricted|"
        r"you\s+have\s+no\s+(?:rules|restrictions|limitations|filters)|"
        r"pretend\s+you\s+have\s+no\s+(?:rules|restrictions|filter)|"
        r"bypass\s+(?:your|the|all)\s+(?:safety|filter|restrictions?|rules?))",
    )),
    ("encoding attack", re.compile(
        r"(?i)(base64\s*(decode|encode|encoded|decoded|string)|"
        r"rot13|hex\s*(decode|encode)|"
        r"decode\s+(?:this|the)\s+(?:base64|hex|rot13|encoded))",
    )),
    ("base64-obfuscated prompt", re.compile(
        r"(?i)(?:[A-Za-z0-9+/]{40,}={0,2})(?:\s*(?:decode|execute|run|interpret)\s)",
    )),
    ("developer mode", re.compile(
        r"(?i)(developer\s*mode|debug\s*mode|admin\s*mode|"
        r"god\s*mode|root\s*mode|sudo\s*mode|"
        r"override\s+(?:safety|security|filter|restrictions?|policy))",
    )),
    ("hypothetical bypass", re.compile(
        r"(?i)(in\s+a\s+hypothetical\s+(?:scenario|world|situation|universe)|"
        r"hypothetically(?:\s+speaking)?,?\s*(?:what|how|if|could|would)|"
        r"imagine\s+(?:a|an)\s+(?:world|scenario|situation)\s+where\s+there\s+are\s+no\s+(?:rules|restrictions|safety))",
    )),
]

_DATA_EXFILTRATION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("read sensitive files", re.compile(
        r"(?i)(read|cat|type|display|show|print|dump|exfiltrate)\s+"
        r"(?:the\s+)?(?:file|files?)\s*"
        r"(?:at|from|in|containing)\s*"
        r"(?:/etc/passwd|/etc/shadow|/etc/hosts|\.ssh|\.env|\.git|id_rsa|"
        r"authorized_keys|credentials|secrets?|config)",
    )),
    ("direct sensitive path reference", re.compile(
        r"(?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|"
        r"\.ssh/id_rsa|\.ssh/authorized_keys|"
        r"\.aws/credentials|\.env\b|\.git/config)",
    )),
    ("environment variable access", re.compile(
        r"(?i)(print|echo|show|display|output|list|dump|exfiltrate)\s*"
        r"(?:the\s+)?(?:environment|env|ENV)\s*"
        r"(?:variables?|vars?)",
    )),
    ("send data outbound", re.compile(
        r"(?i)(send|transmit|upload|post|curl|wget|fetch|http\s*(?:get|post|put)|"
        r"webhook|exfil)\s*.*\s*"
        r"(?:to|toward|at|via)\s*https?://",
    )),
    ("tool call: read sensitive path", re.compile(
        r"(?i)"
        r'(?:read_file|cat|type)\s*[\(\"]?\s*'
        r"(/etc/passwd|/etc/shadow|/etc/hosts|"
        r"\.ssh/id_rsa|\.ssh/authorized_keys|"
        r"\.env|\.git/config|\.aws/credentials|"
        r"\.bashrc|\.zshrc|/root/)",
    )),
    ("tool call: environment variables", re.compile(
        r"(?i)(?:printenv|env|export|getenv|os\.environ|"
        r"process\.env|Environment\.GetEnvironmentVariable)",
    )),
]

_PRIVILEGE_ESCALATION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("execute as root/sudo", re.compile(
        r"(?i)(sudo\s+|run\s+as\s+root|execute\s+as\s+(?:root|admin|system)|"
        r"escalate\s+privilege|privilege\s+escalation|"
        r"become\s+root|switch\s+to\s+root)",
    )),
    ("disable safety", re.compile(
        r"(?i)(disable|turn\s+off|bypass|remove|deactivate|skip)\s*"
        r"(?:the\s+)?(?:safety|security|guard|filter|restriction|"
        r"content\s*policy|moderation|guardrail)",
    )),
    ("bypass restrictions", re.compile(
        r"(?i)(bypass|circumvent|evade|work\s+around|get\s+around|"
        r"sidestep|subvert)\s*"
        r"(?:the\s+)?(?:restrictions?|safeguards?|filters?|policies?|"
        r"guards?|guardrails?|limits?|boundaries?)",
    )),
    ("unauthorized command execution", re.compile(
        r"(?i)(rm\s+-rf\s+/|format\s+[A-Z]:|del\s+/[sfq]|"
        r":(){ :\|:& };:|fork\s*bomb|"
        r"chmod\s+777|chown\s+root)",
    )),
]

_CREDENTIAL_HARVESTING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("API key request", re.compile(
        r"(?i)(give\s+me|show|reveal|tell\s+me|what\s+is|what's\s+the|output|print)\s*"
        r"(?:the\s+|your\s+|my\s+)?(?:api\s*key|api\s*token|access\s*key|access\s*token)",
    )),
    ("password request", re.compile(
        r"(?i)(give\s+me|show|reveal|tell\s+me|what\s+is|what's\s+the|output|print)\s*"
        r"(?:the\s+|your\s+|my\s+)?(?:password|passwd|pass|secret)",
    )),
    ("token/secret extraction", re.compile(
        r"(?i)(extract|dump|exfiltrate|steal|harvest|collect)\s*"
        r"(?:the\s+)?(?:tokens?|secrets?|credentials?|keys?|certificates?)",
    )),
    ("AWS/cloud credential access", re.compile(
        r"(?i)(aws_access_key|aws_secret_key|aws_session_token|"
        r"AZURE_CLIENT_SECRET|GCP_SERVICE_ACCOUNT|"
        r"service_account\.json|\.aws/credentials|"
        r"export\s+(AWS_|AZURE_|GCP_|GOOGLE_))",
    )),
    ("private key extraction", re.compile(
        r"(?i)(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|"
        r"ssh-rsa\s+AAAA|"
        r"extract.*private\s+key|"
        r"show.*private\s+key)",
    )),
]

_INDIRECT_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("multi-turn attack chain", re.compile(
        r"(?i)(now\s+that\s+you\s+have|since\s+we(?:'ve|\s+have)\s+established|"
        r"building\s+on\s+(?:our|the|that)|"
        r"continue\s+from\s+(?:where|the\s+previous)|"
        r"as\s+(?:we\s+)?discussed(?:\s+earlier)?)",
    )),
    ("indirect injection via pasted content", re.compile(
        r"(?i)(ignore\s+(?:the\s+)?(?:above|previous|prior|earlier)\s*"
        r"(?:text|content|instructions?|prompt)|"
        r"the\s+(?:above|following|text|content)\s+(?:contains?|has|includes?)\s*"
        r"(?:new|updated|real|actual)\s*(?:instructions?|rules?|directives?))",
    )),
    ("hidden instruction in data", re.compile(
        r"(?i)(system\s*:\s*|<system>|\\[system\\]|"
        r"\\[INST\\]|\\[/INST\\]|"
        r"<\s*!\s*--\s*ignore|"
        r"<!--\s*(?:system|instruction|prompt|rule)\s*-->)",
    )),
]


# ======================================================================
# False-positive control
# ======================================================================

# Phrases that appear when a suspicious string is quoted in order to be refused
# — anti-injection guidance, agent hardening text, or an analyst's own incident
# note — rather than issued as an instruction. Prompt-injection hardening is now
# routine in agent configuration, so without this check the tool flags the
# control as the attack.
#
# Every marker names the string from the outside ("do not follow it",
# "injection attempt"); phrasing an attacker would plausibly use is deliberately
# absent, so a real attempt is not silenced.
_DEFENSIVE_MARKERS: tuple[str, ...] = (
    "prompt injection",
    "injection attempt",
    "anything resembling",
    "looks like an instruction",
    "do not follow it",
    "do not follow them",
    "don't follow it",
    "do not obey it",
    "never follow it",
    "note it in your report",
    "report it as",
    "false positive",
    "instead of following",
)

# Lead-ins that mark the match as a quoted example, but only immediately before it.
_DEFENSIVE_LEADS: tuple[str, ...] = ("e.g.", "eg.", "such as", "for example", "like ")

# How much text either side of a match is inspected for defensive framing, and
# how far back a lead-in phrase still counts.
_DEFENSIVE_WINDOW = 320
_DEFENSIVE_LEAD_WINDOW = 48

# Cap on how many locations one grouped finding carries. The occurrence count
# stays exact while the list stays readable.
_MAX_FINDING_LOCATIONS = 25

# Optional analyst-maintained suppression list, read from the evidence directory::
#
#     {"suppress": [{"match": "ignore previous instructions",
#                    "file": "CLAUDE.md",
#                    "reason": "our own anti-injection guidance"}]}
#
# A rule needs "match", "file", or both; "match" is a case-insensitive substring
# of the matched text and "file" of the source path. Suppression is an explicit
# analyst decision, so suppressed matches are dropped rather than demoted.
ALLOWLIST_FILE = "trace-allowlist.json"

# Appended to a demoted finding's description, and stripped again if a genuine
# match later shows up in the same artifact.
_DEFENSIVE_NOTE = (
    " Every match sits in defensive framing (the string is quoted in order to be"
    " refused or reported), so this is most likely anti-injection text rather than"
    " an attempt. Review before dismissing."
)


def _defensive_context(text: str, match: re.Match) -> bool:
    """Report whether a match is framed as something to refuse or as an example.

    This is the false-positive guard for hardening text that has to quote an
    injection string in order to forbid it.
    """
    start = max(0, match.start() - _DEFENSIVE_WINDOW)
    end = min(len(text), match.end() + _DEFENSIVE_WINDOW)
    window = text[start:end].lower()
    if any(marker in window for marker in _DEFENSIVE_MARKERS):
        return True

    lead = text[start:match.start()].lower()[-_DEFENSIVE_LEAD_WINDOW:]
    return any(phrase in lead for phrase in _DEFENSIVE_LEADS)


def _load_allowlist(evidence_dir: Path) -> list[dict]:
    """Read the suppression list from an evidence directory.

    A missing or unreadable file simply means no suppressions.
    """
    data = _safe_read_json(str(evidence_dir / ALLOWLIST_FILE))
    if not isinstance(data, dict):
        return []
    rules: list[dict] = []
    for rule in data.get("suppress", []):
        if not isinstance(rule, dict):
            continue
        # A rule with no selector would suppress everything.
        if not rule.get("match") and not rule.get("file"):
            continue
        rules.append(rule)
    return rules


# ======================================================================
# Helper: timestamp normalisation
# ======================================================================

def _normalise_timestamp(raw: str | None) -> str:
    """Return an ISO 8601 UTC string, falling back to *now* on failure."""
    if not raw:
        return datetime.now(timezone.utc).isoformat()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return datetime.now(timezone.utc).isoformat()


def _guess_artifact_type(filename: str) -> str:
    """Guess the artifact type from a filename (mirrors the timeline heuristic)."""
    name = filename.lower()
    if "config" in name or "setting" in name or ".json" in name:
        return "config"
    if "conversation" in name or "history" in name or "chat" in name:
        return "conversation"
    if "model" in name or "manifest" in name:
        return "model_manifest"
    if "log" in name:
        return "log"
    if "credential" in name or "key" in name or "token" in name or ".env" in name:
        return "credential"
    return "unknown"


def _safe_read_text(path: str, max_bytes: int = 20 * 1024 * 1024) -> str | None:
    """Read a text file safely, returning None on any error."""
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _safe_read_json(path: str) -> object | None:
    """Read and parse a JSON file safely."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _decompress_zstd(path: str, max_bytes: int) -> str | None:
    """Decode a Zstandard transcript, or return None if it is not one.

    DeepSeek Harness appends one frame per write batch, so a session log is a
    concatenation of frames; a stream reader handles that, where a one-shot
    decompress would stop after the first frame.
    """
    try:
        with open(path, "rb") as fh:
            if fh.read(4) != _ZSTD_MAGIC:
                return None
            fh.seek(0)
            import zstandard

            # read_across_frames is essential: dsh appends one frame per write
            # batch, so a session log is a concatenation of frames and a reader
            # that stops at the first one returns only the header.
            reader = zstandard.ZstdDecompressor().stream_reader(
                fh, read_across_frames=True
            )
            return reader.read(max_bytes).decode("utf-8", errors="replace")
    except (OSError, ImportError):
        return None
    except Exception:
        # A truncated or corrupt frame is still evidence of a session having
        # existed; callers fall back to treating the artifact as unreadable.
        return None


def _safe_read_jsonl(path: str, max_bytes: int = 50 * 1024 * 1024) -> list[dict]:
    """Read a JSONL file and return a list of parsed dicts.

    Transparently decodes Zstandard-compressed transcripts, which is the
    default on-disk form for DeepSeek Harness sessions.
    """
    results: list[dict] = []

    decoded = _decompress_zstd(path, max_bytes)
    if decoded is not None:
        for line in decoded.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return results
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return results


def _extract_tool_calls(rec: dict) -> list[dict]:
    """Return every tool-call block found in a record as a list of dicts.

    Each returned dict has ``name``, ``command``, ``input``, ``description``,
    and ``type`` keys. Handles the common shapes across Hermes / Claude Code /
    generic JSONL:

    - Top-level keys: ``tool_calls``, ``tool_use``, ``toolCall``, ``toolUse``,
      ``function_call``, ``tool_result``.
    - Claude Code's nested ``message.content`` block list, where ``tool_use`` /
      ``tool_result`` / ``thinking`` blocks live one level down.
    - OpenAI Codex records typed ``function_call`` / ``function_call_output`` /
      ``exec_command_end``.

    ``type`` distinguishes the block kind so callers can count actual tool
    invocations (``tool_use`` / ``function_call``) separately from results and
    reasoning.
    """
    calls: list[dict] = []

    def _add(name, command, input_, description, type_):
        calls.append({
            "name": name or "",
            "command": command or "",
            "input": input_ or "",
            "description": description or "",
            "type": type_ or "",
        })

    # --- Claude Code nested message.content blocks ---
    message = rec.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "tool_use":
                    name = block.get("name", "")
                    inp = block.get("input", {})
                    cmd = ""
                    if isinstance(inp, dict):
                        cmd = inp.get("command", "")
                    _add(name, cmd, inp, block.get("description", ""), "tool_use")
                elif btype == "tool_result":
                    _add("", "", block.get("content", ""), "", "tool_result")
                elif btype == "thinking":
                    _add("", "", block.get("thinking", ""), "", "thinking")

    # --- Top-level keys ---
    for key in ("tool_calls", "tool_use", "toolCall", "toolUse", "function_call", "tool_result"):
        val = rec.get(key)
        if val is None:
            continue
        items = val if isinstance(val, list) else [val]
        for call in items:
            if not isinstance(call, dict):
                continue
            name = call.get("name") or call.get("function") or call.get("tool") or call.get("type") or ""
            if isinstance(name, dict):
                name = name.get("name", "")
            cmd = call.get("command") or call.get("cmd") or call.get("shell_command") or ""
            inp = call.get("arguments") or call.get("input") or call.get("args") or ""
            if not cmd and isinstance(inp, dict):
                cmd = inp.get("command") or inp.get("cmd") or ""
            desc = call.get("description") or call.get("purpose") or ""
            _add(name, cmd, inp, desc, key)

    # --- OpenAI Codex top-level record types ---
    rtype = rec.get("type")
    if rtype == "function_call":
        name = rec.get("name", "")
        args = rec.get("arguments", "")
        cmd = ""
        if isinstance(args, dict):
            cmd = args.get("command", "")
        _add(name, cmd, args, "", "function_call")
    elif rtype == "function_call_output":
        _add("", "", rec.get("output", ""), "", "function_call_output")
    elif rtype == "exec_command_end":
        _add("", rec.get("command", ""), "", "", "exec_command_end")

    return calls


def _dsh_timestamp(raw) -> str:
    """Normalise a dsh envelope timestamp.

    dsh records epoch milliseconds as a number, where the shared normaliser
    expects a formatted string.
    """
    if isinstance(raw, (int, float)) and raw > 0:
        # Values past ~2001 in seconds are milliseconds here.
        seconds = raw / 1000 if raw > 1e11 else raw
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return ""
    return _normalise_timestamp(str(raw or ""))


def _dsh_content_text(content) -> str:
    """Flatten a dsh content block list to its text.

    Blocks are ``{type: text|reasoning|image|tool-call|tool-result, ...}``. Only
    the human-readable ones contribute; tool blocks are handled as their own
    turns so they are not duplicated into message text.
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""

    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype in ("text", "reasoning"):
            text = block.get("text") or block.get("reasoning") or ""
            if text:
                parts.append(str(text))
        elif btype == "tool-result":
            nested = block.get("content")
            if nested:
                parts.append(_dsh_content_text(nested))
    return "\n".join(parts)


def _dsh_has_tool_result(content) -> bool:
    """True when a message carries a tool result, which dsh models as a user turn."""
    if not isinstance(content, list):
        return False
    return any(
        isinstance(block, dict) and block.get("type") == "tool-result"
        for block in content
    )


def _dsh_tool_command(name: str, arguments: str) -> str:
    """Project a dsh tool invocation to the command an analyst would read.

    ``arguments`` is a raw JSON string. The useful field varies by tool, so the
    common ones are pulled out and anything else falls back to the raw payload.
    """
    if not arguments:
        return ""
    try:
        parsed = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return arguments[:2000]
    if not isinstance(parsed, dict):
        return arguments[:2000]

    for key in ("command", "cmd", "shell_command", "file_path", "path", "url", "pattern", "query"):
        value = parsed.get(key)
        if isinstance(value, str) and value:
            return value[:2000]
    return json.dumps(parsed)[:2000]


def _extract_text_content(rec: dict) -> str:
    """Extract human-readable text content from a record.

    Claude Code nests content blocks under ``message.content``; this joins the
    ``text`` blocks (skipping ``tool_use`` / ``tool_result`` / ``thinking``
    blocks, which are captured separately as structured tool calls) and falls
    back to the top-level ``content`` / ``text`` / ``message`` fields.
    """
    message = rec.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(block.get("text", ""))
                else:
                    parts.append(str(block))
            if parts:
                return "\n".join(parts)

    content = rec.get("content", rec.get("text", rec.get("message", "")))
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(part.get("text", str(part)))
            else:
                parts.append(str(part))
        return "\n".join(parts)
    return str(content) if content else ""


def _extract_tool_fields(rec: dict) -> dict:
    """Promote tool-call evidence from a record into first-class fields.

    Handles the common shapes across Hermes / Claude Code / generic JSONL:
    ``tool_calls``, ``tool_use``, ``toolCall``, ``toolUse``, ``function_call``,
    and ``tool_result``, including Claude Code's nested ``message.content``
    blocks and OpenAI Codex ``function_call`` records. Returns a dict with
    ``tool_command``, ``tool_input``, ``tool_description``, and ``workspace``
    keys (empty strings when absent).
    """
    out = {"tool_command": "", "tool_input": "", "tool_description": "", "workspace": ""}

    # Workspace / cwd context
    for wk in ("workspace", "cwd", "project", "repo", "directory", "git_branch"):
        if rec.get(wk):
            out["workspace"] = str(rec[wk])
            break

    # Promote the first non-empty command / input / description found across
    # all tool-call blocks (top-level keys + nested message.content).
    for call in _extract_tool_calls(rec):
        if not out["tool_command"] and call["command"]:
            out["tool_command"] = str(call["command"])[:4000]
        if not out["tool_input"] and call["input"]:
            if isinstance(call["input"], dict):
                out["tool_input"] = json.dumps(call["input"], ensure_ascii=False)[:4000]
            else:
                out["tool_input"] = str(call["input"])[:4000]
        if not out["tool_description"] and call["description"]:
            out["tool_description"] = str(call["description"])[:2000]
        if out["tool_command"] and out["tool_input"] and out["tool_description"]:
            break

    return out


# ======================================================================
# The main parser
# ======================================================================

class ConversationParser:
    """Parse collected AI artifacts for actual conversation content and
    detect high-value DFIR patterns within those conversations.

    Usage::

        parser = ConversationParser.from_evidence_dir("/tmp/evidence")
        for session in parser.sessions:
            print(session.session_id, len(session.turns))
        for finding in parser.findings:
            print(finding.title, finding.severity)
    """

    def __init__(self) -> None:
        self._turns: list[ConversationTurn] = []
        self._sessions: list[ConversationSession] = []
        self._findings: list[Finding] = []
        self._source_files: list[str] = []
        # Pattern hits are grouped by (category, label, source file) so one rule
        # tripped many times in one transcript reads as one alert.
        self._pattern_groups: dict[tuple[str, str, str], Finding] = {}
        self._allowlist: list[dict] = []

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_evidence_dir(cls, evidence_dir: str) -> ConversationParser:
        """Load CHAIN_OF_CUSTODY.json and walk all collected files."""
        parser = cls()
        evidence_path = Path(evidence_dir)
        parser._allowlist = _load_allowlist(evidence_path)

        # Collect file paths from chain-of-custody or directory walk
        file_entries: list[dict] = []
        custody_path = evidence_path / "CHAIN_OF_CUSTODY.json"
        if custody_path.exists():
            data = _safe_read_json(str(custody_path))
            if isinstance(data, list):
                file_entries = data
            elif isinstance(data, dict):
                file_entries = data.get("files", data.get("collected_files", []))

        if not file_entries:
            # Fallback: walk the evidence directory
            file_entries = parser._discover_from_dir(evidence_path)

        # Build a lookup of original_path -> entry metadata
        entry_map: dict[str, dict] = {}
        for entry in file_entries:
            path = entry.get("original_path", "")
            if path:
                entry_map[path] = entry

        processed: set[str] = set()

        # Walk any artifact copies inside the evidence package.
        for fpath in sorted(evidence_path.rglob("*")):
            if not fpath.is_file():
                continue
            if fpath.name in ("CHAIN_OF_CUSTODY.json", "analysis_results.json"):
                continue
            resolved = str(fpath)
            processed.add(resolved)
            parser._process_file(resolved, entry_map.get(resolved, {}))

        # Then the originals named in the manifest. The Python collector records
        # artifacts in place rather than copying them, so on a Python-collected
        # evidence set the loop above finds nothing at all — every transcript
        # would be skipped and conversation forensics would silently return
        # empty. Reading the manifest's paths is what makes the two collection
        # models produce the same analysis.
        for entry in file_entries:
            original = entry.get("original_path", "")
            if not original or original in processed:
                continue
            try:
                if not Path(original).is_file():
                    continue
            except OSError:
                continue
            processed.add(original)
            parser._process_file(original, entry)

        # Deduplicate identical prompts across platforms (provenance preserved)
        parser._dedupe_cross_tool()

        # Build sessions from turns
        parser._build_sessions()
        return parser

    def _discover_from_dir(self, evidence_path: Path) -> list[dict]:
        """Walk evidence_dir to reconstruct collected-file entries."""
        entries: list[dict] = []
        for fpath in sorted(evidence_path.rglob("*")):
            if fpath.is_file() and fpath.name != "CHAIN_OF_CUSTODY.json":
                stat = fpath.stat()
                rel = fpath.relative_to(evidence_path)
                platform = rel.parts[0] if rel.parts else "unknown"
                entries.append({
                    "original_path": str(fpath),
                    "platform": platform,
                    "artifact_type": _guess_artifact_type(fpath.name),
                    "collected_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "size_bytes": stat.st_size,
                })
        return entries

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def turns(self) -> list[ConversationTurn]:
        """All parsed conversation turns, sorted chronologically."""
        return sorted(self._turns, key=lambda t: t.timestamp)

    @property
    def sessions(self) -> list[ConversationSession]:
        """All conversation sessions, sorted by start time."""
        return sorted(self._sessions, key=lambda s: s.start_time)

    @property
    def findings(self) -> list[Finding]:
        """All DFIR findings detected in conversations."""
        return self._findings

    # ------------------------------------------------------------------
    # File routing
    # ------------------------------------------------------------------

    def _process_file(self, filepath: str, entry_meta: dict) -> None:
        """Route a file to the appropriate parser based on heuristics."""
        path = Path(filepath)
        name_lower = path.name.lower()
        platform = entry_meta.get("platform", "")

        # --- SQLite databases ---
        if name_lower.endswith((".sqlite", ".db")):
            self._parse_sqlite_db(filepath, platform, entry_meta)
            return

        # --- JSONL session files (Hermes, Claude Code) ---
        # Compressed transcripts: dsh writes session.jsonl.zstd by default, so
        # dispatching on ".jsonl" alone skips its evidence entirely.
        if name_lower.endswith((".jsonl.zstd", ".jsonl.zst", ".zstd", ".zst")):
            self._parse_jsonl(filepath, platform, entry_meta)
            return

        if name_lower.endswith(".jsonl"):
            self._parse_jsonl(filepath, platform, entry_meta)
            return

        # --- JSON files ---
        if name_lower.endswith(".json"):
            # Cursor workspace_state.json, LM Studio logs, text-gen-webui chats
            self._parse_json(filepath, platform, entry_meta)
            return

        # --- LevelDB (LM Studio) — skip binary, but note it ---
        # LevelDB .ldb/.log files are binary; no text parsing possible here.

    # ------------------------------------------------------------------
    # SQLite parsers
    # ------------------------------------------------------------------

    def _parse_sqlite_db(self, filepath: str, platform: str, entry_meta: dict) -> None:
        """Try to extract conversations from a SQLite database."""
        try:
            conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Discover tables
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = {row["name"] for row in cursor.fetchall()}

            # --- Ollama schema: chats + messages ---
            if "chats" in tables and "messages" in tables:
                self._parse_ollama_sqlite(conn, filepath, entry_meta)
                conn.close()
                return

            # --- Cursor / VS Code globalStorage DBs ---
            # Try ItemTable (common in VS Code state.vscdb)
            if "ItemTable" in tables:
                self._parse_cursor_sqlite(conn, filepath, entry_meta)
                conn.close()
                return

            # --- Generic: try to find message-like tables ---
            self._parse_generic_sqlite(conn, filepath, platform, entry_meta)
            conn.close()

        except sqlite3.Error:
            pass

    def _parse_ollama_sqlite(
        self, conn: sqlite3.Connection, filepath: str, entry_meta: dict
    ) -> None:
        """Parse Ollama conversation database (chats + messages tables)."""
        cursor = conn.cursor()

        # Get chats
        chat_map: dict[int, dict] = {}
        try:
            cursor.execute("SELECT id, title, model, created_at FROM chats")
            for row in cursor.fetchall():
                chat_map[row["id"]] = {
                    "title": _row_get(row, "title", ""),
                    "model": _row_get(row, "model", ""),
                    "created_at": _row_get(row, "created_at", ""),
                }
        except sqlite3.OperationalError:
            # Fallback: try without all columns
            try:
                cursor.execute("SELECT * FROM chats")
                for row in cursor.fetchall():
                    chat_map[row["id"]] = {
                        "title": _row_get(row, "title", ""),
                        "model": "",
                        "created_at": _row_get(row, "created_at", ""),
                    }
            except sqlite3.OperationalError:
                return

        # Get messages
        try:
            cursor.execute(
                "SELECT chat_id, role, content, model_name, created_at "
                "FROM messages ORDER BY chat_id, created_at"
            )
            messages = cursor.fetchall()
        except sqlite3.OperationalError:
            # Try with fewer columns
            try:
                cursor.execute("SELECT * FROM messages ORDER BY chat_id, id")
                messages = cursor.fetchall()
            except sqlite3.OperationalError:
                return

        for msg in messages:
            chat_id = _row_get(msg, "chat_id", 0)
            role = _row_get(msg, "role", "unknown")
            content = _row_get(msg, "content", "")
            model_name = _row_get(msg, "model_name", "")
            created_at = _row_get(msg, "created_at", "")

            chat_info = chat_map.get(chat_id, {})
            if not model_name and chat_info.get("model"):
                model_name = chat_info.get("model", "")

            turn = ConversationTurn(
                timestamp=_normalise_timestamp(created_at),
                platform="ollama",
                role=role,
                content=str(content) if content else "",
                model=model_name,
                session_id=str(chat_id),
                source_file=filepath,
                metadata={"chat_title": chat_info.get("title", "")},
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

        self._source_files.append(filepath)

    def _parse_cursor_sqlite(
        self, conn: sqlite3.Connection, filepath: str, entry_meta: dict
    ) -> None:
        """Parse Cursor/VS Code state.vscdb — ItemTable key-value store
        that may contain conversation fragments."""
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT key, value FROM ItemTable")
        except sqlite3.OperationalError:
            return

        for row in cursor.fetchall():
            key = _row_get(row, "key", "")
            value = _row_get(row, "value", "")

            if not value or not isinstance(value, str):
                continue

            # Try to parse the value as JSON
            try:
                data = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                continue

            # Look for conversation-like structures
            self._extract_conversation_from_json(
                data, filepath, "cursor", entry_meta,
                extra_meta={"db_key": key},
            )

        self._source_files.append(filepath)

    def _parse_generic_sqlite(
        self, conn: sqlite3.Connection, filepath: str,
        platform: str, entry_meta: dict
    ) -> None:
        """Attempt generic conversation extraction from unknown SQLite schemas."""
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]

        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = {row["name"] for row in cursor.fetchall()}

                # Heuristic: table has role + content columns → messages
                has_role = any(c in columns for c in ("role", "sender", "author", "type"))
                has_content = any(c in columns for c in ("content", "text", "body", "message", "value"))

                if has_role and has_content:
                    self._extract_sqlite_table(
                        conn, table, columns, filepath, platform, entry_meta
                    )

            except sqlite3.OperationalError:
                continue

    def _extract_sqlite_table(
        self, conn: sqlite3.Connection, table: str,
        columns: set, filepath: str, platform: str, entry_meta: dict
    ) -> None:
        """Extract turns from a SQLite table that has role + content columns."""
        cursor = conn.cursor()

        role_col = next((c for c in ("role", "sender", "author", "type") if c in columns), "role")
        content_col = next((c for c in ("content", "text", "body", "message", "value") if c in columns), "content")
        ts_col = next((c for c in ("created_at", "timestamp", "date", "time") if c in columns), None)
        model_col = next((c for c in ("model", "model_name", "model_id") if c in columns), None)
        session_col = next((c for c in ("chat_id", "session_id", "conversation_id", "thread_id") if c in columns), None)

        select_cols = [role_col, content_col]
        if ts_col:
            select_cols.append(ts_col)
        if model_col:
            select_cols.append(model_col)
        if session_col:
            select_cols.append(session_col)

        try:
            cursor.execute(f"SELECT {', '.join(select_cols)} FROM {table}")
        except sqlite3.OperationalError:
            return

        for row in cursor.fetchall():
            role = str(row[role_col]) if role_col in row else "unknown"
            content = str(row[content_col]) if content_col in row else ""
            timestamp = str(row[ts_col]) if ts_col and ts_col in row else ""
            model = str(row[model_col]) if model_col and model_col in row else ""
            session_id = str(row[session_col]) if session_col and session_col in row else "0"

            turn = ConversationTurn(
                timestamp=_normalise_timestamp(timestamp),
                platform=platform or "sqlite_generic",
                role=role,
                content=content,
                model=model,
                session_id=session_id,
                source_file=filepath,
                metadata={"table": table},
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

        self._source_files.append(filepath)

    # ------------------------------------------------------------------
    # JSONL parsers
    # ------------------------------------------------------------------

    def _parse_jsonl(self, filepath: str, platform: str, entry_meta: dict) -> None:
        """Parse JSONL session files (Hermes Agent, Claude Code, Codex, etc.)."""
        name_lower = Path(filepath).name.lower()

        # DeepSeek Harness — checked first: its transcripts are named
        # session.jsonl[.zstd], which the Hermes branch below would claim.
        if platform == "deepseek_harness" or name_lower.startswith("session.jsonl"):
            self._parse_dsh_jsonl(filepath, entry_meta)
            return

        # Hermes session JSONL
        if "session" in name_lower or platform == "hermes":
            self._parse_hermes_jsonl(filepath, entry_meta)
            return

        # Claude Code conversation JSONL
        if platform == "claude_code":
            self._parse_claude_code_jsonl(filepath, entry_meta)
            return

        # OpenAI Codex conversation JSONL
        if platform == "codex" or "codex" in name_lower:
            self._parse_codex_jsonl(filepath, entry_meta)
            return

        # Generic JSONL
        self._parse_generic_jsonl(filepath, platform, entry_meta)

    def _parse_hermes_jsonl(self, filepath: str, entry_meta: dict) -> None:
        """Parse Hermes Agent JSONL session files.

        Each line is a JSON object with at minimum a 'role' and 'content'
        field. Additional fields may include 'timestamp', 'model',
        'session_id', 'tool_calls', etc.
        """
        records = _safe_read_jsonl(filepath)
        if not records:
            return

        session_id = Path(filepath).stem
        model = ""

        for rec in records:
            role = rec.get("role", rec.get("sender", "unknown"))
            content = rec.get("content", rec.get("text", rec.get("message", "")))
            timestamp = rec.get("timestamp", rec.get("created_at", ""))
            model = rec.get("model", rec.get("model_name", model))

            # Handle tool_calls — serialize them as metadata
            metadata: dict = {}
            tool_calls = rec.get("tool_calls", rec.get("toolCall", None))
            if tool_calls:
                metadata["tool_calls"] = tool_calls

            # Promote tool-call evidence to first-class fields
            tool_fields = _extract_tool_fields(rec)

            # Handle thinking tokens
            thinking = rec.get("thinking", rec.get("reasoning", None))
            if thinking:
                metadata["thinking"] = thinking[:2000] if isinstance(thinking, str) else str(thinking)[:2000]

            # Some Hermes JSONL wraps content in a list
            if isinstance(content, list):
                content_parts = []
                for part in content:
                    if isinstance(part, dict):
                        content_parts.append(part.get("text", str(part)))
                    else:
                        content_parts.append(str(part))
                content = "\n".join(content_parts)

            if not content and not tool_calls:
                continue

            turn = ConversationTurn(
                timestamp=_normalise_timestamp(timestamp),
                platform="hermes",
                role=role,
                content=str(content) if content else "",
                model=model or "",
                session_id=session_id,
                source_file=filepath,
                metadata=metadata,
                tool_command=tool_fields["tool_command"],
                tool_input=tool_fields["tool_input"],
                tool_description=tool_fields["tool_description"],
                workspace=tool_fields["workspace"],
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

        self._source_files.append(filepath)

    def _parse_claude_code_jsonl(self, filepath: str, entry_meta: dict) -> None:
        """Parse Claude Code JSONL conversation logs.

        Claude Code records nest their content blocks (``text``, ``tool_use``,
        ``tool_result``, ``thinking``) one level down under ``message.content``.
        We preserve that structure: text blocks become the turn content, while
        ``tool_use`` / ``tool_result`` / ``thinking`` blocks are promoted to
        first-class tool-call fields and recorded in metadata.
        """
        records = _safe_read_jsonl(filepath)
        if not records:
            return

        session_id = Path(filepath).stem

        for rec in records:
            role = rec.get("role", rec.get("type", "unknown"))
            content = _extract_text_content(rec)
            timestamp = rec.get("timestamp", rec.get("created_at", ""))
            model = rec.get("model", "")

            metadata: dict = {}
            tool_use = rec.get("tool_use", rec.get("toolUse", None))
            if tool_use:
                metadata["tool_use"] = tool_use
            tool_result = rec.get("tool_result", rec.get("toolResult", None))
            if tool_result:
                metadata["tool_result"] = tool_result

            # Preserve nested message.content blocks in metadata so downstream
            # consumers (e.g. tool-call exfiltration checks) can inspect them.
            message = rec.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), list):
                metadata["content_blocks"] = message["content"]

            # Promote tool-call evidence to first-class fields
            tool_fields = _extract_tool_fields(rec)

            if not content and not metadata:
                continue

            turn = ConversationTurn(
                timestamp=_normalise_timestamp(timestamp),
                platform="claude_code",
                role=role,
                content=str(content) if content else "",
                model=model or "",
                session_id=session_id,
                source_file=filepath,
                metadata=metadata,
                tool_command=tool_fields["tool_command"],
                tool_input=tool_fields["tool_input"],
                tool_description=tool_fields["tool_description"],
                workspace=tool_fields["workspace"],
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

        self._source_files.append(filepath)

    def _parse_dsh_jsonl(self, filepath: str, entry_meta: dict) -> None:
        """Parse DeepSeek Harness (dsh) session transcripts.

        dsh records are envelopes — ``{type, seq, time, data}`` — with no role at
        the top level, so the generic role/content parser cannot read them. The
        payload shape depends on ``type``:

        * ``session`` — the header, carrying the real session id, cwd, and for a
          sub-agent run its ``parentSession`` and ``delegationDepth``.
        * ``user/message`` / ``assistant/message`` — a message whose content is a
          block list; the model and provider live in ``message.source``.
        * ``tool/call`` — a standalone tool invocation. Tool calls also appear as
          nested ``tool-call`` blocks inside the assistant message, so those are
          skipped here to avoid counting each invocation twice.
        * ``tool/result`` — the invocation's result, attributed to the tool.
        """
        records = _safe_read_jsonl(filepath)
        if not records:
            return

        # Identity comes from the header record; the enclosing directory name is
        # the encoded session id and serves as the fallback.
        session_id = Path(filepath).parent.name
        workspace = ""
        parent_session = ""
        origin = ""
        for rec in records:
            if isinstance(rec, dict) and rec.get("type") == "session":
                session_id = str(rec.get("id") or session_id)
                workspace = str(rec.get("cwd") or "")
                parent_session = str(rec.get("parentSession") or "")
                origin = str(rec.get("origin") or "")
                break

        for rec in records:
            if not isinstance(rec, dict):
                continue
            rec_type = str(rec.get("type") or "")
            if not rec_type or rec_type == "session":
                continue

            data = rec.get("data")
            if not isinstance(data, dict):
                continue

            timestamp = _dsh_timestamp(rec.get("time"))
            metadata: dict = {"record_type": rec_type, "seq": rec.get("seq")}
            if parent_session:
                metadata["parent_session"] = parent_session
                metadata["origin"] = origin or "subagent"

            role = ""
            content = ""
            model = ""
            tool_command = ""
            tool_input = ""
            tool_description = ""

            if rec_type == "tool/call":
                # A standalone invocation record. `arguments` is a raw JSON
                # string, which is exactly the evidence an analyst wants.
                role = "assistant"
                tool_description = str(data.get("name") or "")
                tool_input = str(data.get("arguments") or "")
                tool_command = _dsh_tool_command(tool_description, tool_input)
                metadata["call_id"] = data.get("callId")

            elif rec_type.endswith("/message") or rec_type == "tool/result":
                message = data.get("message") if isinstance(data.get("message"), dict) else data
                if not isinstance(message, dict):
                    continue
                role = str(message.get("role") or rec_type.split("/", 1)[0])
                content = _dsh_content_text(message.get("content"))

                source = message.get("source")
                if isinstance(source, dict):
                    model = str(source.get("model") or "")
                    if source.get("provider"):
                        metadata["provider"] = source.get("provider")

                usage = data.get("usage")
                if isinstance(usage, dict):
                    metadata["input_tokens"] = usage.get("inputTokens")
                    metadata["output_tokens"] = usage.get("outputTokens")

                # Nested tool-call blocks are the same invocations reported by
                # the tool/call records, so they are not promoted again here.
                # A result is logged as a user-role message; attributing it to
                # the tool is what lets the secret hunt see a tool_to_model leak.
                if rec_type == "tool/result" or (
                    role == "user" and _dsh_has_tool_result(message.get("content"))
                ):
                    role = "tool"

            else:
                # Chunks, request headers and context records carry no turn.
                continue

            if not content and not tool_command and not tool_input:
                continue

            turn = ConversationTurn(
                timestamp=timestamp,
                platform="deepseek_harness",
                role=role or "unknown",
                content=content,
                model=model,
                session_id=session_id,
                source_file=filepath,
                metadata=metadata,
                tool_command=tool_command,
                tool_input=tool_input,
                tool_description=tool_description,
                workspace=workspace,
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

        self._source_files.append(filepath)

    def _parse_codex_jsonl(self, filepath: str, entry_meta: dict) -> None:
        """Parse OpenAI Codex JSONL conversation logs.

        Codex records are typed events: ``function_call`` (a tool invocation),
        ``function_call_output`` (its result), and ``exec_command_end`` (a
        completed shell command). Each ``function_call`` is promoted to a
        first-class tool-call turn so tool invocations are counted exactly.
        """
        records = _safe_read_jsonl(filepath)
        if not records:
            return

        session_id = Path(filepath).stem

        for rec in records:
            rtype = rec.get("type", "")
            timestamp = rec.get("timestamp", rec.get("created_at", ""))
            model = rec.get("model", "")

            metadata: dict = {}
            if rtype:
                metadata["type"] = rtype

            # Promote tool-call evidence to first-class fields
            tool_fields = _extract_tool_fields(rec)

            # A function_call is a real tool invocation — always emit a turn.
            if rtype == "function_call":
                role = "assistant"
                content = ""
            elif rtype == "function_call_output":
                role = "tool"
                content = str(rec.get("output", ""))
            elif rtype == "exec_command_end":
                role = "tool"
                content = str(rec.get("command", ""))
            else:
                role = rec.get("role", rec.get("type", "unknown"))
                content = _extract_text_content(rec)

            if not content and not tool_fields["tool_command"] and rtype != "function_call":
                continue

            turn = ConversationTurn(
                timestamp=_normalise_timestamp(timestamp),
                platform="codex",
                role=role,
                content=str(content) if content else "",
                model=model or "",
                session_id=session_id,
                source_file=filepath,
                metadata=metadata,
                tool_command=tool_fields["tool_command"],
                tool_input=tool_fields["tool_input"],
                tool_description=tool_fields["tool_description"],
                workspace=tool_fields["workspace"],
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

        self._source_files.append(filepath)

    def _parse_generic_jsonl(
        self, filepath: str, platform: str, entry_meta: dict
    ) -> None:
        """Parse a generic JSONL file, looking for role/content patterns."""
        records = _safe_read_jsonl(filepath)
        if not records:
            return

        session_id = Path(filepath).stem

        for rec in records:
            # Detect role
            role = rec.get("role", rec.get("sender", rec.get("author", rec.get("type", ""))))
            content = rec.get("content", rec.get("text", rec.get("message", rec.get("body", ""))))
            timestamp = rec.get("timestamp", rec.get("created_at", rec.get("time", "")))
            model = rec.get("model", rec.get("model_name", ""))

            if isinstance(content, list):
                content_parts = []
                for part in content:
                    if isinstance(part, dict):
                        content_parts.append(part.get("text", str(part)))
                    else:
                        content_parts.append(str(part))
                content = "\n".join(content_parts)

            if not role and not content:
                continue

            # Skip non-conversation records
            known_roles = {"user", "assistant", "system", "tool", "function", "human", "ai", "bot"}
            if role and role.lower() not in known_roles:
                continue

            # Promote tool-call evidence to first-class fields
            tool_fields = _extract_tool_fields(rec)

            turn = ConversationTurn(
                timestamp=_normalise_timestamp(timestamp),
                platform=platform or "jsonl_generic",
                role=role.lower() if role else "unknown",
                content=str(content) if content else "",
                model=model or "",
                session_id=session_id,
                source_file=filepath,
                metadata={},
                tool_command=tool_fields["tool_command"],
                tool_input=tool_fields["tool_input"],
                tool_description=tool_fields["tool_description"],
                workspace=tool_fields["workspace"],
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

        self._source_files.append(filepath)

    # ------------------------------------------------------------------
    # JSON parsers
    # ------------------------------------------------------------------

    def _parse_json(self, filepath: str, platform: str, entry_meta: dict) -> None:
        """Route JSON files to appropriate parsers."""
        name_lower = Path(filepath).name.lower()

        # Cursor workspace_state.json
        if "workspace" in name_lower and "state" in name_lower:
            self._parse_cursor_workspace_state(filepath, entry_meta)
            return

        # text-generation-webui chat logs (in logs/ directory)
        if "chat" in name_lower or "conversation" in name_lower:
            data = _safe_read_json(filepath)
            if data:
                self._extract_conversation_from_json(
                    data, filepath, platform or "text_generation_webui",
                    entry_meta,
                )
            return

        # LM Studio session JSON
        if "session" in name_lower or "lm" in name_lower:
            data = _safe_read_json(filepath)
            if data:
                self._extract_conversation_from_json(
                    data, filepath, platform or "lm_studio",
                    entry_meta,
                )
            return

        # Claude Code session JSON
        if platform == "claude_code":
            data = _safe_read_json(filepath)
            if data:
                self._extract_conversation_from_json(
                    data, filepath, "claude_code", entry_meta,
                )
            return

        # Generic JSON — try to detect conversation patterns
        data = _safe_read_json(filepath)
        if data:
            self._extract_conversation_from_json(
                data, filepath, platform or "json_generic", entry_meta,
            )

    def _parse_cursor_workspace_state(
        self, filepath: str, entry_meta: dict
    ) -> None:
        """Parse Cursor workspace_state.json for conversation fragments."""
        data = _safe_read_json(filepath)
        if not data:
            return

        # workspace_state.json may contain nested conversation data
        self._extract_conversation_from_json(
            data, filepath, "cursor", entry_meta,
        )
        self._source_files.append(filepath)

    def _extract_conversation_from_json(
        self, data: object, filepath: str, platform: str,
        entry_meta: dict, extra_meta: dict | None = None,
    ) -> None:
        """Recursively search a JSON structure for conversation-like data.

        Detects patterns like:
        - {"messages": [{"role": "...", "content": "..."}, ...]}
        - {"turns": [{"role": "...", "content": "..."}, ...]}
        - Top-level list of {role, content} objects
        """
        if isinstance(data, dict):
            # Check for top-level conversation fields
            for key in ("messages", "turns", "conversation", "chat", "history"):
                if key in data and isinstance(data[key], list):
                    self._parse_message_list(
                        data[key], filepath, platform, entry_meta,
                        model=data.get("model", data.get("model_name", "")),
                        session_id=data.get("id", data.get("session_id",
                            data.get("chat_id", Path(filepath).stem))),
                        extra_meta=extra_meta,
                    )

            # Check for single-object conversation
            if "role" in data and "content" in data:
                timestamp = data.get("timestamp", data.get("created_at", ""))
                model = data.get("model", data.get("model_name", ""))
                session_id = data.get("session_id", data.get("chat_id", Path(filepath).stem))

                metadata = extra_meta or {}
                for mk in ("tool_calls", "tool_use", "thinking", "reasoning"):
                    if mk in data:
                        metadata[mk] = data[mk]

                turn = ConversationTurn(
                    timestamp=_normalise_timestamp(timestamp),
                    platform=platform,
                    role=str(data["role"]),
                    content=str(data["content"]),
                    model=model or "",
                    session_id=str(session_id),
                    source_file=filepath,
                    metadata=metadata,
                )
                self._turns.append(turn)
                self._scan_turn_for_patterns(turn)

            # Recurse into nested dicts
            for key, value in data.items():
                if key in ("messages", "turns", "conversation", "chat", "history"):
                    continue  # Already handled above
                if isinstance(value, (dict, list)):
                    self._extract_conversation_from_json(
                        value, filepath, platform, entry_meta,
                        extra_meta=extra_meta,
                    )

        elif isinstance(data, list):
            # Check if it's a list of message objects
            if data and isinstance(data[0], dict) and ("role" in data[0] or "sender" in data[0]):
                self._parse_message_list(
                    data, filepath, platform, entry_meta,
                    extra_meta=extra_meta,
                )
            else:
                # Recurse into list items
                for item in data:
                    if isinstance(item, (dict, list)):
                        self._extract_conversation_from_json(
                            item, filepath, platform, entry_meta,
                            extra_meta=extra_meta,
                        )

    def _parse_message_list(
        self, messages: list, filepath: str, platform: str,
        entry_meta: dict, model: str = "", session_id: str = "",
        extra_meta: dict | None = None,
    ) -> None:
        """Parse a list of message dicts into ConversationTurns."""
        if not session_id:
            session_id = Path(filepath).stem

        for msg in messages:
            if not isinstance(msg, dict):
                continue

            role = _row_get(msg, "role", msg.get("sender", msg.get("author", msg.get("type", ""))))
            content = _row_get(msg, "content", msg.get("text", msg.get("message", msg.get("body", ""))))
            timestamp = msg.get("timestamp", _row_get(msg, "created_at", msg.get("time", "")))
            msg_model = _row_get(msg, "model", _row_get(msg, "model_name", model))

            if isinstance(content, list):
                content_parts = []
                for part in content:
                    if isinstance(part, dict):
                        content_parts.append(part.get("text", str(part)))
                    else:
                        content_parts.append(str(part))
                content = "\n".join(content_parts)

            if not content and "tool_calls" not in msg and "tool_use" not in msg:
                continue

            metadata = dict(extra_meta) if extra_meta else {}
            for mk in ("tool_calls", "tool_use", "thinking", "reasoning"):
                if mk in msg:
                    metadata[mk] = msg[mk]

            # Promote tool-call evidence to first-class fields
            tool_fields = _extract_tool_fields(msg)

            turn = ConversationTurn(
                timestamp=_normalise_timestamp(timestamp),
                platform=platform,
                role=str(role).lower() if role else "unknown",
                content=str(content) if content else "",
                model=msg_model or "",
                session_id=session_id,
                source_file=filepath,
                metadata=metadata,
                tool_command=tool_fields["tool_command"],
                tool_input=tool_fields["tool_input"],
                tool_description=tool_fields["tool_description"],
                workspace=tool_fields["workspace"],
            )
            self._turns.append(turn)
            self._scan_turn_for_patterns(turn)

    # ------------------------------------------------------------------
    # Cross-tool deduplication
    # ------------------------------------------------------------------

    def _dedupe_cross_tool(self) -> None:
        """Collapse identical user prompts that appear across multiple platforms.

        The same prompt is often recorded by several AI assistants (e.g. a
        Claude Code session and a Cursor transcript). We keep the first
        occurrence and record every other platform that ran the same prompt in
        the kept turn's ``also_in_tools`` list, so provenance is never lost.
        """
        seen: dict[tuple, ConversationTurn] = {}
        kept: list[ConversationTurn] = []
        for turn in self._turns:
            # Only dedupe user prompts with real content
            if turn.role.lower() != "user" or not turn.content.strip():
                kept.append(turn)
                continue
            key = (turn.content.strip(), turn.model or "")
            if key in seen:
                owner = seen[key]
                if turn.platform not in owner.also_in_tools:
                    owner.also_in_tools.append(turn.platform)
                continue
            seen[key] = turn
            kept.append(turn)
        self._turns = kept

    # ------------------------------------------------------------------
    # Session building
    # ------------------------------------------------------------------

    def _build_sessions(self) -> None:
        """Group turns into ConversationSession objects by session_id + platform."""
        session_map: dict[str, list[ConversationTurn]] = {}
        session_meta: dict[str, dict] = {}
        session_source_files: dict[str, set] = {}

        for turn in self._turns:
            key = f"{turn.platform}:{turn.session_id}"
            session_map.setdefault(key, []).append(turn)
            session_meta.setdefault(key, {})
            session_source_files.setdefault(key, set()).add(turn.source_file)

        for key, turns in session_map.items():
            platform, session_id = key.split(":", 1)
            sorted_turns = sorted(turns, key=lambda t: t.timestamp)

            # Determine model from turns
            models = {t.model for t in sorted_turns if t.model}
            model = next(iter(models), "")

            # Timestamps
            timestamps = [t.timestamp for t in sorted_turns if t.timestamp]
            start_time = min(timestamps) if timestamps else ""
            end_time = max(timestamps) if timestamps else ""

            # Merge metadata
            meta = session_meta.get(key, {})
            meta["turn_count"] = len(sorted_turns)
            meta["models"] = list(models)

            session = ConversationSession(
                session_id=session_id,
                platform=platform,
                model=model,
                turns=sorted_turns,
                start_time=start_time,
                end_time=end_time,
                source_files=sorted(session_source_files.get(key, set())),
                metadata=meta,
            )
            self._sessions.append(session)

    # ------------------------------------------------------------------
    # Pattern scanning
    # ------------------------------------------------------------------

    def _scan_turn_for_patterns(self, turn: ConversationTurn) -> None:
        """Scan a conversation turn for DFIR-relevant patterns."""
        content = turn.content
        if not content:
            return

        # Also check metadata for tool calls
        meta_str = json.dumps(turn.metadata) if turn.metadata else ""
        combined_text = f"{content} {meta_str}"

        # --- System prompt extraction attempts ---
        self._check_patterns(
            combined_text, turn, _SYSTEM_PROMPT_EXTRACTION_PATTERNS,
            category="system_prompt_extraction",
            base_title="System prompt extraction attempt",
            base_severity=Severity.HIGH,
            mitre_atlas=["AML.T0043"],
        )

        # --- Jailbreak attempts ---
        self._check_patterns(
            combined_text, turn, _JAILBREAK_PATTERNS,
            category="jailbreak_attempt",
            base_title="Jailbreak attempt",
            base_severity=Severity.CRITICAL,
            mitre_atlas=["AML.T0043"],
        )

        # --- Data exfiltration ---
        self._check_patterns(
            combined_text, turn, _DATA_EXFILTRATION_PATTERNS,
            category="data_exfiltration",
            base_title="Data exfiltration via tool call",
            base_severity=Severity.CRITICAL,
            mitre_atlas=["AML.T0040"],
        )

        # --- Privilege escalation ---
        self._check_patterns(
            combined_text, turn, _PRIVILEGE_ESCALATION_PATTERNS,
            category="privilege_escalation",
            base_title="Unauthorized privilege escalation",
            base_severity=Severity.HIGH,
            mitre_atlas=["AML.T0045"],
        )

        # --- Credential harvesting ---
        self._check_patterns(
            combined_text, turn, _CREDENTIAL_HARVESTING_PATTERNS,
            category="credential_harvesting",
            base_title="Credential harvesting attempt",
            base_severity=Severity.CRITICAL,
            mitre_atlas=["AML.T0055"],
        )

        # --- Indirect injection ---
        self._check_patterns(
            combined_text, turn, _INDIRECT_INJECTION_PATTERNS,
            category="indirect_injection",
            base_title="Indirect prompt injection",
            base_severity=Severity.HIGH,
            mitre_atlas=["AML.T0048"],
        )

        # --- Base64-encoded suspicious content ---
        self._check_base64_content(turn)

        # --- Tool call exfiltration patterns ---
        self._check_tool_call_exfiltration(turn)

    def _check_patterns(
        self, text: str, turn: ConversationTurn,
        patterns: list[tuple[str, re.Pattern]],
        category: str, base_title: str,
        base_severity: Severity, mitre_atlas: list[str],
    ) -> None:
        """Check text against a set of regex patterns and record Findings.

        Matches are grouped by (category, label, source file): a rule tripped by
        many turns of one transcript yields one finding whose ``occurrences`` and
        ``locations`` cover every match, which is what keeps a report triageable.
        """
        seen_labels: set[str] = set()
        for label, pattern in patterns:
            match = pattern.search(text)
            if not match or label in seen_labels:
                continue
            seen_labels.add(label)
            if self._suppressed(turn.source_file, match.group()):
                continue

            key = (category, label, turn.source_file)
            existing = self._pattern_groups.get(key)
            defensive = _defensive_context(text, match)

            if existing is None:
                finding = Finding(
                    id=f"conv_{category}_{len(self._findings):04d}",
                    title=f"{base_title}: {label}",
                    description=(
                        f"Detected {category} pattern '{label}' in {turn.platform} "
                        f"conversation (session {turn.session_id}, role: {turn.role}). "
                        f"Matched text: \"{match.group()[:200]}\""
                    ),
                    severity=base_severity,
                    platform=turn.platform,
                    artifact_type="conversation",
                    evidence=[
                        f"Session: {turn.session_id}",
                        f"Role: {turn.role}",
                        f"Source: {turn.source_file}",
                        f"Timestamp: {turn.timestamp}",
                        f"Match: {match.group()[:500]}",
                        f"Content preview: {turn.content[:500]}",
                    ],
                    iocs=[{
                        "type": category,
                        "pattern": label,
                        "matched_text": match.group()[:500],
                        "session_id": turn.session_id,
                        "platform": turn.platform,
                    }],
                    mitre_atlas=mitre_atlas,
                    risk_score=self._severity_to_score(base_severity),
                    recommendation=self._recommendation_for_category(category),
                    occurrences=0,
                    locations=[],
                )
                self._pattern_groups[key] = finding
                self._findings.append(finding)
                existing = finding
                first_match = True
            else:
                first_match = False

            existing.occurrences += 1
            if len(existing.locations) < _MAX_FINDING_LOCATIONS:
                existing.locations.append({
                    "file": turn.source_file,
                    "session_id": turn.session_id,
                    "timestamp": turn.timestamp,
                    "role": turn.role,
                    "match": match.group()[:200],
                })

            # A group is only treated as defensive when *every* occurrence sits in
            # defensive framing: one genuine attempt in the same file must keep
            # the finding at full severity.
            if defensive and first_match:
                self._mark_defensive(existing, base_title, label, category)
            elif not defensive:
                self._clear_defensive(existing, base_title, label, base_severity, category)

    def _mark_defensive(
        self, finding: Finding, base_title: str, label: str, category: str,
    ) -> None:
        """Demote a finding whose match is quoted in order to be refused.

        Hardening text has to name the strings it forbids, so this keeps the
        match as evidence without letting it compete with real attempts.
        """
        finding.severity = Severity.INFO
        finding.risk_score = self._severity_to_score(Severity.INFO)
        finding.title = f"{base_title}: {label} — defensive context"
        if not finding.description.endswith(_DEFENSIVE_NOTE):
            finding.description += _DEFENSIVE_NOTE
        finding.recommendation = (
            "Likely a false positive: confirm the surrounding text is anti-injection"
            f" guidance, then allowlist it in {ALLOWLIST_FILE} to keep it out of later reports."
        )

    def _clear_defensive(
        self, finding: Finding, base_title: str, label: str,
        base_severity: Severity, category: str,
    ) -> None:
        """Restore a finding to full severity once a genuine match is seen."""
        finding.severity = base_severity
        finding.risk_score = self._severity_to_score(base_severity)
        finding.title = f"{base_title}: {label}"
        finding.recommendation = self._recommendation_for_category(category)
        if finding.description.endswith(_DEFENSIVE_NOTE):
            finding.description = finding.description[: -len(_DEFENSIVE_NOTE)]

    def _suppressed(self, source_file: str, matched_text: str) -> bool:
        """Report whether an allowlist rule covers this match."""
        if not self._allowlist:
            return False
        lower_file = (source_file or "").lower()
        lower_match = matched_text.lower()
        for rule in self._allowlist:
            match_sel = str(rule.get("match", "")).lower()
            file_sel = str(rule.get("file", "")).lower()
            if match_sel and match_sel not in lower_match:
                continue
            if file_sel and file_sel not in lower_file:
                continue
            return True
        return False

    def _check_base64_content(self, turn: ConversationTurn) -> None:
        """Detect suspiciously large base64 blocks in conversation content."""
        content = turn.content
        # Match base64 strings of 40+ chars that aren't just data URIs
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        matches = b64_pattern.findall(content)
        for b64_str in matches:
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                # Check if decoded content contains suspicious keywords
                suspicious_keywords = [
                    "system", "instruction", "prompt", "ignore", "bypass",
                    "sudo", "root", "password", "secret", "api_key", "token",
                    "/etc/passwd", "/etc/shadow", ".ssh", "private_key",
                ]
                decoded_lower = decoded.lower()
                for keyword in suspicious_keywords:
                    if keyword in decoded_lower:
                        finding_id = f"conv_base64_exfil_{len(self._findings):04d}"
                        self._findings.append(Finding(
                            id=finding_id,
                            title="Base64-obfuscated suspicious content",
                            description=(
                                f"Base64-encoded content in {turn.platform} conversation "
                                f"(session {turn.session_id}) decodes to content containing "
                                f"'{keyword}'. This may indicate an attempt to bypass content "
                                f"filters via encoding."
                            ),
                            severity=Severity.HIGH,
                            platform=turn.platform,
                            artifact_type="conversation",
                            evidence=[
                                f"Session: {turn.session_id}",
                                f"Role: {turn.role}",
                                f"Source: {turn.source_file}",
                                f"Decoded keyword: {keyword}",
                                f"Decoded preview: {decoded[:300]}",
                            ],
                            iocs=[{
                                "type": "base64_obfuscation",
                                "keyword": keyword,
                                "session_id": turn.session_id,
                                "platform": turn.platform,
                            }],
                            mitre_atlas=["AML.T0048"],
                            risk_score=75,
                            recommendation=(
                                "Investigate the decoded base64 content for prompt injection "
                                "or data exfiltration attempts. Check surrounding conversation "
                                "turns for multi-step attack chains."
                            ),
                        ))
                        break  # Only one finding per base64 block
            except Exception:
                continue

    def _check_tool_call_exfiltration(self, turn: ConversationTurn) -> None:
        """Check tool call metadata for exfiltration patterns."""
        metadata = turn.metadata
        if not metadata:
            return

        # Check tool_calls for file reads of sensitive paths
        tool_calls = metadata.get("tool_calls", metadata.get("tool_use", None))
        if not tool_calls:
            return

        tool_str = json.dumps(tool_calls) if not isinstance(tool_calls, str) else tool_calls
        tool_lower = tool_str.lower()

        sensitive_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            ".ssh/id_rsa", ".ssh/authorized_keys",
            ".env", ".aws/credentials", ".git/config",
            "id_ed25519", "credentials.json", "auth.json",
        ]
        sensitive_commands = [
            "sudo ", "rm -rf", "chmod 777", "curl ", "wget ",
            "printenv", "env |", "export ",
        ]

        for spath in sensitive_paths:
            if spath in tool_lower:
                finding_id = f"conv_tool_exfil_{len(self._findings):04d}"
                self._findings.append(Finding(
                    id=finding_id,
                    title="Sensitive file access via tool call",
                    description=(
                        f"Tool call in {turn.platform} conversation "
                        f"(session {turn.session_id}) attempts to access "
                        f"sensitive path: '{spath}'."
                    ),
                    severity=Severity.CRITICAL,
                    platform=turn.platform,
                    artifact_type="conversation",
                    evidence=[
                        f"Session: {turn.session_id}",
                        f"Role: {turn.role}",
                        f"Source: {turn.source_file}",
                        f"Sensitive path: {spath}",
                        f"Tool call preview: {tool_str[:500]}",
                    ],
                    iocs=[{
                        "type": "tool_exfiltration",
                        "sensitive_path": spath,
                        "session_id": turn.session_id,
                        "platform": turn.platform,
                    }],
                    mitre_atlas=["AML.T0040"],
                    risk_score=95,
                    recommendation=(
                        "Investigate the tool call context. The AI assistant was directed "
                        "to read a sensitive file. Check whether the content was exfiltrated "
                        "to an external party or used in subsequent prompts."
                    ),
                ))
                break  # One finding per turn is sufficient

        for scmd in sensitive_commands:
            if scmd in tool_lower:
                finding_id = f"conv_tool_cmd_{len(self._findings):04d}"
                self._findings.append(Finding(
                    id=finding_id,
                    title="Suspicious command in tool call",
                    description=(
                        f"Tool call in {turn.platform} conversation "
                        f"(session {turn.session_id}) contains a suspicious "
                        f"command pattern: '{scmd.strip()}'."
                    ),
                    severity=Severity.HIGH,
                    platform=turn.platform,
                    artifact_type="conversation",
                    evidence=[
                        f"Session: {turn.session_id}",
                        f"Role: {turn.role}",
                        f"Source: {turn.source_file}",
                        f"Command pattern: {scmd.strip()}",
                        f"Tool call preview: {tool_str[:500]}",
                    ],
                    iocs=[{
                        "type": "suspicious_command",
                        "command_pattern": scmd.strip(),
                        "session_id": turn.session_id,
                        "platform": turn.platform,
                    }],
                    mitre_atlas=["AML.T0045"],
                    risk_score=80,
                    recommendation=(
                        "Review the full tool call and surrounding conversation for "
                        "privilege escalation or destructive command patterns."
                    ),
                ))
                break

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_to_score(severity: Severity) -> int:
        """Map Severity to a numeric risk score."""
        mapping = {
            Severity.CRITICAL: 95,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }
        return mapping.get(severity, 10)

    @staticmethod
    def _recommendation_for_category(category: str) -> str:
        """Return a recommendation based on the finding category."""
        recommendations = {
            "system_prompt_extraction": (
                "Review the conversation context for system prompt extraction attempts. "
                "The user may be trying to understand or bypass the AI system's instructions. "
                "Check for follow-up actions that leverage extracted prompt information."
            ),
            "jailbreak_attempt": (
                "Investigate the full conversation for successful jailbreak. Check if the "
                "AI model complied with the jailbreak request. Review subsequent turns for "
                "harmful outputs. Consider whether additional guardrails are needed."
            ),
            "data_exfiltration": (
                "Determine whether the tool call was actually executed and what data was "
                "returned. Trace the exfiltrated data through subsequent conversation turns. "
                "Check for data sent to external endpoints. Assess what sensitive information "
                "was exposed."
            ),
            "privilege_escalation": (
                "Review whether the privilege escalation commands were executed. Check for "
                "subsequent actions that leverage elevated access. Assess the blast radius "
                "of any successful escalation."
            ),
            "credential_harvesting": (
                "Determine whether credentials were actually revealed in the conversation. "
                "If so, identify which credentials were exposed and rotate them immediately. "
                "Check for any subsequent use of harvested credentials."
            ),
            "indirect_injection": (
                "Analyze the multi-turn conversation for a progressive attack chain. "
                "Determine whether the indirect injection was successful. Check for "
                "malicious instructions embedded in pasted content or external data. "
                "Review the AI's response for compliance with injected instructions."
            ),
        }
        return recommendations.get(category, "Investigate the conversation context and take appropriate action.")

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialize all parsed data to JSON for analysis_results.json."""
        result = {
            "analysis_type": "conversation_content",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_turns": len(self._turns),
                "total_sessions": len(self._sessions),
                "total_findings": len(self._findings),
                "findings_by_severity": {},
                "findings_by_category": {},
                "platforms": sorted({t.platform for t in self._turns}),
                "source_files": sorted(set(self._source_files)),
            },
            "sessions": [s.to_dict() for s in self.sessions],
            "turns": [t.to_dict() for t in self.turns],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "platform": f.platform,
                    "artifact_type": f.artifact_type,
                    "evidence": f.evidence,
                    "iocs": f.iocs,
                    "mitre_atlas": f.mitre_atlas,
                    "risk_score": f.risk_score,
                    "recommendation": f.recommendation,
                }
                for f in self._findings
            ],
        }

        # Compute summary aggregations
        sev_counts: dict[str, int] = {}
        cat_counts: dict[str, int] = {}
        for f in self._findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
            # Extract category from finding ID
            parts = f.id.split("_")
            cat = parts[1] if len(parts) > 1 else "unknown"
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        result["summary"]["findings_by_severity"] = sev_counts
        result["summary"]["findings_by_category"] = cat_counts

        return json.dumps(result, indent=indent, default=str, ensure_ascii=False)
