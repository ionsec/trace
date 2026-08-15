"""
ConversationSecretHunt — scan parsed AI conversation turns for leaked secrets.

Runs the shared SecretDetector over the prompts, responses, and tool-call
evidence an analyst actually cares about, and enriches each finding with:

  * leak direction  — whether the secret flowed user→service (typed by the
    subject) or service→user (returned by the model / a tool result);
  * per-field provenance — which evidence field (content, tool_command,
    tool_input, tool_description) carried the secret, with start/end offsets;
  * a salted fingerprint — a stable per-scan hash so the same secret can be
    correlated across rows, sessions, and platforms without cleartext ever
    being written to disk.

Findings are permanently redacted (first4…last4 + length). Cleartext never
crosses the result path.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import asdict, dataclass, field

from ionsec_trace.analyzer.conversation_parser import ConversationTurn
from ionsec_trace.analyzer.secret_detector import SecretDetector

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ConversationSecretFinding:
    """A secret detected inside a conversation turn, with provenance."""

    rule_id: str
    secret_type: str
    description: str
    severity: str
    redacted: str
    fingerprint: str
    confidence: float
    leak_direction: str            # "user→service" | "service→user" | ""
    evidence_field: str            # content | tool_command | tool_input | tool_description
    start_offset: int
    end_offset: int
    timestamp: str
    platform: str
    role: str
    session_id: str
    source_file: str
    workspace: str = ""
    also_in_tools: list = field(default_factory=list)
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ConversationSecretHuntResult:
    """Aggregated result of a conversation secret hunt."""

    findings: list[ConversationSecretFinding] = field(default_factory=list)
    total: int = 0
    flagged_turns: int = 0
    unique_secrets: int = 0
    by_severity: dict = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    })
    by_leak_direction: dict = field(default_factory=dict)
    by_platform: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "total": self.total,
            "flagged_turns": self.flagged_turns,
            "unique_secrets": self.unique_secrets,
            "by_severity": self.by_severity,
            "by_leak_direction": self.by_leak_direction,
            "by_platform": self.by_platform,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SNIPPET_PAD = 48
_MAX_FINDINGS = 10_000


def _leak_direction(role: str) -> str:
    r = str(role or "").lower()
    if r == "user":
        return "user→service"
    if r in ("assistant", "tool", "function"):
        return "service→user"
    return ""


def _fingerprint(value: str, salt: str) -> str:
    """Stable per-scan fingerprint for cross-row correlation (no cleartext)."""
    return hmac.new(
        salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:16]


def _snippet(text: str, start: int, end: int, replacement: str = "") -> str:
    """Return the text surrounding a match, with the match itself redacted.

    The snippet exists so an analyst can see how a credential was used — the
    sentence around it, not the credential. Without the substitution below the
    raw value travels verbatim into analysis_results.json and every report built
    from it, which would defeat the point of redacting it in the first place.
    """
    # Expand the match to its whole whitespace-delimited token before
    # substituting. A rule's reported end offset can fall short of the full
    # value, and splicing on that boundary alone leaves the tail of the
    # credential sitting in the snippet.
    tok_start, tok_end = start, end
    while tok_start > 0 and not text[tok_start - 1].isspace() and text[tok_start - 1] not in "\"'`":
        tok_start -= 1
    while tok_end < len(text) and not text[tok_end].isspace() and text[tok_end] not in "\"'`":
        tok_end += 1

    s = max(0, tok_start - _SNIPPET_PAD)
    e = min(len(text), tok_end + _SNIPPET_PAD)
    seg = text[s:tok_start] + (replacement or "***REDACTED***") + text[tok_end:e]
    return f"{'…' if s > 0 else ''}{seg}{'…' if e < len(text) else ''}".replace("\n", " ").strip()


# ---------------------------------------------------------------------------
# The hunt
# ---------------------------------------------------------------------------


class ConversationSecretHunt:
    """Scan conversation turns for leaked secrets with full provenance."""

    def __init__(self, detector: SecretDetector | None = None, salt: str | None = None):
        self.detector = detector or SecretDetector()
        self.salt = salt or secrets.token_hex(8)

    # -- public API --------------------------------------------------------

    def scan_turn(self, turn: ConversationTurn) -> list[ConversationSecretFinding]:
        """Scan a single turn's content + tool-call evidence for secrets."""
        findings: list[ConversationSecretFinding] = []
        direction = _leak_direction(turn.role)

        # Scan each evidence field with provenance
        fields = [
            ("content", turn.content),
            ("tool_command", turn.tool_command),
            ("tool_input", turn.tool_input),
            ("tool_description", turn.tool_description),
        ]
        for field_name, text in fields:
            if not text:
                continue
            for match in self.detector.scan(text, file_path=turn.source_file):
                # Locate the match within the field text for offsets
                start = max(text.find(match.redacted.replace("…", "")) if match.redacted else -1, 0)
                end = start + match.raw_length
                findings.append(ConversationSecretFinding(
                    rule_id=match.rule_id,
                    secret_type=match.secret_type,
                    description=match.description,
                    severity=match.severity,
                    redacted=match.redacted,
                    fingerprint=_fingerprint(match.redacted, self.salt),
                    confidence=match.confidence,
                    leak_direction=direction,
                    evidence_field=field_name,
                    start_offset=start,
                    end_offset=end,
                    timestamp=turn.timestamp,
                    platform=turn.platform,
                    role=turn.role,
                    session_id=turn.session_id,
                    source_file=turn.source_file,
                    workspace=turn.workspace,
                    also_in_tools=list(turn.also_in_tools),
                    snippet=_snippet(text, start, end, match.redacted),
                ))
        return findings

    def scan_turns(self, turns: list[ConversationTurn]) -> ConversationSecretHuntResult:
        """Scan many turns and aggregate the result."""
        result = ConversationSecretHuntResult()
        flagged_turns: set[str] = set()
        fingerprints: set[str] = set()

        for turn in turns:
            turn_findings = self.scan_turn(turn)
            if not turn_findings:
                continue
            flagged_turns.add(f"{turn.platform}:{turn.session_id}:{turn.timestamp}")
            for f in turn_findings:
                if len(result.findings) >= _MAX_FINDINGS:
                    break
                result.findings.append(f)
                result.total += 1
                result.by_severity[f.severity] = result.by_severity.get(f.severity, 0) + 1
                result.by_leak_direction[f.leak_direction] = result.by_leak_direction.get(f.leak_direction, 0) + 1
                result.by_platform[f.platform] = result.by_platform.get(f.platform, 0) + 1
                fingerprints.add(f.fingerprint)

        result.flagged_turns = len(flagged_turns)
        result.unique_secrets = len(fingerprints)
        return result

    def scan_parser(self, parser) -> ConversationSecretHuntResult:
        """Scan all turns from a ConversationParser."""
        return self.scan_turns(parser.turns)
