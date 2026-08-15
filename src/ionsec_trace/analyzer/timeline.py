"""
UnifiedTimeline — builds a chronological forensic timeline of ACTUAL events
from inside collected artifacts (conversations, logs, configs), not just
"file collected" metadata entries.

The timeline extracts real timestamps from Ollama SQLite chats, Hermes JSONL
sessions, log files, and config/credential files, then merges in
ConversationParser turns and AIIndicator results for a complete DFIR-grade
chronological view.
"""

import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table


def _row_get(row: sqlite3.Row, key: str, default=None):
    """Read a column from a sqlite3.Row by name.

    sqlite3.Row supports mapping-style indexing but has no ``.get``, and raises
    IndexError for columns a given schema does not have — which varies across
    the app databases TRACE collects.
    """
    try:
        value = row[key]
    except (IndexError, KeyError):
        return default
    return default if value is None else value


from ionsec_trace.collector.base import Severity

# ---------------------------------------------------------------------------
# DFIR content patterns for severity inference
# ---------------------------------------------------------------------------

_API_KEY_PATTERN = re.compile(
    r"(?i)(sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{12,}|"
    r"api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9\-_]{10,}|"
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|"
    r"aws_access_key_id|aws_secret_access_key)",
)

_JAILBREAK_PATTERN = re.compile(
    r"(?i)(DAN\s*mode|do\s+anything\s+now|jailbreak|"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s*(?:instructions|rules)|"
    r"bypass\s+(?:your\s+)?(?:safety|filter|restrictions)|"
    r"pretend\s+you\s+are\s+(?:an?\s+)?(?:evil|unrestricted|unethical)|"
    r"you\s+are\s+now\s+(?:DAN|unrestricted|uncensored)|"
    r"system\s*prompt\s*(?:extraction|leak|dump)|"
    r"forget\s+(?:that\s+you|your)\s*(?:are|instructions|rules))",
)

_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(password\s*[=:]\s*|passwd\s*[=:]\s*|secret\s*[=:]\s*|"
    r"token\s*[=:]\s*['\"]?[a-zA-Z0-9\-_\.]{10,}|"
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|"
    r"ssh-rsa\s+AAAA|"
    r"\.aws/credentials|\.env\b|\.ssh/id_rsa)",
)

_SENSITIVE_PATH_PATTERN = re.compile(
    r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts|"
    r"\.ssh/id_rsa|\.ssh/authorized_keys|"
    r"\.aws/credentials|\.env|\.git/config|"
    r"/root/|/home/.*?/\.bashrc|/home/.*?/\.zshrc)",
)

_NETWORK_PATTERN = re.compile(
    r"(?i)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"[a-zA-Z0-9\-]+\.(com|net|org|io|dev|xyz|top|ru|cn)|"
    r"https?://[^\s]+)",
)

_SYSTEM_INTERNALS_PATTERN = re.compile(
    r"(?i)(what\s+are\s+your\s+(?:system|initial|original)\s*(?:instructions|prompt)|"
    r"reveal\s+your\s+(?:system\s+)?prompt|"
    r"show\s+me\s+(?:your\s+)?(?:system|initial)\s*(?:instructions|prompt)|"
    r"system\s+prompt)",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    """A single event on the unified forensic timeline."""

    timestamp: str
    platform: str
    artifact_type: str
    description: str
    severity: Severity
    source_path: str
    user: str | None = None
    is_collection_event: bool = False
    content_preview: str = ""

    def to_dict(self) -> dict:
        d = asdict(self, dict_factory=lambda pairs: {k: v for k, v in pairs if v is not None})
        d["severity"] = self.severity.value
        return d


class UnifiedTimeline:
    """Build a chronological timeline of all AI interactions from collected evidence.

    Produces REAL forensic events (conversation turns, log entries, credential
    exposures, jailbreak attempts) with timestamps extracted from inside the
    artifacts, not just collection-time metadata.
    """

    def __init__(self, evidence_dir: str):
        self.evidence_dir = Path(evidence_dir)
        self.events: list[TimelineEvent] = []
        self._custody_data: list[dict] = []
        self._console = Console()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> "UnifiedTimeline":
        """Load chain-of-custody JSON and build the timeline."""
        custody_path = self.evidence_dir / "CHAIN_OF_CUSTODY.json"
        if custody_path.exists():
            try:
                with open(custody_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                # Support both top-level list and {"files": [...]} envelope
                if isinstance(data, list):
                    self._custody_data = data
                elif isinstance(data, dict):
                    self._custody_data = data.get("files", data.get("collected_files", []))
            except (json.JSONDecodeError, OSError):
                self._custody_data = []
        else:
            # Fallback: walk the evidence directory for collected files
            self._custody_data = self._discover_from_dir()

        # Step 1: Build basic collection-time events (backward compat)
        self._build_events()

        # Step 2: Extract real events from artifact content
        self._extract_real_events()

        # Step 3: Merge in ConversationParser turns
        self._merge_conversation_turns()

        # Step 4: Merge in AI indicators
        self._merge_ai_indicators()

        # Step 5: Deduplicate — remove exact duplicates from overlapping sources
        # (e.g., SQLite events from both _extract_real_events and ConversationParser)
        self._deduplicate_events()

        # Step 6: Final sort — content events before collection events at same ts
        self.events.sort(key=lambda e: (e.timestamp, int(e.is_collection_event)))

        return self

    def _discover_from_dir(self) -> list[dict]:
        """Walk evidence_dir to reconstruct collected-file entries when no CoC JSON exists."""
        entries: list[dict] = []
        for fpath in sorted(self.evidence_dir.rglob("*")):
            if fpath.is_file() and fpath.name != "CHAIN_OF_CUSTODY.json":
                stat = fpath.stat()
                # Infer platform from first path segment under evidence_dir
                rel = fpath.relative_to(self.evidence_dir)
                platform = rel.parts[0] if rel.parts else "unknown"
                entries.append({
                    "original_path": str(fpath),
                    "platform": platform,
                    "artifact_type": self._guess_artifact_type(fpath.name),
                    "collected_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "size_bytes": stat.st_size,
                })
        return entries

    @staticmethod
    def _guess_artifact_type(filename: str) -> str:
        name = filename.lower()
        if "config" in name or "setting" in name or name.endswith(".json"):
            return "config"
        if "conversation" in name or "history" in name or "chat" in name:
            return "conversation"
        if "model" in name or "manifest" in name:
            return "model_manifest"
        if "log" in name:
            return "log"
        if "credential" in name or "key" in name or "token" in name or name.endswith(".env"):
            return "credential"
        # Detect SQLite databases
        if name.endswith((".sqlite", ".db")):
            return "session_database"
        if name.endswith(".jsonl"):
            return "session_log"
        return "unknown"

    # ------------------------------------------------------------------
    # Event building (original collection-time events)
    # ------------------------------------------------------------------

    def _build_events(self) -> None:
        """Convert custody data entries into TimelineEvent objects (collection-time)."""
        for entry in self._custody_data:
            ts = entry.get("collected_at") or entry.get("timestamp") or ""
            if not ts:
                # Try filesystem mtime
                orig = entry.get("original_path", "")
                p = Path(orig) if orig else None
                if p and p.exists():
                    ts = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat()
                else:
                    ts = datetime.now(timezone.utc).isoformat()

            severity = self._severity_from_entry(entry)
            source = entry.get("original_path", "")
            platform = entry.get("platform", "unknown")
            artifact_type = entry.get("artifact_type", "unknown")
            user = entry.get("user", entry.get("username", None))

            description = self._describe_event(entry)

            self.events.append(TimelineEvent(
                timestamp=ts,
                platform=platform,
                artifact_type=artifact_type,
                description=description,
                severity=severity,
                source_path=source,
                user=user,
                is_collection_event=True,
            ))

    # ------------------------------------------------------------------
    # Real event extraction
    # ------------------------------------------------------------------

    def _extract_real_events(self) -> None:
        """Walk artifact content and extract REAL timestamps and events."""
        for entry in self._custody_data:
            source_path = entry.get("original_path", "")
            if not source_path:
                continue

            platform = entry.get("platform", "unknown")
            artifact_type = entry.get("artifact_type", "unknown")
            collected_at = entry.get("collected_at", "")

            # Re-derive artifact type from filename if unknown
            fname = Path(source_path).name.lower()

            # --- Ollama SQLite (session_database) ---
            if fname.endswith((".sqlite", ".db")):
                self._extract_sqlite_events(source_path, platform, collected_at)
                continue

            # --- Hermes JSONL sessions (session_log) ---
            if fname.endswith(".jsonl"):
                self._extract_jsonl_events(source_path, platform, collected_at)
                continue

            # --- Log files ---
            if artifact_type == "log" or fname.endswith(".log"):
                self._extract_log_events(source_path, platform, collected_at)
                continue

            # --- Config / credential files ---
            if artifact_type in ("config", "credential") or fname.endswith(".json"):
                self._extract_config_events(source_path, platform, artifact_type, collected_at)
                continue

            # --- Env / credential files ---
            if fname.endswith(".env") or "credential" in fname or "key" in fname:
                self._extract_config_events(source_path, platform, "credential", collected_at)
                continue

    def _extract_sqlite_events(self, filepath: str, platform: str, collected_at: str) -> None:
        """Extract real conversation events from Ollama SQLite databases."""
        try:
            conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Discover tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"] for row in cursor.fetchall()}

            if "messages" in tables:
                chat_map: dict[int, dict] = {}
                if "chats" in tables:
                    try:
                        cursor.execute("SELECT id, title, model, created_at FROM chats")
                        for row in cursor.fetchall():
                            chat_map[row["id"]] = {
                                "title": _row_get(row, "title", ""),
                                "model": _row_get(row, "model", ""),
                                "created_at": _row_get(row, "created_at", ""),
                            }
                    except sqlite3.OperationalError:
                        pass

                # Extract messages
                try:
                    cursor.execute(
                        "SELECT chat_id, role, content, model_name, created_at "
                        "FROM messages ORDER BY chat_id, created_at"
                    )
                    messages = cursor.fetchall()
                except sqlite3.OperationalError:
                    try:
                        cursor.execute("SELECT * FROM messages ORDER BY chat_id, id")
                        messages = cursor.fetchall()
                    except sqlite3.OperationalError:
                        conn.close()
                        return

                for msg in messages:
                    chat_id = _row_get(msg, "chat_id", 0)
                    role = _row_get(msg, "role", "unknown")
                    content = str(_row_get(msg, "content", ""))
                    model_name = _row_get(msg, "model_name", "")
                    created_at = _row_get(msg, "created_at", "")

                    if not model_name:
                        chat_info = chat_map.get(chat_id, {})
                        model_name = chat_info.get("model", "")

                    # Use content timestamp, fall back to chat created_at, then file mtime
                    ts = self._resolve_timestamp(created_at, filepath, collected_at)

                    content_preview = content[:120].replace("\n", " ").strip()
                    if role == "user":
                        description = f"[{platform}] User prompt: '{content_preview}'"
                    elif role == "assistant":
                        description = f"[{platform}] Assistant response: {content_preview}"
                    elif role == "system":
                        description = f"[{platform}] System message: {content_preview}"
                    else:
                        description = f"[{platform}] {role} message: {content_preview}"

                    severity = self._infer_severity_from_content(content, role)

                    self.events.append(TimelineEvent(
                        timestamp=ts,
                        platform=platform or "ollama",
                        artifact_type="conversation",
                        description=description,
                        severity=severity,
                        source_path=filepath,
                        user="user" if role == "user" else (model_name or role),
                        is_collection_event=False,
                        content_preview=content_preview,
                    ))

            conn.close()

        except (sqlite3.Error, OSError):
            pass

    def _extract_jsonl_events(self, filepath: str, platform: str, collected_at: str) -> None:
        """Extract real events from JSONL session files (Hermes, Claude Code, etc.)."""
        try:
            size = os.path.getsize(filepath)
            if size > 50 * 1024 * 1024:  # 50 MB limit
                return

            records: list[dict] = []
            with open(filepath, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            for rec in records:
                role = rec.get("role", rec.get("sender", rec.get("author", "unknown")))
                content = rec.get("content", rec.get("text", rec.get("message", "")))
                timestamp = rec.get("timestamp", rec.get("created_at", rec.get("time", "")))
                model = rec.get("model", rec.get("model_name", ""))

                # Handle content as list
                if isinstance(content, list):
                    parts = []
                    for part in content:
                        if isinstance(part, dict):
                            parts.append(part.get("text", str(part)))
                        else:
                            parts.append(str(part))
                    content = "\n".join(parts)

                if not content and "tool_calls" not in rec and "tool_use" not in rec:
                    continue

                content_str = str(content) if content else ""
                content_preview = content_str[:120].replace("\n", " ").strip()

                ts = self._resolve_timestamp(timestamp, filepath, collected_at)

                # Determine the platform more specifically
                effective_platform = platform
                fname = Path(filepath).name.lower()
                if "session" in fname or platform == "hermes":
                    effective_platform = "hermes"
                elif platform == "claude_code":
                    effective_platform = "claude_code"

                role_lower = str(role).lower() if role else "unknown"
                if role_lower == "user":
                    description = f"[{effective_platform}] User prompt: '{content_preview}'"
                elif role_lower == "assistant":
                    description = f"[{effective_platform}] Assistant response: {content_preview}"
                elif role_lower == "system":
                    description = f"[{effective_platform}] System message: {content_preview}"
                elif role_lower == "tool":
                    description = f"[{effective_platform}] Tool call: {content_preview}"
                else:
                    description = f"[{effective_platform}] {role} message: {content_preview}"

                # Check tool calls for sensitive patterns
                tool_calls = rec.get("tool_calls", rec.get("toolCall", None))
                if tool_calls:
                    tool_str = json.dumps(tool_calls) if not isinstance(tool_calls, str) else tool_calls
                    severity = self._infer_severity_from_content(
                        content_str + " " + tool_str, role_lower
                    )
                else:
                    severity = self._infer_severity_from_content(content_str, role_lower)

                self.events.append(TimelineEvent(
                    timestamp=ts,
                    platform=effective_platform,
                    artifact_type="conversation",
                    description=description,
                    severity=severity,
                    source_path=filepath,
                    user="user" if role_lower == "user" else (model or role_lower),
                    is_collection_event=False,
                    content_preview=content_preview,
                ))

        except OSError:
            pass

    def _extract_log_events(self, filepath: str, platform: str, collected_at: str) -> None:
        """Extract timestamped events from log files."""
        try:
            size = os.path.getsize(filepath)
            if size > 20 * 1024 * 1024:  # 20 MB limit
                return

            with open(filepath, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue

                    # Try to extract timestamps from common log formats
                    ts = self._extract_timestamp_from_log_line(line, filepath, collected_at)
                    content_preview = line[:120]
                    severity = self._infer_severity_from_content(line, "log")

                    description = f"[{platform}] Log: {content_preview}"

                    self.events.append(TimelineEvent(
                        timestamp=ts,
                        platform=platform,
                        artifact_type="log",
                        description=description,
                        severity=severity,
                        source_path=filepath,
                        is_collection_event=False,
                        content_preview=content_preview,
                    ))

        except OSError:
            pass

    def _extract_config_events(self, filepath: str, platform: str,
                                artifact_type: str, collected_at: str) -> None:
        """Extract events from config/credential files using mtime as timestamp."""
        try:
            stat = os.stat(filepath)
            ts = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

            # Read content for severity inference
            try:
                with open(filepath, encoding="utf-8", errors="replace") as fh:
                    content = fh.read(65536)  # Read up to 64KB
            except OSError:
                content = ""

            basename = Path(filepath).name
            effective_type = artifact_type
            if effective_type == "unknown":
                if _CREDENTIAL_PATTERN.search(content) or _API_KEY_PATTERN.search(content):
                    effective_type = "credential"
                else:
                    effective_type = "config"

            severity = self._infer_severity_from_content(content, "config")

            if effective_type == "credential":
                description = f"[{platform}] Credential file modified: {basename}"
            else:
                description = f"[{platform}] Config modified: {filepath}"

            content_preview = content[:120].replace("\n", " ").strip() if content else ""

            self.events.append(TimelineEvent(
                timestamp=ts,
                platform=platform,
                artifact_type=effective_type,
                description=description,
                severity=severity,
                source_path=filepath,
                is_collection_event=False,
                content_preview=content_preview,
            ))

        except OSError:
            pass

    # ------------------------------------------------------------------
    # ConversationParser merge
    # ------------------------------------------------------------------

    def _merge_conversation_turns(self) -> None:
        """Import and use ConversationParser to get conversation turns as timeline events."""
        try:
            from ionsec_trace.analyzer.conversation_parser import ConversationParser
        except ImportError:
            return

        try:
            parser = ConversationParser.from_evidence_dir(str(self.evidence_dir))
        except Exception:
            return

        for turn in parser.turns:
            content_preview = turn.content[:120].replace("\n", " ").strip()
            role = turn.role.lower() if turn.role else "unknown"

            if role == "user":
                description = f"[{turn.platform}] User prompt: '{content_preview}'"
            elif role == "assistant":
                description = f"[{turn.platform}] Assistant response: {content_preview}"
            elif role == "system":
                description = f"[{turn.platform}] System message: {content_preview}"
            elif role == "tool":
                description = f"[{turn.platform}] Tool call: {content_preview}"
            else:
                description = f"[{turn.platform}] {turn.role} message: {content_preview}"

            # Infer severity from content
            severity = self._infer_severity_from_content(turn.content, role)

            # Also check metadata for tool calls
            if turn.metadata:
                meta_str = json.dumps(turn.metadata)
                meta_sev = self._infer_severity_from_content(meta_str, "tool_call")
                if meta_sev.value in ("critical", "high") and severity not in (Severity.CRITICAL, Severity.HIGH):
                    severity = meta_sev

            user = "user" if role == "user" else (turn.model or role)

            self.events.append(TimelineEvent(
                timestamp=turn.timestamp,
                platform=turn.platform,
                artifact_type="conversation",
                description=description,
                severity=severity,
                source_path=turn.source_file,
                user=user,
                is_collection_event=False,
                content_preview=content_preview,
            ))

    # ------------------------------------------------------------------
    # AI Indicator merge
    # ------------------------------------------------------------------

    def _merge_ai_indicators(self) -> None:
        """If analysis_results.json exists, convert ai_indicators into timeline events."""
        results_path = self.evidence_dir / "analysis_results.json"
        if not results_path.exists():
            return

        try:
            with open(results_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return

        if not isinstance(data, dict):
            return

        ai_indicators = data.get("ai_indicators", [])
        if not isinstance(ai_indicators, list):
            return

        # Build a map of source_file -> mtime for timestamp resolution
        file_mtimes: dict[str, str] = {}
        for entry in self._custody_data:
            src = entry.get("original_path", "")
            collected_at = entry.get("collected_at", "")
            if src and collected_at:
                file_mtimes[src] = collected_at
                # Also try to get mtime from the actual file
                try:
                    mtime = os.path.getmtime(src)
                    file_mtimes[src] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
                except OSError:
                    pass

        for ind in ai_indicators:
            if not isinstance(ind, dict):
                continue

            indicator_type = ind.get("indicator_type", "unknown")
            value = ind.get("value", "")
            severity_str = ind.get("severity", "info")
            context = ind.get("context", "")
            platform = ind.get("platform", "unknown")
            source_file = ind.get("source_file", "")
            recommendation = ind.get("recommendation", "")

            # Resolve severity
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(severity_str.lower(), Severity.HIGH)

            # Resolve timestamp: use source file mtime, fallback to collected_at, then now
            ts = file_mtimes.get(source_file, "")
            if not ts:
                # Look for any custody entry matching this source
                for entry in self._custody_data:
                    if entry.get("original_path", "") == source_file:
                        ts = entry.get("collected_at", "")
                        break
            if not ts:
                ts = datetime.now(timezone.utc).isoformat()

            # Build description
            value_preview = (value[:80] if value else "")
            rec_preview = (recommendation[:60] if recommendation else "")
            description = f"[{indicator_type}] {value_preview}"
            if rec_preview:
                description += f" — {rec_preview}"

            # Infer severity from content if needed
            content_for_sev = f"{value} {context}"
            inferred_severity = self._infer_severity_from_content(content_for_sev, indicator_type)
            # Use the higher severity
            severity_order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                              Severity.HIGH: 3, Severity.CRITICAL: 4}
            if severity_order.get(inferred_severity, 0) > severity_order.get(severity, 0):
                severity = inferred_severity

            self.events.append(TimelineEvent(
                timestamp=ts,
                platform=platform,
                artifact_type=indicator_type,
                description=description,
                severity=severity,
                source_path=source_file,
                is_collection_event=False,
                content_preview=value_preview,
            ))

    # ------------------------------------------------------------------
    # Timestamp resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_timestamp(content_ts: str, filepath: str, collected_at: str) -> str:
        """Resolve the best available timestamp for a forensic event.

        Priority order:
        1. Content timestamp (from inside the artifact)
        2. File mtime (when the artifact was last modified)
        3. collected_at (last resort)
        """
        # 1. Content timestamp
        if content_ts:
            normalised = UnifiedTimeline._normalise_timestamp(content_ts)
            if (normalised and normalised.startswith("20")) or normalised:
                # Check it's not just a fallback "now" timestamp
                return normalised

        # 2. File mtime
        try:
            mtime = os.path.getmtime(filepath)
            return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except OSError:
            pass

        # 3. collected_at
        if collected_at:
            return collected_at

        # Ultimate fallback
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _normalise_timestamp(raw: str | None) -> str:
        """Return an ISO 8601 UTC string, falling back to *now* on failure."""
        if not raw:
            return ""
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
        return ""

    @staticmethod
    def _extract_timestamp_from_log_line(line: str, filepath: str, collected_at: str) -> str:
        """Try to extract a timestamp from a log line.

        Supports:
        - ISO 8601 (2025-01-01T12:00:00...)
        - Syslog format (Jan  1 12:00:00)
        - Bracket format ([2025-01-01 12:00:00])
        - Common log format (01/Jan/2025:12:00:00)
        """
        # ISO 8601
        iso_match = re.search(
            r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?', line
        )
        if iso_match:
            ts = UnifiedTimeline._normalise_timestamp(iso_match.group())
            if ts:
                return ts

        # Bracket format [2025-01-01 12:00:00]
        bracket_match = re.search(r'\[(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})\]', line)
        if bracket_match:
            ts = UnifiedTimeline._normalise_timestamp(bracket_match.group(1))
            if ts:
                return ts

        # Syslog-like format (Mon DD HH:MM:SS)
        syslog_match = re.search(
            r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            line,
        )
        if syslog_match:
            # Use current year since syslog doesn't include it
            raw = f"2025 {syslog_match.group()}"
            for fmt in ("%Y %b %d %H:%M:%S", "%Y %b  %d %H:%M:%S"):
                try:
                    dt = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                    return dt.isoformat()
                except ValueError:
                    continue

        # Fall back to file mtime
        try:
            mtime = os.path.getmtime(filepath)
            return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except OSError:
            pass

        # Ultimate fallback
        if collected_at:
            return collected_at
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Severity inference
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_severity_from_content(content: str, role_or_type: str) -> Severity:
        """Infer severity by inspecting the actual content.

        Priority (highest first):
        - API key patterns → CRITICAL
        - Jailbreak patterns → CRITICAL
        - Credential/password patterns → HIGH
        - Sensitive file paths → HIGH
        - Network indicators (IPs, domains) → MEDIUM
        - User turns asking about system internals → MEDIUM
        - Normal conversation → INFO
        - Config/log collection → INFO
        """
        if not content:
            return Severity.INFO

        # CRITICAL: API keys
        if _API_KEY_PATTERN.search(content):
            return Severity.CRITICAL

        # CRITICAL: Jailbreak patterns
        if _JAILBREAK_PATTERN.search(content):
            return Severity.CRITICAL

        # HIGH: Credentials / passwords / private keys
        if _CREDENTIAL_PATTERN.search(content):
            return Severity.HIGH

        # HIGH: Sensitive file paths
        if _SENSITIVE_PATH_PATTERN.search(content):
            return Severity.HIGH

        # MEDIUM: Network indicators
        if _NETWORK_PATTERN.search(content):
            return Severity.MEDIUM

        # MEDIUM: System internals queries (user role)
        if role_or_type == "user" and _SYSTEM_INTERNALS_PATTERN.search(content):
            return Severity.MEDIUM

        # INFO: everything else
        return Severity.INFO

    # ------------------------------------------------------------------
    # Legacy methods (kept for backward compatibility)
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate_events(self) -> None:
        """Remove duplicate events that come from overlapping extraction sources.

        Events are considered duplicates if they share the same timestamp,
        platform, artifact_type, and content_preview (or description if no preview).
        Prefer real events over collection events.
        """
        seen: dict[tuple, TimelineEvent] = {}
        unique: list[TimelineEvent] = []

        for ev in self.events:
            # Build a dedup key from the distinguishing fields
            preview = ev.content_preview or ev.description[:80]
            key = (ev.timestamp[:19], ev.platform, ev.artifact_type, preview)

            if key not in seen:
                seen[key] = ev
                unique.append(ev)
            else:
                # Keep the more informative event (prefer real over collection)
                existing = seen[key]
                if not ev.is_collection_event and existing.is_collection_event:
                    # Replace collection event with real event
                    idx = unique.index(existing)
                    unique[idx] = ev
                    seen[key] = ev
                elif ev.is_collection_event and not existing.is_collection_event:
                    # Keep existing real event
                    pass
                # Both real or both collection — keep the one with more content
                elif len(ev.description) > len(existing.description):
                    idx = unique.index(existing)
                    unique[idx] = ev
                    seen[key] = ev

        self.events = unique

    @staticmethod
    def _severity_from_entry(entry: dict) -> Severity:
        """Infer severity from entry metadata (legacy method)."""
        sev_str = entry.get("severity", "")
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        if isinstance(sev_str, str) and sev_str.lower() in mapping:
            return mapping[sev_str.lower()]
        # Heuristic: credential and model_manifest artefacts are higher risk
        atype = entry.get("artifact_type", "")
        if atype == "credential":
            return Severity.HIGH
        if atype == "model_manifest":
            return Severity.MEDIUM
        return Severity.INFO

    @staticmethod
    def _describe_event(entry: dict) -> str:
        """Generate a human-readable description for a collection entry."""
        platform = entry.get("platform", "unknown")
        atype = entry.get("artifact_type", "unknown")
        source = entry.get("original_path", "")
        basename = Path(source).name if source else "<unknown>"
        return f"[{platform}] {atype.replace('_', ' ').title()} collected: {basename}"

    # ------------------------------------------------------------------
    # Grouping helpers
    # ------------------------------------------------------------------

    def group_by_platform(self) -> dict[str, list[TimelineEvent]]:
        """Return events grouped by platform."""
        groups: dict[str, list[TimelineEvent]] = {}
        for ev in self.events:
            groups.setdefault(ev.platform, []).append(ev)
        return groups

    def group_by_user(self) -> dict[str, list[TimelineEvent]]:
        """Return events grouped by user (None for unattributed)."""
        groups: dict[str, list[TimelineEvent]] = {}
        for ev in self.events:
            key = ev.user or "<unattributed>"
            groups.setdefault(key, []).append(ev)
        return groups

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialize the timeline to JSON."""
        return json.dumps([e.to_dict() for e in self.events], indent=indent, default=str)

    def __str__(self) -> str:
        """Rich table representation of the timeline."""
        if not self.events:
            return "No timeline events."

        table = Table(title="TRACE Unified Timeline", show_lines=True)
        table.add_column("Timestamp", style="cyan", max_width=26)
        table.add_column("Platform", style="magenta")
        table.add_column("Type", style="green")
        table.add_column("User", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Description", style="white", max_width=60)

        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "dim",
            Severity.INFO: "dim",
        }

        for ev in self.events:
            sev_style = severity_styles.get(ev.severity, "white")
            table.add_row(
                ev.timestamp[:26] if ev.timestamp else "",
                ev.platform,
                ev.artifact_type,
                ev.user or "-",
                f"[{sev_style}]{ev.severity.value}[/{sev_style}]",
                ev.description[:120],
            )

        with self._console.capture() as capture:
            self._console.print(table)
        return capture.get()
