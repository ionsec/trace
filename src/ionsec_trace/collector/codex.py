"""Codex CLI forensic artifact collector for TRACE.

Artifact paths verified against the official config reference
(learn.chatgpt.com/docs/config-file) and session-store registries, Oct 2026.
Rollout format (validated against a real store on 2026-10-24): JSONL lines
with top-level types ``session_meta`` / ``response_item`` / ``event_msg`` /
``turn_context``; messages are ``response_item`` lines whose payload type is
``"message"`` and carry a role.
"""

import json
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class CodexCLICollector(BaseCollector):
    PLATFORM_NAME = "codex_cli"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["codex"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.codex"]
    MACOS_PATHS = ["~/.codex"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.codex"]

    _SESSION_DIRS = ("sessions", "archived_sessions")

    def discover(self) -> bool:
        import shutil
        if shutil.which("codex"):
            return True
        return any((home / ".codex").exists() for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = home / ".codex"
            if not root.is_dir():
                continue
            for rel, artifact_type in (
                ("config.toml", "config"),
                ("auth.json", "credential"),
                ("history.jsonl", "history"),
            ):
                f = root / rel
                if f.is_file():
                    collected.append(self._record(f, artifact_type))
            for sub in self._SESSION_DIRS:
                base = root / sub
                if not base.is_dir():
                    continue
                for f in base.rglob("*.jsonl"):
                    collected.append(self._record(f, "session"))
                for f in base.rglob("*.zst"):
                    collected.append(self._record(f, "session_archive"))
        return collected

    def _record(self, path: Path, artifact_type: str) -> CollectedFile:
        cf = CollectedFile(
            original_path=str(path),
            source_os=self.detect_os(),
            platform=self.PLATFORM_NAME,
            artifact_type=artifact_type,
            size_bytes=path.stat().st_size,
            sha256=self.calculate_hash(str(path)),
            collected_at=self.timestamp(),
        )
        self.collected_files.append(cf)
        return cf

    def parse(self) -> list[ParsedArtifact]:
        artifacts = []
        for cf in self.collected_files:
            if cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM
                        if "model_provider" in content or "api_key" in content.lower()
                        else Severity.INFO,
                        data={"path": cf.original_path,
                              "has_mcp_servers": "[mcp_servers" in content},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "session":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    artifacts.append(self._parse_session(content, cf))
            elif cf.artifact_type == "history":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    entries = sum(1 for line in content.splitlines() if line.strip())
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="history",
                        severity=Severity.INFO,
                        data={"path": cf.original_path, "entries": entries},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "credential":
                # Flag existence only — never read credential file contents.
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="credential",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "note": "Codex file credential store present"},
                    source_file=cf.original_path,
                ))
        return artifacts

    def _parse_session(self, content: str, cf: CollectedFile) -> ParsedArtifact:
        meta = {}
        roles = {}
        messages = 0
        event_count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            top = obj.get("type")
            payload = obj.get("payload")
            if not isinstance(payload, dict):
                payload = {}
            if top == "session_meta":
                for key in ("id", "cwd", "cli_version", "model_provider",
                            "originator", "source"):
                    if key in payload:
                        meta[key] = payload[key]
            elif top == "response_item" and payload.get("type") == "message":
                messages += 1
                role = payload.get("role", "unknown")
                roles[role] = roles.get(role, 0) + 1
            elif top == "event_msg":
                event_count += 1
        return ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="session",
            severity=Severity.LOW,
            data={"path": cf.original_path, "session_meta": meta,
                  "messages": messages, "roles": roles,
                  "event_count": event_count},
            source_file=cf.original_path,
        )
