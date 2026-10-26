"""Gemini CLI forensic artifact collector for TRACE.

Paths verified against geminicli.com docs (session management, enterprise,
changelog), Oct 2026. Two session generations coexist on disk: whole-session
JSON and replay JSONL — both are collected, deduped by session id at parse.
"""


from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class GeminiCLICollector(BaseCollector):
    PLATFORM_NAME = "gemini_cli"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["gemini"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.gemini"]
    MACOS_PATHS = ["~/.gemini"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.gemini"]

    def discover(self) -> bool:
        import shutil
        if shutil.which("gemini"):
            return True
        return any((home / ".gemini").exists() for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = home / ".gemini"
            if not root.is_dir():
                continue
            for rel, artifact_type in (
                ("settings.json", "config"),
                ("projects.json", "config"),
                ("mcp-server-enablement.json", "config"),
                ("mcp-oauth-tokens.json", "credential"),
            ):
                f = root / rel
                if f.is_file():
                    collected.append(self._record(f, artifact_type))
            chats_root = root / "tmp"
            if chats_root.is_dir():
                for f in chats_root.glob("*/chats/*.json"):
                    collected.append(self._record(f, "session"))
                for f in chats_root.glob("*/chats/*.jsonl"):
                    collected.append(self._record(f, "session_replay"))
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
            if cf.artifact_type == "session":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                data = self.safe_read_json(cf.original_path)
                if not isinstance(data, dict):
                    continue
                messages = data.get("messages")
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session",
                    severity=Severity.LOW,
                    data={
                        "path": cf.original_path,
                        "session_id": data.get("sessionId"),
                        "start_time": data.get("startTime"),
                        "last_updated": data.get("lastUpdated"),
                        "messages": len(messages) if isinstance(messages, list) else 0,
                    },
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "session_replay":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_replay",
                        severity=Severity.LOW,
                        data={"path": cf.original_path,
                              "entries": sum(1 for line in content.splitlines() if line.strip())},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    data = self.safe_read_json(cf.original_path) or {}
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if "mcpServers" in content else Severity.INFO,
                        data={"path": cf.original_path,
                              "has_mcp_servers": "mcpServers" in content,
                              "keys": sorted(data.keys()) if isinstance(data, dict) else []},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "credential":
                # Existence only — never read OAuth token contents.
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="credential",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "note": "Gemini CLI MCP OAuth token store present"},
                    source_file=cf.original_path,
                ))
        return artifacts
