"""GitHub Copilot forensic artifact collector for TRACE.

Covers the Copilot CLI store (~/.copilot/session-state/*/events.jsonl) and
VS Code Copilot Chat stores, including the 1.143 SDK-harness layout
(workspaceStorage/<hash>/chatSessions + GitHub.copilot-chat/transcripts).
Paths verified against docs.github.com and VS Code release notes, Oct 2026.
"""

import os
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)

_HOSTS = ("Code", "Code - Insiders", "Cursor", "VSCodium", "Windsurf")


class CopilotCollector(BaseCollector):
    PLATFORM_NAME = "copilot"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["copilot"]
    SERVICE_PORTS = []

    def discover(self) -> bool:
        import shutil
        if shutil.which("copilot"):
            return True
        for home in self.get_user_home_dirs():
            if (home / ".copilot").exists():
                return True
        return any((root / "github.copilot-chat").is_dir()
                   for root in self._global_storage_roots())

    def _global_storage_roots(self) -> list[Path]:
        roots = []
        system = self.detect_os()
        appdata = os.environ.get("APPDATA")
        for home in self.get_user_home_dirs():
            for host in _HOSTS:
                if system == "macos":
                    base = home / "Library/Application Support" / host / "User/globalStorage"
                elif system == "windows":
                    if not appdata:
                        continue
                    base = Path(appdata) / host / "User/globalStorage"
                else:
                    base = home / ".config" / host / "User/globalStorage"
                if base.is_dir():
                    roots.append(base)
        return roots

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = home / ".copilot"
            if root.is_dir():
                for f in root.glob("session-state/*/events.jsonl"):
                    collected.append(self._record(f, "session"))
                for rel in ("mcp-config.json", "config.json"):
                    f = root / rel
                    if f.is_file():
                        collected.append(self._record(f, "config"))

        for gs in self._global_storage_roots():
            chat_dir = gs / "github.copilot-chat"
            if chat_dir.is_dir():
                chat = chat_dir / "chat.json"
                if chat.is_file():
                    collected.append(self._record(chat, "chat"))
                db = chat_dir / "state.vscdb"
                if db.is_file():
                    collected.append(self._record(db, "chat_db"))
            workspace_storage = gs.parent / "workspaceStorage"
            if workspace_storage.is_dir():
                for f in workspace_storage.glob("*/chatSessions/*"):
                    if f.is_file():
                        collected.append(self._record(f, "transcript"))
                for f in workspace_storage.glob("*/GitHub.copilot-chat/transcripts/*.jsonl"):
                    collected.append(self._record(f, "transcript"))
        return collected

    def _record(self, path: Path, artifact_type: str) -> CollectedFile:
        cf = CollectedFile(
            original_path=str(path.resolve()),
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
            if cf.artifact_type in ("session", "transcript"):
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type=cf.artifact_type,
                        severity=Severity.LOW,
                        data={"path": cf.original_path,
                              "entries": sum(1 for line in content.splitlines() if line.strip())},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "chat":
                data = self.safe_read_json(cf.original_path)
                entries = len(data) if isinstance(data, list) else (
                    len(data.get("messages", [])) if isinstance(data, dict) else 0)
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="chat",
                    severity=Severity.LOW,
                    data={"path": cf.original_path, "entries": entries},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "chat_db":
                # VS Code state.vscdb is an opaque (often keyed) SQLite store —
                # presence and size only, no schema probing of user data.
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="chat_db",
                    severity=Severity.INFO,
                    data={"path": cf.original_path, "bytes": cf.size_bytes,
                          "note": "VS Code state database (opaque store)"},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if "mcpServers" in content else Severity.INFO,
                        data={"path": cf.original_path,
                              "has_mcp_servers": "mcpServers" in content},
                        source_file=cf.original_path,
                    ))
        return artifacts
