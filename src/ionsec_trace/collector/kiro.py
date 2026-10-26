"""Kiro forensic artifact collector for TRACE.

Kiro CLI auto-saves conversation turns as JSONL under ~/.kiro and a SQLite
store per platform. Paths verified against kiro.dev docs (session management,
MCP configuration), Oct 2026.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)
from ionsec_trace.collector.sqlite_util import sqlite_counts


class KiroCollector(BaseCollector):
    PLATFORM_NAME = "kiro"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["kiro", "kiro-cli"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.kiro", "~/.local/share/kiro-cli"]
    MACOS_PATHS = ["~/.kiro", "~/Library/Application Support/kiro-cli"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.kiro", "%LOCALAPPDATA%\\kiro-cli"]

    def discover(self) -> bool:
        import shutil
        if shutil.which("kiro") or shutil.which("kiro-cli"):
            return True
        for home in self.get_user_home_dirs():
            if (home / ".kiro").exists():
                return True
            if (home / ".local/share/kiro-cli").exists():
                return True
        return False

    def _db_candidates(self) -> list[Path]:
        candidates = []
        for home in self.get_user_home_dirs():
            candidates.append(home / ".local/share/kiro-cli/data.sqlite3")
            candidates.append(home / "Library/Application Support/kiro-cli/data.sqlite3")
        return candidates

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = home / ".kiro"
            if root.is_dir():
                mcp = root / "settings/mcp.json"
                if mcp.is_file():
                    collected.append(self._record(mcp, "config"))
                sessions = root / "sessions"
                if sessions.is_dir():
                    for f in sessions.rglob("*.jsonl"):
                        collected.append(self._record(f, "session"))
        for db in self._db_candidates():
            if db.is_file():
                collected.append(self._record(db, "session_db"))
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
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session",
                        severity=Severity.LOW,
                        data={"path": cf.original_path,
                              "entries": sum(1 for line in content.splitlines() if line.strip())},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "session_db":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_db",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "tables": sqlite_counts(cf.original_path)},
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
