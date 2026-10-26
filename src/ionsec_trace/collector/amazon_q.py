"""Amazon Q Developer forensic artifact collector for TRACE.

IDE chat history is a per-workspace LokiJS-style JSON store; the CLI keeps a
SQLite conversation DB. Paths verified against AWS docs and aws-toolkit-vscode
sources, Oct 2026.
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


class AmazonQCollector(BaseCollector):
    PLATFORM_NAME = "amazon_q"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["q", "q-cli", "amazon-q"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.aws/amazonq", "~/.local/share/amazon-q"]
    MACOS_PATHS = ["~/.aws/amazonq", "~/.local/share/amazon-q"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.aws\\amazonq"]

    def discover(self) -> bool:
        return any((home / ".aws/amazonq").exists()
                   for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            history = home / ".aws/amazonq/history"
            if history.is_dir():
                for f in history.glob("chat-history-*.json"):
                    collected.append(self._record(f, "chat_history"))
            db = home / ".local/share/amazon-q/data.sqlite3"
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
            if cf.artifact_type == "chat_history":
                data = self.safe_read_json(cf.original_path)
                tabs = 0
                if isinstance(data, dict):
                    collections = data.get("collections")
                    if isinstance(collections, list):
                        for collection in collections:
                            if not isinstance(collection, dict):
                                continue
                            entries = collection.get("tabs")
                            if isinstance(entries, list):
                                tabs += len(entries)
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="chat_history",
                    severity=Severity.LOW,
                    data={"path": cf.original_path, "tabs": tabs},
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
        return artifacts
