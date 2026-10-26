"""Kilo Code forensic artifact collector for TRACE.

The CLI keeps an OpenCode-schema SQLite store (~/.local/share/kilo/kilo.db)
while the VS Code-family extension writes per-task JSON into each host's
globalStorage. Paths verified against deja-vu registry and Orq.ai agent list, Oct 2026.
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
from ionsec_trace.collector.sqlite_util import sqlite_counts

_HOSTS = ("Code", "Code - Insiders", "Cursor", "VSCodium", "Windsurf")


class KiloCollector(BaseCollector):
    PLATFORM_NAME = "kilo"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["kilo"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.local/share/kilo"]
    MACOS_PATHS = ["~/.local/share/kilo"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.local\\share\\kilo"]

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

    def discover(self) -> bool:
        if any((home / ".local/share/kilo").exists()
               for home in self.get_user_home_dirs()):
            return True
        return any((root / "kilocode.kilo-code").is_dir()
                   for root in self._global_storage_roots())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            db = home / ".local/share/kilo/kilo.db"
            if db.is_file():
                collected.append(self._record(db, "session_db"))
        for root in self._global_storage_roots():
            tasks = root / "kilocode.kilo-code/tasks"
            if not tasks.is_dir():
                continue
            for task in tasks.iterdir():
                history = task / "api_conversation_history.json"
                if history.is_file():
                    collected.append(self._record(history, "session_legacy"))
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
            if cf.artifact_type == "session_db":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_db",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "tables": sqlite_counts(cf.original_path)},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "session_legacy":
                data = self.safe_read_json(cf.original_path)
                messages = len(data) if isinstance(data, list) else 0
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_legacy",
                    severity=Severity.LOW,
                    data={"path": cf.original_path, "messages": messages},
                    source_file=cf.original_path,
                ))
        return artifacts
