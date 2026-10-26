"""Zed editor assistant-thread collector for TRACE.

Threads moved from per-conversation JSON files to a SQLite threads.db;
legacy JSON conversations may still exist. Paths verified against
zed-industries issue/discussion reports, Oct 2026.
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


class ZedCollector(BaseCollector):
    PLATFORM_NAME = "zed"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["zed"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.local/share/zed", "~/.config/zed"]
    MACOS_PATHS = ["~/Library/Application Support/Zed"]
    WINDOWS_PATHS = ["%LOCALAPPDATA%\\Zed"]

    def discover(self) -> bool:
        import shutil
        if shutil.which("zed"):
            return True
        for home in self.get_user_home_dirs():
            if (home / ".local/share/zed").exists():
                return True
            if (home / "Library/Application Support/Zed").exists():
                return True
        return False

    def _data_root(self, home: Path) -> Path:
        system = self.detect_os()
        if system == "macos":
            return home / "Library/Application Support/Zed"
        if system == "windows":
            local = os.environ.get("LOCALAPPDATA")
            if local:
                return Path(local) / "Zed"
        return home / ".local/share/zed"

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            data_root = self._data_root(home)
            db = data_root / "threads/threads.db"
            if db.is_file():
                collected.append(self._record(db, "threads_db"))
            legacy = home / ".local/share/zed/conversations"
            if legacy.is_dir():
                for f in legacy.glob("*.json"):
                    collected.append(self._record(f, "conversation_legacy"))
            cfg = home / ".config/zed/settings.json"
            if cfg.is_file():
                collected.append(self._record(cfg, "config"))
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
            if cf.artifact_type == "threads_db":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="threads_db",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "tables": sqlite_counts(cf.original_path)},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "conversation_legacy":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_legacy",
                    severity=Severity.LOW,
                    data={"path": cf.original_path, "bytes": cf.size_bytes},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if "context_servers" in content else Severity.INFO,
                        data={"path": cf.original_path,
                              "has_mcp": "context_servers" in content},
                        source_file=cf.original_path,
                    ))
        return artifacts
