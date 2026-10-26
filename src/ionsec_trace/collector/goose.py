"""Goose forensic artifact collector for TRACE.

Session storage moved from per-session JSONL to sessions.db (SQLite) at
v1.10.0; legacy JSONL files stay on disk unmanaged, so both generations are
collected. Paths verified against block/goose docs (logs, config files), Oct 2026.
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


class GooseCollector(BaseCollector):
    PLATFORM_NAME = "goose"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["goose"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.config/goose", "~/.local/share/goose"]
    MACOS_PATHS = ["~/.config/goose", "~/.local/share/goose"]
    WINDOWS_PATHS = ["%APPDATA%\\Block\\goose\\data"]

    _CONFIG_FILES = ("profiles.yaml", "config.yaml", "history.txt")

    def discover(self) -> bool:
        import shutil
        if shutil.which("goose"):
            return True
        for home in self.get_user_home_dirs():
            if (home / ".config/goose").exists():
                return True
            if (home / ".local/share/goose/sessions").exists():
                return True
        return False

    def _data_root(self, home: Path) -> Path:
        appdata = os.environ.get("APPDATA")
        if self.detect_os() == "windows" and appdata:
            return Path(appdata) / "Block/goose/data"
        return home / ".local/share/goose"

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            cfg_root = home / ".config/goose"
            if cfg_root.is_dir():
                for rel in self._CONFIG_FILES:
                    f = cfg_root / rel
                    if f.is_file():
                        collected.append(self._record(f, "config"))
            sessions = self._data_root(home) / "sessions"
            if not sessions.is_dir():
                continue
            db = sessions / "sessions.db"
            if db.is_file():
                collected.append(self._record(db, "session_db"))
            for f in sessions.glob("*.jsonl"):
                collected.append(self._record(f, "session_legacy"))
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
                    iocs = []
                    if "api_key" in content.lower():
                        iocs.append({"type": "api_key_in_config",
                                     "detail": "API key reference in Goose config"})
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if iocs else Severity.INFO,
                        data={"path": cf.original_path},
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0055"] if iocs else [],
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
            elif cf.artifact_type == "session_legacy":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_legacy",
                        severity=Severity.LOW,
                        data={"path": cf.original_path,
                              "entries": sum(1 for line in content.splitlines() if line.strip())},
                        source_file=cf.original_path,
                    ))
        return artifacts
