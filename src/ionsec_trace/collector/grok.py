"""Grok Build (xAI) forensic artifact collector for TRACE.

ACP-style update JSONL sessions plus a SQLite store live under ~/.grok
(GROK_HOME overrides). Path verified against deja-vu registry, Oct 2026.
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


class GrokCollector(BaseCollector):
    PLATFORM_NAME = "grok"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["grok"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.grok"]
    MACOS_PATHS = ["~/.grok"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.grok"]

    def _root(self) -> Path | None:
        env = os.environ.get("GROK_HOME")
        if env:
            return Path(env)
        for home in self.get_user_home_dirs():
            candidate = home / ".grok"
            if candidate.is_dir():
                return candidate
        return None

    def discover(self) -> bool:
        return self._root() is not None

    def collect(self) -> list[CollectedFile]:
        collected = []
        root = self._root()
        if root is None or not root.is_dir():
            return collected
        for f in root.rglob("updates.jsonl"):
            collected.append(self._record(f, "session"))
        db = root / "grok.db"
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
        return artifacts
