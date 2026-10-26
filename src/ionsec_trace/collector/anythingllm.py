"""AnythingLLM desktop forensic artifact collector for TRACE.

anythingllm.db is a Prisma SQLite store holding workspaces, threads, messages
and API keys; lancedb/ and models/ prove document ingestion. Note: Oct 2026
switched the bundled engine to Lemonade — old Ollama-managed model dirs are
legacy evidence, not current config. Paths verified against
docs.anythingllm.com storage docs, Oct 2026 (v1.18.0).
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


class AnythingLLMCollector(BaseCollector):
    PLATFORM_NAME = "anythingllm"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["anythingllm"]
    SERVICE_PORTS = [3001]

    LINUX_PATHS = ["~/.config/anythingllm-desktop/storage"]
    MACOS_PATHS = ["~/Library/Application Support/anythingllm-desktop/storage"]
    WINDOWS_PATHS = ["%APPDATA%\\anythingllm-desktop\\storage"]

    def _storage_root(self, home: Path) -> Path:
        system = self.detect_os()
        if system == "macos":
            return home / "Library/Application Support/anythingllm-desktop/storage"
        if system == "windows":
            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "anythingllm-desktop/storage"
        return home / ".config/anythingllm-desktop/storage"

    def discover(self) -> bool:
        return any(self._storage_root(home).is_dir()
                   for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = self._storage_root(home)
            if not root.is_dir():
                continue
            db = root / "anythingllm.db"
            if db.is_file():
                collected.append(self._record(db, "session_db"))
            cfg = root / "config.json"
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
            if cf.artifact_type == "session_db":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_db",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "tables": sqlite_counts(cf.original_path)},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "config":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    severity=Severity.INFO,
                    data={"path": cf.original_path, "bytes": cf.size_bytes},
                    source_file=cf.original_path,
                ))
        return artifacts
