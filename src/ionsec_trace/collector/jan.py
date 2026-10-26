"""Jan desktop app forensic artifact collector for TRACE.

Threads are JSONL per thread plus a thread.json sidecar; the data folder is
relocatable but defaults per OS. Paths verified against janhq/jan docs
(data-folder, troubleshooting), Oct 2026 (v0.8.7).
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


class JanCollector(BaseCollector):
    PLATFORM_NAME = "jan"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["jan"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.local/share/Jan/data"]
    MACOS_PATHS = ["~/Library/Application Support/Jan/data"]
    WINDOWS_PATHS = ["%APPDATA%\\Jan\\data"]

    def _data_root(self, home: Path) -> Path:
        system = self.detect_os()
        if system == "macos":
            return home / "Library/Application Support/Jan/data"
        if system == "windows":
            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "Jan/data"
        return home / ".local/share/Jan/data"

    def discover(self) -> bool:
        return any(self._data_root(home).is_dir()
                   for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = self._data_root(home)
            if not root.is_dir():
                continue
            threads = root / "threads"
            if threads.is_dir():
                for f in threads.glob("*/messages.jsonl"):
                    collected.append(self._record(f, "thread"))
                for f in threads.glob("*/thread.json"):
                    collected.append(self._record(f, "thread_meta"))
            store = root / "store.json"
            if store.is_file():
                collected.append(self._record(store, "config"))
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
            if cf.artifact_type == "thread":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="thread",
                        severity=Severity.LOW,
                        data={"path": cf.original_path,
                              "entries": sum(1 for line in content.splitlines() if line.strip())},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "thread_meta":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="thread_meta",
                    severity=Severity.INFO,
                    data={"path": cf.original_path, "bytes": cf.size_bytes},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.INFO,
                        data={"path": cf.original_path},
                        source_file=cf.original_path,
                    ))
        return artifacts
