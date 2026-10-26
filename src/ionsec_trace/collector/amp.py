"""Sourcegraph Amp forensic artifact collector for TRACE.

One JSON object per agent thread under the XDG data dir (~/.local/share/amp).
Path verified against ampcode docs and deja-vu registry; macOS layout is the
same amp/threads tree under the platform data dir.
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


class AmpCollector(BaseCollector):
    PLATFORM_NAME = "amp"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["amp"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.local/share/amp"]
    MACOS_PATHS = ["~/.local/share/amp"]
    WINDOWS_PATHS = ["%LOCALAPPDATA%\\amp"]

    def _data_root(self) -> Path | None:
        env = os.environ.get("XDG_DATA_HOME")
        if env:
            return Path(env) / "amp"
        for home in self.get_user_home_dirs():
            candidate = home / ".local/share/amp"
            if candidate.is_dir():
                return candidate
        return None

    def discover(self) -> bool:
        return self._data_root() is not None

    def collect(self) -> list[CollectedFile]:
        collected = []
        root = self._data_root()
        if root is None or not root.is_dir():
            return collected
        threads = root / "threads"
        if threads.is_dir():
            for f in threads.glob("*.json"):
                collected.append(self._record(f, "thread"))
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
            if cf.artifact_type != "thread":
                continue
            data = self.safe_read_json(cf.original_path)
            messages = 0
            if isinstance(data, dict):
                value = data.get("messages")
                if isinstance(value, list):
                    messages = len(value)
            elif isinstance(data, list):
                messages = len(data)
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="thread",
                severity=Severity.LOW,
                data={"path": cf.original_path, "messages": messages},
                source_file=cf.original_path,
            ))
        return artifacts
