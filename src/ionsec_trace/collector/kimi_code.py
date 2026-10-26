"""Kimi Code (Moonshot) forensic artifact collector for TRACE.

Per-agent wire-format JSONL transcripts under ~/.kimi-code plus the TOML
config under ~/.kimi. Paths verified against MoonshotAI docs (kimi-cli and
kimi-code config-files pages), Oct 2026.
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


class KimiCodeCollector(BaseCollector):
    PLATFORM_NAME = "kimi_code"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["kimi", "kimi-code"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.kimi-code", "~/.kimi"]
    MACOS_PATHS = ["~/.kimi-code", "~/.kimi"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.kimi-code", "%USERPROFILE%\\.kimi"]

    def _sessions_root(self) -> Path | None:
        env = os.environ.get("KIMI_CODE_HOME")
        if env:
            return Path(env)
        for home in self.get_user_home_dirs():
            candidate = home / ".kimi-code"
            if candidate.is_dir():
                return candidate
        return None

    def discover(self) -> bool:
        import shutil
        if shutil.which("kimi"):
            return True
        if self._sessions_root() is not None:
            return True
        return any((home / ".kimi").exists() for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        root = self._sessions_root()
        if root is not None and root.is_dir():
            for f in root.rglob("wire.jsonl"):
                collected.append(self._record(f, "session"))
        for home in self.get_user_home_dirs():
            cfg = home / ".kimi/config.toml"
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
            elif cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if "api_key" in content.lower() else Severity.INFO,
                        data={"path": cf.original_path},
                        source_file=cf.original_path,
                    ))
        return artifacts
