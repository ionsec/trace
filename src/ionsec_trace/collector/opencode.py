"""OpenCode forensic artifact collector for TRACE.

Storage moved from flat JSON files to SQLite (opencode.db) in v1.2.0; v2.1
renamed SDK fields but kept the DB. Paths verified on opencode.ai docs
(troubleshooting / cli / config), Oct 2026.
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


class OpenCodeCollector(BaseCollector):
    PLATFORM_NAME = "opencode"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["opencode"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.local/share/opencode"]
    MACOS_PATHS = ["~/.local/share/opencode"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.local\\share\\opencode"]

    def discover(self) -> bool:
        import shutil
        if shutil.which("opencode"):
            return True
        return any((home / ".local/share/opencode").exists()
                   for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = home / ".local/share/opencode"
            cfg_root = home / ".config/opencode"
            for rel, artifact_type in (
                ("opencode.db", "session_db"),
                ("auth.json", "credential"),
            ):
                f = root / rel
                if f.is_file():
                    collected.append(self._record(f, artifact_type))
            diffs = root / "storage/session_diff"
            if diffs.is_dir():
                for f in diffs.glob("ses_*.json"):
                    collected.append(self._record(f, "session_diff"))
            cfg = cfg_root / "opencode.json"
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
            elif cf.artifact_type == "session_diff":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_diff",
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
                        severity=Severity.MEDIUM if '"mcp"' in content else Severity.INFO,
                        data={"path": cf.original_path, "has_mcp": '"mcp"' in content},
                        source_file=cf.original_path,
                    ))
            elif cf.artifact_type == "credential":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="credential",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "note": "OpenCode auth store present (API keys / OAuth)"},
                    source_file=cf.original_path,
                ))
        return artifacts
