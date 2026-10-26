"""Warp terminal / Warp Agent CLI forensic artifact collector for TRACE.

The macOS database lives in a Group Container outside the usual home-dir
scan; Linux keeps config under the XDG config dir. Assistant response text
is not stored locally — the DB holds queries, tool executions and blocks.
Paths verified against docs.warp.dev (session restoration, file locations), Oct 2026.
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

_GROUP_CONTAINER = (
    "Library/Group Containers/2BBY89MBSN.dev.warp/"
    "Library/Application Support/dev.warp.Warp-Stable/warp.sqlite"
)


class WarpCollector(BaseCollector):
    PLATFORM_NAME = "warp"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["warp", "warp-terminal"]
    SERVICE_PORTS = []

    def discover(self) -> bool:
        import shutil
        if shutil.which("warp"):
            return True
        for home in self.get_user_home_dirs():
            if (home / ".warp").exists() or (home / _GROUP_CONTAINER).exists():
                return True
        return False

    def _config_roots(self) -> list[Path]:
        roots = []
        for home in self.get_user_home_dirs():
            roots.append(home / ".warp")
            roots.append(home / ".config/warp-terminal")
        return roots

    def _database_candidates(self) -> list[Path]:
        candidates = []
        for home in self.get_user_home_dirs():
            candidates.append(home / ".warp/warp.sqlite")
            candidates.append(home / _GROUP_CONTAINER)
        return candidates

    def collect(self) -> list[CollectedFile]:
        collected = []
        for db in self._database_candidates():
            if db.is_file():
                collected.append(self._record(db, "terminal_db"))
        for root in self._config_roots():
            if not root.is_dir():
                continue
            for rel, artifact_type in (
                ("settings.toml", "config"),
                (".mcp.json", "mcp_config"),
            ):
                f = root / rel
                if f.is_file():
                    collected.append(self._record(f, artifact_type))
            for sub, artifact_type in (("workflows", "workflow"), ("skills", "skill")):
                base = root / sub
                if base.is_dir():
                    for f in base.rglob("*"):
                        if f.is_file():
                            collected.append(self._record(f, artifact_type))
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
            if cf.artifact_type == "terminal_db":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="terminal_db",
                    severity=Severity.MEDIUM,
                    data={
                        "path": cf.original_path,
                        "tables": sqlite_counts(cf.original_path),
                        "note": "assistant response text is not stored locally; "
                                "DB holds AI queries, tool executions and blocks",
                    },
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "mcp_config":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="mcp_config",
                    severity=Severity.INFO,
                    data={"path": cf.original_path},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.INFO,
                        data={"path": cf.original_path, "bytes": cf.size_bytes},
                        source_file=cf.original_path,
                    ))
        return artifacts
