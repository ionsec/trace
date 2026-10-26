"""Lemonade (AMD) forensic artifact collector for TRACE.

Lemonade became AnythingLLM Desktop's embedded engine in Oct 2026, and its
config migrated from the .cache to the .config location across platforms.
Paths verified against lemonade-server.ai configuration docs and the
migration wiki, Oct 2026.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class LemonadeCollector(BaseCollector):
    PLATFORM_NAME = "lemonade"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["lemonade", "lemond"]
    SERVICE_PORTS = [13305]

    LINUX_PATHS = ["~/.config/lemonade", "/var/lib/lemonade"]
    MACOS_PATHS = ["~/.config/lemonade"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.config\\lemonade"]

    def _roots(self) -> list[Path]:
        roots = []
        for home in self.get_user_home_dirs():
            roots.append(home / ".config/lemonade")
        if self.detect_os() == "linux":
            roots.append(Path("/var/lib/lemonade"))
        return roots

    def discover(self) -> bool:
        return any(root.is_dir() for root in self._roots())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for root in self._roots():
            if not root.is_dir():
                continue
            for rel in ("config.json", "user_models.json"):
                f = root / rel
                if f.is_file():
                    collected.append(self._record(f, "config"))
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
            data = self.safe_read_json(cf.original_path)
            if isinstance(data, dict):
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    severity=Severity.INFO,
                    data={"path": cf.original_path, "keys": sorted(data.keys())},
                    source_file=cf.original_path,
                ))
        return artifacts
