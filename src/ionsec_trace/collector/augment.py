"""Augment Code forensic artifact collector for TRACE.

Per-conversation JSON sessions, a capped prompt history, and settings live
under ~/.augment. Path verified against Augment docs and deja-vu registry, Oct 2026.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class AugmentCollector(BaseCollector):
    PLATFORM_NAME = "augment"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["augment"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.augment"]
    MACOS_PATHS = ["~/.augment"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.augment"]

    def discover(self) -> bool:
        return any((home / ".augment").exists() for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = home / ".augment"
            if not root.is_dir():
                continue
            sessions = root / "sessions"
            if sessions.is_dir():
                for f in sessions.glob("*.json"):
                    collected.append(self._record(f, "session"))
            hist = root / "prompt-history.jsonl"
            if hist.is_file():
                collected.append(self._record(hist, "history"))
            cfg = root / "settings.json"
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
                data = self.safe_read_json(cf.original_path)
                turns = 0
                if isinstance(data, dict):
                    value = data.get("turns")
                    if isinstance(value, list):
                        turns = len(value)
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session",
                    severity=Severity.LOW,
                    data={"path": cf.original_path, "turns": turns},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "history":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="history",
                        severity=Severity.INFO,
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
