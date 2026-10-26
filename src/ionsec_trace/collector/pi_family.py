"""pi-family agent collector for TRACE.

pi, MiniMax Code, omp and senpi all write pi-style tree JSONL session stores
under their own home dirs (JetBrains ThinkRail writes into pi's store too).
One parser covers the family; the tool is attributed from the path.
Paths verified against deja-vu session registry and vendor docs, Oct 2026.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class PiFamilyCollector(BaseCollector):
    PLATFORM_NAME = "pi_family"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["pi", "minimax", "omp", "senpi"]
    SERVICE_PORTS = []

    _ROOTS = (
        (".pi/agent/sessions", "pi"),
        (".minimax/v2/sessions", "minimax"),
        (".omp/agent/sessions", "omp"),
        (".senpi/agent/sessions", "senpi"),
    )

    def discover(self) -> bool:
        return any((home / rel).exists()
                   for home in self.get_user_home_dirs()
                   for rel, _tool in self._ROOTS)

    @staticmethod
    def _tool_for(path: str) -> str:
        for needle, tool in (
            ("/.pi/", "pi"),
            ("/.minimax/", "minimax"),
            ("/.omp/", "omp"),
            ("/.senpi/", "senpi"),
        ):
            if needle in path:
                return tool
        return "unknown"

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            for rel, _tool in self._ROOTS:
                root = home / rel
                if not root.is_dir():
                    continue
                for f in root.rglob("*.jsonl"):
                    collected.append(self._record(f, "session"))
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
            if cf.artifact_type != "session":
                continue
            content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
            if content is None:
                continue
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="session",
                severity=Severity.LOW,
                data={
                    "path": cf.original_path,
                    "tool": self._tool_for(cf.original_path),
                    "entries": sum(1 for line in content.splitlines() if line.strip()),
                },
                source_file=cf.original_path,
            ))
        return artifacts
