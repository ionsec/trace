"""Continue.dev forensic artifact collector for TRACE.

Config (YAML/JSON), assistant sessions and MCP server definitions live under
~/.continue. Paths verified against docs.continue.dev, Oct 2026.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class ContinueCollector(BaseCollector):
    PLATFORM_NAME = "continue"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["continue"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.continue"]
    MACOS_PATHS = ["~/.continue"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.continue"]

    def discover(self) -> bool:
        return any((home / ".continue").exists() for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            root = home / ".continue"
            if not root.is_dir():
                continue
            for rel in ("config.yaml", "config.json"):
                f = root / rel
                if f.is_file():
                    collected.append(self._record(f, "config"))
            sessions = root / "sessions"
            if sessions.is_dir():
                for f in sessions.glob("*.json"):
                    collected.append(self._record(f, "session"))
            mcp = root / "mcpServers"
            if mcp.is_dir():
                for f in mcp.glob("*.json"):
                    collected.append(self._record(f, "mcp_config"))
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
            if cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    iocs = []
                    if "api_key" in content.lower():
                        iocs.append({"type": "api_key_in_config",
                                     "detail": "API key reference in Continue config"})
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if iocs else Severity.INFO,
                        data={"path": cf.original_path},
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0055"] if iocs else [],
                    ))
            elif cf.artifact_type == "session":
                data = self.safe_read_json(cf.original_path)
                entries = 0
                if isinstance(data, dict):
                    for key in ("messages", "history"):
                        value = data.get(key)
                        if isinstance(value, list):
                            entries = len(value)
                            break
                elif isinstance(data, list):
                    entries = len(data)
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session",
                    severity=Severity.LOW,
                    data={"path": cf.original_path, "messages": entries},
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
        return artifacts
