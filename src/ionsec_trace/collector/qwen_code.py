"""Qwen Code forensic artifact collector for TRACE.

Only the settings file is documented and verified; the local chat store is
not confirmed by official sources, so nothing beyond config is collected.
Path verified against QwenLM/qwen-code docs, Oct 2026.
"""


from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class QwenCodeCollector(BaseCollector):
    PLATFORM_NAME = "qwen_code"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["qwen", "qwen-code"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.qwen"]
    MACOS_PATHS = ["~/.qwen"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.qwen"]

    def discover(self) -> bool:
        import shutil
        if shutil.which("qwen"):
            return True
        return any((home / ".qwen").exists() for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for home in self.get_user_home_dirs():
            cfg = home / ".qwen/settings.json"
            if cfg.is_file():
                cf = CollectedFile(
                    original_path=str(cfg),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    size_bytes=cfg.stat().st_size,
                    sha256=self.calculate_hash(str(cfg)),
                    collected_at=self.timestamp(),
                )
                self.collected_files.append(cf)
                collected.append(cf)
        return collected

    def parse(self) -> list[ParsedArtifact]:
        artifacts = []
        for cf in self.collected_files:
            if cf.artifact_type != "config":
                continue
            content = self.safe_read_file(cf.original_path)
            if content:
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    severity=Severity.MEDIUM if "mcpServers" in content else Severity.INFO,
                    data={"path": cf.original_path,
                          "has_mcp_servers": "mcpServers" in content},
                    source_file=cf.original_path,
                ))
        return artifacts
