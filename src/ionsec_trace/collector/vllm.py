"""vLLM forensic artifact collector for TRACE.

vLLM logs to stdout by default; the on-disk evidence is the config root
(VLLM_CONFIG_ROOT, default ~/.config/vllm) which can hold API keys and
profiler caches. Model weights live in the HF cache (covered by the
huggingface collector). Paths verified against docs.vllm.ai env-var docs, Oct 2026.
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


class VLLMCollector(BaseCollector):
    PLATFORM_NAME = "vllm"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["vllm", "vllm-openai"]
    SERVICE_PORTS = [8000]

    LINUX_PATHS = ["~/.config/vllm"]
    MACOS_PATHS = ["~/.config/vllm"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.config\\vllm"]

    def _config_root(self) -> Path | None:
        env = os.environ.get("VLLM_CONFIG_ROOT")
        if env:
            return Path(env)
        for home in self.get_user_home_dirs():
            candidate = home / ".config/vllm"
            if candidate.is_dir():
                return candidate
        return None

    def discover(self) -> bool:
        return self._config_root() is not None

    def collect(self) -> list[CollectedFile]:
        collected = []
        root = self._config_root()
        if root is None or not root.is_dir():
            return collected
        for f in root.rglob("*"):
            if f.is_file() and f.suffix in (".json", ".yaml", ".yml"):
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
            content = self.safe_read_file(cf.original_path)
            if not content:
                continue
            iocs = []
            if "api_key" in content.lower():
                iocs.append({"type": "api_key_in_config",
                             "detail": "API key reference in vLLM config"})
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="config",
                severity=Severity.MEDIUM if iocs else Severity.INFO,
                data={"path": cf.original_path},
                source_file=cf.original_path,
                iocs=iocs,
                mitre_atlas=["AML.T0055"] if iocs else [],
            ))
        return artifacts
