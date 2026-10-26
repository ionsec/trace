"""LocalAI forensic artifact collector for TRACE.

Per-model YAML configs, the API key store and env files reveal every model
ever configured (including remote providers). Paths verified against
localai.io docs (FAQ, model configuration, CLI reference), Oct 2026 (v4.11.0).
"""

from pathlib import Path

import yaml

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class LocalAICollector(BaseCollector):
    PLATFORM_NAME = "localai"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["local-ai", "localai"]
    SERVICE_PORTS = [8080]

    LINUX_PATHS = ["~/.localai/models", "~/.config/localai.env"]
    MACOS_PATHS = ["~/.localai/models", "~/.config/localai.env"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.localai\\models"]

    def _model_dirs(self) -> list[Path]:
        dirs = [Path("./models")]
        for home in self.get_user_home_dirs():
            dirs.append(home / ".localai/models")
        return dirs

    def discover(self) -> bool:
        if any(d.is_dir() for d in self._model_dirs()):
            return True
        return any((home / ".config/localai.env").exists()
                   for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for models in self._model_dirs():
            if not models.is_dir():
                continue
            for f in models.glob("*.yaml"):
                collected.append(self._record(f, "model_config"))
        for home in self.get_user_home_dirs():
            keys = home / ".localai/configuration/api_keys.json"
            if keys.is_file():
                collected.append(self._record(keys, "api_keys"))
            env = home / ".config/localai.env"
            if env.is_file():
                collected.append(self._record(env, "env"))
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
            if cf.artifact_type == "model_config":
                content = self.safe_read_file(cf.original_path)
                if not content:
                    continue
                try:
                    data = yaml.safe_load(content) or {}
                except yaml.YAMLError:
                    data = {}
                name = data.get("name") if isinstance(data, dict) else None
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="model_config",
                    severity=Severity.INFO,
                    data={"path": cf.original_path,
                          "name": name or Path(cf.original_path).stem},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "api_keys":
                # Existence only.
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="api_keys",
                    severity=Severity.CRITICAL,
                    data={"path": cf.original_path,
                          "note": "LocalAI API key store present"},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "env":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="env",
                    severity=Severity.HIGH,
                    data={"path": cf.original_path,
                          "note": "LocalAI env file may contain provider keys"},
                    source_file=cf.original_path,
                ))
        return artifacts
