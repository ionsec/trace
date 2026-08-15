"""
Aider forensic artifact collector for TRACE.

Collects: chat history, input history, tags cache, config files,
and conversation metadata from Aider coding assistant.
"""

import re
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class AiderCollector(BaseCollector):
    PLATFORM_NAME = "aider"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["aider"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.aider",
    ]
    MACOS_PATHS = [
        "~/.aider",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.aider",
    ]

    def discover(self) -> bool:
        """Detect if Aider is installed or has been used."""
        import shutil
        if shutil.which("aider"):
            return True

        for home in self.get_user_home_dirs():
            # Check for .aider* files in home directory
            for _ in home.glob(".aider*"):
                return True

        # Check common project directories for .aider.chat.history.md
        for home in self.get_user_home_dirs():
            for proj_dir in [home / "projects", home / "src", home / "work", home / "code"]:
                if not proj_dir.exists():
                    continue
                try:
                    for _ in proj_dir.rglob(".aider.chat.history.md"):
                        return True
                except (PermissionError, OSError):
                    continue

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all Aider forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            # Home-level .aider files
            aider_files = {
                ".aider.chat.history.md": "chat_history",
                ".aider.chat.history": "chat_history",
                ".aider.input.history": "input_history",
                ".aider.conf.yml": "config",
                ".aider.conf.yaml": "config",
                ".aider.tags.cache.v3": "tags_cache",
            }

            for filename, artifact_type in aider_files.items():
                file_path = home / filename
                if file_path.exists():
                    cf = CollectedFile(
                        original_path=str(file_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type=artifact_type,
                        size_bytes=file_path.stat().st_size,
                        sha256=self.calculate_hash(str(file_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # .aider directory (newer versions may use a directory)
            aider_dir = home / ".aider"
            if aider_dir.exists() and aider_dir.is_dir():
                for item in aider_dir.rglob("*"):
                    if item.is_file():
                        artifact_type = self._classify_aider_file(item.name)
                        cf = CollectedFile(
                            original_path=str(item),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type=artifact_type,
                            size_bytes=item.stat().st_size,
                            sha256=self.calculate_hash(str(item)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Project-level aider files
            project_dirs = [
                home / "projects",
                home / "src",
                home / "work",
                home / "code",
            ]
            for proj_base in project_dirs:
                if not proj_base.exists():
                    continue
                try:
                    # Search for .aider.chat.history.md in project subdirectories
                    for history_file in proj_base.rglob(".aider.chat.history.md"):
                        cf = CollectedFile(
                            original_path=str(history_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="chat_history",
                            size_bytes=history_file.stat().st_size,
                            sha256=self.calculate_hash(str(history_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                    # Also collect .aider.conf.yml from project dirs
                    for conf_file in proj_base.rglob(".aider.conf.yml"):
                        cf = CollectedFile(
                            original_path=str(conf_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="config",
                            size_bytes=conf_file.stat().st_size,
                            sha256=self.calculate_hash(str(conf_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                    for conf_file in proj_base.rglob(".aider.conf.yaml"):
                        cf = CollectedFile(
                            original_path=str(conf_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="config",
                            size_bytes=conf_file.stat().st_size,
                            sha256=self.calculate_hash(str(conf_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                    # Input history
                    for input_file in proj_base.rglob(".aider.input.history"):
                        cf = CollectedFile(
                            original_path=str(input_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="input_history",
                            size_bytes=input_file.stat().st_size,
                            sha256=self.calculate_hash(str(input_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                    # Tags cache directories
                    for tags_dir in proj_base.rglob(".aider.tags.cache.v3"):
                        if tags_dir.is_dir():
                            for cache_file in tags_dir.rglob("*"):
                                if cache_file.is_file():
                                    cf = CollectedFile(
                                        original_path=str(cache_file),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type="tags_cache",
                                        size_bytes=cache_file.stat().st_size,
                                        sha256=self.calculate_hash(str(cache_file)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

                except (PermissionError, OSError):
                    continue

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Aider artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "chat_history":
                content = self.safe_read_file(cf.original_path)
                if content:
                    # Extract conversation topics from markdown headers
                    topics = []
                    model_names = []
                    for line in content.splitlines():
                        line_stripped = line.strip()
                        # Aider uses # as conversation delimiters
                        if line_stripped.startswith("# "):
                            topics.append(line_stripped[2:].strip())
                        # Extract model references
                        model_match = re.search(
                            r"(?:model|Model)[:\s]+(\S+)", line_stripped
                        )
                        if model_match:
                            model_names.append(model_match.group(1))

                    # Count conversations (separated by Aider's standard delimiters)
                    conversation_count = content.count("#### ") + content.count("### ")

                    iocs = []
                    if model_names:
                        for model in set(model_names):
                            iocs.append({"type": "model_usage", "detail": f"Model used: {model}"})

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="chat_history",
                        severity=Severity.LOW,
                        data={
                            "topics": topics[:50],  # Cap at 50
                            "model_names": list(set(model_names)),
                            "total_size_bytes": cf.size_bytes,
                            "conversation_count": conversation_count,
                        },
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "input_history":
                content = self.safe_read_file(cf.original_path)
                if content:
                    commands = [line.strip() for line in content.splitlines() if line.strip()]
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="input_history",
                        severity=Severity.LOW,
                        data={
                            "total_commands": len(commands),
                            "preview": commands[:20],
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    try:
                        import yaml
                        data = yaml.safe_load(content)
                    except Exception:
                        data = {"raw": content}

                    iocs = []
                    if isinstance(data, dict):
                        config_str = str(data).lower()
                        if "api_key" in config_str:
                            iocs.append({"type": "api_key_in_config", "detail": "API key reference found in Aider config"})
                        # Extract model configuration
                        model = data.get("model", data.get("model-name"))
                        if model:
                            iocs.append({"type": "model_config", "detail": f"Default model: {model}"})

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if iocs else Severity.INFO,
                        data=data if isinstance(data, dict) else {"raw": str(data)},
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0055"] if any(i.get("type") == "api_key_in_config" for i in iocs) else [],
                    ))

            elif cf.artifact_type == "tags_cache":
                # Tags cache is internal Aider data — just catalog it
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="tags_cache",
                    severity=Severity.INFO,
                    data={"filename": Path(cf.original_path).name, "size": cf.size_bytes},
                    source_file=cf.original_path,
                ))

        return artifacts

    @staticmethod
    def _classify_aider_file(filename: str) -> str:
        """Map an Aider filename to an artifact type."""
        name = filename.lower()
        if "chat.history" in name:
            return "chat_history"
        if "input.history" in name:
            return "input_history"
        if "tags.cache" in name:
            return "tags_cache"
        if name.startswith(".aider.conf"):
            return "config"
        if name.endswith((".yml", ".yaml")):
            return "config"
        if name.endswith((".md", ".txt")):
            return "log"
        return "data"
