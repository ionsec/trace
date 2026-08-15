"""
text-generation-webui (oobabooga) forensic artifact collector for TRACE.

Collects: settings.yaml, chat logs, model listings, character definitions,
instruction templates, and process detection for running instances.
"""

import subprocess
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class TextGenWebUICollector(BaseCollector):
    PLATFORM_NAME = "text_generation_webui"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["text-generation-webui", "server.py", "oobabooga"]
    SERVICE_PORTS = [7860, 5000]

    # Common install paths to search
    LINUX_PATHS = [
        "~/text-generation-webui/",
        "/opt/text-generation-webui/",
    ]
    MACOS_PATHS = [
        "~/text-generation-webui/",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\text-generation-webui\\",
        "C:\\text-generation-webui\\",
    ]

    def _find_install_dirs(self) -> list[Path]:
        """Search for text-generation-webui installations."""
        dirs = []

        # Check common paths
        candidate_paths = [
            Path.home() / "text-generation-webui",
            Path("/opt/text-generation-webui"),
        ]

        # Also check user home directories
        for home in self.get_user_home_dirs():
            candidate_paths.append(home / "text-generation-webui")

        # Check for running processes to find install dir
        try:
            result = subprocess.run(
                ["pgrep", "-af", "text-generation-webui"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    # Extract directory from process command line
                    parts = line.split()
                    for part in parts:
                        if "text-generation-webui" in part:
                            # Get parent dir of the script path
                            p = Path(part)
                            if p.exists():
                                # Could be a script inside the install dir
                                candidate_paths.append(p.parent)
        except Exception:
            pass

        # Deduplicate and validate
        seen = set()
        for p in candidate_paths:
            resolved = p.resolve() if p.exists() else p
            if str(resolved) not in seen:
                seen.add(str(resolved))
                # Verify it's actually a text-generation-webui install
                if (p / "user_data").exists() or (p / "extensions").exists():
                    dirs.append(p)

        return dirs

    def discover(self) -> bool:
        """Detect if text-generation-webui is installed or running."""
        # Check install directories
        if self._find_install_dirs():
            return True

        # Check for running process
        try:
            result = subprocess.run(
                ["pgrep", "-f", "text-generation-webui"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        # Check for running server on common ports
        try:
            result = subprocess.run(
                ["pgrep", "-f", "server.py"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all text-generation-webui forensic artifacts."""
        collected = []

        install_dirs = self._find_install_dirs()

        for install_dir in install_dirs:
            user_data = install_dir / "user_data"
            if not user_data.exists():
                continue

            # Settings
            for settings_name in ["settings.yaml", "settings.json", "config.yaml"]:
                settings_path = user_data / settings_name
                if settings_path.exists():
                    cf = CollectedFile(
                        original_path=str(settings_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        size_bytes=settings_path.stat().st_size,
                        sha256=self.calculate_hash(str(settings_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Chat logs (JSON format)
            chats_dir = user_data / "logs"
            if chats_dir.exists():
                for chat_file in chats_dir.rglob("*.json"):
                    cf = CollectedFile(
                        original_path=str(chat_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="chat_log",
                        size_bytes=chat_file.stat().st_size,
                        sha256=self.calculate_hash(str(chat_file)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

                # Also collect text logs
                for chat_file in chats_dir.rglob("*.txt"):
                    cf = CollectedFile(
                        original_path=str(chat_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="chat_log",
                        size_bytes=chat_file.stat().st_size,
                        sha256=self.calculate_hash(str(chat_file)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Models directory listing (just top-level to avoid huge hashes)
            models_dir = user_data / "models"
            if models_dir.exists():
                for model_dir in models_dir.iterdir():
                    if model_dir.is_dir():
                        cf = CollectedFile(
                            original_path=str(model_dir),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="model_directory",
                            size_bytes=0,
                            sha256="directory",
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Character definitions
            characters_dir = user_data / "characters"
            if characters_dir.exists():
                for char_file in characters_dir.iterdir():
                    if char_file.is_file():
                        cf = CollectedFile(
                            original_path=str(char_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="character",
                            size_bytes=char_file.stat().st_size,
                            sha256=self.calculate_hash(str(char_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Instruction templates
            templates_dir = user_data / "instruction-templates"
            if templates_dir.exists():
                for tmpl_file in templates_dir.iterdir():
                    if tmpl_file.is_file():
                        cf = CollectedFile(
                            original_path=str(tmpl_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="instruction_template",
                            size_bytes=tmpl_file.stat().st_size,
                            sha256=self.calculate_hash(str(tmpl_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Training datasets (if present)
            training_dir = user_data / "training"
            if training_dir.exists():
                for train_file in training_dir.rglob("*"):
                    if train_file.is_file():
                        cf = CollectedFile(
                            original_path=str(train_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="training_data",
                            size_bytes=train_file.stat().st_size,
                            sha256=self.calculate_hash(str(train_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Extensions config
            extensions_dir = install_dir / "extensions"
            if extensions_dir.exists():
                for ext_dir in extensions_dir.iterdir():
                    if ext_dir.is_dir():
                        ext_requirements = ext_dir / "requirements.txt"
                        if ext_requirements.exists():
                            cf = CollectedFile(
                                original_path=str(ext_requirements),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="extension_requirement",
                                size_bytes=ext_requirements.stat().st_size,
                                sha256=self.calculate_hash(str(ext_requirements)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

            # Presets
            presets_dir = user_data / "presets"
            if presets_dir.exists():
                for preset_file in presets_dir.rglob("*.yaml"):
                    cf = CollectedFile(
                        original_path=str(preset_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="preset",
                        size_bytes=preset_file.stat().st_size,
                        sha256=self.calculate_hash(str(preset_file)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

                for preset_file in presets_dir.rglob("*.json"):
                    cf = CollectedFile(
                        original_path=str(preset_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="preset",
                        size_bytes=preset_file.stat().st_size,
                        sha256=self.calculate_hash(str(preset_file)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected text-generation-webui artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                path = Path(cf.original_path)
                if path.suffix == ".yaml":
                    try:
                        import yaml
                        with open(cf.original_path, encoding="utf-8", errors="replace") as f:
                            data = yaml.safe_load(f)
                    except Exception:
                        data = None
                else:
                    data = self.safe_read_json(cf.original_path)

                if data:
                    iocs = []
                    config_str = str(data).lower()
                    if "api_key" in config_str or "apikey" in config_str:
                        iocs.append({
                            "type": "api_key_exposure",
                            "detail": "API key found in text-generation-webui settings",
                        })
                    if "openai" in config_str and ("key" in config_str or "token" in config_str):
                        iocs.append({
                            "type": "openai_key_exposure",
                            "detail": "OpenAI key reference found in settings",
                        })

                    # Extract model information
                    model_names = []
                    if isinstance(data, dict):
                        for key in ["model", "default_model", "model-menu", "loader"]:
                            if key in data:
                                model_names.append(f"{key}={data[key]}")

                    parsed_data = data if isinstance(data, dict) else {"raw": str(data)}
                    if model_names:
                        parsed_data["_extracted_model_info"] = model_names

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=parsed_data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "chat_log":
                data = self.safe_read_json(cf.original_path)
                if data:
                    # Extract metadata without full conversation content
                    chat_meta = {}
                    if isinstance(data, dict):
                        for key in ["model", "character", "mode", "timestamp", "created_at"]:
                            if key in data:
                                chat_meta[key] = data[key]
                        # Count messages without storing them
                        if "messages" in data and isinstance(data["messages"], list):
                            chat_meta["message_count"] = len(data["messages"])
                    elif isinstance(data, list):
                        chat_meta["entry_count"] = len(data)

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="chat_log",
                        severity=Severity.MEDIUM,
                        data=chat_meta,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "character":
                data = self.safe_read_json(cf.original_path)
                if data:
                    char_name = data.get("name", Path(cf.original_path).stem)
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="character",
                        severity=Severity.INFO,
                        data={"character_name": char_name, "file": cf.original_path},
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "model_directory":
                model_name = Path(cf.original_path).name
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="model_directory",
                    severity=Severity.INFO,
                    data={"model_name": model_name, "path": cf.original_path},
                    source_file=cf.original_path,
                ))

            elif cf.artifact_type == "instruction_template":
                data = self.safe_read_json(cf.original_path)
                if data:
                    template_name = data.get("name", Path(cf.original_path).stem)
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="instruction_template",
                        severity=Severity.INFO,
                        data={"template_name": template_name},
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "preset":
                path = Path(cf.original_path)
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="preset",
                    severity=Severity.INFO,
                    data={"preset_name": path.stem, "file": cf.original_path},
                    source_file=cf.original_path,
                ))

        return artifacts
