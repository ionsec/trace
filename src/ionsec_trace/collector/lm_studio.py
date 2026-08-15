"""
LM Studio forensic artifact collector for TRACE.

Collects: config, conversation databases (LevelDB), session store,
model directory listings, log files, and API key indicators.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class LMStudioCollector(BaseCollector):
    PLATFORM_NAME = "lm_studio"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["lm-studio", "LM Studio"]
    SERVICE_PORTS = [1234]

    LINUX_PATHS = [
        "~/.cache/lm-studio/",
    ]
    MACOS_PATHS = [
        "~/Library/Application Support/LM Studio/",
        "~/Library/Caches/lm-studio/",
    ]
    WINDOWS_PATHS = [
        "%APPDATA%\\LM Studio\\",
        "%LOCALAPPDATA%\\LM Studio\\",
    ]

    def _get_platform_dirs(self) -> list[Path]:
        """Return LM Studio data directories for the current OS."""
        os_name = self.detect_os()
        dirs = []
        if os_name == "linux":
            dirs = [Path.home() / ".cache" / "lm-studio"]
        elif os_name == "macos":
            dirs = [
                Path.home() / "Library" / "Application Support" / "LM Studio",
                Path.home() / "Library" / "Caches" / "lm-studio",
            ]
        elif os_name == "windows":
            import os
            appdata = os.environ.get("APPDATA", "")
            localappdata = os.environ.get("LOCALAPPDATA", "")
            if appdata:
                dirs.append(Path(appdata) / "LM Studio")
            if localappdata:
                dirs.append(Path(localappdata) / "LM Studio")
        return [d for d in dirs if d is not None]

    def discover(self) -> bool:
        """Detect if LM Studio is installed or has been used."""
        import shutil
        if shutil.which("lm-studio"):
            return True

        for d in self._get_platform_dirs():
            if d.exists():
                return True

        # Check for running process
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-f", "lm-studio"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all LM Studio forensic artifacts."""
        collected = []

        for base_dir in self._get_platform_dirs():
            if not base_dir.exists():
                continue

            # Config / settings
            for settings_name in ["settings.json", "config.json"]:
                settings_path = base_dir / settings_name
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

            # LevelDB conversation store (Local Storage)
            local_storage = base_dir / "Local Storage" / "leveldb"
            if local_storage.exists():
                for ldb_file in local_storage.iterdir():
                    if ldb_file.is_file():
                        cf = CollectedFile(
                            original_path=str(ldb_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="conversation_leveldb",
                            size_bytes=ldb_file.stat().st_size,
                            sha256=self.calculate_hash(str(ldb_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Session store
            for session_name in ["Session Storage"]:
                session_dir = base_dir / session_name
                if session_dir.exists() and session_dir.is_dir():
                    for sf in session_dir.rglob("*"):
                        if sf.is_file():
                            cf = CollectedFile(
                                original_path=str(sf),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="session_store",
                                size_bytes=sf.stat().st_size,
                                sha256=self.calculate_hash(str(sf)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

            # Model directory listing
            models_dir = base_dir / "models"
            if models_dir.exists():
                for model_file in models_dir.rglob("*"):
                    if model_file.is_file():
                        cf = CollectedFile(
                            original_path=str(model_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="model_file",
                            size_bytes=model_file.stat().st_size,
                            sha256=self.calculate_hash(str(model_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Log files
            logs_dir = base_dir / "logs"
            if logs_dir.exists():
                for log_file in logs_dir.iterdir():
                    if log_file.is_file():
                        cf = CollectedFile(
                            original_path=str(log_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="log",
                            size_bytes=log_file.stat().st_size,
                            sha256=self.calculate_hash(str(log_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # IndexedDB (may contain chat data)
            idb_dir = base_dir / "IndexedDB"
            if idb_dir.exists():
                for idb_file in idb_dir.rglob("*"):
                    if idb_file.is_file():
                        cf = CollectedFile(
                            original_path=str(idb_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="indexeddb",
                            size_bytes=idb_file.stat().st_size,
                            sha256=self.calculate_hash(str(idb_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

        # Also check user home for .cache/lm-studio on Linux
        for home in self.get_user_home_dirs():
            cache_dir = home / ".cache" / "lm-studio"
            if cache_dir.exists() and cache_dir not in self._get_platform_dirs():
                for item in cache_dir.rglob("*"):
                    if item.is_file():
                        cf = CollectedFile(
                            original_path=str(item),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="cache_file",
                            size_bytes=item.stat().st_size,
                            sha256=self.calculate_hash(str(item)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected LM Studio artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    config_str = str(data).lower()
                    if "api_key" in config_str or "apikey" in config_str:
                        iocs.append({
                            "type": "api_key_exposure",
                            "detail": "API key found in LM Studio settings",
                        })
                    if "token" in config_str and "bearer" in config_str:
                        iocs.append({
                            "type": "bearer_token_exposure",
                            "detail": "Bearer token found in LM Studio settings",
                        })

                    # Extract model names from config
                    model_names = []
                    for key in ["models", "downloadedModels", "loadedModels", "activeModel"]:
                        if key in data:
                            val = data[key]
                            if isinstance(val, list):
                                model_names.extend(val)
                            elif isinstance(val, str):
                                model_names.append(val)

                    parsed_data = dict(data) if isinstance(data, dict) else {"raw": str(data)}
                    if model_names:
                        parsed_data["_extracted_model_names"] = model_names

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=parsed_data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "log":
                content = self.safe_read_file(cf.original_path, max_bytes=2 * 1024 * 1024)
                if content:
                    errors = [line for line in content.splitlines() if "error" in line.lower()]
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="log",
                        severity=Severity.LOW,
                        data={
                            "path": cf.original_path,
                            "line_count": len(content.splitlines()),
                            "error_lines": len(errors),
                            "preview": content[:2000],
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "model_file":
                fname = Path(cf.original_path).name
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="model_file",
                    severity=Severity.INFO,
                    data={
                        "filename": fname,
                        "size_bytes": cf.size_bytes,
                        "path": cf.original_path,
                    },
                    source_file=cf.original_path,
                ))

        return artifacts
