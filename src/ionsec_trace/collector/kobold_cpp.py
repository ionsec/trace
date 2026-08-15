"""
KoboldCpp forensic artifact collector for TRACE.

Collects: config files, session saves, model paths, logs, and process info.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class KoboldCppCollector(BaseCollector):
    PLATFORM_NAME = "kobold_cpp"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["koboldcpp", "koboldcpp.py"]
    SERVICE_PORTS = [5001]

    LINUX_PATHS = [
        "~/.koboldcpp",
        "/opt/koboldcpp",
        "/usr/local/bin/koboldcpp",
    ]
    MACOS_PATHS = [
        "~/.koboldcpp",
        "~/Library/Application Support/KoboldCpp",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.koboldcpp",
        "%LOCALAPPDATA%\\KoboldCpp",
        "%PROGRAMFILES%\\KoboldCpp",
    ]

    def discover(self) -> bool:
        """Detect if KoboldCpp is installed or has been used."""
        import shutil

        # Check for koboldcpp binary
        if shutil.which("koboldcpp"):
            return True

        # Check common install directories
        for home in self.get_user_home_dirs():
            if (home / ".koboldcpp").exists():
                return True

        # Check system-level installs
        os_name = self.detect_os()
        if os_name == "linux":
            for sys_path in ["/opt/koboldcpp", "/usr/local/bin/koboldcpp"]:
                if Path(sys_path).exists():
                    return True
        elif os_name == "macos":
            app_support = Path.home() / "Library" / "Application Support" / "KoboldCpp"
            if app_support.exists():
                return True
        elif os_name == "windows":
            for win_path in [
                Path.home() / ".koboldcpp",
                Path.home() / "AppData" / "Local" / "KoboldCpp",
            ]:
                if win_path.exists():
                    return True

        # Check for running process
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-f", "koboldcpp"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all KoboldCpp forensic artifacts."""
        collected = []

        # Check user home directories
        for home in self.get_user_home_dirs():
            kobold_dir = home / ".koboldcpp"
            if kobold_dir.exists():
                collected.extend(self._collect_from_dir(kobold_dir))

            # macOS Application Support
            if self.detect_os() == "macos":
                app_support = home / "Library" / "Application Support" / "KoboldCpp"
                if app_support.exists():
                    collected.extend(self._collect_from_dir(app_support))

            # Windows paths
            if self.detect_os() == "windows":
                local_app = home / "AppData" / "Local" / "KoboldCpp"
                if local_app.exists():
                    collected.extend(self._collect_from_dir(local_app))

        # System-level installs (Linux)
        if self.detect_os() == "linux":
            for sys_path_str in ["/opt/koboldcpp"]:
                sys_path = Path(sys_path_str)
                if sys_path.exists():
                    collected.extend(self._collect_from_dir(sys_path))

        return collected

    def _collect_from_dir(self, base_dir: Path) -> list[CollectedFile]:
        """Collect artifacts from a KoboldCpp directory."""
        collected = []

        # Config JSON files
        for config_file in base_dir.glob("*.json"):
            cf = CollectedFile(
                original_path=str(config_file),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="config",
                size_bytes=config_file.stat().st_size,
                sha256=self.calculate_hash(str(config_file)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # Config YAML files
        for config_file in base_dir.glob("*.yaml"):
            cf = CollectedFile(
                original_path=str(config_file),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="config",
                size_bytes=config_file.stat().st_size,
                sha256=self.calculate_hash(str(config_file)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        for config_file in base_dir.glob("*.yml"):
            cf = CollectedFile(
                original_path=str(config_file),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="config",
                size_bytes=config_file.stat().st_size,
                sha256=self.calculate_hash(str(config_file)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # Session save files
        sessions_dir = base_dir / "sessions"
        if sessions_dir.exists():
            for session_file in sessions_dir.rglob("*"):
                if session_file.is_file():
                    cf = CollectedFile(
                        original_path=str(session_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_save",
                        size_bytes=session_file.stat().st_size,
                        sha256=self.calculate_hash(str(session_file)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        # Log files
        for log_file in base_dir.glob("*.log"):
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

        for log_file in base_dir.glob("*.log.*"):
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

        # Main executable/script
        for exe_name in ["koboldcpp.py", "koboldcpp.exe", "koboldcpp"]:
            exe_path = base_dir / exe_name
            if exe_path.exists():
                cf = CollectedFile(
                    original_path=str(exe_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="executable",
                    size_bytes=exe_path.stat().st_size,
                    sha256=self.calculate_hash(str(exe_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected KoboldCpp artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    model_paths = []

                    # Extract model paths from config
                    for key in ["model", "model_path", "modelpath", "ggml_file", "lora_file"]:
                        if key in data:
                            model_paths.append(data[key])

                    if model_paths:
                        iocs.append({
                            "type": "model_path_in_config",
                            "detail": "Model path found in KoboldCpp config",
                            "paths": model_paths,
                        })

                    config_str = str(data)
                    if "api_key" in config_str.lower():
                        iocs.append({
                            "type": "api_key_exposure",
                            "detail": "API key found in KoboldCpp config",
                        })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "session_save":
                content = self.safe_read_file(cf.original_path, max_bytes=1024 * 1024)
                if content:
                    data = {"filename": Path(cf.original_path).name, "size_bytes": cf.size_bytes}
                    # Try JSON parse for session metadata
                    json_data = self.safe_read_json(cf.original_path)
                    if json_data:
                        data["parsed"] = json_data
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_save",
                        severity=Severity.LOW,
                        data=data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "log":
                content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
                if content:
                    errors = []
                    for line in content.splitlines():
                        line_lower = line.lower()
                        if "error" in line_lower or "fail" in line_lower or "exception" in line_lower:
                            errors.append(line.strip()[:200])

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="log",
                        severity=Severity.MEDIUM if errors else Severity.INFO,
                        data={
                            "log_file": Path(cf.original_path).name,
                            "size_bytes": cf.size_bytes,
                            "error_count": len(errors),
                            "errors_preview": errors[:10],
                        },
                        source_file=cf.original_path,
                    ))

        return artifacts
