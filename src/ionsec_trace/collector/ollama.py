"""
Ollama forensic artifact collector for TRACE.

Collects: config, model manifests, history, service logs, API keys,
ed25519 keypairs, process info, network connections, and model inventory.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class OllamaCollector(BaseCollector):
    PLATFORM_NAME = "ollama"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["ollama", "ollama serve"]
    SERVICE_PORTS = [11434]

    LINUX_PATHS = [
        "/root/.ollama",
        "/usr/share/ollama/.ollama",
    ]
    MACOS_PATHS = [
        "~/.ollama",
        "~/Library/Application Support/Ollama",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.ollama",
        "%LOCALAPPDATA%\\Ollama",
    ]

    def discover(self) -> bool:
        """Detect if Ollama is installed or has been used."""
        import shutil
        if shutil.which("ollama"):
            return True

        for home in self.get_user_home_dirs():
            if (home / ".ollama").exists():
                return True

        return bool(self.detect_os() == "linux" and Path("/etc/systemd/system/ollama.service").exists())

    def collect(self) -> list[CollectedFile]:
        """Collect all Ollama forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            ollama_dir = home / ".ollama"
            if not ollama_dir.exists():
                continue

            # Config file
            config_path = ollama_dir / "config.json"
            if config_path.exists():
                cf = CollectedFile(
                    original_path=str(config_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    size_bytes=config_path.stat().st_size,
                    sha256=self.calculate_hash(str(config_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # CLI history
            history_path = ollama_dir / "history"
            if history_path.exists():
                cf = CollectedFile(
                    original_path=str(history_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="cli_history",
                    size_bytes=history_path.stat().st_size,
                    sha256=self.calculate_hash(str(history_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # SQLite conversation database (Ollama v0.5+)
            for db_file in ["db.sqlite", "db.sqlite-wal", "db.sqlite-shm"]:
                db_path = ollama_dir / db_file
                if db_path.exists():
                    cf = CollectedFile(
                        original_path=str(db_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="conversation_database" if db_file == "db.sqlite" else "conversation_database_wal",
                        size_bytes=db_path.stat().st_size,
                        sha256=self.calculate_hash(str(db_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # macOS Application Support paths
            app_support = home / "Library" / "Application Support" / "Ollama"
            if app_support.exists():
                for db_file in ["db.sqlite", "db.sqlite-wal", "db.sqlite-shm"]:
                    db_path = app_support / db_file
                    if db_path.exists():
                        cf = CollectedFile(
                            original_path=str(db_path),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="conversation_database" if db_file == "db.sqlite" else "conversation_database_wal",
                            size_bytes=db_path.stat().st_size,
                            sha256=self.calculate_hash(str(db_path)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                # Server logs (macOS)
                for log_file in app_support.glob("server.log*"):
                    cf = CollectedFile(
                        original_path=str(log_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="server_log",
                        size_bytes=log_file.stat().st_size,
                        sha256=self.calculate_hash(str(log_file)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

                # PID file
                pid_path = app_support / "ollama.pid"
                if pid_path.exists():
                    cf = CollectedFile(
                        original_path=str(pid_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="pid_file",
                        size_bytes=pid_path.stat().st_size,
                        sha256=self.calculate_hash(str(pid_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Ed25519 keypair
            for key_file in ["id_ed25519", "id_ed25519.pub"]:
                key_path = ollama_dir / key_file
                if key_path.exists():
                    cf = CollectedFile(
                        original_path=str(key_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="signing_key",
                        size_bytes=key_path.stat().st_size,
                        sha256=self.calculate_hash(str(key_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Model manifests
            manifests_dir = ollama_dir / "models" / "manifests"
            if manifests_dir.exists():
                for manifest in manifests_dir.rglob("*"):
                    if manifest.is_file():
                        cf = CollectedFile(
                            original_path=str(manifest),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="model_manifest",
                            size_bytes=manifest.stat().st_size,
                            sha256=self.calculate_hash(str(manifest)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

        # System-level Ollama (Linux)
        system_ollama = Path("/usr/share/ollama/.ollama")
        if system_ollama.exists():
            for key_file in ["id_ed25519", "id_ed25519.pub"]:
                key_path = system_ollama / key_file
                if key_path.exists():
                    cf = CollectedFile(
                        original_path=str(key_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="system_signing_key",
                        size_bytes=key_path.stat().st_size,
                        sha256=self.calculate_hash(str(key_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            sys_manifests = system_ollama / "models" / "manifests"
            if sys_manifests.exists():
                for manifest in sys_manifests.rglob("*"):
                    if manifest.is_file():
                        cf = CollectedFile(
                            original_path=str(manifest),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="system_model_manifest",
                            size_bytes=manifest.stat().st_size,
                            sha256=self.calculate_hash(str(manifest)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Ollama artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    if "api_key" in str(data).lower():
                        iocs.append({"type": "api_key_exposure", "detail": "API key found in Ollama config"})
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type in ("model_manifest", "system_model_manifest"):
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="model_manifest",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "cli_history":
                content = self.safe_read_file(cf.original_path)
                if content:
                    iocs = []
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            iocs.append({"type": "cli_command", "command": line})
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="cli_history",
                        severity=Severity.LOW,
                        data={"commands": [line.strip() for line in content.splitlines() if line.strip()]},
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

        return artifacts
