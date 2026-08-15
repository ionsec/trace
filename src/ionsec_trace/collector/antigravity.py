"""
Antigravity forensic artifact collector for TRACE.

Antigravity is Google's AI IDE (formerly Jules). Collects: settings,
keybindings, globalStorage (SQLite conversation DBs), workspace storage,
logs, machine id, and storage.json.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class AntigravityCollector(BaseCollector):
    PLATFORM_NAME = "antigravity"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["antigravity", "Antigravity"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.antigravity",
        "~/.config/Antigravity",
    ]
    MACOS_PATHS = [
        "~/Library/Application Support/Antigravity",
    ]
    WINDOWS_PATHS = [
        "%APPDATA%\\Antigravity",
    ]

    def discover(self) -> bool:
        """Detect if Antigravity IDE is installed or has been used."""
        for home in self.get_user_home_dirs():
            os_name = self.detect_os()

            # Linux: ~/.antigravity or ~/.config/Antigravity
            if (home / ".antigravity").exists():
                return True
            if (home / ".config" / "Antigravity").exists():
                return True

            # macOS: ~/Library/Application Support/Antigravity
            if os_name == "macos":
                app_support = home / "Library" / "Application Support" / "Antigravity"
                if app_support.exists():
                    return True

            # Windows: %APPDATA%\Antigravity
            if os_name == "windows":
                appdata = home / "AppData" / "Roaming" / "Antigravity"
                if appdata.exists():
                    return True

        return False

    def _get_config_dir(self, home: Path) -> Path | None:
        """Get the Antigravity config directory for a user home."""
        os_name = self.detect_os()
        if os_name == "linux":
            # Prefer ~/.antigravity, fall back to ~/.config/Antigravity
            if (home / ".antigravity").exists():
                return home / ".antigravity"
            return home / ".config" / "Antigravity"
        elif os_name == "macos":
            return home / "Library" / "Application Support" / "Antigravity"
        elif os_name == "windows":
            return home / "AppData" / "Roaming" / "Antigravity"
        return None

    def collect(self) -> list[CollectedFile]:
        """Collect all Antigravity forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            config_dir = self._get_config_dir(home)
            if config_dir and config_dir.exists():
                collected.extend(self._collect_config_dir(config_dir))

        return collected

    def _collect_config_dir(self, config_dir: Path) -> list[CollectedFile]:
        """Collect artifacts from the Antigravity config directory."""
        collected = []

        # Settings
        settings_path = config_dir / "settings.json"
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

        # Keybindings
        keybindings_path = config_dir / "keybindings.json"
        if keybindings_path.exists():
            cf = CollectedFile(
                original_path=str(keybindings_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="config",
                size_bytes=keybindings_path.stat().st_size,
                sha256=self.calculate_hash(str(keybindings_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # globalStorage — contains SQLite DBs with AI conversation data
        global_storage = config_dir / "User" / "globalStorage"
        if global_storage.exists():
            for db_file in global_storage.rglob("*.sqlite"):
                if not db_file.is_file():
                    continue
                cf = CollectedFile(
                    original_path=str(db_file),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_database",
                    size_bytes=db_file.stat().st_size,
                    sha256=self.calculate_hash(str(db_file)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            for db_file in global_storage.rglob("*.sqlite-wal"):
                if not db_file.is_file():
                    continue
                cf = CollectedFile(
                    original_path=str(db_file),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_database_wal",
                    size_bytes=db_file.stat().st_size,
                    sha256=self.calculate_hash(str(db_file)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            for db_file in global_storage.rglob("*.sqlite-shm"):
                if not db_file.is_file():
                    continue
                cf = CollectedFile(
                    original_path=str(db_file),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_database_shm",
                    size_bytes=db_file.stat().st_size,
                    sha256=self.calculate_hash(str(db_file)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # JSON state files in globalStorage
            for state_json in global_storage.rglob("state.vscdb"):
                if state_json.is_file():
                    cf = CollectedFile(
                        original_path=str(state_json),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="workspace_state",
                        size_bytes=state_json.stat().st_size,
                        sha256=self.calculate_hash(str(state_json)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        # Workspace storage
        workspace_storage = config_dir / "User" / "workspaceStorage"
        if workspace_storage.exists():
            for ws_dir in workspace_storage.iterdir():
                if ws_dir.is_dir():
                    ws_state = ws_dir / "state.vscdb"
                    if ws_state.exists():
                        cf = CollectedFile(
                            original_path=str(ws_state),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="workspace_state",
                            size_bytes=ws_state.stat().st_size,
                            sha256=self.calculate_hash(str(ws_state)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                    # workspace.json in each workspace folder
                    ws_json = ws_dir / "workspace.json"
                    if ws_json.exists():
                        cf = CollectedFile(
                            original_path=str(ws_json),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="workspace_config",
                            size_bytes=ws_json.stat().st_size,
                            sha256=self.calculate_hash(str(ws_json)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

        # Logs
        logs_dir = config_dir / "logs"
        if logs_dir.exists():
            for log_file in logs_dir.rglob("*.log"):
                if not log_file.is_file():
                    continue
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

        # Machine ID
        machine_id_path = config_dir / "machineId"
        if machine_id_path.exists():
            cf = CollectedFile(
                original_path=str(machine_id_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="machine_id",
                size_bytes=machine_id_path.stat().st_size,
                sha256=self.calculate_hash(str(machine_id_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # Storage JSON
        storage_path = config_dir / "storage.json"
        if storage_path.exists():
            cf = CollectedFile(
                original_path=str(storage_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="storage",
                size_bytes=storage_path.stat().st_size,
                sha256=self.calculate_hash(str(storage_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        return collected

    def _redact_secret(self, value: str) -> str:
        """Redact a secret, keeping only the first and last 4 characters."""
        if not value:
            return value
        if len(value) <= 8:
            return "****"
        return f"{value[:4]}...{value[-4:]}"

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Antigravity artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    config_str = str(data)

                    # Check for sensitive settings
                    if "api_key" in config_str.lower():
                        iocs.append({
                            "type": "api_key_in_config",
                            "detail": "API key found in Antigravity settings",
                        })
                    if "token" in config_str.lower():
                        iocs.append({
                            "type": "auth_token_in_config",
                            "detail": "Authentication token found in Antigravity settings",
                        })

                    # Redact any secret values found in the config
                    redacted = {}
                    for key, value in data.items():
                        if isinstance(value, str) and any(
                            k in key.lower() for k in ("api_key", "token", "secret", "password")
                        ):
                            redacted[key] = self._redact_secret(value)
                        else:
                            redacted[key] = value

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=redacted,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "conversation_database":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_database",
                    severity=Severity.MEDIUM,
                    data={
                        "note": "SQLite DB containing AI conversation data",
                        "filename": Path(cf.original_path).name,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0048"],
                ))

            elif cf.artifact_type == "workspace_state":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="workspace_state",
                    severity=Severity.INFO,
                    data={
                        "note": "Workspace state database",
                        "filename": Path(cf.original_path).name,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                ))

            elif cf.artifact_type == "workspace_config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="workspace_config",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "log":
                content = self.safe_read_file(cf.original_path)
                if content:
                    iocs = []
                    content_lower = content.lower()
                    for keyword in ["api_key", "token", "secret", "password", "credential"]:
                        if keyword in content_lower:
                            iocs.append({
                                "type": "sensitive_keyword_in_log",
                                "detail": f"'{keyword}' referenced in Antigravity log",
                                "file": cf.original_path,
                            })
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="log",
                        severity=Severity.MEDIUM if iocs else Severity.LOW,
                        data={
                            "content_preview": content[:2000],
                            "full_length": len(content),
                            "path": cf.original_path,
                        },
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "machine_id":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="machine_id",
                        severity=Severity.LOW,
                        data={"machine_id": content.strip()},
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "storage":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="storage",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

        return artifacts
