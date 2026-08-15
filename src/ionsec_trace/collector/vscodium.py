"""
VSCodium forensic artifact collector for TRACE.

VSCodium is the open-source (MIT) build of VS Code without Microsoft
branding or telemetry. Collects: settings, keybindings, globalStorage
SQLite DBs (state.vscdb, conversation DBs), workspace storage,
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


class VSCodiumCollector(BaseCollector):
    PLATFORM_NAME = "vscodium"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["codium", "VSCodium"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.config/VSCodium",
    ]
    MACOS_PATHS = [
        "~/Library/Application Support/VSCodium",
    ]
    WINDOWS_PATHS = [
        "%APPDATA%\\VSCodium",
    ]

    def discover(self) -> bool:
        """Detect if VSCodium editor is installed or has been used."""
        for home in self.get_user_home_dirs():
            os_name = self.detect_os()

            # Linux: ~/.config/VSCodium
            config_dir = home / ".config" / "VSCodium"
            if config_dir.exists():
                return True

            # macOS: ~/Library/Application Support/VSCodium
            if os_name == "macos":
                app_support = home / "Library" / "Application Support" / "VSCodium"
                if app_support.exists():
                    return True

            # Windows: %APPDATA%\VSCodium
            if os_name == "windows":
                appdata = home / "AppData" / "Roaming" / "VSCodium"
                if appdata.exists():
                    return True

        return False

    def _get_config_dir(self, home: Path) -> Path | None:
        """Get the VSCodium config directory for a user home."""
        os_name = self.detect_os()
        if os_name == "linux":
            return home / ".config" / "VSCodium"
        elif os_name == "macos":
            return home / "Library" / "Application Support" / "VSCodium"
        elif os_name == "windows":
            return home / "AppData" / "Roaming" / "VSCodium"
        return None

    def collect(self) -> list[CollectedFile]:
        """Collect all VSCodium forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            config_dir = self._get_config_dir(home)
            if config_dir and config_dir.exists():
                collected.extend(self._collect_config_dir(config_dir))

        return collected

    def _collect_config_dir(self, config_dir: Path) -> list[CollectedFile]:
        """Collect artifacts from the VSCodium config directory."""
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

            # state.vscdb in globalStorage
            for state_db in global_storage.rglob("state.vscdb"):
                if not state_db.is_file():
                    continue
                cf = CollectedFile(
                    original_path=str(state_db),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="workspace_state",
                    size_bytes=state_db.stat().st_size,
                    sha256=self.calculate_hash(str(state_db)),
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

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected VSCodium artifacts."""
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
                            "detail": "API key found in VSCodium settings",
                        })
                    if "token" in config_str.lower():
                        iocs.append({
                            "type": "auth_token_in_config",
                            "detail": "Authentication token found in VSCodium settings",
                        })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=data,
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
                                "detail": f"'{keyword}' referenced in VSCodium log",
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
