"""
Eigent forensic artifact collector for TRACE.

Eigent is an AI agent/assistant tool. Collects: config files
(yaml/json/toml), session/conversation logs, SQLite DBs, .env files,
and auth/token files.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class EigentCollector(BaseCollector):
    PLATFORM_NAME = "eigent"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = ["eigent"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.eigent",
        "~/.config/eigent",
    ]
    MACOS_PATHS = [
        "~/.eigent",
        "~/.config/eigent",
        "~/Library/Application Support/Eigent",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.eigent",
        "%APPDATA%\\Eigent",
    ]

    # Config file extensions to look for
    CONFIG_EXTENSIONS = (".yaml", ".yml", ".json", ".toml")

    def discover(self) -> bool:
        """Detect if Eigent is installed or has been used."""
        for home in self.get_user_home_dirs():
            os_name = self.detect_os()

            # ~/.eigent
            eigent_dir = home / ".eigent"
            if eigent_dir.exists():
                return True

            # ~/.config/eigent
            config_dir = home / ".config" / "eigent"
            if config_dir.exists():
                return True

            # macOS: ~/Library/Application Support/Eigent
            if os_name == "macos":
                app_support = home / "Library" / "Application Support" / "Eigent"
                if app_support.exists():
                    return True

            # Windows: %APPDATA%\Eigent
            if os_name == "windows":
                appdata = home / "AppData" / "Roaming" / "Eigent"
                if appdata.exists():
                    return True

        return False

    def _get_config_dirs(self, home: Path) -> list[Path]:
        """Get the Eigent config directories for a user home."""
        os_name = self.detect_os()
        dirs = [
            home / ".eigent",
            home / ".config" / "eigent",
        ]
        if os_name == "macos":
            dirs.append(home / "Library" / "Application Support" / "Eigent")
        elif os_name == "windows":
            dirs.append(home / "AppData" / "Roaming" / "Eigent")
        return dirs

    def collect(self) -> list[CollectedFile]:
        """Collect all Eigent forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            for config_dir in self._get_config_dirs(home):
                if config_dir.exists():
                    collected.extend(self._collect_config_dir(config_dir))

        return collected

    def _collect_config_dir(self, config_dir: Path) -> list[CollectedFile]:
        """Collect artifacts from an Eigent config directory."""
        collected = []

        # Config files (yaml/json/toml) at the root of the config dir
        for cfg in config_dir.iterdir():
            if not cfg.is_file():
                continue
            if cfg.suffix.lower() in self.CONFIG_EXTENSIONS:
                cf = CollectedFile(
                    original_path=str(cfg),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    size_bytes=cfg.stat().st_size,
                    sha256=self.calculate_hash(str(cfg)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        # .env files
        for env_file in config_dir.rglob(".env*"):
            if not env_file.is_file():
                continue
            cf = CollectedFile(
                original_path=str(env_file),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="env_file",
                size_bytes=env_file.stat().st_size,
                sha256=self.calculate_hash(str(env_file)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # Auth/token files
        for token_file in config_dir.rglob("*token*"):
            if not token_file.is_file():
                continue
            cf = CollectedFile(
                original_path=str(token_file),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="auth_token",
                size_bytes=token_file.stat().st_size,
                sha256=self.calculate_hash(str(token_file)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # SQLite databases
        for db_file in config_dir.rglob("*.sqlite"):
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

        for db_file in config_dir.rglob("*.db"):
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

        # Session/conversation logs (jsonl, log, txt)
        for log_file in config_dir.rglob("*.jsonl"):
            if not log_file.is_file():
                continue
            cf = CollectedFile(
                original_path=str(log_file),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="session_log",
                size_bytes=log_file.stat().st_size,
                sha256=self.calculate_hash(str(log_file)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        for log_file in config_dir.rglob("*.log"):
            if not log_file.is_file():
                continue
            cf = CollectedFile(
                original_path=str(log_file),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="session_log",
                size_bytes=log_file.stat().st_size,
                sha256=self.calculate_hash(str(log_file)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        return collected

    def _redact_secret(self, value: str) -> str:
        """Redact a secret, keeping only the first 4 and last 4 chars."""
        value = value.strip()
        if len(value) <= 8:
            return "****"
        return f"{value[:4]}...{value[-4:]}"

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Eigent artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    config_str = str(data)
                    if "api_key" in config_str.lower():
                        iocs.append({
                            "type": "api_key_in_config",
                            "detail": "API key found in Eigent config",
                        })
                    if "token" in config_str.lower():
                        iocs.append({
                            "type": "auth_token_in_config",
                            "detail": "Authentication token found in Eigent config",
                        })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))
                else:
                    # Non-JSON config (yaml/toml) — read as text
                    content = self.safe_read_file(cf.original_path)
                    if content:
                        iocs = []
                        content_lower = content.lower()
                        if "api_key" in content_lower or "apikey" in content_lower:
                            iocs.append({
                                "type": "api_key_in_config",
                                "detail": "API key found in Eigent config",
                            })
                        if "token" in content_lower:
                            iocs.append({
                                "type": "auth_token_in_config",
                                "detail": "Authentication token found in Eigent config",
                            })

                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="config",
                            severity=Severity.HIGH if iocs else Severity.INFO,
                            data={
                                "content_preview": content[:2000],
                                "full_length": len(content),
                                "path": cf.original_path,
                            },
                            source_file=cf.original_path,
                            iocs=iocs,
                        ))

            elif cf.artifact_type == "session_log":
                content = self.safe_read_file(cf.original_path)
                if content:
                    # Extract commands and timestamps from session logs
                    commands = []
                    timestamps = []
                    for line in content.splitlines():
                        if "command" in line.lower() or line.strip().startswith("$"):
                            commands.append(line.strip()[:500])
                        # Heuristic: look for ISO timestamps
                        if "T" in line and ":" in line:
                            for token in line.split():
                                if len(token) >= 19 and token[4] == "-" and token[10] == "T":
                                    timestamps.append(token)
                                    break

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_log",
                        severity=Severity.MEDIUM,
                        data={
                            "note": "Eigent session/conversation log",
                            "filename": Path(cf.original_path).name,
                            "size_bytes": cf.size_bytes,
                            "command_count": len(commands),
                            "commands_preview": commands[:50],
                            "timestamps_preview": timestamps[:20],
                        },
                        source_file=cf.original_path,
                        mitre_atlas=["AML.T0048"],
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

            elif cf.artifact_type == "env_file":
                content = self.safe_read_file(cf.original_path)
                if content:
                    # Redact secrets in .env files
                    redacted_lines = []
                    secret_keys = []
                    for line in content.splitlines():
                        if "=" in line and not line.strip().startswith("#"):
                            key, _, value = line.partition("=")
                            key = key.strip()
                            value = value.strip()
                            if any(k in key.lower() for k in
                                   ["key", "token", "secret", "password", "credential", "auth"]):
                                secret_keys.append(key)
                                redacted_lines.append(f"{key}={self._redact_secret(value)}")
                            else:
                                redacted_lines.append(line)
                        else:
                            redacted_lines.append(line)

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="env_file",
                        severity=Severity.CRITICAL if secret_keys else Severity.INFO,
                        data={
                            "note": "Environment file (secrets redacted)",
                            "filename": Path(cf.original_path).name,
                            "secret_keys": secret_keys,
                            "redacted_content": "\n".join(redacted_lines),
                        },
                        source_file=cf.original_path,
                        iocs=[{
                            "type": "env_secret_found",
                            "detail": f"Secret keys found in .env: {', '.join(secret_keys)}",
                        }] if secret_keys else [],
                    ))

            elif cf.artifact_type == "auth_token":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="auth_token",
                        severity=Severity.HIGH,
                        data={
                            "note": "Authentication token file found (contents redacted)",
                            "filename": Path(cf.original_path).name,
                            "token_preview": self._redact_secret(content.strip()[:64]),
                        },
                        source_file=cf.original_path,
                        iocs=[{
                            "type": "auth_token_file",
                            "filename": Path(cf.original_path).name,
                        }],
                        mitre_atlas=["AML.T0055"],
                    ))

        return artifacts
