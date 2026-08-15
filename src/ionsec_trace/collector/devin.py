"""
Devin Desktop forensic artifact collector for TRACE.

Devin is Cognition's autonomous AI software engineer (Devin Desktop app).
Collects: config (yaml/json/toml), session/conversation logs, SQLite DBs,
.env files, and auth/token files.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class DevinCollector(BaseCollector):
    PLATFORM_NAME = "devin"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = ["devin", "Devin"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.devin",
        "~/.config/devin",
    ]
    MACOS_PATHS = [
        "~/Library/Application Support/Devin",
    ]
    WINDOWS_PATHS = [
        "%APPDATA%\\Devin",
    ]

    # Config file names to look for in the config directory
    CONFIG_FILENAMES = [
        "config.json",
        "config.yaml",
        "config.yml",
        "config.toml",
        "settings.json",
        "settings.yaml",
        "settings.toml",
    ]

    # Auth/token file names
    AUTH_FILENAMES = [
        "auth.json",
        "auth.yaml",
        "auth.toml",
        "credentials.json",
        "token.json",
        "tokens.json",
        "tokens.yaml",
        "tokens.toml",
    ]

    def discover(self) -> bool:
        """Detect if Devin Desktop is installed or has been used."""
        for home in self.get_user_home_dirs():
            os_name = self.detect_os()

            # Linux: ~/.devin or ~/.config/devin
            if (home / ".devin").exists():
                return True
            if (home / ".config" / "devin").exists():
                return True

            # macOS: ~/Library/Application Support/Devin
            if os_name == "macos":
                app_support = home / "Library" / "Application Support" / "Devin"
                if app_support.exists():
                    return True

            # Windows: %APPDATA%\Devin
            if os_name == "windows":
                appdata = home / "AppData" / "Roaming" / "Devin"
                if appdata.exists():
                    return True

        return False

    def _get_config_dir(self, home: Path) -> Path | None:
        """Get the Devin config directory for a user home."""
        os_name = self.detect_os()
        if os_name == "linux":
            # Prefer ~/.devin, fall back to ~/.config/devin
            if (home / ".devin").exists():
                return home / ".devin"
            return home / ".config" / "devin"
        elif os_name == "macos":
            return home / "Library" / "Application Support" / "Devin"
        elif os_name == "windows":
            return home / "AppData" / "Roaming" / "Devin"
        return None

    def collect(self) -> list[CollectedFile]:
        """Collect all Devin Desktop forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            config_dir = self._get_config_dir(home)
            if config_dir and config_dir.exists():
                collected.extend(self._collect_config_dir(config_dir))

        return collected

    def _collect_config_dir(self, config_dir: Path) -> list[CollectedFile]:
        """Collect artifacts from the Devin config directory."""
        collected = []

        # Config files (yaml/json/toml)
        for filename in self.CONFIG_FILENAMES:
            config_path = config_dir / filename
            if config_path.exists() and config_path.is_file():
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

        # Auth/token files
        for filename in self.AUTH_FILENAMES:
            auth_path = config_dir / filename
            if auth_path.exists() and auth_path.is_file():
                cf = CollectedFile(
                    original_path=str(auth_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="auth",
                    size_bytes=auth_path.stat().st_size,
                    sha256=self.calculate_hash(str(auth_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        # .env files
        env_path = config_dir / ".env"
        if env_path.exists() and env_path.is_file():
            cf = CollectedFile(
                original_path=str(env_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="env",
                size_bytes=env_path.stat().st_size,
                sha256=self.calculate_hash(str(env_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # Session/conversation logs
        for logs_dir_name in ("logs", "sessions", "conversations", "session_logs"):
            logs_dir = config_dir / logs_dir_name
            if logs_dir.exists() and logs_dir.is_dir():
                for log_file in logs_dir.rglob("*"):
                    if not log_file.is_file():
                        continue
                    if log_file.suffix.lower() in (".log", ".jsonl", ".json", ".txt", ".yaml", ".yml", ".toml"):
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

        return collected

    def _redact_secret(self, value: str) -> str:
        """Redact a secret, keeping only the first and last 4 characters."""
        if not value:
            return value
        if len(value) <= 8:
            return "****"
        return f"{value[:4]}...{value[-4:]}"

    def _redact_env_content(self, content: str) -> str:
        """Redact secret values in .env file content."""
        redacted_lines = []
        for line in content.splitlines():
            if "=" in line and not line.strip().startswith("#"):
                key, _, value = line.partition("=")
                key = key.strip()
                if any(k in key.lower() for k in ("key", "token", "secret", "password", "auth")):
                    redacted_lines.append(f"{key}={self._redact_secret(value.strip())}")
                    continue
            redacted_lines.append(line)
        return "\n".join(redacted_lines)

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Devin Desktop artifacts."""
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
                            "detail": "API key found in Devin config",
                        })
                    if "token" in config_str.lower():
                        iocs.append({
                            "type": "auth_token_in_config",
                            "detail": "Authentication token found in Devin config",
                        })

                    # Redact secret values
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

            elif cf.artifact_type == "auth":
                # Auth/token files are high value — note but redact content
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="auth",
                    severity=Severity.HIGH,
                    data={
                        "note": "Authentication/token file found (contents redacted)",
                        "filename": Path(cf.original_path).name,
                    },
                    source_file=cf.original_path,
                    iocs=[{
                        "type": "auth_credential_file",
                        "filename": Path(cf.original_path).name,
                    }],
                    mitre_atlas=["AML.T0055"],
                ))

            elif cf.artifact_type == "env":
                content = self.safe_read_file(cf.original_path)
                if content:
                    redacted = self._redact_env_content(content)
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="env",
                        severity=Severity.CRITICAL,
                        data={
                            "note": ".env file found containing potential secrets (redacted)",
                            "content_preview": redacted[:2000],
                            "full_length": len(content),
                            "path": cf.original_path,
                        },
                        source_file=cf.original_path,
                        iocs=[{
                            "type": "env_secrets_found",
                            "detail": "Secrets found in .env file",
                            "file": cf.original_path,
                        }],
                        mitre_atlas=["AML.T0055"],
                    ))

            elif cf.artifact_type == "session_log":
                content = self.safe_read_file(cf.original_path)
                if content:
                    iocs = []
                    content_lower = content.lower()

                    # Extract commands and timestamps from session logs
                    commands = []
                    for line in content.splitlines():
                        stripped = line.strip()
                        if stripped.startswith(("$ ", "> ", "cmd:", "command:")):
                            commands.append(stripped[:500])

                    for keyword in ["api_key", "token", "secret", "password", "credential"]:
                        if keyword in content_lower:
                            iocs.append({
                                "type": "sensitive_keyword_in_session",
                                "detail": f"'{keyword}' referenced in Devin session log",
                                "file": cf.original_path,
                            })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_log",
                        severity=Severity.MEDIUM if iocs else Severity.LOW,
                        data={
                            "note": "Devin session/conversation log",
                            "commands_extracted": commands[:100],
                            "content_preview": content[:2000],
                            "full_length": len(content),
                            "path": cf.original_path,
                        },
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0048"],
                    ))

            elif cf.artifact_type == "conversation_database":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_database",
                    severity=Severity.MEDIUM,
                    data={
                        "note": "SQLite DB containing Devin conversation data",
                        "filename": Path(cf.original_path).name,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0048"],
                ))

        return artifacts
