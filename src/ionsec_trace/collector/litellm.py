"""
LiteLLM forensic artifact collector for TRACE.

Collects: config YAML/JSON, SQLite request/response logs, .env files,
proxy logs, and model routing configuration.
"""

import os
import re
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class LiteLLMCollector(BaseCollector):
    PLATFORM_NAME = "litellm"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["litellm"]
    SERVICE_PORTS = [4000]

    LINUX_PATHS = [
        "~/.litellm",
        "/etc/litellm",
    ]
    MACOS_PATHS = [
        "~/.litellm",
        "/etc/litellm",
        "~/Library/Application Support/litellm",
    ]
    WINDOWS_PATHS = [
        "%APPDATA%\\litellm",
        "%PROGRAMDATA%\\litellm",
    ]

    # ── Discover ──────────────────────────────────────────────

    def discover(self) -> bool:
        """Detect if LiteLLM is installed or has been used."""
        import shutil

        # Check for litellm binary
        if shutil.which("litellm"):
            return True

        # Check for litellm process running
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-f", "litellm"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        # Check for config files in common locations
        for home in self.get_user_home_dirs():
            if (home / ".litellm").exists():
                return True

        # Check system-level config paths
        system_paths = self._get_system_paths()
        for p in system_paths:
            if Path(p).expanduser().exists():
                return True

        # Check current directory for litellm config
        return bool(Path("litellm_config.yaml").exists() or Path("litellm_config.yml").exists())

    def _get_system_paths(self) -> list[str]:
        """Return OS-appropriate system-level paths."""
        system = self.detect_os()
        paths = []
        if system == "linux":
            paths = self.LINUX_PATHS
        elif system == "macos":
            paths = self.MACOS_PATHS
        elif system == "windows":
            paths = self.WINDOWS_PATHS
        return paths

    # ── Collect ───────────────────────────────────────────────

    def collect(self) -> list[CollectedFile]:
        """Collect all LiteLLM forensic artifacts."""
        collected = []

        # ── User-level paths ─────────────────────────────────
        for home in self.get_user_home_dirs():
            litellm_dir = home / ".litellm"
            if litellm_dir.exists():
                collected.extend(self._collect_dir(litellm_dir))

            # macOS Application Support
            if self.detect_os() == "macos":
                app_support = home / "Library" / "Application Support" / "litellm"
                if app_support.exists():
                    collected.extend(self._collect_dir(app_support))

        # ── System-level paths ────────────────────────────────
        system_paths = self._get_system_paths()
        for sp in system_paths:
            p = Path(sp).expanduser()
            if p.exists():
                collected.extend(self._collect_dir(p))

        # ── Windows paths with env var expansion ──────────────
        if self.detect_os() == "windows":
            for wp in self.WINDOWS_PATHS:
                expanded = Path(os.path.expandvars(wp))
                if expanded.exists():
                    collected.extend(self._collect_dir(expanded))

        # ── Current directory config ──────────────────────────
        for name in ["litellm_config.yaml", "litellm_config.yml", "litellm_config.json"]:
            cfg = Path(name)
            if cfg.exists():
                cf = CollectedFile(
                    original_path=str(cfg.resolve()),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    size_bytes=cfg.stat().st_size,
                    sha256=self.calculate_hash(str(cfg.resolve())),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        # ── .env files in current and common directories ───────
        env_dirs = [Path("."), Path.home()]
        for env_dir in env_dirs:
            env_path = env_dir / ".env"
            if env_path.exists():
                cf = CollectedFile(
                    original_path=str(env_path.resolve()),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="credential",
                    size_bytes=env_path.stat().st_size,
                    sha256=self.calculate_hash(str(env_path.resolve())),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        return collected

    def _collect_dir(self, directory: Path) -> list[CollectedFile]:
        """Collect all relevant files from a LiteLLM directory."""
        collected = []

        # Config files
        for pattern in ["*.yaml", "*.yml", "*.json", "*.toml"]:
            for f in directory.glob(pattern):
                if f.is_file():
                    artifact_type = "config"
                    if "log" in f.name.lower():
                        artifact_type = "log"
                    elif "route" in f.name.lower() or "routing" in f.name.lower():
                        artifact_type = "model_routing_config"
                    cf = CollectedFile(
                        original_path=str(f),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type=artifact_type,
                        size_bytes=f.stat().st_size,
                        sha256=self.calculate_hash(str(f)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        # SQLite databases
        for db_pattern in ["*.db", "*.sqlite", "*.sqlite3"]:
            for f in directory.glob(db_pattern):
                if f.is_file():
                    artifact_type = "request_database"
                    if "log" in f.name.lower():
                        artifact_type = "request_database"
                    cf = CollectedFile(
                        original_path=str(f),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type=artifact_type,
                        size_bytes=f.stat().st_size,
                        sha256=self.calculate_hash(str(f)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        # Log files
        for f in directory.glob("*.log*"):
            if f.is_file():
                cf = CollectedFile(
                    original_path=str(f),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="proxy_log",
                    size_bytes=f.stat().st_size,
                    sha256=self.calculate_hash(str(f)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        # .env files
        env_path = directory / ".env"
        if env_path.is_file():
            cf = CollectedFile(
                original_path=str(env_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="credential",
                size_bytes=env_path.stat().st_size,
                sha256=self.calculate_hash(str(env_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        return collected

    # ── Parse ─────────────────────────────────────────────────

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected LiteLLM artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                artifacts.extend(self._parse_config(cf))
            elif cf.artifact_type == "request_database":
                artifacts.extend(self._parse_sqlite(cf))
            elif cf.artifact_type == "credential":
                artifacts.extend(self._parse_env(cf))
            elif cf.artifact_type == "proxy_log":
                artifacts.extend(self._parse_log(cf))
            elif cf.artifact_type == "model_routing_config":
                artifacts.extend(self._parse_config(cf))

        return artifacts

    def _parse_config(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse YAML/JSON config files."""
        content = self.safe_read_file(cf.original_path)
        if not content:
            return []

        iocs = []
        data = {"raw": content}

        # Extract API keys (redacted)
        key_patterns = [
            (r'(?:api_key|apikey|api-key)\s*[:=]\s*["\']?([\w\-]{8,})["\']?', "api_key"),
            (r'(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_API_KEY|AWS_ACCESS_KEY_ID)\s*[:=]\s*["\']?([\w\-/+=]{8,})["\']?', "env_api_key"),
        ]
        for pattern, ioc_type in key_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                key_val = match.group(1)
                iocs.append({
                    "type": ioc_type,
                    "detail": f"API key found in {cf.original_path}",
                    "value_redacted": key_val[:4] + "..." + key_val[-4:],
                })

        # Extract model names
        model_matches = re.findall(
            r'(?:model_name|model)\s*[:=]\s*["\']?([a-zA-Z0-9_./\-]+)["\']?',
            content, re.IGNORECASE,
        )
        if model_matches:
            data["models_configured"] = list(set(model_matches))

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="config",
            severity=Severity.HIGH if iocs else Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]

    def _parse_sqlite(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse SQLite databases for request/response logs."""
        artifacts = []
        try:
            import sqlite3

            conn = sqlite3.connect(cf.original_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                try:
                    # Count rows
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    count = cursor.fetchone()[0]
                    if count == 0:
                        continue

                    # Get columns
                    cursor.execute(f"PRAGMA table_info([{table}])")
                    columns = [row[1] for row in cursor.fetchall()]

                    data = {
                        "database": cf.original_path,
                        "table": table,
                        "row_count": count,
                        "columns": columns,
                    }

                    iocs = []

                    # Extract model usage stats if columns exist
                    model_col = next((c for c in columns if "model" in c.lower()), None)
                    if model_col:
                        cursor.execute(f"SELECT [{model_col}], COUNT(*) FROM [{table}] GROUP BY [{model_col}] ORDER BY COUNT(*) DESC LIMIT 20")
                        model_usage = dict(cursor.fetchall())
                        data["model_usage"] = model_usage

                    # Extract error patterns if status/error columns exist
                    error_col = next((c for c in columns if "status" in c.lower() or "error" in c.lower()), None)
                    if error_col:
                        cursor.execute(f"SELECT [{error_col}], COUNT(*) FROM [{table}] GROUP BY [{error_col}] ORDER BY COUNT(*) DESC LIMIT 20")
                        error_patterns = dict(cursor.fetchall())
                        data["error_patterns"] = error_patterns

                    # Check for API keys in the data
                    for col in columns:
                        try:
                            cursor.execute(f"SELECT [{col}] FROM [{table}] LIMIT 100")
                            for row in cursor.fetchall():
                                val = str(row[0]) if row[0] else ""
                                if re.search(r"sk-[a-zA-Z0-9]{20,}", val):
                                    iocs.append({
                                        "type": "api_key_in_database",
                                        "detail": f"OpenAI-style API key found in column '{col}'",
                                    })
                                    break
                        except Exception:
                            continue

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="request_database",
                        severity=Severity.HIGH if iocs else Severity.MEDIUM,
                        data=data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))
                except Exception:
                    continue

            conn.close()
        except Exception:
            # If we can't parse the database, just note it exists
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="request_database",
                severity=Severity.LOW,
                data={"note": "Could not parse database", "path": cf.original_path},
                source_file=cf.original_path,
            ))

        return artifacts

    def _parse_env(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse .env files for credential exposure."""
        content = self.safe_read_file(cf.original_path)
        if not content:
            return []

        iocs = []
        env_keys = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                env_keys.append(key)

                # Redact sensitive values
                sensitive_keywords = ["key", "secret", "token", "password", "credential"]
                if any(kw in key.lower() for kw in sensitive_keywords):
                    redacted = value[:4] + "..." + value[-4:] if len(value) > 8 else "***REDACTED***"
                    iocs.append({
                        "type": "env_secret",
                        "detail": f"Sensitive environment variable: {key}",
                        "value_redacted": redacted,
                    })

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="credential",
            severity=Severity.CRITICAL if iocs else Severity.MEDIUM,
            data={"env_keys": env_keys, "sensitive_count": len(iocs)},
            source_file=cf.original_path,
            iocs=iocs,
        )]

    def _parse_log(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse proxy log files for request metadata and error patterns."""
        content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
        if not content:
            return []

        iocs = []
        data = {"path": cf.original_path}

        # Count request types
        error_count = len(re.findall(r"(?i)error|exception|fail|timeout", content))
        data["error_line_count"] = error_count

        # Extract model names from log lines
        models = set(re.findall(
            r'model["\s:=]+([a-zA-Z0-9_./\-]+)',
            content,
        ))
        if models:
            data["models_seen"] = list(models)

        # Extract API key patterns
        api_key_matches = re.findall(r"sk-[a-zA-Z0-9]{20,}", content)
        if api_key_matches:
            for key in set(api_key_matches):
                iocs.append({
                    "type": "api_key_in_log",
                    "detail": "API key found in proxy log",
                    "value_redacted": key[:4] + "..." + key[-4:],
                })

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="proxy_log",
            severity=Severity.HIGH if iocs else Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]
