"""
Bifrost forensic artifact collector for TRACE.

Collects: config YAML/JSON, request logs, routing tables,
cached responses, and SQLite/JSON databases.
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


class BifrostCollector(BaseCollector):
    PLATFORM_NAME = "bifrost"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["bifrost"]
    SERVICE_PORTS = [8080, 8443]

    LINUX_PATHS = [
        "~/.bifrost",
        "/etc/bifrost",
        "/var/lib/bifrost",
    ]
    MACOS_PATHS = [
        "~/.bifrost",
        "/etc/bifrost",
        "/var/lib/bifrost",
        "~/Library/Application Support/bifrost",
    ]
    WINDOWS_PATHS = [
        "%APPDATA%\\bifrost",
        "%PROGRAMDATA%\\bifrost",
    ]

    # ── Discover ──────────────────────────────────────────────

    def discover(self) -> bool:
        """Detect if Bifrost is installed or has been used."""
        import shutil

        # Check for bifrost binary
        if shutil.which("bifrost"):
            return True

        # Check for bifrost process running
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-f", "bifrost"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        # Check for config/data directories
        for home in self.get_user_home_dirs():
            if (home / ".bifrost").exists():
                return True

        # Check system-level paths
        system_paths = self._get_system_paths()
        for sp in system_paths:
            if Path(sp).expanduser().exists():
                return True

        # Windows env-var paths
        if self.detect_os() == "windows":
            for wp in self.WINDOWS_PATHS:
                expanded = Path(os.path.expandvars(wp))
                if expanded.exists():
                    return True

        return False

    def _get_system_paths(self) -> list[str]:
        """Return OS-appropriate system-level paths."""
        return {
            "linux": self.LINUX_PATHS,
            "macos": self.MACOS_PATHS,
            "windows": self.WINDOWS_PATHS,
        }.get(self.detect_os(), [])

    # ── Collect ───────────────────────────────────────────────

    def collect(self) -> list[CollectedFile]:
        """Collect all Bifrost forensic artifacts."""
        collected = []

        # ── User-level paths ─────────────────────────────────
        for home in self.get_user_home_dirs():
            bifrost_dir = home / ".bifrost"
            if bifrost_dir.exists():
                collected.extend(self._collect_dir(bifrost_dir))

            # macOS Application Support
            if self.detect_os() == "macos":
                app_support = home / "Library" / "Application Support" / "bifrost"
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

        return collected

    def _collect_dir(self, directory: Path) -> list[CollectedFile]:
        """Collect all relevant files from a Bifrost directory."""
        collected = []

        # Config files
        for pattern in ["*.yaml", "*.yml", "*.json", "*.toml"]:
            for f in directory.glob(pattern):
                if f.is_file():
                    artifact_type = "config"
                    name_lower = f.name.lower()
                    if "route" in name_lower or "routing" in name_lower:
                        artifact_type = "routing_table"
                    elif "log" in name_lower:
                        artifact_type = "request_log"
                    elif "cache" in name_lower:
                        artifact_type = "cached_response"
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

        # Recurse into subdirectories for config files (one level deep)
        for subdir in directory.iterdir():
            if subdir.is_dir() and not subdir.name.startswith("."):
                for pattern in ["*.yaml", "*.yml", "*.json"]:
                    for f in subdir.glob(pattern):
                        if f.is_file():
                            artifact_type = "config"
                            name_lower = f.name.lower()
                            if "route" in name_lower or "routing" in name_lower:
                                artifact_type = "routing_table"
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
                    cf = CollectedFile(
                        original_path=str(f),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="database",
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
                    artifact_type="request_log",
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
        """Parse collected Bifrost artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                artifacts.extend(self._parse_config(cf))
            elif cf.artifact_type == "routing_table":
                artifacts.extend(self._parse_routing(cf))
            elif cf.artifact_type == "database":
                artifacts.extend(self._parse_database(cf))
            elif cf.artifact_type == "credential":
                artifacts.extend(self._parse_env(cf))
            elif cf.artifact_type in ("log", "request_log"):
                artifacts.extend(self._parse_log(cf))
            elif cf.artifact_type == "cached_response":
                artifacts.extend(self._parse_cached_response(cf))

        return artifacts

    def _parse_config(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse YAML/JSON config files."""
        content = self.safe_read_file(cf.original_path)
        if not content:
            return []

        iocs = []
        data = {"raw": content}

        # Extract routing rules / model mappings
        model_matches = re.findall(
            r'(?:model_name|model|upstream_model)\s*[:=]\s*["\']?([a-zA-Z0-9_./\-]+)["\']?',
            content, re.IGNORECASE,
        )
        if model_matches:
            data["models_configured"] = list(set(model_matches))

        # Extract API keys (redacted)
        key_patterns = [
            (r'(?:api_key|apikey|api-key|key)\s*[:=]\s*["\']?([\w\-]{8,})["\']?', "api_key"),
        ]
        for pattern, ioc_type in key_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                key_val = match.group(1)
                iocs.append({
                    "type": ioc_type,
                    "detail": f"API key found in {cf.original_path}",
                    "value_redacted": key_val[:4] + "..." + key_val[-4:],
                })

        # Extract upstream endpoints
        endpoint_matches = re.findall(
            r'(?:url|endpoint|base_url|api_base)\s*[:=]\s*["\']?(https?://[^\s"\'>,]+)',
            content, re.IGNORECASE,
        )
        if endpoint_matches:
            data["upstream_endpoints"] = list(set(endpoint_matches))

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="config",
            severity=Severity.HIGH if iocs else Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]

    def _parse_routing(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse routing table / model mapping config."""
        content = self.safe_read_file(cf.original_path)
        if not content:
            return []

        data = {"raw": content}

        # Extract routing rules
        routing_rules = []
        route_patterns = [
            r'(?:route|path|prefix)\s*[:=]\s*["\']?(/[^\s"\'>,]+)["\']?',
            r'(?:model|model_name|upstream)\s*[:=]\s*["\']?([a-zA-Z0-9_./\-]+)["\']?',
        ]
        for pattern in route_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                routing_rules.append(match.group(1))

        if routing_rules:
            data["routing_rules"] = list(set(routing_rules))

        # Extract model mappings
        model_mappings = re.findall(
            r'(?:model|model_name)\s*[:=]\s*["\']?([a-zA-Z0-9_./\-]+)["\'][^}]*?(?:upstream|target|provider)\s*[:=]\s*["\']?([a-zA-Z0-9_./\-]+)["\']?',
            content, re.IGNORECASE,
        )
        if model_mappings:
            data["model_mappings"] = [
                {"alias": m[0], "upstream": m[1]} for m in model_mappings
            ]

        iocs = []
        # Check for API keys in routing config
        for match in re.finditer(r'(?:api_key|key)\s*[:=]\s*["\']?([\w\-]{8,})["\']?', content, re.IGNORECASE):
            key_val = match.group(1)
            iocs.append({
                "type": "api_key_in_routing",
                "detail": "API key found in routing configuration",
                "value_redacted": key_val[:4] + "..." + key_val[-4:],
            })

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="routing_table",
            severity=Severity.HIGH if iocs else Severity.MEDIUM,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]

    def _parse_database(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse SQLite databases for request metadata."""
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
                    cursor.execute(f"SELECT COUNT(*) FROM [{table}]")
                    count = cursor.fetchone()[0]
                    if count == 0:
                        continue

                    cursor.execute(f"PRAGMA table_info([{table}])")
                    columns = [row[1] for row in cursor.fetchall()]

                    data = {
                        "database": cf.original_path,
                        "table": table,
                        "row_count": count,
                        "columns": columns,
                    }

                    iocs = []

                    # Extract model usage stats
                    model_col = next((c for c in columns if "model" in c.lower()), None)
                    if model_col:
                        cursor.execute(
                            f"SELECT [{model_col}], COUNT(*) FROM [{table}] "
                            f"GROUP BY [{model_col}] ORDER BY COUNT(*) DESC LIMIT 20"
                        )
                        model_usage = dict(cursor.fetchall())
                        data["model_usage"] = model_usage

                    # Extract request counts by status
                    status_col = next(
                        (c for c in columns if "status" in c.lower() or "error" in c.lower()),
                        None,
                    )
                    if status_col:
                        cursor.execute(
                            f"SELECT [{status_col}], COUNT(*) FROM [{table}] "
                            f"GROUP BY [{status_col}] ORDER BY COUNT(*) DESC LIMIT 20"
                        )
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
                                        "detail": f"API key found in column '{col}'",
                                    })
                                    break
                        except Exception:
                            continue

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="database",
                        severity=Severity.HIGH if iocs else Severity.MEDIUM,
                        data=data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))
                except Exception:
                    continue

            conn.close()
        except Exception:
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="database",
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
        """Parse request log files."""
        content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
        if not content:
            return []

        iocs = []
        data = {"path": cf.original_path}

        # Error patterns
        error_count = len(re.findall(r"(?i)error|exception|fail|timeout|5\d{2}", content))
        data["error_line_count"] = error_count

        # Extract model names
        models = set(re.findall(
            r'model["\s:=]+([a-zA-Z0-9_./\-]+)',
            content,
        ))
        if models:
            data["models_seen"] = list(models)

        # Extract request metadata patterns
        request_ids = re.findall(
            r'(?:request_id|request-id|trace.?id)\s*[:=]\s*["\']?([a-zA-Z0-9\-]+)',
            content, re.IGNORECASE,
        )
        if request_ids:
            data["request_ids_sample"] = list(set(request_ids))[:50]

        # Check for API keys in logs
        api_key_matches = re.findall(r"sk-[a-zA-Z0-9]{20,}", content)
        if api_key_matches:
            for key in set(api_key_matches):
                iocs.append({
                    "type": "api_key_in_log",
                    "detail": "API key found in request log",
                    "value_redacted": key[:4] + "..." + key[-4:],
                })

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="request_log",
            severity=Severity.HIGH if iocs else Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]

    def _parse_cached_response(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse cached response files."""
        content = self.safe_read_file(cf.original_path)
        if not content:
            return []

        data = {"path": cf.original_path, "size_bytes": cf.size_bytes}

        # Try JSON parse for structured cache
        json_data = self.safe_read_json(cf.original_path)
        if json_data:
            data["structure_keys"] = list(json_data.keys()) if isinstance(json_data, dict) else []

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="cached_response",
            severity=Severity.INFO,
            data=data,
            source_file=cf.original_path,
        )]
