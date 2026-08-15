"""
Unsloth / Unsloth Studio forensic artifact collector for TRACE.

Unsloth is a fine-tuning library (unslothai/unsloth on GitHub) and Unsloth
Studio is its GUI. Collects: config files (yaml/json/toml), training logs,
model checkpoint metadata, .env files, and any SQLite/JSONL session data.

Parse: extract model names, training config, API keys (redacted), and
timestamps.
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


class UnslothCollector(BaseCollector):
    PLATFORM_NAME = "unsloth"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["unsloth", "unsloth-studio"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.unsloth",
        "~/.cache/unsloth",
        "~/.config/unsloth",
        "~/.local/share/unsloth",
    ]
    MACOS_PATHS = [
        "~/.unsloth",
        "~/.cache/unsloth",
        "~/.config/unsloth",
        "~/.local/share/unsloth",
        "~/Library/Application Support/unsloth",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.unsloth",
        "%LOCALAPPDATA%\\unsloth",
        "%APPDATA%\\unsloth",
    ]

    # ── Discover ──────────────────────────────────────────────

    def discover(self) -> bool:
        """Detect if Unsloth / Unsloth Studio is installed or has been used."""
        import shutil

        # Check for unsloth CLI binary
        if shutil.which("unsloth"):
            return True

        # Check for pip-installed unsloth package
        if self._is_pip_installed():
            return True

        # Check for config/data directories in common locations
        for home in self.get_user_home_dirs():
            for rel in (".unsloth", ".cache/unsloth", ".config/unsloth",
                        ".local/share/unsloth"):
                if (home / rel).exists():
                    return True

        # Check system-level paths
        return any(Path(p).expanduser().exists() for p in self._get_system_paths())

    def _is_pip_installed(self) -> bool:
        """Check whether the unsloth package is importable."""
        try:
            import importlib.util
            return importlib.util.find_spec("unsloth") is not None
        except Exception:
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
        """Collect all Unsloth / Unsloth Studio forensic artifacts."""
        collected = []

        # ── User-level paths ─────────────────────────────────
        for home in self.get_user_home_dirs():
            for rel in (".unsloth", ".cache/unsloth", ".config/unsloth",
                        ".local/share/unsloth"):
                d = home / rel
                if d.exists():
                    collected.extend(self._collect_dir(d))

            # macOS Application Support
            if self.detect_os() == "macos":
                app_support = home / "Library" / "Application Support" / "unsloth"
                if app_support.exists():
                    collected.extend(self._collect_dir(app_support))

        # ── System-level paths ────────────────────────────────
        for sp in self._get_system_paths():
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
        for name in ["unsloth_config.yaml", "unsloth_config.yml",
                     "unsloth_config.json", "unsloth_config.toml"]:
            cfg = Path(name)
            if cfg.exists() and cfg.is_file():
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

        return collected

    def _collect_dir(self, directory: Path) -> list[CollectedFile]:
        """Collect all relevant files from an Unsloth directory."""
        collected = []

        # Config files
        for pattern in ["*.yaml", "*.yml", "*.json", "*.toml"]:
            for f in directory.glob(pattern):
                if f.is_file():
                    artifact_type = "config"
                    if "log" in f.name.lower():
                        artifact_type = "log"
                    elif "train" in f.name.lower():
                        artifact_type = "training_config"
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

        # Training logs
        for f in directory.glob("*.log*"):
            if f.is_file():
                cf = CollectedFile(
                    original_path=str(f),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="training_log",
                    size_bytes=f.stat().st_size,
                    sha256=self.calculate_hash(str(f)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        # JSONL session / training data
        for f in directory.glob("*.jsonl"):
            if f.is_file():
                cf = CollectedFile(
                    original_path=str(f),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_data",
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
                        artifact_type="session_database",
                        size_bytes=f.stat().st_size,
                        sha256=self.calculate_hash(str(f)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        # Model checkpoint metadata (adapter configs, etc.)
        for f in directory.rglob("adapter_config.json"):
            if f.is_file():
                cf = CollectedFile(
                    original_path=str(f),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="model_checkpoint_metadata",
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
        """Parse collected Unsloth artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type in ("config", "training_config"):
                artifacts.extend(self._parse_config(cf))
            elif cf.artifact_type == "credential":
                artifacts.extend(self._parse_env(cf))
            elif cf.artifact_type == "training_log":
                artifacts.extend(self._parse_log(cf))
            elif cf.artifact_type == "session_data":
                artifacts.extend(self._parse_jsonl(cf))
            elif cf.artifact_type == "session_database":
                artifacts.extend(self._parse_sqlite(cf))
            elif cf.artifact_type == "model_checkpoint_metadata":
                artifacts.extend(self._parse_checkpoint(cf))

        return artifacts

    def _redact(self, value: str) -> str:
        """Redact a secret, showing first 4 + last 4 chars."""
        if len(value) > 8:
            return value[:4] + "..." + value[-4:]
        return "***REDACTED***"

    def _parse_config(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse YAML/JSON config files for model names and API keys."""
        content = self.safe_read_file(cf.original_path)
        if not content:
            return []

        iocs = []
        data = {"raw": content}

        # Extract API keys (redacted)
        key_patterns = [
            (r'(?:api_key|apikey|api-key|hf_token|huggingface_token)\s*[:=]\s*["\']?([\w\-]{8,})["\']?', "api_key"),
            (r'(?:HF_TOKEN|HUGGING_FACE_HUB_TOKEN|WANDB_API_KEY|OPENAI_API_KEY)\s*[:=]\s*["\']?([\w\-/+=]{8,})["\']?', "env_api_key"),
        ]
        for pattern, ioc_type in key_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                key_val = match.group(1)
                iocs.append({
                    "type": ioc_type,
                    "detail": f"API key found in {cf.original_path}",
                    "value_redacted": self._redact(key_val),
                })

        # Extract model names
        model_matches = re.findall(
            r'(?:model_name|model|base_model)\s*[:=]\s*["\']?([a-zA-Z0-9_./\-]+)["\']?',
            content, re.IGNORECASE,
        )
        if model_matches:
            data["models_configured"] = list(set(model_matches))

        # Extract training hyperparameters
        for key in ("learning_rate", "num_train_epochs", "batch_size",
                    "max_seq_length", "lora_rank", "lora_alpha"):
            m = re.search(rf'{key}\s*[:=]\s*([\d.]+)', content, re.IGNORECASE)
            if m:
                data[key] = m.group(1)

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="config",
            severity=Severity.HIGH if iocs else Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]

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
                    iocs.append({
                        "type": "env_secret",
                        "detail": f"Sensitive environment variable: {key}",
                        "value_redacted": self._redact(value),
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
        """Parse training log files for model names and loss curves."""
        content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
        if not content:
            return []

        iocs = []
        data = {"path": cf.original_path}

        # Extract model names
        models = set(re.findall(
            r'model["\s:=]+([a-zA-Z0-9_./\-]+)',
            content,
        ))
        if models:
            data["models_seen"] = list(models)

        # Extract loss values
        losses = re.findall(r'loss[:\s=]+([\d.]+)', content, re.IGNORECASE)
        if losses:
            data["loss_samples"] = losses[:20]

        # Extract API key patterns
        api_key_matches = re.findall(r"(?:sk-|hf_)[a-zA-Z0-9]{20,}", content)
        if api_key_matches:
            for key in set(api_key_matches):
                iocs.append({
                    "type": "api_key_in_log",
                    "detail": "API key found in training log",
                    "value_redacted": self._redact(key),
                })

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="training_log",
            severity=Severity.HIGH if iocs else Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]

    def _parse_jsonl(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse JSONL session/training data."""
        content = self.safe_read_file(cf.original_path, max_bytes=5 * 1024 * 1024)
        if not content:
            return []

        import json as _json

        records = []
        iocs = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = _json.loads(line)
                records.append(rec)
            except Exception:
                continue

        data = {"path": cf.original_path, "record_count": len(records)}
        if records:
            # Collect model names across records
            models = set()
            for rec in records:
                if isinstance(rec, dict):
                    for key in ("model", "model_name", "base_model"):
                        val = rec.get(key)
                        if isinstance(val, str):
                            models.add(val)
            if models:
                data["models_seen"] = list(models)

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="session_data",
            severity=Severity.MEDIUM if records else Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]

    def _parse_sqlite(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse SQLite session databases."""
        artifacts = []
        try:
            import sqlite3

            conn = sqlite3.connect(cf.original_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

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

                    model_col = next((c for c in columns if "model" in c.lower()), None)
                    if model_col:
                        cursor.execute(
                            f"SELECT [{model_col}], COUNT(*) FROM [{table}] "
                            f"GROUP BY [{model_col}] ORDER BY COUNT(*) DESC LIMIT 20"
                        )
                        data["model_usage"] = dict(cursor.fetchall())

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_database",
                        severity=Severity.MEDIUM,
                        data=data,
                        source_file=cf.original_path,
                    ))
                except Exception:
                    continue

            conn.close()
        except Exception:
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="session_database",
                severity=Severity.LOW,
                data={"note": "Could not parse database", "path": cf.original_path},
                source_file=cf.original_path,
            ))

        return artifacts

    def _parse_checkpoint(self, cf: CollectedFile) -> list[ParsedArtifact]:
        """Parse model checkpoint metadata (adapter_config.json)."""
        data = self.safe_read_json(cf.original_path)
        if not data:
            return []

        iocs = []
        # Extract base model name from adapter config
        base_model = data.get("base_model_name_or_path")
        if base_model:
            data["base_model"] = base_model

        return [ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="model_checkpoint_metadata",
            severity=Severity.INFO,
            data=data,
            source_file=cf.original_path,
            iocs=iocs,
        )]
