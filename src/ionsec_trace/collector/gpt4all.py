"""
GPT4All forensic artifact collector for TRACE.

Collects: chat.db (SQLite), models directory listings,
settings, and chat history artifacts.
"""

import sqlite3
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class GPT4AllCollector(BaseCollector):
    PLATFORM_NAME = "gpt4all"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["gpt4all", "GPT4All", "chat"]
    SERVICE_PORTS = [4891]

    LINUX_PATHS = [
        "~/.gpt4all/",
    ]
    MACOS_PATHS = [
        "~/Library/Application Support/gpt4all/",
    ]
    WINDOWS_PATHS = [
        "%APPDATA%\\gpt4all\\",
    ]

    def _get_platform_dirs(self) -> list[Path]:
        """Return GPT4All data directories for the current OS."""
        os_name = self.detect_os()
        dirs = []
        if os_name == "linux":
            for home in self.get_user_home_dirs():
                dirs.append(home / ".gpt4all")
        elif os_name == "macos":
            for home in self.get_user_home_dirs():
                dirs.append(home / "Library" / "Application Support" / "gpt4all")
        elif os_name == "windows":
            import os
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                dirs.append(Path(appdata) / "gpt4all")
            for home in self.get_user_home_dirs():
                dirs.append(home / ".gpt4all")
        return [d for d in dirs if d is not None]

    def discover(self) -> bool:
        """Detect if GPT4All is installed or has been used."""
        import shutil
        if shutil.which("gpt4all"):
            return True

        for d in self._get_platform_dirs():
            if d.exists():
                return True

        # Check for running process
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-f", "gpt4all"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all GPT4All forensic artifacts."""
        collected = []

        for base_dir in self._get_platform_dirs():
            if not base_dir.exists():
                continue

            # Chat database (SQLite)
            for db_name in ["chat.db", "gpt4all.db"]:
                db_path = base_dir / db_name
                if db_path.exists():
                    cf = CollectedFile(
                        original_path=str(db_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="conversation_database",
                        size_bytes=db_path.stat().st_size,
                        sha256=self.calculate_hash(str(db_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

                # WAL/SHM files
                for suffix in ["-wal", "-shm"]:
                    wal_path = base_dir / f"{db_name}{suffix}"
                    if wal_path.exists():
                        cf = CollectedFile(
                            original_path=str(wal_path),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type=f"conversation_database{suffix}",
                            size_bytes=wal_path.stat().st_size,
                            sha256=self.calculate_hash(str(wal_path)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Settings / config
            for settings_name in ["settings.json", "settings.ini", "config.json"]:
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

            # Models directory listing
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

            # Chat history files (some versions store as JSON)
            chats_dir = base_dir / "chats"
            if chats_dir.exists():
                for chat_file in chats_dir.rglob("*"):
                    if chat_file.is_file():
                        cf = CollectedFile(
                            original_path=str(chat_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="chat_history",
                            size_bytes=chat_file.stat().st_size,
                            sha256=self.calculate_hash(str(chat_file)),
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

            # Download metadata
            for dl_name in ["downloads.json", "download_meta.json"]:
                dl_path = base_dir / dl_name
                if dl_path.exists():
                    cf = CollectedFile(
                        original_path=str(dl_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="download_metadata",
                        size_bytes=dl_path.stat().st_size,
                        sha256=self.calculate_hash(str(dl_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected GPT4All artifacts."""
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
                            "detail": "API key found in GPT4All settings",
                        })

                    # Extract model information from settings
                    model_names = []
                    for key in ["model", "defaultModel", "currentModel", "models", "modelPath"]:
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

            elif cf.artifact_type == "conversation_database":
                # Read-only SQLite parsing for conversation metadata
                try:
                    conn = sqlite3.connect(f"file:{cf.original_path}?mode=ro", uri=True)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    # Get table names
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cursor.fetchall()]

                    conversations = []
                    try:
                        cursor.execute("SELECT * FROM conversations ORDER BY rowid LIMIT 100")
                        rows = cursor.fetchall()
                        for row in rows:
                            row_dict = dict(row)
                            # Sanitize: don't include full message content
                            safe_keys = {
                                "id", "title", "created_at", "updated_at",
                                "model", "prompt", "temperature", "top_p",
                                "max_tokens", "system_prompt",
                            }
                            conversations.append({
                                k: v for k, v in row_dict.items()
                                if k.lower() in safe_keys
                            })
                    except Exception:
                        pass

                    try:
                        cursor.execute("SELECT count(*) FROM messages")
                        msg_count = cursor.fetchone()[0]
                    except Exception:
                        msg_count = None

                    conn.close()

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="conversation_database",
                        severity=Severity.MEDIUM,
                        data={
                            "tables": tables,
                            "conversation_count": len(conversations),
                            "total_messages": msg_count,
                            "conversations": conversations[:20],
                        },
                        source_file=cf.original_path,
                        iocs=[{
                            "type": "conversation_data",
                            "detail": f"SQLite chat database with {len(conversations)} conversations",
                        }],
                    ))
                except Exception:
                    pass

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

            elif cf.artifact_type == "chat_history":
                content = self.safe_read_file(cf.original_path)
                if content:
                    # Try JSON parse
                    data = self.safe_read_json(cf.original_path)
                    if data:
                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="chat_history",
                            severity=Severity.MEDIUM,
                            data=data,
                            source_file=cf.original_path,
                        ))
                    else:
                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="chat_history",
                            severity=Severity.LOW,
                            data={
                                "path": cf.original_path,
                                "size_bytes": cf.size_bytes,
                                "preview": content[:1000],
                            },
                            source_file=cf.original_path,
                        ))

            elif cf.artifact_type == "download_metadata":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="download_metadata",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

        return artifacts
