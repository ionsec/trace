"""Open WebUI forensic artifact collector for TRACE.

webui.db is the single richest self-hosted chat-history artifact: users,
chats and model configs in one SQLite file. DATA_DIR defaults to ./data;
docs recommend DATA_DIR=~/.open-webui. Paths verified against
docs.openwebui.com (database schema, env configuration), Oct 2026 (v0.12.0).
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)
from ionsec_trace.collector.sqlite_util import sqlite_counts


class OpenWebUICollector(BaseCollector):
    PLATFORM_NAME = "open_webui"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["open-webui", "open_webui"]
    SERVICE_PORTS = [8080]

    LINUX_PATHS = ["~/.open-webui"]
    MACOS_PATHS = ["~/.open-webui"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.open-webui"]

    def _data_dirs(self) -> list[Path]:
        dirs = [Path("./data")]
        for home in self.get_user_home_dirs():
            dirs.append(home / ".open-webui")
        return dirs

    def discover(self) -> bool:
        return any((d / "webui.db").exists() for d in self._data_dirs())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for data_dir in self._data_dirs():
            db = data_dir / "webui.db"
            if db.is_file():
                collected.append(self._record(db, "session_db"))
            secret = data_dir / ".webui_secret_key"
            if secret.is_file():
                collected.append(self._record(secret, "credential"))
        return collected

    def _record(self, path: Path, artifact_type: str) -> CollectedFile:
        cf = CollectedFile(
            original_path=str(path),
            source_os=self.detect_os(),
            platform=self.PLATFORM_NAME,
            artifact_type=artifact_type,
            size_bytes=path.stat().st_size,
            sha256=self.calculate_hash(str(path)),
            collected_at=self.timestamp(),
        )
        self.collected_files.append(cf)
        return cf

    def parse(self) -> list[ParsedArtifact]:
        artifacts = []
        for cf in self.collected_files:
            if cf.artifact_type == "session_db":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_db",
                    severity=Severity.MEDIUM,
                    data={"path": cf.original_path,
                          "tables": sqlite_counts(cf.original_path)},
                    source_file=cf.original_path,
                ))
            elif cf.artifact_type == "credential":
                # Existence only — never read the secret.
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="credential",
                    severity=Severity.HIGH,
                    data={"path": cf.original_path,
                          "note": "Open WebUI secret key present"},
                    source_file=cf.original_path,
                ))
        return artifacts
