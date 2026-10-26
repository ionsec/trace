"""Cline forensic artifact collector for TRACE (also covers Roo Code).

Cline v4.0.0 migrated the extension to an SDK session layer while pre-4.x
hosts keep per-task folders in every VS Code-family globalStorage root, and
Roo Code uses the same layout — both generations are collected.
Paths verified against cline/cline source and roocodeinc docs, Oct 2026.
"""

import os
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)

_HOSTS = ("Code", "Code - Insiders", "Cursor", "VSCodium", "Windsurf")


class ClineCollector(BaseCollector):
    PLATFORM_NAME = "cline"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["cline"]
    SERVICE_PORTS = []

    def discover(self) -> bool:
        import shutil
        if shutil.which("cline"):
            return True
        for home in self.get_user_home_dirs():
            if (home / ".cline/data/sessions").exists():
                return True
        for root in self._global_storage_roots():
            if (root / "saoudrizwan.claude-dev/tasks").is_dir():
                return True
            if (root / "rooveterinaryinc.roo-cline/tasks").is_dir():
                return True
        return False

    def _sessions_root(self) -> Path | None:
        """Resolve the modern (v4 SDK) sessions directory, honoring env overrides."""
        env = (os.environ.get("CLINE_SESSION_DATA_DIR")
               or os.environ.get("CLINE_DATA_DIR")
               or os.environ.get("CLINE_DIR"))
        if env:
            base = Path(env)
            return base if base.name == "sessions" else base / "sessions"
        for home in self.get_user_home_dirs():
            candidate = home / ".cline/data/sessions"
            if candidate.is_dir():
                return candidate
        return None

    def _global_storage_roots(self) -> list[Path]:
        """All VS Code-family globalStorage roots on this host."""
        roots = []
        system = self.detect_os()
        appdata = os.environ.get("APPDATA")
        for home in self.get_user_home_dirs():
            for host in _HOSTS:
                if system == "macos":
                    base = home / "Library/Application Support" / host / "User/globalStorage"
                elif system == "windows":
                    if not appdata:
                        continue
                    base = Path(appdata) / host / "User/globalStorage"
                else:
                    base = home / ".config" / host / "User/globalStorage"
                if base.is_dir():
                    roots.append(base)
        return roots

    def collect(self) -> list[CollectedFile]:
        collected = []

        sessions_root = self._sessions_root()
        if sessions_root and sessions_root.is_dir():
            for session_dir in sessions_root.iterdir():
                if not session_dir.is_dir():
                    continue
                for f in session_dir.glob("*.messages.json"):
                    collected.append(self._record(f, "session_modern"))

        for root in self._global_storage_roots():
            for sub, tool in (
                ("saoudrizwan.claude-dev", "cline"),
                ("rooveterinaryinc.roo-cline", "roo"),
            ):
                tasks = root / sub / "tasks"
                if not tasks.is_dir():
                    continue
                for task in tasks.iterdir():
                    history = task / "api_conversation_history.json"
                    if history.is_file():
                        collected.append(self._record(history, "session_legacy", tool))
        for home in self.get_user_home_dirs():
            mock_tasks = home / ".vscode-mock/global-storage/tasks"
            if mock_tasks.is_dir():
                for task in mock_tasks.iterdir():
                    history = task / "api_conversation_history.json"
                    if history.is_file():
                        collected.append(self._record(history, "session_legacy", "roo-cli"))
            settings = home / ".cline/data/settings/cline_mcp_settings.json"
            if settings.is_file():
                collected.append(self._record(settings, "mcp_config"))

        return collected

    def _record(self, path: Path, artifact_type: str, tool: str = "cline") -> CollectedFile:
        cf = CollectedFile(
            original_path=str(path),
            source_os=self.detect_os(),
            platform=self.PLATFORM_NAME,
            artifact_type=artifact_type,
            size_bytes=path.stat().st_size,
            sha256=self.calculate_hash(str(path)),
            collected_at=self.timestamp(),
        )
        cf.tool = tool  # type: ignore[attr-defined]
        self.collected_files.append(cf)
        return cf

    def parse(self) -> list[ParsedArtifact]:
        artifacts = []
        for cf in self.collected_files:
            if cf.artifact_type not in ("session_modern", "session_legacy"):
                if cf.artifact_type == "mcp_config":
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="mcp_config",
                        severity=Severity.INFO,
                        data={"path": cf.original_path},
                        source_file=cf.original_path,
                    ))
                continue
            data = self.safe_read_json(cf.original_path)
            if isinstance(data, list):
                messages = len(data)
            elif isinstance(data, dict) and isinstance(data.get("messages"), list):
                messages = len(data["messages"])
            else:
                messages = 0
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type=cf.artifact_type,
                severity=Severity.LOW,
                data={"path": cf.original_path, "messages": messages,
                      "tool": getattr(cf, "tool", "cline")},
                source_file=cf.original_path,
            ))
        return artifacts
