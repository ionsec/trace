"""Desktop chat app forensic artifact collector for TRACE.

ChatGPT and Claude desktop apps keep stores separate from the browser stores
that browser_ai already covers. Their internal schemas are undocumented, so
this collector records presence, size and top-level file names only — it never
exports conversation content. Paths verified against 9to5Mac/Heise reporting
(ChatGPT) and claude.com data-storage docs (Claude), Oct 2026.
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

_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".json", ".jsonl")
_MAX_FILES = 200


class DesktopChatCollector(BaseCollector):
    PLATFORM_NAME = "desktop_chat"
    PLATFORM_CATEGORY = PlatformCategory.CLOUD
    PROCESS_NAMES = ["ChatGPT", "Claude"]
    SERVICE_PORTS = []

    LINUX_PATHS = ["~/.config/Claude"]
    MACOS_PATHS = [
        "~/Library/Application Support/com.openai.chat",
        "~/Library/Application Support/Claude",
    ]
    WINDOWS_PATHS = ["%APPDATA%\\Claude"]

    def _app_roots(self) -> list[tuple[Path, str]]:
        roots = []
        system = self.detect_os()
        appdata = os.environ.get("APPDATA")
        for home in self.get_user_home_dirs():
            if system == "macos":
                roots.append((home / "Library/Application Support/com.openai.chat",
                              "chatgpt_desktop"))
                roots.append((home / "Library/Application Support/Claude",
                              "claude_desktop"))
            elif system == "windows" and appdata:
                roots.append((Path(appdata) / "Claude", "claude_desktop"))
            else:
                roots.append((home / ".config/Claude", "claude_desktop"))
        return roots

    def discover(self) -> bool:
        return any(root.is_dir() for root, _kind in self._app_roots())

    def collect(self) -> list[CollectedFile]:
        collected = []
        for root, kind in self._app_roots():
            if not root.is_dir():
                continue
            count = 0
            for f in root.rglob("*"):
                if count >= _MAX_FILES:
                    break
                if not f.is_file() or f.suffix not in _SUFFIXES:
                    continue
                artifact_type = "mcp_config" if f.name == "claude_desktop_config.json" else kind
                collected.append(self._record(f, artifact_type))
                count += 1
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
            if cf.artifact_type == "mcp_config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="mcp_config",
                        severity=Severity.MEDIUM if "mcpServers" in content else Severity.INFO,
                        data={"path": cf.original_path,
                              "has_mcp_servers": "mcpServers" in content},
                        source_file=cf.original_path,
                    ))
                continue
            # Metadata only: no schema probing of third-party stores.
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type=cf.artifact_type,
                severity=Severity.INFO,
                data={"path": cf.original_path,
                      "bytes": cf.size_bytes,
                      "filename": Path(cf.original_path).name},
                source_file=cf.original_path,
            ))
        return artifacts
