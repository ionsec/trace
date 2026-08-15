"""
AutoGPT forensic artifact collector for TRACE.

Collects: ai_settings.yaml, .env (redacted), workspace files, browse links,
and agent configuration data.
"""

import re
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class AutoGPTCollector(BaseCollector):
    PLATFORM_NAME = "autogpt"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = ["autogpt", "Auto-GPT"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.autogpt",
    ]
    MACOS_PATHS = [
        "~/.autogpt",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.autogpt",
    ]

    # Known API key env var patterns to redact
    _API_KEY_PATTERNS = [
        re.compile(r"(OPENAI_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(GOOGLE_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(ANTHROPIC_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(ELEVENLABS_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(HUGGINGFACE_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(SECRET\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(TOKEN\s*=\s*).+", re.IGNORECASE),
    ]

    def discover(self) -> bool:
        """Detect if AutoGPT is installed or has been used."""
        import shutil
        if shutil.which("autogpt") or shutil.which("agpt"):
            return True

        for home in self.get_user_home_dirs():
            if (home / ".autogpt").exists():
                return True

        # Search for ai_settings.yaml in common project locations
        for home in self.get_user_home_dirs():
            for projects_dir in [home / "Auto-GPT", home / "autogpt", home / "projects"]:
                if projects_dir.exists() and (projects_dir / "ai_settings.yaml").exists():
                    return True

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all AutoGPT forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            # ~/.autogpt/ directory
            autogpt_dir = home / ".autogpt"
            if autogpt_dir.exists():
                for item in autogpt_dir.iterdir():
                    if item.is_file():
                        artifact_type = self._classify_autogpt_file(item.name)
                        if artifact_type:
                            cf = CollectedFile(
                                original_path=str(item),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type=artifact_type,
                                size_bytes=item.stat().st_size,
                                sha256=self.calculate_hash(str(item)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

                # Subdirectories
                for subdir in autogpt_dir.iterdir():
                    if subdir.is_dir():
                        for sub_item in subdir.rglob("*"):
                            if sub_item.is_file():
                                artifact_type = self._classify_autogpt_file(sub_item.name)
                                if artifact_type:
                                    cf = CollectedFile(
                                        original_path=str(sub_item),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type=artifact_type,
                                        size_bytes=sub_item.stat().st_size,
                                        sha256=self.calculate_hash(str(sub_item)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

            # AutoGPT project directories — search for ai_settings.yaml
            project_dirs = [
                home / "Auto-GPT",
                home / "autogpt",
                home / "projects" / "Auto-GPT",
                home / "projects" / "autogpt",
            ]
            for proj_dir in project_dirs:
                if not proj_dir.exists():
                    continue

                # ai_settings.yaml
                settings_path = proj_dir / "ai_settings.yaml"
                if settings_path.exists():
                    cf = CollectedFile(
                        original_path=str(settings_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="agent_settings",
                        size_bytes=settings_path.stat().st_size,
                        sha256=self.calculate_hash(str(settings_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

                # .env file (credentials)
                env_path = proj_dir / ".env"
                if env_path.exists():
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

                # auto_gpt_workspace directory
                workspace_dir = proj_dir / "auto_gpt_workspace"
                if workspace_dir.exists():
                    for ws_file in workspace_dir.rglob("*"):
                        if ws_file.is_file():
                            cf = CollectedFile(
                                original_path=str(ws_file),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="workspace_file",
                                size_bytes=ws_file.stat().st_size,
                                sha256=self.calculate_hash(str(ws_file)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

                # file_logger.txt
                file_logger = proj_dir / "file_logger.txt"
                if file_logger.exists():
                    cf = CollectedFile(
                        original_path=str(file_logger),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="activity_log",
                        size_bytes=file_logger.stat().st_size,
                        sha256=self.calculate_hash(str(file_logger)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

                # browse_links.json
                browse_links = proj_dir / "browse_links.json"
                if browse_links.exists():
                    cf = CollectedFile(
                        original_path=str(browse_links),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="browse_links",
                        size_bytes=browse_links.stat().st_size,
                        sha256=self.calculate_hash(str(browse_links)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected AutoGPT artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "agent_settings":
                content = self.safe_read_file(cf.original_path)
                if content:
                    try:
                        import yaml
                        data = yaml.safe_load(content)
                    except Exception:
                        data = {"raw": content}

                    iocs = []
                    if isinstance(data, dict):
                        # Extract agent goals
                        goals = data.get("goals", [])
                        if goals:
                            iocs.append({"type": "agent_goals", "detail": f"Agent has {len(goals)} goals defined"})

                        # Check for API-related settings
                        api_keys_found = []
                        settings_str = str(data)
                        for pattern in ["api_key", "API_KEY", "api-key"]:
                            if pattern in settings_str:
                                api_keys_found.append(pattern)
                        if api_keys_found:
                            iocs.append({"type": "api_key_in_settings", "detail": f"API key references found: {api_keys_found}"})

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="agent_settings",
                        severity=Severity.MEDIUM if iocs else Severity.INFO,
                        data=data if isinstance(data, dict) else {"raw": str(data)},
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0055"] if iocs else [],
                    ))

            elif cf.artifact_type == "credential":
                content = self.safe_read_file(cf.original_path)
                if content:
                    # Redact API keys but note their existence
                    redacted_lines = []
                    api_keys_found = []
                    for line in content.splitlines():
                        redacted = False
                        for pattern in self._API_KEY_PATTERNS:
                            match = pattern.search(line)
                            if match:
                                redacted_lines.append(f"{match.group(1)}[REDACTED]")
                                api_keys_found.append(match.group(1).strip().rstrip("=").strip())
                                redacted = True
                                break
                        if not redacted:
                            redacted_lines.append(line)

                    iocs = []
                    for key_name in api_keys_found:
                        iocs.append({"type": "api_key_found", "detail": f"API key present: {key_name}"})

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="credential",
                        severity=Severity.CRITICAL,
                        data={
                            "redacted_content": "\n".join(redacted_lines),
                            "api_keys_found": api_keys_found,
                            "note": "API keys redacted; presence noted",
                        },
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0055"],
                    ))

            elif cf.artifact_type == "activity_log":
                content = self.safe_read_file(cf.original_path)
                if content:
                    lines = content.splitlines()
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="activity_log",
                        severity=Severity.LOW,
                        data={
                            "total_entries": len(lines),
                            "preview": lines[:20] if lines else [],
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "browse_links":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="browse_links",
                        severity=Severity.LOW,
                        data=data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "workspace_file":
                # Just catalog workspace files; don't parse contents in bulk
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="workspace_file",
                    severity=Severity.INFO,
                    data={"filename": Path(cf.original_path).name, "size": cf.size_bytes},
                    source_file=cf.original_path,
                ))

        return artifacts

    @staticmethod
    def _classify_autogpt_file(filename: str) -> str | None:
        """Map an AutoGPT filename to an artifact type."""
        name = filename.lower()
        if name in {"ai_settings.yaml", "ai_settings.yml"}:
            return "agent_settings"
        if name == ".env":
            return "credential"
        if name == "file_logger.txt":
            return "activity_log"
        if name == "browse_links.json":
            return "browse_links"
        if name.endswith((".yaml", ".yml")):
            return "config"
        if name.endswith(".json"):
            return "data"
        if name.endswith((".log", ".txt")):
            return "log"
        return None
