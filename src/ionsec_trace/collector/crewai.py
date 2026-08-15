"""
CrewAI forensic artifact collector for TRACE.

Collects: crewai.toml, .env (redacted), ChromaDB memory files,
knowledge directories, and .crewai metadata.
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


class CrewAICollector(BaseCollector):
    PLATFORM_NAME = "crewai"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = ["crewai"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.crewai",
    ]
    MACOS_PATHS = [
        "~/.crewai",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.crewai",
    ]

    _API_KEY_PATTERNS = [
        re.compile(r"(OPENAI_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(ANTHROPIC_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(GOOGLE_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(SERPER_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(BROWSERLESS_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(_API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(API_KEY\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(SECRET\s*=\s*).+", re.IGNORECASE),
        re.compile(r"(TOKEN\s*=\s*).+", re.IGNORECASE),
    ]

    def discover(self) -> bool:
        """Detect if CrewAI is installed or has been used."""
        import shutil
        if shutil.which("crewai"):
            return True

        for home in self.get_user_home_dirs():
            if (home / ".crewai").exists():
                return True

        # Search for crewai.toml in common project locations
        for home in self.get_user_home_dirs():
            for search_dir in [home, home / "projects", home / "src"]:
                if not search_dir.exists():
                    continue
                try:
                    for _ in search_dir.rglob("crewai.toml"):
                        return True
                except (PermissionError, OSError):
                    continue

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all CrewAI forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            # ~/.crewai/ directory
            crewai_dir = home / ".crewai"
            if crewai_dir.exists():
                for item in crewai_dir.iterdir():
                    if item.is_file():
                        artifact_type = self._classify_crewai_file(item.name)
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

                    elif item.is_dir():
                        # Recurse into subdirectories (memory, knowledge, etc.)
                        for sub_item in item.rglob("*"):
                            if sub_item.is_file():
                                artifact_type = self._classify_crewai_file(sub_item.name)
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

            # Project-level crewai.toml and .env files
            project_dirs = [
                home / "projects",
                home / "src",
                home / "work",
            ]
            for proj_base in project_dirs:
                if not proj_base.exists():
                    continue
                try:
                    for crewai_toml in proj_base.rglob("crewai.toml"):
                        cf = CollectedFile(
                            original_path=str(crewai_toml),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="config",
                            size_bytes=crewai_toml.stat().st_size,
                            sha256=self.calculate_hash(str(crewai_toml)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                        # Look for associated .env in same directory
                        env_path = crewai_toml.parent / ".env"
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

                        # .crewai metadata directory in same project
                        crewai_meta = crewai_toml.parent / ".crewai"
                        if crewai_meta.exists() and crewai_meta.is_dir():
                            for meta_item in crewai_meta.rglob("*"):
                                if meta_item.is_file():
                                    cf = CollectedFile(
                                        original_path=str(meta_item),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type="metadata",
                                        size_bytes=meta_item.stat().st_size,
                                        sha256=self.calculate_hash(str(meta_item)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

                        # Memory directory (ChromaDB SQLite files)
                        memory_dir = crewai_toml.parent / "memory"
                        if memory_dir.exists() and memory_dir.is_dir():
                            for mem_item in memory_dir.rglob("*"):
                                if mem_item.is_file():
                                    cf = CollectedFile(
                                        original_path=str(mem_item),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type="memory",
                                        size_bytes=mem_item.stat().st_size,
                                        sha256=self.calculate_hash(str(mem_item)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

                        # Knowledge directory
                        knowledge_dir = crewai_toml.parent / "knowledge"
                        if knowledge_dir.exists() and knowledge_dir.is_dir():
                            for know_item in knowledge_dir.rglob("*"):
                                if know_item.is_file():
                                    cf = CollectedFile(
                                        original_path=str(know_item),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type="knowledge",
                                        size_bytes=know_item.stat().st_size,
                                        sha256=self.calculate_hash(str(know_item)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

                except (PermissionError, OSError):
                    continue

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected CrewAI artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                # crewai.toml
                content = self.safe_read_file(cf.original_path)
                if content:
                    try:
                        import tomllib
                        data = tomllib.loads(content)
                    except Exception:
                        try:
                            import tomli as tomllib  # type: ignore[no-redef]
                            data = tomllib.loads(content)
                        except Exception:
                            data = {"raw": content}

                    iocs = []
                    if isinstance(data, dict):
                        # Extract agent configurations
                        agents = data.get("agents", [])
                        if agents:
                            iocs.append({"type": "agent_config", "detail": f"Found {len(agents)} agent configuration(s)"})
                        tasks = data.get("tasks", [])
                        if tasks:
                            iocs.append({"type": "task_config", "detail": f"Found {len(tasks)} task definition(s)"})

                        # Check for API keys in config string
                        config_str = str(data)
                        for key_pattern in ["api_key", "API_KEY", "openai", "anthropic"]:
                            if key_pattern in config_str:
                                iocs.append({"type": "api_key_in_config", "detail": f"API key reference '{key_pattern}' found in config"})
                                break

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.MEDIUM if iocs else Severity.INFO,
                        data=data if isinstance(data, dict) else {"raw": str(data)},
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0055"] if iocs else [],
                    ))

            elif cf.artifact_type == "credential":
                # .env file — redact keys
                content = self.safe_read_file(cf.original_path)
                if content:
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

            elif cf.artifact_type == "memory":
                filename = Path(cf.original_path).name.lower()
                if filename.endswith((".sqlite3", ".db")):
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="memory",
                        severity=Severity.MEDIUM,
                        data={"note": "ChromaDB memory database", "filename": Path(cf.original_path).name},
                        source_file=cf.original_path,
                        mitre_atlas=["AML.T0051"],
                    ))
                else:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="memory",
                        severity=Severity.INFO,
                        data={"filename": Path(cf.original_path).name, "size": cf.size_bytes},
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "knowledge":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="knowledge",
                    severity=Severity.LOW,
                    data={"filename": Path(cf.original_path).name, "size": cf.size_bytes},
                    source_file=cf.original_path,
                ))

            elif cf.artifact_type == "metadata":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="metadata",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))
                else:
                    content = self.safe_read_file(cf.original_path)
                    if content:
                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="metadata",
                            severity=Severity.INFO,
                            data={"raw": content[:500]},
                            source_file=cf.original_path,
                        ))

        return artifacts

    @staticmethod
    def _classify_crewai_file(filename: str) -> str | None:
        """Map a CrewAI filename to an artifact type."""
        name = filename.lower()
        if name == "crewai.toml":
            return "config"
        if name == ".env":
            return "credential"
        if name.endswith((".sqlite3", ".db", ".sqlite")):
            return "memory"
        if name.endswith((".toml", ".yaml", ".yml")):
            return "config"
        if name.endswith(".json"):
            return "data"
        return None
