"""
Shell-GPT (sgpt) forensic artifact collector for TRACE.

Collects: conversation history, config (.sgptrc), and role definition files.
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


class ShellGPTCollector(BaseCollector):
    PLATFORM_NAME = "shell_gpt"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["sgpt"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.shell_gpt",
    ]
    MACOS_PATHS = [
        "~/.shell_gpt",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.shell_gpt",
    ]

    def discover(self) -> bool:
        """Detect if Shell-GPT is installed or has been used."""
        import shutil
        if shutil.which("sgpt"):
            return True

        return any((home / ".shell_gpt").exists() for home in self.get_user_home_dirs())

    def collect(self) -> list[CollectedFile]:
        """Collect all Shell-GPT forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            sgpt_dir = home / ".shell_gpt"
            if not sgpt_dir.exists():
                continue

            # Config file (.sgptrc)
            config_path = sgpt_dir / ".sgptrc"
            if config_path.exists():
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

            # Conversation history
            history_path = sgpt_dir / "history"
            if history_path.exists():
                cf = CollectedFile(
                    original_path=str(history_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_history",
                    size_bytes=history_path.stat().st_size,
                    sha256=self.calculate_hash(str(history_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Role definition files
            roles_dir = sgpt_dir / "roles"
            if roles_dir.exists() and roles_dir.is_dir():
                for role_file in roles_dir.iterdir():
                    if role_file.is_file():
                        cf = CollectedFile(
                            original_path=str(role_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="role_definition",
                            size_bytes=role_file.stat().st_size,
                            sha256=self.calculate_hash(str(role_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Deep collection: scan for any other files in .shell_gpt
            if self.deep:
                for item in sgpt_dir.rglob("*"):
                    if item.is_file():
                        # Skip files we already collected at top level
                        rel = item.relative_to(sgpt_dir)
                        if str(rel) in [".sgptrc", "history"]:
                            continue
                        if str(rel).startswith("roles/"):
                            continue
                        cf = CollectedFile(
                            original_path=str(item),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="data",
                            size_bytes=item.stat().st_size,
                            sha256=self.calculate_hash(str(item)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Shell-GPT artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                # .sgptrc is key=value format
                content = self.safe_read_file(cf.original_path)
                if content:
                    config = {}
                    api_keys_found = []
                    iocs = []

                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, _, value = line.partition("=")
                            key = key.strip()
                            value = value.strip()

                            # Redact API keys
                            if "api_key" in key.lower() or "key" in key.lower() or "token" in key.lower():
                                api_keys_found.append(key)
                                config[key] = "[REDACTED]"
                                iocs.append({"type": "api_key_found", "detail": f"API key present: {key}"})
                            elif "model" in key.lower():
                                config[key] = value
                                iocs.append({"type": "model_config", "detail": f"Model setting: {key}={value}"})
                            else:
                                config[key] = value

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.CRITICAL if api_keys_found else Severity.INFO,
                        data={
                            "config": config,
                            "api_keys_found": api_keys_found,
                            "note": "API key values redacted; presence noted" if api_keys_found else "",
                        },
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0055"] if api_keys_found else [],
                    ))

            elif cf.artifact_type == "conversation_history":
                # Shell-GPT history is typically plain text or JSON
                content = self.safe_read_file(cf.original_path)
                if content:
                    # Try JSON first
                    data = self.safe_read_json(cf.original_path)
                    topics = []
                    model_choices = []
                    iocs = []

                    if data and isinstance(data, list):
                        # JSON array of conversation entries
                        for entry in data:
                            if isinstance(entry, dict):
                                if "prompt" in entry:
                                    topics.append(entry["prompt"][:100])
                                if "model" in entry:
                                    model_choices.append(entry["model"])

                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="conversation_history",
                            severity=Severity.LOW,
                            data={
                                "total_entries": len(data),
                                "topics": topics[:50],
                                "model_choices": list(set(model_choices)),
                            },
                            source_file=cf.original_path,
                            iocs=iocs,
                        ))
                    else:
                        # Plain text history — extract conversation lines
                        lines = content.splitlines()
                        topics = [line.strip()[:100] for line in lines if line.strip() and not line.strip().startswith("#")][:50]

                        # Look for model references in the history
                        for line in lines:
                            model_match = re.search(r"(?:model|Model|--model)[:\s=]+(\S+)", line)
                            if model_match:
                                model_choices.append(model_match.group(1))

                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="conversation_history",
                            severity=Severity.LOW,
                            data={
                                "total_lines": len(lines),
                                "topics": topics,
                                "model_choices": list(set(model_choices)),
                            },
                            source_file=cf.original_path,
                            iocs=iocs,
                        ))

            elif cf.artifact_type == "role_definition":
                content = self.safe_read_file(cf.original_path)
                if content:
                    # Role files are typically plain text prompt definitions
                    role_name = Path(cf.original_path).stem
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="role_definition",
                        severity=Severity.LOW,
                        data={
                            "role_name": role_name,
                            "content_preview": content[:500],
                            "full_length": len(content),
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "data":
                # Generic data file from deep scan
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="data",
                    severity=Severity.INFO,
                    data={"filename": Path(cf.original_path).name, "size": cf.size_bytes},
                    source_file=cf.original_path,
                ))

        return artifacts
