"""
Claude Code forensic artifact collector for TRACE.

Collects: CLAUDE.md files, project conversation data, settings,
auth tokens, and statsig configuration.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class ClaudeCodeCollector(BaseCollector):
    PLATFORM_NAME = "claude_code"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = ["claude", "claude-code"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.claude",
    ]
    MACOS_PATHS = [
        "~/.claude",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.claude",
    ]

    # Common project directories to scan for CLAUDE.md
    PROJECT_SCAN_DIRS = [
        "~/projects",
        "~/code",
        "~/repos",
        "~/src",
        "~/work",
        "~/Developer",
        "~/development",
    ]

    def discover(self) -> bool:
        """Detect if Claude Code is installed or has been used."""
        for home in self.get_user_home_dirs():
            claude_dir = home / ".claude"
            if claude_dir.exists():
                return True

        # Check for running process
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-f", "claude"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all Claude Code forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            claude_dir = home / ".claude"
            if not claude_dir.exists():
                continue

            # CLAUDE.md in ~/.claude/
            claude_md = claude_dir / "CLAUDE.md"
            if claude_md.exists():
                cf = CollectedFile(
                    original_path=str(claude_md),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="project_instructions",
                    size_bytes=claude_md.stat().st_size,
                    sha256=self.calculate_hash(str(claude_md)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Settings
            settings_path = claude_dir / "settings.json"
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

            # Auth/credentials
            auth_path = claude_dir / "auth.json"
            if auth_path.exists():
                cf = CollectedFile(
                    original_path=str(auth_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="auth",
                    size_bytes=auth_path.stat().st_size,
                    sha256=self.calculate_hash(str(auth_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Credentials file
            creds_path = claude_dir / "credentials.json"
            if creds_path.exists():
                cf = CollectedFile(
                    original_path=str(creds_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="auth",
                    size_bytes=creds_path.stat().st_size,
                    sha256=self.calculate_hash(str(creds_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Statsig configuration
            statsig_dir = claude_dir / "statsig"
            if statsig_dir.exists():
                for stat_file in statsig_dir.iterdir():
                    if stat_file.is_file():
                        cf = CollectedFile(
                            original_path=str(stat_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="statsig",
                            size_bytes=stat_file.stat().st_size,
                            sha256=self.calculate_hash(str(stat_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Project conversation data
            projects_dir = claude_dir / "projects"
            if projects_dir.exists():
                for project_dir in projects_dir.iterdir():
                    if project_dir.is_dir():
                        # Conversation JSONL files
                        for conv_file in project_dir.glob("*.jsonl"):
                            if not conv_file.is_file():
                                continue
                            cf = CollectedFile(
                                original_path=str(conv_file),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="conversation_log",
                                size_bytes=conv_file.stat().st_size,
                                sha256=self.calculate_hash(str(conv_file)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

                        # Project CLAUDE.md
                        project_claude_md = project_dir / "CLAUDE.md"
                        if project_claude_md.exists():
                            cf = CollectedFile(
                                original_path=str(project_claude_md),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="project_instructions",
                                size_bytes=project_claude_md.stat().st_size,
                                sha256=self.calculate_hash(str(project_claude_md)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

                        # Session data
                        for session_file in project_dir.glob("*.json"):
                            if not session_file.is_file():
                                continue
                            cf = CollectedFile(
                                original_path=str(session_file),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="session_data",
                                size_bytes=session_file.stat().st_size,
                                sha256=self.calculate_hash(str(session_file)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

            # State/lock files
            for lock_file in claude_dir.glob("*.lock"):
                if not lock_file.is_file():
                    continue
                cf = CollectedFile(
                    original_path=str(lock_file),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="lock_file",
                    size_bytes=lock_file.stat().st_size,
                    sha256=self.calculate_hash(str(lock_file)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # PID file
            pid_path = claude_dir / "claude.pid"
            if pid_path.exists():
                cf = CollectedFile(
                    original_path=str(pid_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="pid_file",
                    size_bytes=pid_path.stat().st_size,
                    sha256=self.calculate_hash(str(pid_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        # Collect CLAUDE.md from project roots
        collected.extend(self._collect_project_claude_md())

        return collected

    def _collect_project_claude_md(self) -> list[CollectedFile]:
        """Collect CLAUDE.md files from common project directories."""
        collected = []

        for home in self.get_user_home_dirs():
            # Home directory CLAUDE.md
            home_claude = home / "CLAUDE.md"
            if home_claude.exists():
                cf = CollectedFile(
                    original_path=str(home_claude),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="project_instructions",
                    size_bytes=home_claude.stat().st_size,
                    sha256=self.calculate_hash(str(home_claude)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Scan project directories
            for proj_dir_name in self.PROJECT_SCAN_DIRS:
                proj_dir = Path(proj_dir_name).expanduser()
                if not proj_dir.exists():
                    proj_dir = home / proj_dir_name.lstrip("~/")
                if not proj_dir.exists() or not proj_dir.is_dir():
                    continue

                try:
                    # CLAUDE.md at project root level
                    for item in proj_dir.iterdir():
                        if item.is_dir():
                            claude_md = item / "CLAUDE.md"
                            if claude_md.exists():
                                cf = CollectedFile(
                                    original_path=str(claude_md),
                                    source_os=self.detect_os(),
                                    platform=self.PLATFORM_NAME,
                                    artifact_type="project_instructions",
                                    size_bytes=claude_md.stat().st_size,
                                    sha256=self.calculate_hash(str(claude_md)),
                                    collected_at=self.timestamp(),
                                )
                                collected.append(cf)
                                self.collected_files.append(cf)
                except (PermissionError, OSError):
                    continue

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Claude Code artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "project_instructions":
                content = self.safe_read_file(cf.original_path)
                if content:
                    iocs = []
                    content_lower = content.lower()

                    # Check for security-relevant instructions
                    security_keywords = ["secret", "password", "api_key", "token", "credential", "private_key", "ssh_key"]
                    for keyword in security_keywords:
                        if keyword in content_lower:
                            iocs.append({
                                "type": "sensitive_keyword_in_instructions",
                                "detail": f"'{keyword}' referenced in CLAUDE.md",
                                "file": cf.original_path,
                            })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="project_instructions",
                        severity=Severity.MEDIUM if iocs else Severity.LOW,
                        data={
                            "content_preview": content[:3000],
                            "full_length": len(content),
                            "path": cf.original_path,
                        },
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0048"],
                    ))

            elif cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    config_str = str(data)
                    if "api_key" in config_str.lower():
                        iocs.append({
                            "type": "api_key_in_config",
                            "detail": "API key found in Claude Code settings",
                        })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "auth":
                # Auth files are critical — note but redact content
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="auth",
                    severity=Severity.CRITICAL,
                    data={"note": "Authentication credential file found (contents redacted)", "filename": Path(cf.original_path).name},
                    source_file=cf.original_path,
                    iocs=[{"type": "auth_credential_file", "filename": Path(cf.original_path).name}],
                    mitre_atlas=["AML.T0055"],
                ))

            elif cf.artifact_type == "conversation_log":
                # Just metadata — don't read full conversations
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_log",
                    severity=Severity.MEDIUM,
                    data={
                        "note": "Claude Code conversation log (JSONL)",
                        "filename": Path(cf.original_path).name,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0048"],
                ))

            elif cf.artifact_type == "session_data":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="session_data",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "statsig":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="statsig",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

        return artifacts
