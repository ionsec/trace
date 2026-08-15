"""
Hermes Agent forensic artifact collector for TRACE.

Collects: sessions, memories, config, auth, cron, skills, channel directory,
secrets, logs, profiles, and process information.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class HermesCollector(BaseCollector):
    PLATFORM_NAME = "hermes"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = ["hermes"]
    SERVICE_PORTS = []

    def discover(self) -> bool:
        """Detect if Hermes Agent is installed or has been used."""
        for home in self.get_user_home_dirs():
            hermes_dir = home / ".hermes"
            if hermes_dir.exists():
                return True
        return False

    def collect(self) -> list[CollectedFile]:
        """Collect all Hermes Agent forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            hermes_dir = home / ".hermes"
            if not hermes_dir.exists():
                continue

            # Config
            config_path = hermes_dir / "config.yaml"
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

            # Auth
            auth_path = hermes_dir / "auth.json"
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

            # State DB (SQLite — sessions)
            state_path = hermes_dir / "state.db"
            if state_path.exists():
                cf = CollectedFile(
                    original_path=str(state_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="session_database",
                    size_bytes=state_path.stat().st_size,
                    sha256=self.calculate_hash(str(state_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # SQLite WAL/SHM files
            for suffix in ["-wal", "-shm"]:
                wal_path = hermes_dir / f"state.db{suffix}"
                if wal_path.exists():
                    cf = CollectedFile(
                        original_path=str(wal_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type=f"session_database{suffix}",
                        size_bytes=wal_path.stat().st_size,
                        sha256=self.calculate_hash(str(wal_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Verification evidence DB
            ve_path = hermes_dir / "verification_evidence.db"
            if ve_path.exists():
                cf = CollectedFile(
                    original_path=str(ve_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="verification_evidence",
                    size_bytes=ve_path.stat().st_size,
                    sha256=self.calculate_hash(str(ve_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Kanban DB
            kb_path = hermes_dir / "kanban.db"
            if kb_path.exists():
                cf = CollectedFile(
                    original_path=str(kb_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="kanban_database",
                    size_bytes=kb_path.stat().st_size,
                    sha256=self.calculate_hash(str(kb_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Gateway state
            gw_state_path = hermes_dir / "gateway_state.json"
            if gw_state_path.exists():
                cf = CollectedFile(
                    original_path=str(gw_state_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="gateway_state",
                    size_bytes=gw_state_path.stat().st_size,
                    sha256=self.calculate_hash(str(gw_state_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Channel directory
            channel_path = hermes_dir / "channel_directory.json"
            if channel_path.exists():
                cf = CollectedFile(
                    original_path=str(channel_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="channel_directory",
                    size_bytes=channel_path.stat().st_size,
                    sha256=self.calculate_hash(str(channel_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # SOUL.md
            soul_path = hermes_dir / "SOUL.md"
            if soul_path.exists():
                cf = CollectedFile(
                    original_path=str(soul_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="soul_prompt",
                    size_bytes=soul_path.stat().st_size,
                    sha256=self.calculate_hash(str(soul_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Memories
            for mem_file in ["MEMORY.md", "USER.md"]:
                mem_path = hermes_dir / "memories" / mem_file
                if mem_path.exists():
                    cf = CollectedFile(
                        original_path=str(mem_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="memory",
                        size_bytes=mem_path.stat().st_size,
                        sha256=self.calculate_hash(str(mem_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Cron jobs
            cron_path = hermes_dir / "cron" / "jobs.json"
            if cron_path.exists():
                cf = CollectedFile(
                    original_path=str(cron_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="cron_jobs",
                    size_bytes=cron_path.stat().st_size,
                    sha256=self.calculate_hash(str(cron_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Cron executions DB
            cron_db_path = hermes_dir / "cron" / "executions.db"
            if cron_db_path.exists():
                cf = CollectedFile(
                    original_path=str(cron_db_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="cron_executions",
                    size_bytes=cron_db_path.stat().st_size,
                    sha256=self.calculate_hash(str(cron_db_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

            # Secrets
            secrets_dir = hermes_dir / "secrets"
            if secrets_dir.exists():
                for secret_file in secrets_dir.iterdir():
                    if secret_file.is_file():
                        cf = CollectedFile(
                            original_path=str(secret_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="secret",
                            size_bytes=secret_file.stat().st_size,
                            sha256=self.calculate_hash(str(secret_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Session files (if --deep)
            if self.deep:
                sessions_dir = hermes_dir / "sessions"
                if sessions_dir.exists():
                    for session_file in sessions_dir.glob("*.jsonl"):
                        cf = CollectedFile(
                            original_path=str(session_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="session_log",
                            size_bytes=session_file.stat().st_size,
                            sha256=self.calculate_hash(str(session_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Skills
            skills_dir = hermes_dir / "skills"
            if skills_dir.exists():
                for skill_dir in skills_dir.iterdir():
                    if skill_dir.is_dir():
                        skill_md = skill_dir / "SKILL.md"
                        if skill_md.exists():
                            cf = CollectedFile(
                                original_path=str(skill_md),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="skill",
                                size_bytes=skill_md.stat().st_size,
                                sha256=self.calculate_hash(str(skill_md)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

            # Profiles
            profiles_dir = hermes_dir / "profiles"
            if profiles_dir.exists():
                for profile_dir in profiles_dir.iterdir():
                    if profile_dir.is_dir():
                        for cfg in profile_dir.glob("*.yaml"):
                            cf = CollectedFile(
                                original_path=str(cfg),
                                source_os=self.detect_os(),
                                platform=self.PLATFORM_NAME,
                                artifact_type="profile_config",
                                size_bytes=cfg.stat().st_size,
                                sha256=self.calculate_hash(str(cfg)),
                                collected_at=self.timestamp(),
                            )
                            collected.append(cf)
                            self.collected_files.append(cf)

            # Logs
            logs_dir = hermes_dir / "logs"
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

            # Gateway PID and lock
            for gw_file in ["gateway.pid", "gateway.lock"]:
                gw_path = hermes_dir / gw_file
                if gw_path.exists():
                    cf = CollectedFile(
                        original_path=str(gw_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="gateway_file",
                        size_bytes=gw_path.stat().st_size,
                        sha256=self.calculate_hash(str(gw_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Webhook subscriptions
            webhook_path = hermes_dir / "webhook_subscriptions.json"
            if webhook_path.exists():
                cf = CollectedFile(
                    original_path=str(webhook_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="webhook_subscriptions",
                    size_bytes=webhook_path.stat().st_size,
                    sha256=self.calculate_hash(str(webhook_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Hermes artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "config":
                try:
                    import yaml
                    with open(cf.original_path) as f:
                        data = yaml.safe_load(f)
                    iocs = []
                    config_str = str(data)
                    if "api_key" in config_str.lower():
                        iocs.append({"type": "api_key_in_config", "detail": "API key found in Hermes config.yaml"})
                    if "password" in config_str.lower():
                        iocs.append({"type": "password_in_config", "detail": "Password found in Hermes config.yaml"})
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=data if isinstance(data, dict) else {"raw": config_str},
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))
                except Exception:
                    pass

            elif cf.artifact_type == "secret":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="secret",
                        severity=Severity.CRITICAL,
                        data={"note": "Secret file found (contents redacted)", "filename": Path(cf.original_path).name},
                        source_file=cf.original_path,
                        iocs=[{"type": "secret_file", "filename": Path(cf.original_path).name}],
                        mitre_atlas=["AML.T0055"],
                    ))

            elif cf.artifact_type == "soul_prompt":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="soul_prompt",
                        severity=Severity.MEDIUM,
                        data={"content_preview": content[:500], "full_length": len(content)},
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "cron_jobs":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="cron_jobs",
                        severity=Severity.MEDIUM,
                        data=data,
                        source_file=cf.original_path,
                        mitre_atlas=["AML.T0048"],
                    ))

            elif cf.artifact_type == "channel_directory":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="channel_directory",
                        severity=Severity.MEDIUM,
                        data=data,
                        source_file=cf.original_path,
                    ))

        return artifacts
