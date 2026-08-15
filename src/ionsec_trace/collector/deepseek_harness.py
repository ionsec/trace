"""
DeepSeek Harness (dsh) forensic artifact collector for TRACE.

dsh is DeepSeek's open-source agent harness (github.com/deepseek-ai/deepseek-harness,
npm ``@deepseek-ai/dsh``). It is plugin-composed: everything from the model
provider to the session store is a Cordis plugin, so the on-disk footprint is a
harness home plus whatever plugins the profile enables.

Everything lives under a single root, ``~/.dsh`` by default and ``$DSH_HOME``
when set — the same location on every OS, since the harness resolves it through
Node's ``os.homedir()`` rather than an XDG or AppData convention.

Artifacts collected:

* ``sessions/--<cwd>--/<id>/session.jsonl[.zstd]`` — conversation transcripts.
  Zstandard-compressed by default, one frame per append batch, with a session
  header on the first record. Sub-agent runs are ordinary sessions carrying
  ``origin: 'subagent'`` and a ``parentSession`` reference.
* ``.credentials.yaml`` — provider API keys, a bare YAML mapping (mode 0600).
* ``.env`` — environment-style credential fallback.
* ``settings.yaml`` — harness settings.
* ``cordis.patch.yml`` / ``profiles/<name>/`` — plugin composition, including
  MCP server registrations (dsh has no separate mcpServers.json).
* ``AGENTS.md`` and ``skills/**/SKILL.md`` — instructions the agent was given.
* ``storages/`` — web-surface state.
* ``.anonymous-user-id`` — telemetry identifier correlating endpoint activity.
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


class DeepSeekHarnessCollector(BaseCollector):
    PLATFORM_NAME = "deepseek_harness"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = ["dsh", "dsh-acp-demo"]
    # The web surface binds 127.0.0.1:3080 by default.
    SERVICE_PORTS = [3080]

    # Detection paths only. ~/.agents is a shared skills root — it is collected
    # once dsh is confirmed present, but its presence alone proves nothing.
    LINUX_PATHS = ["~/.dsh"]
    MACOS_PATHS = ["~/.dsh"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.dsh"]

    # Per-run bound on transcripts, mirroring the other conversation collectors.
    MAX_SESSIONS = 500
    # ~/.agents is a *shared* skills root — other agent tools populate it too, so
    # it is collected as dsh-reachable instruction material but kept bounded.
    MAX_SKILLS = 100

    def _harness_homes(self) -> list[Path]:
        """Return every dsh home directory on the endpoint.

        ``$DSH_HOME`` overrides the default when set to a non-blank value, which
        is how the harness itself resolves the root — an investigation that only
        looked at ``~/.dsh`` would miss a relocated home entirely.
        """
        homes: list[Path] = []
        seen: set[str] = set()

        def add(path: Path) -> None:
            resolved = str(path)
            if resolved not in seen:
                seen.add(resolved)
                homes.append(path)

        env_home = os.environ.get("DSH_HOME", "").strip()
        if env_home:
            add(Path(env_home).expanduser())

        for home in self.get_user_home_dirs():
            add(home / ".dsh")

        return homes

    def _skill_roots(self) -> list[Path]:
        """Return the shared skills roots (``$DSH_AGENTS_HOME`` or ``~/.agents``)."""
        roots: list[Path] = []
        env_root = os.environ.get("DSH_AGENTS_HOME", "").strip()
        if env_root:
            roots.append(Path(env_root).expanduser())
        for home in self.get_user_home_dirs():
            roots.append(home / ".agents")
        return roots

    def discover(self) -> bool:
        """Detect whether the DeepSeek Harness is installed or has been used."""
        for harness_home in self._harness_homes():
            if harness_home.exists():
                return True
        return False

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def _record(self, path: Path, artifact_type: str) -> CollectedFile | None:
        """Hash and record one artifact, skipping anything unreadable."""
        try:
            size = path.stat().st_size
            sha256 = self.calculate_hash(str(path))
        except OSError:
            return None

        cf = CollectedFile(
            original_path=str(path),
            source_os=self.detect_os(),
            platform=self.PLATFORM_NAME,
            artifact_type=artifact_type,
            size_bytes=size,
            sha256=sha256,
            collected_at=self.timestamp(),
        )
        self.collected_files.append(cf)
        return cf

    def collect(self) -> list[CollectedFile]:
        """Collect all DeepSeek Harness forensic artifacts."""
        collected: list[CollectedFile] = []

        for harness_home in self._harness_homes():
            if not harness_home.exists():
                continue
            collected.extend(self._collect_config(harness_home))
            collected.extend(self._collect_sessions(harness_home))
            collected.extend(self._collect_instructions(harness_home))

        for skills_root in self._skill_roots():
            if skills_root.exists():
                collected.extend(self._collect_skills(skills_root))

        return collected

    def _collect_config(self, harness_home: Path) -> list[CollectedFile]:
        """Collect settings, credentials and the plugin composition."""
        collected: list[CollectedFile] = []

        # (filename, artifact_type) — credentials first, they matter most.
        singles = [
            (".credentials.yaml", "credential"),
            (".env", "credential"),
            ("settings.yaml", "config"),
            ("settings.json", "config"),
            ("cordis.patch.yml", "config"),
            (".anonymous-user-id", "config"),
        ]
        for name, artifact_type in singles:
            path = harness_home / name
            if path.is_file():
                cf = self._record(path, artifact_type)
                if cf:
                    collected.append(cf)

        # Profiles carry their own composition, including MCP registrations.
        profiles = harness_home / "profiles"
        if profiles.is_dir():
            for path in sorted(profiles.glob("*/*.y*ml")) + sorted(profiles.glob("*/package.json")):
                if path.is_file():
                    cf = self._record(path, "config")
                    if cf:
                        collected.append(cf)

        # Web-surface storage state.
        storages = harness_home / "storages"
        if storages.is_dir():
            for path in sorted(storages.rglob("*.json")):
                if path.is_file():
                    cf = self._record(path, "storage")
                    if cf:
                        collected.append(cf)

        return collected

    def _collect_sessions(self, harness_home: Path) -> list[CollectedFile]:
        """Collect conversation transcripts.

        Layout is ``sessions/--<normalized-cwd>--/<encoded-id>/session.jsonl[.zstd]``,
        so the transcripts sit three levels below the sessions root. Both the
        compressed and uncompressed forms are collected — the harness writes
        ``.zstd`` unless compression is disabled.
        """
        collected: list[CollectedFile] = []
        sessions_root = harness_home / "sessions"
        if not sessions_root.is_dir():
            return collected

        transcripts = sorted(sessions_root.rglob("session.jsonl*"))
        for path in transcripts[: self.MAX_SESSIONS]:
            if path.is_file():
                cf = self._record(path, "conversation")
                if cf:
                    collected.append(cf)

        # The SQLite persistence backend is an alternative to the JSONL one.
        for path in sorted(sessions_root.rglob("*.sqlite")) + sorted(sessions_root.rglob("*.db")):
            if path.is_file():
                cf = self._record(path, "conversation_database")
                if cf:
                    collected.append(cf)

        return collected

    def _collect_instructions(self, harness_home: Path) -> list[CollectedFile]:
        """Collect the instructions the agent was operating under."""
        collected: list[CollectedFile] = []

        agents_md = harness_home / "AGENTS.md"
        if agents_md.is_file():
            cf = self._record(agents_md, "instructions")
            if cf:
                collected.append(cf)

        skills = harness_home / "skills"
        if skills.is_dir():
            collected.extend(self._collect_skills(skills))

        return collected

    def _collect_skills(self, skills_root: Path) -> list[CollectedFile]:
        """Collect SKILL.md definitions — executable instructions for the agent."""
        collected: list[CollectedFile] = []
        for path in sorted(skills_root.rglob("SKILL.md"))[: self.MAX_SKILLS]:
            if path.is_file():
                cf = self._record(path, "instructions")
                if cf:
                    collected.append(cf)
        return collected

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _redact_secret(self, value: str) -> str:
        """Redact a secret, keeping only enough to correlate it."""
        if not value:
            return value
        if len(value) <= 8:
            return "****"
        return f"{value[:4]}...{value[-4:]}"

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected DeepSeek Harness artifacts."""
        artifacts: list[ParsedArtifact] = []

        for cf in self.collected_files:
            name = Path(cf.original_path).name

            if cf.artifact_type == "credential":
                artifacts.append(self._parse_credential(cf, name))

            elif cf.artifact_type == "conversation":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation",
                    severity=Severity.MEDIUM,
                    data={
                        "note": "dsh session transcript",
                        "compressed": name.endswith((".zstd", ".zst")),
                        "session_dir": Path(cf.original_path).parent.name,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0048"],
                ))

            elif cf.artifact_type == "conversation_database":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="conversation_database",
                    severity=Severity.MEDIUM,
                    data={
                        "note": "dsh SQLite session store",
                        "filename": name,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0048"],
                ))

            elif cf.artifact_type == "instructions":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="instructions",
                    severity=Severity.MEDIUM,
                    data={
                        "note": "Agent instructions — defines what the harness was told to do",
                        "filename": name,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0051"],
                ))

            elif cf.artifact_type == "config":
                artifacts.append(self._parse_config(cf, name))

        return artifacts

    def _parse_credential(self, cf: CollectedFile, name: str) -> ParsedArtifact:
        """Parse a credential store, recording which keys exist but never their values."""
        content = self.safe_read_file(cf.original_path) or ""
        keys: list[str] = []
        iocs: list[dict] = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Both forms are `KEY: value` (YAML) or `KEY=value` (dotenv).
            for sep in (":", "="):
                if sep in line:
                    key, _, value = line.partition(sep)
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    if key and value:
                        keys.append(key)
                        iocs.append({
                            "type": "provider_credential",
                            "detail": f"{key} present in {name}",
                            "redacted": self._redact_secret(value),
                        })
                    break

        return ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="credential",
            severity=Severity.CRITICAL if iocs else Severity.INFO,
            data={
                "note": "dsh credential store — provider API keys in cleartext on disk",
                "filename": name,
                "keys": keys,
            },
            source_file=cf.original_path,
            iocs=iocs,
            mitre_atlas=["AML.T0055"],
        )

    def _parse_config(self, cf: CollectedFile, name: str) -> ParsedArtifact:
        """Parse a settings or composition file, flagging MCP servers and secrets."""
        content = self.safe_read_file(cf.original_path) or ""
        lowered = content.lower()
        iocs: list[dict] = []

        if "mcp-client" in lowered or "mcpserver" in lowered:
            iocs.append({
                "type": "mcp_server_registration",
                "detail": f"MCP server registered in {name} — extends the agent's tool reach",
            })
        for marker in ("api_key", "apikey", "token", "secret"):
            if marker in lowered:
                iocs.append({
                    "type": "credential_in_config",
                    "detail": f"Possible credential material in {name}",
                })
                break

        return ParsedArtifact(
            platform=self.PLATFORM_NAME,
            artifact_type="config",
            severity=Severity.HIGH if iocs else Severity.INFO,
            data={
                "note": "dsh configuration",
                "filename": name,
                "size_bytes": cf.size_bytes,
            },
            source_file=cf.original_path,
            iocs=iocs,
        )
