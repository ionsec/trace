"""
Code-level AI scanner collector for TRACE.

Detects shadow-AI usage in source code and project configuration by scanning
for AI framework imports, MCP server registrations, and hardcoded API keys.
This is the "code layer" that static artifact collectors miss — it answers
"is this codebase using AI frameworks, MCP servers, or leaked credentials?"

Inspired by the Marauder Scan layer of PatronAI, but implemented as a
read-only, forensically-sound collector that feeds the same chain-of-custody
and analysis pipeline as every other TRACE collector.
"""

import re
from pathlib import Path

from ionsec_trace.analyzer.secret_detector import SecretDetector
from ionsec_trace.collector.ai_providers import (
    MCP_CONFIG_FILES,
    classify_import,
)
from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class CodeScannerCollector(BaseCollector):
    PLATFORM_NAME = "code_scanner"
    PLATFORM_CATEGORY = PlatformCategory.DEVTOOL
    PROCESS_NAMES = []
    SERVICE_PORTS = []

    # Directories to scan for source code (bounded to avoid huge trees)
    SCAN_DIRS = [
        "~/projects",
        "~/code",
        "~/repos",
        "~/src",
        "~/work",
        "~/Developer",
        "~/development",
        "~/Documents",
    ]

    # File extensions to scan for AI framework imports
    CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}

    # Hardcoded API key detection is delegated to the shared SecretDetector
    # (see analyzer/secret_detector.py), which owns the rule catalog, entropy
    # gating, context-layer matching and false-positive heuristics.
    _secret_detector = SecretDetector()

    def discover(self) -> bool:
        """Code scanning is always available (it inspects source on disk)."""
        return True

    def _scan_dirs(self) -> list[Path]:
        """Return the list of directories to scan (existing ones only)."""
        dirs = []
        for home in self.get_user_home_dirs():
            for d in self.SCAN_DIRS:
                p = Path(d).expanduser()
                if not p.exists():
                    p = home / d.lstrip("~/")
                if p.exists() and p.is_dir():
                    dirs.append(p)
        return dirs

    def _iter_code_files(self, max_files: int = 500) -> list[Path]:
        """Iterate code files across scan dirs, bounded to avoid huge trees."""
        files = []
        for base in self._scan_dirs():
            try:
                for p in base.rglob("*"):
                    if p.is_file() and p.suffix in self.CODE_EXTENSIONS:
                        files.append(p)
                        if len(files) >= max_files:
                            return files
            except (PermissionError, OSError):
                continue
        return files

    def collect(self) -> list[CollectedFile]:
        """Collect code files that contain AI framework usage or MCP configs."""
        collected = []
        code_files = self._iter_code_files()

        for f in code_files:
            content = self.safe_read_file(str(f), max_bytes=512 * 1024)
            if not content:
                continue
            # Only collect files that show AI signals
            if self._has_ai_signal(content, str(f)):
                cf = CollectedFile(
                    original_path=str(f),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="ai_code_file",
                    size_bytes=f.stat().st_size,
                    sha256=self.calculate_hash(str(f)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        # Also collect MCP config files
        for home in self.get_user_home_dirs():
            for rel in MCP_CONFIG_FILES:
                p = home / rel
                if p.is_file():
                    cf = CollectedFile(
                        original_path=str(p),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="mcp_config",
                        size_bytes=p.stat().st_size,
                        sha256=self.calculate_hash(str(p)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        return collected

    def _has_ai_signal(self, content: str, file_path: str = "") -> bool:
        """Return True if the content shows AI framework usage or API keys."""
        # Check for AI framework imports
        for m in re.finditer(r"^\s*(?:from|import)\s+([a-zA-Z0-9_\.]+)", content, re.MULTILINE):
            if classify_import(m.group(1)):
                return True
        # Check for hardcoded API keys
        return bool(self._secret_detector.scan(content, file_path))

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected code files into AI framework / credential findings."""
        artifacts = []
        seen_frameworks: dict[str, dict] = {}
        seen_keys: dict[str, dict] = {}

        for cf in self.collected_files:
            if cf.artifact_type == "mcp_config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="mcp_config",
                        severity=Severity.MEDIUM,
                        data={"path": cf.original_path, "config": data},
                        source_file=cf.original_path,
                        mitre_atlas=["AML.T0048"],  # AI Tool Integration
                    ))
                continue

            if cf.artifact_type != "ai_code_file":
                continue

            content = self.safe_read_file(cf.original_path, max_bytes=512 * 1024)
            if not content:
                continue

            # Detect AI framework imports
            for m in re.finditer(r"^\s*(?:from|import)\s+([a-zA-Z0-9_\.]+)", content, re.MULTILINE):
                info = classify_import(m.group(1))
                if info:
                    key = info["framework"]
                    if key not in seen_frameworks:
                        seen_frameworks[key] = {
                            "framework": info["framework"],
                            "category": info["category"],
                            "files": [],
                        }
                    seen_frameworks[key]["files"].append(cf.original_path)

            # Detect hardcoded API keys (redacted) via the shared detector
            for match in self._secret_detector.scan(content, cf.original_path):
                sig = match.redacted
                if sig not in seen_keys:
                    seen_keys[sig] = {
                        "type": match.secret_type,
                        "redacted": match.redacted,
                        "files": [],
                    }
                seen_keys[sig]["files"].append(cf.original_path)

        # Emit framework findings
        for fw in seen_frameworks.values():
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="ai_framework",
                severity=Severity.MEDIUM,
                data={
                    "framework": fw["framework"],
                    "category": fw["category"],
                    "file_count": len(fw["files"]),
                    "files": fw["files"][:20],
                },
                source_file=fw["files"][0],
                mitre_atlas=["AML.T0048"],  # AI Tool Integration
            ))

        # Emit credential findings
        for key in seen_keys.values():
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="hardcoded_api_key",
                severity=Severity.CRITICAL,
                data={
                    "type": key["type"],
                    "redacted": key["redacted"],
                    "file_count": len(key["files"]),
                    "files": key["files"][:20],
                },
                source_file=key["files"][0],
                iocs=[{
                    "type": "api_key",
                    "detail": f"Hardcoded {key['type']} API key in source code",
                    "value_redacted": key["redacted"],
                }],
                mitre_atlas=["AML.T0055"],  # LLM Credential Theft
            ))

        return artifacts
