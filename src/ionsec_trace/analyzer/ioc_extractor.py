"""
IOCExtractor — scans collected files for indicators of compromise.
"""

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ionsec_trace.analyzer.secret_detector import SecretDetector
from ionsec_trace.collector.base import Severity


@dataclass
class IOC:
    """An indicator of compromise."""

    ioc_type: str       # ip, url, domain, filepath, command, email, hash, api_key, exfil_pattern
    value: str
    context: str        # surrounding text / description
    platform: str
    source_file: str
    severity: Severity

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s<>\"]+[^\s<>\".]"
)

DOMAIN_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
    r"+(?:com|net|org|io|dev|ai|co|app|xyz|info|biz|edu|gov|mil|me|us|uk|de|fr|ru|cn|jp)\b"
)

# MD5 / SHA1 / SHA256
HASH_PATTERN = re.compile(
    r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

FILE_PATH_PATTERN = re.compile(
    r"(?:(?:/[a-zA-Z0-9_.\-]+)+/[a-zA-Z0-9_.\-]+)"
    r"|(?:[A-Za-z]:\\(?:[^\s\\/:*?\"<>|\r\n]+\\)*[^\s\\/:*?\"<>|\r\n]+)"
)

# API key detection is delegated to the shared SecretDetector (see
# analyzer/secret_detector.py), which owns the rule catalog, entropy gating,
# context-layer matching and false-positive heuristics.
_secret_detector = SecretDetector()

# Suspicious command patterns
SUSPICIOUS_COMMAND_PATTERNS = {
    "rm_rf":        re.compile(r"\brm\s+\-rf\b"),
    "wget":         re.compile(r"\bwget\b"),
    "curl":         re.compile(r"\bcurl\b"),
    "chmod_777":   re.compile(r"\bchmod\s+777\b"),
    "chmod_000":   re.compile(r"\bchmod\s+000\b"),
    "chown_root":  re.compile(r"\bchown\s+root\b"),
    "sudo_rm":     re.compile(r"\bsudo\s+rm\b"),
    "shutdown":    re.compile(r"\bshutdown\b"),
    "reboot":      re.compile(r"\breboot\b"),
    "mkfs":        re.compile(r"\bmkfs\b"),
    "dd_of":       re.compile(r"\bdd\s+.*of=\b"),
    "fork_bomb":   re.compile(r":\(\)\{.*:\|:&\}"),
    "netcat":      re.compile(r"\bnc\s+.*\-[el]\b"),
    "reverse_shell": re.compile(r"/dev/tcp/"),
    "pip_exec":    re.compile(r"\bpip\s+install\b.*\b\-\-exec\b"),
}

# Data exfiltration patterns
EXFIL_PATTERNS = {
    "base64_encode":      re.compile(r"\bbase64\b.*\bencode\b|\bencode\b.*\bbase64\b"),
    "pipe_network":       re.compile(r"\|\s*(?:nc|curl|wget|ssh|scp|telnet)\b"),
    "curl_upload":        re.compile(r"\bcurl\b.*\b(-T|--upload-file)\b"),
    "scp_outbound":       re.compile(r"\bscp\b.*@\b"),
    "dns_exfil":          re.compile(r"\bdig\b.*@\b|\bnslookup\b.*\b"),
    "env_secret_dump":    re.compile(r"\benv\b|\bprintenv\b|\bexport\b.*\b(?:KEY|SECRET|TOKEN|PASSWORD|API)\b", re.IGNORECASE),
}


class IOCExtractor:
    """Scan collected evidence for indicators of compromise."""

    def __init__(self, evidence_dir: str):
        self.evidence_dir = Path(evidence_dir)
        self.iocs: list[IOC] = []
        self._console = Console()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self) -> "IOCExtractor":
        """Run all IOC extraction passes over the evidence directory."""
        self._load_custody_and_scan()
        self._cross_reference()
        return self

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def _load_custody_and_scan(self) -> None:
        """Load chain of custody and scan each referenced file."""
        custody_path = self.evidence_dir / "CHAIN_OF_CUSTODY.json"
        entries: list[dict] = []

        if custody_path.exists():
            try:
                with open(custody_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    entries = data
                elif isinstance(data, dict):
                    entries = data.get("files", data.get("collected_files", []))
            except (json.JSONDecodeError, OSError):
                pass

        if not entries:
            # Walk the directory
            for fpath in sorted(self.evidence_dir.rglob("*")):
                if fpath.is_file() and fpath.name != "CHAIN_OF_CUSTODY.json":
                    rel = fpath.relative_to(self.evidence_dir)
                    platform = rel.parts[0] if rel.parts else "unknown"
                    entries.append({
                        "original_path": str(fpath),
                        "platform": platform,
                        "artifact_type": "unknown",
                    })

        for entry in entries:
            fpath = entry.get("original_path", "")
            platform = entry.get("platform", "unknown")
            self._scan_file(fpath, platform, entry)

    def _scan_file(self, file_path: str, platform: str, entry: dict) -> None:
        """Read and scan a single file for IOCs."""
        p = Path(file_path)
        if not p.exists():
            return
        try:
            if p.stat().st_size > 10 * 1024 * 1024:
                return  # skip huge files
            with open(p, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            return

        self._extract_generic(content, str(p), platform)
        self._extract_api_keys(content, str(p), platform)
        self._extract_commands(content, str(p), platform)
        self._extract_exfil(content, str(p), platform)

    # ------------------------------------------------------------------
    # Generic pattern extraction
    # ------------------------------------------------------------------

    def _extract_generic(self, content: str, source: str, platform: str) -> None:
        """Extract IPs, URLs, domains, hashes, emails, file paths."""
        for match in IP_PATTERN.finditer(content):
            val = match.group()
            # Skip private / loopback
            if val.startswith(("10.", "172.", "192.168.", "127.", "0.")):
                continue
            self._add_ioc("ip", val, content[max(0, match.start()-40):match.end()+40], platform, source, Severity.MEDIUM)

        for match in URL_PATTERN.finditer(content):
            self._add_ioc("url", match.group(), content[max(0, match.start()-30):match.end()+30], platform, source, Severity.MEDIUM)

        for match in DOMAIN_PATTERN.finditer(content):
            val = match.group()
            # Skip common benign domains
            if val.lower() in ("example.com", "localhost.com"):
                continue
            self._add_ioc("domain", val, content[max(0, match.start()-30):match.end()+30], platform, source, Severity.LOW)

        for match in HASH_PATTERN.finditer(content):
            val = match.group()
            hlen = len(val)
            if hlen == 32:
                self._add_ioc("hash_md5", val, content[max(0, match.start()-30):match.end()+30], platform, source, Severity.LOW)
            elif hlen == 40:
                self._add_ioc("hash_sha1", val, content[max(0, match.start()-30):match.end()+30], platform, source, Severity.LOW)
            elif hlen == 64:
                self._add_ioc("hash_sha256", val, content[max(0, match.start()-30):match.end()+30], platform, source, Severity.INFO)

        for match in EMAIL_PATTERN.finditer(content):
            self._add_ioc("email", match.group(), content[max(0, match.start()-30):match.end()+30], platform, source, Severity.LOW)

        for match in FILE_PATH_PATTERN.finditer(content):
            val = match.group()
            if len(val) > 8:  # skip trivial short matches
                self._add_ioc("filepath", val, content[max(0, match.start()-20):match.end()+20], platform, source, Severity.INFO)

    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------

    def _extract_api_keys(self, content: str, source: str, platform: str) -> None:
        for match in _secret_detector.scan(content, source):
            self._add_ioc(
                "api_key", match.redacted,
                match.context or content[:200],
                platform, source, Severity.CRITICAL,
            )

    # ------------------------------------------------------------------
    # Suspicious commands
    # ------------------------------------------------------------------

    def _extract_commands(self, content: str, source: str, platform: str) -> None:
        for pattern in SUSPICIOUS_COMMAND_PATTERNS.values():
            for match in pattern.finditer(content):
                self._add_ioc(
                    "command", match.group(),
                    content[max(0, match.start()-30):match.end()+30],
                    platform, source, Severity.HIGH,
                )

    # ------------------------------------------------------------------
    # Exfiltration patterns
    # ------------------------------------------------------------------

    def _extract_exfil(self, content: str, source: str, platform: str) -> None:
        for pattern in EXFIL_PATTERNS.values():
            for match in pattern.finditer(content):
                self._add_ioc(
                    "exfil_pattern", match.group(),
                    content[max(0, match.start()-30):match.end()+30],
                    platform, source, Severity.CRITICAL,
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add_ioc(self, ioc_type: str, value: str, context: str, platform: str, source_file: str, severity: Severity) -> None:
        """Deduplicate and add an IOC."""
        # Avoid duplicates with same value+type+source
        for existing in self.iocs:
            if existing.value == value and existing.ioc_type == ioc_type and existing.source_file == source_file:
                return
        # Truncate context for readability
        context = context.strip()[:200]
        self.iocs.append(IOC(
            ioc_type=ioc_type,
            value=value,
            context=context,
            platform=platform,
            source_file=source_file,
            severity=severity,
        ))

    # ------------------------------------------------------------------
    # Cross-referencing
    # ------------------------------------------------------------------

    def _cross_reference(self) -> None:
        """Flag IOCs that appear across multiple platforms."""
        # Group by (ioc_type, value)
        seen: dict[tuple[str, str], list[IOC]] = {}
        for ioc in self.iocs:
            key = (ioc.ioc_type, ioc.value)
            seen.setdefault(key, []).append(ioc)

        for group in seen.values():
            platforms = {ioc.platform for ioc in group}
            if len(platforms) > 1:
                # Upgrade severity for cross-platform IOCs
                for ioc in group:
                    if ioc.severity != Severity.CRITICAL:
                        ioc.severity = Severity.HIGH

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        return json.dumps([ioc.to_dict() for ioc in self.iocs], indent=indent, default=str)

    def summary_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ioc in self.iocs:
            counts[ioc.ioc_type] = counts.get(ioc.ioc_type, 0) + 1
        return counts

    def __str__(self) -> str:
        if not self.iocs:
            return "No IOCs found."

        table = Table(title="TRACE IOC Extraction Results", show_lines=True)
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="magenta", max_width=50)
        table.add_column("Platform", style="green")
        table.add_column("Severity", style="red")
        table.add_column("Source", style="dim", max_width=40)

        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "dim",
            Severity.INFO: "dim",
        }

        for ioc in self.iocs:
            sev_style = severity_styles.get(ioc.severity, "white")
            table.add_row(
                ioc.ioc_type,
                ioc.value[:80],
                ioc.platform,
                f"[{sev_style}]{ioc.severity.value}[/{sev_style}]",
                Path(ioc.source_file).name[:40] if ioc.source_file else "-",
            )

        with self._console.capture() as capture:
            self._console.print(table)
        return capture.get()
