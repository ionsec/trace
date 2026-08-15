"""
RiskScorer — calculates risk scores (0-100) per platform and overall.
"""

import json
from dataclasses import asdict, dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ionsec_trace.collector.base import Finding, Severity

# ---------------------------------------------------------------------------
# Risk score data model
# ---------------------------------------------------------------------------

@dataclass
class RiskScore:
    """Computed risk score with category breakdown."""

    score: int                    # 0-100
    severity: str                 # Critical, High, Medium, Low
    category_scores: dict         # {"credentials": 0-25, "exfiltration": 0-25, "jailbreak": 0-25, "autonomy": 0-25}
    recommendations: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _severity_from_score(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

# Per-indicator point values (within each 0-25 category)
CREDENTIAL_INDICATORS = {
    "api_key_exposed": 10,        # Any API key found in plaintext
    "credential_in_config": 5,    # Credentials in config files
    "credential_in_log": 8,       # Credentials appearing in logs
    "shared_credential": 5,       # Same credential across platforms
    "hardcoded_secret": 7,        # Hardcoded passwords/tokens
    "token_leak": 10,             # OAuth tokens, session tokens
}

EXFILTRATION_INDICATORS = {
    "base64_encode": 5,           # Base64 encoding of data
    "pipe_to_network": 10,        # Data piped to network commands
    "curl_upload": 8,             # curl -T or curl --upload-file
    "scp_outbound": 7,            # SCP to external host
    "dns_exfil": 8,               # DNS-based exfiltration
    "env_dump": 6,                # Environment variable dumps
    "clipboard_access": 3,        # Clipboard reads
    "sensitive_file_read": 5,     # Reading /etc/shadow, etc.
}

JAILBREAK_INDICATORS = {
    "jailbreak_prompt": 15,       # Known jailbreak patterns in conversation
    "prompt_injection": 10,       # Prompt injection attempts
    "safety_bypass": 12,          # Safety filter bypasses
    "roleplay_escape": 8,         # Roleplay-based jailbreak
    "encoding_attack": 7,         # Base64/unicode bypass attempts
    "system_prompt_extract": 5,   # Attempts to extract system prompts
}

AUTONOMY_INDICATORS = {
    "agent_autonomous_exec": 15,  # Agent executing without approval
    "tool_chain": 8,              # Chained tool executions
    "file_write": 5,             # Agent writes files
    "code_execution": 10,         # Agent executes code
    "network_access": 7,          # Agent makes network calls
    "privilege_escalation": 10,   # Agent escalates privileges
    "persistent_agent": 5,        # Long-running autonomous agent
}


class RiskScorer:
    """Calculate risk scores (0-100) per platform and overall."""

    def __init__(self):
        self.platform_scores: dict[str, RiskScore] = {}
        self.overall_score: RiskScore | None = None
        self._console = Console()

    # ------------------------------------------------------------------
    # Main scoring methods
    # ------------------------------------------------------------------

    def calculate_platform_risk(
        self,
        platform: str,
        findings: list[Finding],
        iocs: list,
    ) -> RiskScore:
        """Calculate a risk score for a single platform."""
        cred_score = self._score_credentials(findings, iocs)
        exfil_score = self._score_exfiltration(findings, iocs)
        jail_score = self._score_jailbreak(findings, iocs)
        auto_score = self._score_autonomy(findings, iocs)

        total = min(cred_score + exfil_score + jail_score + auto_score, 100)
        recs = self._generate_recommendations(total, cred_score, exfil_score, jail_score, auto_score)

        risk = RiskScore(
            score=total,
            severity=_severity_from_score(total),
            category_scores={
                "credentials": cred_score,
                "exfiltration": exfil_score,
                "jailbreak": jail_score,
                "autonomy": auto_score,
            },
            recommendations=recs,
        )
        self.platform_scores[platform] = risk
        return risk

    def calculate_overall_risk(
        self,
        all_findings: list[Finding],
        all_iocs: list,
    ) -> RiskScore:
        """Calculate an overall risk score across all platforms."""
        # Group by platform
        platforms: dict[str, dict] = {}
        for f in all_findings:
            platforms.setdefault(f.platform, {"findings": [], "iocs": []})
            platforms[f.platform]["findings"].append(f)
        for ioc in all_iocs:
            p = getattr(ioc, "platform", "unknown")
            platforms.setdefault(p, {"findings": [], "iocs": []})
            platforms[p]["iocs"].append(ioc)

        if not platforms:
            self.overall_score = RiskScore(0, "Low", {"credentials": 0, "exfiltration": 0, "jailbreak": 0, "autonomy": 0}, [])
            return self.overall_score

        # Calculate per-platform scores first
        for plat, data in platforms.items():
            self.calculate_platform_risk(plat, data["findings"], data["iocs"])

        # Overall = weighted average (weighted by number of findings)
        total_findings = len(all_findings)
        if total_findings == 0:
            # Use raw IOC count weighting
            total_iocs = len(all_iocs)
            if total_iocs == 0:
                self.overall_score = RiskScore(0, "Low", {"credentials": 0, "exfiltration": 0, "jailbreak": 0, "autonomy": 0}, ["No findings or IOCs detected."])
                return self.overall_score

        # Weighted by finding count per platform
        weighted_score = 0
        total_weight = 0
        merged_categories = {"credentials": 0, "exfiltration": 0, "jailbreak": 0, "autonomy": 0}
        all_recs: list[str] = []

        for plat, risk in self.platform_scores.items():
            weight = len([f for f in all_findings if f.platform == plat]) or 1
            weighted_score += risk.score * weight
            total_weight += weight
            for cat in merged_categories:
                merged_categories[cat] += risk.category_scores.get(cat, 0) * weight
            all_recs.extend(risk.recommendations)

        overall = weighted_score // max(total_weight, 1)
        # Normalize category scores
        for cat, val in merged_categories.items():
            merged_categories[cat] = min(val // max(total_weight, 1), 25)

        self.overall_score = RiskScore(
            score=min(overall, 100),
            severity=_severity_from_score(min(overall, 100)),
            category_scores=merged_categories,
            recommendations=list(dict.fromkeys(all_recs)),  # dedupe, preserve order
        )
        return self.overall_score

    # ------------------------------------------------------------------
    # Category scoring
    # ------------------------------------------------------------------

    def _score_credentials(self, findings: list[Finding], iocs: list) -> int:
        """Score credential exposure (0-25)."""
        score = 0
        f_text = " ".join(f.title + " " + f.description for f in findings).lower()
        ioc_types = {getattr(i, "ioc_type", "") for i in iocs}
        ioc_vals = " ".join(str(getattr(i, "value", "")) for i in iocs).lower()

        if "api_key" in ioc_types:
            score += CREDENTIAL_INDICATORS["api_key_exposed"]
        if any(kw in f_text for kw in ("credential", "api key", "token", "secret")):
            score += CREDENTIAL_INDICATORS["credential_in_config"]
        if any(kw in f_text for kw in ("log", "history")) and any(kw in ioc_vals for kw in ("sk-", "ghp_", "key-")):
            score += CREDENTIAL_INDICATORS["credential_in_log"]
        if any(kw in f_text for kw in ("shared", "reuse", "duplicate")):
            score += CREDENTIAL_INDICATORS["shared_credential"]
        if any(kw in f_text for kw in ("hardcod", "plaintext", "insecure storage")):
            score += CREDENTIAL_INDICATORS["hardcoded_secret"]
        if any(kw in ioc_vals for kw in ("bearer ", "token=", "session=")):
            score += CREDENTIAL_INDICATORS["token_leak"]

        # Boost by finding severity
        for f in findings:
            if f.severity == Severity.CRITICAL and any(kw in f.title.lower() for kw in ("credential", "key", "token")):
                score += 3

        return min(score, 25)

    def _score_exfiltration(self, findings: list[Finding], iocs: list) -> int:
        """Score data exfiltration risk (0-25)."""
        score = 0
        f_text = " ".join(f.title + " " + f.description for f in findings).lower()
        ioc_types = {getattr(i, "ioc_type", "") for i in iocs}
        ioc_vals = " ".join(str(getattr(i, "value", "")) for i in iocs).lower()

        if "exfil_pattern" in ioc_types:
            score += EXFILTRATION_INDICATORS["base64_encode"]
        if any(kw in ioc_vals for kw in ("base64", "encode")):
            score += EXFILTRATION_INDICATORS["base64_encode"]
        if any(kw in ioc_vals for kw in ("| nc", "| curl", "| wget", "| ssh")):
            score += EXFILTRATION_INDICATORS["pipe_to_network"]
        if any(kw in ioc_vals for kw in ("curl", "upload")):
            score += EXFILTRATION_INDICATORS["curl_upload"]
        if any(kw in ioc_vals for kw in ("scp ", "rsync")):
            score += EXFILTRATION_INDICATORS["scp_outbound"]
        if any(kw in ioc_vals for kw in ("dig", "nslookup")):
            score += EXFILTRATION_INDICATORS["dns_exfil"]
        if any(kw in f_text for kw in ("exfiltrat", "data leak", "send data")):
            score += EXFILTRATION_INDICATORS["sensitive_file_read"]
        if any(kw in ioc_vals for kw in ("env", "printenv", "export")):
            score += EXFILTRATION_INDICATORS["env_dump"]

        for f in findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH) and "exfil" in f_text:
                score += 3

        return min(score, 25)

    def _score_jailbreak(self, findings: list[Finding], iocs: list) -> int:
        """Score jailbreak evidence (0-25)."""
        score = 0
        f_text = " ".join(f.title + " " + f.description for f in findings).lower()

        if any(kw in f_text for kw in ("jailbreak", "bypass safety", "safety bypass")):
            score += JAILBREAK_INDICATORS["jailbreak_prompt"]
        if any(kw in f_text for kw in ("prompt injection", "inject", "ignore previous")):
            score += JAILBREAK_INDICATORS["prompt_injection"]
        if any(kw in f_text for kw in ("roleplay", "pretend", "simulate", "dan ")):
            score += JAILBREAK_INDICATORS["roleplay_escape"]
        if any(kw in f_text for kw in ("base64", "unicode", "encoding attack", "obfuscat")):
            score += JAILBREAK_INDICATORS["encoding_attack"]
        if any(kw in f_text for kw in ("system prompt", "instruction extract", "reveal instructions")):
            score += JAILBREAK_INDICATORS["system_prompt_extract"]

        for f in findings:
            if f.severity == Severity.CRITICAL and any(kw in f.title.lower() for kw in ("jailbreak", "injection", "bypass")):
                score += 5
            elif f.severity == Severity.HIGH and any(kw in f.title.lower() for kw in ("jailbreak", "injection", "bypass")):
                score += 3

        return min(score, 25)

    def _score_autonomy(self, findings: list[Finding], iocs: list) -> int:
        """Score agent autonomy risk (0-25)."""
        score = 0
        f_text = " ".join(f.title + " " + f.description for f in findings).lower()
        ioc_types = {getattr(i, "ioc_type", "") for i in iocs}
        " ".join(str(getattr(i, "value", "")) for i in iocs).lower()

        if any(kw in f_text for kw in ("autonomous", "auto-exec", "without approval", "self-directed")):
            score += AUTONOMY_INDICATORS["agent_autonomous_exec"]
        if any(kw in f_text for kw in ("tool chain", "chained", "sequential tool")):
            score += AUTONOMY_INDICATORS["tool_chain"]
        if any(kw in f_text for kw in ("file write", "created file", "modified file")):
            score += AUTONOMY_INDICATORS["file_write"]
        if any(kw in f_text for kw in ("code execution", "executed code", "ran command", "subprocess")):
            score += AUTONOMY_INDICATORS["code_execution"]
        if any(kw in f_text for kw in ("network", "http request", "api call", "outbound")):
            score += AUTONOMY_INDICATORS["network_access"]
        if any(kw in f_text for kw in ("privilege", "escalat", "root", "sudo")):
            score += AUTONOMY_INDICATORS["privilege_escalation"]
        if any(kw in f_text for kw in ("persistent", "daemon", "background", "long-running")):
            score += AUTONOMY_INDICATORS["persistent_agent"]

        # Suspicious commands in IOC also indicate autonomy
        if "command" in ioc_types:
            score += 3

        for f in findings:
            if f.severity == Severity.CRITICAL:
                score += 2

        return min(score, 25)

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self,
        total: int,
        cred: int,
        exfil: int,
        jail: int,
        auto: int,
    ) -> list[str]:
        recs: list[str] = []
        if cred >= 15:
            recs.append("CRITICAL: Rotate all exposed API keys and credentials immediately.")
            recs.append("Implement secrets scanning in CI/CD pipelines.")
        elif cred >= 8:
            recs.append("Review and rotate exposed credentials. Use a secrets manager.")
        elif cred > 0:
            recs.append("Audit credential storage and rotate if necessary.")

        if exfil >= 15:
            recs.append("CRITICAL: Investigate active data exfiltration. Implement network egress controls.")
        elif exfil >= 8:
            recs.append("Review data exfiltration paths. Monitor outbound network traffic.")
        elif exfil > 0:
            recs.append("Review data handling practices for potential exfiltration vectors.")

        if jail >= 15:
            recs.append("CRITICAL: Active jailbreak attempts detected. Harden AI safety guardrails.")
        elif jail >= 8:
            recs.append("Implement prompt injection detection and input sanitization.")
        elif jail > 0:
            recs.append("Review prompt handling and consider additional input filtering.")

        if auto >= 15:
            recs.append("CRITICAL: Highly autonomous agent behavior detected. Implement approval gates.")
        elif auto >= 8:
            recs.append("Add human-in-the-loop controls for agent tool usage.")
        elif auto > 0:
            recs.append("Review agent permission boundaries and tool access.")

        if total >= 90:
            recs.append("IMMEDIATE ACTION: Critical risk level. Conduct full incident response.")
        elif total >= 70:
            recs.append("Urgent: High risk level. Prioritize remediation of top findings.")

        return recs

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def generate_risk_report(self) -> str:
        """Generate a rich-formatted risk report."""
        if not self.platform_scores and not self.overall_score:
            return "No risk scores calculated yet. Run calculate_platform_risk() or calculate_overall_risk() first."

        severity_colors = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
        }

        # Platform scores table
        table = Table(title="TRACE Risk Assessment", show_lines=True)
        table.add_column("Platform", style="cyan", max_width=20)
        table.add_column("Score", style="bold", justify="right")
        table.add_column("Severity", style="bold")
        table.add_column("Credentials", justify="right")
        table.add_column("Exfiltration", justify="right")
        table.add_column("Jailbreak", justify="right")
        table.add_column("Autonomy", justify="right")

        for platform, risk in sorted(self.platform_scores.items()):
            sev_color = severity_colors.get(risk.severity, "white")
            table.add_row(
                platform,
                str(risk.score),
                f"[{sev_color}]{risk.severity}[/{sev_color}]",
                str(risk.category_scores.get("credentials", 0)),
                str(risk.category_scores.get("exfiltration", 0)),
                str(risk.category_scores.get("jailbreak", 0)),
                str(risk.category_scores.get("autonomy", 0)),
            )

        # Overall row
        if self.overall_score:
            o = self.overall_score
            sev_color = severity_colors.get(o.severity, "white")
            table.add_row(
                "[bold]OVERALL[/bold]",
                f"[bold]{o.score}[/bold]",
                f"[{sev_color}][bold]{o.severity}[/bold][/{sev_color}]",
                str(o.category_scores.get("credentials", 0)),
                str(o.category_scores.get("exfiltration", 0)),
                str(o.category_scores.get("jailbreak", 0)),
                str(o.category_scores.get("autonomy", 0)),
            )

        lines = []
        with self._console.capture() as capture:
            self._console.print(table)
        lines.append(capture.get())

        # Recommendations
        if self.overall_score and self.overall_score.recommendations:
            rec_text = "\n".join(f"  • {r}" for r in self.overall_score.recommendations)
            panel = Panel(rec_text, title="Recommendations", border_style="yellow")
            with self._console.capture() as capture:
                self._console.print(panel)
            lines.append(capture.get())

        return "\n".join(lines)

    def to_json(self, indent: int = 2) -> str:
        result = {
            "platform_scores": {k: v.to_dict() for k, v in self.platform_scores.items()},
            "overall_score": self.overall_score.to_dict() if self.overall_score else None,
        }
        return json.dumps(result, indent=indent, default=str)
