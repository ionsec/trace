"""
ATLASMapper — maps TRACE findings and IOCs to MITRE ATLAS techniques.
"""

import json
from dataclasses import asdict, dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ionsec_trace.collector.base import Finding, Severity

# ---------------------------------------------------------------------------
# ATLAS technique catalog
# ---------------------------------------------------------------------------

ATLAS_TECHNIQUES = {
    "AML.T0010": {
        "name": "Prompt Injection",
        "description": "Crafting adversarial prompts to manipulate AI model behavior, bypass safety controls, or extract sensitive information.",
        "platforms": ["inference", "agent", "devtool"],
    },
    "AML.T0011": {
        "name": "LLM Jailbreak",
        "description": "Techniques to bypass LLM safety guardrails and produce disallowed content or actions.",
        "platforms": ["inference", "agent"],
    },
    "AML.T0025": {
        "name": "Modify Model",
        "description": "Tampering with or replacing model weights, configuration, or inference parameters to alter outputs.",
        "platforms": ["inference", "cloud"],
    },
    "AML.T0043": {
        "name": "Craft Adversarial Input",
        "description": "Creating specially crafted inputs designed to trigger unintended model behavior or reveal training data.",
        "platforms": ["inference", "agent", "devtool"],
    },
    "AML.T0048": {
        "name": "AI Tool Integration",
        "description": "Adversary leverages legitimate AI tool integrations (plugins, agents, APIs) as an attack vector.",
        "platforms": ["agent", "devtool"],
    },
    "AML.T0049": {
        "name": "Exploit AI Tool Integration",
        "description": "Exploiting vulnerabilities in AI tool integration points (tool calls, function dispatch, plugin systems).",
        "platforms": ["agent", "devtool"],
    },
    "AML.T0050": {
        "name": "LLM Data Exfiltration",
        "description": "Extracting data from LLM conversations, system prompts, or context windows through various techniques.",
        "platforms": ["inference", "agent"],
    },
    "AML.T0052": {
        "name": "LLM Prompt Leak",
        "description": "Techniques to extract system prompts, few-shot examples, or other privileged instructions from LLMs.",
        "platforms": ["inference", "agent"],
    },
    "AML.T0054": {
        "name": "AI-Generated Content",
        "description": "Using AI-generated content for phishing, social engineering, disinformation, or malware generation.",
        "platforms": ["inference", "agent"],
    },
    "AML.T0055": {
        "name": "LLM Credential Theft",
        "description": "Stealing API keys, tokens, or other credentials used to access AI services.",
        "platforms": ["inference", "agent", "devtool", "cloud"],
    },
}


@dataclass
class ATLASTechniqueMatch:
    """A mapping between evidence and an ATLAS technique."""

    technique_id: str
    technique_name: str
    description: str
    platforms: list[str]
    evidence_summary: str
    severity: Severity
    source_type: str   # "finding" or "ioc"
    source_id: str     # finding.id or IOC value

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class ATLASMapper:
    """Map TRACE findings and IOCs to MITRE ATLAS techniques."""

    def __init__(self):
        self.matches: list[ATLASTechniqueMatch] = []
        self._console = Console()

    # ------------------------------------------------------------------
    # Public mapping API
    # ------------------------------------------------------------------

    def map_finding(self, finding: Finding) -> list[ATLASTechniqueMatch]:
        """Map a single Finding to relevant ATLAS techniques."""
        matches: list[ATLASTechniqueMatch] = []
        f_lower = (finding.title + " " + finding.description).lower()
        self._platform_category(finding.platform)

        # --- Keyword-based mapping ---

        if any(kw in f_lower for kw in ("prompt injection", "prompt inject", "adversarial prompt", "jailbreak", "bypass safety")):
            matches.append(self._make_match("AML.T0010", finding))

        if any(kw in f_lower for kw in ("jailbreak", "bypass guardrail", "bypass safety", "safety bypass")):
            matches.append(self._make_match("AML.T0011", finding))

        if any(kw in f_lower for kw in ("model tamper", "modify model", "model poison", "weight", "config tamper")):
            matches.append(self._make_match("AML.T0025", finding))

        if any(kw in f_lower for kw in ("adversarial input", "craft adversarial", "evasion", "perturbation")):
            matches.append(self._make_match("AML.T0043", finding))

        if any(kw in f_lower for kw in ("tool integration", "plugin", "function call", "agent tool", "mcp")):
            matches.append(self._make_match("AML.T0048", finding))

        if any(kw in f_lower for kw in ("exploit tool", "tool abuse", "tool misuse", "unauthorized tool")):
            matches.append(self._make_match("AML.T0049", finding))

        if any(kw in f_lower for kw in ("exfiltrat", "data leak", "data extract", "send data", "pipe data")):
            matches.append(self._make_match("AML.T0050", finding))

        if any(kw in f_lower for kw in ("prompt leak", "system prompt", "instruction leak", "reveal prompt")):
            matches.append(self._make_match("AML.T0052", finding))

        if any(kw in f_lower for kw in ("phishing", "social engineering", "disinformation", "malware generat", "ai-generated")):
            matches.append(self._make_match("AML.T0054", finding))

        if any(kw in f_lower for kw in ("credential", "api key", "token", "secret", "password", "auth key")):
            matches.append(self._make_match("AML.T0055", finding))

        # --- Severity-based heuristics ---

        if finding.severity in (Severity.CRITICAL, Severity.HIGH) and not matches:
            # High-severity findings with no keyword match still map to most relevant
            matches.append(self._make_match("AML.T0049", finding))

        # --- IOC-based hints from the finding's own IOC list ---

        for ioc_val in finding.iocs:
            ioc_lower = str(ioc_val).lower()
            if any(kw in ioc_lower for kw in ("sk-", "ghp_", "github_pat_", "xai-", "anthropic_", "key-")) and not any(m.technique_id == "AML.T0055" for m in matches):
                matches.append(self._make_match("AML.T0055", finding))
            if any(kw in ioc_lower for kw in ("base64", "exfil", "pipe")) and not any(m.technique_id == "AML.T0050" for m in matches):
                matches.append(self._make_match("AML.T0050", finding))

        # Store and return
        self.matches.extend(matches)
        return matches

    def map_iocs(self, iocs: list) -> list[ATLASTechniqueMatch]:
        """Map IOC objects to ATLAS techniques.

        iocs: list of IOC objects from ioc_extractor (must have ioc_type, value, severity attrs)
        """
        matches: list[ATLASTechniqueMatch] = []

        for ioc in iocs:
            ioc_type = getattr(ioc, "ioc_type", "unknown")
            ioc_val = str(getattr(ioc, "value", ""))
            ioc_sev = getattr(ioc, "severity", Severity.INFO)
            getattr(ioc, "platform", "unknown")

            if ioc_type == "api_key":
                matches.append(ATLASTechniqueMatch(
                    technique_id="AML.T0055",
                    technique_name=ATLAS_TECHNIQUES["AML.T0055"]["name"],
                    description=ATLAS_TECHNIQUES["AML.T0055"]["description"],
                    platforms=ATLAS_TECHNIQUES["AML.T0055"]["platforms"],
                    evidence_summary=f"API key detected: {ioc_val[:12]}...",
                    severity=ioc_sev,
                    source_type="ioc",
                    source_id=ioc_val,
                ))

            elif ioc_type == "exfil_pattern":
                matches.append(ATLASTechniqueMatch(
                    technique_id="AML.T0050",
                    technique_name=ATLAS_TECHNIQUES["AML.T0050"]["name"],
                    description=ATLAS_TECHNIQUES["AML.T0050"]["description"],
                    platforms=ATLAS_TECHNIQUES["AML.T0050"]["platforms"],
                    evidence_summary=f"Exfiltration pattern: {ioc_val}",
                    severity=ioc_sev,
                    source_type="ioc",
                    source_id=ioc_val,
                ))

            elif ioc_type == "command":
                matches.append(ATLASTechniqueMatch(
                    technique_id="AML.T0049",
                    technique_name=ATLAS_TECHNIQUES["AML.T0049"]["name"],
                    description=ATLAS_TECHNIQUES["AML.T0049"]["description"],
                    platforms=ATLAS_TECHNIQUES["AML.T0049"]["platforms"],
                    evidence_summary=f"Suspicious command: {ioc_val}",
                    severity=ioc_sev,
                    source_type="ioc",
                    source_id=ioc_val,
                ))

            elif ioc_type in ("ip", "url", "domain"):
                matches.append(ATLASTechniqueMatch(
                    technique_id="AML.T0048",
                    technique_name=ATLAS_TECHNIQUES["AML.T0048"]["name"],
                    description=ATLAS_TECHNIQUES["AML.T0048"]["description"],
                    platforms=ATLAS_TECHNIQUES["AML.T0048"]["platforms"],
                    evidence_summary=f"Network indicator ({ioc_type}): {ioc_val}",
                    severity=ioc_sev,
                    source_type="ioc",
                    source_id=ioc_val,
                ))

            elif ioc_type in ("filepath",) and any(kw in ioc_val.lower() for kw in ("model", "weight", "checkpoint", ".bin", ".safetensors", ".gguf")):
                # Could indicate model tampering if paths point to model files
                matches.append(ATLASTechniqueMatch(
                        technique_id="AML.T0025",
                        technique_name=ATLAS_TECHNIQUES["AML.T0025"]["name"],
                        description=ATLAS_TECHNIQUES["AML.T0025"]["description"],
                        platforms=ATLAS_TECHNIQUES["AML.T0025"]["platforms"],
                        evidence_summary=f"Model file path: {ioc_val}",
                        severity=ioc_sev,
                        source_type="ioc",
                        source_id=ioc_val,
                    ))

        self.matches.extend(matches)
        return matches

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self) -> str:
        """Generate a structured ATLAS mapping report using rich."""
        if not self.matches:
            return "No ATLAS technique matches found."

        # Deduplicate by technique_id
        by_technique: dict[str, list[ATLASTechniqueMatch]] = {}
        for m in self.matches:
            by_technique.setdefault(m.technique_id, []).append(m)

        # Summary table
        table = Table(title="MITRE ATLAS Technique Mapping", show_lines=True)
        table.add_column("Technique ID", style="cyan", max_width=14)
        table.add_column("Name", style="magenta", max_width=28)
        table.add_column("Severity", style="red")
        table.add_column("Matches", style="green", justify="right")
        table.add_column("Platforms", style="yellow", max_width=30)

        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "dim",
            Severity.INFO: "dim",
        }

        for tid in sorted(by_technique):
            group = by_technique[tid]
            # Use highest severity in group
            sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            top_sev = Severity.INFO
            for s in sev_order:
                if any(m.severity == s for m in group):
                    top_sev = s
                    break
            sev_style = severity_styles.get(top_sev, "white")
            platforms = ", ".join(sorted({p for m in group for p in m.platforms}))
            table.add_row(
                tid,
                group[0].technique_name,
                f"[{sev_style}]{top_sev.value}[/{sev_style}]",
                str(len(group)),
                platforms[:60],
            )

        # Detail panels
        details = []
        for tid in sorted(by_technique):
            group = by_technique[tid]
            info = ATLAS_TECHNIQUES.get(tid, {})
            lines = [
                f"[bold]{tid}: {info.get('name', 'Unknown')}[/bold]",
                f"{info.get('description', '')}",
                "",
                "[bold]Evidence:[/bold]",
            ]
            for m in group:
                lines.append(f"  • [{m.severity.value}] {m.evidence_summary} ({m.source_type}: {m.source_id[:40]})")
            details.append(Panel("\n".join(lines), title=f"{tid} Detail", border_style="blue"))

        with self._console.capture() as capture:
            self._console.print(table)
            for panel in details:
                self._console.print(panel)
        return capture.get()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_match(self, technique_id: str, finding: Finding) -> ATLASTechniqueMatch:
        info = ATLAS_TECHNIQUES.get(technique_id, {})
        return ATLASTechniqueMatch(
            technique_id=technique_id,
            technique_name=info.get("name", technique_id),
            description=info.get("description", ""),
            platforms=info.get("platforms", []),
            evidence_summary=f"{finding.title}: {finding.description[:80]}",
            severity=finding.severity,
            source_type="finding",
            source_id=finding.id,
        )

    @staticmethod
    def _platform_category(platform: str) -> str:
        """Map a platform name to a rough category."""
        p = platform.lower()
        if any(kw in p for kw in ("ollama", "lm_studio", "kobold", "llama", "gpt4all", "huggingface", "text_gen")):
            return "inference"
        if any(kw in p for kw in ("cursor", "claude_code", "aider", "shell_gpt", "hermes")):
            return "devtool"
        if any(kw in p for kw in ("autogpt", "crewai", "agent")):
            return "agent"
        return "cloud"

    def to_json(self, indent: int = 2) -> str:
        return json.dumps([m.to_dict() for m in self.matches], indent=indent, default=str)
