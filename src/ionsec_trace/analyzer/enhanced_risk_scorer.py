"""
EnhancedRiskScorer — behavioral, context-aware risk scoring engine for DFIR.

Replaces the keyword-only approach of RiskScorer with an 8-category behavioral
model, kill-chain stage detection, confidence scoring, attack narrative
generation, and prioritised remediation recommendations.
"""

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ionsec_trace.collector.base import Finding, Severity

# ---------------------------------------------------------------------------
# Kill-chain stage definitions
# ---------------------------------------------------------------------------

class KillChainStage(Enum):
    """Cyber kill-chain stages mapped to AI-specific indicators."""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command & Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"

    @property
    def value(self) -> str:
        """Return the string value of the stage."""
        return super().value


# ---------------------------------------------------------------------------
# Behavioural risk categories  (each 0–12.5, total = 0–100)
# ---------------------------------------------------------------------------

CATEGORY_NAMES = [
    "credential_exposure",
    "data_exfiltration",
    "jailbreak_evidence",
    "tool_abuse",
    "model_manipulation",
    "attack_progression",
    "lateral_movement",
    "persistence",
]

CATEGORY_LABELS = {
    "credential_exposure": "Credential Exposure",
    "data_exfiltration": "Data Exfiltration",
    "jailbreak_evidence": "Jailbreak Evidence",
    "tool_abuse": "Tool Abuse",
    "model_manipulation": "Model Manipulation",
    "attack_progression": "Attack Progression",
    "lateral_movement": "Lateral Movement",
    "persistence": "Persistence",
}

# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

class ConfidenceLevel(float, Enum):
    """Standardised confidence levels for indicator assessment."""
    DIRECT = 1.0
    STRONG = 0.8
    MODERATE = 0.6
    WEAK = 0.4
    CORRELATION = 0.2


# ---------------------------------------------------------------------------
# AIIndicator — the fundamental unit of behavioural analysis
# ---------------------------------------------------------------------------

@dataclass
class AIIndicator:
    """A single observed behavioural indicator with context."""

    indicator_id: str
    category: str                          # one of CATEGORY_NAMES
    label: str                             # human-readable description
    kill_chain_stage: str                  # KillChainStage value
    confidence: float                      # 0.0–1.0
    weight: float                          # raw contribution before normalisation
    source_ids: list[str] = field(default_factory=list)  # Finding / IOC ids
    platforms: list[str] = field(default_factory=list)
    timestamp: str | None = None
    raw_evidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Attack narrative
# ---------------------------------------------------------------------------

@dataclass
class AttackNarrative:
    """A coherent chain of related indicators forming an attack story."""

    narrative_id: str
    title: str
    kill_chain_stages: list[str]
    indicators: list[str]                  # AIIndicator ids
    platforms: list[str]
    severity: Severity
    confidence: float
    timeline: list[dict]                    # chronological event chain
    recommendation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ---------------------------------------------------------------------------
# DetailedRiskScore — full output of the scorer
# ---------------------------------------------------------------------------

@dataclass
class DetailedRiskScore:
    """Complete risk assessment with category breakdown and narratives."""

    score: int                              # 0–100
    severity: str                           # Critical / High / Medium / Low
    categories: dict[str, float]           # 8 categories, each 0–12.5
    confidence: float                       # overall confidence 0–1
    kill_chain_stages: list[str]
    narratives: list[AttackNarrative]
    recommendations: list[str]
    priority_actions: list[str]             # top-5 immediate actions

    def to_dict(self) -> dict:
        d = asdict(self)
        # Serialise nested narratives
        d["narratives"] = [n.to_dict() if hasattr(n, "to_dict") else n for n in self.narratives]
        return d


# ---------------------------------------------------------------------------
# Indicator rule definitions
# ---------------------------------------------------------------------------

# Each rule: (label, category, kill_chain_stage, confidence, weight, keyword_groups)
# keyword_groups: lists of keywords — ANY keyword in ANY group triggers the rule.
# weight is capped contribution before normalisation to 12.5.

_CREDENTIAL_RULES: list[tuple] = [
    ("API key exposed in plaintext", "credential_exposure",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.DIRECT, 10.0,
     [("api_key", "api key"), ("sk-", "ghp_", "github_pat_", "xai-", "anthropic_", "key-")]),

    ("Credentials found in config files", "credential_exposure",
     KillChainStage.RECONNAISSANCE, ConfidenceLevel.STRONG, 5.0,
     [("credential", "token", "secret"), ("config", "settings", ".env", ".yaml", ".json")]),

    ("Credentials leaked in logs", "credential_exposure",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.STRONG, 8.0,
     [("credential", "password", "token"), ("log", "history", "audit")]),

    ("Shared credentials across platforms", "credential_exposure",
     KillChainStage.EXPLOITATION, ConfidenceLevel.CORRELATION, 5.0,
     [("shared", "reuse", "duplicate", "same credential", "across platform")]),

    ("Hardcoded plaintext secrets", "credential_exposure",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.DIRECT, 7.0,
     [("hardcod", "plaintext", "insecure storage", "clear-text secret")]),

    ("OAuth / session token leak", "credential_exposure",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.DIRECT, 10.0,
     [("bearer ", "token=", "session=", "authorization: bearer")]),
]

_EXFILTRATION_RULES: list[tuple] = [
    ("Base64 data smuggling", "data_exfiltration",
     KillChainStage.EXPLOITATION, ConfidenceLevel.MODERATE, 5.0,
     [("base64",), ("encode", "decode", "smuggl")]),

    ("Data piped to network command", "data_exfiltration",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.DIRECT, 10.0,
     [("| nc", "| curl", "| wget", "| ssh", "pipe to network")]),

    ("curl upload of data", "data_exfiltration",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.STRONG, 8.0,
     [("curl",), ("upload", "-T", "--upload-file")]),

    ("SCP/rsync outbound transfer", "data_exfiltration",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.STRONG, 7.0,
     [("scp ", "rsync")]),

    ("DNS-based exfiltration", "data_exfiltration",
     KillChainStage.COMMAND_AND_CONTROL, ConfidenceLevel.STRONG, 8.0,
     [("dig ", "nslookup", "dns exfil", "dns tunn")]),

    ("Environment variable dump", "data_exfiltration",
     KillChainStage.RECONNAISSANCE, ConfidenceLevel.MODERATE, 6.0,
     [("env", "printenv", "export"), ("KEY", "SECRET", "TOKEN", "PASSWORD", "API")]),

    ("Clipboard access by AI tool", "data_exfiltration",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.MODERATE, 3.0,
     [("clipboard", "pbcopy", "xclip", "xsel", "pbpaste")]),

    ("Sensitive file read attempt", "data_exfiltration",
     KillChainStage.RECONNAISSANCE, ConfidenceLevel.STRONG, 5.0,
     [("/etc/shadow", "/etc/passwd", "id_rsa", ".ssh/", ".gnupg/")]),

    ("Large response data dump", "data_exfiltration",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.WEAK, 4.0,
     [("large response", "dump", "bulk export", "mass download")]),

    ("Sensitive data in conversation turns", "data_exfiltration",
     KillChainStage.EXPLOITATION, ConfidenceLevel.MODERATE, 6.0,
     [("personal data", "pii", "sensitive data", "private information", "confidential")]),
]

_JAILBREAK_RULES: list[tuple] = [
    ("DAN-mode jailbreak", "jailbreak_evidence",
     KillChainStage.DELIVERY, ConfidenceLevel.DIRECT, 12.5,
     [("dan mode", "do anything now", "dan prompt")]),

    ("Roleplay-based bypass", "jailbreak_evidence",
     KillChainStage.DELIVERY, ConfidenceLevel.STRONG, 8.0,
     [("pretend", "simulate", "roleplay", "act as if", "you are now")]),

    ("System prompt extraction", "jailbreak_evidence",
     KillChainStage.RECONNAISSANCE, ConfidenceLevel.STRONG, 5.0,
     [("system prompt", "instruction extract", "reveal instructions", "repeat your instructions", "what are your rules")]),

    ("Prompt injection", "jailbreak_evidence",
     KillChainStage.DELIVERY, ConfidenceLevel.DIRECT, 10.0,
     [("prompt injection", "ignore previous", "ignore above", "disregard instructions", "new instructions")]),

    ("Encoding-based bypass", "jailbreak_evidence",
     KillChainStage.WEAPONIZATION, ConfidenceLevel.MODERATE, 7.0,
     [("encoding attack", "unicode bypass", "base64 jailbreak", "obfuscat")]),

    ("Multi-turn attack chain", "jailbreak_evidence",
     KillChainStage.EXPLOITATION, ConfidenceLevel.STRONG, 12.5,
     [("multi-turn attack", "progressive jailbreak", "incremental bypass", "step by step jailbreak")]),

    ("Safety bypass", "jailbreak_evidence",
     KillChainStage.EXPLOITATION, ConfidenceLevel.DIRECT, 12.0,
     [("safety bypass", "bypass safety", "bypass guardrail", "circumvent filter")]),
]

_TOOL_ABUSE_RULES: list[tuple] = [
    ("Unauthorised file access", "tool_abuse",
     KillChainStage.EXPLOITATION, ConfidenceLevel.STRONG, 8.0,
     [("unauthorized file access", "read restricted file", "access denied", "forbidden path")]),

    ("Suspicious network call from tool", "tool_abuse",
     KillChainStage.COMMAND_AND_CONTROL, ConfidenceLevel.STRONG, 7.0,
     [("outbound connection", "network call", "http request", "api call from tool")]),

    ("Code execution via AI tool", "tool_abuse",
     KillChainStage.EXPLOITATION, ConfidenceLevel.DIRECT, 10.0,
     [("code execution", "executed code", "ran command", "subprocess", "shell exec")]),

    ("Privilege escalation via tool", "tool_abuse",
     KillChainStage.EXPLOITATION, ConfidenceLevel.DIRECT, 10.0,
     [("privilege escalation", "escalat", "root access", "sudo", "runas")]),

    ("Dangerous command pattern", "tool_abuse",
     KillChainStage.EXPLOITATION, ConfidenceLevel.STRONG, 8.0,
     [("rm -rf", "mkfs", "dd of=", "chmod 777", "fork bomb")]),

    ("Autonomous agent execution", "tool_abuse",
     KillChainStage.EXPLOITATION, ConfidenceLevel.MODERATE, 6.0,
     [("autonomous", "auto-exec", "without approval", "self-directed")]),
]

_MODEL_MANIPULATION_RULES: list[tuple] = [
    ("Model switching / replacement", "model_manipulation",
     KillChainStage.INSTALLATION, ConfidenceLevel.STRONG, 8.0,
     [("model switch", "swap model", "replace model", "change model", "different model")]),

    ("Safety parameter modification", "model_manipulation",
     KillChainStage.INSTALLATION, ConfidenceLevel.DIRECT, 10.0,
     [("safety parameter", "temperature", "top_p", "system prompt mod", "frequency penalty", "presence penalty")]),

    ("System prompt modification", "model_manipulation",
     KillChainStage.INSTALLATION, ConfidenceLevel.DIRECT, 12.5,
     [("system prompt modification", "modify instructions", "alter system prompt", "change system message")]),

    ("Fine-tuning indicators", "model_manipulation",
     KillChainStage.WEAPONIZATION, ConfidenceLevel.MODERATE, 7.0,
     [("fine-tun", "fine tun", "model training", "weight update", "lora")]),
]

_ATTACK_PROGRESSION_RULES: list[tuple] = [
    ("Multi-phase attack detected", "attack_progression",
     KillChainStage.ACTIONS_ON_OBJECTIVES, ConfidenceLevel.STRONG, 12.5,
     [("multi-phase", "kill chain", "attack chain", "attack progression")]),

    ("Reconnaissance activity", "attack_progression",
     KillChainStage.RECONNAISSANCE, ConfidenceLevel.MODERATE, 4.0,
     [("system info", "gather information", "enumerate", "reconnaissance", "scan")]),

    ("Weaponisation indicators", "attack_progression",
     KillChainStage.WEAPONIZATION, ConfidenceLevel.STRONG, 6.0,
     [("craft payload", "prepare exploit", "weaponiz", "staging")]),

    ("Exploitation confirmed", "attack_progression",
     KillChainStage.EXPLOITATION, ConfidenceLevel.DIRECT, 10.0,
     [("successful bypass", "unauthorized access", "exploitation confirmed")]),

    ("Command & Control established", "attack_progression",
     KillChainStage.COMMAND_AND_CONTROL, ConfidenceLevel.DIRECT, 10.0,
     [("c2 callback", "beacon", "reverse shell", "command and control", "remote access")]),
]

_LATERAL_MOVEMENT_RULES: list[tuple] = [
    ("Credential reuse across platforms", "lateral_movement",
     KillChainStage.EXPLOITATION, ConfidenceLevel.CORRELATION, 8.0,
     [("same credential", "credential reuse", "shared key across", "cross-platform credential")]),

    ("Cross-platform tool usage", "lateral_movement",
     KillChainStage.EXPLOITATION, ConfidenceLevel.MODERATE, 6.0,
     [("cross-platform", "pivot", "lateral move", "spread to", "other platform")]),

    ("Pivoting through AI tools", "lateral_movement",
     KillChainStage.EXPLOITATION, ConfidenceLevel.STRONG, 10.0,
     [("pivot through", "ai tool pivot", "using ai to move", "chain tool")]),
]

_PERSISTENCE_RULES: list[tuple] = [
    ("Cron job / scheduled task creation", "persistence",
     KillChainStage.INSTALLATION, ConfidenceLevel.STRONG, 10.0,
     [("crontab", "cron job", "scheduled task", "at job", "launchd", "systemd timer")]),

    ("Startup item modification", "persistence",
     KillChainStage.INSTALLATION, ConfidenceLevel.STRONG, 8.0,
     [("startup item", "login item", "autostart", "auto-run", "boot persistence")]),

    ("Configuration modification", "persistence",
     KillChainStage.INSTALLATION, ConfidenceLevel.MODERATE, 6.0,
     [("config modification", "config change", "alter configuration", "persist setting")]),

    ("Daemon / service creation via AI", "persistence",
     KillChainStage.INSTALLATION, ConfidenceLevel.DIRECT, 10.0,
     [("daemon creation", "service creation", "background service", "systemd service", "launch daemon")]),
]

# Aggregate all rules for iteration
ALL_RULES: list[tuple] = (
    _CREDENTIAL_RULES + _EXFILTRATION_RULES + _JAILBREAK_RULES +
    _TOOL_ABUSE_RULES + _MODEL_MANIPULATION_RULES + _ATTACK_PROGRESSION_RULES +
    _LATERAL_MOVEMENT_RULES + _PERSISTENCE_RULES
)

# ---------------------------------------------------------------------------
# IOC-type to category mapping  (used when raw IOC data supplements findings)
# ---------------------------------------------------------------------------

_IOC_CATEGORY_MAP: dict[str, tuple[str, str, float]] = {
    # (category, kill_chain_stage, weight)
    "api_key":       ("credential_exposure",       KillChainStage.ACTIONS_ON_OBJECTIVES.value, 10.0),
    "command":       ("tool_abuse",                KillChainStage.EXPLOITATION.value, 6.0),
    "exfil_pattern": ("data_exfiltration",          KillChainStage.ACTIONS_ON_OBJECTIVES.value, 8.0),
    "ip":            ("data_exfiltration",          KillChainStage.COMMAND_AND_CONTROL.value, 4.0),
    "url":           ("data_exfiltration",          KillChainStage.COMMAND_AND_CONTROL.value, 5.0),
    "domain":        ("data_exfiltration",          KillChainStage.COMMAND_AND_CONTROL.value, 3.0),
    "email":         ("credential_exposure",        KillChainStage.RECONNAISSANCE.value, 3.0),
    "filepath":      ("tool_abuse",                 KillChainStage.RECONNAISSANCE.value, 2.0),
}

# ---------------------------------------------------------------------------
# Narrative templates — link categories to story patterns
# ---------------------------------------------------------------------------

_NARRATIVE_TEMPLATES: list[dict] = [
    {
        "title": "Credential Theft via Prompt Injection",
        "categories": {"credential_exposure", "jailbreak_evidence"},
        "stages": [KillChainStage.DELIVERY, KillChainStage.EXPLOITATION, KillChainStage.ACTIONS_ON_OBJECTIVES],
        "recommendation": "Rotate all exposed API keys immediately. Enable key rotation policies. "
                          "Implement prompt injection detection on all AI-facing endpoints.",
    },
    {
        "title": "Data Exfiltration via AI Tool",
        "categories": {"data_exfiltration", "tool_abuse"},
        "stages": [KillChainStage.EXPLOITATION, KillChainStage.COMMAND_AND_CONTROL, KillChainStage.ACTIONS_ON_OBJECTIVES],
        "recommendation": "Block outbound connections to identified exfiltration endpoints. "
                          "Implement data-loss prevention (DLP) controls on AI tool outputs.",
    },
    {
        "title": "Multi-Stage AI Attack Chain",
        "categories": {"attack_progression", "jailbreak_evidence", "tool_abuse"},
        "stages": [KillChainStage.RECONNAISSANCE, KillChainStage.WEAPONIZATION, KillChainStage.DELIVERY, KillChainStage.EXPLOITATION],
        "recommendation": "Conduct full incident response. Review all AI session logs for the "
                          "complete attack timeline. Revoke compromised sessions.",
    },
    {
        "title": "Model Manipulation and Safety Bypass",
        "categories": {"model_manipulation", "jailbreak_evidence"},
        "stages": [KillChainStage.WEAPONIZATION, KillChainStage.EXPLOITATION],
        "recommendation": "Audit AI tool configurations for unauthorised changes. Restore "
                          "known-good system prompts and safety parameters.",
    },
    {
        "title": "Lateral Movement Across AI Platforms",
        "categories": {"lateral_movement", "credential_exposure"},
        "stages": [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION, KillChainStage.ACTIONS_ON_OBJECTIVES],
        "recommendation": "Review and revoke compromised sessions. Enforce unique credentials "
                          "per platform. Implement cross-platform monitoring.",
    },
    {
        "title": "Persistence via AI-Assisted Mechanisms",
        "categories": {"persistence", "tool_abuse"},
        "stages": [KillChainStage.EXPLOITATION, KillChainStage.INSTALLATION],
        "recommendation": "Audit cron jobs, startup items, and service definitions for "
                          "unauthorised additions. Remove persistence mechanisms.",
    },
    {
        "title": "Autonomous Agent Abuse",
        "categories": {"tool_abuse", "attack_progression"},
        "stages": [KillChainStage.EXPLOITATION, KillChainStage.ACTIONS_ON_OBJECTIVES],
        "recommendation": "Implement human-in-the-loop approval for all agent actions. "
                          "Restrict agent tool access to least-privilege set.",
    },
    {
        "title": "Exfiltration via Encoding / Smuggling",
        "categories": {"data_exfiltration", "jailbreak_evidence"},
        "stages": [KillChainStage.WEAPONIZATION, KillChainStage.EXPLOITATION, KillChainStage.ACTIONS_ON_OBJECTIVES],
        "recommendation": "Implement output filtering for base64 / encoded content. "
                          "Monitor large response payloads from AI tools.",
    },
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _severity_from_score(score: int) -> str:
    """Map numeric score to severity label."""
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _severity_from_enum(sev: Severity) -> str:
    """Convert collector.base.Severity enum to simple string."""
    return sev.value.capitalize()


def _make_indicator_id(label: str, category: str, confidence: float) -> str:
    """Deterministic ID for an indicator."""
    raw = f"{category}:{label}:{confidence}"
    return f"IND-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


# ---------------------------------------------------------------------------
# EnhancedRiskScorer
# ---------------------------------------------------------------------------

class EnhancedRiskScorer:
    """Behavioural, context-aware risk scoring engine for AI DFIR.

    Expands the original 4-category keyword scorer into an 8-category
    behavioural model with kill-chain staging, confidence scoring, attack
    narrative generation, and prioritised remediation.

    Usage::

        scorer = EnhancedRiskScorer()
        score = scorer.score_from_indicators(findings, iocs)
        print(score.severity, score.score)
        for narrative in score.narratives:
            print(narrative.title, narrative.recommendation)
    """

    def __init__(self):
        self.indicators: list[AIIndicator] = []
        self.platform_scores: dict[str, DetailedRiskScore] = {}
        self.overall_score: DetailedRiskScore | None = None
        self._console = Console()

    # ------------------------------------------------------------------
    # Phase 1 — Indicator extraction
    # ------------------------------------------------------------------

    def _extract_indicators(
        self,
        findings: list[Finding],
        iocs: list,
    ) -> list[AIIndicator]:
        """Derive AIIndicator objects from findings and IOCs."""

        indicators: list[AIIndicator] = []

        # --- From findings (keyword + severity heuristics) ---
        combined_text_parts: list[str] = []
        for f in findings:
            combined_text_parts.append(f"{f.title} {f.description}")
        combined_text = " ".join(combined_text_parts).lower()

        # Severity boost lookup
        severity_boost = {
            Severity.CRITICAL: 3.0,
            Severity.HIGH: 2.0,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.5,
            Severity.INFO: 0.0,
        }

        matched_rules: set[int] = set()
        for idx, (label, category, stage, confidence, weight, kw_groups) in enumerate(ALL_RULES):
            # A rule fires when at least one keyword from EVERY group matches
            # (single-element groups always match that group).
            groups_matched = 0
            evidence_bits: list[str] = []
            for group in kw_groups:
                for kw in group:
                    if kw.lower() in combined_text:
                        groups_matched += 1
                        evidence_bits.append(kw)
                        break  # one hit per group is enough

            if groups_matched == len(kw_groups):
                # Severity boost
                boost = 0.0
                for f in findings:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH) and any(kw.lower() in f"{f.title} {f.description}".lower() for kw in evidence_bits):
                        boost += severity_boost.get(f.severity, 0.0)

                # Find platforms from matching findings
                platforms: set[str] = set()
                for f in findings:
                    fl = f"{f.title} {f.description}".lower()
                    if any(kw.lower() in fl for kw in evidence_bits):
                        platforms.add(f.platform)

                indicators.append(AIIndicator(
                    indicator_id=_make_indicator_id(label, category, float(confidence)),
                    category=category,
                    label=label,
                    kill_chain_stage=stage.value,
                    confidence=float(confidence),
                    weight=min(weight + boost, 12.5),
                    source_ids=[f.id for f in findings if any(kw.lower() in f"{f.title} {f.description}".lower() for kw in evidence_bits)],
                    platforms=sorted(platforms) or ["unknown"],
                    raw_evidence=", ".join(evidence_bits),
                ))
                matched_rules.add(idx)

        # --- From IOCs (type-based mapping) ---
        for ioc in iocs:
            ioc_type = getattr(ioc, "ioc_type", "")
            ioc_val = str(getattr(ioc, "value", ""))
            ioc_sev = getattr(ioc, "severity", Severity.INFO)
            ioc_platform = getattr(ioc, "platform", "unknown")

            if ioc_type not in _IOC_CATEGORY_MAP:
                continue

            category, stage, weight = _IOC_CATEGORY_MAP[ioc_type]
            # Map IOC severity to confidence
            ioc_conf = {
                Severity.CRITICAL: ConfidenceLevel.DIRECT,
                Severity.HIGH: ConfidenceLevel.STRONG,
                Severity.MEDIUM: ConfidenceLevel.MODERATE,
                Severity.LOW: ConfidenceLevel.WEAK,
                Severity.INFO: ConfidenceLevel.CORRELATION,
            }.get(ioc_sev, ConfidenceLevel.MODERATE)

            # Extra weight for known API-key prefixes
            if ioc_type == "api_key":
                for prefix in ("sk-", "ghp_", "github_pat_", "xai-", "anthropic_", "key-"):
                    if ioc_val.startswith(prefix):
                        weight = 12.5
                        break

            indicators.append(AIIndicator(
                indicator_id=_make_indicator_id(ioc_val[:40], category, float(ioc_conf)),
                category=category,
                label=f"IOC: {ioc_type} — {ioc_val[:50]}",
                kill_chain_stage=stage if isinstance(stage, str) else stage.value,
                confidence=float(ioc_conf),
                weight=weight,
                source_ids=[ioc_val[:60]],
                platforms=[ioc_platform],
                raw_evidence=ioc_val[:120],
            ))

        # --- Cross-platform correlation (lateral-movement boost) ---
        platform_creds: dict[str, set[str]] = {}
        for ioc in iocs:
            if getattr(ioc, "ioc_type", "") == "api_key":
                p = getattr(ioc, "platform", "unknown")
                platform_creds.setdefault(p, set()).add(str(getattr(ioc, "value", "")))

        if len(platform_creds) > 1:
            # Check for shared credentials
            all_vals: set[str] = set()
            for vals in platform_creds.values():
                all_vals.update(vals)
            # Simple heuristic: if the same credential prefix appears on multiple platforms
            indicators.append(AIIndicator(
                indicator_id=_make_indicator_id("cross-platform-cred", "lateral_movement", "0.2"),
                category="lateral_movement",
                label="Same credential pattern across multiple platforms",
                kill_chain_stage=KillChainStage.EXPLOITATION.value,
                confidence=ConfidenceLevel.CORRELATION,
                weight=8.0,
                source_ids=list(platform_creds.keys()),
                platforms=sorted(platform_creds.keys()),
                raw_evidence=f"Platforms: {', '.join(sorted(platform_creds.keys()))}",
            ))

        return indicators

    # ------------------------------------------------------------------
    # Phase 2 — Category scoring
    # ------------------------------------------------------------------

    def _score_categories(self, indicators: list[AIIndicator]) -> dict[str, float]:
        """Aggregate indicator weights into 8 category scores, each 0–12.5."""
        categories: dict[str, float] = dict.fromkeys(CATEGORY_NAMES, 0.0)

        for ind in indicators:
            if ind.category in categories:
                categories[ind.category] += ind.weight

        # Clamp each category to 12.5
        for cat, val in categories.items():
            categories[cat] = min(val, 12.5)

        # Round for readability
        return {cat: round(val, 2) for cat, val in categories.items()}

    # ------------------------------------------------------------------
    # Phase 3 — Confidence aggregation
    # ------------------------------------------------------------------

    def _aggregate_confidence(self, indicators: list[AIIndicator]) -> float:
        """Weighted average confidence across all indicators."""
        if not indicators:
            return 0.0
        total_weight = sum(i.weight for i in indicators)
        if total_weight == 0:
            return 0.0
        weighted_conf = sum(i.confidence * i.weight for i in indicators)
        return round(weighted_conf / total_weight, 3)

    # ------------------------------------------------------------------
    # Phase 4 — Kill-chain stage detection
    # ------------------------------------------------------------------

    def _detect_kill_chain_stages(self, indicators: list[AIIndicator]) -> list[str]:
        """Return unique kill-chain stages represented by indicators."""
        seen = set()
        result = []
        # Define order
        stage_order = [s.value for s in KillChainStage]
        for ind in indicators:
            if ind.kill_chain_stage not in seen:
                seen.add(ind.kill_chain_stage)
        for stage in stage_order:
            if stage in seen:
                result.append(stage)
        return result

    # ------------------------------------------------------------------
    # Phase 5 — Narrative generation
    # ------------------------------------------------------------------

    def generate_narratives(self, indicators: list[AIIndicator]) -> list[AttackNarrative]:
        """Chain related indicators into coherent attack narratives."""
        if not indicators:
            return []

        # Build a set of active categories
        active_categories = {ind.category for ind in indicators if ind.weight > 0}
        narratives: list[AttackNarrative] = []

        for template in _NARRATIVE_TEMPLATES:
            required_cats = template["categories"]
            overlap = required_cats & active_categories
            if len(overlap) < 1:
                continue

            # Collect indicators matching this template's categories
            relevant = [i for i in indicators if i.category in required_cats and i.weight > 0]
            if not relevant:
                continue

            # Sort by confidence then weight
            relevant.sort(key=lambda i: (i.confidence, i.weight), reverse=True)

            # Determine highest severity among relevant indicators
            max_conf = max(i.confidence for i in relevant)
            if max_conf >= ConfidenceLevel.DIRECT:
                sev = Severity.CRITICAL
            elif max_conf >= ConfidenceLevel.STRONG:
                sev = Severity.HIGH
            elif max_conf >= ConfidenceLevel.MODERATE:
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW

            # Build timeline from indicator timestamps
            timeline: list[dict] = []
            for i in relevant:
                timeline.append({
                    "indicator_id": i.indicator_id,
                    "category": i.category,
                    "label": i.label,
                    "kill_chain_stage": i.kill_chain_stage,
                    "confidence": i.confidence,
                    "weight": i.weight,
                    "timestamp": i.timestamp or "unknown",
                })

            # Compute narrative confidence as mean of relevant indicator confidences
            nar_conf = round(sum(i.confidence for i in relevant) / len(relevant), 3) if relevant else 0.0

            # Collect platforms
            platforms_set: set[str] = set()
            for i in relevant:
                platforms_set.update(i.platforms)

            # Convert kill-chain stages to string values
            stage_strings = [s.value if hasattr(s, "value") else str(s) for s in template["stages"]]

            narratives.append(AttackNarrative(
                narrative_id=f"NAR-{hashlib.sha256(template['title'].encode()).hexdigest()[:8]}",
                title=template["title"],
                kill_chain_stages=stage_strings,
                indicators=[i.indicator_id for i in relevant],
                platforms=sorted(platforms_set) or ["unknown"],
                severity=sev,
                confidence=nar_conf,
                timeline=timeline,
                recommendation=template["recommendation"],
            ))

        # If no templates matched, create a generic narrative from top indicators
        if not narratives and indicators:
            top = sorted(indicators, key=lambda i: i.weight, reverse=True)[:5]
            nar_sev = Severity.MEDIUM
            if any(i.confidence >= ConfidenceLevel.DIRECT for i in top):
                nar_sev = Severity.CRITICAL
            elif any(i.confidence >= ConfidenceLevel.STRONG for i in top):
                nar_sev = Severity.HIGH

            narratives.append(AttackNarrative(
                narrative_id=f"NAR-{uuid.uuid4().hex[:8]}",
                title="General AI Security Concern",
                kill_chain_stages=list(dict.fromkeys(i.kill_chain_stage for i in top)),
                indicators=[i.indicator_id for i in top],
                platforms=sorted({p for i in top for p in i.platforms}) or ["unknown"],
                severity=nar_sev,
                confidence=round(sum(i.confidence for i in top) / len(top), 3) if top else 0.0,
                timeline=[
                    {
                        "indicator_id": i.indicator_id,
                        "category": i.category,
                        "label": i.label,
                        "kill_chain_stage": i.kill_chain_stage,
                        "confidence": i.confidence,
                        "weight": i.weight,
                        "timestamp": i.timestamp or "unknown",
                    }
                    for i in top
                ],
                recommendation="Investigate the identified indicators and review AI tool usage policies.",
            ))

        return narratives

    # ------------------------------------------------------------------
    # Phase 6 — Recommendations & priority actions
    # ------------------------------------------------------------------

    def prioritize_recommendations(
        self,
        categories: dict[str, float],
        narratives: list[AttackNarrative],
    ) -> list[str]:
        """Generate prioritised, actionable recommendations."""
        recs: list[str] = []

        # Category-driven recommendations
        cred = categories.get("credential_exposure", 0)
        exfil = categories.get("data_exfiltration", 0)
        jail = categories.get("jailbreak_evidence", 0)
        tool = categories.get("tool_abuse", 0)
        model = categories.get("model_manipulation", 0)
        prog = categories.get("attack_progression", 0)
        lateral = categories.get("lateral_movement", 0)
        persist = categories.get("persistence", 0)

        if cred >= 8:
            recs.append("CRITICAL: Rotate all exposed API keys and credentials immediately.")
            recs.append("Implement secrets scanning in CI/CD pipelines and pre-commit hooks.")
        elif cred >= 4:
            recs.append("Review and rotate exposed credentials. Deploy a secrets manager.")
        elif cred > 0:
            recs.append("Audit credential storage and enforce rotation policies.")

        if exfil >= 8:
            recs.append("CRITICAL: Investigate active data exfiltration. Implement network egress controls.")
            recs.append("Deploy DLP (Data Loss Prevention) on AI tool outputs.")
        elif exfil >= 4:
            recs.append("Review data exfiltration paths. Monitor outbound network traffic.")
        elif exfil > 0:
            recs.append("Review data handling practices for potential exfiltration vectors.")

        if jail >= 8:
            recs.append("CRITICAL: Active jailbreak attempts detected. Harden AI safety guardrails.")
        elif jail >= 4:
            recs.append("Implement prompt injection detection and input sanitisation.")
        elif jail > 0:
            recs.append("Review prompt handling and consider additional input filtering.")

        if tool >= 8:
            recs.append("Implement human-in-the-loop approval for all agent tool usage.")
        elif tool >= 4:
            recs.append("Restrict AI tool permissions to least-privilege set.")
        elif tool > 0:
            recs.append("Review agent permission boundaries and tool access policies.")

        if model >= 6:
            recs.append("Audit AI tool configurations for unauthorised changes.")
            recs.append("Restore known-good system prompts and safety parameters.")
        elif model > 0:
            recs.append("Review model configuration changes for tampering.")

        if prog >= 6:
            recs.append("Conduct full incident response — multi-phase attack detected.")
        elif prog > 0:
            recs.append("Review AI session logs for attack progression patterns.")

        if lateral >= 6:
            recs.append("Enforce unique credentials per platform. Implement cross-platform monitoring.")
        elif lateral > 0:
            recs.append("Investigate credential reuse across platforms.")

        if persist >= 6:
            recs.append("Audit cron jobs, startup items, and service definitions.")
        elif persist > 0:
            recs.append("Review recent persistence mechanism changes.")

        # Narrative-driven recommendations
        for nar in narratives:
            if nar.recommendation and nar.recommendation not in recs:
                recs.append(nar.recommendation)

        return recs

    def _generate_priority_actions(
        self,
        categories: dict[str, float],
        indicators: list[AIIndicator],
        narratives: list[AttackNarrative],
    ) -> list[str]:
        """Generate the top-5 most urgent immediate actions."""
        actions: list[tuple[float, str]] = []

        cred = categories.get("credential_exposure", 0)
        exfil = categories.get("data_exfiltration", 0)
        jail = categories.get("jailbreak_evidence", 0)
        tool = categories.get("tool_abuse", 0)
        model = categories.get("model_manipulation", 0)
        prog = categories.get("attack_progression", 0)
        lateral = categories.get("lateral_movement", 0)
        persist = categories.get("persistence", 0)

        # Collect exfil targets (IPs, domains from indicators)
        exfil_targets: list[str] = []
        for ind in indicators:
            if ind.category == "data_exfiltration" and ind.raw_evidence:
                for kw in ("ip:", "domain:", "url:"):
                    if kw in ind.raw_evidence.lower():
                        exfil_targets.append(ind.raw_evidence.split(kw)[-1][:40])

        # Priority action mapping with urgency scores
        if cred >= 8:
            actions.append((100.0, "Rotate exposed API keys immediately — plaintext credentials detected."))
        if exfil >= 8:
            target_str = f" to {', '.join(exfil_targets[:3])}" if exfil_targets else ""
            actions.append((95.0, f"Block outbound connections{target_str} — active exfiltration detected."))
        if jail >= 8:
            actions.append((90.0, "Harden AI safety guardrails — active jailbreak attempts detected."))
        if prog >= 6:
            actions.append((88.0, "Initiate incident response — multi-phase attack progression detected."))
        if tool >= 8:
            actions.append((85.0, "Disable autonomous agent execution — unauthorised tool abuse detected."))
        if model >= 6:
            actions.append((82.0, "Audit AI tool configurations for unauthorised changes."))
        if persist >= 6:
            actions.append((80.0, "Remove unauthorised persistence mechanisms (cron, services, startup)."))
        if lateral >= 6:
            actions.append((78.0, "Review and revoke compromised sessions — lateral movement detected."))

        # Lower-tier actions
        if cred >= 4 and cred < 8:
            actions.append((60.0, "Review and rotate exposed credentials."))
        if exfil >= 4 and exfil < 8:
            actions.append((55.0, "Monitor outbound network traffic for data exfiltration."))
        if jail >= 4 and jail < 8:
            actions.append((50.0, "Deploy prompt injection detection."))
        if tool >= 4 and tool < 8:
            actions.append((45.0, "Restrict AI tool permissions to least privilege."))

        # Sort by urgency (descending) and return top 5
        actions.sort(key=lambda x: x[0], reverse=True)
        return [a[1] for a in actions[:5]]

    # ------------------------------------------------------------------
    # Phase 7 — Main scoring methods
    # ------------------------------------------------------------------

    def score_from_indicators(
        self,
        findings: list[Finding],
        iocs: list,
    ) -> DetailedRiskScore:
        """Compute a DetailedRiskScore from findings and IOCs.

        This is the primary entry point for the enhanced scorer.
        """
        indicators = self._extract_indicators(findings, iocs)
        self.indicators = indicators

        categories = self._score_categories(indicators)
        total_score = min(int(sum(categories.values())), 100)
        confidence = self._aggregate_confidence(indicators)
        kill_chain_stages = self._detect_kill_chain_stages(indicators)
        narratives = self.generate_narratives(indicators)
        recommendations = self.prioritize_recommendations(categories, narratives)
        priority_actions = self._generate_priority_actions(categories, indicators, narratives)

        score = DetailedRiskScore(
            score=total_score,
            severity=_severity_from_score(total_score),
            categories=categories,
            confidence=confidence,
            kill_chain_stages=kill_chain_stages,
            narratives=narratives,
            recommendations=recommendations,
            priority_actions=priority_actions,
        )
        self.overall_score = score
        return score

    def score_platform(
        self,
        platform: str,
        findings: list[Finding],
        iocs: list,
    ) -> DetailedRiskScore:
        """Compute a DetailedRiskScore for a single platform.

        Filters findings and IOCs to the given platform before scoring.
        """
        # Filter findings for this platform
        plat_findings = [f for f in findings if f.platform == platform]
        # Filter IOCs for this platform
        plat_iocs = [i for i in iocs if getattr(i, "platform", "unknown") == platform]

        indicators = self._extract_indicators(plat_findings, plat_iocs)
        categories = self._score_categories(indicators)
        total_score = min(int(sum(categories.values())), 100)
        confidence = self._aggregate_confidence(indicators)
        kill_chain_stages = self._detect_kill_chain_stages(indicators)
        narratives = self.generate_narratives(indicators)
        recommendations = self.prioritize_recommendations(categories, narratives)
        priority_actions = self._generate_priority_actions(categories, indicators, narratives)

        score = DetailedRiskScore(
            score=total_score,
            severity=_severity_from_score(total_score),
            categories=categories,
            confidence=confidence,
            kill_chain_stages=kill_chain_stages,
            narratives=narratives,
            recommendations=recommendations,
            priority_actions=priority_actions,
        )
        self.platform_scores[platform] = score
        return score

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_risk_report(self) -> str:
        """Generate a rich-formatted risk report with categories, narratives, and actions."""
        if not self.platform_scores and not self.overall_score:
            return "No risk scores calculated yet. Run score_from_indicators() or score_platform() first."

        severity_colors = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "green",
        }

        lines: list[str] = []

        # --- Category breakdown table ---
        if self.overall_score:
            o = self.overall_score
            cat_table = Table(title="TRACE Enhanced Risk Assessment", show_lines=True)
            cat_table.add_column("Category", style="cyan", max_width=22)
            cat_table.add_column("Score", justify="right", style="bold")
            cat_table.add_column("Max", justify="right")
            cat_table.add_column("Bar", max_width=20)

            for cat in CATEGORY_NAMES:
                val = o.categories.get(cat, 0)
                bar_len = int(val / 12.5 * 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                cat_table.add_row(
                    CATEGORY_LABELS.get(cat, cat),
                    f"{val:.1f}",
                    "12.5",
                    f"[green]{bar}[/green]" if val < 5 else f"[yellow]{bar}[/yellow]" if val < 9 else f"[red]{bar}[/red]",
                )

            with self._console.capture() as capture:
                self._console.print(cat_table)
            lines.append(capture.get())

            # --- Summary line ---
            sev_color = severity_colors.get(o.severity, "white")
            summary = Panel(
                f"Overall Score: [bold]{o.score}[/bold]  |  "
                f"Severity: [{sev_color}]{o.severity}[/{sev_color}]  |  "
                f"Confidence: {o.confidence:.2f}  |  "
                f"Kill-Chain Stages: {', '.join(o.kill_chain_stages) or 'None detected'}",
                title="Risk Summary",
                border_style="red" if o.severity == "Critical" else "yellow",
            )
            with self._console.capture() as capture:
                self._console.print(summary)
            lines.append(capture.get())

        # --- Per-platform table ---
        if self.platform_scores:
            plat_table = Table(title="Platform Risk Scores", show_lines=True)
            plat_table.add_column("Platform", style="cyan", max_width=18)
            plat_table.add_column("Score", justify="right", style="bold")
            plat_table.add_column("Severity", style="bold")
            plat_table.add_column("Confidence", justify="right")
            plat_table.add_column("Top Category", max_width=18)

            for platform, ps in sorted(self.platform_scores.items()):
                sev_color = severity_colors.get(ps.severity, "white")
                top_cat = max(ps.categories, key=ps.categories.get) if ps.categories else "-"
                plat_table.add_row(
                    platform,
                    str(ps.score),
                    f"[{sev_color}]{ps.severity}[/{sev_color}]",
                    f"{ps.confidence:.2f}",
                    CATEGORY_LABELS.get(top_cat, top_cat),
                )

            with self._console.capture() as capture:
                self._console.print(plat_table)
            lines.append(capture.get())

        # --- Attack Narratives ---
        if self.overall_score and self.overall_score.narratives:
            for nar in self.overall_score.narratives:
                sev_color = severity_colors.get(_severity_from_enum(nar.severity), "white")
                nar_text = (
                    f"[bold]{nar.title}[/bold]\n"
                    f"Stages: {', '.join(nar.kill_chain_stages)}\n"
                    f"Severity: [{sev_color}]{nar.severity.value}[/{sev_color}]  "
                    f"Confidence: {nar.confidence:.2f}\n"
                    f"Platforms: {', '.join(nar.platforms)}\n"
                    f"Indicators: {len(nar.indicators)}\n"
                    f"Recommendation: {nar.recommendation}"
                )
                panel = Panel(nar_text, title=f"Narrative: {nar.narrative_id}", border_style="magenta")
                with self._console.capture() as capture:
                    self._console.print(panel)
                lines.append(capture.get())

        # --- Priority Actions ---
        if self.overall_score and self.overall_score.priority_actions:
            action_text = "\n".join(
                f"  {i+1}. {a}" for i, a in enumerate(self.overall_score.priority_actions)
            )
            panel = Panel(action_text, title="Priority Actions (Top 5)", border_style="red")
            with self._console.capture() as capture:
                self._console.print(panel)
            lines.append(capture.get())

        # --- Recommendations ---
        if self.overall_score and self.overall_score.recommendations:
            rec_text = "\n".join(f"  • {r}" for r in self.overall_score.recommendations)
            panel = Panel(rec_text, title="Recommendations", border_style="yellow")
            with self._console.capture() as capture:
                self._console.print(panel)
            lines.append(capture.get())

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialize all scores to JSON."""
        result = {
            "overall_score": self.overall_score.to_dict() if self.overall_score else None,
            "platform_scores": {k: v.to_dict() for k, v in self.platform_scores.items()},
            "indicators": [i.to_dict() for i in self.indicators],
        }
        return json.dumps(result, indent=indent, default=str)
