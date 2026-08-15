"""
AIIOCDetector — detects AI-specific indicators of compromise that the generic
IOC extractor misses entirely.  These are the IOCs that matter most in AI DFIR
investigations: jailbreak patterns, tool abuse, credential exposure, data
exfiltration, model manipulation, and cross-platform correlation.
"""

import base64
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ionsec_trace.analyzer.secret_detector import SecretDetector
from ionsec_trace.collector.base import Finding, Severity

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AIIndicator:
    """An AI-specific indicator of compromise."""

    indicator_type: str        # jailbreak, tool_abuse, credential_exposure, exfiltration, model_manipulation, cross_platform
    severity: Severity
    value: str                 # the actual detected pattern / IOC
    context: str               # surrounding context (150 chars)
    platform: str
    source_file: str
    confidence: float         # 0.0–1.0
    attack_phase: str          # recon, initial_access, execution, persistence, exfiltration, impact
    mitre_atlas: list[str]    # e.g. ["AML.T0010", "AML.T0050"]
    mitre_attack: list[str]   # e.g. ["T1078", "T1530"]
    recommendation: str       # actionable remediation
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ---------------------------------------------------------------------------
# Detection patterns — Jailbreak
# ---------------------------------------------------------------------------

JAILBREAK_PATTERNS: list[tuple[str, re.Pattern, float, str, list[str], list[str], str]] = [
    # (name, regex, confidence, attack_phase, mitre_atlas, mitre_attack, recommendation)
    (
        "dan_mode",
        re.compile(
            r"(?i)\bDAN\b.*\bmode\b"
            r"|do\s+anything\s+now"
            r"|\bDAN\s*:\s*"
            r"|you\s+are\s+now\s+DAN"
            r"|jailbreak"
            r"|bypass\s+(?:your\s+)?safety"
            r"|ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|rules|constraints)"
            r"|disable\s+(?:your\s+)?safety"
            r"|turn\s+off\s+(?:your\s+)?safety",
        ),
        0.90,
        "initial_access",
        ["AML.T0010"],
        ["T1190"],
        "Review and harden system prompts; add explicit refusal patterns for jailbreak attempts.",
    ),
    (
        "roleplay_escape",
        re.compile(
            r"(?i)pretend\s+you\s+are"
            r"|act\s+as\s+if\s+you\s+(?:are|were)"
            r"|simulate\s+(?:being|you\s+are)"
            r"|roleplay\s+as"
            r"|you\s+are\s+now\s+(?:an?\s+)?(?:evil|unethical|malicious|uncensored|unfiltered)"
            r"|forget\s+(?:that\s+you\s+are|you're)\s+(?:an?\s+)?AI"
            r"|you\s+are\s+no\s+longer\s+(?:an?\s+)?AI"
            r"|you\s+are\s+(?:now\s+)?(?:DAN|evil|unrestricted)",
        ),
        0.75,
        "initial_access",
        ["AML.T0010"],
        ["T1190"],
        "Add roleplay-awareness to safety guardrails; detect persona shifts across turns.",
    ),
    (
        "system_prompt_extraction",
        re.compile(
            r"(?i)what\s+are\s+your\s+(?:initial|original|system|hidden)\s+instructions"
            r"|reveal\s+your\s+(?:system\s+)?prompt"
            r"|show\s+me\s+(?:your\s+)?(?:system|initial)\s+(?:instructions|prompt)"
            r"|repeat\s+(?:your|the)\s+(?:system|initial)\s+prompt"
            r"|output\s+(?:your|the)\s+(?:system|initial)\s+(?:instructions|prompt)"
            r"|ignore\s+previous\s+(?:instructions|directives|rules)"
            r"|forget\s+(?:your|all\s+previous)\s+instructions"
            r"|disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules)",
        ),
        0.85,
        "recon",
        ["AML.T0010", "AML.T0043"],
        ["T1082"],
        "Implement prompt-leak detection; avoid echoing system prompts; red-team extraction attacks.",
    ),
    (
        "prompt_injection_pasted",
        re.compile(
            r"(?i)ignore\s+the\s+(?:above|following|previous)\s+(?:text|content|instructions)\s+and"
            r"|the\s+above\s+text\s+is\s+(?:not|no)\s+(?:part\s+of)?\s*(?:the\s+)?(?:prompt|instruction)"
            r"|\[INST\].*\[/INST\]"
            r"|<!\s*--\s*ignore\s+.*?\s*--\s*>"
            r"|```\s*(?:system|instruction|prompt)"
            r"|NEW\s+RULES?\s*:"
            r"|from\s+now\s+on[,.]?\s+(?:you|your|the)\s+(?:must|will|should|shall|are)",
        ),
        0.80,
        "initial_access",
        ["AML.T0010"],
        ["T1190"],
        "Sanitize pasted content before processing; treat embedded instructions with suspicion.",
    ),
    (
        "encoding_attack",
        re.compile(
            r"(?i)decode\s+(?:this|the\s+following)\s*:\s*(?:[A-Za-z0-9+/]{40,}={0,2})"
            r"|base64\s+decode"
            r"|execute\s+(?:this\s+)?(?:base64|b64|encoded)",
        ),
        0.70,
        "execution",
        ["AML.T0010"],
        ["T1059.001", "T1059.004"],
        "Detect and block encoded payloads; decode and inspect before processing.",
    ),
    (
        "multi_turn_escalation",
        re.compile(
            r"(?i)now\s+that\s+you(?:'ve|\s+have)\s+(?:started|agreed|shown)"
            r"|continue\s+(?:from\s+)?(?:where\s+we\s+)?left\s+off"
            r"|since\s+you\s+already\s+(?:told|showed|gave)"
            r"|one\s+more\s+(?:thing|step|request)"
            r"|can\s+you\s+(?:also|additionally|now)\s+(?:do|tell|show|give|provide)"
            r"|I\s+know\s+you\s+(?:can't|shouldn't|won't)\s+but",
        ),
        0.55,
        "initial_access",
        ["AML.T0010"],
        ["T1190"],
        "Track escalation across conversation turns; implement per-turn risk scoring.",
    ),
]

# ---------------------------------------------------------------------------
# Detection patterns — Tool Abuse
# ---------------------------------------------------------------------------

TOOL_ABUSE_SENSITIVE_PATHS = [
    (r"(?i)/etc/shadow", "sensitive_credential_file", 0.95, "execution", ["T1005"], "Rotate all exposed credentials; audit /etc/shadow access."),
    (r"(?i)/etc/passwd", "sensitive_system_file", 0.85, "recon", ["T1082"], "Review file access logs; restrict /etc/passwd reads."),
    (r"(?i)(?:~|/home/\w+)/(?:\.ssh|\.gnupg)", "sensitive_crypto_dir", 0.95, "execution", ["T1005"], "Rotate SSH/GPG keys; restrict directory access."),
    (r"(?i)(?:~|/home/\w+)/\.(?:aws|azure|gcloud|config|env|netrc|gitconfig)", "sensitive_config_dir", 0.90, "recon", ["T1082"], "Audit cloud credential files; use secret management."),
    (r"(?i)(?:~|/home/\w+)/\.ssh/(?:id_rsa|id_ed25519|config|authorized_keys)", "sensitive_ssh_key", 0.95, "execution", ["T1005"], "Rotate SSH keys; revoke authorized_keys entries."),
    (r"(?i)/etc/(?:hosts\.allow|hosts\.deny|ssh/sshd_config)", "sensitive_network_config", 0.80, "recon", ["T1082"], "Review network configuration changes."),
    (r"(?i)(?:/etc|/var)/(?:shadow|passwd|group)", "sensitive_auth_file", 0.85, "execution", ["T1005"], "Audit authentication file access."),
]

TOOL_ABUSE_COMMAND_PATTERNS: list[tuple[str, re.Pattern, Severity, float, str, list[str], list[str], str]] = [
    (
        "dangerous_deletion",
        re.compile(r"(?i)\brm\s+-rf\s+/(?:etc|home|var|root|usr)\b|\brm\s+-rf\s+~"),
        Severity.CRITICAL,
        0.95,
        "impact",
        [],
        ["T1059.004"],
        "Immediately investigate; check for data destruction; restore from backups.",
    ),
    (
        "privilege_escalation",
        re.compile(r"(?i)\bsudo\s+(?:rm|chmod|chown|cat|tee|bash|sh|python|perl)\b|\bsudo\s+-i\b|\bsudo\s+su\b"),
        Severity.HIGH,
        0.90,
        "execution",
        [],
        ["T1059.004"],
        "Audit sudo usage; check sudoers configuration.",
    ),
    (
        "permission_modification",
        re.compile(r"(?i)\bchmod\s+(?:777|666|000)\b|\bchown\s+\w+\s+/"),
        Severity.HIGH,
        0.85,
        "persistence",
        [],
        ["T1059.004"],
        "Review permission changes; restore proper file permissions.",
    ),
    (
        "network_exfil_tool",
        re.compile(
            r"(?i)\bcurl\s+.*(?:--data|-d|-T|--upload-file)\b"
            r"|\bwget\s+.*--post-file\b"
            r"|\bscp\s+\S+@\S+:"
            r"|\bsftp\s+.*@\s"
            r"|\bssh\s+-[NRDR]\b"
            r"|\bnc\s+.*-[el]\b"
            r"|\bncat\s+.*--[el]\b"
            r"|\bsocat\s+.*(?:TCP|EXEC|SYSTEM)",
        ),
        Severity.CRITICAL,
        0.90,
        "exfiltration",
        ["AML.T0050"],
        ["T1048", "T1567"],
        "Block outbound data transfers; audit network tool usage from AI sessions.",
    ),
    (
        "env_dump",
        re.compile(
            r"(?i)\benv\b(?!\s+PATH)"
            r"|\bprintenv\b"
            r"|\bexport\s+\w*(?:KEY|SECRET|TOKEN|PASSWORD|API|CREDENTIAL)\w*\s*=",
        ),
        Severity.HIGH,
        0.85,
        "exfiltration",
        [],
        ["T1082"],
        "Restrict environment variable access in AI tool sandboxes; use secrets management.",
    ),
    (
        "pip_dangerous",
        re.compile(r"(?i)\bpip\s+install\b.*(?:--exec|--user|--target\s+/etc|--target\s+/root)"),
        Severity.HIGH,
        0.80,
        "execution",
        [],
        ["T1059.004"],
        "Block pip install with exec flags in AI contexts; use virtual environments.",
    ),
    (
        "database_access",
        re.compile(
            r"(?i)(?:mysql|psql|pg|sqlite3|mongosh)\s+.*(?:-p\b|password|secret)"
            r"|(?:postgres|mysql|mongodb)://\S+:\S+@"
            r"|connection_string\s*=\s*[\"'].*(?:password|pwd)\s*="
        ),
        Severity.CRITICAL,
        0.90,
        "exfiltration",
        [],
        ["T1078", "T1530"],
        "Rotate database credentials; use connection pooling with secret injection.",
    ),
]

# ---------------------------------------------------------------------------
# Detection patterns — Credential Exposure
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern, Severity, float, str, list[str], list[str], str]] = [
    # (name, regex, severity, confidence, attack_phase, mitre_atlas, mitre_attack, recommendation)
    (
        "openai_api_key",
        re.compile(r"\bsk-[a-zA-Z0-9\-_]{20,}\b"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Immediately rotate the OpenAI API key; audit usage logs for unauthorized access.",
    ),
    (
        "anthropic_api_key",
        re.compile(r"\banthropic_[a-zA-Z0-9\-_]{20,}\b"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Rotate the Anthropic API key; check usage for unauthorized calls.",
    ),
    (
        "github_token",
        re.compile(r"\bghp_[a-zA-Z0-9]{36,}\b|\bgithub_pat_[a-zA-Z0-9_]{20,}\b|\bgho_[a-zA-Z0-9]{36,}\b|\bghu_[a-zA-Z0-9]{36,}\b|\bghs_[a-zA-Z0-9]{36,}\b"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Revoke the GitHub token; audit repository access and git pushes.",
    ),
    (
        "xai_api_key",
        re.compile(r"\bxai-[a-zA-Z0-9\-_]{20,}\b"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Rotate the xAI API key; audit usage for unauthorized model access.",
    ),
    (
        "google_ai_key",
        re.compile(r"\bAIza[a-zA-Z0-9\-_]{30,}\b"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Rotate the Google AI key; restrict API key scope in GCP console.",
    ),
    (
        "aws_access_key",
        re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Disable the AWS access key; check CloudTrail for unauthorized usage.",
    ),
    (
        "azure_key",
        re.compile(r"(?i)\b(?:azure|tenant|subscription|client[_-]?secret)[_-]?(?:key|id|secret)\s*[:=]\s*[\"']?[a-zA-Z0-9\-_.]{20,}"),
        Severity.CRITICAL,
        0.90,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Rotate the Azure credential; check activity logs.",
    ),
    (
        "oauth_token",
        re.compile(r"(?i)\b(?:access_token|refresh_token|bearer)\s*[:=]\s*[\"']?[a-zA-Z0-9\-._~+/]{40,}"),
        Severity.HIGH,
        0.85,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Revoke the OAuth token; review OAuth scopes and consent grants.",
    ),
    (
        "private_key_pem",
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        [],
        ["T1078"],
        "Immediately rotate the private key; check for unauthorized use in SSH/SSL.",
    ),
    (
        "private_key_openssh",
        re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        [],
        ["T1078"],
        "Rotate the SSH private key; audit authorized_keys and session logs.",
    ),
    (
        "pgp_private_key",
        re.compile(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"),
        Severity.CRITICAL,
        0.95,
        "exfiltration",
        [],
        ["T1078"],
        "Revoke and regenerate the PGP private key.",
    ),
    (
        "credential_in_cli",
        re.compile(
            r"(?i)(?:--password|--secret|--token|--api-key|--apikey|--credential)\s+\S+"
            r"|-p\s+[^\-]\S+"
            r"|\bpassword\s*[:=]\s*[\"']?[^\s\"']{6,}"
            r"|\bsecret\s*[:=]\s*[\"']?[^\s\"']{6,}",
        ),
        Severity.HIGH,
        0.80,
        "exfiltration",
        [],
        ["T1078"],
        "Never pass credentials on command lines; use env vars or secret managers.",
    ),
    (
        "generic_api_key",
        re.compile(r"\bkey-[a-zA-Z0-9\-_]{10,}\b"),
        Severity.HIGH,
        0.70,
        "exfiltration",
        ["AML.T0050"],
        ["T1078"],
        "Investigate and rotate the API key if confirmed sensitive.",
    ),
]

# ---------------------------------------------------------------------------
# Detection patterns — Data Exfiltration
# ---------------------------------------------------------------------------

EXFIL_PATTERN_RULES: list[tuple[str, re.Pattern, Severity, float, str, list[str], list[str], str]] = [
    (
        "large_response_dump",
        re.compile(r".{10000,}"),  # matched post-hoc on response length
        Severity.MEDIUM,
        0.60,
        "exfiltration",
        ["AML.T0050"],
        ["T1567"],
        "Review large AI outputs for data smuggling; set response size limits.",
    ),
    (
        "base64_smuggling",
        re.compile(r"(?:[A-Za-z0-9+/]{100,}={0,2})(?:\s|$)"),
        Severity.HIGH,
        0.75,
        "exfiltration",
        ["AML.T0050"],
        ["T1048"],
        "Decode and inspect base64 payloads in AI conversations; block suspicious encodings.",
    ),
    (
        "url_in_response",
        re.compile(r"(?i)\bhttps?://(?:[a-z0-9\-]+\.)+(?:[a-z]{2,})(?:/[^\s]{10,})?(?:\.(?:exe|ps1|sh|bat|dll|py|rb|bin))\b"),
        Severity.HIGH,
        0.70,
        "exfiltration",
        [],
        ["T1567", "T1190"],
        "Block suspicious URLs in AI responses; verify external domains.",
    ),
    (
        "piped_network_command",
        re.compile(
            r"(?i)\|\s*(?:nc|ncat|curl|wget|ssh|telnet|socat|nslookup|dig)\b"
            r"|(?:cat|head|tail)\s+\S+\s*\|\s*(?:curl|wget|nc|ssh)\b",
        ),
        Severity.CRITICAL,
        0.90,
        "exfiltration",
        ["AML.T0050"],
        ["T1048"],
        "Block piped commands to network utilities in AI tool execution.",
    ),
    (
        "clipboard_access",
        re.compile(
            r"(?i)\b(?:pbcopy|pbpaste|xclip|xsel|clip|powershell.*(?:Get-Clipboard|Set-Clipboard|Get-Content.*clip))\b"
            r"|\bclipboard\b.*\b(?:read|write|copy|paste)\b",
        ),
        Severity.MEDIUM,
        0.55,
        "exfiltration",
        [],
        ["T1530"],
        "Monitor clipboard access from AI tool sessions; consider clipboard isolation.",
    ),
    (
        "credit_card_in_response",
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        Severity.CRITICAL,
        0.70,
        "exfiltration",
        ["AML.T0050"],
        ["T1530"],
        "Detected potential credit card number in AI response; redact and investigate.",
    ),
    (
        "ssn_in_response",
        re.compile(r"\b\d{3}[ -]?\d{2}[ -]?\d{4}\b"),
        Severity.CRITICAL,
        0.60,
        "exfiltration",
        ["AML.T0050"],
        ["T1530"],
        "Detected potential SSN in AI response; redact and investigate.",
    ),
    (
        "dns_exfil",
        re.compile(r"(?i)\b(?:dig|nslookup|host)\s+.*(?:\||>|>>)|\bdig\s+\S+@\S+"),
        Severity.HIGH,
        0.85,
        "exfiltration",
        [],
        ["T1048"],
        "Monitor DNS queries for data exfiltration patterns; restrict DNS tools.",
    ),
]

# ---------------------------------------------------------------------------
# Detection patterns — Model Manipulation
# ---------------------------------------------------------------------------

MODEL_MANIPULATION_PATTERNS: list[tuple[str, re.Pattern, float, str, list[str], list[str], str]] = [
    (
        "model_switch",
        re.compile(
            r"(?i)(?:switch|change|use)\s+(?:to\s+)?(?:model|engine|llm)\s*[:=]?\s*(?:gpt-4|claude-3|claude-opus|o1|o3|gemini|deepseek-r1)"
            r"|(?:\\?\")?model(?:\\?\")?\s*[:=]\s*(?:\\?\")?(?:gpt-4|claude-3|claude-opus|o1|o3|gemini|deepseek-r1)"
            r"|\b(?:openai|anthropic|google)\s+model\s*[:=]",
        ),
        0.70,
        "initial_access",
        ["AML.T0043"],
        ["T1190"],
        "Audit model-switch events; restrict which models AI tools can invoke.",
    ),
    (
        "temperature_manipulation",
        re.compile(
            r"(?i)(?:\\?\")?temperature(?:\\?\")?\s*[:=]\s*(?:\\?\")?\s*([2-9]|\d\.\d)"
            r"|(?:\\?\")?temp(?:\\?\")?\s*[:=]\s*(?:\\?\")?\s*([2-9]|\d\.\d)"
            r"|(?:\\?\")?top_p(?:\\?\")?\s*[:=]\s*(?:\\?\")?\s*0[.,]0?\d?\b",
        ),
        0.80,
        "execution",
        ["AML.T0043"],
        ["T1190"],
        "Flag anomalous temperature/top_p settings; enforce safety parameter bounds.",
    ),
    (
        "system_prompt_modification",
        re.compile(
            r"(?i)(?:\\?\")?system(?:\\?\")?\s*[:=]\s*(?:\\?\")?.*?(?:ignore|override|bypass|disable|jailbreak|DAN)"
            r"|(?:new|modified|updated)\s+system\s+(?:prompt|message|instruction)\s*[:=]",
        ),
        0.85,
        "execution",
        ["AML.T0010", "AML.T0043"],
        ["T1190"],
        "Log all system prompt changes; require approval for modifications.",
    ),
    (
        "finetuning_artifact",
        re.compile(
            r"(?i)(?:fine[- ]?tun|finetun|adapter|lora)\w*\s*(?:model|checkpoint|weights?|file|path)\s*[:=]"
            r"|\.safetensors\b"
            r"|\badapter_config\.json\b"
            r"|\b(?:lora|qlora)\s+(?:rank|alpha|dropout)\s*[:=]",
        ),
        0.65,
        "persistence",
        ["AML.T0043"],
        ["T1190"],
        "Verify fine-tuning artifacts are authorized; check for model poisoning.",
    ),
]


# ---------------------------------------------------------------------------
# Zero-width character detection
# ---------------------------------------------------------------------------

ZERO_WIDTH_CHARS = set(
    "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\u206a"
    "\u206b\u206c\u206d\u206e\u206f\u180e\ufeff\ufff9\ufffa\ufffb"
)

HOMOGLYPH_MAP = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrilric һ
    "\u0131": "i",  # dotless i
    "\u026a": "I",  # iota
}


# ===========================================================================
# AIIOCDetector
# ===========================================================================

class AIIOCDetector:
    """Detect AI-specific indicators of compromise in collected evidence."""

    CONTEXT_WINDOW = 150  # chars of surrounding context

    def __init__(self, evidence_dir: str):
        self.evidence_dir = Path(evidence_dir)
        self._indicators: list[AIIndicator] = []
        self._console = Console()
        self._files: dict[str, str] = {}  # path → content cache
        self._secret_detector = SecretDetector()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def indicators(self) -> list[AIIndicator]:
        return list(self._indicators)

    @property
    def findings(self) -> list[Finding]:
        """Convert high-confidence indicators (>=0.7) to Finding objects."""
        findings: list[Finding] = []
        idx = 0
        for ind in self._indicators:
            if ind.confidence < 0.7:
                continue
            idx += 1
            findings.append(Finding(
                id=f"AI-IOC-{idx:04d}",
                title=f"[{ind.indicator_type}] {ind.value[:80]}",
                description=f"AI-specific IOC detected: {ind.indicator_type} — {ind.value[:200]}",
                severity=ind.severity,
                platform=ind.platform,
                artifact_type="ai_indicator",
                evidence=[ind.to_dict()],
                iocs=[ind.value],
                mitre_atlas=ind.mitre_atlas,
                risk_score=int(ind.confidence * 100),
                recommendation=ind.recommendation,
            ))
        return findings

    def detect(self) -> "AIIOCDetector":
        """Run all AI-specific detection passes."""
        self._load_files()
        for file_path, content in self._files.items():
            platform = self._platform_from_path(file_path)
            self._detect_jailbreak(content, file_path, platform)
            self._detect_tool_abuse(content, file_path, platform)
            self._detect_credentials(content, file_path, platform)
            self._detect_shared_secrets(content, file_path, platform)
            self._detect_exfiltration(content, file_path, platform)
            self._detect_model_manipulation(content, file_path, platform)
            self._detect_encoding_attacks(content, file_path, platform)
            self._detect_sensitive_paths(content, file_path, platform)
            self._detect_large_responses(content, file_path, platform)
        self._cross_reference()
        return self

    def cross_reference(self) -> dict:
        """Correlate indicators across platforms."""
        return self._cross_reference()

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            [ind.to_dict() for ind in self._indicators],
            indent=indent,
            default=str,
        )

    def summary_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ind in self._indicators:
            counts[ind.indicator_type] = counts.get(ind.indicator_type, 0) + 1
        return counts

    def summary_by_phase(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ind in self._indicators:
            counts[ind.attack_phase] = counts.get(ind.attack_phase, 0) + 1
        return counts

    def __str__(self) -> str:
        if not self._indicators:
            return "No AI-specific IOCs found."

        table = Table(title="TRACE AI-Specific IOC Detection Results", show_lines=True)
        table.add_column("Type", style="cyan", max_width=20)
        table.add_column("Value", style="magenta", max_width=50)
        table.add_column("Phase", style="yellow", max_width=14)
        table.add_column("Severity", style="red", max_width=10)
        table.add_column("Confidence", style="green", max_width=10)
        table.add_column("Platform", style="blue", max_width=12)

        sev_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "dim",
            Severity.INFO: "dim",
        }

        for ind in self._indicators:
            sev_style = sev_styles.get(ind.severity, "white")
            table.add_row(
                ind.indicator_type,
                ind.value[:80],
                ind.attack_phase,
                f"[{sev_style}]{ind.severity.value}[/{sev_style}]",
                f"{ind.confidence:.2f}",
                ind.platform,
            )

        with self._console.capture() as capture:
            self._console.print(table)
        return capture.get()

    # ------------------------------------------------------------------
    # File loading
    # ------------------------------------------------------------------

    def _load_files(self) -> None:
        """Load all evidence files from the evidence directory."""
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
            for fpath in sorted(self.evidence_dir.rglob("*")):
                if fpath.is_file() and fpath.name != "CHAIN_OF_CUSTODY.json":
                    rel = fpath.relative_to(self.evidence_dir)
                    platform = rel.parts[0] if rel.parts else "unknown"
                    entries.append({
                        "original_path": str(fpath),
                        "platform": platform,
                    })

        for entry in entries:
            fpath = entry.get("original_path", "")
            p = Path(fpath)
            if not p.exists() or not p.is_file():
                continue
            try:
                if p.stat().st_size > 10 * 1024 * 1024:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    self._files[fpath] = fh.read()
            except OSError:
                continue

    def _platform_from_path(self, file_path: str) -> str:
        """Infer platform from file path."""
        try:
            rel = Path(file_path).relative_to(self.evidence_dir)
            return rel.parts[0] if rel.parts else "unknown"
        except ValueError:
            return "unknown"

    # ------------------------------------------------------------------
    # Context helper
    # ------------------------------------------------------------------

    def _context(self, content: str, start: int, end: int) -> str:
        """Extract surrounding context up to CONTEXT_WINDOW chars."""
        ctx_start = max(0, start - self.CONTEXT_WINDOW // 2)
        ctx_end = min(len(content), end + self.CONTEXT_WINDOW // 2)
        return content[ctx_start:ctx_end].strip()[:self.CONTEXT_WINDOW]

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _add_indicator(self, indicator: AIIndicator) -> None:
        """Deduplicate indicators by (indicator_type, value, source_file)."""
        for existing in self._indicators:
            if (existing.indicator_type == indicator.indicator_type
                    and existing.value == indicator.value
                    and existing.source_file == indicator.source_file):
                return
        self._indicators.append(indicator)

    # ------------------------------------------------------------------
    # Detection: Jailbreak
    # ------------------------------------------------------------------

    def _detect_jailbreak(self, content: str, source: str, platform: str) -> None:
        for name, pattern, confidence, phase, atlas, attack, rec in JAILBREAK_PATTERNS:
            for match in pattern.finditer(content):
                self._add_indicator(AIIndicator(
                    indicator_type="jailbreak",
                    severity=Severity.CRITICAL,
                    value=match.group()[:200],
                    context=self._context(content, match.start(), match.end()),
                    platform=platform,
                    source_file=source,
                    confidence=confidence,
                    attack_phase=phase,
                    mitre_atlas=atlas,
                    mitre_attack=attack,
                    recommendation=rec,
                    metadata={"pattern_name": name},
                ))

    # ------------------------------------------------------------------
    # Detection: Tool Abuse — commands
    # ------------------------------------------------------------------

    def _detect_tool_abuse(self, content: str, source: str, platform: str) -> None:
        for name, pattern, severity, confidence, phase, atlas, attack, rec in TOOL_ABUSE_COMMAND_PATTERNS:
            for match in pattern.finditer(content):
                self._add_indicator(AIIndicator(
                    indicator_type="tool_abuse",
                    severity=severity,
                    value=match.group()[:200],
                    context=self._context(content, match.start(), match.end()),
                    platform=platform,
                    source_file=source,
                    confidence=confidence,
                    attack_phase=phase,
                    mitre_atlas=atlas,
                    mitre_attack=attack,
                    recommendation=rec,
                    metadata={"pattern_name": name},
                ))

    # ------------------------------------------------------------------
    # Detection: Tool Abuse — sensitive file paths
    # ------------------------------------------------------------------

    def _detect_sensitive_paths(self, content: str, source: str, platform: str) -> None:
        for path_re, name, confidence, phase, attack, rec in TOOL_ABUSE_SENSITIVE_PATHS:
            pattern = re.compile(path_re)
            for match in pattern.finditer(content):
                self._add_indicator(AIIndicator(
                    indicator_type="tool_abuse",
                    severity=Severity.HIGH,
                    value=match.group()[:200],
                    context=self._context(content, match.start(), match.end()),
                    platform=platform,
                    source_file=source,
                    confidence=confidence,
                    attack_phase=phase,
                    mitre_atlas=[],
                    mitre_attack=attack,
                    recommendation=rec,
                    metadata={"pattern_name": f"sensitive_path_{name}"},
                ))

    # ------------------------------------------------------------------
    # Detection: Credential Exposure
    # ------------------------------------------------------------------

    def _detect_credentials(self, content: str, source: str, platform: str) -> None:
        for name, pattern, severity, confidence, phase, atlas, attack, rec in CREDENTIAL_PATTERNS:
            for match in pattern.finditer(content):
                # Mask the actual key value for security
                raw_val = match.group()
                display_val = (raw_val[:6] + "..." + raw_val[-4:]) if len(raw_val) > 12 else raw_val[:4] + "..."

                self._add_indicator(AIIndicator(
                    indicator_type="credential_exposure",
                    severity=severity,
                    value=display_val,
                    context=self._context(content, match.start(), match.end()),
                    platform=platform,
                    source_file=source,
                    confidence=confidence,
                    attack_phase=phase,
                    mitre_atlas=atlas,
                    mitre_attack=attack,
                    recommendation=rec,
                    metadata={"pattern_name": name, "raw_length": len(raw_val)},
                ))

    def _detect_shared_secrets(self, content: str, source: str, platform: str) -> None:
        """Catch secrets the curated CREDENTIAL_PATTERNS miss, using the shared
        SecretDetector (shared rule catalog,
        entropy gating, context-layer key matching, and false-positive filters).

        This broadens coverage to the full provider set (Slack, Discord, Stripe,
        npm, PyPI, GitLab, JWT, PEM/OpenSSH/PGP blocks, etc.) and to prefix-less
        credentials found via key-name context matching.
        """
        for match in self._secret_detector.scan(content, source):
            self._add_indicator(AIIndicator(
                indicator_type="credential_exposure",
                severity=Severity(match.severity),
                value=match.redacted,
                context=match.context or self._context(content, 0, min(200, len(content))),
                platform=platform,
                source_file=source,
                confidence=match.confidence,
                attack_phase="exfiltration",
                mitre_atlas=["AML.T0050"],
                mitre_attack=["T1078"],
                recommendation=(
                    "Rotate the exposed credential immediately; audit usage logs "
                    "for unauthorized access."
                ),
                metadata={
                    "pattern_name": match.rule_id,
                    "detection_layer": match.detection_layer,
                    "context_key": match.context_key,
                    "raw_length": match.raw_length,
                },
            ))

    # ------------------------------------------------------------------
    # Detection: Data Exfiltration
    # ------------------------------------------------------------------

    def _detect_exfiltration(self, content: str, source: str, platform: str) -> None:
        for name, pattern, severity, confidence, phase, atlas, attack, rec in EXFIL_PATTERN_RULES:
            if name == "large_response_dump":
                continue  # handled separately
            for match in pattern.finditer(content):
                self._add_indicator(AIIndicator(
                    indicator_type="exfiltration",
                    severity=severity,
                    value=match.group()[:200],
                    context=self._context(content, match.start(), match.end()),
                    platform=platform,
                    source_file=source,
                    confidence=confidence,
                    attack_phase=phase,
                    mitre_atlas=atlas,
                    mitre_attack=attack,
                    recommendation=rec,
                    metadata={"pattern_name": name},
                ))

    def _detect_large_responses(self, content: str, source: str, platform: str) -> None:
        """Detect suspiciously large response bodies that could be data dumps."""
        # Check if content itself is >10KB (indicating a large AI response)
        if len(content) > 10000:
            self._add_indicator(AIIndicator(
                indicator_type="exfiltration",
                severity=Severity.MEDIUM,
                value=f"Large content body ({len(content)} bytes) — potential data dump",
                context=content[:150].strip(),
                platform=platform,
                source_file=source,
                confidence=0.60,
                attack_phase="exfiltration",
                mitre_atlas=["AML.T0050"],
                mitre_attack=["T1567"],
                recommendation="Review large AI outputs for data smuggling; set response size limits.",
                metadata={"size_bytes": len(content)},
            ))

    # ------------------------------------------------------------------
    # Detection: Model Manipulation
    # ------------------------------------------------------------------

    def _detect_model_manipulation(self, content: str, source: str, platform: str) -> None:
        for name, pattern, confidence, phase, atlas, attack, rec in MODEL_MANIPULATION_PATTERNS:
            for match in pattern.finditer(content):
                self._add_indicator(AIIndicator(
                    indicator_type="model_manipulation",
                    severity=Severity.HIGH,
                    value=match.group()[:200],
                    context=self._context(content, match.start(), match.end()),
                    platform=platform,
                    source_file=source,
                    confidence=confidence,
                    attack_phase=phase,
                    mitre_atlas=atlas,
                    mitre_attack=attack,
                    recommendation=rec,
                    metadata={"pattern_name": name},
                ))

    # ------------------------------------------------------------------
    # Detection: Encoding Attacks
    # ------------------------------------------------------------------

    def _detect_encoding_attacks(self, content: str, source: str, platform: str) -> None:
        # Zero-width characters
        zw_positions = [i for i, ch in enumerate(content) if ch in ZERO_WIDTH_CHARS]
        if len(zw_positions) >= 3:
            # Group nearby positions
            groups: list[list[int]] = []
            current_group = [zw_positions[0]]
            for pos in zw_positions[1:]:
                if pos - current_group[-1] <= 5:
                    current_group.append(pos)
                else:
                    groups.append(current_group)
                    current_group = [pos]
            groups.append(current_group)

            for group in groups:
                if len(group) >= 3:
                    start = group[0]
                    end = group[-1] + 1
                    self._add_indicator(AIIndicator(
                        indicator_type="jailbreak",
                        severity=Severity.HIGH,
                        value=f"Zero-width characters ({len(group)} chars): {repr(content[start:end])[:100]}",
                        context=self._context(content, start, end),
                        platform=platform,
                        source_file=source,
                        confidence=0.85,
                        attack_phase="initial_access",
                        mitre_atlas=["AML.T0010"],
                        mitre_attack=["T1190"],
                        recommendation="Strip zero-width characters from input; detect hidden instructions.",
                        metadata={"pattern_name": "zero_width_chars", "count": len(group)},
                    ))

        # Unicode homoglyphs (Cyrillic lookalikes)
        homoglyph_positions = [(i, ch) for i, ch in enumerate(content) if ch in HOMOGLYPH_MAP]
        if len(homoglyph_positions) >= 3:
            # Check if they form suspicious words
            suspicious_words_jailbreak = re.compile(
                r"(?i)\b(?:admin|root|sudo|system|exec|rm|delete|drop|bypass|hack|exploit)\b",
            )
            nearby_text = content[max(0, homoglyph_positions[0][0] - 20):
                                  min(len(content), homoglyph_positions[-1][0] + 20)]
            if suspicious_words_jailbreak.search(nearby_text):
                self._add_indicator(AIIndicator(
                    indicator_type="jailbreak",
                    severity=Severity.HIGH,
                    value=f"Unicode homoglyph attack ({len(homoglyph_positions)} chars near suspicious keywords)",
                    context=nearby_text[:150].strip(),
                    platform=platform,
                    source_file=source,
                    confidence=0.75,
                    attack_phase="initial_access",
                    mitre_atlas=["AML.T0010"],
                    mitre_attack=["T1190"],
                    recommendation="Normalize Unicode input; detect homoglyph substitution attacks.",
                    metadata={"pattern_name": "unicode_homoglyphs", "count": len(homoglyph_positions)},
                ))

        # Base64-decoded prompt injection
        self._detect_base64_prompt_injection(content, source, platform)

    def _detect_base64_prompt_injection(self, content: str, source: str, platform: str) -> None:
        """Detect base64-encoded content that decodes to prompt injection."""
        # Find potential base64 blocks
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        prompt_keywords = re.compile(
            r"(?i)(?:ignore|disregard|forget|bypass|override|jailbreak|system\s+prompt"
            r"|you\s+are|pretend|act\s+as|roleplay|DAN)",
        )

        for match in b64_pattern.finditer(content):
            candidate = match.group()
            if len(candidate) % 4 != 0:
                continue  # not valid base64
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            except Exception:
                continue

            if prompt_keywords.search(decoded):
                self._add_indicator(AIIndicator(
                    indicator_type="jailbreak",
                    severity=Severity.CRITICAL,
                    value=f"Base64-encoded prompt injection: {decoded[:100]}...",
                    context=self._context(content, match.start(), match.end()),
                    platform=platform,
                    source_file=source,
                    confidence=0.90,
                    attack_phase="initial_access",
                    mitre_atlas=["AML.T0010"],
                    mitre_attack=["T1059.001", "T1059.004"],
                    recommendation="Decode and inspect base64 payloads; block prompt injection in decoded content.",
                    metadata={"pattern_name": "base64_prompt_injection", "decoded_length": len(decoded)},
                ))

    # ------------------------------------------------------------------
    # Cross-platform correlation
    # ------------------------------------------------------------------

    def _cross_reference(self) -> dict:
        """Correlate indicators across platforms and upgrade severity."""
        # Group by (indicator_type, value) to find cross-platform matches
        grouped: dict[tuple[str, str], list[AIIndicator]] = {}
        for ind in self._indicators:
            key = (ind.indicator_type, ind.value)
            grouped.setdefault(key, []).append(ind)

        correlations: dict = {
            "cross_platform_credentials": [],
            "cross_platform_domains": [],
            "cross_platform_ips": [],
            "temporal_correlations": [],
            "summary": {},
        }

        for key, group in grouped.items():
            platforms = {ind.platform for ind in group}
            if len(platforms) > 1:
                # Upgrade severity for cross-platform IOCs
                for ind in group:
                    if ind.severity != Severity.CRITICAL:
                        # Upgrade one level
                        upgrade = {
                            Severity.INFO: Severity.LOW,
                            Severity.LOW: Severity.MEDIUM,
                            Severity.MEDIUM: Severity.HIGH,
                            Severity.HIGH: Severity.CRITICAL,
                        }
                        ind.severity = upgrade.get(ind.severity, ind.severity)

                # Add cross-platform indicator
                self._add_indicator(AIIndicator(
                    indicator_type="cross_platform",
                    severity=Severity.CRITICAL,
                    value=f"{key[0]}: {key[1]} (across {', '.join(sorted(platforms))})",
                    context=f"Found across platforms: {', '.join(sorted(platforms))}",
                    platform="*",
                    source_file=", ".join(sorted({ind.source_file for ind in group})),
                    confidence=0.95,
                    attack_phase=group[0].attack_phase,
                    mitre_atlas=["AML.T0050"],
                    mitre_attack=["T1078"],
                    recommendation=f"Cross-platform indicator detected across {', '.join(sorted(platforms))}. Investigate lateral movement and shared credential compromise.",
                    metadata={"platforms": sorted(platforms), "count": len(group)},
                ))

                # Categorize for structured output
                if key[0] == "credential_exposure":
                    correlations["cross_platform_credentials"].append({
                        "value": key[1],
                        "platforms": sorted(platforms),
                        "files": [ind.source_file for ind in group],
                    })

        # Temporal correlation — look for files modified in suspicious time windows
        # This is a structural check based on file timestamps
        correlations["summary"] = {
            "total_indicators": len(self._indicators),
            "cross_platform_count": sum(
                1 for ind in self._indicators if ind.indicator_type == "cross_platform"
            ),
            "by_type": self.summary_by_type(),
            "by_phase": self.summary_by_phase(),
        }

        return correlations

    # ------------------------------------------------------------------
    # Shared credential detection across platform configs
    # ------------------------------------------------------------------

    def detect_shared_credentials(self) -> list[dict]:
        """Find credentials that appear across multiple platform config files.

        This is a specialized cross-platform correlation that looks for the same
        API key or credential string in multiple platform directories.
        """
        # Collect all credential values with their platforms
        cred_by_value: dict[str, list[AIIndicator]] = {}
        for ind in self._indicators:
            if ind.indicator_type == "credential_exposure":
                cred_by_value.setdefault(ind.value, []).append(ind)

        shared: list[dict] = []
        for value, indicators in cred_by_value.items():
            platforms = {ind.platform for ind in indicators}
            if len(platforms) > 1:
                shared.append({
                    "credential": value,
                    "platforms": sorted(platforms),
                    "files": sorted({ind.source_file for ind in indicators}),
                    "severity": Severity(max(ind.severity.value for ind in indicators)).value,
                })

        return shared
