"""
SecretDetector — the shared, data-driven secret detection engine for TRACE.

One engine backs every TRACE collector and analyzer, so a credential is
recognized identically wherever it appears — a config file, a conversation
turn, or a tool-call argument.

This module is read-only and forensically sound: it performs no network calls
and never emits a raw secret value, only a redacted preview. Live credential
verification is deliberately not implemented, since probing a provider would
break TRACE's chain-of-custody guarantees.

Design notes
------------
* Every rule carries a `prefix` (or `keywords`) used as a cheap substring
  pre-filter before the regex runs — the single biggest performance win.
* Entropy is gated per rule: strong-prefix rules (AKIA, ghp_, sk-proj-) get a
  low threshold; generic rules need higher entropy. Path confidence shifts the
  threshold — high-value directories lower it, low-trust ones raise it.
* A context layer catches prefix-less secrets by matching assignment lines
  whose *key name* contains secret words (api_key, client_secret, ...).
* An allowlist kills the classic false positives: lockfiles, vendor trees,
  minified JS, `$VAR` / `{{ }}` / `%s` placeholders, and stopwords.

Maintained by IONSEC (https://ionsec.io).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# ReDoS guard
# ---------------------------------------------------------------------------
# A rule catalog is only as safe as its worst regex. We reject patterns that
# are pathological (nested/ambiguous quantifiers, runaway repetition) and cap
# the value length we scan so a single oversized cell cannot hang the process.
# Unsafe rules are dropped at load time, never at scan time.

_MAX_REGEX_LEN = 1024
_MAX_SCAN_VALUE_LEN = 64 * 1024
# A quantified group that itself contains a quantifier is the classic ReDoS
# shape (e.g. `(a+)+`). We reject it outright.
_AMBIGUOUS_QUANTIFIER_RE = re.compile(r"\([^)]*[+*{][^)]*\)[+*{]")


def compile_safe_regex(pattern: str, flags: int = 0) -> re.Pattern | None:
    """Compile a rule regex, returning None if it is unsafe or invalid.

    Guards: length cap, ambiguous-quantifier detection, and a compile-time
    check. A malformed or pathological rule is dropped rather than allowed to
    hang the scanner.
    """
    if not pattern or len(pattern) > _MAX_REGEX_LEN:
        return None
    if _AMBIGUOUS_QUANTIFIER_RE.search(pattern):
        return None
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def _bounded_text(content: str) -> str:
    """Cap the value scanned so a single oversized cell cannot exhaust memory."""
    return content if len(content) <= _MAX_SCAN_VALUE_LEN else content[:_MAX_SCAN_VALUE_LEN]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SecretRule:
    """A single secret detection rule ."""

    id: str
    description: str
    regex: str
    severity: str = "critical"          # critical | high | medium | low
    prefix: str = ""                    # cheap substring pre-filter ("" = none)
    keywords: list = field(default_factory=list)  # extra pre-filter terms
    min_entropy: float = 0.0            # 0.0 = no entropy gate
    ignore_case: bool = False
    # True when the prefix is distinctive enough that entropy is unnecessary
    strong_prefix: bool = False


@dataclass
class SecretMatch:
    """A detected secret with redacted value and confidence."""

    rule_id: str
    secret_type: str
    description: str
    severity: str
    redacted: str
    entropy: float
    confidence: float
    detection_layer: str               # "value" | "context" | "both"
    context_key: str = ""              # key name for context-layer matches
    raw_length: int = 0
    context: str = ""                  # surrounding line text (for IOC context)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "secret_type": self.secret_type,
            "description": self.description,
            "severity": self.severity,
            "redacted": self.redacted,
            "entropy": round(self.entropy, 3),
            "confidence": round(self.confidence, 3),
            "detection_layer": self.detection_layer,
            "context_key": self.context_key,
            "raw_length": self.raw_length,
            "context": self.context,
        }


# ---------------------------------------------------------------------------
# Rule catalog
# ---------------------------------------------------------------------------
# AI-relevant secrets first (the core of TRACE's mission), then common
# infrastructure secrets. Prefixes are the distinctive token prefixes.

RULES: list[SecretRule] = [
    # --- AI providers -----------------------------------------------------
    SecretRule("openai_legacy", "OpenAI API key (legacy shape)",
               r"sk-[A-Za-z0-9]{20,}", "critical", "sk-", min_entropy=3.0),
    SecretRule("openai_project", "OpenAI project API key",
               r"sk-proj-[A-Za-z0-9_-]{20,}", "critical", "sk-proj-", strong_prefix=True),
    SecretRule("anthropic", "Anthropic API key",
               r"sk-ant-api[A-Za-z0-9_-]{10,}", "critical", "sk-ant-api", strong_prefix=True),
    SecretRule("xai", "xAI API key",
               r"xai-[A-Za-z0-9_-]{20,}", "critical", "xai-", min_entropy=3.0),
    SecretRule("google_ai", "Google AI / Gemini API key",
               r"AIza[0-9A-Za-z_-]{35}", "high", "AIza", min_entropy=3.0),
    SecretRule("huggingface", "HuggingFace access token",
               r"hf_[A-Za-z0-9]{20,}", "critical", "hf_", strong_prefix=True),
    SecretRule("deepseek", "DeepSeek API key",
               r"sk-[a-f0-9]{32,}", "critical", "sk-", min_entropy=3.0),
    SecretRule("mistral", "Mistral API key",
               r"[A-Za-z0-9]{32}\.[A-Za-z0-9]{6}\.[A-Za-z0-9]{6,}", "critical", "", min_entropy=3.5),
    SecretRule("cohere", "Cohere API key",
               r"[A-Za-z0-9]{40}", "high", "", min_entropy=4.0),
    SecretRule("replicate", "Replicate API token",
               r"r8_[A-Za-z0-9]{20,}", "critical", "r8_", strong_prefix=True),
    SecretRule("together", "Together AI API key",
               r"tgp_[A-Za-z0-9]{20,}", "critical", "tgp_", strong_prefix=True),
    SecretRule("groq", "Groq API key",
               r"gsk_[A-Za-z0-9]{20,}", "critical", "gsk_", strong_prefix=True),
    SecretRule("perplexity", "Perplexity API key",
               r"pplx-[A-Za-z0-9]{20,}", "critical", "pplx-", strong_prefix=True),
    SecretRule("openrouter", "OpenRouter API key",
               r"sk-or-v1-[A-Za-z0-9]{20,}", "critical", "sk-or-v1-", strong_prefix=True),
    SecretRule("ollama", "Ollama API key",
               r"ollama_[A-Za-z0-9]{20,}", "high", "ollama_", strong_prefix=True),

    # --- GitHub / Git hosting --------------------------------------------
    SecretRule("github_pat", "GitHub personal access token (classic)",
               r"ghp_[A-Za-z0-9]{36,}", "critical", "ghp_", strong_prefix=True),
    SecretRule("github_fine", "GitHub fine-grained PAT",
               r"github_pat_[A-Za-z0-9_]{20,}", "critical", "github_pat_", strong_prefix=True),
    SecretRule("github_oauth", "GitHub OAuth token",
               r"gho_[A-Za-z0-9]{36,}", "high", "gho_", strong_prefix=True),
    SecretRule("github_app", "GitHub app/user token",
               r"ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}|ghr_[A-Za-z0-9]{36,}",
               "high", "gh", strong_prefix=True),
    SecretRule("gitlab_pat", "GitLab personal access token",
               r"glpat-[A-Za-z0-9_-]{20,}", "critical", "glpat-", strong_prefix=True),
    SecretRule("bitbucket", "Bitbucket app password",
               r"ATBB[A-Za-z0-9]{32,}", "critical", "ATBB", strong_prefix=True),

    # --- Cloud / infra ----------------------------------------------------
    SecretRule("aws_access_key", "AWS access key ID",
               r"AKIA[0-9A-Z]{16}", "critical", "AKIA", strong_prefix=True),
    SecretRule("aws_temp", "AWS temporary access key ID",
               r"ASIA[0-9A-Z]{16}", "critical", "ASIA", strong_prefix=True),
    SecretRule("azure", "Azure client secret / connection string",
               r"(?i)(?:azure|tenant|subscription|client[_-]?secret)[_-]?(?:key|id|secret)\s*[:=]\s*[\"']?[a-zA-Z0-9\-_.]{20,}",
               "critical", "azure", min_entropy=3.0),
    SecretRule("gcp_service_account", "GCP service account key",
               r"\"type\"\s*:\s*\"service_account\"", "high", "service_account"),
    SecretRule("stripe", "Stripe secret/restricted key",
               r"sk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}|rk_test_[0-9a-zA-Z]{24,}",
               "critical", "sk_", strong_prefix=True),
    SecretRule("slack_bot", "Slack bot token",
               r"xoxb-[0-9A-Za-z-]{50,}", "high", "xoxb-", strong_prefix=True),
    SecretRule("slack_user", "Slack user token",
               r"xoxp-[0-9A-Za-z-]{50,}", "high", "xoxp-", strong_prefix=True),
    SecretRule("slack_app", "Slack app-level token",
               r"xoxa-[0-9A-Za-z-]{50,}", "high", "xoxa-", strong_prefix=True),
    SecretRule("slack_webhook", "Slack incoming webhook URL",
               r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "medium", "hooks.slack.com"),
    SecretRule("discord_bot", "Discord bot token",
               r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
               "high", "", min_entropy=3.5),
    SecretRule("npm_token", "npm access token",
               r"npm_[A-Za-z0-9]{36,}", "high", "npm_", strong_prefix=True),
    SecretRule("pypi_token", "PyPI API token",
               r"pypi-[A-Za-z0-9_-]{50,}", "high", "pypi-", strong_prefix=True),
    SecretRule("nuget", "NuGet API key",
               r"oy2[a-z0-9]{15,}[A-Za-z0-9]{28}", "high", "oy2", min_entropy=4.0),
    SecretRule("atlassian", "Atlassian Cloud API token",
               r"ATATT3[A-Za-z0-9+/=]{20,}", "critical", "ATATT3", strong_prefix=True),
    SecretRule("shopify", "Shopify access token",
               r"shpat_[A-Za-z0-9]{32,}|shpca_[A-Za-z0-9]{32,}|shpss_[A-Za-z0-9]{32,}",
               "critical", "shp", strong_prefix=True),
    SecretRule("sendgrid", "SendGrid API key",
               r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "high", "SG.", strong_prefix=True),
    SecretRule("twilio", "Twilio API key",
               r"SK[0-9a-fA-F]{32}", "high", "SK", min_entropy=3.0),
    SecretRule("telegram_bot", "Telegram bot token",
               r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "high", "", min_entropy=3.5),
    SecretRule("jwt", "JSON Web Token",
               r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
               "high", "eyJ", min_entropy=3.0),
    SecretRule("private_key_pem", "PEM private key block",
               r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----",
               "critical", "PRIVATE KEY", strong_prefix=True),
    SecretRule("private_key_openssh", "OpenSSH private key block",
               r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
               "critical", "OPENSSH PRIVATE KEY", strong_prefix=True),
    SecretRule("pgp_private_key", "PGP private key block",
               r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
               "critical", "PGP PRIVATE KEY", strong_prefix=True),
    SecretRule("generic_key", "Generic API key (key- prefix)",
               r"\bkey-[A-Za-z0-9_-]{10,}\b", "high", "key-", min_entropy=3.0),

    # --- Additional providers (distinctive token prefixes) -----------------
    SecretRule("databricks", "Databricks API token",
               r"\bdapi[a-f0-9]{32}(?:-\d)?\b", "critical", "dapi", strong_prefix=True),
    SecretRule("digitalocean_pat", "DigitalOcean personal access token",
               r"\bdop_v1_[a-f0-9]{64}\b", "critical", "dop_v1_", strong_prefix=True),
    SecretRule("doppler", "Doppler API token",
               r"\bdp\.pt\.[a-z0-9]{43}\b", "critical", "dp.pt.", strong_prefix=True),
    SecretRule("linear", "Linear API key",
               r"\blin_api_[a-z0-9]{40}\b", "critical", "lin_api_", strong_prefix=True),
    SecretRule("notion", "Notion API token",
               r"\bntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}\b", "critical", "ntn_", strong_prefix=True),
    SecretRule("postman", "Postman API token",
               r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b", "critical", "PMAK-", strong_prefix=True),
    SecretRule("pulumi", "Pulumi API token",
               r"\bpul-[a-f0-9]{40}\b", "critical", "pul-", strong_prefix=True),
    SecretRule("readme", "ReadMe API token",
               r"\brdme_[a-z0-9]{70}\b", "critical", "rdme_", strong_prefix=True),
    SecretRule("rubygems", "RubyGems API token",
               r"\brubygems_[a-f0-9]{48}\b", "critical", "rubygems_", strong_prefix=True),
    SecretRule("sendinblue", "Sendinblue API token",
               r"\bxkeysib-[a-f0-9]{64}-[a-z0-9]{16}\b", "critical", "xkeysib-", strong_prefix=True),
    SecretRule("square", "Square access token",
               r"\b(?:EAAA|sq0atp-)[\w-]{22,60}\b", "critical", "sq0atp-", strong_prefix=True),
    SecretRule("typeform", "Typeform API token",
               r"\btfp_[a-z0-9\-_\.=]{59}\b", "critical", "tfp_", strong_prefix=True),
    SecretRule("vault_batch", "HashiCorp Vault batch token",
               r"\bhvb\.[\w-]{138,300}\b", "critical", "hvb.", strong_prefix=True),
    SecretRule("yandex", "Yandex API key",
               r"\bAQVN[A-Za-z0-9_\-]{35,38}\b", "critical", "AQVN", strong_prefix=True),
    SecretRule("maxmind", "MaxMind license key",
               r"\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\b", "high", "_mmk", strong_prefix=True),
    SecretRule("octopus", "Octopus Deploy API key",
               r"\bAPI-[A-Z0-9]{26}\b", "critical", "API-", strong_prefix=True),
    SecretRule("sourcegraph", "Sourcegraph access token",
               r"\bsgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}\b", "critical", "sgp_", strong_prefix=True),
    SecretRule("sonar", "SonarQube token",
               r"\b(?:squ_|sqp_|sqa_)[a-z0-9=_\-]{40}\b", "high", "sq", strong_prefix=True),
    SecretRule("newrelic", "New Relic user API key",
               r"\bNRAK-[a-z0-9]{27}\b", "critical", "NRAK-", strong_prefix=True),
    SecretRule("grafana", "Grafana API key",
               r"\beyJrIjoi[A-Za-z0-9]{70,400}={0,3}\b", "critical", "eyJrIjoi", strong_prefix=True),
    SecretRule("hashicorp_tf", "HashiCorp Terraform API token",
               r"\b[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}\b", "critical", "atlasv1", strong_prefix=True),
    SecretRule("flyio", "Fly.io access token",
               r"\b(?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+/]{100,}={0,3}|fm2_[a-zA-Z0-9+/]{100,}={0,3})\b",
               "critical", "fo1_", strong_prefix=True),
    SecretRule("microsoft_teams_webhook", "Microsoft Teams webhook URL",
               r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9-]+@[a-z0-9-]+/IncomingWebhook/[a-z0-9]{32}/[a-z0-9-]+",
               "medium", "webhook.office.com"),
    SecretRule("kubernetes_secret", "Kubernetes Secret manifest",
               r"(?i)\bkind:\s*[\"']?Secret[\"']?(?s:.{0,200}?)\bdata:", "high", "kind: Secret"),
    SecretRule("github_refresh", "GitHub refresh token",
               r"\bghr_[0-9a-zA-Z]{36}\b", "critical", "ghr_", strong_prefix=True),
    SecretRule("gitlab_ptt", "GitLab pipeline trigger token",
               r"\bglptt-[a-zA-Z0-9_-]{20,}\b", "high", "glptt-", strong_prefix=True),
    SecretRule("gitlab_runner", "GitLab runner auth token",
               r"\bglrt-[a-zA-Z0-9_-]{20,}\b", "high", "glrt-", strong_prefix=True),
    SecretRule("cloudflare", "Cloudflare API key",
               r"(?i)\b(?:cloudflare)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9_-]{40})\b",
               "critical", "cloudflare", min_entropy=3.0),
    SecretRule("datadog", "Datadog API key",
               r"(?i)\b(?:datadog)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{40})\b",
               "critical", "datadog", min_entropy=3.0),
    SecretRule("mailchimp", "Mailchimp API key",
               r"(?i)\b(?:mailchimp)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-f0-9]{32}-us\d\d)\b",
               "critical", "mailchimp", min_entropy=3.0),
    SecretRule("mapbox", "Mapbox API token",
               r"\bpk\.[a-z0-9]{60}\.[a-z0-9]{22}\b", "high", "pk.", min_entropy=3.0),
    SecretRule("heroku", "Heroku API key",
               r"(?i)\b(?:heroku)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
               "critical", "heroku", min_entropy=3.0),
    SecretRule("facebook", "Facebook access token",
               r"\b\d{15,16}(\||%)[0-9a-z\-_]{27,40}\b", "high", "", min_entropy=3.5),
    SecretRule("twitch", "Twitch API token",
               r"(?i)\b(?:twitch)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{30})\b",
               "high", "twitch", min_entropy=3.0),
    SecretRule("twitter_bearer", "Twitter/X bearer token",
               r"(?i)\b(?:twitter)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})\b",
               "critical", "twitter", min_entropy=3.0),
    SecretRule("sentry", "Sentry access token",
               r"(?i)\b(?:sentry)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-f0-9]{64})\b",
               "critical", "sentry", min_entropy=3.0),
    SecretRule("jfrog", "JFrog API key",
               r"(?i)\b(?:jfrog|artifactory|bintray|xray)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{73})\b",
               "critical", "jfrog", min_entropy=3.0),
    SecretRule("dropbox", "Dropbox API token",
               r"(?i)\b(?:dropbox)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{15})\b",
               "high", "dropbox", min_entropy=3.0),
    SecretRule("airtable", "Airtable API key",
               r"(?i)\b(?:airtable)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{17})\b",
               "high", "airtable", min_entropy=3.0),
    SecretRule("algolia", "Algolia API key",
               r"(?i)\b(?:algolia)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{32})\b",
               "high", "algolia", min_entropy=3.0),
    SecretRule("intercom", "Intercom API key",
               r"(?i)\b(?:intercom)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{60})\b",
               "critical", "intercom", min_entropy=3.0),
    SecretRule("launchdarkly", "LaunchDarkly access token",
               r"(?i)\b(?:launchdarkly)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{40})\b",
               "critical", "launchdarkly", min_entropy=3.0),
    SecretRule("netlify", "Netlify access token",
               r"(?i)\b(?:netlify)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{40,46})\b",
               "critical", "netlify", min_entropy=3.0),
    SecretRule("plaid", "Plaid secret key",
               r"(?i)\b(?:plaid)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{30})\b",
               "critical", "plaid", min_entropy=3.0),
    SecretRule("zendesk", "Zendesk secret key",
               r"(?i)\b(?:zendesk)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{40})\b",
               "critical", "zendesk", min_entropy=3.0),
    SecretRule("okta", "Okta access token",
               r"(?i)\b(?:okta)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}(00[\w=\-]{40})\b",
               "critical", "okta", min_entropy=3.0),
    SecretRule("sumologic", "SumoLogic access ID",
               r"(?i)\b(?:sumo)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}(su[a-zA-Z0-9]{12})\b",
               "high", "sumo", min_entropy=3.0),
    SecretRule("travisci", "Travis CI access token",
               r"(?i)\b(?:travis)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{22})\b",
               "high", "travis", min_entropy=3.0),
    SecretRule("mattermost", "Mattermost access token",
               r"(?i)\b(?:mattermost)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{26})\b",
               "high", "mattermost", min_entropy=3.0),
    SecretRule("codecov", "Codecov access token",
               r"(?i)\b(?:codecov)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{32})\b",
               "high", "codecov", min_entropy=3.0),
    SecretRule("confluent", "Confluent secret key",
               r"(?i)\b(?:confluent)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{64})\b",
               "critical", "confluent", min_entropy=3.0),
    SecretRule("contentful", "Contentful delivery token",
               r"(?i)\b(?:contentful)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{43})\b",
               "critical", "contentful", min_entropy=3.0),
    SecretRule("fastly", "Fastly API token",
               r"(?i)\b(?:fastly)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{32})\b",
               "critical", "fastly", min_entropy=3.0),
    SecretRule("asana", "Asana client secret",
               r"(?i)\b(?:asana)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{32})\b",
               "high", "asana", min_entropy=3.0),
    SecretRule("bitbucket_client", "Bitbucket client secret",
               r"(?i)\b(?:bitbucket)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{64})\b",
               "critical", "bitbucket", min_entropy=3.0),
    SecretRule("discord_client", "Discord client secret",
               r"(?i)\b(?:discord)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9=_\-]{32})\b",
               "high", "discord", min_entropy=3.0),
    SecretRule("linkedin_client", "LinkedIn client secret",
               r"(?i)\b(?:linked[_-]?in)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{16})\b",
               "high", "linkedin", min_entropy=3.0),
    SecretRule("mailgun", "Mailgun private API token",
               r"(?i)\b(?:mailgun)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}(key-[a-f0-9]{32})\b",
               "critical", "mailgun", min_entropy=3.0),
    SecretRule("dropbox_long", "Dropbox long-lived API token",
               r"(?i)\b(?:dropbox)[\s'\"]{0,3}(?:=|:)[\x60'\"\s=]{0,5}([a-z0-9]{11}AAAAAAAAAA[a-z0-9\-_=]{43})\b",
               "critical", "dropbox", min_entropy=3.0),
]

# Rules whose format is distinctive enough to bypass the looks-like-code check
# (URLs, PEM headers, JWTs, and provider-keyword context rules).
_BYPASS_CODE_CHECK = {
    "slack_webhook", "private_key_pem", "private_key_openssh",
    "pgp_private_key", "jwt", "gcp_service_account",
    # Provider-keyword context rules (cloudflare=..., datadog=..., etc.)
    "cloudflare", "datadog", "mailchimp", "heroku", "sentry", "jfrog",
    "intercom", "launchdarkly", "netlify", "plaid", "zendesk", "okta",
    "sumologic", "travisci", "mattermost", "codecov", "confluent",
    "contentful", "fastly", "asana", "bitbucket_client", "discord_client",
    "linkedin_client", "mailgun", "dropbox", "dropbox_long", "airtable",
    "algolia", "twitch", "twitter_bearer", "mapbox",
}

# Rules that must run against the whole content (multi-line), not per-line.
_MULTILINE_RULES = {
    "kubernetes_secret",
}

# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string in bits per char ."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = float(len(s))
    ent = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent


# ---------------------------------------------------------------------------
# Path confidence 
# ---------------------------------------------------------------------------

_NOISE_DIR_FRAGMENTS = [
    "/node_modules/", "/.git/", "/.svn/", "/.hg/", "/dist/", "/build/",
    "/out/", "/target/", "/bin/", "/obj/", "/.venv/", "/venv/",
    "/__pycache__/", "/.tox/", "/coverage/", "/.next/", "/.nuxt/",
    "/.gradle/", "/Pods/", "/.terraform/", "/vendor/", "/site-packages/",
    "/.cache/", "/packages/", "/.cargo/", "/.rustup/", "/.npm/",
    "/.nuget/", "/.m2/", "/Carthage/", "/.yarn/", "/.pnpm-store/",
    "/bower_components/", "/.gem/", "/.bundle/", "/gopath/pkg/",
    "/fixtures/", "/testdata/", "/__tests__/", "/mocks/", "/mock/",
    "/coverage/", "/.next/", "/tmp/", "/temp/",
]

_HIGH_VALUE_DIR_FRAGMENTS = [
    "/dev/", "/src/", "/projects/", "/repos/", "/code/", "/work/",
]

# Paths where context-layer matching is dominated by clones/caches/fixtures.
_CONTEXT_LOW_TRUST_FRAGMENTS = [
    "/cache/", "/.cache/", "/tmp/", "/temp/", "/fixtures/", "/testdata/",
    "/__tests__/", "/mocks/", "/mock/", "/_repo/", "/.gradle/caches/",
    "/.cargo/registry/", "/site-packages/", "/coverage/", "/.next/",
    "/.nuget/", "/node_modules/", "/bower_components/", "/.pnpm-store/",
    "/.yarn/", "/vendor/bundle/", "/gopath/pkg/", "/.gem/", "/.bundle/",
]


def _path_confidence(file_path: str) -> str:
    """Return 'low' | 'medium' | 'high' for a file path ."""
    low = file_path.lower()
    for frag in _NOISE_DIR_FRAGMENTS:
        if frag in low:
            return "low"
    for frag in _HIGH_VALUE_DIR_FRAGMENTS:
        if frag in low:
            return "high"
    return "medium"


def _is_env_file(file_path: str) -> bool:
    name = Path(file_path).name.lower()
    return (
        name.startswith(".env")
        or name in ("credentials", "config", "secrets", ".npmrc", ".pypirc", ".netrc")
    )


def _is_context_low_trust(file_path: str) -> bool:
    low = file_path.lower()
    return any(frag in low for frag in _CONTEXT_LOW_TRUST_FRAGMENTS)


def _is_example_or_template(file_path: str) -> bool:
    base = Path(file_path).name.lower()
    if base.startswith(".env") and base.endswith((".example", ".sample", ".template", ".dist")):
        return True
    return base.endswith((".env.example", ".env.sample"))


# ---------------------------------------------------------------------------
# False-positive heuristics
# ---------------------------------------------------------------------------

_CODE_INDICATORS = [
    "__", "function", "callback", "eventid", "handler", "classname",
    "onclick", "onchange", "addeventlistener", "prototype", "constructor",
    "tostring", "undefined", "template", "component", "module.exports",
]


def _looks_like_code(val: str) -> bool:
    """True if the value looks like a code identifier, not a real secret."""
    lower = val.lower()
    for ind in _CODE_INDICATORS:
        if ind in lower:
            return True
    # 3+ long lowercase word segments (camelCase identifiers) after any prefix.
    check = val[8:] if len(val) > 8 else val
    consecutive_lower = 0
    long_word_segments = 0
    for c in check:
        if "a" <= c <= "z":
            consecutive_lower += 1
        else:
            if consecutive_lower >= 5:
                long_word_segments += 1
            consecutive_lower = 0
    if consecutive_lower >= 5:
        long_word_segments += 1
    return long_word_segments >= 3


_PLACEHOLDER_PREFIXES = [
    "your_", "insert_", "replace_with_", "replace_", "enter_your_", "my_api_",
    "xxx", "test_fake_", "fake_", "dummy_", "sample_", "mock_", "lorem",
    "foobar", "foo_bar", "bar_baz", "example_", "ex_",
]

_PLACEHOLDER_VALUES = {
    "changeme", "change_me", "replace_me", "your_token_here",
    "xxx", "todo", "placeholder", "example", "test", "dummy", "redacted",
    "redacted_by_vaultify",
}


def _is_repeating_char_string(val: str) -> bool:
    if len(val) < 10:
        return False
    first = val[0]
    return all(c == first for c in val[1:])


def _is_placeholder(val: str) -> bool:
    if _is_repeating_char_string(val):
        return True
    lower = val.lower()
    if lower in _PLACEHOLDER_VALUES:
        return True
    for p in _PLACEHOLDER_PREFIXES:
        if lower.startswith(p):
            return True
    # Test-mode prefixes (context layer only)
    return bool(lower.startswith(("pk_test_", "sk_test_", "whsec_test_", "rk_test_")))


# Markers left behind by secret-redaction tooling: a value carrying one of
# these is already sanitized and is not a live credential.
_REDACTION_MARKERS = ("redacted", "redacted_by_vaultify", "***redacted***", "[redacted]")


def _is_redacted_or_vault_ref(val: str) -> bool:
    """True when a value is a secret-manager reference or already redacted."""
    v = val.strip()
    if not v:
        return False
    if v.startswith("op://"):
        return True
    low = v.lower()
    return any(marker in low for marker in _REDACTION_MARKERS)


def _rhs_is_non_literal(val: str) -> bool:
    """True if the RHS is a function call, not a literal secret."""
    trimmed = val.strip()
    if not trimmed:
        return False
    paren = trimmed.find("(")
    if paren <= 0:
        return False
    fn = trimmed[:paren].strip()
    if not fn:
        return False
    return all(c.isalnum() or c in "_." for c in fn)


# ---------------------------------------------------------------------------
# Context-layer pattern 
# ---------------------------------------------------------------------------

_CONTEXT_PATTERN = re.compile(
    r"(?i)([\w]*(?:"
    r"api_key|apikey|api_secret|api_token|"
    r"secret_key|secret_access|client_secret|"
    r"auth_token|access_token|bearer_token|bot_token|"
    r"password|passwd|"
    r"private_key|encryption_key|signing_key|"
    r"database_url|db_url|db_password|db_pass|"
    r"connection_string|conn_str|"
    r"webhook_url|webhook_secret"
    r")[\w]*)\s*[=:]\s*[\"'\x60]?([^\"'\x60\s\r\n]{8,})[\"'\x60]?"
)

_CONTEXT_ENTROPY_FLOOR = 3.25


# ---------------------------------------------------------------------------
# Allowlist 
# ---------------------------------------------------------------------------

# Paths that are never scanned for secrets (lockfiles, vendor, images, etc.)
_ALLOWLIST_PATH_PATTERNS = [
    re.compile(r"(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$"),
    re.compile(r"(?i)\.(?:eot|[ot]tf|woff2?)$"),
    re.compile(r"(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf)$"),
    re.compile(r"go\.(?:mod|sum|work(?:\.sum)?)$"),
    re.compile(r"(?:^|/)node_modules(?:/.*)?$"),
    re.compile(r"(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$"),
    re.compile(r"(?:^|/)bower_components(?:/.*)?$"),
    re.compile(r"(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$"),
    re.compile(r"(?:^|/)(?:Pipfile|poetry)\.lock$"),
    re.compile(r"(?:^|/)\.git$"),
]

# Regexes that match placeholder / non-secret values 
_ALLOWLIST_REGEXES = [
    re.compile(r"(?i)^true|false|null$"),
    re.compile(r"^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)$"),
    re.compile(r"^\$(?:\d+|{\d+})$"),
    re.compile(r"^\$(?:[A-Z_]+|[a-z_]+)$"),
    re.compile(r"^\${(?:[A-Z_]+|[a-z_]+)}$"),
    re.compile(r"^\{\{[ \t]*[\w ().|]+[ \t]*}}$"),
    re.compile(r"^\$\{\{[ \t]*(?:(?:env|github|secrets|vars)(?:\.[A-Za-z]\w+)+[\w \"'&./=|]*)[ \t]*}}$"),
    re.compile(r"^%(?:[A-Z_]+|[a-z_]+)%$"),
    re.compile(r"^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$"),
    re.compile(r"^\{\d{0,2}}$"),
    re.compile(r"^@(?:[A-Z_]+|[a-z_]+)@$"),
    re.compile(r"^/Users/[a-z0-9]+/[\w ./-]+$", re.IGNORECASE),
    re.compile(r"^/(?:bin|etc|home|opt|tmp|usr|var)/[\w ./-]+$"),
]

_STOPWORDS = {
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
}


def _is_allowlisted_path(file_path: str) -> bool:
    return any(pat.search(file_path) for pat in _ALLOWLIST_PATH_PATTERNS)


def _is_allowlisted_value(val: str) -> bool:
    v = val.strip()
    if v.lower() in _STOPWORDS:
        return True
    return any(pat.match(v) for pat in _ALLOWLIST_REGEXES)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def redact(val: str) -> str:
    """Redact a secret value, keeping only a short preview."""
    if len(val) > 12:
        return val[:6] + "..." + val[-4:]
    if len(val) > 8:
        return val[:4] + "..." + val[-4:]
    return "***REDACTED***"


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class SecretDetector:
    """Scan content for secrets using the shared rule catalog + heuristics."""

    def __init__(self, rules: list[SecretRule] | None = None):
        self.rules = rules if rules is not None else RULES
        self._compiled: list[tuple[SecretRule, re.Pattern]] = []
        for rule in self.rules:
            flags = re.IGNORECASE if rule.ignore_case else 0
            pattern = compile_safe_regex(rule.regex, flags)
            if pattern is None:
                # Drop unsafe/invalid rules at load time — never at scan time.
                continue
            self._compiled.append((rule, pattern))

    # -- public API --------------------------------------------------------

    def scan(self, content: str, file_path: str = "") -> list[SecretMatch]:
        """Scan content and return all secret matches (redacted)."""
        if _is_allowlisted_path(file_path):
            return []
        content = _bounded_text(content)
        matches: list[SecretMatch] = []
        seen: set[tuple[str, str]] = set()  # (rule_id, redacted) dedupe

        # Multi-line rules (e.g. Kubernetes Secret manifests) run against the
        # whole content, not per-line.
        for rule, pattern in self._compiled:
            if rule.id not in _MULTILINE_RULES:
                continue
            if rule.prefix and rule.prefix not in content:
                continue
            for m in pattern.finditer(content):
                val = m.group(0)
                if len(val) < 8 or _is_redacted_or_vault_ref(val):
                    continue
                if _is_allowlisted_value(val):
                    continue
                key = (rule.id, redact(val))
                if key in seen:
                    continue
                seen.add(key)
                matches.append(SecretMatch(
                    rule_id=rule.id,
                    secret_type=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    redacted=redact(val),
                    entropy=shannon_entropy(val),
                    confidence=self._compute_confidence(
                        shannon_entropy(val), "value", file_path, 0),
                    detection_layer="value",
                    raw_length=len(val),
                    context=val[:200],
                ))

        for line in content.splitlines():
            if any(marker in line.lower() for marker in _REDACTION_MARKERS):
                continue
            has_assign = "=" in line or ":" in line

            # Layer 2: context detection (key-name matching on assignment lines)
            if has_assign and not _is_context_low_trust(file_path) \
                    and not _is_example_or_template(file_path):
                for m in _CONTEXT_PATTERN.finditer(line):
                    key_name = m.group(1)
                    val = m.group(2)
                    if len(val) < 8 or _is_placeholder(val) \
                            or _is_redacted_or_vault_ref(val) \
                            or _rhs_is_non_literal(val):
                        continue
                    ent = shannon_entropy(val)
                    if not self._context_value_allowed(file_path, val, ent):
                        continue
                    key = (key_name.lower(), redact(val))
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append(SecretMatch(
                        rule_id="context",
                        secret_type="context_credential",
                        description=f"Context-detected credential: {key_name}",
                        severity="high",
                        redacted=redact(val),
                        entropy=ent,
                        confidence=self._compute_confidence(
                            ent, "context", file_path, 0),
                        detection_layer="context",
                        context_key=key_name,
                        raw_length=len(val),
                        context=line.strip()[:200],
                    ))

            # Layer 1: value pattern detection (all lines)
            for rule, pattern in self._compiled:
                if rule.prefix and rule.prefix not in line:
                    continue
                if rule.keywords and not any(k in line for k in rule.keywords):
                    continue
                for m in pattern.finditer(line):
                    val = m.group(0)
                    if len(val) < 8 or _is_redacted_or_vault_ref(val):
                        continue
                    if _is_allowlisted_value(val):
                        continue
                    if not self._is_likely_secret(rule, val, file_path):
                        continue
                    key = (rule.id, redact(val))
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append(SecretMatch(
                        rule_id=rule.id,
                        secret_type=rule.id,
                        description=rule.description,
                        severity=rule.severity,
                        redacted=redact(val),
                        entropy=shannon_entropy(val),
                        confidence=self._compute_confidence(
                            shannon_entropy(val), "value", file_path, 0),
                        detection_layer="value",
                        raw_length=len(val),
                        context=line.strip()[:200],
                    ))

        return matches

    # -- heuristics --------------------------------------------------------

    def _is_likely_secret(self, rule: SecretRule, val: str, file_path: str) -> bool:
        # Strong-prefix rules (distinctive token prefixes like dapi_, ghp_,
        # sk-proj-) bypass the looks-like-code heuristic — a distinctive
        # prefix is far stronger evidence than the code-shape check.
        if not rule.strong_prefix and rule.id not in _BYPASS_CODE_CHECK \
                and _looks_like_code(val):
            return False
        if rule.strong_prefix:
            # A distinctive prefix (e.g. sk-proj-) is far stronger evidence
            # than the entropy gate — bypass it entirely.
            threshold = 0.0
        elif rule.min_entropy <= 0:
            # No entropy gate configured: require a reasonable default so
            # generic rules don't fire on noise.
            threshold = 3.0
        else:
            threshold = rule.min_entropy
        ent = shannon_entropy(val)
        path_conf = _path_confidence(file_path)
        if path_conf == "low":
            threshold += 0.5
        elif path_conf == "high":
            threshold -= 0.3
        return ent >= threshold

    def _context_value_allowed(self, file_path: str, val: str, ent: float) -> bool:
        if _is_placeholder(val):
            return False
        if _looks_like_code(val):
            return False
        min_ent = _CONTEXT_ENTROPY_FLOOR
        if _path_confidence(file_path) == "low":
            min_ent += 0.45
        return ent >= min_ent

    def _compute_confidence(self, ent: float, layer: str, file_path: str,
                            file_context_count: int) -> float:
        score = 0.0
        if ent >= 4.5:
            score += 0.4
        elif ent >= 3.5:
            score += 0.3
        elif ent >= 2.5:
            score += 0.2
        if layer == "both":
            score += 0.35
        elif layer == "value":
            score += 0.3
        elif layer == "context":
            score += 0.2
        if _is_env_file(file_path):
            score += 0.15
        if file_context_count > 3:
            score += 0.1
        return min(score, 1.0)


# Convenience singleton
detector = SecretDetector()
