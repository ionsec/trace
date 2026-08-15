"""Tests for the expanded SecretDetector rule catalog."""

import random
import string

import pytest

from ionsec_trace.analyzer.secret_detector import RULES, SecretDetector


def _he(n: int) -> str:
    """High-entropy lowercase alphanumeric string (matches provider formats)."""
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _hex(n: int) -> str:
    """High-entropy hex string (matches hex-only provider formats)."""
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


@pytest.fixture
def detector():
    return SecretDetector()


# Each case: (rule_id, content) — content must contain a realistic secret.
# Values use high-entropy material so the entropy gate passes.
CASES = [
    ("databricks", "DATABRICKS_TOKEN=dapi" + _hex(32)),
    ("digitalocean_pat", "DIGITALOCEAN_TOKEN=dop_v1_" + _hex(64)),
    ("doppler", "DOPPLER_TOKEN=dp.pt." + _he(43)),
    ("linear", "LINEAR_KEY=lin_api_" + _he(40)),
    ("notion", "NOTION_TOKEN=ntn_12345678901" + _he(32) + "abc"),
    ("postman", "POSTMAN_TOKEN=PMAK-" + _hex(24) + "-" + _hex(34)),
    ("pulumi", "PULUMI_TOKEN=pul-" + _hex(40)),
    ("github_refresh", "GITHUB_TOKEN=ghr_" + _he(36)),
    ("newrelic", "NEW_RELIC_API_KEY=NRAK-" + _he(27)),
    ("grafana", "GRAFANA_API_KEY=eyJrIjoi" + _he(80)),
    ("hashicorp_tf", "TF_API_TOKEN=" + _he(14) + ".atlasv1." + _he(65)),
    ("sonar", "SONAR_TOKEN=sqp_" + _he(40)),
    ("sendinblue", "SENDINBLUE_KEY=xkeysib-" + _hex(64) + "-" + _he(16)),
    ("square", "SQUARE_TOKEN=sq0atp-" + _he(30)),
    ("yandex", "YANDEX_KEY=AQVN" + _he(36)),
    ("maxmind", "MAXMIND_KEY=abcdef_" + _he(29) + "_mmk"),
    ("octopus", "OCTOPUS_KEY=API-" + _he(26).upper()),
    ("vault_batch", "VAULT_TOKEN=hvb." + _he(150)),
    ("cloudflare", "CLOUDFLARE_API_KEY=cloudflare=" + _he(40)),
    ("datadog", "DATADOG_API_KEY=datadog=" + _he(40)),
    ("mailchimp", "MAILCHIMP_API_KEY=mailchimp=" + _hex(32) + "-us12"),
    ("heroku", "HEROKU_API_KEY=heroku=12345678-1234-1234-1234-123456789012"),
    ("sentry", "SENTRY_AUTH_TOKEN=sentry=" + _hex(64)),
    ("jfrog", "JFROG_API_KEY=jfrog=" + _he(73)),
    ("intercom", "INTERCOM_API_KEY=intercom=" + _he(60)),
    ("launchdarkly", "LAUNCHDARKLY_TOKEN=launchdarkly=" + _he(40)),
    ("netlify", "NETLIFY_AUTH_TOKEN=netlify=" + _he(40)),
    ("plaid", "PLAID_SECRET=plaid=" + _he(30)),
    ("zendesk", "ZENDESK_API_KEY=zendesk=" + _he(40)),
    ("okta", "OKTA_API_TOKEN=okta=00" + _he(40)),
    ("confluent", "CONFLUENT_SECRET=confluent=" + _he(64)),
    ("contentful", "CONTENTFUL_TOKEN=contentful=" + _he(43)),
    ("fastly", "FASTLY_API_TOKEN=fastly=" + _he(32)),
    ("bitbucket_client", "BITBUCKET_CLIENT_SECRET=bitbucket=" + _he(64)),
    ("discord_client", "DISCORD_CLIENT_SECRET=discord=" + _he(32)),
    ("mailgun", "MAILGUN_API_KEY=mailgun=key-" + _hex(32)),
    ("dropbox_long", "DROPBOX_TOKEN=dropbox=" + _he(11) + "AAAAAAAAAA" + _he(43)),
]


@pytest.mark.parametrize("rule_id,content", CASES)
def test_new_rules_detect(detector, rule_id, content):
    """Each new rule should fire on a realistic secret value."""
    matches = detector.scan(content, "/tmp/test.env")
    ids = {m.rule_id for m in matches}
    assert rule_id in ids, f"rule {rule_id} did not fire on {content[:40]}..."


def test_rule_count_expanded():
    """The catalog should have grown well beyond the original ~40 rules."""
    assert len(RULES) >= 100


def test_strong_prefix_rules_bypass_code_check(detector):
    """Strong-prefix rules must not be filtered by the looks-like-code heuristic."""
    content = "DATABRICKS_TOKEN=dapi" + _hex(32)
    matches = detector.scan(content, "/tmp/test.env")
    assert any(m.rule_id == "databricks" for m in matches)


def test_kubernetes_secret_multiline(detector):
    """Kubernetes Secret manifests should be detected (multi-line)."""
    content = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  password: aGVsbG8="
    matches = detector.scan(content, "/tmp/k8s.yaml")
    assert any(m.rule_id == "kubernetes_secret" for m in matches)
