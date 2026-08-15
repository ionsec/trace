"""Tests for the shared SecretDetector."""

import pytest

from ionsec_trace.analyzer.secret_detector import (
    RULES,
    SecretDetector,
    SecretMatch,
    redact,
    shannon_entropy,
)


@pytest.fixture
def detector():
    return SecretDetector()


# ---------------------------------------------------------------------------
# Rule catalog
# ---------------------------------------------------------------------------


class TestRuleCatalog:
    def test_has_ai_provider_rules(self):
        ids = {r.id for r in RULES}
        for expected in (
            "openai_legacy", "openai_project", "anthropic", "xai",
            "google_ai", "huggingface", "deepseek", "mistral",
            "replicate", "together", "groq", "perplexity", "openrouter",
        ):
            assert expected in ids, f"missing rule {expected}"

    def test_has_infra_rules(self):
        ids = {r.id for r in RULES}
        for expected in (
            "github_pat", "github_fine", "gitlab_pat", "aws_access_key",
            "stripe", "slack_bot", "discord_bot", "npm_token", "pypi_token",
            "jwt", "private_key_pem", "private_key_openssh", "pgp_private_key",
        ):
            assert expected in ids, f"missing rule {expected}"

    def test_all_rules_compile(self):
        d = SecretDetector()
        assert len(d._compiled) == len(RULES)


# ---------------------------------------------------------------------------
# Value-pattern detection
# ---------------------------------------------------------------------------


class TestValueDetection:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("sk-proj-abc123def456ghi789jkl012mno345", "openai_project"),
            ("sk-abcdefghijklmnopqrstuvwxyz123456", "openai_legacy"),
            ("sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456", "anthropic"),
            ("xai-abcdefghijklmnopqrstuvwxyz123456", "xai"),
            ("AIzaSyA-1234567890abcdefghijklmnopqrstuvwxyz", "google_ai"),
            ("hf_abcdefghijklmnopqrstuvwxyz123456", "huggingface"),
            ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github_pat"),
            ("github_pat_abcdefghijklmnopqrstuvwxyz123456", "github_fine"),
            ("glpat-abcdefghijklmnopqrstuvwxyz123456", "gitlab_pat"),
            ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
            ("sk_test_abcdefghijklmnopqrstuvwxyz123456", "stripe"),
            ("xoxb-123456789012345678901234567890123456789012345678901234", "slack_bot"),
            ("npm_abcdefghijklmnopqrstuvwxyz1234567890", "npm_token"),
            ("pypi-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz", "pypi_token"),
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt"),
            ("-----BEGIN PRIVATE KEY-----", "private_key_pem"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_openssh"),
            ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key"),
        ],
    )
    def test_detects_known_secret(self, detector, value, expected):
        matches = detector.scan(f'x = "{value}"', "/home/user/projects/app/config.py")
        ids = {m.rule_id for m in matches}
        assert expected in ids, f"expected {expected} in {ids}"

    def test_redacts_value(self, detector):
        matches = detector.scan(
            'key = "sk-proj-abc123def456ghi789jkl012mno345"',
            "/home/user/projects/app/config.py",
        )
        assert matches
        m = matches[0]
        assert isinstance(m, SecretMatch)
        assert "sk-proj-abc123" not in m.redacted  # full value never leaked
        assert m.redacted.startswith("sk-pro")
        assert "..." in m.redacted

    def test_deduplicates_same_secret(self, detector):
        content = (
            'a = "sk-proj-abc123def456ghi789jkl012mno345"\n'
            'b = "sk-proj-abc123def456ghi789jkl012mno345"\n'
        )
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Context-layer detection
# ---------------------------------------------------------------------------


class TestContextDetection:
    def test_detects_prefixless_secret_by_key_name(self, detector):
        content = 'client_secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert matches
        assert matches[0].detection_layer == "context"
        assert matches[0].context_key == "client_secret"

    def test_detects_access_token(self, detector):
        content = 'access_token = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert any(m.detection_layer == "context" for m in matches)

    def test_skips_placeholder_value(self, detector):
        content = 'api_key = "your_api_key_here"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert not matches

    def test_skips_code_identifier(self, detector):
        content = "access_token = create_access_token(user)"
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert not matches

    def test_skips_short_value(self, detector):
        content = 'api_key = "abc"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert not matches


# ---------------------------------------------------------------------------
# False-positive suppression
# ---------------------------------------------------------------------------


class TestFalsePositives:
    def test_allowlisted_path_skipped(self, detector):
        content = 'key = "sk-proj-abc123def456ghi789jkl012mno345"'
        matches = detector.scan(
            content, "/home/user/projects/app/node_modules/pkg/index.js"
        )
        assert not matches

    def test_allowlisted_placeholder_value(self, detector):
        content = 'key = "{{ secrets.OPENAI_API_KEY }}"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert not matches

    def test_allowlisted_env_var_ref(self, detector):
        content = 'key = "$OPENAI_API_KEY"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert not matches

    def test_redacted_marker_skipped(self, detector):
        content = 'key = "REDACTED_BY_VAULTIFY"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert not matches

    def test_low_entropy_generic_rejected(self, detector):
        # "key-" generic rule requires entropy; a low-entropy value is noise.
        content = 'key = "key-aaaaaaaaaaaaaaaaaaaa"'
        matches = detector.scan(content, "/home/user/projects/app/config.py")
        assert not matches


# ---------------------------------------------------------------------------
# Entropy / redaction helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_shannon_entropy_high_for_random(self):
        assert shannon_entropy("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7") > 3.5

    def test_shannon_entropy_low_for_repeated(self):
        assert shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa") < 1.0

    def test_shannon_entropy_empty(self):
        assert shannon_entropy("") == 0.0

    def test_redact_long(self):
        assert redact("abcdefghijklmnopqrstuvwxyz") == "abcdef...wxyz"

    def test_redact_short(self):
        assert redact("abc") == "***REDACTED***"
