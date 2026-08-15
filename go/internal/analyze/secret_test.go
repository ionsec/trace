package analyze

import "testing"

// realPath is a high-confidence source path, so path heuristics do not
// suppress the fixtures below.
const realPath = "/home/user/projects/app/config.py"

// TestRuleCatalogCompiles verifies every catalogued rule survives the
// load-time safety check — a dropped rule is a silent detection gap.
func TestRuleCatalogCompiles(t *testing.T) {
	d := NewSecretDetector()
	if d.RuleCount() != len(secretRules) {
		t.Fatalf("compiled %d of %d rules", d.RuleCount(), len(secretRules))
	}
	if len(secretRules) < 100 {
		t.Fatalf("catalog has %d rules, want >= 100", len(secretRules))
	}
}

// TestCatalogCoversProvidersAndInfra pins the rule IDs the reports rely on.
func TestCatalogCoversProvidersAndInfra(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range secretRules {
		ids[r.ID] = true
	}
	for _, want := range []string{
		"openai_legacy", "openai_project", "anthropic", "xai", "google_ai",
		"huggingface", "deepseek", "mistral", "replicate", "together", "groq",
		"perplexity", "openrouter", "github_pat", "github_fine", "gitlab_pat",
		"aws_access_key", "stripe", "slack_bot", "discord_bot", "npm_token",
		"pypi_token", "jwt", "private_key_pem", "private_key_openssh",
		"pgp_private_key",
	} {
		if !ids[want] {
			t.Errorf("catalog missing rule %q", want)
		}
	}
}

// TestDetectsKnownSecrets runs the same fixtures as the Python suite so both
// builds are proven to recognize the same credentials.
func TestDetectsKnownSecrets(t *testing.T) {
	cases := []struct{ value, rule string }{
		{"sk-proj-abc123def456ghi789jkl012mno345", "openai_project"},
		{"sk-abcdefghijklmnopqrstuvwxyz123456", "openai_legacy"},
		{"sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456", "anthropic"},
		{"xai-abcdefghijklmnopqrstuvwxyz123456", "xai"},
		{"AIzaSyA-1234567890abcdefghijklmnopqrstuvwxyz", "google_ai"},
		{"hf_abcdefghijklmnopqrstuvwxyz123456", "huggingface"},
		{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github_pat"},
		{"github_pat_abcdefghijklmnopqrstuvwxyz123456", "github_fine"},
		{"glpat-abcdefghijklmnopqrstuvwxyz123456", "gitlab_pat"},
		{"AKIAIOSFODNN7EXAMPLE", "aws_access_key"},
		{"sk_test_abcdefghijklmnopqrstuvwxyz123456", "stripe"},
		{"xoxb-123456789012345678901234567890123456789012345678901234", "slack_bot"},
		{"npm_abcdefghijklmnopqrstuvwxyz1234567890", "npm_token"},
		{"pypi-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz", "pypi_token"},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt"},
		{"-----BEGIN PRIVATE KEY-----", "private_key_pem"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_openssh"},
		{"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key"},
	}
	d := NewSecretDetector()
	for _, tc := range cases {
		matches := d.Scan(`x = "`+tc.value+`"`, realPath)
		found := false
		for _, m := range matches {
			if m.RuleID == tc.rule {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule %q did not fire for its own fixture", tc.rule)
		}
	}
}

// TestRedactsAndDeduplicates verifies raw values never escape and that the
// same secret is reported once per file.
func TestRedactsAndDeduplicates(t *testing.T) {
	d := NewSecretDetector()
	secret := "sk-proj-abc123def456ghi789jkl012mno345"

	matches := d.Scan(`key = "`+secret+`"`, realPath)
	if len(matches) == 0 {
		t.Fatal("no matches")
	}
	for _, m := range matches {
		if m.Redacted == secret {
			t.Error("match carried the raw secret value")
		}
	}

	dup := d.Scan("a = \""+secret+"\"\nb = \""+secret+"\"\n", realPath)
	if len(dup) != 1 {
		t.Errorf("duplicate secret reported %d times, want 1", len(dup))
	}
}

// TestContextLayer covers prefix-less secrets caught by key name.
func TestContextLayer(t *testing.T) {
	d := NewSecretDetector()
	matches := d.Scan(`client_secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"`, realPath)
	if len(matches) == 0 {
		t.Fatal("context-layer secret not detected")
	}
	if matches[0].DetectionLayer != "context" || matches[0].ContextKey != "client_secret" {
		t.Errorf("got layer=%q key=%q", matches[0].DetectionLayer, matches[0].ContextKey)
	}
}

// TestFalsePositiveSuppression covers the noise the detector must stay quiet on.
func TestFalsePositiveSuppression(t *testing.T) {
	d := NewSecretDetector()
	cases := []struct {
		name, content, path string
	}{
		{"placeholder", `api_key = "your_api_key_here"`, realPath},
		{"code identifier", `access_token = create_access_token(user)`, realPath},
		{"short value", `api_key = "abc"`, realPath},
		{"template expression", `key = "{{ secrets.OPENAI_API_KEY }}"`, realPath},
		{"env var reference", `key = "$OPENAI_API_KEY"`, realPath},
		{"already redacted", `key = "REDACTED_BY_VAULTIFY"`, realPath},
		{"low entropy generic", `key = "key-aaaaaaaaaaaaaaaaaaaa"`, realPath},
		{"allowlisted path", `key = "sk-proj-abc123def456ghi789jkl012mno345"`,
			"/home/user/projects/app/node_modules/pkg/index.js"},
	}
	for _, tc := range cases {
		if matches := d.Scan(tc.content, tc.path); len(matches) != 0 {
			t.Errorf("%s: expected no matches, got %d (%s)", tc.name, len(matches), matches[0].RuleID)
		}
	}
}

// TestEntropyAndRedaction covers the shared helpers.
func TestEntropyAndRedaction(t *testing.T) {
	if e := shannonEntropy("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7"); e <= 3.5 {
		t.Errorf("random string entropy %.2f, want > 3.5", e)
	}
	if e := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaa"); e >= 1.0 {
		t.Errorf("repeated string entropy %.2f, want < 1.0", e)
	}
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("empty string entropy %.2f, want 0", e)
	}
	if got := Redact("abcdefghijklmnopqrstuvwxyz"); got != "abcdef...wxyz" {
		t.Errorf("Redact long = %q", got)
	}
	if got := Redact("abc"); got != "***REDACTED***" {
		t.Errorf("Redact short = %q", got)
	}
}
