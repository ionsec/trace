package catalog

import "testing"

func TestPlatformsNonEmpty(t *testing.T) {
	if len(Platforms) < 40 {
		t.Fatalf("expected at least 40 platforms, got %d", len(Platforms))
	}
	seen := map[string]bool{}
	for _, p := range Platforms {
		if p.Name == "" {
			t.Errorf("platform %+v has empty Name", p)
		}
		if seen[p.Name] {
			t.Errorf("duplicate platform name %q", p.Name)
		}
		seen[p.Name] = true
	}
}

func TestByNameFound(t *testing.T) {
	want := Platforms[0].Name
	got, ok := ByName(want)
	if !ok {
		t.Fatalf("ByName(%q) not found", want)
	}
	if got.Name != want {
		t.Errorf("ByName(%q).Name = %q, want %q", want, got.Name, want)
	}
}

func TestByNameMissing(t *testing.T) {
	if _, ok := ByName("__definitely_not_a_platform__"); ok {
		t.Error("ByName returned ok=true for a name that does not exist")
	}
}

func TestNewPlatformsPresent(t *testing.T) {
	for _, name := range []string{
		"codex_cli", "gemini_cli", "opencode", "cline", "copilot", "warp",
		"goose", "kiro", "amazon_q", "zed", "pi_family", "kimi_code",
		"qwen_code", "continue", "augment", "grok", "amp", "kilo",
		"jan", "anythingllm", "localai", "open_webui", "vllm", "lemonade",
		"desktop_chat",
	} {
		if _, ok := ByName(name); !ok {
			t.Errorf("platform %q missing from catalog", name)
		}
	}
}
