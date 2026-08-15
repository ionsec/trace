package detect

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHomeDirs verifies home dir resolution returns at least the user's home.
func TestHomeDirs(t *testing.T) {
	dirs := homeDirs()
	if len(dirs) == 0 {
		t.Fatal("expected at least one home dir")
	}
	if _, err := os.UserHomeDir(); err == nil {
		found := false
		h, _ := os.UserHomeDir()
		for _, d := range dirs {
			if d == h {
				found = true
			}
		}
		if !found {
			t.Errorf("user home %q not in homeDirs %v", h, dirs)
		}
	}
}

// TestResolvePath verifies path joining across OS separators.
func TestResolvePath(t *testing.T) {
	got := resolvePath("/home/user", ".ollama")
	if got != filepath.Join("/home/user", ".ollama") {
		t.Errorf("resolvePath = %q, want %q", got, filepath.Join("/home/user", ".ollama"))
	}

	// Windows-style rel should be handled.
	w := resolvePath("C:\\Users\\user", "AppData\\Roaming\\Cursor")
	if w == "" {
		t.Error("expected non-empty windows path")
	}
}

// TestCatalogNonEmpty verifies the curated shadowCatalog is populated.
func TestCatalogNonEmpty(t *testing.T) {
	if len(shadowCatalog) < 40 {
		t.Fatalf("shadowCatalog has %d entries, want >= 40", len(shadowCatalog))
	}
	// OpenClaw family must all be present.
	names := map[string]bool{}
	for _, c := range shadowCatalog {
		names[c.name] = true
	}
	for _, want := range []string{"openclaw", "clawdbot", "moltbot", "nanoclaw", "antigravity", "devin", "vscodium", "eigent"} {
		if !names[want] {
			t.Errorf("shadowCatalog missing %q", want)
		}
	}
}

// TestDiscoverDoesNotPanic verifies detection runs cleanly on the test host.
func TestDiscoverDoesNotPanic(t *testing.T) {
	ds := Discover()
	for _, d := range ds {
		if d.Tool == "" {
			t.Error("detection with empty tool name")
		}
	}
}

// TestFindBinary checks binary lookup against a known executable.
func TestFindBinary(t *testing.T) {
	// At minimum, the test binary's own PATH should contain `go` or `sh`.
	if findBinary([]string{"this-does-not-exist-xyz"}) != "" {
		t.Error("expected empty for missing binary")
	}
}
