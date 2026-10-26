package catalog

import "testing"

func TestShadowToolsNonEmpty(t *testing.T) {
	if len(ShadowTools) < 5 {
		t.Fatalf("expected at least 5 shadow tools, got %d", len(ShadowTools))
	}
	for _, s := range ShadowTools {
		if s.Name == "" {
			t.Errorf("shadow tool %+v has empty Name", s)
		}
	}
}

func TestScanDirsNonEmpty(t *testing.T) {
	if len(LlamaCppInstallDirs) == 0 {
		t.Error("LlamaCppInstallDirs is empty")
	}
	if len(CodeScanDirs) == 0 {
		t.Error("CodeScanDirs is empty")
	}
	for _, dir := range append(append([]string{}, LlamaCppInstallDirs...), CodeScanDirs...) {
		if dir == "" {
			t.Error("scan dir list contains an empty string")
		}
	}
}

func TestHermesRoot(t *testing.T) {
	if HermesRoot != ".hermes" {
		t.Errorf("HermesRoot = %q, want %q", HermesRoot, ".hermes")
	}
}
