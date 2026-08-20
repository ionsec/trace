package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestResolveEvidenceDirIsAbsolute is the Windows regression: every path TRACE
// prints must name the real destination, so a relative or driveless -o value
// still resolves to an absolute path.
func TestResolveEvidenceDirIsAbsolute(t *testing.T) {
	for _, in := range []string{"", "evidence", "./evidence", "/evidence"} {
		got := resolveEvidenceDir(in, io.Discard)
		if !filepath.IsAbs(got) {
			t.Errorf("resolveEvidenceDir(%q) = %q, want an absolute path", in, got)
		}
	}
}

// TestResolveEvidenceDirDefaults verifies an empty flag value falls back to the
// documented default rather than the current directory.
func TestResolveEvidenceDirDefaults(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	want := filepath.Join(cwd, "evidence")
	if got := resolveEvidenceDir("", io.Discard); got != want {
		t.Errorf("resolveEvidenceDir(\"\") = %q, want %q", got, want)
	}
}

// TestResolveEvidenceDirWarnsOnDrivelessWindowsPath verifies the driveless form
// that started this bug report is called out, because on Windows it silently
// resolves against the current drive.
func TestResolveEvidenceDirWarnsOnDrivelessWindowsPath(t *testing.T) {
	var warn strings.Builder
	resolveEvidenceDir("/evidence", &warn)

	warned := strings.Contains(warn.String(), "no drive letter")
	if runtime.GOOS == "windows" && !warned {
		t.Error("expected a warning for /evidence on Windows")
	}
	if runtime.GOOS != "windows" && warned {
		t.Errorf("unexpected Windows warning on %s: %q", runtime.GOOS, warn.String())
	}
}

// TestDriveless pins which paths count as rooted-but-driveless.
func TestDriveless(t *testing.T) {
	cases := map[string]bool{
		"/evidence":     true,
		`\evidence`:     true,
		"evidence":      false,
		"./evidence":    false,
		`C:\evidence`:   false,
		"/tmp/evidence": true,
	}
	for in, want := range cases {
		if got := driveless(in); got != want {
			t.Errorf("driveless(%q) = %v, want %v", in, got, want)
		}
	}
}
