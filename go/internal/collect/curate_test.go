package collect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCuratedKeepsParseable verifies the curation filter retains analyst-parseable files.
func TestCuratedKeepsParseable(t *testing.T) {
	cases := []struct {
		path string
		keep bool
		typ  string
	}{
		{"/home/u/.claude/settings.json", true, "config"},
		{"/home/u/.claude/projects/foo/123.jsonl", true, "session"},
		{"/home/u/.ollama/history", true, "cli_history"},
		{"/home/u/.ollama/config.json", true, "config"},
		{"/home/u/.cursor/User/globalStorage/state.vscdb", true, "conversation_database"},
		{"/home/u/.env", true, "credential"},
		{"/home/u/.cursor/extensions/foo/extension.js", false, ""},
		{"/home/u/.cursor/extensions/foo/README.md", false, ""},
		{"/home/u/.cursor/extensions/foo/.vsixmanifest", false, ""},
		{"/home/u/.claude/file-history/abc/def@v2", false, ""},
		{"/home/u/.claude/backups/.claude.json.backup.123", false, ""},
		{"/home/u/.cursor/.DS_Store", false, ""},
		{"/home/u/.ollama/models/blobs/sha256-abc", false, ""},
		{"/home/u/randomfile.bin", false, ""},
		{"/home/u/node_modules/pkg/index.js", false, ""},
	}
	for _, c := range cases {
		typ, keep := curated(c.path, 100, false)
		if keep != c.keep || (keep && typ != c.typ) {
			t.Errorf("curated(%q) = (%q,%v), want (%q,%v)", c.path, typ, keep, c.typ, c.keep)
		}
	}
}

// TestCuratedDeepMiscText verifies deep mode keeps small text files.
func TestCuratedDeepMiscText(t *testing.T) {
	// A .txt file is a parseable text extension; in deep mode it's kept as config.
	typ, keep := curated("/home/u/.claude/notes.txt", 100, true)
	if !keep || typ != "config" {
		t.Errorf("deep misc text: keep=%v typ=%q, want keep=true typ=config", keep, typ)
	}
	// Non-text extension should NOT be kept even in deep mode.
	if _, keep := curated("/home/u/.claude/native-bin", 100, true); keep {
		t.Error("native binary should not be kept in deep mode")
	}
}

// TestParseSQLiteRoundTrip creates a real SQLite file and verifies parsing.
func TestParseSQLiteRoundTrip(t *testing.T) {
	sqliteBin, err := findSQLiteBinary()
	if err != nil {
		t.Skip("sqlite3 not available:", err)
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "test.db")
	// Create a minimal SQLite DB with a conversations table.
	cmd := []string{sqliteBin, db, "CREATE TABLE conversations(id INTEGER, text TEXT); INSERT INTO conversations VALUES(1,'hello model');"}
	if out, err := runCmd(cmd); err != nil {
		t.Skipf("sqlite create failed: %v %s", err, out)
	}

	s := ParseSQLite(db)
	if s == nil {
		t.Fatal("ParseSQLite returned nil for a real sqlite file")
	}
	if !s.IsSQLite {
		t.Error("IsSQLite = false, want true")
	}
	if len(s.Tables) == 0 {
		t.Error("no tables extracted")
	}
	foundConv := false
	for _, tb := range s.Tables {
		if tb == "conversations" {
			foundConv = true
		}
	}
	if !foundConv {
		t.Errorf("tables = %v, want to contain 'conversations'", s.Tables)
	}
}

func findSQLiteBinary() (string, error) {
	for _, b := range []string{"sqlite3"} {
		if p, err := exec.LookPath(b); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("sqlite3 not on PATH")
}

func runCmd(args []string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestTruncationRecords verifies D3: when the per-tool file cap is hit, the
// collection is clipped and a truncation record is emitted rather than
// silently dropping files.
func TestTruncationRecords(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "tool")
	mustMkdir(t, root)
	// Create 5 parseable files.
	for i := 0; i < 5; i++ {
		mustWrite(t, filepath.Join(root, fmt.Sprintf("f%d.json", i)), fmt.Sprintf(`{"i":%d}`, i))
	}

	c := &collector{evidenceDir: t.TempDir(), used: map[string]string{}, maxFiles: 3}
	b := &budget{}
	out := c.collectRoot(root, "tool", b)

	if len(out) != 3 {
		t.Errorf("collected %d files, want 3 (capped)", len(out))
	}
	if !b.truncated {
		t.Error("budget.truncated = false, want true")
	}
	if b.skipped == 0 {
		t.Error("budget.skipped = 0, want > 0")
	}

	// A full Collect run must surface the truncation in the manifest.
	dir := t.TempDir()
	coc, err := Collect(dir, false, Options{MaxFilesPerTool: 3})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Truncations may be empty if no platform has >3 files on this host, but
	// the field must be present in the manifest JSON.
	data, err := os.ReadFile(filepath.Join(dir, "CHAIN_OF_CUSTODY.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(data), "truncations") {
		t.Error("manifest missing truncations field")
	}
	_ = coc
}
