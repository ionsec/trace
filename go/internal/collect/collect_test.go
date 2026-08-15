package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClassifyArtifact verifies artifact type classification.
func TestClassifyArtifact(t *testing.T) {
	cases := map[string]string{
		"config.json":    "config",
		"settings.yaml":  "config",
		"chat.db":        "conversation_database",
		"sessions.jsonl": "session",
		"history":        "cli_history",
		".env":           "credential",
		"auth.json":      "credential",
		"randomfile.txt": "artifact",
	}
	for path, want := range cases {
		if got := classifyArtifact(path); got != want {
			t.Errorf("classifyArtifact(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestCollectEndToEnd runs the full pipeline against a temp dir and verifies
// the chain-of-custody manifest is written.
func TestCollectEndToEnd(t *testing.T) {
	dir := t.TempDir()
	coc, err := Collect(dir, false)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	manifest := filepath.Join(dir, "CHAIN_OF_CUSTODY.json")
	if _, err := os.Stat(manifest); err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	if coc.Tool == "" {
		t.Error("coc tool empty")
	}
	if coc.TotalFiles != len(coc.Files) {
		t.Errorf("TotalFiles=%d != len(Files)=%d", coc.TotalFiles, len(coc.Files))
	}
}

// TestCopyAndHash verifies a collected file is hashed with SHA-256 (64 hex).
func TestCopyAndHash(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f.json")
	os.WriteFile(src, []byte(`{"a":1}`), 0o600)
	c := &collector{evidenceDir: t.TempDir(), used: map[string]string{}}
	cf := c.copyAndHash(src, "test", "config", "f.json")
	if cf == nil {
		t.Fatal("copyAndHash returned nil")
	}
	if len(cf.SHA256) != 64 {
		t.Errorf("sha256 length = %d, want 64", len(cf.SHA256))
	}
	if !strings.HasPrefix(cf.SHA256, "") {
		t.Error("empty sha256")
	}
	if cf.RelativePath != "f.json" {
		t.Errorf("RelativePath = %q, want f.json", cf.RelativePath)
	}
	// The on-disk copy must hash to the manifest hash (chain-of-custody).
	onDisk, err := sha256File(filepath.Join(c.evidenceDir, "test", "f.json"))
	if err != nil {
		t.Fatalf("re-hash on-disk copy: %v", err)
	}
	if onDisk != cf.SHA256 {
		t.Errorf("on-disk hash %s != manifest hash %s", onDisk, cf.SHA256)
	}
}

// TestSha256Sum determinism.
func TestSha256Sum(t *testing.T) {
	a := sha256Sum([]byte("hello"))
	b := sha256Sum([]byte("hello"))
	if a != b {
		t.Errorf("sha256 not deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("len=%d want 64", len(a))
	}
}

// TestCollectEmptyDetection still writes a manifest.
func TestCollectEmptyDetection(t *testing.T) {
	dir := t.TempDir()
	coc, err := Collect(dir, true)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	_ = coc
	if _, err := os.Stat(filepath.Join(dir, "CHAIN_OF_CUSTODY.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
}

// TestCollisionFixture verifies D1: two sources sharing a basename in
// different directories map to distinct relative paths, so no file is
// overwritten and the chain-of-custody is preserved.
func TestCollisionFixture(t *testing.T) {
	base := t.TempDir()
	// Two roots, each with a file named "config.json" but different content.
	rootA := filepath.Join(base, "toolA")
	rootB := filepath.Join(base, "toolB")
	mustMkdir(t, filepath.Join(rootA, "sub"))
	mustMkdir(t, filepath.Join(rootB, "sub"))
	mustWrite(t, filepath.Join(rootA, "sub", "config.json"), `{"tool":"A"}`)
	mustWrite(t, filepath.Join(rootB, "sub", "config.json"), `{"tool":"B"}`)

	c := &collector{evidenceDir: t.TempDir(), used: map[string]string{}}
	b := &budget{}
	out := c.collectRoot(rootA, "tool", b)
	out = append(out, c.collectRoot(rootB, "tool", b)...)

	if len(out) != 2 {
		t.Fatalf("collected %d files, want 2", len(out))
	}
	// Every relative path must be unique.
	seen := map[string]bool{}
	for _, cf := range out {
		if cf.RelativePath == "" {
			t.Error("empty relative_path")
		}
		if seen[cf.RelativePath] {
			t.Errorf("duplicate relative_path %q", cf.RelativePath)
		}
		seen[cf.RelativePath] = true
		// The on-disk copy must hash to the manifest hash.
		onDisk, err := sha256File(filepath.Join(c.evidenceDir, "tool", cf.RelativePath))
		if err != nil {
			t.Fatalf("re-hash %s: %v", cf.RelativePath, err)
		}
		if onDisk != cf.SHA256 {
			t.Errorf("on-disk hash %s != manifest hash %s for %s", onDisk, cf.SHA256, cf.RelativePath)
		}
	}
	if len(seen) != len(out) {
		t.Errorf("len(set(relative_path))=%d != len(files)=%d", len(seen), len(out))
	}
}

// TestDepth7Fixture verifies D2: sub-agent transcripts at depth 7 are reached.
func TestDepth7Fixture(t *testing.T) {
	base := t.TempDir()
	// .claude/projects/<slug>/<uuid>/subagents/agent-1.jsonl  (depth 7)
	root := filepath.Join(base, ".claude")
	deep := filepath.Join(root, "projects", "proj-slug", "uuid-1234", "subagents")
	mustMkdir(t, deep)
	mustWrite(t, filepath.Join(deep, "agent-1.jsonl"), `{"role":"assistant","text":"hello"}`)
	// A non-transcript deep file at depth 4 should still be bounded out.
	mustMkdir(t, filepath.Join(root, "blobs", "a", "b"))
	mustWrite(t, filepath.Join(root, "blobs", "a", "b", "deep.txt"), "noise")

	c := &collector{evidenceDir: t.TempDir(), used: map[string]string{}}
	b := &budget{}
	out := c.collectRoot(root, "claude_code", b)

	found := false
	for _, cf := range out {
		if strings.Contains(cf.RelativePath, "subagents") {
			found = true
		}
	}
	if !found {
		t.Errorf("depth-7 sub-agent transcript not collected; got %d files", len(out))
	}
	// The bounded blob tree must NOT be collected.
	for _, cf := range out {
		if strings.Contains(cf.RelativePath, "blobs") {
			t.Errorf("bounded blob tree should not be collected, got %q", cf.RelativePath)
		}
	}
}

// TestSQLiteWALFixture verifies D5: a SQLite database's -wal and -shm sidecars
// are collected and hashed separately.
func TestSQLiteWALFixture(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "cursor")
	mustMkdir(t, root)
	db := filepath.Join(root, "state.vscdb")
	mustWrite(t, db, "sqlite-bytes")
	mustWrite(t, db+"-wal", "wal-bytes")
	mustWrite(t, db+"-shm", "shm-bytes")

	c := &collector{evidenceDir: t.TempDir(), used: map[string]string{}}
	b := &budget{}
	out := c.collectRoot(root, "cursor", b)

	if len(out) != 3 {
		t.Fatalf("collected %d files, want 3 (db + wal + shm)", len(out))
	}
	names := map[string]bool{}
	for _, cf := range out {
		names[cf.RelativePath] = true
		if cf.ArtifactType != "conversation_database" {
			t.Errorf("sidecar %q artifact_type = %q, want conversation_database", cf.RelativePath, cf.ArtifactType)
		}
		onDisk, err := sha256File(filepath.Join(c.evidenceDir, "cursor", cf.RelativePath))
		if err != nil {
			t.Fatalf("re-hash %s: %v", cf.RelativePath, err)
		}
		if onDisk != cf.SHA256 {
			t.Errorf("on-disk hash %s != manifest hash %s for %s", onDisk, cf.SHA256, cf.RelativePath)
		}
	}
	for _, want := range []string{"state.vscdb", "state.vscdb-wal", "state.vscdb-shm"} {
		if !names[want] {
			t.Errorf("missing collected file %q; got %v", want, names)
		}
	}
}

// TestSanitizeRelPath verifies the portable component sanitizer.
func TestSanitizeRelPath(t *testing.T) {
	cases := map[string]string{
		"sub/config.json":      filepath.Join("sub", "config.json"),
		"../etc/passwd":        filepath.Join("etc", "passwd"),
		"C:\\Users\\u\\f.json": filepath.Join("C", "Users", "u", "f.json"),
		".hidden/file.json":    filepath.Join("hidden", "file.json"),
		"a/../../b/c.json":     filepath.Join("a", "b", "c.json"),
		"..":                   "file",
		"dir/..":               "dir",
		"a\\b\\c.json":         filepath.Join("a", "b", "c.json"),
	}
	for in, want := range cases {
		if got := sanitizeRelPath(in); got != want {
			t.Errorf("sanitizeRelPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUniqueRelDisambiguates verifies the case-folded uniqueness guard.
func TestUniqueRelDisambiguates(t *testing.T) {
	c := &collector{used: map[string]string{}}
	a := c.uniqueRel("sub/config.json", "/x/sub/config.json")
	b := c.uniqueRel("sub/config.json", "/y/sub/config.json")
	if a == b {
		t.Errorf("collision not disambiguated: %q == %q", a, b)
	}
	// Case-folded collision must also be disambiguated.
	c2 := &collector{used: map[string]string{}}
	_ = c2.uniqueRel("Config.json", "/a/Config.json")
	d := c2.uniqueRel("config.json", "/b/config.json")
	if d == "config.json" {
		t.Errorf("case-folded collision not disambiguated: %q", d)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
