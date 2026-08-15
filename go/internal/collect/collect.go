// Package collect implements forensic evidence collection for the Go TRACE
// CLI: reading artifact files, computing SHA-256 hashes, and writing a
// chain-of-custody manifest. It mirrors the Python ionsec_trace collectors'
// read-only, hashed, timestamped behavior.
package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ionsec/trace/go/internal/detect"
	"github.com/ionsec/trace/go/internal/model"
)

const toolVersion = "1.0.1"

// nowUTC returns the current UTC time in ISO 8601 format.
func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// sha256File computes the SHA-256 of a file in hex form.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// safeReadFile reads a file up to maxBytes, returning "" on any error.
func safeReadFile(path string, maxBytes int64) string {
	st, err := os.Stat(path)
	if err != nil || st.Size() > maxBytes {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// maxDepth bounds recursive collection into config/blob trees (mirrors Python).
const maxDepth = 3

// transcriptMaxDepth is the depth limit applied to transcript trees (Claude
// Code projects, Codex sessions). Sub-agent transcripts live at depth 5-7
// (.claude/projects/<slug>/<uuid>/subagents/agent-*.jsonl), so these trees are
// walked far deeper than the bounded config/blob trees.
const transcriptMaxDepth = 64

// transcriptDirSegments mark directory trees that hold deep session/transcript
// files. When a walked path contains one of these segments, the depth limit is
// raised so sub-agent transcripts are reached.
var transcriptDirSegments = map[string]bool{
	"projects":  true,
	"sessions":  true,
	"subagents": true,
	"rollout":   true,
}

// isTranscriptTree reports whether a source-relative path descends into a
// transcript tree that should be walked unbounded.
func isTranscriptTree(rel string) bool {
	for _, seg := range strings.FieldsFunc(rel, func(r rune) bool { return r == '/' || r == '\\' }) {
		if transcriptDirSegments[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// Options configures collection. Zero values select sensible defaults.
type Options struct {
	// MaxFilesPerTool caps the number of files collected per tool. 0 uses the
	// default of 200.
	MaxFilesPerTool int
	// MaxBytesPerTool caps the total bytes collected per tool. 0 means
	// unlimited.
	MaxBytesPerTool int64
}

// budget tracks per-tool collection against the file/byte caps so truncation
// is recorded rather than silent.
type budget struct {
	files     int
	bytes     int64
	truncated bool
	skipped   int
}

// collector carries the state shared across a single Collect run: the evidence
// destination, the per-tool budgets, the relative-path uniqueness guard, and
// any truncation records.
type collector struct {
	evidenceDir string
	deep        bool
	maxFiles    int
	maxBytes    int64
	used        map[string]string // lowercased relative path -> actual relative path
	truncations []model.Truncation
}

// Collect runs the full collection pipeline for all detected shadow-AI tools,
// writing a CHAIN_OF_CUSTODY.json manifest into the evidence directory.
func Collect(evidenceDir string, deep bool, opts ...Options) (model.ChainOfCustody, error) {
	o := Options{MaxFilesPerTool: 200}
	if len(opts) > 0 {
		if opts[0].MaxFilesPerTool > 0 {
			o.MaxFilesPerTool = opts[0].MaxFilesPerTool
		}
		o.MaxBytesPerTool = opts[0].MaxBytesPerTool
	}

	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		return model.ChainOfCustody{}, err
	}

	c := &collector{
		evidenceDir: evidenceDir,
		deep:        deep,
		maxFiles:    o.MaxFilesPerTool,
		maxBytes:    o.MaxBytesPerTool,
		used:        map[string]string{},
	}

	detections := detect.Discover()
	var files []model.CollectedFile
	for _, d := range detections {
		files = append(files, c.collectTool(d)...)
	}

	coc := model.ChainOfCustody{
		Tool:        "TRACE (Go)",
		Version:     toolVersion,
		CollectedAt: nowUTC(),
		TotalFiles:  len(files),
		Files:       files,
		Truncations: c.truncations,
	}

	manifestPath := filepath.Join(evidenceDir, "CHAIN_OF_CUSTODY.json")
	data, err := json.MarshalIndent(coc, "", "  ")
	if err != nil {
		return coc, err
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		return coc, err
	}

	return coc, nil
}

// collectTool copies a detected tool's config directory into the evidence
// dir (bounded depth + count, read-only), hashing every file that passes the
// curated filter (only analyst-parseable artifacts are retained). Returns the
// collected files.
func (c *collector) collectTool(d model.Detection) []model.CollectedFile {
	var out []model.CollectedFile
	b := &budget{}
	roots := collectRoots(d)
	for _, root := range roots {
		out = append(out, c.collectRoot(root, d.Tool, b)...)
	}
	if b.truncated {
		c.truncations = append(c.truncations, model.Truncation{
			Platform:     d.Tool,
			Root:         strings.Join(roots, ", "),
			Reason:       "per-tool collection budget exhausted",
			Limit:        int64(c.maxFiles),
			SkippedFiles: b.skipped,
		})
	}
	return out
}

// collectRoots returns every artifact root to walk for a detection, keeping
// ConfigPath for detections that carry only a single path.
func collectRoots(d model.Detection) []string {
	if len(d.Roots) > 0 {
		return d.Roots
	}
	if d.ConfigPath == "" {
		return nil
	}
	return []string{d.ConfigPath}
}

// collectRoot walks one artifact root, honoring the per-tool file/byte budget
// already consumed by earlier roots.
func (c *collector) collectRoot(rootPath, platform string, b *budget) []model.CollectedFile {
	var out []model.CollectedFile

	st, err := os.Stat(rootPath)
	if err != nil {
		return out
	}

	if st.IsDir() {
		// Walk the artifact root, bounded depth and count, applying curation.
		root := rootPath
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			depth := len(strings.Split(rel, string(filepath.Separator)))
			limit := maxDepth
			if isTranscriptTree(rel) {
				limit = transcriptMaxDepth
			}
			if depth > limit {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			// File-count budget: stop the whole walk once the cap is hit.
			if c.maxFiles > 0 && b.files >= c.maxFiles {
				b.truncated = true
				b.skipped++
				return filepath.SkipAll
			}
			// Skip huge blobs unless deep.
			if info.Size() > 5*1024*1024 && !c.deep {
				return nil
			}
			// Curate: only keep analyst-parseable artifacts.
			atype, keep := curated(path, info.Size(), c.deep)
			if !keep {
				return nil
			}
			// Byte budget: skip this file (but keep walking) once the cap is hit.
			if c.maxBytes > 0 && b.bytes+info.Size() > c.maxBytes {
				b.truncated = true
				b.skipped++
				return nil
			}
			cf := c.copyAndHash(path, platform, atype, rel)
			if cf != nil {
				out = append(out, *cf)
				b.files++
				b.bytes += cf.SizeBytes
				// SQLite sidecars (-wal / -shm) are separate forensic files.
				if atype == "conversation_database" {
					out = c.collectSidecars(path, platform, rel, out, b)
				}
			}
			return nil
		})
	} else if st.Mode().IsRegular() {
		atype, keep := curated(rootPath, st.Size(), c.deep)
		if keep {
			if c.maxFiles > 0 && b.files >= c.maxFiles {
				b.truncated = true
				b.skipped++
			} else if c.maxBytes > 0 && b.bytes+st.Size() > c.maxBytes {
				b.truncated = true
				b.skipped++
			} else {
				cf := c.copyAndHash(rootPath, platform, atype, filepath.Base(rootPath))
				if cf != nil {
					out = append(out, *cf)
					b.files++
					b.bytes += cf.SizeBytes
					if atype == "conversation_database" {
						out = c.collectSidecars(rootPath, platform, filepath.Base(rootPath), out, b)
					}
				}
			}
		}
	}
	return out
}

// collectSidecars collects the SQLite -wal and -shm sidecars of a collected
// database file, hashing each separately. Sidecars are skipped by the normal
// curation filter (their extensions are not parseable), so they are pulled in
// explicitly here.
func (c *collector) collectSidecars(src, platform, rel string, out []model.CollectedFile, b *budget) []model.CollectedFile {
	for _, suffix := range []string{"-wal", "-shm"} {
		sc := src + suffix
		st, err := os.Stat(sc)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if c.maxFiles > 0 && b.files >= c.maxFiles {
			b.truncated = true
			b.skipped++
			continue
		}
		if c.maxBytes > 0 && b.bytes+st.Size() > c.maxBytes {
			b.truncated = true
			b.skipped++
			continue
		}
		cf := c.copyAndHash(sc, platform, "conversation_database", rel+suffix)
		if cf != nil {
			out = append(out, *cf)
			b.files++
			b.bytes += cf.SizeBytes
		}
	}
	return out
}

// copyAndHash reads a source file, copies it under the evidence dir at the
// given relative path, hashes it, and returns a CollectedFile record (or nil
// on read/copy failure). After writing, the on-disk copy is re-hashed and
// asserted to equal the manifest hash, preserving the chain-of-custody
// guarantee.
func (c *collector) copyAndHash(src, platform, artifactType, rel string) *model.CollectedFile {
	rel = c.uniqueRel(rel, src)
	dest := filepath.Join(c.evidenceDir, platform, rel)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return nil
	}

	content := safeReadFile(src, 10*1024*1024)
	var sha string
	var size int64
	if content == "" {
		// Large/non-text file: hash + copy.
		s, err := sha256File(src)
		if err != nil {
			return nil
		}
		sha = s
		size = fileSize(src)
		if err := copyFile(src, dest); err != nil {
			return nil
		}
	} else {
		sha = sha256Sum([]byte(content))
		size = int64(len(content))
		if err := os.WriteFile(dest, []byte(content), 0o600); err != nil {
			return nil
		}
	}

	// Re-hash the on-disk copy and assert it matches the manifest hash.
	onDisk, err := sha256File(dest)
	if err != nil || onDisk != sha {
		return nil
	}

	return &model.CollectedFile{
		OriginalPath:     src,
		RelativePath:     rel,
		SourceOS:         osName(),
		Platform:         platform,
		ArtifactType:     artifactType,
		SizeBytes:        size,
		SHA256:           sha,
		CollectedAt:      nowUTC(),
		CollectorVersion: toolVersion,
	}
}

// uniqueRel sanitizes a source-relative path and guarantees it is unique
// (case-folded) within the evidence tree. On a collision it appends a short
// hash of the original source path, deterministically and order-independently.
func (c *collector) uniqueRel(rel, src string) string {
	rel = sanitizeRelPath(rel)
	key := strings.ToLower(rel)
	if _, ok := c.used[key]; ok {
		h := sha256Sum([]byte(src))
		ext := filepath.Ext(rel)
		base := strings.TrimSuffix(rel, ext)
		rel = base + "_" + h[:8] + ext
		key = strings.ToLower(rel)
	}
	c.used[key] = rel
	return rel
}

// sanitizeRelPath converts a source-relative path into a portable, safe
// relative path for the evidence tree: it strips path separators, drive
// letters, leading dots, and any "." / ".." components so the destination can
// never escape the platform directory or collide across OSes.
func sanitizeRelPath(rel string) string {
	parts := strings.FieldsFunc(rel, func(r rune) bool { return r == '/' || r == '\\' })
	var out []string
	for _, p := range parts {
		p = sanitizeComponent(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return "file"
	}
	return filepath.Join(out...)
}

// sanitizeComponent cleans a single path component for portability.
func sanitizeComponent(comp string) string {
	// Strip a Windows drive-letter prefix ("C:" -> "C").
	if len(comp) >= 2 && comp[1] == ':' {
		comp = comp[:1] + comp[2:]
	}
	// Replace any remaining path separators with an underscore.
	comp = strings.NewReplacer("/", "_", "\\", "_").Replace(comp)
	// Strip leading dots (hidden files / ".." remnants).
	comp = strings.TrimLeft(comp, ".")
	return comp
}

// classifyArtifact guesses an artifact type from a file path.
func classifyArtifact(path string) string {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	// Credential files first (name trumps extension: auth.json is a credential).
	if stringsContains(base, ".env") || stringsContains(base, "token") || stringsContains(base, "auth") || stringsContains(base, "secret") || stringsContains(base, "credential") {
		return "credential"
	}
	switch {
	case filepath.Ext(base) == ".json":
		return "config"
	case filepath.Ext(base) == ".yaml" || filepath.Ext(base) == ".yml":
		return "config"
	case filepath.Ext(base) == ".toml":
		return "config"
	case filepath.Ext(base) == ".sqlite" || filepath.Ext(base) == ".db":
		return "conversation_database"
	case filepath.Ext(base) == ".jsonl" || filepath.Ext(base) == ".log":
		return "session"
	case stringsContains(lower, "history"):
		return "cli_history"
	default:
		return "artifact"
	}
}
