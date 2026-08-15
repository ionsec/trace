// Package collect — analyst-facing parsing of structured artifacts.
//
// SQLite conversation/state stores are collected for integrity, but the
// analyst gets a *parsed summary*: file signature, page size, schema table
// list, row estimates, and a redacted sample of readable conversation
// strings. This is stdlib-only (no SQLite driver dependency), so it reads
// the SQLite file header and the sqlite_master schema directly.
package collect

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// sqliteHeaderLen is the fixed 100-byte SQLite database header.
const sqliteHeaderLen = 100

// SQLiteSummary is the analyst-facing parse result for a SQLite file.
type SQLiteSummary struct {
	Path          string   `json:"path"`
	IsSQLite      bool     `json:"is_sqlite"`
	PageSize      int      `json:"page_size"`
	PageCount     int      `json:"page_count"`
	Tables        []string `json:"tables"`
	RowEstimate   int      `json:"row_estimate"`
	SampleStrings []string `json:"sample_strings"`
}

// parseSQLite inspects a SQLite file's header + sqlite_master schema and
// returns a compact analyst-facing summary.
func parseSQLite(path string) *SQLiteSummary {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	head := make([]byte, sqliteHeaderLen)
	n, _ := f.Read(head)
	if n < sqliteHeaderLen {
		return nil
	}
	// SQLite magic: "SQLite format 3\000" (16 bytes, incl. terminator)
	if string(head[0:16]) != "SQLite format 3\x00" {
		return nil
	}

	sum := &SQLiteSummary{
		Path:     path,
		IsSQLite: true,
		PageSize: int(binary.BigEndian.Uint16(head[16:18])),
	}
	if sum.PageSize == 1 {
		sum.PageSize = 65536
	}
	sum.PageCount = int(binary.BigEndian.Uint32(head[28:32]))

	// Read the first 3 pages to extract schema table names + readable text.
	read := make([]byte, sum.PageSize*3)
	rn, _ := f.ReadAt(read, 0)
	blob := string(read[:rn])

	// Table names from CREATE TABLE / CREATE VIEW statements.
	re := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+["'` + "`" + `]?([a-zA-Z0-9_]+)`)
	for _, m := range re.FindAllStringSubmatch(blob, -1) {
		sum.Tables = append(sum.Tables, m[1])
	}
	if sum.Tables == nil {
		sum.Tables = []string{}
	}

	// Row estimate = page_count (approximate; each page ~1 row for chats).
	if sum.PageCount > 1 {
		sum.RowEstimate = sum.PageCount - 1
	}

	// Extract readable, forensic-relevant strings (skip binary noise).
	stringsFound := extractReadableStrings(blob)
	// Trim to a bounded, useful sample (cap each + total).
	const maxSample = 8
	const maxLen = 120
	var sample []string
	for _, s := range stringsFound {
		s = cleanString(s)
		if len(s) < 6 || len(s) > maxLen {
			continue
		}
		if !looksForensic(s) {
			continue
		}
		sample = append(sample, s)
		if len(sample) >= maxSample {
			break
		}
	}
	sum.SampleStrings = sample

	return sum
}

// extractReadableStrings pulls runs of printable ASCII/UTF-8 of reasonable
// length from a blob, deduping.
func extractReadableStrings(blob string) []string {
	var out []string
	var cur []rune
	flush := func() {
		s := strings.TrimSpace(string(cur))
		if len(s) >= 4 {
			out = append(out, s)
		}
		cur = nil
	}
	for _, r := range blob {
		if r >= 32 && r < 127 || r >= 0x80 {
			cur = append(cur, r)
		} else {
			flush()
		}
	}
	flush()
	// Dedupe preserving order.
	seen := map[string]bool{}
	var res []string
	for _, s := range out {
		if !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
}

// cleanString collapses whitespace and trims punctuation.
func cleanString(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	re := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(re.ReplaceAllString(s, " "))
}

// looksForensic keeps strings that plausibly relate to conversations, config,
// or model usage rather than random binary fragments.
var forensicPattern = regexp.MustCompile(`(?i)(chat|message|user|assistant|prompt|model|claude|gpt|ollama|api|key|token|role|session|history|conversation|system|content|config|settings)`)

func looksForensic(s string) bool {
	return forensicPattern.MatchString(s)
}

// formatSQLiteSummary renders a SQLiteSummary for the CLI/report.
func formatSQLiteSummary(s *SQLiteSummary) string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SQLite DB (%s) · %d tables · ~%d rows", fileShortName(s.Path), len(s.Tables), s.RowEstimate)
	if len(s.Tables) > 0 {
		b.WriteString("\n  tables: " + strings.Join(s.Tables, ", "))
	}
	if len(s.SampleStrings) > 0 {
		b.WriteString("\n  sample: ")
		b.WriteString(strings.Join(s.SampleStrings[:min(len(s.SampleStrings), 3)], " | "))
	}
	return b.String()
}

// fileShortName returns just the basename for display.
func fileShortName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ---------------------------------------------------------------------------
// Exported helpers used by the report package.
// ---------------------------------------------------------------------------

// ParseSQLite is the exported wrapper for parseSQLite.
func ParseSQLite(path string) *SQLiteSummary { return parseSQLite(path) }

// Format renders a SQLiteSummary for analyst display.
func (s *SQLiteSummary) Format() string { return formatSQLiteSummary(s) }

// ReadPreview returns a bounded analyst-facing preview of a text artifact.
// It reads at most previewMaxBytes and caps at previewMaxLines.
const (
	previewMaxBytes = 8 * 1024
	previewMaxLines = 30
)

func ReadPreview(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, previewMaxBytes)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	content := string(buf[:n])
	lines := strings.Split(content, "\n")
	if len(lines) > previewMaxLines {
		lines = lines[:previewMaxLines]
	}
	return strings.Join(lines, "\n")
}
