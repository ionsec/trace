// Package collect — artifact curation & analyst-facing parsing.
//
// The collection pipeline is deliberately curated: only human-parseable
// artifact files are retained (config, history, session, conversation,
// credential). Unparseable noise (compiled extensions, .DS_Store, README,
// LICENSE, binary blobs, node_modules) is skipped so the evidence set stays
// analyst-readable. Non-readable structured files (SQLite) are parsed into
// analyst-facing summaries rather than collected raw.
package collect

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// parseableExt is the set of text/config extensions we consider analyst-parseable.
var parseableExt = map[string]bool{
	".json":   true,
	".jsonl":  true,
	".ndjson": true,
	".yaml":   true,
	".yml":    true,
	".toml":   true,
	".log":    true,
	".txt":    true,
	".md":     true,
	".csv":    true,
	".xml":    true,
	".sql":    true,
	".py":     true,
	".js":     true,
	".ts":     true,
	".cfg":    true,
	".conf":   true,
	".ini":    true,
	".rc":     true,
}

// compressedTranscriptExt are transcript logs stored compressed. They are kept
// as sessions — the analyzer decompresses them rather than reading lines.
var compressedTranscriptExt = map[string]bool{
	".zstd": true,
	".zst":  true,
}

// conversationExt are binary stores we parse into summaries instead of raw.
var conversationExt = map[string]bool{
	".sqlite":  true,
	".sqlite3": true,
	".db":      true,
	".vscdb":   true,
	".leveldb": true,
}

// noiseBasename are files that carry no forensic value.
var noiseBasename = map[string]bool{
	".ds_store":         true,
	"thumbs.db":         true,
	"desktop.ini":       true,
	"readme.md":         true,
	"readme.txt":        true,
	"readme":            true,
	"license":           true,
	"license.txt":       true,
	"license.md":        true,
	"changelog.md":      true,
	"changelog.txt":     true,
	"copying":           true,
	"contributing.md":   true,
	"package.json":      true,
	"package-lock.json": true,
	"yarn.lock":         true,
	"go.sum":            true,
	"node_modules":      true,
	".vsixmanifest":     true,
	".obsolete":         true,
	"extension.js":      true,
	"sign.proj":         true,
	"packages.config":   true,
	".gitignore":        true,
	".npmignore":        true,
}

// noiseDirSegment marks directory components to skip entirely.
var noiseDirSegment = []string{
	"node_modules",
	"__pycache__",
	".git",
	".hg",
	".svn",
	"extensions", // VS Code / Cursor extension bundles (compiled, non-forensic)
	"dist",
	"build",
	".cache", // large caches, blobs
	".blobs", // ollama model blobs
	"models/blobs",
	".npm",
	".venv",
	"venv",
	"site-packages",
	"file-history", // Claude Code internal file versioning (binary, non-forensic)
	"backups",      // automated backup copies
	"hooks",        // native compiled hooks
	"daemon",       // runtime daemon state
	"logs/cursor",  // cursor runtime logs
}

// noiseFragment marks path substrings that indicate non-analyst binaries.
var noiseFragment = []string{
	".lean-ctx.bak",
	"blocklist",
	"control.key",
	"@v2", // file-history versioned blobs
	"@v1",
	".last-cleanup",
}

// curated checks whether a file is worth retaining as a forensic artifact.
// It returns the artifact type and whether the file should be kept.
func curated(path string, size int64, deep bool) (string, bool) {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	// Skip explicit noise filenames.
	if noiseBasename[base] {
		return "", false
	}

	// Skip any path containing a noise directory segment or fragment.
	lowPath := strings.ToLower(filepath.ToSlash(path))
	for _, seg := range noiseDirSegment {
		if strings.Contains(lowPath, "/"+seg+"/") {
			return "", false
		}
	}
	for _, frag := range noiseFragment {
		if strings.Contains(lowPath, frag) {
			return "", false
		}
	}

	// Credential files always kept (name trumps extension).
	if strings.Contains(base, ".env") || strings.Contains(base, "token") ||
		strings.Contains(base, "auth") || strings.Contains(base, "secret") ||
		strings.Contains(base, "credential") || strings.Contains(base, "api_key") {
		return "credential", true
	}

	// Conversation stores: keep, and they will be parsed into summaries.
	if conversationExt[ext] {
		return "conversation_database", true
	}

	// Compressed transcripts (dsh session.jsonl.zstd) are session evidence.
	if compressedTranscriptExt[ext] {
		return "session", true
	}

	// CLI history / shell history files.
	if strings.Contains(base, "history") {
		return "cli_history", true
	}

	// Parseable text/config.
	if parseableExt[ext] {
		switch {
		case strings.Contains(base, "config") || ext == ".json" && strings.Contains(base, "settings"):
			return "config", true
		case strings.Contains(base, "session") || ext == ".jsonl" || ext == ".ndjson":
			return "session", true
		case ext == ".log":
			return "session", true
		default:
			return "config", true
		}
	}

	// Deep collection may still grab a bounded set of misc parseable text
	// files, but only those with a known text extension and small size.
	if deep && size < 256*1024 && isTextExt(ext) {
		return "artifact", true
	}

	return "", false
}

// isTextExt reports whether an extension is a known text/parseable type.
func isTextExt(ext string) bool {
	return parseableExt[ext]
}

// jsonSummary returns a compact JSON pretty-print of a file, capped in size.
func jsonSummary(content []byte, maxBytes int) (string, error) {
	var v interface{}
	if err := json.Unmarshal(content, &v); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	return string(b), nil
}

// firstLines returns the first n lines of a file as a string, capped.
func firstLines(content []byte, maxLines int, maxBytes int) string {
	lines := strings.Split(string(content), "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	s := strings.Join(lines, "\n")
	if len(s) > maxBytes {
		s = s[:maxBytes]
	}
	return s
}
