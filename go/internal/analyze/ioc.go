// Package analyze implements TRACE's evidence analysis: IOC extraction,
// secret detection, conversation forensics, timeline building, MITRE ATLAS and
// ATT&CK mapping, kill-chain reconstruction and risk scoring.
//
// It mirrors src/ionsec_trace/analyzer/ so the Go and Python builds produce the
// same analysis_results.json from the same evidence.
package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ionsec/trace/go/internal/model"
)

// maxScanBytes caps the size of a file TRACE will read into memory to scan.
const maxScanBytes = 10 * 1024 * 1024

// Generic indicator patterns, ported from analyzer/ioc_extractor.py.
var (
	ipPattern     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	urlPattern    = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>"]+[^\s<>".]`)
	domainPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|ai|co|app|xyz|info|biz|edu|gov|mil|me|us|uk|de|fr|ru|cn|jp)\b`)
	hashPattern   = regexp.MustCompile(`\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b`)
	emailPattern  = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)
	pathPattern   = regexp.MustCompile(`(?:(?:/[a-zA-Z0-9_.\-]+)+/[a-zA-Z0-9_.\-]+)|(?:[A-Za-z]:\\(?:[^\s\\/:*?"<>|\r\n]+\\)*[^\s\\/:*?"<>|\r\n]+)`)
)

// namedPattern is a labelled regex in the suspicious-command and exfiltration
// catalogs.
type namedPattern struct {
	name string
	re   *regexp.Regexp
}

// suspiciousCommands are shell constructs that destroy data, escalate
// privilege or open a remote shell.
var suspiciousCommands = []namedPattern{
	{"rm_rf", regexp.MustCompile(`\brm\s+-rf\b`)},
	{"wget", regexp.MustCompile(`\bwget\b`)},
	{"curl", regexp.MustCompile(`\bcurl\b`)},
	{"chmod_777", regexp.MustCompile(`\bchmod\s+777\b`)},
	{"chmod_000", regexp.MustCompile(`\bchmod\s+000\b`)},
	{"chown_root", regexp.MustCompile(`\bchown\s+root\b`)},
	{"sudo_rm", regexp.MustCompile(`\bsudo\s+rm\b`)},
	{"shutdown", regexp.MustCompile(`\bshutdown\b`)},
	{"reboot", regexp.MustCompile(`\breboot\b`)},
	{"mkfs", regexp.MustCompile(`\bmkfs\b`)},
	{"dd_of", regexp.MustCompile(`\bdd\s+.*of=`)},
	{"fork_bomb", regexp.MustCompile(`:\(\)\{.*:\|:&\}`)},
	{"netcat", regexp.MustCompile(`\bnc\s+.*-[el]\b`)},
	{"reverse_shell", regexp.MustCompile(`/dev/tcp/`)},
	{"pip_exec", regexp.MustCompile(`\bpip\s+install\b.*--exec\b`)},
}

// exfilPatterns are constructs that move data off the endpoint.
var exfilPatterns = []namedPattern{
	{"base64_encode", regexp.MustCompile(`\bbase64\b.*\bencode\b|\bencode\b.*\bbase64\b`)},
	{"pipe_network", regexp.MustCompile(`\|\s*(?:nc|curl|wget|ssh|scp|telnet)\b`)},
	{"curl_upload", regexp.MustCompile(`\bcurl\b.*\b(-T|--upload-file)\b`)},
	{"scp_outbound", regexp.MustCompile(`\bscp\b.*@`)},
	{"dns_exfil", regexp.MustCompile(`\bdig\b.*@|\bnslookup\b`)},
	{"env_secret_dump", regexp.MustCompile(`(?i)\benv\b|\bprintenv\b|\bexport\b.*\b(?:KEY|SECRET|TOKEN|PASSWORD|API)\b`)},
}

// IOCExtractor scans collected evidence for indicators of compromise.
type IOCExtractor struct {
	EvidenceDir string
	IOCs        []model.IOC

	seen     map[string]bool
	detector *SecretDetector
}

// NewIOCExtractor returns an extractor bound to an evidence directory.
func NewIOCExtractor(evidenceDir string) *IOCExtractor {
	return &IOCExtractor{
		EvidenceDir: evidenceDir,
		seen:        map[string]bool{},
		detector:    NewSecretDetector(),
	}
}

// custodyEntry is one file record from CHAIN_OF_CUSTODY.json.
type custodyEntry struct {
	OriginalPath string `json:"original_path"`
	Platform     string `json:"platform"`
	ArtifactType string `json:"artifact_type"`
}

// custodyDoc is the chain-of-custody manifest as read back for analysis.
type custodyDoc struct {
	Files          []custodyEntry `json:"files"`
	CollectedFiles []custodyEntry `json:"collected_files"`
}

// LoadCustody returns the collected-file records for an evidence directory,
// falling back to a directory walk when no manifest is present.
func LoadCustody(evidenceDir string) []custodyEntry {
	path := filepath.Join(evidenceDir, "CHAIN_OF_CUSTODY.json")
	if data, err := os.ReadFile(path); err == nil {
		var doc custodyDoc
		if err := json.Unmarshal(data, &doc); err == nil {
			if len(doc.Files) > 0 {
				return doc.Files
			}
			if len(doc.CollectedFiles) > 0 {
				return doc.CollectedFiles
			}
		}
	}

	var entries []custodyEntry
	filepath.Walk(evidenceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() == "CHAIN_OF_CUSTODY.json" {
			return nil
		}
		rel, relErr := filepath.Rel(evidenceDir, path)
		platform := "unknown"
		if relErr == nil {
			if parts := strings.Split(rel, string(filepath.Separator)); len(parts) > 1 {
				platform = parts[0]
			}
		}
		entries = append(entries, custodyEntry{OriginalPath: path, Platform: platform, ArtifactType: "unknown"})
		return nil
	})
	return entries
}

// Extract runs every extraction pass over the evidence directory.
func (e *IOCExtractor) Extract() *IOCExtractor {
	for _, entry := range LoadCustody(e.EvidenceDir) {
		e.scanFile(entry.OriginalPath, entry.Platform)
	}
	e.crossReference()
	return e
}

// readCapped reads a file if it is small enough to scan, returning "" otherwise.
// Compressed transcripts are decoded transparently, so a Zstandard-backed
// session log is scanned for indicators like any other artifact.
func readCapped(path string) string {
	return readMaybeCompressed(path)
}

// scanFile runs all indicator passes over one file's content.
func (e *IOCExtractor) scanFile(path, platform string) {
	content := readCapped(path)
	if content == "" {
		return
	}
	e.extractGeneric(content, path, platform)
	e.extractSecrets(content, path, platform)
	e.extractPatterns(content, path, platform, suspiciousCommands, "command", "high")
	e.extractPatterns(content, path, platform, exfilPatterns, "exfil_pattern", "critical")
}

// context returns the surrounding text of a match, bounded and trimmed.
func context(content string, start, end, pad int) string {
	lo := start - pad
	if lo < 0 {
		lo = 0
	}
	hi := end + pad
	if hi > len(content) {
		hi = len(content)
	}
	out := strings.TrimSpace(content[lo:hi])
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// extractGeneric pulls IPs, URLs, domains, hashes, emails and file paths.
func (e *IOCExtractor) extractGeneric(content, source, platform string) {
	for _, m := range ipPattern.FindAllStringIndex(content, -1) {
		val := content[m[0]:m[1]]
		// Private and loopback space is not an indicator on its own.
		if strings.HasPrefix(val, "10.") || strings.HasPrefix(val, "172.") ||
			strings.HasPrefix(val, "192.168.") || strings.HasPrefix(val, "127.") ||
			strings.HasPrefix(val, "0.") {
			continue
		}
		e.add("ip", val, context(content, m[0], m[1], 40), platform, source, "medium")
	}
	for _, m := range urlPattern.FindAllStringIndex(content, -1) {
		e.add("url", content[m[0]:m[1]], context(content, m[0], m[1], 30), platform, source, "medium")
	}
	for _, m := range domainPattern.FindAllStringIndex(content, -1) {
		val := content[m[0]:m[1]]
		switch strings.ToLower(val) {
		case "example.com", "localhost.com":
			continue
		}
		e.add("domain", val, context(content, m[0], m[1], 30), platform, source, "low")
	}
	for _, m := range hashPattern.FindAllStringIndex(content, -1) {
		val := content[m[0]:m[1]]
		kind, sev := "hash_md5", "low"
		switch len(val) {
		case 40:
			kind = "hash_sha1"
		case 64:
			kind, sev = "hash_sha256", "info"
		}
		e.add(kind, val, context(content, m[0], m[1], 30), platform, source, sev)
	}
	for _, m := range emailPattern.FindAllStringIndex(content, -1) {
		e.add("email", content[m[0]:m[1]], context(content, m[0], m[1], 30), platform, source, "low")
	}
	for _, m := range pathPattern.FindAllStringIndex(content, -1) {
		val := content[m[0]:m[1]]
		if len(val) <= 8 {
			continue
		}
		e.add("filepath", val, context(content, m[0], m[1], 20), platform, source, "info")
	}
}

// extractSecrets records every credential the secret detector recognizes,
// storing only the redacted form.
func (e *IOCExtractor) extractSecrets(content, source, platform string) {
	for _, m := range e.detector.Scan(content, source) {
		e.add("api_key", m.Redacted, m.Context, platform, source, "critical")
	}
}

// extractPatterns records matches for a labelled pattern catalog.
func (e *IOCExtractor) extractPatterns(content, source, platform string, patterns []namedPattern, iocType, severity string) {
	for _, p := range patterns {
		for _, m := range p.re.FindAllStringIndex(content, -1) {
			e.add(iocType, content[m[0]:m[1]], context(content, m[0], m[1], 30), platform, source, severity)
		}
	}
}

// add appends an indicator, skipping duplicates of the same type, value and
// source file.
func (e *IOCExtractor) add(iocType, value, ctx, platform, source, severity string) {
	key := iocType + "\x00" + value + "\x00" + source
	if e.seen[key] {
		return
	}
	e.seen[key] = true
	e.IOCs = append(e.IOCs, model.IOC{
		IOCType:    iocType,
		Value:      value,
		Context:    ctx,
		Platform:   platform,
		SourceFile: source,
		Severity:   severity,
	})
}

// crossReference raises the severity of indicators seen on more than one
// platform — shared infrastructure is a stronger signal than a lone hit.
func (e *IOCExtractor) crossReference() {
	groups := map[string][]int{}
	for i, ioc := range e.IOCs {
		key := ioc.IOCType + "\x00" + ioc.Value
		groups[key] = append(groups[key], i)
	}
	for _, idxs := range groups {
		platforms := map[string]bool{}
		for _, i := range idxs {
			platforms[e.IOCs[i].Platform] = true
		}
		if len(platforms) <= 1 {
			continue
		}
		for _, i := range idxs {
			if e.IOCs[i].Severity != "critical" {
				e.IOCs[i].Severity = "high"
			}
		}
	}
}

// SummaryByType counts indicators per type, most common first.
func (e *IOCExtractor) SummaryByType() []struct {
	Type  string
	Count int
} {
	counts := map[string]int{}
	for _, ioc := range e.IOCs {
		counts[ioc.IOCType]++
	}
	out := make([]struct {
		Type  string
		Count int
	}, 0, len(counts))
	for t, c := range counts {
		out = append(out, struct {
			Type  string
			Count int
		}{t, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}
