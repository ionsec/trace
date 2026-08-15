package analyze

import (
	"math"
	"regexp"
	"strings"
)

// SecretRule is one credential-shape rule in the detection catalog.
type SecretRule struct {
	ID          string
	Description string
	Regex       string
	Severity    string
	// Prefix is a cheap substring pre-filter: the regex only runs on lines
	// containing it. Keywords serve the same purpose for prefix-less rules.
	Prefix     string
	Keywords   []string
	MinEntropy float64
	IgnoreCase bool
	// StrongPrefix marks a token prefix distinctive enough (sk-proj-, ghp_)
	// that entropy and code-shape gating would only cause false negatives.
	StrongPrefix bool
}

// SecretMatch is a detected secret. The raw value never leaves the detector —
// only a redacted preview does, so reports stay safe to share.
type SecretMatch struct {
	RuleID         string
	SecretType     string
	Description    string
	Severity       string
	Redacted       string
	Entropy        float64
	Confidence     float64
	DetectionLayer string
	ContextKey     string
	RawLength      int
	Context        string
}

// Scan limits, mirroring the Python ReDoS guard.
const (
	maxRegexLen     = 1024
	maxScanValueLen = 64 * 1024
)

// ambiguousQuantifier matches the classic catastrophic-backtracking shape — a
// quantified group that itself contains a quantifier.
var ambiguousQuantifier = regexp.MustCompile(`\([^)]*[+*{][^)]*\)[+*{]`)

// compileSafe compiles a rule regex, returning nil when the pattern is
// oversized, pathological or invalid. Unsafe rules are dropped at load time.
func compileSafe(pattern string, ignoreCase bool) *regexp.Regexp {
	if pattern == "" || len(pattern) > maxRegexLen {
		return nil
	}
	if ambiguousQuantifier.MatchString(pattern) {
		return nil
	}
	if ignoreCase {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}

// shannonEntropy returns the Shannon entropy of a string in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	total := 0.0
	for _, r := range s {
		counts[r]++
		total++
	}
	entropy := 0.0
	for _, c := range counts {
		p := c / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Redact keeps only a short preview of a secret value.
func Redact(val string) string {
	switch {
	case len(val) > 12:
		return val[:6] + "..." + val[len(val)-4:]
	case len(val) > 8:
		return val[:4] + "..." + val[len(val)-4:]
	default:
		return "***REDACTED***"
	}
}

// Directory fragments that shift how much a path is trusted.
var (
	noiseDirFragments = []string{
		"/node_modules/", "/.git/", "/.svn/", "/.hg/", "/dist/", "/build/",
		"/out/", "/target/", "/bin/", "/obj/", "/.venv/", "/venv/",
		"/__pycache__/", "/.tox/", "/coverage/", "/.next/", "/.nuxt/",
		"/.gradle/", "/Pods/", "/.terraform/", "/vendor/", "/site-packages/",
		"/.cache/", "/packages/", "/.cargo/", "/.rustup/", "/.npm/",
		"/.nuget/", "/.m2/", "/Carthage/", "/.yarn/", "/.pnpm-store/",
		"/bower_components/", "/.gem/", "/.bundle/", "/gopath/pkg/",
		"/fixtures/", "/testdata/", "/__tests__/", "/mocks/", "/mock/",
		"/tmp/", "/temp/",
	}
	highValueDirFragments = []string{"/dev/", "/src/", "/projects/", "/repos/", "/code/", "/work/"}
	contextLowTrust       = []string{
		"/cache/", "/.cache/", "/tmp/", "/temp/", "/fixtures/", "/testdata/",
		"/__tests__/", "/mocks/", "/mock/", "/_repo/", "/.gradle/caches/",
		"/.cargo/registry/", "/site-packages/", "/coverage/", "/.next/",
		"/.nuget/", "/node_modules/", "/bower_components/", "/.pnpm-store/",
		"/.yarn/", "/vendor/bundle/", "/gopath/pkg/", "/.gem/", "/.bundle/",
	}
)

// containsAny reports whether s contains any of the fragments.
func containsAny(s string, fragments []string) bool {
	for _, f := range fragments {
		if strings.Contains(s, f) {
			return true
		}
	}
	return false
}

// pathConfidence rates how much a file path is trusted to hold real secrets.
func pathConfidence(filePath string) string {
	low := strings.ToLower(filePath)
	if containsAny(low, noiseDirFragments) {
		return "low"
	}
	if containsAny(low, highValueDirFragments) {
		return "high"
	}
	return "medium"
}

// baseName returns the final path element, handling both separators.
func baseName(filePath string) string {
	if i := strings.LastIndexAny(filePath, "/\\"); i >= 0 {
		return filePath[i+1:]
	}
	return filePath
}

// isEnvFile reports whether the path is a dotenv file or another conventional
// credential store, where a match is more likely to be real.
func isEnvFile(filePath string) bool {
	name := strings.ToLower(baseName(filePath))
	if strings.HasPrefix(name, ".env") {
		return true
	}
	switch name {
	case "credentials", "config", "secrets", ".npmrc", ".pypirc", ".netrc":
		return true
	}
	return false
}

// isContextLowTrust reports whether context-layer matching in this path would
// be dominated by clones, caches and fixtures.
func isContextLowTrust(filePath string) bool {
	return containsAny(strings.ToLower(filePath), contextLowTrust)
}

// isExampleOrTemplate reports whether the path is a sample or template file,
// where every "secret" is a placeholder by design.
func isExampleOrTemplate(filePath string) bool {
	base := strings.ToLower(baseName(filePath))
	if strings.HasPrefix(base, ".env") {
		for _, suffix := range []string{".example", ".sample", ".template", ".dist"} {
			if strings.HasSuffix(base, suffix) {
				return true
			}
		}
	}
	return strings.HasSuffix(base, ".env.example") || strings.HasSuffix(base, ".env.sample")
}

// codeIndicators are substrings that mark a value as source code rather than
// a credential.
var codeIndicators = []string{
	"__", "function", "callback", "eventid", "handler", "classname",
	"onclick", "onchange", "addeventlistener", "prototype", "constructor",
	"tostring", "undefined", "template", "component", "module.exports",
}

// looksLikeCode reports whether a value reads as a code identifier rather than
// a random credential.
func looksLikeCode(val string) bool {
	lower := strings.ToLower(val)
	for _, ind := range codeIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	// Three or more long lowercase runs read as camelCase identifiers.
	check := val
	if len(val) > 8 {
		check = val[8:]
	}
	consecutive, longSegments := 0, 0
	for _, c := range check {
		if c >= 'a' && c <= 'z' {
			consecutive++
			continue
		}
		if consecutive >= 5 {
			longSegments++
		}
		consecutive = 0
	}
	if consecutive >= 5 {
		longSegments++
	}
	return longSegments >= 3
}

var (
	placeholderPrefixes = []string{
		"your_", "insert_", "replace_with_", "replace_", "enter_your_", "my_api_",
		"xxx", "test_fake_", "fake_", "dummy_", "sample_", "mock_", "lorem",
		"foobar", "foo_bar", "bar_baz", "example_", "ex_",
		"pk_test_", "sk_test_", "whsec_test_", "rk_test_",
	}
	placeholderValues = map[string]bool{
		"changeme": true, "change_me": true, "replace_me": true,
		"your_token_here": true, "xxx": true, "todo": true, "placeholder": true,
		"example": true, "test": true, "dummy": true, "redacted": true,
	}
)

// isRepeatingChar reports whether a value is one character repeated.
func isRepeatingChar(val string) bool {
	if len(val) < 10 {
		return false
	}
	for i := 1; i < len(val); i++ {
		if val[i] != val[0] {
			return false
		}
	}
	return true
}

// isPlaceholder reports whether a value is a documented stand-in rather than a
// live credential.
func isPlaceholder(val string) bool {
	if isRepeatingChar(val) {
		return true
	}
	lower := strings.ToLower(val)
	if placeholderValues[lower] {
		return true
	}
	for _, p := range placeholderPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// isRedactedOrVaultRef reports whether a value is already redacted or is a
// secret-manager reference rather than the secret itself.
func isRedactedOrVaultRef(val string) bool {
	v := strings.TrimSpace(val)
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "op://") {
		return true
	}
	low := strings.ToLower(v)
	return low == "redacted" || strings.Contains(low, "redacted_by_vaultify")
}

// rhsIsNonLiteral reports whether an assignment's right-hand side is a
// function call rather than a literal secret.
func rhsIsNonLiteral(val string) bool {
	trimmed := strings.TrimSpace(val)
	paren := strings.Index(trimmed, "(")
	if paren <= 0 {
		return false
	}
	fn := strings.TrimSpace(trimmed[:paren])
	if fn == "" {
		return false
	}
	for _, c := range fn {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// contextPattern matches assignment lines whose key name names a credential,
// catching secrets that have no distinctive value shape.
var contextPattern = regexp.MustCompile(`(?i)(\w*(?:` +
	`api_key|apikey|api_secret|api_token|` +
	`secret_key|secret_access|client_secret|` +
	`auth_token|access_token|bearer_token|bot_token|` +
	`password|passwd|` +
	`private_key|encryption_key|signing_key|` +
	`database_url|db_url|db_password|db_pass|` +
	`connection_string|conn_str|` +
	`webhook_url|webhook_secret` +
	`)\w*)\s*[=:]\s*["'` + "`" + `]?([^"'` + "`" + `\s\r\n]{8,})["'` + "`" + `]?`)

// contextEntropyFloor is the minimum entropy for a context-layer match.
const contextEntropyFloor = 3.25

// allowlistPaths are file types and vendored trees never scanned for secrets.
var allowlistPaths = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$`),
	regexp.MustCompile(`(?i)\.(?:eot|[ot]tf|woff2?)$`),
	regexp.MustCompile(`(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf)$`),
	regexp.MustCompile(`go\.(?:mod|sum|work(?:\.sum)?)$`),
	regexp.MustCompile(`(?:^|/)node_modules(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$`),
	regexp.MustCompile(`(?:^|/)bower_components(?:/.*)?$`),
	regexp.MustCompile(`(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$`),
	regexp.MustCompile(`(?:^|/)(?:Pipfile|poetry)\.lock$`),
	regexp.MustCompile(`(?:^|/)\.git$`),
}

// allowlistValues match placeholders, template expressions and format verbs.
var allowlistValues = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(?:true|false|null)$`),
	regexp.MustCompile(`(?i)^(?:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)$`),
	regexp.MustCompile(`^\$(?:\d+|\{\d+\})$`),
	regexp.MustCompile(`^\$(?:[A-Z_]+|[a-z_]+)$`),
	regexp.MustCompile(`^\$\{(?:[A-Z_]+|[a-z_]+)\}$`),
	regexp.MustCompile(`^\{\{[ \t]*[\w ().|]+[ \t]*\}\}$`),
	regexp.MustCompile(`^\$\{\{[ \t]*(?:(?:env|github|secrets|vars)(?:\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*\}\}$`),
	regexp.MustCompile(`^%(?:[A-Z_]+|[a-z_]+)%$`),
	regexp.MustCompile(`^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$`),
	regexp.MustCompile(`^\{\d{0,2}\}$`),
	regexp.MustCompile(`^@(?:[A-Z_]+|[a-z_]+)@$`),
	regexp.MustCompile(`(?i)^/Users/[a-z0-9]+/[\w ./-]+$`),
	regexp.MustCompile(`^/(?:bin|etc|home|opt|tmp|usr|var)/[\w ./-]+$`),
}

// stopwords are canonical filler strings that are never real secrets.
var stopwords = map[string]bool{
	"abcdefghijklmnopqrstuvwxyz":       true,
	"0123456789":                       true,
	"00000000000000000000000000000000": true,
	"ffffffffffffffffffffffffffffffff": true,
}

// isAllowlistedPath reports whether a file is excluded from scanning.
func isAllowlistedPath(filePath string) bool {
	for _, re := range allowlistPaths {
		if re.MatchString(filePath) {
			return true
		}
	}
	return false
}

// isAllowlistedValue reports whether a matched value is a known non-secret.
func isAllowlistedValue(val string) bool {
	v := strings.TrimSpace(val)
	if stopwords[strings.ToLower(v)] {
		return true
	}
	for _, re := range allowlistValues {
		if loc := re.FindStringIndex(v); loc != nil && loc[0] == 0 {
			return true
		}
	}
	return false
}

// compiledRule pairs a rule with its compiled pattern.
type compiledRule struct {
	rule SecretRule
	re   *regexp.Regexp
}

// SecretDetector scans content for credentials using the shared rule catalog
// plus entropy, path-confidence and false-positive heuristics.
type SecretDetector struct {
	compiled []compiledRule
}

// NewSecretDetector builds a detector over the full rule catalog.
func NewSecretDetector() *SecretDetector {
	d := &SecretDetector{}
	for _, rule := range secretRules {
		re := compileSafe(rule.Regex, rule.IgnoreCase)
		if re == nil {
			continue
		}
		d.compiled = append(d.compiled, compiledRule{rule: rule, re: re})
	}
	return d
}

// RuleCount returns how many rules survived the load-time safety check.
func (d *SecretDetector) RuleCount() int { return len(d.compiled) }

// Scan returns every secret found in content, with values redacted.
func (d *SecretDetector) Scan(content, filePath string) []SecretMatch {
	if isAllowlistedPath(filePath) {
		return nil
	}
	if len(content) > maxScanValueLen {
		content = content[:maxScanValueLen]
	}

	var matches []SecretMatch
	seen := map[string]bool{}

	add := func(m SecretMatch, key string) {
		if seen[key] {
			return
		}
		seen[key] = true
		matches = append(matches, m)
	}

	// Multi-line rules (e.g. Kubernetes Secret manifests) run over the whole
	// document rather than line by line.
	for _, c := range d.compiled {
		if !multilineRules[c.rule.ID] {
			continue
		}
		if c.rule.Prefix != "" && !strings.Contains(content, c.rule.Prefix) {
			continue
		}
		for _, val := range c.re.FindAllString(content, -1) {
			if len(val) < 8 || isRedactedOrVaultRef(val) || isAllowlistedValue(val) {
				continue
			}
			ent := shannonEntropy(val)
			add(SecretMatch{
				RuleID:         c.rule.ID,
				SecretType:     c.rule.ID,
				Description:    c.rule.Description,
				Severity:       c.rule.Severity,
				Redacted:       Redact(val),
				Entropy:        ent,
				Confidence:     confidence(ent, "value", filePath),
				DetectionLayer: "value",
				RawLength:      len(val),
				Context:        truncate(val, 200),
			}, c.rule.ID+"\x00"+Redact(val))
		}
	}

	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(strings.ToLower(line), "redacted_by_vaultify") {
			continue
		}
		hasAssign := strings.Contains(line, "=") || strings.Contains(line, ":")

		// Layer 2 — context detection by key name.
		if hasAssign && !isContextLowTrust(filePath) && !isExampleOrTemplate(filePath) {
			for _, m := range contextPattern.FindAllStringSubmatch(line, -1) {
				keyName, val := m[1], m[2]
				if len(val) < 8 || isPlaceholder(val) || isRedactedOrVaultRef(val) || rhsIsNonLiteral(val) {
					continue
				}
				ent := shannonEntropy(val)
				if !contextValueAllowed(filePath, val, ent) {
					continue
				}
				add(SecretMatch{
					RuleID:         "context",
					SecretType:     "context_credential",
					Description:    "Context-detected credential: " + keyName,
					Severity:       "high",
					Redacted:       Redact(val),
					Entropy:        ent,
					Confidence:     confidence(ent, "context", filePath),
					DetectionLayer: "context",
					ContextKey:     keyName,
					RawLength:      len(val),
					Context:        truncate(strings.TrimSpace(line), 200),
				}, strings.ToLower(keyName)+"\x00"+Redact(val))
			}
		}

		// Layer 1 — value pattern detection.
		for _, c := range d.compiled {
			if multilineRules[c.rule.ID] {
				continue
			}
			if c.rule.Prefix != "" && !strings.Contains(line, c.rule.Prefix) {
				continue
			}
			if len(c.rule.Keywords) > 0 && !containsAny(line, c.rule.Keywords) {
				continue
			}
			for _, val := range c.re.FindAllString(line, -1) {
				if len(val) < 8 || isRedactedOrVaultRef(val) || isAllowlistedValue(val) {
					continue
				}
				if !isLikelySecret(c.rule, val, filePath) {
					continue
				}
				ent := shannonEntropy(val)
				add(SecretMatch{
					RuleID:         c.rule.ID,
					SecretType:     c.rule.ID,
					Description:    c.rule.Description,
					Severity:       c.rule.Severity,
					Redacted:       Redact(val),
					Entropy:        ent,
					Confidence:     confidence(ent, "value", filePath),
					DetectionLayer: "value",
					RawLength:      len(val),
					Context:        truncate(strings.TrimSpace(line), 200),
				}, c.rule.ID+"\x00"+Redact(val))
			}
		}
	}

	return matches
}

// isLikelySecret applies the code-shape and entropy gates for a value match.
func isLikelySecret(rule SecretRule, val, filePath string) bool {
	if !rule.StrongPrefix && !bypassCodeCheck[rule.ID] && looksLikeCode(val) {
		return false
	}
	var threshold float64
	switch {
	case rule.StrongPrefix:
		// A distinctive prefix outweighs any entropy signal.
		threshold = 0
	case rule.MinEntropy <= 0:
		threshold = 3.0
	default:
		threshold = rule.MinEntropy
	}
	switch pathConfidence(filePath) {
	case "low":
		threshold += 0.5
	case "high":
		threshold -= 0.3
	}
	return shannonEntropy(val) >= threshold
}

// contextValueAllowed gates context-layer matches, which have no distinctive
// value shape to lean on.
func contextValueAllowed(filePath, val string, ent float64) bool {
	if isPlaceholder(val) || looksLikeCode(val) {
		return false
	}
	minEnt := contextEntropyFloor
	if pathConfidence(filePath) == "low" {
		minEnt += 0.45
	}
	return ent >= minEnt
}

// confidence scores a match from its entropy, detection layer and location.
func confidence(ent float64, layer, filePath string) float64 {
	score := 0.0
	switch {
	case ent >= 4.5:
		score += 0.4
	case ent >= 3.5:
		score += 0.3
	case ent >= 2.5:
		score += 0.2
	}
	switch layer {
	case "both":
		score += 0.35
	case "value":
		score += 0.3
	case "context":
		score += 0.2
	}
	if isEnvFile(filePath) {
		score += 0.15
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}

// truncate caps a string at n bytes, respecting UTF-8 boundaries.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isUTF8Start(s[n]) {
		n--
	}
	return s[:n]
}

// isUTF8Start reports whether b begins a UTF-8 rune.
func isUTF8Start(b byte) bool { return b&0xC0 != 0x80 }
