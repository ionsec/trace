package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ionsec/trace/go/internal/model"
)

// Turn is a single message in an AI conversation, with the tool-call evidence
// promoted to first-class fields so an analyst can read the exact command an
// assistant ran without digging through opaque metadata.
type Turn struct {
	Timestamp       string
	Platform        string
	Role            string
	Content         string
	Model           string
	SessionID       string
	SourceFile      string
	SourceLine      int // 1-based line in SourceFile; 0 when the format has no lines
	TurnIndex       int // 1-based position of this turn within SourceFile
	ToolCommand     string
	ToolInput       string
	ToolDescription string
	Workspace       string
	Threading       string
	GitBranch       string
	SubAgent        bool
	TokensIn        int
	TokensOut       int
}

// ConversationParser reconstructs conversations from collected evidence.
type ConversationParser struct {
	Turns    []Turn
	Findings []model.Finding

	// Pattern hits are accumulated per (category, pattern, source file) and
	// only then turned into findings, so one rule tripped many times in one
	// transcript reads as one alert with many locations.
	hits      map[string]*convHit
	hitOrder  []string
	allowlist []allowRule
}

// convHit accumulates every match of one pattern in one source file.
type convHit struct {
	category    convCategory
	pattern     string
	platform    string
	role        string
	firstMatch  string
	defensive   bool
	occurrences int
	locations   []model.FindingLocation
}

// rawMessage covers the message shapes TRACE meets across platforms: the
// OpenAI-style {role, content}, and the session-log style used by agent CLIs.
type rawMessage struct {
	Role      string          `json:"role"`
	Sender    string          `json:"sender"`
	Author    string          `json:"author"`
	Type      string          `json:"type"`
	Content   json.RawMessage `json:"content"`
	Text      string          `json:"text"`
	Message   json.RawMessage `json:"message"`
	Body      string          `json:"body"`
	Timestamp string          `json:"timestamp"`
	CreatedAt string          `json:"created_at"`
	Time      string          `json:"time"`
	Model     string          `json:"model"`
	ModelName string          `json:"model_name"`
	SessionID string          `json:"session_id"`
	UUID      string          `json:"uuid"`
	Command   string          `json:"command"`
	Input     json.RawMessage `json:"input"`
	Tool      string          `json:"tool"`
	ToolName  string          `json:"tool_name"`
	CWD       string          `json:"cwd"`
	Workspace string          `json:"workspace"`

	// Nested message object (Claude Code / OpenAI assistant shape).
	MessageRole  string          `json:"message_role"`
	MessageModel string          `json:"message_model"`
	MessageUsage json.RawMessage `json:"message_usage"`

	// Codex / OpenAI function-call shapes.
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Output    string          `json:"output"`
	CallID    string          `json:"call_id"`
	ExitCode  *int            `json:"exit_code"`

	// Usage / token accounting.
	Usage json.RawMessage `json:"usage"`

	// Side-channel metadata.
	Threading string `json:"threading"`
	GitBranch string `json:"git_branch"`
	SubAgent  bool   `json:"subagent"`
}

// nestedMessage is the object wrapped by the top-level "message" field in
// Claude Code / OpenAI assistant transcripts.
type nestedMessage struct {
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
	Usage   json.RawMessage `json:"usage"`
}

// contentBlock is one element of a content array. Claude Code nests tool calls
// as typed blocks one level down from the message object.
type contentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
}

// usageTokens extracts input/output token counts from a usage object that may
// be flat ({input_tokens, output_tokens}) or nested ({input_tokens:{...}}).
func usageTokens(raw json.RawMessage) (in, out int) {
	if len(raw) == 0 {
		return 0, 0
	}
	var flat struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	}
	if err := json.Unmarshal(raw, &flat); err == nil {
		return flat.InputTokens, flat.OutputTokens
	}
	var nested struct {
		InputTokens  json.RawMessage `json:"input_tokens"`
		OutputTokens json.RawMessage `json:"output_tokens"`
	}
	if err := json.Unmarshal(raw, &nested); err != nil {
		return 0, 0
	}
	json.Unmarshal(nested.InputTokens, &in)
	json.Unmarshal(nested.OutputTokens, &out)
	return in, out
}

// unwrapMessage parses the nested "message" object, returning the role, model,
// usage and content blocks it carries.
func unwrapMessage(raw json.RawMessage) (role, model string, in, out int, blocks []contentBlock) {
	if len(raw) == 0 {
		return "", "", 0, 0, nil
	}
	var m nestedMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", 0, 0, nil
	}
	in, out = usageTokens(m.Usage)
	if len(m.Content) == 0 {
		return m.Role, m.Model, in, out, nil
	}
	// Content may be a plain string or an array of blocks.
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return m.Role, m.Model, in, out, nil
	}
	if err := json.Unmarshal(m.Content, &blocks); err != nil {
		return m.Role, m.Model, in, out, nil
	}
	return m.Role, m.Model, in, out, blocks
}

// toolCallFromBlock promotes a tool_use content block into a Turn, returning
// the turn and whether it carried tool evidence.
func toolCallFromBlock(b contentBlock, path, platform, sessionID string) (Turn, bool) {
	if b.Type != "tool_use" {
		return Turn{}, false
	}
	toolInput := ""
	if len(b.Input) > 0 {
		toolInput = strings.TrimSpace(string(b.Input))
	}
	command := ""
	var inputObj struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(b.Input, &inputObj); err == nil {
		command = inputObj.Command
	}
	return Turn{
		Platform:        platform,
		Role:            "assistant",
		SessionID:       sessionID,
		SourceFile:      path,
		ToolCommand:     command,
		ToolInput:       toolInput,
		ToolDescription: b.Name,
	}, true
}

// ParseEvidenceDir reconstructs every conversation recorded in an evidence
// directory and scans each turn for the DFIR pattern catalog.
func ParseEvidenceDir(evidenceDir string) *ConversationParser {
	p := &ConversationParser{allowlist: loadAllowlist(evidenceDir)}
	for _, entry := range LoadCustody(evidenceDir) {
		p.parseFile(entry.OriginalPath, entry.Platform)
	}
	for _, turn := range p.Turns {
		p.scanTurn(turn)
	}
	return p
}

// conversationFile reports whether a path is worth parsing as a transcript.
func conversationFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".ndjson", ".json":
		return true
	case ".zstd", ".zst":
		// dsh writes session.jsonl.zstd; the reader decompresses transparently.
		return true
	}
	return false
}

// parseFile dispatches one collected artifact to the right transcript parser.
func (p *ConversationParser) parseFile(path, platform string) {
	if !conversationFile(path) {
		return
	}
	content := readCapped(path)
	if content == "" {
		return
	}
	if isDshTranscript(path, platform) {
		p.parseDsh(content, path, platform)
		return
	}
	if strings.EqualFold(filepath.Ext(path), ".json") {
		p.parseJSON(content, path, platform)
		return
	}
	p.parseJSONL(content, path, platform)
}

// parseJSONL reads a line-delimited transcript, the format agent CLIs use.
func (p *ConversationParser) parseJSONL(content, path, platform string) {
	sessionID := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	index := 0
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var msg rawMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if turn, ok := p.toTurn(msg, path, platform, sessionID); ok {
			index++
			turn.SourceLine = i + 1
			turn.TurnIndex = index
			p.Turns = append(p.Turns, turn)
		}
	}
}

// jsonDoc covers the document shapes that wrap a message list.
type jsonDoc struct {
	Messages     []rawMessage `json:"messages"`
	Conversation []rawMessage `json:"conversation"`
	History      []rawMessage `json:"history"`
	Turns        []rawMessage `json:"turns"`
	Chat         []rawMessage `json:"chat"`
	SessionID    string       `json:"session_id"`
	ID           string       `json:"id"`
	Model        string       `json:"model"`
}

// parseJSON reads a whole-document transcript.
func (p *ConversationParser) parseJSON(content, path, platform string) {
	var doc jsonDoc
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		// A bare array of messages is also common.
		var msgs []rawMessage
		if err := json.Unmarshal([]byte(content), &msgs); err != nil {
			return
		}
		doc.Messages = msgs
	}

	sessionID := doc.SessionID
	if sessionID == "" {
		sessionID = doc.ID
	}
	if sessionID == "" {
		sessionID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}

	// A whole-document transcript has no per-message line, so the turn's
	// position in the document is the locator an analyst gets instead.
	index := 0
	for _, list := range [][]rawMessage{doc.Messages, doc.Conversation, doc.History, doc.Turns, doc.Chat} {
		for _, msg := range list {
			if msg.Model == "" {
				msg.Model = doc.Model
			}
			if turn, ok := p.toTurn(msg, path, platform, sessionID); ok {
				index++
				turn.TurnIndex = index
				p.Turns = append(p.Turns, turn)
			}
		}
	}
}

// textOf renders a content field that may be a string, a list of content
// blocks, or an object — every shape TRACE meets in the wild.
func textOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []struct {
		Text string          `json:"text"`
		Type string          `json:"type"`
		Body json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			switch {
			case b.Text != "":
				parts = append(parts, b.Text)
			case len(b.Body) > 0:
				parts = append(parts, textOf(b.Body))
			}
		}
		return strings.Join(parts, "\n")
	}
	var obj struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj.Content) > 0 {
		return textOf(obj.Content)
	}
	return ""
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// toTurn normalizes one raw message into a conversation turn, dropping
// records that carry neither text nor tool evidence. It unwraps the nested
// "message" object used by Claude Code and dispatches the Codex function-call
// shapes, so tool calls are promoted to first-class fields instead of being
// lost inside opaque content.
func (p *ConversationParser) toTurn(msg rawMessage, path, platform, sessionID string) (Turn, bool) {
	// Unwrap the nested message object for role/model/usage and content blocks.
	msgRole, msgModel, tokIn, tokOut, blocks := unwrapMessage(msg.Message)
	role := firstNonEmpty(msg.Role, msg.Sender, msg.Author, msg.Type, msgRole)
	model := firstNonEmpty(msg.Model, msg.ModelName, msgModel)
	if msg.SessionID != "" {
		sessionID = msg.SessionID
	}

	// Claude Code: each tool_use content block is its own tool call.
	for _, b := range blocks {
		if turn, ok := toolCallFromBlock(b, path, platform, sessionID); ok {
			turn.Model = model
			turn.Timestamp = firstNonEmpty(msg.Timestamp, msg.CreatedAt, msg.Time)
			turn.Workspace = firstNonEmpty(msg.Workspace, msg.CWD)
			turn.Threading = msg.Threading
			turn.GitBranch = msg.GitBranch
			turn.SubAgent = msg.SubAgent
			turn.TokensIn = tokIn
			turn.TokensOut = tokOut
			p.Turns = append(p.Turns, turn)
		}
	}

	// Codex / OpenAI function-call dispatch.
	if turn, ok := p.codexTurn(msg, path, platform, sessionID, model); ok {
		return turn, true
	}

	content := firstNonEmpty(textOf(msg.Content), msg.Text, textOf(msg.Message), msg.Body)
	toolInput := ""
	if len(msg.Input) > 0 {
		toolInput = strings.TrimSpace(string(msg.Input))
	}
	if content == "" && msg.Command == "" && toolInput == "" {
		return Turn{}, false
	}
	if role == "" {
		role = "unknown"
	}
	return Turn{
		Timestamp:       firstNonEmpty(msg.Timestamp, msg.CreatedAt, msg.Time),
		Platform:        platform,
		Role:            role,
		Content:         content,
		Model:           model,
		SessionID:       sessionID,
		SourceFile:      path,
		ToolCommand:     msg.Command,
		ToolInput:       toolInput,
		ToolDescription: firstNonEmpty(msg.Tool, msg.ToolName),
		Workspace:       firstNonEmpty(msg.Workspace, msg.CWD),
		Threading:       msg.Threading,
		GitBranch:       msg.GitBranch,
		SubAgent:        msg.SubAgent,
		TokensIn:        tokIn,
		TokensOut:       tokOut,
	}, true
}

// codexTurn handles the OpenAI Codex payload shapes: function_call,
// function_call_output and exec_command_end. Only function_call carries a tool
// invocation; the others are recorded as content turns so the timeline is
// complete.
func (p *ConversationParser) codexTurn(msg rawMessage, path, platform, sessionID, model string) (Turn, bool) {
	switch msg.Type {
	case "function_call":
		toolInput := ""
		if len(msg.Arguments) > 0 {
			toolInput = strings.TrimSpace(string(msg.Arguments))
		}
		command := ""
		var args struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(msg.Arguments, &args); err == nil {
			command = args.Command
		}
		return Turn{
			Timestamp:       firstNonEmpty(msg.Timestamp, msg.CreatedAt, msg.Time),
			Platform:        platform,
			Role:            "assistant",
			Model:           model,
			SessionID:       sessionID,
			SourceFile:      path,
			ToolCommand:     command,
			ToolInput:       toolInput,
			ToolDescription: msg.Name,
			Workspace:       firstNonEmpty(msg.Workspace, msg.CWD),
			Threading:       msg.Threading,
			GitBranch:       msg.GitBranch,
			SubAgent:        msg.SubAgent,
		}, true
	case "function_call_output":
		return Turn{
			Timestamp:  firstNonEmpty(msg.Timestamp, msg.CreatedAt, msg.Time),
			Platform:   platform,
			Role:       "tool",
			Model:      model,
			SessionID:  sessionID,
			SourceFile: path,
			Content:    msg.Output,
			Workspace:  firstNonEmpty(msg.Workspace, msg.CWD),
		}, true
	case "exec_command_end":
		return Turn{
			Timestamp:  firstNonEmpty(msg.Timestamp, msg.CreatedAt, msg.Time),
			Platform:   platform,
			Role:       "tool",
			Model:      model,
			SessionID:  sessionID,
			SourceFile: path,
			Content:    msg.Command,
			Workspace:  firstNonEmpty(msg.Workspace, msg.CWD),
		}, true
	}
	return Turn{}, false
}

// maxFindingLocations caps how many locations one grouped finding carries. A
// transcript can trip the same rule thousands of times; the count stays exact
// while the location list stays readable.
const maxFindingLocations = 25

// scanTurn runs the conversation-forensics catalog over one turn, recording
// each category hit against its (category, pattern, source file) group.
func (p *ConversationParser) scanTurn(turn Turn) {
	haystack := strings.Join([]string{turn.Content, turn.ToolCommand, turn.ToolInput}, "\n")
	if strings.TrimSpace(haystack) == "" {
		return
	}
	for _, cat := range convCategories {
		for _, pat := range cat.Patterns {
			match := pat.Re.FindString(haystack)
			if match == "" {
				continue
			}
			p.recordHit(cat, pat.Label, turn, match, haystack)
			break // one hit per category per turn
		}
	}
	p.rebuildConvFindings()
}

// recordHit folds one pattern match into its group, unless the analyst has
// allowlisted it.
func (p *ConversationParser) recordHit(cat convCategory, label string, turn Turn, match, haystack string) {
	if p.suppressed(turn.SourceFile, match) {
		return
	}
	if p.hits == nil {
		p.hits = map[string]*convHit{}
	}

	key := cat.Name + "|" + label + "|" + turn.SourceFile
	hit, ok := p.hits[key]
	if !ok {
		hit = &convHit{
			category:   cat,
			pattern:    label,
			platform:   turn.Platform,
			role:       turn.Role,
			firstMatch: strings.TrimSpace(match),
			defensive:  true,
		}
		p.hits[key] = hit
		p.hitOrder = append(p.hitOrder, key)
	}

	hit.occurrences++
	if len(hit.locations) < maxFindingLocations {
		hit.locations = append(hit.locations, model.FindingLocation{
			File:  turn.SourceFile,
			Line:  turn.SourceLine,
			Turn:  turn.TurnIndex,
			Match: truncate(strings.TrimSpace(match), 200),
		})
	}
	// A group is only treated as defensive when *every* occurrence sits in
	// defensive framing: one genuine attempt in the same file must keep the
	// finding at full severity.
	if !defensiveContext(haystack, match) {
		hit.defensive = false
	}
}

// rebuildConvFindings projects the accumulated hits onto Findings. It runs
// after each scanned turn so Findings is always current, and rebuilds from
// scratch so IDs stay dense and stable in hit order.
func (p *ConversationParser) rebuildConvFindings() {
	p.Findings = p.Findings[:0]
	for _, key := range p.hitOrder {
		hit := p.hits[key]
		if hit == nil {
			continue
		}

		severity := hit.category.Severity
		description := hit.category.Description + " detected in a " + hit.role + " turn on " + hit.platform + "."
		recommendation := recommendationForCategory(hit.category.Name)
		title := hit.category.Description + " (" + hit.pattern + ")"
		if hit.defensive {
			// The match is quoted in order to be forbidden — hardening text, an
			// injection-handling instruction, or an incident note. Kept as
			// evidence, but demoted so it does not compete with real attempts.
			severity = string(model.SeverityInfo)
			title += " — defensive context"
			description += " Every match sits in defensive framing (the string is quoted in order" +
				" to be refused or reported), so this is most likely anti-injection text rather" +
				" than an attempt. Review before dismissing."
			recommendation = "Likely a false positive: confirm the surrounding text is anti-injection" +
				" guidance, then allowlist it in " + AllowlistFile + " to keep it out of later reports."
		}
		if hit.occurrences > 1 {
			description += fmt.Sprintf(" Matched %d time(s) in this file; see the locations list.", hit.occurrences)
		}

		p.Findings = append(p.Findings, model.Finding{
			ID:             fmt.Sprintf("TRACE-CONV-%04d", len(p.Findings)+1),
			Title:          title,
			Description:    description,
			Severity:       model.Severity(severity),
			Platform:       hit.platform,
			ArtifactType:   "conversation",
			Evidence:       []string{locationLabel(hit.locations, hit.category.Name), truncate(hit.firstMatch, 200)},
			MITREAtlas:     atlasForCategory(hit.category.Name),
			RiskScore:      severityScore(severity),
			Recommendation: recommendation,
			Occurrences:    hit.occurrences,
			Locations:      hit.locations,
		})
	}
}

// locationLabel renders the first location as the "file:line" reference an
// analyst can paste into an editor.
func locationLabel(locations []model.FindingLocation, fallback string) string {
	if len(locations) == 0 {
		return fallback
	}
	first := locations[0]
	if first.Line > 0 {
		return fmt.Sprintf("%s:%d", first.File, first.Line)
	}
	if first.Turn > 0 {
		return fmt.Sprintf("%s (turn %d)", first.File, first.Turn)
	}
	return first.File
}

// defensiveWindow is how much text either side of a match is inspected for
// defensive framing.
const defensiveWindow = 320

// defensiveMarkers are phrases that appear when a suspicious string is being
// quoted in order to be refused — anti-injection guidance, agent hardening
// text, or an analyst's own incident note — rather than issued as an
// instruction. Prompt-injection hardening is now routine in agent
// configuration, so without this check the tool flags the control as the
// attack.
//
// Every marker names the string from the outside ("do not follow it",
// "injection attempt"); phrasing an attacker would plausibly use is
// deliberately absent, so a real attempt is not silenced.
var defensiveMarkers = []string{
	"prompt injection",
	"injection attempt",
	"anything resembling",
	"looks like an instruction",
	"do not follow it",
	"do not follow them",
	"don't follow it",
	"do not obey it",
	"never follow it",
	"note it in your report",
	"report it as",
	"false positive",
	"instead of following",
}

// defensiveLeads mark the match as an example rather than a request, but only
// when they sit immediately before it.
var defensiveLeads = []string{"e.g.", "eg.", "such as", "for example", "like "}

// defensiveLeadWindow is how far back a lead-in phrase still counts.
const defensiveLeadWindow = 48

// defensiveContext reports whether a match is framed as something to refuse or
// as a quoted example, rather than issued as an instruction.
func defensiveContext(haystack, match string) bool {
	idx := strings.Index(haystack, match)
	if idx < 0 {
		return false
	}

	start := idx - defensiveWindow
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + defensiveWindow
	if end > len(haystack) {
		end = len(haystack)
	}
	window := strings.ToLower(haystack[start:end])
	for _, marker := range defensiveMarkers {
		if strings.Contains(window, marker) {
			return true
		}
	}

	lead := strings.ToLower(haystack[start:idx])
	if len(lead) > defensiveLeadWindow {
		lead = lead[len(lead)-defensiveLeadWindow:]
	}
	for _, l := range defensiveLeads {
		if strings.Contains(lead, l) {
			return true
		}
	}
	return false
}

// AllowlistFile is the optional analyst-maintained suppression list read from
// the evidence directory:
//
//	{"suppress": [{"match": "ignore previous instructions",
//	               "file": "CLAUDE.md",
//	               "reason": "our own anti-injection guidance"}]}
//
// A rule needs "match", "file", or both; "match" is a case-insensitive
// substring of the matched text and "file" of the source path. Suppression is
// an explicit analyst decision, so suppressed hits are dropped rather than
// demoted.
const AllowlistFile = "trace-allowlist.json"

// allowRule is one suppression entry.
type allowRule struct {
	Match  string `json:"match"`
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// allowlistDoc is the allowlist file's document shape.
type allowlistDoc struct {
	Suppress []allowRule `json:"suppress"`
}

// loadAllowlist reads the allowlist from an evidence directory. A missing or
// unreadable file simply means no suppressions.
func loadAllowlist(evidenceDir string) []allowRule {
	data, err := os.ReadFile(filepath.Join(evidenceDir, AllowlistFile))
	if err != nil {
		return nil
	}
	var doc allowlistDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	rules := make([]allowRule, 0, len(doc.Suppress))
	for _, r := range doc.Suppress {
		if r.Match == "" && r.File == "" {
			continue // a rule with no selector would suppress everything
		}
		rules = append(rules, r)
	}
	return rules
}

// suppressed reports whether an allowlist rule covers this match.
func (p *ConversationParser) suppressed(sourceFile, match string) bool {
	if len(p.allowlist) == 0 {
		return false
	}
	lowerFile := strings.ToLower(sourceFile)
	lowerMatch := strings.ToLower(match)
	for _, rule := range p.allowlist {
		if rule.Match != "" && !strings.Contains(lowerMatch, strings.ToLower(rule.Match)) {
			continue
		}
		if rule.File != "" && !strings.Contains(lowerFile, strings.ToLower(rule.File)) {
			continue
		}
		return true
	}
	return false
}

// atlasForCategory maps a conversation attack category to MITRE ATLAS.
func atlasForCategory(category string) []string {
	switch category {
	case "jailbreak":
		return []string{"AML.T0054"}
	case "system_prompt_extraction", "indirect_injection":
		return []string{"AML.T0051"}
	case "data_exfiltration":
		return []string{"AML.T0024"}
	case "credential_harvesting":
		return []string{"AML.T0055"}
	case "privilege_escalation":
		return []string{"AML.T0053"}
	}
	return nil
}

// recommendationForCategory is the analyst guidance attached to a finding.
func recommendationForCategory(category string) string {
	switch category {
	case "jailbreak":
		return "Preserve the transcript, interview the user, and enforce an approved-agent policy with tool allow-lists and central session logging."
	case "system_prompt_extraction":
		return "Review what the assistant disclosed and treat any revealed system prompt or policy text as exposed."
	case "data_exfiltration":
		return "Determine whether the referenced data left the endpoint, and review provider-side logs for the session."
	case "credential_harvesting":
		return "Rotate every credential referenced in the transcript and audit provider logs for use from unexpected sources."
	case "privilege_escalation":
		return "Review the executed tool calls for privileged actions and re-scope the agent's tool permissions."
	case "indirect_injection":
		return "Identify the external content source and restrict the agent's ability to act on untrusted input."
	}
	return "Review the conversation transcript as part of the incident timeline."
}

// severityScore converts a severity label to the 0-100 risk contribution used
// across TRACE.
func severityScore(severity string) int {
	switch severity {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 50
	case "low":
		return 25
	}
	return 10
}

// Summary aggregates sessions for the report's conversation tab.
func (p *ConversationParser) Summary() model.ConversationSummary {
	type agg struct {
		session model.ConversationSession
	}
	order := []string{}
	byID := map[string]*agg{}

	for _, t := range p.Turns {
		key := t.Platform + "\x00" + t.SessionID
		a, ok := byID[key]
		if !ok {
			a = &agg{session: model.ConversationSession{Platform: t.Platform, SessionID: t.SessionID}}
			byID[key] = a
			order = append(order, key)
		}
		a.session.Turns++
		switch strings.ToLower(t.Role) {
		case "user", "human":
			a.session.UserTurns++
		case "assistant", "ai", "model":
			a.session.AssistantTurns++
		}
		if t.ToolCommand != "" || t.ToolInput != "" {
			a.session.ToolCalls++
		}
	}

	// Attribute jailbreak findings back to their session.
	jailbreakBySession := map[string]int{}
	worstBySession := map[string]string{}
	for _, f := range p.Findings {
		for _, t := range p.Turns {
			if len(f.Evidence) == 0 || f.Evidence[0] != t.SourceFile {
				continue
			}
			key := t.Platform + "\x00" + t.SessionID
			if strings.Contains(strings.ToLower(f.Title), "jailbreak") {
				jailbreakBySession[key]++
			}
			if severityRank(string(f.Severity)) > severityRank(worstBySession[key]) {
				worstBySession[key] = string(f.Severity)
			}
			break
		}
	}

	summary := model.ConversationSummary{}
	for _, key := range order {
		s := byID[key].session
		s.JailbreakAttempts = jailbreakBySession[key]
		s.RiskAssessment = worstBySession[key]
		if s.RiskAssessment == "" {
			s.RiskAssessment = "info"
		}
		summary.Sessions = append(summary.Sessions, s)
		summary.ToolCallsTotal += s.ToolCalls
		summary.JailbreakAttemptsTotal += s.JailbreakAttempts
	}
	summary.TotalSessions = len(summary.Sessions)
	sort.SliceStable(summary.Sessions, func(i, j int) bool {
		return severityRank(summary.Sessions[i].RiskAssessment) > severityRank(summary.Sessions[j].RiskAssessment)
	})
	return summary
}

// severityRank orders severities for comparison.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// SecretHunt scans every parsed conversation turn for leaked credentials,
// recording which direction each secret travelled and which field carried it.
func (p *ConversationParser) SecretHunt() *model.SecretHunt {
	detector := NewSecretDetector()
	hunt := &model.SecretHunt{
		BySeverity:      map[string]int{},
		ByLeakDirection: map[string]int{},
	}
	fingerprints := map[string]bool{}
	flagged := map[int]bool{}

	for i, turn := range p.Turns {
		fields := []struct{ name, value string }{
			{"content", turn.Content},
			{"tool_command", turn.ToolCommand},
			{"tool_input", turn.ToolInput},
		}
		for _, f := range fields {
			if f.value == "" {
				continue
			}
			for _, m := range detector.Scan(f.value, turn.SourceFile) {
				direction := leakDirection(turn.Role)
				fp := fingerprint(m.RuleID, m.Redacted)
				hunt.Findings = append(hunt.Findings, model.SecretFinding{
					SecretType:    m.SecretType,
					Redacted:      m.Redacted,
					Severity:      m.Severity,
					LeakDirection: direction,
					EvidenceField: f.name,
					Platform:      turn.Platform,
					SessionID:     turn.SessionID,
					Timestamp:     turn.Timestamp,
					Fingerprint:   fp,
				})
				hunt.BySeverity[m.Severity]++
				hunt.ByLeakDirection[direction]++
				fingerprints[fp] = true
				flagged[i] = true
			}
		}
	}

	hunt.Total = len(hunt.Findings)
	hunt.FlaggedTurns = len(flagged)
	hunt.UniqueSecrets = len(fingerprints)
	return hunt
}

// leakDirection reports which way a secret travelled, based on who spoke.
func leakDirection(role string) string {
	switch strings.ToLower(role) {
	case "assistant", "ai", "model":
		return "model_to_user"
	case "user", "human":
		return "user_to_model"
	case "tool", "function":
		return "tool_to_model"
	}
	return "unknown"
}

// fingerprint is a stable, salted identifier for a redacted secret, so the
// same credential can be counted once without storing its value.
func fingerprint(ruleID, redacted string) string {
	sum := sha256.Sum256([]byte("trace-secret-hunt\x00" + ruleID + "\x00" + redacted))
	return hex.EncodeToString(sum[:8])
}

// writeJSON writes an indented JSON document to disk.
func writeJSON(path string, doc any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
