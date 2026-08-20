package analyze

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

// DeepSeek Harness (dsh) transcript parsing.
//
// dsh records are envelopes — {type, seq, time, data} — with no role at the top
// level, so the shape-driven parser cannot read them. The payload depends on
// the record type:
//
//	session          the header: real session id, cwd, and for a sub-agent run
//	                 its parentSession and delegationDepth
//	user/message     a message whose content is a typed block list
//	assistant/message  ditto, with provider and model under message.source
//	tool/call        a standalone invocation; arguments is a raw JSON string
//	tool/result      that invocation's result, attributed to the tool
//
// Tool calls also appear as nested tool-call blocks inside the assistant
// message. Those are deliberately not promoted again here — dsh logs each
// invocation twice, and counting both would double every tool-call metric.

// dshRecord is one line of a dsh session log.
type dshRecord struct {
	Type string          `json:"type"`
	Seq  int             `json:"seq"`
	Time json.Number     `json:"time"`
	Data json.RawMessage `json:"data"`

	// Header-only fields, present when Type == "session".
	ID              string `json:"id"`
	CWD             string `json:"cwd"`
	Origin          string `json:"origin"`
	ParentSession   string `json:"parentSession"`
	DelegationDepth int    `json:"delegationDepth"`
}

// dshMessagePayload is the data of a */message record.
type dshMessagePayload struct {
	Turn    int             `json:"turn"`
	Step    int             `json:"step"`
	Message json.RawMessage `json:"message"`
	Usage   *struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"usage"`
	// A user/message carries its fields inline rather than under "message".
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
	Source  json.RawMessage `json:"source"`
}

// dshMessage is the message object itself.
type dshMessage struct {
	ID      string          `json:"id"`
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
	Source  struct {
		Kind     string `json:"kind"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		CallID   string `json:"callId"`
	} `json:"source"`
}

// dshToolCall is the data of a tool/call record.
type dshToolCall struct {
	Turn      int    `json:"turn"`
	Step      int    `json:"step"`
	CallID    string `json:"callId"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// dshBlock is one element of a dsh content array. Note the hyphenated type
// names — dsh uses "tool-call" where Claude Code uses "tool_use".
type dshBlock struct {
	Type       string          `json:"type"`
	Text       string          `json:"text"`
	Reasoning  string          `json:"reasoning"`
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Arguments  string          `json:"arguments"`
	ToolCallID string          `json:"toolCallId"`
	Content    json.RawMessage `json:"content"`
	IsError    bool            `json:"isError"`
}

// isDshTranscript reports whether a path is a dsh session log. dsh names every
// transcript session.jsonl, optionally Zstandard-compressed.
func isDshTranscript(path, platform string) bool {
	if platform == "deepseek_harness" {
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(base, "session.jsonl")
}

// parseDsh reads a dsh transcript into turns.
func (p *ConversationParser) parseDsh(content, path, platform string) {
	lines := strings.Split(content, "\n")

	// Identity comes from the header record; the session directory name is the
	// encoded id and serves as the fallback.
	sessionID := filepath.Base(filepath.Dir(path))
	workspace := ""
	parentSession := ""

	// The source line travels with the record so a finding can point an analyst
	// at the exact line of the transcript, not just the file.
	type numbered struct {
		rec  dshRecord
		line int
	}
	records := make([]numbered, 0, len(lines))
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec dshRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Type == "session" {
			if rec.ID != "" {
				sessionID = rec.ID
			}
			workspace = rec.CWD
			parentSession = rec.ParentSession
			continue
		}
		records = append(records, numbered{rec: rec, line: i + 1})
	}

	index := 0
	for _, n := range records {
		turn, ok := p.dshTurn(n.rec, path, sessionID, workspace, parentSession)
		if ok {
			index++
			turn.SourceLine = n.line
			turn.TurnIndex = index
			p.Turns = append(p.Turns, turn)
		}
	}
}

// dshTurn converts one dsh record to a turn.
func (p *ConversationParser) dshTurn(rec dshRecord, path, sessionID, workspace, parentSession string) (Turn, bool) {
	if len(rec.Data) == 0 {
		return Turn{}, false
	}

	turn := Turn{
		Timestamp:  dshTimestamp(rec.Time),
		Platform:   "deepseek_harness",
		SessionID:  sessionID,
		SourceFile: path,
		Workspace:  workspace,
		Threading:  parentSession,
		SubAgent:   parentSession != "",
	}

	switch {
	case rec.Type == "tool/call":
		var call dshToolCall
		if err := json.Unmarshal(rec.Data, &call); err != nil {
			return Turn{}, false
		}
		turn.Role = "assistant"
		turn.ToolDescription = call.Name
		turn.ToolInput = truncate(call.Arguments, 4000)
		turn.ToolCommand = dshToolCommand(call.Arguments)

	case strings.HasSuffix(rec.Type, "/message"), rec.Type == "tool/result":
		var payload dshMessagePayload
		if err := json.Unmarshal(rec.Data, &payload); err != nil {
			return Turn{}, false
		}

		msg := dshMessage{Role: payload.Role, Content: payload.Content}
		if len(payload.Message) > 0 {
			if err := json.Unmarshal(payload.Message, &msg); err != nil {
				return Turn{}, false
			}
		}

		turn.Role = msg.Role
		if turn.Role == "" {
			turn.Role = strings.SplitN(rec.Type, "/", 2)[0]
		}
		if rec.Type == "tool/result" {
			// dsh records a result as a user-role message; attributing it to the
			// tool is what lets the secret hunt see a tool_to_model leak.
			turn.Role = "tool"
		}
		turn.Model = msg.Source.Model
		turn.Content = dshContentText(msg.Content)

		// dsh models a tool result as a user-role message. Re-attributing it to
		// the tool is what lets the secret hunt record a tool_to_model leak.
		if turn.Role == "user" && msg.Source.Kind == "tool" {
			turn.Role = "tool"
		}
		if payload.Usage != nil {
			turn.TokensIn = payload.Usage.InputTokens
			turn.TokensOut = payload.Usage.OutputTokens
		}

	default:
		// Chunks, request headers and context records carry no turn.
		return Turn{}, false
	}

	if turn.Content == "" && turn.ToolCommand == "" && turn.ToolInput == "" {
		return Turn{}, false
	}
	return turn, true
}

// dshContentText flattens a dsh content block list to its readable text. Tool
// blocks are handled as their own turns and are not duplicated into message
// text.
func dshContentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []dshBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}

	var parts []string
	for _, b := range blocks {
		switch b.Type {
		case "text":
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		case "reasoning":
			if b.Reasoning != "" {
				parts = append(parts, b.Reasoning)
			} else if b.Text != "" {
				parts = append(parts, b.Text)
			}
		case "tool-result":
			if nested := dshContentText(b.Content); nested != "" {
				parts = append(parts, nested)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// dshToolCommand projects a dsh tool invocation to the command an analyst reads.
// Arguments is a raw JSON string, and the useful field varies by tool.
func dshToolCommand(arguments string) string {
	if arguments == "" {
		return ""
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil {
		return truncate(arguments, 2000)
	}
	for _, key := range []string{"command", "cmd", "shell_command", "file_path", "path", "url", "pattern", "query"} {
		if v, ok := parsed[key].(string); ok && v != "" {
			return truncate(v, 2000)
		}
	}
	return truncate(arguments, 2000)
}

// dshTimestamp converts a dsh envelope timestamp (epoch milliseconds) to
// RFC 3339.
func dshTimestamp(raw json.Number) string {
	if raw == "" {
		return ""
	}
	n, err := raw.Int64()
	if err != nil || n <= 0 {
		return ""
	}
	// Values this large are milliseconds; anything smaller is seconds.
	if n > 1e11 {
		return time.UnixMilli(n).UTC().Format(time.RFC3339)
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}
