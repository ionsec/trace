package analyze

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ionsec/trace/go/internal/model"
)

// timestampPatterns recognize the timestamp shapes TRACE meets inside logs and
// transcripts, most precise first.
var timestampPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`),
	regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`),
}

// BuildTimeline reconstructs a chronological view of AI activity from the
// collected evidence: real in-artifact events first, with collection events
// marked so they never masquerade as user activity.
func BuildTimeline(evidenceDir string, turns []Turn) []model.TimelineEvent {
	var events []model.TimelineEvent

	for _, turn := range turns {
		ts := turn.Timestamp
		if ts == "" {
			continue
		}
		description := "[" + turn.Platform + "] " + roleLabel(turn.Role)
		if turn.ToolCommand != "" {
			description += " ran tool command"
		}
		events = append(events, model.TimelineEvent{
			Timestamp:      normalizeTimestamp(ts),
			Platform:       turn.Platform,
			ArtifactType:   "conversation",
			Description:    description,
			Severity:       severityForTurn(turn),
			SourcePath:     turn.SourceFile,
			ContentPreview: truncate(strings.ReplaceAll(strings.TrimSpace(turn.Content), "\n", " "), 120),
		})
	}

	for _, entry := range LoadCustody(evidenceDir) {
		st, err := os.Stat(entry.OriginalPath)
		if err != nil {
			continue
		}
		events = append(events, model.TimelineEvent{
			Timestamp:         st.ModTime().UTC().Format(time.RFC3339),
			Platform:          entry.Platform,
			ArtifactType:      entry.ArtifactType,
			Description:       "[" + entry.Platform + "] artifact last modified: " + baseName(entry.OriginalPath),
			Severity:          "info",
			SourcePath:        entry.OriginalPath,
			IsCollectionEvent: true,
		})
	}

	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp < events[j].Timestamp })
	return events
}

// roleLabel renders a conversation role for a timeline description.
func roleLabel(role string) string {
	switch strings.ToLower(role) {
	case "user", "human":
		return "user prompt"
	case "assistant", "ai", "model":
		return "assistant response"
	case "system":
		return "system message"
	case "tool", "function":
		return "tool call"
	}
	return role + " message"
}

// severityForTurn rates a turn by what it contains: tool execution outranks
// plain text, because it acts on the endpoint.
func severityForTurn(turn Turn) string {
	if turn.ToolCommand != "" || turn.ToolInput != "" {
		return "medium"
	}
	return "info"
}

// normalizeTimestamp converts the recognized timestamp shapes to RFC 3339 so
// the timeline sorts lexicographically.
func normalizeTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05", "2006/01/02 15:04:05", "2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	// Epoch seconds or milliseconds, as emitted by several chat stores.
	if n, ok := parseEpoch(raw); ok {
		return n.UTC().Format(time.RFC3339)
	}
	for _, re := range timestampPatterns {
		if m := re.FindString(raw); m != "" {
			return m
		}
	}
	return raw
}

// parseEpoch interprets a numeric timestamp in seconds or milliseconds.
func parseEpoch(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	var n int64
	for _, c := range raw {
		if c < '0' || c > '9' {
			return time.Time{}, false
		}
		n = n*10 + int64(c-'0')
	}
	switch {
	case n > 1e12:
		return time.UnixMilli(n), true
	case n > 1e9:
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}
