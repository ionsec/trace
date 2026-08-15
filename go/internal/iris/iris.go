// Package iris pushes TRACE evidence into a DFIR-IRIS case: the source host as
// an asset, extracted indicators as IOCs, the forensic timeline as case events,
// findings as notes and priority actions as tasks.
//
// It speaks the documented IRIS REST API directly, mirroring the Python
// integration in src/ionsec_trace/integration/iris.py.
package iris

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/ionsec/trace/go/internal/model"
)

// Config describes how to reach IRIS and which case to write to.
type Config struct {
	Host     string
	APIKey   string
	CaseID   int
	CaseName string
	Customer string
	SOCID    string
	// SkipTLS disables certificate verification, for IRIS deployments behind a
	// self-signed certificate. Off by default.
	SkipTLS bool
}

// Result reports what was written to the case.
type Result struct {
	CaseID       int
	IOCsPushed   int
	AssetsPushed int
	EventsPushed int
	NotesPushed  int
	TasksPushed  int
}

// iocTypeMap translates TRACE indicator types to IRIS IOC types.
var iocTypeMap = map[string]string{
	"ip": "ip-any", "ipv4": "ip-any", "url": "url", "domain": "domain",
	"hostname": "hostname", "email": "email", "filepath": "file-path",
	"path": "file-path", "hash_md5": "md5", "hash_sha1": "sha1",
	"hash_sha256": "sha256", "md5": "md5", "sha1": "sha1", "sha256": "sha256",
	"sha512": "sha512", "api_key": "other", "command": "text",
	"exfil_pattern": "text", "jailbreak": "text", "credential": "other",
}

// assetTypeMap translates a source OS to an IRIS asset type.
var assetTypeMap = map[string]string{
	"linux": "Linux - Server", "darwin": "macOS", "macos": "macOS",
	"windows": "Windows - Computer",
}

// client wraps the IRIS REST endpoint with authentication.
type client struct {
	host   string
	apiKey string
	http   *http.Client
}

// newClient builds an IRIS API client.
func newClient(cfg Config) *client {
	transport := http.DefaultTransport
	if cfg.SkipTLS {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &client{
		host:   strings.TrimRight(cfg.Host, "/"),
		apiKey: cfg.APIKey,
		http:   &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}
}

// post sends a JSON payload to an IRIS endpoint and decodes the response.
func (c *client) post(path string, payload map[string]any) (map[string]any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.host+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("iris %s returned %s: %s", path, resp.Status, truncate(string(data), 200))
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("iris %s returned unreadable JSON: %w", path, err)
	}
	if status, ok := out["status"].(string); ok && status == "error" {
		return out, fmt.Errorf("iris %s failed: %v", path, out["message"])
	}
	return out, nil
}

// Check verifies the IRIS endpoint is reachable and the API key is accepted.
func Check(cfg Config) error {
	c := newClient(cfg)
	req, err := http.NewRequest(http.MethodGet, c.host+"/api/versions", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("iris responded %s", resp.Status)
	}
	return nil
}

// Push writes an evidence set into IRIS, creating the case when no case ID is
// supplied, and returns what was written.
func Push(cfg Config, coc model.ChainOfCustody, analysis model.Analysis) (Result, error) {
	c := newClient(cfg)
	result := Result{CaseID: cfg.CaseID}

	if result.CaseID == 0 {
		caseID, err := createCase(c, cfg, coc, analysis)
		if err != nil {
			return result, err
		}
		result.CaseID = caseID
	}
	cid := result.CaseID

	if host := sourceHost(coc); host != "" {
		osKey := strings.ToLower(coc.Files[0].SourceOS)
		assetType, ok := assetTypeMap[osKey]
		if !ok {
			assetType = assetTypeMap[runtime.GOOS]
		}
		if _, err := c.post("/case/assets/add", map[string]any{
			"cid":               cid,
			"asset_name":        host,
			"asset_type_id":     assetType,
			"asset_description": "AI/compute evidence source host (TRACE)",
			"asset_tags":        "trace",
		}); err == nil {
			result.AssetsPushed++
		}
	}

	for _, ioc := range analysis.IOCs {
		value := strings.TrimSpace(ioc.Value)
		if value == "" {
			continue
		}
		iocType, ok := iocTypeMap[strings.ToLower(ioc.IOCType)]
		if !ok {
			iocType = "other"
		}
		description := ioc.Context
		if description == "" {
			description = "Collected by TRACE (" + ioc.Platform + ")"
		}
		if _, err := c.post("/case/ioc/add", map[string]any{
			"cid":             cid,
			"ioc_value":       value,
			"ioc_type":        iocType,
			"ioc_description": description,
			"ioc_tlp_id":      "amber",
			"ioc_tags":        "trace:" + ioc.Platform,
		}); err == nil {
			result.IOCsPushed++
		}
	}

	for _, event := range analysis.Timeline {
		when := event.Timestamp
		if _, err := time.Parse(time.RFC3339, when); err != nil {
			when = time.Now().UTC().Format(time.RFC3339)
		}
		title := event.Description
		if title == "" {
			title = event.Platform + " event"
		}
		if _, err := c.post("/case/timeline/events/add", map[string]any{
			"cid":              cid,
			"event_title":      truncate(title, 255),
			"event_date":       when,
			"event_content":    eventMarkdown(event),
			"event_raw":        event.SourcePath,
			"event_source":     "TRACE",
			"event_tags":       "trace:" + event.Platform,
			"event_tz":         "+00:00",
			"event_assets":     []int{},
			"event_iocs":       []int{},
			"event_in_summary": false,
			"event_in_graph":   true,
		}); err == nil {
			result.EventsPushed++
		}
	}

	for _, f := range analysis.Findings {
		if _, err := c.post("/case/notes/add", map[string]any{
			"cid":           cid,
			"note_title":    truncate(string(f.Severity)+" — "+f.Title, 255),
			"note_content":  findingMarkdown(f),
			"note_group_id": 1,
		}); err == nil {
			result.NotesPushed++
		}
	}

	for _, action := range analysis.PriorityActions {
		description := "**Urgency:** " + action.Urgency
		for _, e := range action.Evidence {
			description += "\n- `" + e + "`"
		}
		if _, err := c.post("/case/tasks/add", map[string]any{
			"cid":               cid,
			"task_title":        truncate(action.Action, 255),
			"task_description":  description,
			"task_status_id":    1,
			"task_tags":         "trace",
			"task_assignees_id": []int{},
		}); err == nil {
			result.TasksPushed++
		}
	}

	return result, nil
}

// createCase opens a new IRIS case for this evidence set.
func createCase(c *client, cfg Config, coc model.ChainOfCustody, analysis model.Analysis) (int, error) {
	resp, err := c.post("/manage/cases/add", map[string]any{
		"case_name":           cfg.CaseName,
		"case_description":    caseDescription(coc, analysis),
		"case_customer":       1,
		"case_classification": 1,
		"soc_id":              cfg.SOCID,
		"custom_attributes":   map[string]any{},
	})
	if err != nil {
		return 0, err
	}
	data, _ := resp["data"].(map[string]any)
	if data == nil {
		return 0, fmt.Errorf("iris case creation returned no case data")
	}
	switch id := data["case_id"].(type) {
	case float64:
		return int(id), nil
	case string:
		var n int
		fmt.Sscanf(id, "%d", &n)
		if n > 0 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("iris case creation returned no usable case id")
}

// caseDescription summarizes the evidence for the case body.
func caseDescription(coc model.ChainOfCustody, analysis model.Analysis) string {
	counts := map[string]int{}
	for _, f := range analysis.Findings {
		counts[strings.ToLower(string(f.Severity))]++
	}
	return fmt.Sprintf(
		"Evidence collected by TRACE.\n\n"+
			"- Artifacts: %d\n- Indicators: %d\n- Findings: %d (%d critical, %d high)\n"+
			"- Risk score: %d/100 (%s)\n- Collected at: %s\n",
		len(coc.Files), len(analysis.IOCs), len(analysis.Findings),
		counts["critical"], counts["high"],
		analysis.RiskScores.Score, analysis.RiskScores.Severity, coc.CollectedAt)
}

// findingMarkdown renders a finding as an IRIS note body.
func findingMarkdown(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Severity:** %s\n\n**Platform:** %s\n\n%s\n", f.Severity, f.Platform, f.Description)
	if len(f.Evidence) > 0 {
		b.WriteString("\n**Evidence**\n")
		for _, e := range f.Evidence {
			b.WriteString("- `" + e + "`\n")
		}
	}
	if len(f.MITREAtlas) > 0 {
		b.WriteString("\n**MITRE ATLAS**\n")
		for _, m := range f.MITREAtlas {
			b.WriteString("- " + m + "\n")
		}
	}
	if f.Recommendation != "" {
		b.WriteString("\n**Recommendation**\n" + f.Recommendation + "\n")
	}
	return b.String()
}

// eventMarkdown renders a timeline event as an IRIS event body.
func eventMarkdown(e model.TimelineEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Platform:** %s\n\n**Artifact type:** %s\n\n**Severity:** %s\n", e.Platform, e.ArtifactType, e.Severity)
	if e.SourcePath != "" {
		b.WriteString("\n**Source:** `" + e.SourcePath + "`\n")
	}
	if e.ContentPreview != "" {
		b.WriteString("\n```\n" + e.ContentPreview + "\n```\n")
	}
	return b.String()
}

// sourceHost returns the endpoint the evidence came from, if recorded.
func sourceHost(coc model.ChainOfCustody) string {
	if len(coc.Files) == 0 {
		return ""
	}
	for _, f := range coc.Files {
		if f.SourceOS != "" {
			return "trace-source-" + strings.ToLower(f.SourceOS)
		}
	}
	return ""
}

// truncate caps a string at n bytes on a UTF-8 boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
