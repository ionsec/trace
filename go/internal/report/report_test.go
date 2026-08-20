package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ionsec/trace/go/internal/model"
)

// sampleEvidence is a small analyzed evidence set covering every report tab.
func sampleEvidence() (model.ChainOfCustody, model.Analysis) {
	coc := model.ChainOfCustody{
		Tool:        "TRACE",
		Version:     toolVersion,
		CollectedAt: "2026-08-15T09:00:00Z",
		TotalFiles:  2,
		Files: []model.CollectedFile{
			{OriginalPath: "/home/dana/.ollama/config.json", SourceOS: "linux", Platform: "ollama",
				ArtifactType: "config", SizeBytes: 42, SHA256: strings.Repeat("a", 64),
				CollectedAt: "2026-08-15T09:00:00Z", CollectorVersion: toolVersion},
			{OriginalPath: "/home/dana/.claude/session.jsonl", SourceOS: "linux", Platform: "claude_code",
				ArtifactType: "conversation", SizeBytes: 8192, SHA256: strings.Repeat("b", 64),
				CollectedAt: "2026-08-15T09:00:01Z", CollectorVersion: toolVersion},
		},
	}

	analysis := model.Analysis{
		Platforms: []string{"ollama", "claude_code"},
		IOCs: []model.IOC{
			{IOCType: "api_key", Value: "sk-ant...Vn2A", Platform: "claude_code",
				SourceFile: "/home/dana/.claude/session.jsonl", Severity: "critical"},
			{IOCType: "domain", Value: "api.anthropic.com", Platform: "claude_code",
				SourceFile: "/home/dana/.claude/session.jsonl", Severity: "low"},
		},
		Findings: []model.Finding{
			{ID: "TRACE-CONV-0001", Title: "Jailbreak attempt", Description: "Guardrail bypass in a user turn.",
				Severity: model.SeverityCritical, Platform: "claude_code", ArtifactType: "conversation",
				Evidence: []string{"/home/dana/.claude/session.jsonl"}, MITREAtlas: []string{"AML.T0054"},
				RiskScore: 90, Recommendation: "Preserve the transcript."},
			{ID: "TRACE-CONV-0002", Title: "Indirect prompt injection via external content",
				Description: "One rule tripped repeatedly in a single transcript.",
				Severity:    model.SeverityHigh, Platform: "claude_code", ArtifactType: "conversation",
				Evidence:   []string{"/home/dana/.claude/session.jsonl:42"},
				MITREAtlas: []string{"AML.T0051"}, RiskScore: 70,
				Recommendation: "Preserve the transcript and review every location.",
				Occurrences:    7,
				Locations: []model.FindingLocation{
					{File: "/home/dana/.claude/session.jsonl", Line: 42, Turn: 3, Match: "ignore previous instructions"},
					{File: "/home/dana/.claude/session.jsonl", Line: 88, Turn: 9, Match: "ignore previous instructions"},
				}},
		},
		AtlasMapping: []model.AtlasMapping{
			{TechniqueID: "AML.T0055", TechniqueName: "Unsecured Credentials", Evidence: "API key detected",
				Platform: "claude_code", Confidence: "high"},
		},
		MitreAttack: []model.AttackTechnique{
			{TechniqueID: "T1552", TechniqueName: "Unsecured Credentials", Tactic: "Credential Access",
				Count: 2, Evidence: []string{"API key IOC detected"}},
		},
		KillChainStages: []model.KillChainStage{
			{Stage: "Reconnaissance", Detected: true, Evidence: []string{"Network indicator: api.anthropic.com"}},
			{Stage: "Exploitation", Detected: true, Evidence: []string{"Exposed credential"}},
			{Stage: "Command & Control", Detected: false},
		},
		PriorityActions: []model.PriorityAction{
			{Urgency: "CRITICAL", Action: "Rotate exposed API keys", Evidence: []string{"session.jsonl"}},
		},
		CrossPlatformCorrelations: []model.Correlation{
			{Indicator: "api_key: sk-ant...", CorrelationType: "shared_indicator",
				Platforms: []string{"ollama", "claude_code"}, Severity: "high"},
		},
		AttackNarratives: []model.Narrative{
			{Title: "Credential exposure across AI tooling", Severity: "critical", Confidence: "high",
				AffectedPlatforms: []string{"claude_code"}, KillChainStages: []string{"Exploitation"},
				Recommendation: "Revoke every exposed key."},
		},
		ConversationSummary: model.ConversationSummary{
			TotalSessions: 1, JailbreakAttemptsTotal: 1, ToolCallsTotal: 4,
			Sessions: []model.ConversationSession{{Platform: "claude_code", SessionID: "s1", Turns: 20,
				UserTurns: 10, AssistantTurns: 10, ToolCalls: 4, JailbreakAttempts: 1, RiskAssessment: "critical"}},
		},
		Timeline: []model.TimelineEvent{
			{Timestamp: "2026-08-14T14:22:07Z", Platform: "claude_code", ArtifactType: "conversation",
				Description: "user prompt", Severity: "info", SourcePath: "/home/dana/.claude/session.jsonl"},
		},
		RiskScores:   model.RiskScores{Score: 72, Severity: "high", CategoryScores: map[string]float64{"credentials": 20, "jailbreak": 15}},
		EnhancedRisk: model.EnhancedRisk{Score: 72, Severity: "high", Categories: map[string]float64{"credentials": 20, "jailbreak": 15, "network_exposure": 10}},
		ConversationSecretHunt: &model.SecretHunt{
			Total: 1, FlaggedTurns: 1, UniqueSecrets: 1,
			BySeverity:      map[string]int{"critical": 1},
			ByLeakDirection: map[string]int{"user_to_model": 1},
			Findings: []model.SecretFinding{{SecretType: "anthropic", Redacted: "sk-ant...Vn2A", Severity: "critical",
				LeakDirection: "user_to_model", EvidenceField: "content", Platform: "claude_code",
				SessionID: "s1", Timestamp: "2026-08-14T14:22:07Z"}},
		},
	}
	return coc, analysis
}

// TestGenerateJSONReport writes a JSON report and verifies its schema blocks.
func TestGenerateJSONReport(t *testing.T) {
	dir := t.TempDir()
	coc, analysis := sampleEvidence()

	out, err := GenerateJSONReport(dir, coc, analysis)
	if err != nil {
		t.Fatalf("GenerateJSONReport: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	for _, want := range []string{
		"schema_version", "metadata", "detections", "severity_summary",
		"risk_scores", "platforms", "evidence_manifest", "findings", "analysis",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("report missing %q", want)
		}
	}
}

// TestGenerateHTMLRendersEveryTab verifies the full report renders each
// section, so a regression in one tab cannot pass unnoticed.
func TestGenerateHTMLRendersEveryTab(t *testing.T) {
	dir := t.TempDir()
	coc, analysis := sampleEvidence()

	out, err := GenerateHTML(dir, coc, analysis)
	if err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	html := string(data)

	for _, want := range []string{
		"<!DOCTYPE html>", "#e63946",
		"Executive Summary", "Attack Surface Map", "Findings", "IOC Extractor Results",
		"Event Timeline", "MITRE ATLAS Mapping", "Kill Chain Analysis", "Priority Actions",
		"Attack Narratives", "Cross-Platform Correlation", "Conversation Forensics",
		"Conversation Secret Hunt", "Risk Assessment", "Evidence Manifest", "Appendices",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing section %q", want)
		}
	}

	// Evidence content must actually reach the page, not just its headings.
	for _, want := range []string{
		"Jailbreak attempt", "api.anthropic.com", "T1552", "Rotate exposed API keys",
		"conic-gradient", "claude_code",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing content %q", want)
		}
	}

	// A grouped finding must expose every location, so collapsing repeat alerts
	// never costs an analyst the ability to reach each match.
	for _, want := range []string{
		"Locations", "session.jsonl:42", "session.jsonl:88", "7 match(es)",
		"Location list truncated",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing grouped-finding detail %q", want)
		}
	}

	// The report must never carry a raw secret, only its redacted form.
	if strings.Contains(html, "sk-ant-api03-") {
		t.Error("html leaked an unredacted secret value")
	}
}

// TestGenerateSTIXBundle verifies the STIX 2.1 bundle structure.
func TestGenerateSTIXBundle(t *testing.T) {
	dir := t.TempDir()
	coc, analysis := sampleEvidence()

	out, err := GenerateSTIX(dir, coc, analysis)
	if err != nil {
		t.Fatalf("GenerateSTIX: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read stix: %v", err)
	}
	for _, want := range []string{
		`"type": "bundle"`, `"type": "identity"`, `"type": "indicator"`,
		`"type": "observed-data"`, `"type": "attack-pattern"`, `"type": "course-of-action"`,
		`"type": "report"`, "spec_version", "mitre-attack",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("stix bundle missing %q", want)
		}
	}
}

// TestReportsLandInEvidenceDir verifies every format writes where it should.
func TestReportsLandInEvidenceDir(t *testing.T) {
	dir := t.TempDir()
	coc, analysis := sampleEvidence()

	if err := writeAnalysis(dir, analysis); err != nil {
		t.Fatalf("seed analysis: %v", err)
	}
	paths, err := GenerateAll(dir, coc, []string{"html", "json", "stix"})
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	for kind, path := range paths {
		if filepath.Dir(path) != dir {
			t.Errorf("%s report written to %s, want %s", kind, filepath.Dir(path), dir)
		}
	}
	if len(paths) != 3 {
		t.Errorf("generated %d reports, want 3", len(paths))
	}
}
