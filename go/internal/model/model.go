// Package model defines the core data structures shared across the Go
// TRACE CLI — the same forensic data model as the Python ionsec_trace
// package, kept in sync so evidence produced by either binary is
// interchangeable.
package model

// Severity mirrors the Python Severity enum.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// PlatformCategory mirrors the Python PlatformCategory enum.
type PlatformCategory string

const (
	CategoryInference PlatformCategory = "inference"
	CategoryAgent     PlatformCategory = "agent"
	CategoryDevTool   PlatformCategory = "devtool"
	CategoryCloud     PlatformCategory = "cloud"
	CategoryNetwork   PlatformCategory = "network"
	CategoryCode      PlatformCategory = "code"
)

// CollectedFile is a single collected forensic artifact with integrity
// metadata — the Go equivalent of the Python CollectedFile dataclass.
type CollectedFile struct {
	OriginalPath     string `json:"original_path"`
	RelativePath     string `json:"relative_path"`
	SourceOS         string `json:"source_os"`
	Platform         string `json:"platform"`
	ArtifactType     string `json:"artifact_type"`
	SizeBytes        int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	CollectedAt      string `json:"collected_at"`
	CollectorVersion string `json:"collector_version"`
}

// Detection is a detected shadow-AI tool on the endpoint.
type Detection struct {
	Tool       string   `json:"tool"`
	Installed  bool     `json:"installed"`
	ConfigPath string   `json:"config_path,omitempty"`
	Binary     string   `json:"binary,omitempty"`
	Roots      []string `json:"roots,omitempty"`
	Risk       string   `json:"risk"`
	Note       string   `json:"note"`
	Category   string   `json:"category"`
}

// FindingLocation is one place a finding's pattern matched. Repeat matches are
// grouped into a single finding — one alert per rule per file rather than one
// per turn — and the locations are what still let an analyst reach every
// occurrence.
type FindingLocation struct {
	File  string `json:"file"`
	Line  int    `json:"line,omitempty"`
	Turn  int    `json:"turn,omitempty"`
	Match string `json:"match,omitempty"`
}

// Finding is a forensic finding with a risk assessment.
type Finding struct {
	ID             string            `json:"id"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Severity       Severity          `json:"severity"`
	Platform       string            `json:"platform"`
	ArtifactType   string            `json:"artifact_type"`
	Evidence       []string          `json:"evidence"`
	IOCs           []string          `json:"iocs"`
	MITREAtlas     []string          `json:"mitre_atlas"`
	RiskScore      int               `json:"risk_score"`
	Recommendation string            `json:"recommendation"`
	Occurrences    int               `json:"occurrences,omitempty"`
	Locations      []FindingLocation `json:"locations,omitempty"`
}

// Truncation records that collection was clipped for a platform because a
// per-tool budget (file count or byte count) was exhausted. It makes silent
// truncation explicit so an analyst knows the evidence set is incomplete.
type Truncation struct {
	Platform     string `json:"platform"`
	Root         string `json:"root"`
	Reason       string `json:"reason"`
	Limit        int64  `json:"limit"`
	SkippedFiles int    `json:"skipped_files"`
}

// ChainOfCustody is the manifest written to the evidence directory.
type ChainOfCustody struct {
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	CollectedAt string          `json:"collected_at"`
	TotalFiles  int             `json:"total_files"`
	Files       []CollectedFile `json:"files"`
	Truncations []Truncation    `json:"truncations,omitempty"`
}

// ParsedArtifact is an analyst-facing summary of a collected artifact that
// would otherwise be unreadable (SQLite) or too large to eyeball (JSON/log).
type ParsedArtifact struct {
	Path         string   `json:"path"`
	Platform     string   `json:"platform"`
	ArtifactType string   `json:"artifact_type"`
	Summary      string   `json:"summary"`
	Tables       []string `json:"tables,omitempty"`
	RowEstimate  int      `json:"row_estimate,omitempty"`
	Sample       []string `json:"sample,omitempty"`
}

// Report is the aggregate result written by the report command. Its JSON
// shape mirrors the Python ionsec_trace JSON report so evidence produced by
// either binary is interchangeable.
type Report struct {
	SchemaVersion    string           `json:"schema_version"`
	Metadata         Metadata         `json:"metadata"`
	Platforms        []Platform       `json:"platforms"`
	EvidenceManifest []CollectedFile  `json:"evidence_manifest"`
	Findings         []Finding        `json:"findings"`
	Detections       []Detection      `json:"detections"`
	ChainOfCustody   ChainOfCustody   `json:"chain_of_custody"`
	ParsedArtifacts  []ParsedArtifact `json:"parsed_artifacts,omitempty"`
	SeveritySummary  map[string]int   `json:"severity_summary"`
	Analysis         *Analysis        `json:"analysis,omitempty"`
	RiskScores       RiskScores       `json:"risk_scores"`
	Summary          Summary          `json:"summary"`
}

// Metadata mirrors the Python report metadata block.
type Metadata struct {
	ReportID      string `json:"report_id"`
	GeneratedAt   string `json:"generated_at"`
	Tool          string `json:"tool"`
	Version       string `json:"version"`
	SchemaVersion string `json:"schema_version"`
	SourceOS      string `json:"source_os,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
}

// Platform is a per-platform inventory entry (mirrors Python).
type Platform struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	ArtifactCount int    `json:"artifact_count"`
	FindingCount  int    `json:"finding_count"`
	MaxSeverity   string `json:"max_severity"`
}

// RiskScores mirrors the Python risk_scores block.
type RiskScores struct {
	Score          int                `json:"score"`
	Severity       string             `json:"severity"`
	CategoryScores map[string]float64 `json:"category_scores,omitempty"`
}

// Summary aggregates top-level counts for the report.
type Summary struct {
	PlatformsDetected int `json:"platforms_detected"`
	FilesCollected    int `json:"files_collected"`
	CriticalFindings  int `json:"critical_findings"`
	HighFindings      int `json:"high_findings"`
	RiskScore         int `json:"risk_score"`
}

// Roots are all artifact roots found for a detected platform. ConfigPath keeps
// the first one for backwards-compatible single-path consumers.
// (Declared here rather than on Detection's literal so JSON stays stable.)

// IOC is an indicator of compromise extracted from collected evidence.
type IOC struct {
	IOCType    string `json:"ioc_type"`
	Value      string `json:"value"`
	Context    string `json:"context"`
	Platform   string `json:"platform"`
	SourceFile string `json:"source_file"`
	Severity   string `json:"severity"`
}

// TimelineEvent is a single event on the unified forensic timeline.
type TimelineEvent struct {
	Timestamp         string `json:"timestamp"`
	Platform          string `json:"platform"`
	ArtifactType      string `json:"artifact_type"`
	Description       string `json:"description"`
	Severity          string `json:"severity"`
	SourcePath        string `json:"source_path"`
	User              string `json:"user,omitempty"`
	IsCollectionEvent bool   `json:"is_collection_event,omitempty"`
	ContentPreview    string `json:"content_preview,omitempty"`
}

// AtlasMapping maps an indicator to a MITRE ATLAS technique.
type AtlasMapping struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Tactic        string `json:"tactic"`
	Evidence      string `json:"evidence"`
	Platform      string `json:"platform"`
	Confidence    string `json:"confidence"`
}

// AttackTechnique is a MITRE ATT&CK technique derived from evidence.
type AttackTechnique struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	Tactic        string   `json:"tactic"`
	Count         int      `json:"count"`
	Evidence      []string `json:"evidence"`
}

// KillChainStage is one stage of the intrusion kill chain.
type KillChainStage struct {
	Stage    string   `json:"stage"`
	Detected bool     `json:"detected"`
	Evidence []string `json:"evidence"`
}

// PriorityAction is a recommended remediation step, most urgent first.
type PriorityAction struct {
	Action   string   `json:"action"`
	Urgency  string   `json:"urgency"`
	Evidence []string `json:"evidence"`
}

// Correlation links one indicator seen across multiple platforms.
type Correlation struct {
	Indicator       string   `json:"indicator"`
	CorrelationType string   `json:"correlation_type"`
	Platforms       []string `json:"platforms"`
	Severity        string   `json:"severity"`
}

// Narrative is a human-readable attack story assembled from findings.
type Narrative struct {
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	Confidence        string   `json:"confidence"`
	AffectedPlatforms []string `json:"affected_platforms"`
	KillChainStages   []string `json:"kill_chain_stages"`
	Recommendation    string   `json:"recommendation"`
	EvidenceRefs      []string `json:"evidence_refs"`
	IOCRefs           []string `json:"ioc_refs"`
}

// ConversationSession summarizes one parsed AI conversation session.
type ConversationSession struct {
	Platform          string `json:"platform"`
	SessionID         string `json:"session_id"`
	Turns             int    `json:"turns"`
	UserTurns         int    `json:"user_turns"`
	AssistantTurns    int    `json:"assistant_turns"`
	ToolCalls         int    `json:"tool_calls"`
	JailbreakAttempts int    `json:"jailbreak_attempts"`
	RiskAssessment    string `json:"risk_assessment"`
}

// ConversationSummary aggregates all parsed conversation sessions.
type ConversationSummary struct {
	TotalSessions          int                   `json:"total_sessions"`
	JailbreakAttemptsTotal int                   `json:"jailbreak_attempts_total"`
	ToolCallsTotal         int                   `json:"tool_calls_total"`
	Sessions               []ConversationSession `json:"sessions"`
}

// SecretFinding is one secret discovered inside a conversation turn.
type SecretFinding struct {
	SecretType    string `json:"secret_type"`
	Redacted      string `json:"redacted"`
	Severity      string `json:"severity"`
	LeakDirection string `json:"leak_direction"`
	EvidenceField string `json:"evidence_field"`
	Platform      string `json:"platform"`
	SessionID     string `json:"session_id"`
	Timestamp     string `json:"timestamp"`
	Fingerprint   string `json:"fingerprint"`
}

// SecretHunt is the result of scanning conversation turns for secrets.
type SecretHunt struct {
	Total           int             `json:"total"`
	FlaggedTurns    int             `json:"flagged_turns"`
	UniqueSecrets   int             `json:"unique_secrets"`
	BySeverity      map[string]int  `json:"by_severity"`
	ByLeakDirection map[string]int  `json:"by_leak_direction"`
	Findings        []SecretFinding `json:"findings"`
}

// EnhancedRisk is the weighted, category-level risk breakdown.
type EnhancedRisk struct {
	Score      int                `json:"score"`
	Severity   string             `json:"severity"`
	Categories map[string]float64 `json:"categories"`
}

// Analysis is the analysis_results.json document, matching the Python build's
// shape so either binary's evidence can be reported by the other.
type Analysis struct {
	Timeline                  []TimelineEvent     `json:"timeline"`
	IOCs                      []IOC               `json:"iocs"`
	AtlasMapping              []AtlasMapping      `json:"atlas_mapping"`
	RiskScores                RiskScores          `json:"risk_scores"`
	Platforms                 []string            `json:"platforms"`
	Findings                  []Finding           `json:"findings"`
	AttackNarratives          []Narrative         `json:"attack_narratives"`
	KillChainStages           []KillChainStage    `json:"kill_chain_stages"`
	MitreAttack               []AttackTechnique   `json:"mitre_attack"`
	PriorityActions           []PriorityAction    `json:"priority_actions"`
	CrossPlatformCorrelations []Correlation       `json:"cross_platform_correlations"`
	ConversationSummary       ConversationSummary `json:"conversation_summary"`
	EnhancedRisk              EnhancedRisk        `json:"enhanced_risk"`
	ConversationSecretHunt    *SecretHunt         `json:"conversation_secret_hunt,omitempty"`
}

// Redacted returns a shortened form of an indicator's value, safe to place in
// a narrative or report summary.
func (i IOC) Redacted() string {
	const max = 24
	if len(i.Value) <= max {
		return i.Value
	}
	return i.Value[:max-4] + "..."
}

// Correlations returns the cross-platform correlations, tolerating documents
// written before the field existed.
func (a Analysis) Correlations() []Correlation { return a.CrossPlatformCorrelations }
