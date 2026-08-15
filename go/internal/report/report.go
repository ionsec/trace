// Package report generates JSON and HTML forensic reports from collected
// evidence, mirroring the Python ionsec_trace reporters.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ionsec/trace/go/internal/collect"
	"github.com/ionsec/trace/go/internal/detect"
	"github.com/ionsec/trace/go/internal/model"
)

// GenerateJSONReport writes the structured JSON report for analyzed evidence.
// Its shape mirrors the Python JSON reporter so either build's evidence can be
// consumed by the same downstream tooling.
func GenerateJSONReport(evidenceDir string, coc model.ChainOfCustody, analysis model.Analysis) (string, error) {
	detections := detect.Discover()
	parsed := buildParsedArtifacts(coc)
	now := time.Now().UTC()

	platforms := buildPlatformDetails(coc, analysis)
	for i := range platforms {
		for _, d := range detections {
			if d.Tool == platforms[i].Name && platforms[i].Category == "" {
				platforms[i].Category = d.Category
			}
		}
	}

	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range analysis.Findings {
		key := strings.ToLower(string(f.Severity))
		if key == "" {
			key = "info"
		}
		sev[key]++
	}

	risk := analysis.RiskScores
	if risk.Score == 0 && risk.Severity == "" {
		risk = model.RiskScores{Score: riskScore(detections), Severity: riskSeverity(detections)}
	}

	report := model.Report{
		SchemaVersion: "2.0.0",
		Metadata: model.Metadata{
			ReportID:      reportID(),
			GeneratedAt:   now.Format(time.RFC3339),
			Tool:          "TRACE",
			Version:       toolVersion,
			SchemaVersion: "2.0.0",
			SourceOS:      osName(),
			Hostname:      hostname(),
		},
		Platforms:        platforms,
		EvidenceManifest: coc.Files,
		Findings:         analysis.Findings,
		Detections:       detections,
		ChainOfCustody:   coc,
		ParsedArtifacts:  parsed,
		SeveritySummary:  sev,
		RiskScores:       risk,
		Analysis:         &analysis,
		Summary: model.Summary{
			PlatformsDetected: len(platforms),
			FilesCollected:    len(coc.Files),
			CriticalFindings:  sev["critical"],
			HighFindings:      sev["high"],
			RiskScore:         risk.Score,
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(evidenceDir, "report.json")
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return "", err
	}
	return out, nil
}

// osName returns the current OS name (mirrors Python source_os).
func osName() string {
	return runtime.GOOS
}

// riskScore derives a 0-100 risk score from detections (mirrors Python).
func riskScore(ds []model.Detection) int {
	score := 0
	for _, d := range ds {
		switch d.Risk {
		case "critical":
			score += 30
		case "high":
			score += 20
		case "medium":
			score += 10
		case "low":
			score += 3
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

// riskSeverity maps a risk score to a severity label.
func riskSeverity(ds []model.Detection) string {
	s := riskScore(ds)
	switch {
	case s >= 80:
		return "critical"
	case s >= 60:
		return "high"
	case s >= 40:
		return "medium"
	case s >= 20:
		return "low"
	default:
		return "info"
	}
}

// buildParsedArtifacts turns collected files into analyst-facing parsed
// summaries. SQLite conversation/state stores get schema + sample parsing;
// text config/session files get a bounded readable preview.
func buildParsedArtifacts(coc model.ChainOfCustody) []model.ParsedArtifact {
	var out []model.ParsedArtifact
	for _, f := range coc.Files {
		ext := strings.ToLower(filepath.Ext(f.OriginalPath))
		switch {
		case ext == ".sqlite" || ext == ".sqlite3" || ext == ".db" || ext == ".vscdb":
			sum := collect.ParseSQLite(f.OriginalPath)
			if sum != nil {
				out = append(out, model.ParsedArtifact{
					Path:         f.OriginalPath,
					Platform:     f.Platform,
					ArtifactType: f.ArtifactType,
					Summary:      sum.Format(),
					Tables:       sum.Tables,
					RowEstimate:  sum.RowEstimate,
					Sample:       sum.SampleStrings,
				})
			}
		case ext == ".json" || ext == ".jsonl" || ext == ".ndjson" || ext == ".log" || ext == ".txt" || ext == ".md":
			preview := collect.ReadPreview(f.OriginalPath)
			if preview != "" {
				out = append(out, model.ParsedArtifact{
					Path:         f.OriginalPath,
					Platform:     f.Platform,
					ArtifactType: f.ArtifactType,
					Summary:      preview,
				})
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func countHigh(ds []model.Detection) int {
	n := 0
	for _, d := range ds {
		if d.Risk == "high" || d.Risk == "critical" {
			n++
		}
	}
	return n
}

func reportID() string {
	return fmt.Sprintf("TRACE_Report_%d", time.Now().Unix())
}
