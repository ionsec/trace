package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ionsec/trace/go/internal/analyze"
	"github.com/ionsec/trace/go/internal/model"
)

// stixObject is one STIX 2.1 SDO or SRO. STIX is schema-loose enough that a
// map keeps the generator readable without a type per object kind.
type stixObject map[string]any

// stixID builds a STIX identifier of the form <type>--<uuid v4>.
func stixID(objType string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A deterministic fallback is preferable to failing a report.
		copy(b[:], []byte(objType+"trace-fallback-id"))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s--%s-%s-%s-%s-%s", objType, h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// stixPattern renders an indicator as a STIX pattern expression.
func stixPattern(ioc model.IOC) string {
	value := strings.ReplaceAll(ioc.Value, "'", "\\'")
	switch strings.ToLower(ioc.IOCType) {
	case "ip":
		return "[ipv4-addr:value = '" + value + "']"
	case "domain":
		return "[domain-name:value = '" + value + "']"
	case "url":
		return "[url:value = '" + value + "']"
	case "email":
		return "[email-addr:value = '" + value + "']"
	case "filepath":
		return "[file:name = '" + value + "']"
	case "hash_md5":
		return "[file:hashes.'MD5' = '" + value + "']"
	case "hash_sha1":
		return "[file:hashes.'SHA-1' = '" + value + "']"
	case "hash_sha256":
		return "[file:hashes.'SHA-256' = '" + value + "']"
	case "api_key":
		return "[artifact:payload_bin = '" + value + "']"
	}
	return "[x-trace-indicator:value = '" + value + "']"
}

// severityLabels are the STIX labels attached to an object of a severity.
func severityLabels(severity string) []string {
	switch strings.ToLower(severity) {
	case "critical":
		return []string{"malicious-activity", "critical"}
	case "high":
		return []string{"malicious-activity", "high"}
	case "medium":
		return []string{"suspicious-activity", "medium"}
	case "low":
		return []string{"suspicious-activity", "low"}
	}
	return []string{"informational"}
}

// severityConfidence maps a severity to a STIX confidence score.
func severityConfidence(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 40
	}
	return 20
}

// GenerateSTIX writes a STIX 2.1 bundle describing the analyzed evidence.
func GenerateSTIX(evidenceDir string, coc model.ChainOfCustody, analysis model.Analysis) (string, error) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	var objects []stixObject

	identityID := stixID("identity")
	objects = append(objects, stixObject{
		"type": "identity", "spec_version": "2.1", "id": identityID,
		"created": ts, "modified": ts,
		"name": "IONSEC", "identity_class": "organization",
		"sectors":             []string{"technology", "cybersecurity"},
		"contact_information": "trace@ionsec.io",
	})

	indicatorByValue := map[string]string{}
	var indicatorIDs []string
	for _, ioc := range analysis.IOCs {
		id := stixID("indicator")
		indicatorIDs = append(indicatorIDs, id)
		indicatorByValue[ioc.Value] = id
		objects = append(objects, stixObject{
			"type": "indicator", "spec_version": "2.1", "id": id,
			"created_by_ref": identityID, "created": ts, "modified": ts,
			"name":             "TRACE IOC: " + ioc.Value,
			"description":      "Indicator of compromise detected by TRACE: " + ioc.Value,
			"indicator_types":  []string{"malicious-activity", "suspicious-activity"},
			"pattern":          stixPattern(ioc),
			"pattern_type":     "stix",
			"valid_from":       ts,
			"confidence":       severityConfidence(ioc.Severity),
			"labels":           severityLabels(ioc.Severity),
			"x_trace_ioc_type": ioc.IOCType,
			"x_trace_source":   ioc.SourceFile,
			"x_trace_platform": ioc.Platform,
		})
	}

	var observedIDs []string
	for _, f := range analysis.Findings {
		id := stixID("observed-data")
		observedIDs = append(observedIDs, id)
		refs := []string{}
		for _, ref := range f.IOCs {
			if indicatorID, ok := indicatorByValue[ref]; ok {
				refs = append(refs, indicatorID)
			}
		}
		objects = append(objects, stixObject{
			"type": "observed-data", "spec_version": "2.1", "id": id,
			"created_by_ref": identityID, "created": ts, "modified": ts,
			"first_observed": ts, "last_observed": ts, "number_observed": 1,
			"object_refs":         refs,
			"x_trace_finding_id":  f.ID,
			"x_trace_title":       f.Title,
			"x_trace_description": f.Description,
			"x_trace_severity":    string(f.Severity),
			"x_trace_platform":    f.Platform,
			"x_trace_risk_score":  f.RiskScore,
			"labels":              severityLabels(string(f.Severity)),
		})
	}

	attackPatternIDs := map[string]string{}
	for _, tech := range analysis.MitreAttack {
		if tech.TechniqueID == "" || attackPatternIDs[tech.TechniqueID] != "" {
			continue
		}
		id := stixID("attack-pattern")
		attackPatternIDs[tech.TechniqueID] = id
		description := tech.TechniqueName
		if len(tech.Evidence) > 0 {
			description = tech.Evidence[0]
		}
		objects = append(objects, stixObject{
			"type": "attack-pattern", "spec_version": "2.1", "id": id,
			"created_by_ref": identityID, "created": ts, "modified": ts,
			"name": tech.TechniqueName, "description": description,
			"external_references": []map[string]string{{
				"source_name": "mitre-attack",
				"external_id": tech.TechniqueID,
				"url":         "https://attack.mitre.org/techniques/" + tech.TechniqueID + "/",
			}},
			"kill_chain_phases": []map[string]string{{
				"kill_chain_name": "mitre-attack",
				"phase_name":      strings.ToLower(strings.ReplaceAll(tech.Tactic, " ", "-")),
			}},
		})
	}

	for _, entry := range analysis.AtlasMapping {
		if entry.TechniqueID == "" || attackPatternIDs[entry.TechniqueID] != "" {
			continue
		}
		id := stixID("attack-pattern")
		attackPatternIDs[entry.TechniqueID] = id
		objects = append(objects, stixObject{
			"type": "attack-pattern", "spec_version": "2.1", "id": id,
			"created_by_ref": identityID, "created": ts, "modified": ts,
			"name": entry.TechniqueName, "description": entry.Evidence,
			"external_references": []map[string]string{{
				"source_name": "mitre-atlas",
				"external_id": entry.TechniqueID,
				"url":         "https://atlas.mitre.org/techniques/" + entry.TechniqueID,
			}},
		})
	}

	// Relate every indicator to the techniques the evidence supports.
	for _, indicatorID := range indicatorIDs {
		for _, apID := range attackPatternIDs {
			objects = append(objects, stixObject{
				"type": "relationship", "spec_version": "2.1", "id": stixID("relationship"),
				"created_by_ref": identityID, "created": ts, "modified": ts,
				"relationship_type": "indicates",
				"source_ref":        indicatorID,
				"target_ref":        apID,
			})
			break // one representative link per indicator keeps the bundle readable
		}
	}

	var coaIDs []string
	for _, action := range analysis.PriorityActions {
		id := stixID("course-of-action")
		coaIDs = append(coaIDs, id)
		objects = append(objects, stixObject{
			"type": "course-of-action", "spec_version": "2.1", "id": id,
			"created_by_ref": identityID, "created": ts, "modified": ts,
			"name":             action.Action,
			"description":      "Urgency: " + action.Urgency + ". Evidence: " + joinLimit(action.Evidence, 3, "; "),
			"x_trace_urgency":  action.Urgency,
			"x_trace_evidence": action.Evidence,
		})
	}

	for _, n := range analysis.AttackNarratives {
		objects = append(objects, stixObject{
			"type": "note", "spec_version": "2.1", "id": stixID("note"),
			"created_by_ref": identityID, "created": ts, "modified": ts,
			"abstract":                   n.Title,
			"content":                    n.Recommendation,
			"authors":                    []string{"TRACE"},
			"object_refs":                observedIDs,
			"x_trace_severity":           n.Severity,
			"x_trace_confidence":         n.Confidence,
			"x_trace_kill_chain_stages":  n.KillChainStages,
			"x_trace_affected_platforms": n.AffectedPlatforms,
		})
	}

	reportRefs := append(append([]string{}, indicatorIDs...), observedIDs...)
	reportRefs = append(reportRefs, coaIDs...)
	if len(reportRefs) == 0 {
		reportRefs = []string{identityID}
	}
	objects = append(objects, stixObject{
		"type": "report", "spec_version": "2.1", "id": stixID("report"),
		"created_by_ref": identityID, "created": ts, "modified": ts,
		"name":                  "TRACE AI Forensic Report",
		"description":           "AI platform forensic evidence collected and analyzed by TRACE.",
		"report_types":          []string{"threat-report"},
		"published":             ts,
		"object_refs":           reportRefs,
		"x_trace_version":       toolVersion,
		"x_trace_risk_score":    analysis.RiskScores.Score,
		"x_trace_total_files":   len(coc.Files),
		"x_trace_source_os":     osName(),
		"x_trace_platform_list": analysis.Platforms,
	})

	bundle := map[string]any{
		"type":    "bundle",
		"id":      stixID("bundle"),
		"objects": objects,
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(evidenceDir, "report.stix.json")
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return "", err
	}
	return out, nil
}

// GenerateAll writes every report format for an evidence directory and returns
// the paths written, keyed by format.
func GenerateAll(evidenceDir string, coc model.ChainOfCustody, formats []string) (map[string]string, error) {
	analysis, err := LoadAnalysis(evidenceDir)
	if err != nil {
		// A report over un-analyzed evidence is still useful: run the analysis
		// passes inline rather than emitting an empty report.
		analysis, err = analyze.Run(evidenceDir, analyze.AllPasses())
		if err != nil {
			return nil, err
		}
	}

	out := map[string]string{}
	for _, format := range formats {
		switch format {
		case "html":
			path, err := GenerateHTML(evidenceDir, coc, analysis)
			if err != nil {
				return out, err
			}
			out["html"] = path
		case "json":
			path, err := GenerateJSONReport(evidenceDir, coc, analysis)
			if err != nil {
				return out, err
			}
			out["json"] = path
		case "stix":
			path, err := GenerateSTIX(evidenceDir, coc, analysis)
			if err != nil {
				return out, err
			}
			out["stix"] = path
		}
	}
	return out, nil
}

// LoadAnalysis reads analysis_results.json from an evidence directory.
func LoadAnalysis(evidenceDir string) (model.Analysis, error) {
	var analysis model.Analysis
	data, err := os.ReadFile(filepath.Join(evidenceDir, "analysis_results.json"))
	if err != nil {
		return analysis, err
	}
	if err := json.Unmarshal(data, &analysis); err != nil {
		return analysis, err
	}
	return analysis, nil
}

// writeAnalysis persists an analysis document into an evidence directory,
// which is how the report command finds a prior `trace analyze` run.
func writeAnalysis(evidenceDir string, analysis model.Analysis) error {
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(evidenceDir, "analysis_results.json"), data, 0o600)
}
