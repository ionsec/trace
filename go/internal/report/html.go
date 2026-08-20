package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ionsec/trace/go/internal/model"
)

//go:embed assets/report.html.tmpl
var reportTemplate string

//go:embed assets/report.css
var reportCSS string

// toolVersion is the TRACE release this binary belongs to.
const toolVersion = "1.0.1"

// sevColors maps a severity to the TRACE palette, kept in sync with the
// Python reporter's SEV_COLORS.
var sevColors = map[string]string{
	"critical": "#ff4444",
	"high":     "#ff8800",
	"medium":   "#ffaa00",
	"low":      "#00aaff",
	"info":     "#8a8a9e",
}

func sevColor(level string) string {
	if c, ok := sevColors[strings.ToLower(level)]; ok {
		return c
	}
	return sevColors["info"]
}

// severityOrder is the ranking used for max-severity and chart ordering.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// bar is one rendered chart bar.
type bar struct {
	Label string
	Value string
	Pct   string
	Color string
}

// keyed is a labelled count used for badges and small tables.
type keyed struct {
	Key   string
	Label string
	Value int
}

// countRow is one row of an aggregate table.
type countRow struct {
	Type  string
	Count int
}

// findingView is a finding prepared for display.
type findingView struct {
	model.Finding
	SeverityLabel      string
	SearchText         string
	LocationsTruncated bool
}

// locationSearchText makes a grouped finding's files reachable from the
// findings filter box, so an analyst can search by the file that tripped it.
func locationSearchText(locations []model.FindingLocation) string {
	var b strings.Builder
	for _, l := range locations {
		b.WriteString(l.File)
		b.WriteString(" ")
	}
	return b.String()
}

// actionView is a priority action with its urgency colour resolved.
type actionView struct {
	model.PriorityAction
	Color string
}

// narrativeView is a narrative prepared for display.
type narrativeView struct {
	model.Narrative
	SeverityLabel string
	PlatformText  string
}

// attackView is an ATT&CK technique with its evidence flattened.
type attackView struct {
	model.AttackTechnique
	EvidenceText string
}

// killChainView is a kill-chain stage with its CSS class and label resolved.
type killChainView struct {
	model.KillChainStage
	StageID      string
	Short        string
	EvidenceText string
}

// atlasRow aggregates ATLAS mappings by technique.
type atlasRow struct {
	TechniqueID   string
	TechniqueName string
	Count         int
}

// artifactView is a collected file prepared for the evidence manifest.
type artifactView struct {
	model.CollectedFile
	BaseName          string
	ArtifactTypeUpper string
	SizeText          string
}

// riskCategoryView is one row of the enhanced risk breakdown.
type riskCategoryView struct {
	Label      string
	Value      string
	Level      string
	LevelLabel string
}

// custodyRow is one chain-of-custody metadata pair.
type custodyRow struct {
	Key   string
	Value string
}

// reportView is everything the HTML template renders. All formatting decisions
// happen here so the template stays a layout, not a program.
type reportView struct {
	CSS      template.CSS
	ReportID string

	GeneratedAt string
	Version     string
	EvidenceDir string
	SourceOS    string
	Hostname    string

	SummaryText        string
	RiskScore          int
	RiskSeverity       string
	RiskColor          string
	RiskInterpretation string

	TotalArtifacts int
	TotalIOCs      int
	TotalFindings  int
	PlatformCount  int
	PlatformList   string
	CriticalCount  int
	HighCount      int

	KillChainDetected int
	KillChainTotal    int

	Platforms      []string
	SeverityBadges []keyed
	SeverityBars   []bar
	DonutGradient  template.CSS
	IOCBars        []bar
	PlatformBars   []bar
	TimelineBars   []bar
	MitreBars      []bar
	RiskCatBars    []bar

	TopActions []actionView
	Actions    []actionView

	Findings          []findingView
	IOCs              []model.IOC
	IOCSummary        []countRow
	Timeline          []model.TimelineEvent
	TimelineTotal     int
	TimelineTruncated bool
	AtlasSummary      []atlasRow
	AtlasTotal        int
	MitreAttack       []attackView
	KillChain         []killChainView
	Narratives        []narrativeView
	Correlations      []model.Correlation
	Conversation      model.ConversationSummary
	SecretHunt        *model.SecretHunt
	SecretSeverities  []keyed
	SecretDirections  []keyed
	RiskCategories    []riskCategoryView
	Artifacts         []artifactView
	PlatformDetails   []model.Platform
	Custody           []custodyRow

	MapDataJSON template.JS
}

// display caps for the tables that can grow without bound.
const (
	maxTimelineRows = 500
	maxIOCRows      = 200
	maxSecretRows   = 200
)

// GenerateHTML writes the full forensic report to the evidence directory,
// rendering the same 15-tab layout as the Python reporter.
func GenerateHTML(evidenceDir string, coc model.ChainOfCustody, analysis model.Analysis) (string, error) {
	view := buildView(evidenceDir, coc, analysis)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}).Parse(reportTemplate)
	if err != nil {
		return "", err
	}

	out := filepath.Join(evidenceDir, "report.html")
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := tmpl.Execute(f, view); err != nil {
		return "", err
	}
	return out, nil
}

// buildView turns raw evidence and analysis into the render-ready view.
func buildView(evidenceDir string, coc model.ChainOfCustody, analysis model.Analysis) reportView {
	generated := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	severityCounts := map[string]int{}
	for _, f := range analysis.Findings {
		sev := strings.ToLower(string(f.Severity))
		if sev == "" {
			sev = "info"
		}
		severityCounts[sev]++
	}

	platformDetails := buildPlatformDetails(coc, analysis)
	risk := analysis.RiskScores.Score
	riskSeverity := analysis.RiskScores.Severity
	if riskSeverity == "" {
		riskSeverity = "info"
	}

	view := reportView{
		CSS:                template.CSS(reportCSS),
		ReportID:           reportID(),
		GeneratedAt:        generated,
		Version:            toolVersion,
		EvidenceDir:        evidenceDir,
		SourceOS:           osName(),
		Hostname:           hostname(),
		RiskScore:          risk,
		RiskSeverity:       strings.ToUpper(riskSeverity[:1]) + riskSeverity[1:],
		RiskColor:          riskColor(risk),
		RiskInterpretation: riskInterpretation(risk),
		TotalArtifacts:     len(coc.Files),
		TotalIOCs:          len(analysis.IOCs),
		TotalFindings:      len(analysis.Findings),
		CriticalCount:      severityCounts["critical"],
		HighCount:          severityCounts["high"],
		KillChainTotal:     len(analysis.KillChainStages),
		Platforms:          analysis.Platforms,
		IOCs:               capIOCs(analysis.IOCs, maxIOCRows),
		Correlations:       analysis.Correlations(),
		Conversation:       analysis.ConversationSummary,
		PlatformDetails:    platformDetails,
	}
	view.PlatformCount = len(platformDetails)

	names := make([]string, 0, len(platformDetails))
	for _, p := range platformDetails {
		names = append(names, p.Name)
	}
	view.PlatformList = strings.Join(names, ", ")
	if view.PlatformList == "" {
		view.PlatformList = "none"
	}
	if len(view.Platforms) == 0 {
		view.Platforms = names
	}

	view.SummaryText = fmt.Sprintf(
		"TRACE collected %d artifacts from %d platform(s) (%s). Analysis identified %d findings (%s) and %d indicator(s) of compromise. Overall risk score: %d/100.",
		len(coc.Files), len(platformDetails), view.PlatformList, len(analysis.Findings),
		severityText(severityCounts), len(analysis.IOCs), risk)

	for _, s := range analysis.KillChainStages {
		if s.Detected {
			view.KillChainDetected++
		}
	}

	// Badges and charts.
	for _, sev := range severityOrder {
		if severityCounts[sev] == 0 {
			continue
		}
		view.SeverityBadges = append(view.SeverityBadges, keyed{Key: sev, Label: title(sev), Value: severityCounts[sev]})
	}
	sevMax := 1
	for _, sev := range severityOrder {
		if severityCounts[sev] > sevMax {
			sevMax = severityCounts[sev]
		}
	}
	for _, sev := range severityOrder {
		view.SeverityBars = append(view.SeverityBars, makeBar(title(sev), severityCounts[sev], sevMax, sevColor(sev), ""))
	}
	view.DonutGradient = template.CSS(donutGradient(severityCounts))

	view.IOCSummary = iocSummary(analysis.IOCs)
	iocMax := 1
	for _, row := range view.IOCSummary {
		if row.Count > iocMax {
			iocMax = row.Count
		}
	}
	for i, row := range view.IOCSummary {
		if i >= 10 {
			break
		}
		view.IOCBars = append(view.IOCBars, makeBar(row.Type, row.Count, iocMax, "#e63946", ""))
	}

	platMax := 1
	for _, p := range platformDetails {
		if p.ArtifactCount > platMax {
			platMax = p.ArtifactCount
		}
	}
	for _, p := range platformDetails {
		view.PlatformBars = append(view.PlatformBars, makeBar(p.Name, p.ArtifactCount, platMax, sevColor(p.MaxSeverity), ""))
	}

	view.TimelineTotal = len(analysis.Timeline)
	view.Timeline = analysis.Timeline
	if len(view.Timeline) > maxTimelineRows {
		view.Timeline = view.Timeline[:maxTimelineRows]
		view.TimelineTruncated = true
	}
	view.TimelineBars = timelineBars(analysis.Timeline)

	mitreMax := 1
	for _, t := range analysis.MitreAttack {
		if t.Count > mitreMax {
			mitreMax = t.Count
		}
	}
	for i, t := range analysis.MitreAttack {
		if i >= 8 {
			break
		}
		view.MitreBars = append(view.MitreBars, makeBar(t.TechniqueID, t.Count, mitreMax, sevColors["high"], ""))
		view.MitreAttack = append(view.MitreAttack, attackView{
			AttackTechnique: t,
			EvidenceText:    joinLimit(t.Evidence, 2, "; "),
		})
	}
	for i := len(view.MitreAttack); i < len(analysis.MitreAttack); i++ {
		t := analysis.MitreAttack[i]
		view.MitreAttack = append(view.MitreAttack, attackView{
			AttackTechnique: t,
			EvidenceText:    joinLimit(t.Evidence, 2, "; "),
		})
	}

	for _, cat := range sortedCategoryNames(analysis.EnhancedRisk.Categories) {
		score := analysis.EnhancedRisk.Categories[cat]
		level := riskLevel(score)
		view.RiskCatBars = append(view.RiskCatBars, makeBar(strings.ReplaceAll(cat, "_", " "), int(score), 25, sevColor(level), trimFloat(score)))
		view.RiskCategories = append(view.RiskCategories, riskCategoryView{
			Label:      title(strings.ReplaceAll(cat, "_", " ")),
			Value:      trimFloat(score),
			Level:      level,
			LevelLabel: title(level),
		})
	}

	for _, a := range analysis.PriorityActions {
		view.Actions = append(view.Actions, actionView{PriorityAction: a, Color: urgencyColor(a.Urgency)})
	}
	view.TopActions = view.Actions
	if len(view.TopActions) > 3 {
		view.TopActions = view.TopActions[:3]
	}

	for _, f := range analysis.Findings {
		sev := strings.ToLower(string(f.Severity))
		view.Findings = append(view.Findings, findingView{
			Finding:            f,
			SeverityLabel:      title(sev),
			SearchText:         strings.ToLower(f.Title + " " + f.Description + " " + f.Platform + " " + locationSearchText(f.Locations)),
			LocationsTruncated: f.Occurrences > len(f.Locations),
		})
	}

	view.AtlasTotal = len(analysis.AtlasMapping)
	view.AtlasSummary = atlasSummary(analysis.AtlasMapping)

	for _, s := range analysis.KillChainStages {
		view.KillChain = append(view.KillChain, killChainView{
			KillChainStage: s,
			StageID:        stageID(s.Stage),
			Short:          shortStage(s.Stage),
			EvidenceText:   joinLimit(s.Evidence, 3, "; "),
		})
	}

	for _, n := range analysis.AttackNarratives {
		platforms := strings.Join(n.AffectedPlatforms, ", ")
		if platforms == "" {
			platforms = "Unknown"
		}
		view.Narratives = append(view.Narratives, narrativeView{
			Narrative:     n,
			SeverityLabel: title(n.Severity),
			PlatformText:  platforms,
		})
	}

	if hunt := analysis.ConversationSecretHunt; hunt != nil && hunt.Total > 0 {
		trimmed := *hunt
		if len(trimmed.Findings) > maxSecretRows {
			trimmed.Findings = trimmed.Findings[:maxSecretRows]
		}
		view.SecretHunt = &trimmed
		for _, sev := range severityOrder {
			if n := hunt.BySeverity[sev]; n > 0 {
				view.SecretSeverities = append(view.SecretSeverities, keyed{Key: sev, Label: title(sev), Value: n})
			}
		}
		for _, dir := range sortedCountKeys(hunt.ByLeakDirection) {
			view.SecretDirections = append(view.SecretDirections, keyed{Key: dir, Value: hunt.ByLeakDirection[dir]})
		}
	}

	for _, f := range coc.Files {
		view.Artifacts = append(view.Artifacts, artifactView{
			CollectedFile:     f,
			BaseName:          filepath.Base(f.OriginalPath),
			ArtifactTypeUpper: strings.ToUpper(f.ArtifactType),
			SizeText:          humanSize(f.SizeBytes),
		})
	}

	view.Custody = []custodyRow{
		{"tool", coc.Tool},
		{"version", coc.Version},
		{"collected_at", coc.CollectedAt},
		{"total_files", fmt.Sprint(coc.TotalFiles)},
		{"hash_algorithm", "SHA-256"},
	}

	view.MapDataJSON = template.JS(mapDataJSON(platformDetails, analysis))
	return view
}

// buildPlatformDetails aggregates artifacts and findings per platform.
func buildPlatformDetails(coc model.ChainOfCustody, analysis model.Analysis) []model.Platform {
	byName := map[string]*model.Platform{}
	var order []string
	ensure := func(name string) *model.Platform {
		if name == "" {
			name = "unknown"
		}
		p, ok := byName[name]
		if !ok {
			p = &model.Platform{Name: name, MaxSeverity: "info"}
			byName[name] = p
			order = append(order, name)
		}
		return p
	}

	for _, f := range coc.Files {
		ensure(f.Platform).ArtifactCount++
	}
	for _, f := range analysis.Findings {
		p := ensure(f.Platform)
		p.FindingCount++
		if severityRank(string(f.Severity)) > severityRank(p.MaxSeverity) {
			p.MaxSeverity = strings.ToLower(string(f.Severity))
		}
	}

	out := make([]model.Platform, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ArtifactCount > out[j].ArtifactCount })
	return out
}

// severityRank orders severities for comparison.
func severityRank(s string) int {
	for i, name := range severityOrder {
		if strings.EqualFold(s, name) {
			return len(severityOrder) - i
		}
	}
	return 0
}

// makeBar renders one chart bar; display overrides the printed value.
func makeBar(label string, value, max int, color, display string) bar {
	pct := 0
	if max > 0 {
		pct = value * 100 / max
		if pct < 2 {
			pct = 2
		}
	}
	shown := display
	if shown == "" {
		shown = fmt.Sprint(value)
	}
	return bar{Label: label, Value: shown, Pct: fmt.Sprintf("%d%%", pct), Color: color}
}

// donutGradient builds the conic-gradient stops for the severity donut.
func donutGradient(counts map[string]int) string {
	total := 0
	for _, sev := range severityOrder {
		total += counts[sev]
	}
	if total == 0 {
		return ""
	}
	var stops []string
	cursor := 0.0
	for _, sev := range severityOrder {
		n := counts[sev]
		if n == 0 {
			continue
		}
		end := cursor + float64(n)/float64(total)*100
		stops = append(stops, fmt.Sprintf("%s %.4g%% %.4g%%", sevColor(sev), cursor, end))
		cursor = end
	}
	return "conic-gradient(" + strings.Join(stops, ", ") + ")"
}

// iocSummary counts indicators per type, most common first.
func iocSummary(iocs []model.IOC) []countRow {
	counts := map[string]int{}
	for _, ioc := range iocs {
		counts[ioc.IOCType]++
	}
	out := make([]countRow, 0, len(counts))
	for t, c := range counts {
		out = append(out, countRow{Type: t, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// atlasSummary aggregates ATLAS mappings by technique, most frequent first.
func atlasSummary(mappings []model.AtlasMapping) []atlasRow {
	counts := map[string]*atlasRow{}
	var order []string
	for _, m := range mappings {
		r, ok := counts[m.TechniqueID]
		if !ok {
			r = &atlasRow{TechniqueID: m.TechniqueID, TechniqueName: m.TechniqueName}
			counts[m.TechniqueID] = r
			order = append(order, m.TechniqueID)
		}
		r.Count++
	}
	out := make([]atlasRow, 0, len(order))
	for _, id := range order {
		out = append(out, *counts[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// timelineBars buckets timeline events per day for the activity chart.
func timelineBars(events []model.TimelineEvent) []bar {
	buckets := map[string]int{}
	for _, e := range events {
		day := e.Timestamp
		if len(day) >= 10 {
			day = day[:10]
		}
		if day == "" {
			day = "unknown"
		}
		buckets[day]++
	}
	days := make([]string, 0, len(buckets))
	for d := range buckets {
		days = append(days, d)
	}
	sort.Strings(days)
	if len(days) > 30 {
		days = days[len(days)-30:]
	}
	max := 1
	for _, d := range days {
		if buckets[d] > max {
			max = buckets[d]
		}
	}
	out := make([]bar, 0, len(days))
	for _, d := range days {
		label := d
		if len(d) >= 10 {
			label = d[5:10]
		}
		out = append(out, makeBar(label, buckets[d], max, "#e63946", ""))
	}
	return out
}

// mapDataJSON builds the attack-map graph: one node per platform, one edge per
// cross-platform correlation.
func mapDataJSON(platforms []model.Platform, analysis model.Analysis) string {
	type node struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		Category      string `json:"category"`
		Color         string `json:"color"`
		MaxSeverity   string `json:"max_severity"`
		FindingCount  int    `json:"finding_count"`
		ArtifactCount int    `json:"artifact_count"`
		IOCCount      int    `json:"ioc_count"`
		RiskIndex     int    `json:"risk_index"`
	}
	type edge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Label  string `json:"label"`
	}

	iocCounts := map[string]int{}
	for _, ioc := range analysis.IOCs {
		iocCounts[ioc.Platform]++
	}

	nodes := make([]node, 0, len(platforms))
	present := map[string]bool{}
	for _, p := range platforms {
		present[p.Name] = true
		nodes = append(nodes, node{
			ID: p.Name, Name: p.Name, Category: p.Category,
			Color: sevColor(p.MaxSeverity), MaxSeverity: p.MaxSeverity,
			FindingCount: p.FindingCount, ArtifactCount: p.ArtifactCount,
			IOCCount: iocCounts[p.Name], RiskIndex: severityRank(p.MaxSeverity),
		})
	}

	var edges []edge
	seen := map[string]bool{}
	for _, c := range analysis.Correlations() {
		for i := 0; i < len(c.Platforms); i++ {
			for j := i + 1; j < len(c.Platforms); j++ {
				a, b := c.Platforms[i], c.Platforms[j]
				if !present[a] || !present[b] {
					continue
				}
				key := a + "\x00" + b
				if seen[key] {
					continue
				}
				seen[key] = true
				edges = append(edges, edge{Source: a, Target: b, Label: c.CorrelationType})
			}
		}
	}

	data, err := json.Marshal(map[string]any{"nodes": nodes, "edges": edges})
	if err != nil {
		return `{"nodes":[],"edges":[]}`
	}
	return string(data)
}

// riskColor is the palette entry for a 0-100 risk score.
func riskColor(score int) string {
	switch {
	case score >= 80:
		return sevColors["critical"]
	case score >= 60:
		return sevColors["high"]
	case score >= 40:
		return sevColors["medium"]
	case score >= 20:
		return sevColors["low"]
	}
	return "#e63946"
}

// riskInterpretation is the analyst-facing reading of a risk score.
func riskInterpretation(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL: Immediate investigation required. Multiple high-confidence indicators of AI misuse or compromise."
	case score >= 60:
		return "HIGH: Significant threats identified. Prioritize remediation within 24 hours."
	case score >= 40:
		return "MEDIUM: Notable risk indicators present. Review and remediate during the next work cycle."
	case score >= 20:
		return "LOW: Minor risk indicators. Monitor and address as routine hygiene."
	}
	return "INFO: No significant risk indicators detected in the collected evidence."
}

// riskLevel labels a 0-25 category score.
func riskLevel(score float64) string {
	switch {
	case score >= 20:
		return "critical"
	case score >= 14:
		return "high"
	case score >= 8:
		return "medium"
	case score > 0:
		return "low"
	}
	return "info"
}

// urgencyColor is the palette entry for a priority-action urgency.
func urgencyColor(urgency string) string {
	switch strings.ToUpper(urgency) {
	case "CRITICAL":
		return sevColors["critical"]
	case "HIGH":
		return sevColors["high"]
	case "MEDIUM":
		return sevColors["medium"]
	case "LOW":
		return sevColors["low"]
	}
	return sevColors["info"]
}

// stageID is the CSS class suffix for a kill-chain stage.
func stageID(stage string) string {
	switch stage {
	case "Command & Control":
		return "stage-c2"
	case "Actions on Objectives":
		return "stage-actions"
	}
	return "stage-" + strings.ToLower(strings.ReplaceAll(stage, " ", "-"))
}

// shortStage abbreviates a stage name for the compact kill-chain bar.
func shortStage(stage string) string {
	first := strings.SplitN(stage, " ", 2)[0]
	if len(first) > 6 {
		return first[:6]
	}
	return first
}

// severityText renders the severity mix for the executive summary.
func severityText(counts map[string]int) string {
	var parts []string
	for _, sev := range severityOrder {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

// sortedCategoryNames returns risk categories in descending score order.
func sortedCategoryNames(categories map[string]float64) []string {
	names := make([]string, 0, len(categories))
	for name := range categories {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if categories[names[i]] != categories[names[j]] {
			return categories[names[i]] > categories[names[j]]
		}
		return names[i] < names[j]
	})
	return names
}

// sortedCountKeys returns a count map's keys in descending count order.
func sortedCountKeys(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// capIOCs limits how many indicators the report table renders.
func capIOCs(iocs []model.IOC, n int) []model.IOC {
	if len(iocs) <= n {
		return iocs
	}
	return iocs[:n]
}

// joinLimit joins up to n items, rendering an em dash when there are none.
func joinLimit(items []string, n int, sep string) string {
	if len(items) == 0 {
		return "—"
	}
	if len(items) > n {
		items = items[:n]
	}
	return strings.Join(items, sep)
}

// title upper-cases the first letter of a label.
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// trimFloat renders a score without trailing zeros.
func trimFloat(f float64) string {
	return strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.1f", f), "0"), ".")
}

// humanSize renders a byte count in binary units.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// hostname returns this endpoint's name, or "" when it cannot be read.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
