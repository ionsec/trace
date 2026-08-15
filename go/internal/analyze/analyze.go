package analyze

import (
	"path/filepath"
	"sort"

	"github.com/ionsec/trace/go/internal/model"
)

// Options selects the optional analysis passes.
type Options struct {
	MITREAtlas  bool
	MITREAttack bool
	RiskScore   bool
	SecretHunt  bool
}

// AllPasses enables every analysis pass.
func AllPasses() Options {
	return Options{MITREAtlas: true, MITREAttack: true, RiskScore: true, SecretHunt: true}
}

// Run analyzes an evidence directory and returns the complete analysis
// document, which Run also writes to analysis_results.json.
func Run(evidenceDir string, opts Options) (model.Analysis, error) {
	conv := ParseEvidenceDir(evidenceDir)
	iocs := NewIOCExtractor(evidenceDir).Extract().IOCs

	analysis := model.Analysis{
		IOCs:     iocs,
		Findings: conv.Findings,
		Timeline: BuildTimeline(evidenceDir, conv.Turns),
	}

	if opts.MITREAtlas {
		analysis.AtlasMapping = MapATLAS(iocs)
	}

	analysis.KillChainStages = DeriveKillChain(analysis.Findings, iocs, analysis.AtlasMapping)

	if opts.MITREAttack {
		analysis.MitreAttack = DeriveAttack(analysis.Findings, iocs, analysis.AtlasMapping)
	}

	if opts.RiskScore {
		analysis.RiskScores = ScoreRisk(analysis.Findings, iocs)
		analysis.EnhancedRisk = DeriveEnhancedRisk(analysis.RiskScores, analysis.Findings, iocs)
	}

	analysis.CrossPlatformCorrelations = DeriveCorrelations(iocs, analysis.Findings)
	analysis.PriorityActions = DerivePriorityActions(analysis.Findings, iocs, analysis.KillChainStages)
	analysis.AttackNarratives = DeriveNarratives(analysis.Findings, iocs, analysis.KillChainStages, analysis.CrossPlatformCorrelations)
	analysis.ConversationSummary = conv.Summary()
	analysis.Platforms = platformList(iocs, analysis.Findings)

	if opts.SecretHunt {
		analysis.ConversationSecretHunt = conv.SecretHunt()
	}

	out := filepath.Join(evidenceDir, "analysis_results.json")
	if err := writeJSON(out, analysis); err != nil {
		return analysis, err
	}
	return analysis, nil
}

// platformList returns every platform named by the evidence, in stable order.
func platformList(iocs []model.IOC, findings []model.Finding) []string {
	set := map[string]bool{}
	for _, ioc := range iocs {
		if ioc.Platform != "" {
			set[ioc.Platform] = true
		}
	}
	for _, f := range findings {
		if f.Platform != "" {
			set[f.Platform] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
