package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ionsec/trace/go/internal/model"
)

// MapATLAS maps extracted indicators to MITRE ATLAS techniques.
func MapATLAS(iocs []model.IOC) []model.AtlasMapping {
	var out []model.AtlasMapping
	add := func(tid, evidence, platform, severity string) {
		info := AtlasTechniques[tid]
		out = append(out, model.AtlasMapping{
			TechniqueID:   tid,
			TechniqueName: info.Name,
			Tactic:        info.Tactic,
			Evidence:      evidence,
			Platform:      platform,
			Confidence:    confidenceForSeverity(severity),
		})
	}

	for _, ioc := range iocs {
		switch ioc.IOCType {
		case "api_key":
			add("AML.T0055", "API key detected: "+truncate(ioc.Value, 12)+"...", ioc.Platform, ioc.Severity)
		case "exfil_pattern":
			add("AML.T0050", "Exfiltration pattern: "+truncate(ioc.Value, 60), ioc.Platform, ioc.Severity)
		case "command":
			add("AML.T0049", "Suspicious command: "+truncate(ioc.Value, 60), ioc.Platform, ioc.Severity)
		case "ip", "url", "domain":
			add("AML.T0048", "Network indicator ("+ioc.IOCType+"): "+truncate(ioc.Value, 60), ioc.Platform, ioc.Severity)
		case "filepath":
			low := strings.ToLower(ioc.Value)
			for _, kw := range []string{"model", "weight", "checkpoint", ".bin", ".safetensors", ".gguf"} {
				if strings.Contains(low, kw) {
					add("AML.T0025", "Model file path: "+truncate(ioc.Value, 60), ioc.Platform, ioc.Severity)
					break
				}
			}
		}
	}
	return out
}

// confidenceForSeverity expresses how much weight to give a mapping.
func confidenceForSeverity(severity string) string {
	switch severity {
	case "critical", "high":
		return "high"
	case "medium":
		return "medium"
	}
	return "low"
}

// findingsText joins every finding's title and description for keyword tests.
func findingsText(findings []model.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(f.Title)
		b.WriteByte(' ')
		b.WriteString(f.Description)
		b.WriteByte(' ')
	}
	return strings.ToLower(b.String())
}

// containsAnyWord reports whether text contains any of the keywords.
func containsAnyWord(text string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

// DeriveAttack builds the MITRE ATT&CK view from ATLAS mappings, finding text
// and indicator types.
func DeriveAttack(findings []model.Finding, iocs []model.IOC, atlas []model.AtlasMapping) []model.AttackTechnique {
	byID := map[string]*model.AttackTechnique{}
	ensure := func(id string, evidence ...string) *model.AttackTechnique {
		t, ok := byID[id]
		if !ok {
			info := AttackTechniques[id]
			name, tactic := info.Name, info.Tactic
			if name == "" {
				name, tactic = id, "Unknown"
			}
			t = &model.AttackTechnique{TechniqueID: id, TechniqueName: name, Tactic: tactic}
			byID[id] = t
		}
		t.Evidence = append(t.Evidence, evidence...)
		return t
	}

	for _, entry := range atlas {
		for _, attackID := range AtlasToAttack[entry.TechniqueID] {
			t := ensure(attackID, "ATLAS "+entry.TechniqueID+": "+entry.TechniqueName)
			t.Count++
		}
	}

	text := findingsText(findings)
	keywordToAttack := []struct{ keyword, id, evidence string }{
		{"credential", "T1552", "Unsecured Credentials found in findings"},
		{"api key", "T1552", "API key exposure in findings"},
		{"token", "T1552", "Token exposure in findings"},
		{"password", "T1078", "Password-related finding"},
		{"exfil", "T1048", "Exfiltration evidence in findings"},
		{"data leak", "T1567", "Data leak evidence in findings"},
		{"injection", "T1190", "Injection-based exploitation"},
		{"jailbreak", "T1190", "Jailbreak indicates exploitation of public-facing service"},
		{"command", "T1059", "Command execution evidence"},
		{"script", "T1059", "Script execution evidence"},
		{"network", "T1071", "Network communication evidence"},
		{"scan", "T1595", "Active scanning evidence"},
		{"discover", "T1087", "Discovery evidence"},
	}
	for _, k := range keywordToAttack {
		if !strings.Contains(text, k.keyword) {
			continue
		}
		if _, exists := byID[k.id]; exists {
			byID[k.id].Count++
			continue
		}
		ensure(k.id, k.evidence)
	}

	iocTypes := map[string]bool{}
	for _, ioc := range iocs {
		iocTypes[strings.ToLower(ioc.IOCType)] = true
	}
	if iocTypes["api_key"] {
		if _, ok := byID["T1552"]; !ok {
			ensure("T1552", "API key IOC detected").Count = 1
		}
	}
	if iocTypes["exfil_pattern"] {
		if _, ok := byID["T1048"]; !ok {
			ensure("T1048", "Exfiltration pattern IOC detected").Count = 1
		}
	}

	out := make([]model.AttackTechnique, 0, len(byID))
	for _, t := range byID {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].TechniqueID < out[j].TechniqueID
	})
	return out
}

// DeriveKillChain reconstructs which intrusion stages the evidence supports.
func DeriveKillChain(findings []model.Finding, iocs []model.IOC, atlas []model.AtlasMapping) []model.KillChainStage {
	stages := map[string]*model.KillChainStage{}
	for _, name := range KillChainStages {
		stages[name] = &model.KillChainStage{Stage: name}
	}
	mark := func(stage, evidence string) {
		s := stages[stage]
		if s == nil {
			return
		}
		s.Detected = true
		if evidence != "" {
			s.Evidence = append(s.Evidence, evidence)
		}
	}

	for _, ioc := range iocs {
		switch strings.ToLower(ioc.IOCType) {
		case "ip", "domain", "url":
			mark("Reconnaissance", "Network indicator: "+ioc.Value)
			if ioc.IOCType != "ip" {
				mark("Delivery", "Delivery vector: "+ioc.Value)
			}
		case "command":
			mark("Weaponization", "Command: "+ioc.Value)
		case "api_key":
			mark("Exploitation", "Exposed credential: "+truncate(ioc.Value, 20)+"...")
		case "exfil_pattern":
			mark("Actions on Objectives", "Exfiltration: "+ioc.Value)
		}
	}

	text := findingsText(findings)
	keywordStages := []struct {
		stage    string
		keywords []string
	}{
		{"Reconnaissance", []string{"recon", "discover", "scan", "enumerate"}},
		{"Weaponization", []string{"weaponiz", "payload", "exploit", "adversarial input"}},
		{"Delivery", []string{"phishing", "delivery", "social engineer", "drive-by"}},
		{"Exploitation", []string{"exploit", "vulnerability", "injection", "bypass", "jailbreak"}},
		{"Installation", []string{"install", "persist", "backdoor", "implant"}},
		{"Command & Control", []string{"c2", "command and control", "beacon", "callback"}},
		{"Actions on Objectives", []string{"exfiltrat", "data leak", "impact", "destruction", "ransom"}},
	}
	for _, ks := range keywordStages {
		if containsAnyWord(text, ks.keywords) {
			mark(ks.stage, "")
		}
	}

	for _, entry := range atlas {
		if _, ok := AtlasToAttack[entry.TechniqueID]; ok {
			mark("Exploitation", "ATLAS "+entry.TechniqueID+" detected")
		}
	}

	out := make([]model.KillChainStage, 0, len(KillChainStages))
	for _, name := range KillChainStages {
		out = append(out, *stages[name])
	}
	return out
}

// ScoreRisk produces the 0-100 overall risk score and its four category
// components, mirroring the Python RiskScorer.
func ScoreRisk(findings []model.Finding, iocs []model.IOC) model.RiskScores {
	text := findingsText(findings)
	iocTypes := map[string]bool{}
	var vals strings.Builder
	for _, ioc := range iocs {
		iocTypes[ioc.IOCType] = true
		vals.WriteString(strings.ToLower(ioc.Value))
		vals.WriteByte(' ')
	}
	iocVals := vals.String()

	cap25 := func(n int) int {
		if n > 25 {
			return 25
		}
		return n
	}

	credentials := 0
	if iocTypes["api_key"] {
		credentials += credentialIndicators["api_key_exposed"]
	}
	if containsAnyWord(text, []string{"credential", "api key", "token", "secret"}) {
		credentials += credentialIndicators["credential_in_config"]
	}
	if containsAnyWord(text, []string{"log", "history"}) && containsAnyWord(iocVals, []string{"sk-", "ghp_", "key-"}) {
		credentials += credentialIndicators["credential_in_log"]
	}
	if containsAnyWord(text, []string{"shared", "reuse", "duplicate"}) {
		credentials += credentialIndicators["shared_credential"]
	}
	if containsAnyWord(text, []string{"hardcod", "plaintext", "insecure storage"}) {
		credentials += credentialIndicators["hardcoded_secret"]
	}
	if containsAnyWord(iocVals, []string{"bearer ", "token=", "session="}) {
		credentials += credentialIndicators["token_leak"]
	}
	for _, f := range findings {
		if f.Severity == model.SeverityCritical && containsAnyWord(strings.ToLower(f.Title), []string{"credential", "key", "token"}) {
			credentials += 3
		}
	}

	exfiltration := 0
	if iocTypes["exfil_pattern"] {
		exfiltration += exfiltrationIndicators["base64_encode"]
	}
	if containsAnyWord(iocVals, []string{"base64", "encode"}) {
		exfiltration += exfiltrationIndicators["base64_encode"]
	}
	if containsAnyWord(iocVals, []string{"| nc", "| curl", "| wget", "| ssh"}) {
		exfiltration += exfiltrationIndicators["pipe_to_network"]
	}
	if containsAnyWord(iocVals, []string{"curl", "upload"}) {
		exfiltration += exfiltrationIndicators["curl_upload"]
	}
	if containsAnyWord(iocVals, []string{"scp ", "rsync"}) {
		exfiltration += exfiltrationIndicators["scp_outbound"]
	}
	if containsAnyWord(iocVals, []string{"dig", "nslookup"}) {
		exfiltration += exfiltrationIndicators["dns_exfil"]
	}
	if containsAnyWord(text, []string{"exfiltrat", "data leak", "send data"}) {
		exfiltration += exfiltrationIndicators["sensitive_file_read"]
	}
	if containsAnyWord(iocVals, []string{"env", "printenv", "export"}) {
		exfiltration += exfiltrationIndicators["env_dump"]
	}

	jailbreak := 0
	if containsAnyWord(text, []string{"jailbreak", "bypass safety", "safety bypass"}) {
		jailbreak += jailbreakIndicators["jailbreak_prompt"]
	}
	if containsAnyWord(text, []string{"prompt injection", "inject", "ignore previous"}) {
		jailbreak += jailbreakIndicators["prompt_injection"]
	}
	if containsAnyWord(text, []string{"roleplay", "pretend", "simulate", "dan "}) {
		jailbreak += jailbreakIndicators["roleplay_escape"]
	}
	if containsAnyWord(text, []string{"base64", "unicode", "encoding attack", "obfuscat"}) {
		jailbreak += jailbreakIndicators["encoding_attack"]
	}
	if containsAnyWord(text, []string{"system prompt", "instruction extract", "reveal instructions"}) {
		jailbreak += jailbreakIndicators["system_prompt_extract"]
	}
	for _, f := range findings {
		title := strings.ToLower(f.Title)
		if !containsAnyWord(title, []string{"jailbreak", "injection", "bypass"}) {
			continue
		}
		switch f.Severity {
		case model.SeverityCritical:
			jailbreak += 5
		case model.SeverityHigh:
			jailbreak += 3
		}
	}

	autonomy := 0
	if containsAnyWord(text, []string{"autonomous", "auto-exec", "without approval", "self-directed"}) {
		autonomy += autonomyIndicators["agent_autonomous_exec"]
	}
	if containsAnyWord(text, []string{"tool chain", "chained", "sequential tool"}) {
		autonomy += autonomyIndicators["tool_chain"]
	}
	if containsAnyWord(text, []string{"file write", "created file", "modified file"}) {
		autonomy += autonomyIndicators["file_write"]
	}
	if containsAnyWord(text, []string{"code execution", "executed code", "ran command", "subprocess"}) {
		autonomy += autonomyIndicators["code_execution"]
	}
	if containsAnyWord(text, []string{"network", "http request", "api call", "outbound"}) {
		autonomy += autonomyIndicators["network_access"]
	}
	if containsAnyWord(text, []string{"privilege", "escalat", "root", "sudo"}) {
		autonomy += autonomyIndicators["privilege_escalation"]
	}
	if containsAnyWord(text, []string{"persistent", "daemon", "background", "long-running"}) {
		autonomy += autonomyIndicators["persistent_agent"]
	}
	if iocTypes["command"] {
		autonomy += 3
	}
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			autonomy += 2
		}
	}

	categories := map[string]float64{
		"credentials":  float64(cap25(credentials)),
		"exfiltration": float64(cap25(exfiltration)),
		"jailbreak":    float64(cap25(jailbreak)),
		"autonomy":     float64(cap25(autonomy)),
	}
	total := 0
	for _, v := range categories {
		total += int(v)
	}
	if total > 100 {
		total = 100
	}

	return model.RiskScores{
		Score:          total,
		Severity:       SeverityFromScore(total),
		CategoryScores: categories,
	}
}

// SeverityFromScore labels a 0-100 risk score.
func SeverityFromScore(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	}
	return "info"
}

// DeriveEnhancedRisk expands the four base categories into the eight-category
// breakdown the report shows.
func DeriveEnhancedRisk(risk model.RiskScores, findings []model.Finding, iocs []model.IOC) model.EnhancedRisk {
	categories := map[string]float64{}
	for _, cat := range []string{"credentials", "exfiltration", "jailbreak", "autonomy"} {
		categories[cat] = risk.CategoryScores[cat]
	}

	text := findingsText(findings)
	netCount := 0
	for _, ioc := range iocs {
		switch strings.ToLower(ioc.IOCType) {
		case "ip", "url", "domain":
			netCount++
		}
	}
	netScore := 5 * netCount
	if netScore > 25 {
		netScore = 25
	}
	categories["network_exposure"] = float64(netScore)

	categories["supply_chain"] = 0
	if containsAnyWord(text, []string{"model", "dependency", "package", "plugin"}) {
		categories["supply_chain"] = 15
	}
	categories["data_integrity"] = 0
	if containsAnyWord(text, []string{"tamper", "modify", "integrity", "hash"}) {
		categories["data_integrity"] = 10
	}
	categories["compliance"] = 0
	if containsAnyWord(text, []string{"credential", "api_key", "api key"}) {
		categories["compliance"] = 5
	}

	return model.EnhancedRisk{
		Score:      risk.Score,
		Severity:   risk.Severity,
		Categories: categories,
	}
}

// DerivePriorityActions ranks the remediation steps an analyst should take
// first, most urgent last-in-wins order preserved from the Python build.
func DerivePriorityActions(findings []model.Finding, iocs []model.IOC, killChain []model.KillChainStage) []model.PriorityAction {
	var actions []model.PriorityAction

	matching := func(keywords []string) []model.Finding {
		var out []model.Finding
		for _, f := range findings {
			if containsAnyWord(strings.ToLower(f.Title+" "+f.Description), keywords) {
				out = append(out, f)
			}
		}
		return out
	}
	iocsOfType := func(types ...string) []model.IOC {
		var out []model.IOC
		for _, ioc := range iocs {
			for _, t := range types {
				if strings.EqualFold(ioc.IOCType, t) {
					out = append(out, ioc)
					break
				}
			}
		}
		return out
	}
	titles := func(fs []model.Finding, n int) []string {
		var out []string
		for i, f := range fs {
			if i >= n {
				break
			}
			out = append(out, f.Title)
		}
		return out
	}

	credIOCs := iocsOfType("api_key")
	credFindings := matching([]string{"credential", "api key", "token", "secret", "password"})
	if len(credIOCs) > 0 || len(credFindings) > 0 {
		platforms := map[string]bool{}
		var evidence []string
		for i, c := range credIOCs {
			platforms[c.Platform] = true
			if i < 3 {
				evidence = append(evidence, "Credential exposure: "+truncate(c.Value, 30)+"...")
			}
		}
		for _, f := range credFindings {
			platforms[f.Platform] = true
		}
		evidence = append(evidence, titles(credFindings, 2)...)
		actions = append(actions, model.PriorityAction{
			Urgency: "CRITICAL",
			Action: fmt.Sprintf("Rotate exposed API keys and credentials — %d credential(s) found across %d platform(s)",
				len(credIOCs)+len(credFindings), len(platforms)),
			Evidence: evidence,
		})
	}

	exfilIOCs := iocsOfType("exfil_pattern")
	exfilFindings := matching([]string{"exfil"})
	if len(exfilIOCs) > 0 || len(exfilFindings) > 0 {
		actions = append(actions, model.PriorityAction{
			Urgency: "CRITICAL",
			Action: fmt.Sprintf("Investigate active data exfiltration — %d exfiltration indicator(s) detected",
				len(exfilIOCs)+len(exfilFindings)),
			Evidence: titles(exfilFindings, 3),
		})
	}

	jailFindings := matching([]string{"jailbreak", "injection", "bypass"})
	if len(jailFindings) > 0 {
		actions = append(actions, model.PriorityAction{
			Urgency:  "HIGH",
			Action:   fmt.Sprintf("Harden AI safety guardrails — %d jailbreak/injection attempt(s) detected", len(jailFindings)),
			Evidence: titles(jailFindings, 3),
		})
	}

	netIOCs := iocsOfType("ip", "url", "domain")
	if len(netIOCs) > 3 {
		var evidence []string
		for i, ioc := range netIOCs {
			if i >= 3 {
				break
			}
			evidence = append(evidence, ioc.IOCType+": "+ioc.Value)
		}
		actions = append(actions, model.PriorityAction{
			Urgency:  "HIGH",
			Action:   fmt.Sprintf("Block suspicious network indicators — %d suspicious IP/URL/domain IOC(s) detected", len(netIOCs)),
			Evidence: evidence,
		})
	}

	agentFindings := matching([]string{"autonomous", "agent", "tool chain", "self-directed"})
	if len(agentFindings) > 0 {
		actions = append(actions, model.PriorityAction{
			Urgency:  "MEDIUM",
			Action:   fmt.Sprintf("Implement human-in-the-loop controls — %d autonomous agent behavior(s) detected", len(agentFindings)),
			Evidence: titles(agentFindings, 3),
		})
	}

	var detected []string
	for _, s := range killChain {
		if s.Detected {
			detected = append(detected, s.Stage)
		}
	}
	if len(detected) >= 3 {
		actions = append(actions, model.PriorityAction{
			Urgency: "CRITICAL",
			Action: fmt.Sprintf("Multi-stage attack chain detected — %d of %d kill chain stages present, conduct full incident response",
				len(detected), len(KillChainStages)),
			Evidence: detected,
		})
	}

	if len(actions) == 0 {
		actions = append(actions, model.PriorityAction{
			Urgency: "LOW",
			Action:  "Continue routine monitoring — no critical or high-priority actions identified",
		})
	}
	if len(actions) > 5 {
		actions = actions[:5]
	}
	return actions
}

// DeriveCorrelations finds indicators and severities that span platforms.
func DeriveCorrelations(iocs []model.IOC, findings []model.Finding) []model.Correlation {
	var out []model.Correlation

	type group struct {
		iocType   string
		value     string
		platforms map[string]bool
	}
	groups := map[string]*group{}
	var order []string
	for _, ioc := range iocs {
		key := strings.ToLower(ioc.IOCType) + "\x00" + ioc.Value
		g, ok := groups[key]
		if !ok {
			g = &group{iocType: strings.ToLower(ioc.IOCType), value: ioc.Value, platforms: map[string]bool{}}
			groups[key] = g
			order = append(order, key)
		}
		g.platforms[ioc.Platform] = true
	}
	for _, key := range order {
		g := groups[key]
		if len(g.platforms) <= 1 {
			continue
		}
		out = append(out, model.Correlation{
			Indicator:       g.iocType + ": " + truncate(g.value, 60),
			CorrelationType: "shared_indicator",
			Platforms:       sortedKeys(g.platforms),
			Severity:        "high",
		})
	}

	sevPlatforms := map[string]map[string]bool{}
	var sevOrder []string
	for _, f := range findings {
		sev := string(f.Severity)
		if sev == "" {
			sev = "info"
		}
		if _, ok := sevPlatforms[sev]; !ok {
			sevPlatforms[sev] = map[string]bool{}
			sevOrder = append(sevOrder, sev)
		}
		sevPlatforms[sev][f.Platform] = true
	}
	for _, sev := range sevOrder {
		platforms := sevPlatforms[sev]
		if len(platforms) <= 1 {
			continue
		}
		out = append(out, model.Correlation{
			Indicator:       strings.ToUpper(sev[:1]) + sev[1:] + "-severity findings across platforms",
			CorrelationType: "severity_pattern",
			Platforms:       sortedKeys(platforms),
			Severity:        sev,
		})
	}
	return out
}

// sortedKeys returns a set's members in stable order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DeriveNarratives assembles the human-readable attack stories shown in the
// report, one per corroborated pattern.
func DeriveNarratives(findings []model.Finding, iocs []model.IOC, killChain []model.KillChainStage, correlations []model.Correlation) []model.Narrative {
	var out []model.Narrative

	platformsOf := func(fs []model.Finding) []string {
		set := map[string]bool{}
		for _, f := range fs {
			set[f.Platform] = true
		}
		return sortedKeys(set)
	}
	matching := func(keywords []string) []model.Finding {
		var res []model.Finding
		for _, f := range findings {
			if containsAnyWord(strings.ToLower(f.Title+" "+f.Description), keywords) {
				res = append(res, f)
			}
		}
		return res
	}
	stageDetected := func(name string) bool {
		for _, s := range killChain {
			if s.Stage == name && s.Detected {
				return true
			}
		}
		return false
	}

	credFindings := matching([]string{"credential", "api key", "token", "secret"})
	var credIOCs []string
	for _, ioc := range iocs {
		if ioc.IOCType == "api_key" && len(credIOCs) < 3 {
			credIOCs = append(credIOCs, ioc.Redacted())
		}
	}
	if len(credFindings) > 0 || len(credIOCs) > 0 {
		out = append(out, model.Narrative{
			Title:             "Credential exposure across AI tooling",
			Severity:          "critical",
			Confidence:        confidenceFromCount(len(credFindings) + len(credIOCs)),
			AffectedPlatforms: platformsOf(credFindings),
			KillChainStages:   detectedStages(killChain, "Exploitation", "Credential Access"),
			Recommendation:    "Revoke every exposed key at the provider, move to secrets-manager-backed injection, and audit provider logs for use from unexpected source addresses.",
			IOCRefs:           credIOCs,
		})
	}

	jailFindings := matching([]string{"jailbreak", "injection", "bypass", "system prompt"})
	if len(jailFindings) > 0 {
		out = append(out, model.Narrative{
			Title:             "Guardrail bypass activity in conversation transcripts",
			Severity:          "high",
			Confidence:        confidenceFromCount(len(jailFindings)),
			AffectedPlatforms: platformsOf(jailFindings),
			KillChainStages:   detectedStages(killChain, "Exploitation"),
			Recommendation:    "Preserve the transcripts as evidence, interview the user, and enforce an approved-agent policy with tool allow-lists and central session logging.",
			EvidenceRefs:      evidenceRefs(jailFindings, 3),
		})
	}

	if stageDetected("Command & Control") || stageDetected("Actions on Objectives") {
		exfilFindings := matching([]string{"exfil", "network", "outbound", "upload"})
		out = append(out, model.Narrative{
			Title:             "Data movement off the endpoint via AI tooling",
			Severity:          "high",
			Confidence:        confidenceFromCount(len(exfilFindings)),
			AffectedPlatforms: platformsOf(exfilFindings),
			KillChainStages:   detectedStages(killChain, "Command & Control", "Actions on Objectives"),
			Recommendation:    "Reconstruct what left the endpoint from the timeline, then close the egress path and rotate anything the transferred data exposed.",
			EvidenceRefs:      evidenceRefs(exfilFindings, 3),
		})
	}

	if len(correlations) > 0 {
		set := map[string]bool{}
		for _, c := range correlations {
			for _, p := range c.Platforms {
				set[p] = true
			}
		}
		out = append(out, model.Narrative{
			Title:             "Shared indicators link multiple AI platforms",
			Severity:          "medium",
			Confidence:        confidenceFromCount(len(correlations)),
			AffectedPlatforms: sortedKeys(set),
			KillChainStages:   detectedStages(killChain),
			Recommendation:    "Treat the correlated platforms as one incident scope: the same credential or endpoint appears in more than one tool.",
		})
	}

	return out
}

// detectedStages returns the requested stages that were detected, or every
// detected stage when no names are given.
func detectedStages(killChain []model.KillChainStage, names ...string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []string
	for _, s := range killChain {
		if !s.Detected {
			continue
		}
		if len(want) == 0 || want[s.Stage] {
			out = append(out, s.Stage)
		}
	}
	return out
}

// evidenceRefs collects up to n evidence paths from findings.
func evidenceRefs(findings []model.Finding, n int) []string {
	var out []string
	for _, f := range findings {
		for _, e := range f.Evidence {
			if len(out) >= n {
				return out
			}
			out = append(out, e)
		}
	}
	return out
}

// confidenceFromCount expresses how much corroboration a narrative has.
func confidenceFromCount(n int) string {
	switch {
	case n >= 5:
		return "high"
	case n >= 2:
		return "medium"
	}
	return "low"
}
