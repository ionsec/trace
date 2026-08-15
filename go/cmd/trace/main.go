// Command trace is a self-contained Go binary for TRACE — a
// forensically sound shadow-AI detector and evidence collector that runs
// on Windows, macOS, and Linux without requiring Python.
//
// Subcommands:
//
//	trace run [-o DIR]      — one-shot: discover → deep-collect → HTML+JSON reports
//	trace discover          — list detected shadow-AI tools
//	trace scan              — quick one-line risk summary
//	trace collect -o DIR [--deep]
//	trace report -o DIR     — generate JSON and HTML reports
//	trace --version
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ionsec/trace/go/internal/analyze"
	"github.com/ionsec/trace/go/internal/collect"
	"github.com/ionsec/trace/go/internal/detect"
	"github.com/ionsec/trace/go/internal/iris"
	"github.com/ionsec/trace/go/internal/model"
	"github.com/ionsec/trace/go/internal/report"
	"github.com/ionsec/trace/go/internal/ui"
)

const version = "1.0.1"

// brandColors maps the TRACE brand accent to the banner.
const (
	cRed    = "\x1b[38;5;196m"
	cRedBr  = "\x1b[38;5;203m"
	cWhite  = "\x1b[38;5;231m"
	cGray   = "\x1b[38;5;244m"
	cDim    = "\x1b[38;5;240m"
	cYellow = "\x1b[38;5;220m"
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
)

// banner is the TRACE-branded intro shown on every invocation.
func banner() string {
	if !ui.IsTTY() {
		return `TRACE (Go) v` + version + ` — Tool for Reconnaissance of AI & Compute Evidence
github.com/ionsec/trace
`
	}
	// Clean terminal frame (68-char inner field).
	var b strings.Builder
	const W = 68
	b.WriteString("\n")
	b.WriteString(ui.Red.S("┌"+strings.Repeat("─", W)+"┐") + "\n")
	b.WriteString(ui.Red.S("│"+strings.Repeat(" ", W)+"│") + "\n")
	b.WriteString(ui.Red.S("│") + ui.RedBr.S(bold+center62("TRACE", W)+reset) + ui.Red.S("│") + "\n")
	b.WriteString(ui.Red.S("│") + ui.Gray.S(center62("Tool for Reconnaissance of AI & Compute Evidence", W)) + ui.Red.S("│") + "\n")
	b.WriteString(ui.Red.S("├"+strings.Repeat("─", W)+"┤") + "\n")
	b.WriteString(ui.Red.S("│") + ui.Dim.S(center62("github.com/ionsec/trace", W)) + ui.Red.S("│") + "\n")
	b.WriteString(ui.Red.S("│") + ui.Dim.S(center62("v"+version+"  ·  AGPL-3.0-or-later  ·  Leave no model untraced", W)) + ui.Red.S("│") + "\n")
	b.WriteString(ui.Red.S("│") + ui.Yellow.S(center62("USE AT YOUR OWN RISK — provided AS IS, without warranty", W)) + ui.Red.S("│") + "\n")
	b.WriteString(ui.Red.S("│"+strings.Repeat(" ", W)+"│") + "\n")
	b.WriteString(ui.Red.S("└"+strings.Repeat("─", W)+"┘") + "\n")
	return b.String()
}

// center62 centers a plain string within a width-char field (no ANSI codes).
func center62(s string, width int) string {
	l := len(s)
	if l >= width {
		return s
	}
	pad := (width - l) / 2
	return strings.Repeat(" ", pad) + s + strings.Repeat(" ", width-pad-l)
}

func usage() {
	fmt.Print(banner())
	fmt.Println()
	ui.Header(" COMMANDS ", 68)
	fmt.Println("  " + ui.Style(ui.Red, "run") + "       one-shot: discover → deep collect → HTML+JSON reports")
	fmt.Println("  " + ui.Style(ui.Red, "discover") + "   list detected shadow-AI tools")
	fmt.Println("  " + ui.Style(ui.Red, "scan") + "       quick risk summary (no files written)")
	fmt.Println("  " + ui.Style(ui.Red, "collect") + "   collect forensic artifacts + chain of custody")
	fmt.Println("  " + ui.Style(ui.Red, "analyze") + "   analyze evidence: IOCs, secrets, MITRE, kill chain, risk")
	fmt.Println("  " + ui.Style(ui.Red, "report") + "    generate HTML, JSON and STIX reports")
	fmt.Println("  " + ui.Style(ui.Red, "iris") + "      push evidence to a DFIR-IRIS case")
	fmt.Println("  " + ui.Style(ui.Red, "--version") + "  print version")
	fmt.Println()
	ui.Header(" OPTIONS ", 68)
	fmt.Println("  " + ui.Style(ui.Cyan, "-o, --output DIR") + "     evidence output directory (default: evidence)")
	fmt.Println("  " + ui.Style(ui.Cyan, "-d, --deep") + "            deep collection (session data, larger scope)")
	fmt.Println("  " + ui.Style(ui.Cyan, "--max-files N") + "         per-tool file cap (default: 200)")
	fmt.Println("  " + ui.Style(ui.Cyan, "--format FMT") + "          report format: html|json|stix|all (default: all)")
	fmt.Println("  " + ui.Style(ui.Cyan, "--mitre-atlas") + "         map findings to MITRE ATLAS")
	fmt.Println("  " + ui.Style(ui.Cyan, "--mitre-attack") + "        map findings to MITRE ATT&CK")
	fmt.Println("  " + ui.Style(ui.Cyan, "--risk-score") + "          calculate risk scores")
	fmt.Println("  " + ui.Style(ui.Cyan, "--secret-hunt") + "         scan conversation turns for leaked secrets")
	fmt.Println("  " + ui.Style(ui.Cyan, "--host URL") + "            IRIS server URL (or IRIS_HOST)")
	fmt.Println("  " + ui.Style(ui.Cyan, "--api-key KEY") + "         IRIS API key (or IRIS_API_KEY)")
	fmt.Println("  " + ui.Style(ui.Cyan, "--case-id N") + "           push into an existing IRIS case")
	fmt.Println("  " + ui.Style(ui.Cyan, "--case-name NAME") + "      name of the IRIS case to create")
	fmt.Println()
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "--version", "-v", "version":
		fmt.Print(banner())
		fmt.Println("TRACE (Go), version", version)
	case "run", "all", "everything":
		cmdRun()
	case "discover":
		cmdDiscover()
	case "scan":
		cmdScan()
	case "collect":
		cmdCollect()
	case "analyze":
		cmdAnalyze()
	case "report":
		cmdReport()
	case "iris":
		cmdIRIS()
	case "--help", "-h", "help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ unknown command:")+" "+os.Args[1])
		usage()
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// cmdRun — one-shot: discover → deep collect → HTML+JSON reports
// ---------------------------------------------------------------------------

func cmdRun() {
	evidenceDir := flagValue("o", "evidence")
	if evidenceDir == "" {
		evidenceDir = "evidence"
	}

	fmt.Print(banner())
	ui.Header(" FULL SWEEP ", 68)
	fmt.Println()
	ui.SystemBanner()
	ui.Line(ui.Dim, 68)
	fmt.Println()

	// 1. Discover
	sp := ui.NewSpinner("Scanning for shadow-AI tools")
	detections := detect.Discover()
	sp.Stop()
	ui.Line(ui.Dim, 68)
	fmt.Printf("  %s  %s %d shadow-AI tool(s) detected\n",
		ui.Style(ui.Green, "✓"),
		ui.Style(ui.White, "Discovery:"),
		len(detections))
	for _, d := range detections {
		c := ui.RiskColor(d.Risk)
		loc := d.ConfigPath
		if loc == "" {
			loc = d.Binary
		}
		fmt.Printf("     %s %s %s [%s] %s\n",
			c.S(ui.RiskGlyph(d.Risk)),
			ui.Style(c, d.Tool),
			ui.Dim.S("—"),
			ui.Gray.S(d.Risk),
			ui.Dim.S(loc))
	}
	fmt.Println()

	// 2. Deep collect
	sp = ui.NewSpinner("Deep-collecting forensic artifacts (SHA-256 hashing)")
	coc, err := collect.Collect(evidenceDir, true, collect.Options{MaxFilesPerTool: flagInt("max-files")})
	sp.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ collection failed:")+" "+err.Error())
		os.Exit(1)
	}
	ui.Line(ui.Dim, 68)
	fmt.Printf("  %s  %s %d artifact(s) from %d platform(s)\n",
		ui.Style(ui.Green, "✓"),
		ui.Style(ui.White, "Collection:"),
		len(coc.Files), len(detections))
	fmt.Printf("     %s %s\n", ui.Style(ui.Cyan, "custody:"), ui.Gray.S(evidenceDir+"/CHAIN_OF_CUSTODY.json"))
	if len(coc.Truncations) > 0 {
		fmt.Printf("  %s  %s %d platform(s) truncated (per-tool budget hit)\n",
			ui.Style(ui.Yellow, "⚠"),
			ui.Style(ui.Yellow, "Collection clipped:"),
			len(coc.Truncations))
	}
	fmt.Println()

	// 3. Reports
	sp = ui.NewSpinner("Analyzing evidence (IOCs, secrets, MITRE, risk)")
	analysis, err := analyze.Run(evidenceDir, analyze.AllPasses())
	sp.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ analysis failed:")+" "+err.Error())
		os.Exit(1)
	}
	ui.Line(ui.Dim, 68)
	fmt.Printf("  %s  %s %d IOC(s), %d finding(s), risk %d/100\n",
		ui.Style(ui.Green, "✓"), ui.Style(ui.White, "Analysis:"),
		len(analysis.IOCs), len(analysis.Findings), analysis.RiskScores.Score)
	fmt.Println()

	sp = ui.NewSpinner("Generating HTML, JSON and STIX reports")
	paths, err := report.GenerateAll(evidenceDir, coc, []string{"html", "json", "stix"})
	sp.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ report generation failed:")+" "+err.Error())
		os.Exit(1)
	}
	ui.Line(ui.Dim, 68)
	fmt.Printf("  %s  %s\n", ui.Style(ui.Green, "✓"), ui.Style(ui.White, "Reports generated:"))
	for _, kind := range []string{"html", "json", "stix"} {
		if p, ok := paths[kind]; ok {
			fmt.Printf("     %s %s\n", ui.Style(ui.Cyan, kind+":"), ui.Gray.S(p))
		}
	}
	fmt.Println()
	ui.Line(ui.Red, 68)
	fmt.Printf("  %s  %s %s\n",
		ui.Style(ui.Red, "✦"),
		ui.Style(ui.Red, "Sweep complete."),
		ui.Dim.S("Leave no model untraced."))
	fmt.Println()
}

// ---------------------------------------------------------------------------
// discover
// ---------------------------------------------------------------------------

func cmdDiscover() {
	detections := detect.Discover()
	if len(detections) == 0 {
		fmt.Println(ui.Style(ui.Yellow, "No shadow-AI tools detected on this system."))
		return
	}
	ui.Header(fmt.Sprintf(" %d SHADOW-AI TOOL(S) ", len(detections)), 68)
	fmt.Println()
	ui.SystemBanner()
	ui.Line(ui.Dim, 68)
	fmt.Println()
	for _, d := range detections {
		c := ui.RiskColor(d.Risk)
		loc := d.ConfigPath
		if loc == "" {
			loc = d.Binary
		}
		fmt.Printf("  %s %s %s [%s] %s\n",
			c.S(ui.RiskGlyph(d.Risk)),
			ui.Style(c, d.Tool),
			ui.Dim.S("—"),
			ui.Gray.S(d.Risk),
			ui.Dim.S(loc))
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

func cmdScan() {
	detections := detect.Discover()
	high, medium, low := 0, 0, 0
	for _, d := range detections {
		switch d.Risk {
		case "high", "critical":
			high++
		case "medium":
			medium++
		default:
			low++
		}
	}

	ui.Header(" QUICK SCAN ", 68)
	fmt.Println()
	ui.SystemBanner()
	ui.Line(ui.Dim, 68)
	fmt.Printf("  %s %d AI tool(s) detected\n", ui.Style(ui.White, "Total:"), len(detections))
	fmt.Printf("  %s %s\n", ui.Red.S(ui.RiskGlyph("high")), ui.Style(ui.Orange, fmt.Sprintf("%d high", high)))
	fmt.Printf("  %s %s\n", ui.Yellow.S(ui.RiskGlyph("medium")), ui.Style(ui.Yellow, fmt.Sprintf("%d medium", medium)))
	fmt.Printf("  %s %s\n", ui.Green.S(ui.RiskGlyph("low")), ui.Style(ui.Green, fmt.Sprintf("%d low", low)))
	fmt.Println()
	ui.Line(ui.Dim, 68)
	if high > 0 {
		fmt.Println("  " + ui.Style(ui.Red, "⚠ High-risk shadow AI present — investigate."))
	} else if len(detections) > 0 {
		fmt.Println("  " + ui.Style(ui.Green, "✓ AI tools present but low/medium risk."))
	} else {
		fmt.Println("  " + ui.Style(ui.Green, "✓ No shadow-AI tools detected."))
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// collect
// ---------------------------------------------------------------------------

func cmdCollect() {
	evidenceDir := flagValue("o", "evidence")
	if evidenceDir == "" {
		evidenceDir = "evidence"
	}
	deep := hasFlag("deep")

	sp := ui.NewSpinner("Collecting forensic artifacts (SHA-256 hashing)")
	coc, err := collect.Collect(evidenceDir, deep, collect.Options{MaxFilesPerTool: flagInt("max-files")})
	sp.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ collection failed:")+" "+err.Error())
		os.Exit(1)
	}
	fmt.Printf("  %s %d artifact(s) from %d platform(s)\n",
		ui.Style(ui.Green, "✓"),
		len(coc.Files), len(detect.Discover()))
	fmt.Printf("  %s %s\n", ui.Style(ui.Cyan, "custody:"), ui.Gray.S(evidenceDir+"/CHAIN_OF_CUSTODY.json"))
	if len(coc.Truncations) > 0 {
		fmt.Printf("  %s %d platform(s) truncated (per-tool budget hit)\n",
			ui.Style(ui.Yellow, "⚠"), len(coc.Truncations))
	}
	_ = coc
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

func cmdReport() {
	evidenceDir := flagValue("o", "evidence")
	if evidenceDir == "" {
		evidenceDir = "evidence"
	}

	coc, err := loadCustody(evidenceDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ no evidence found:")+" "+err.Error())
		os.Exit(1)
	}

	formats := []string{"html", "json", "stix"}
	if f := flagValue("format", ""); f != "" && f != "all" {
		formats = []string{f}
	}

	sp := ui.NewSpinner("Generating reports")
	paths, err := report.GenerateAll(evidenceDir, coc, formats)
	sp.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ report generation failed:")+" "+err.Error())
		os.Exit(1)
	}
	for _, kind := range []string{"html", "json", "stix"} {
		if p, ok := paths[kind]; ok {
			fmt.Printf("  %s %s\n", ui.Style(ui.Cyan, kind+":"), ui.Gray.S(p))
		}
	}
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------

func cmdAnalyze() {
	evidenceDir := flagValue("o", "evidence")
	if evidenceDir == "" {
		evidenceDir = "evidence"
	}
	if dir := positionalArg(); dir != "" {
		evidenceDir = dir
	}

	opts := analyze.Options{
		MITREAtlas:  hasFlag("mitre-atlas"),
		MITREAttack: hasFlag("mitre-attack"),
		RiskScore:   hasFlag("risk-score"),
		SecretHunt:  hasFlag("secret-hunt"),
	}
	// With no pass selected, run them all — the useful default for an analyst.
	if !opts.MITREAtlas && !opts.MITREAttack && !opts.RiskScore && !opts.SecretHunt {
		opts = analyze.AllPasses()
	}

	fmt.Printf("%s %s\n", ui.Style(ui.White, "Analyzing evidence from"), ui.Gray.S(evidenceDir))
	sp := ui.NewSpinner("Extracting IOCs, parsing conversations, scoring risk")
	analysis, err := analyze.Run(evidenceDir, opts)
	sp.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ analysis failed:")+" "+err.Error())
		os.Exit(1)
	}

	detected := 0
	for _, s := range analysis.KillChainStages {
		if s.Detected {
			detected++
		}
	}
	fmt.Printf("  %s %d events\n", ui.Style(ui.Green, "Timeline:"), len(analysis.Timeline))
	fmt.Printf("  %s %d indicators\n", ui.Style(ui.Green, "IOCs:"), len(analysis.IOCs))
	fmt.Printf("  %s %d findings\n", ui.Style(ui.Green, "Findings:"), len(analysis.Findings))
	fmt.Printf("  %s %d technique mappings\n", ui.Style(ui.Green, "ATLAS:"), len(analysis.AtlasMapping))
	fmt.Printf("  %s %d techniques\n", ui.Style(ui.Green, "ATT&CK:"), len(analysis.MitreAttack))
	fmt.Printf("  %s %d/%d stages detected\n", ui.Style(ui.Green, "Kill chain:"), detected, len(analysis.KillChainStages))
	fmt.Printf("  %s %d/100 (%s)\n", ui.Style(ui.Green, "Risk score:"), analysis.RiskScores.Score, analysis.RiskScores.Severity)
	fmt.Printf("  %s %d action(s)\n", ui.Style(ui.Green, "Priority actions:"), len(analysis.PriorityActions))
	if h := analysis.ConversationSecretHunt; h != nil {
		fmt.Printf("  %s %d finding(s) across %d turn(s), %d unique\n",
			ui.Style(ui.Green, "Secret hunt:"), h.Total, h.FlaggedTurns, h.UniqueSecrets)
	}
	fmt.Printf("  %s %s\n", ui.Style(ui.Cyan, "results:"), ui.Gray.S(evidenceDir+"/analysis_results.json"))
}

// ---------------------------------------------------------------------------
// iris
// ---------------------------------------------------------------------------

func cmdIRIS() {
	evidenceDir := flagValue("o", "evidence")
	if evidenceDir == "" {
		evidenceDir = "evidence"
	}
	if dir := positionalArg(); dir != "" {
		evidenceDir = dir
	}

	cfg := iris.Config{
		Host:     firstNonEmpty(flagValue("host", ""), os.Getenv("IRIS_HOST")),
		APIKey:   firstNonEmpty(flagValue("api-key", ""), os.Getenv("IRIS_API_KEY")),
		CaseName: firstNonEmpty(flagValue("case-name", ""), "TRACE — AI Evidence Collection"),
		Customer: firstNonEmpty(flagValue("customer", ""), "TRACE"),
		SOCID:    flagValue("soc-id", ""),
		SkipTLS:  hasFlag("insecure"),
		CaseID:   flagInt("case-id"),
	}
	if cfg.Host == "" || cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ IRIS host and API key are required")+" (--host / --api-key, or IRIS_HOST / IRIS_API_KEY)")
		os.Exit(1)
	}

	coc, err := loadCustody(evidenceDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ no evidence found:")+" "+err.Error())
		os.Exit(1)
	}
	analysis, err := report.LoadAnalysis(evidenceDir)
	if err != nil {
		analysis, err = analyze.Run(evidenceDir, analyze.AllPasses())
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ analysis failed:")+" "+err.Error())
			os.Exit(1)
		}
	}

	sp := ui.NewSpinner("Pushing evidence to DFIR-IRIS")
	result, err := iris.Push(cfg, coc, analysis)
	sp.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Style(ui.Red, "✖ IRIS push failed:")+" "+err.Error())
		os.Exit(1)
	}
	fmt.Printf("  %s %d\n", ui.Style(ui.Green, "case id:"), result.CaseID)
	fmt.Printf("  %s %d\n", ui.Style(ui.Green, "iocs pushed:"), result.IOCsPushed)
	fmt.Printf("  %s %d\n", ui.Style(ui.Green, "assets pushed:"), result.AssetsPushed)
	fmt.Printf("  %s %d\n", ui.Style(ui.Green, "timeline events:"), result.EventsPushed)
	fmt.Printf("  %s %d\n", ui.Style(ui.Green, "notes:"), result.NotesPushed)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func loadCustody(dir string) (model.ChainOfCustody, error) {
	var coc model.ChainOfCustody
	data, err := os.ReadFile(strings.TrimSuffix(dir, "/") + "/CHAIN_OF_CUSTODY.json")
	if err != nil {
		return coc, err
	}
	if err := json.Unmarshal(data, &coc); err != nil {
		return coc, err
	}
	return coc, nil
}

// flagValue returns the value for a flag like "-o value" / "--output value".
func flagValue(flag, def string) string {
	args := os.Args[2:]
	for i, a := range args {
		if a == "-"+flag || a == "--"+flag {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return def
}

// hasFlag reports whether a boolean flag is present.
func hasFlag(flag string) bool {
	for _, a := range os.Args[2:] {
		if a == "-"+flag || a == "--"+flag {
			return true
		}
	}
	return false
}

// positionalArg returns the first non-flag argument after the command name,
// so `trace analyze /path/to/evidence` works like the Python CLI.
func positionalArg() string {
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			// Skip the value of a value-taking flag.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && takesValue(a) {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

// takesValue reports whether a flag consumes the next argument.
func takesValue(flag string) bool {
	switch strings.TrimLeft(flag, "-") {
	case "o", "output", "format", "host", "api-key", "case-id", "case-name", "customer", "soc-id":
		return true
	}
	return false
}

// flagInt returns an integer flag value, or 0 when absent or unparseable.
func flagInt(flag string) int {
	v := flagValue(flag, "")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
