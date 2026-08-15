"""
TRACE — Tool for Reconnaissance of AI & Compute Evidence
Forensically sound AI harness artifact collection and analysis.

USE AT YOUR OWN RISK. Provided AS IS, without warranty of any kind.
"""

import json
import os
from pathlib import Path

import click
from rich.console import Console

console = Console()

VERSION = "1.0.1"

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique catalog (AI/ML-relevant subset)
# ---------------------------------------------------------------------------

MITRE_ATTACK_TECHNIQUES = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1039": {"name": "Data from Network Shared Drive", "tactic": "Collection"},
    "T1114": {"name": "Email Collection", "tactic": "Collection"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1565": {"name": "Data Manipulation", "tactic": "Impact"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1119": {"name": "Automated Collection", "tactic": "Collection"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T1200": {"name": "Hardware Additions", "tactic": "Initial Access"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1590": {"name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
}

ATLAS_TO_ATTACK = {
    "AML.T0010": ["T1190", "T1059"],
    "AML.T0011": ["T1190", "T1059"],
    "AML.T0025": ["T1565", "T1078"],
    "AML.T0043": ["T1203"],
    "AML.T0048": ["T1071", "T1105"],
    "AML.T0049": ["T1059", "T1548"],
    "AML.T0050": ["T1048", "T1567"],
    "AML.T0052": ["T1087", "T1083"],
    "AML.T0054": ["T1486"],
    "AML.T0055": ["T1552"],
}

KILL_CHAIN_STAGES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives",
]


BANNER = """\
[bold red]
### ####### #     #  #####  #######  #####
 #  #     # ##    # #     # #       #     #
 #  #     # # #   # #       #       #
 #  #     # #  #  #  #####  #####   #
 #  #     # #   # #       # #       #
 #  #     # #    ## #     # #       #     #
### ####### #     #  #####  #######  #####
[/bold red]
[bold]TRACE — Tool for Reconnaissance of AI & Compute Evidence[/bold]
[dim]github.com/ionsec/trace[/dim]
[dim]v{VERSION} · AGPL-3.0-or-later · Leave no model untraced.[/dim]
[yellow]USE AT YOUR OWN RISK — provided AS IS, without warranty.[/yellow]
"""


@click.group()
@click.version_option(version=VERSION, prog_name="TRACE")
def main():
    """TRACE — Tool for Reconnaissance of AI & Compute Evidence."""
    console.print(BANNER.format(VERSION=VERSION))


@main.command()
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def discover(verbose):
    """Discover AI tools installed on this system."""
    from ionsec_trace.collector import discover_all
    results = discover_all(verbose=verbose)
    if not results:
        console.print("[yellow]No AI platforms detected.[/yellow]")
        return
    console.print(f"[bold green]Discovered {len(results)} AI platform(s):[/bold green]")
    for r in results:
        console.print(f"  • {r}")


@main.command()
@click.option("--output", "-o", required=True, help="Output directory for evidence")
@click.option("--platforms", "-p", default="", help="Comma-separated platform list (empty=all)")
@click.option("--hash/--no-hash", default=True, help="SHA-256 hash collected files")
@click.option("--chain-of-custody/--no-chain-of-custody", default=True, help="Generate chain of custody manifest")
@click.option("--deep", is_flag=True, help="Deep collection including session history")
def collect(output, platforms, hash, chain_of_custody, deep):
    """Collect AI forensic evidence from this system."""
    from ionsec_trace.collector import collect_all
    collect_all(
        output_dir=output,
        platforms=platforms.split(",") if platforms else None,
        do_hash=hash,
        chain_of_custody=chain_of_custody,
        deep=deep,
    )


def _derive_attack_mapping(findings, iocs, atlas_mapping):
    """Derive MITRE ATT&CK technique mappings from findings, IOCs, and ATLAS data."""
    attack_map = {}

    for entry in atlas_mapping:
        if not isinstance(entry, dict):
            continue
        tid = entry.get("technique_id", "")
        for attack_id in ATLAS_TO_ATTACK.get(tid, []):
            if attack_id not in attack_map:
                info = MITRE_ATTACK_TECHNIQUES.get(attack_id, {"name": attack_id, "tactic": "Unknown"})
                attack_map[attack_id] = {
                    "technique_id": attack_id,
                    "technique_name": info["name"],
                    "tactic": info["tactic"],
                    "count": 0,
                    "evidence": [],
                    "source_atlas": tid,
                }
            attack_map[attack_id]["count"] += 1
            attack_map[attack_id]["evidence"].append(f"ATLAS {tid}: {entry.get('technique_name', tid)}")

    f_text = " ".join(f.get("title", "") + " " + f.get("description", "") for f in findings).lower()
    keyword_to_attack = {
        "credential": ("T1552", "Unsecured Credentials found in findings"),
        "api key": ("T1552", "API key exposure in findings"),
        "token": ("T1552", "Token exposure in findings"),
        "password": ("T1078", "Password-related finding"),
        "exfil": ("T1048", "Exfiltration evidence in findings"),
        "data leak": ("T1567", "Data leak evidence in findings"),
        "injection": ("T1190", "Injection-based exploitation"),
        "jailbreak": ("T1190", "Jailbreak indicates exploitation of public-facing service"),
        "command": ("T1059", "Command execution evidence"),
        "script": ("T1059", "Script execution evidence"),
        "network": ("T1071", "Network communication evidence"),
        "scan": ("T1595", "Active scanning evidence"),
        "discover": ("T1087", "Discovery evidence"),
    }
    for kw, (attack_id, evidence_note) in keyword_to_attack.items():
        if kw in f_text and attack_id not in attack_map:
            info = MITRE_ATTACK_TECHNIQUES.get(attack_id, {"name": attack_id, "tactic": "Unknown"})
            attack_map[attack_id] = {
                "technique_id": attack_id,
                "technique_name": info["name"],
                "tactic": info["tactic"],
                "count": 0,
                "evidence": [evidence_note],
                "source_atlas": "",
            }
        elif kw in f_text and attack_id in attack_map:
            attack_map[attack_id]["count"] += 1

    ioc_types = {i.get("ioc_type", i.get("type", "")).lower() for i in iocs}
    if "api_key" in ioc_types and "T1552" not in attack_map:
        attack_map["T1552"] = {
            "technique_id": "T1552", "technique_name": "Unsecured Credentials",
            "tactic": "Credential Access", "count": 1, "evidence": ["API key IOC detected"],
            "source_atlas": "AML.T0055",
        }
    if "exfil_pattern" in ioc_types and "T1048" not in attack_map:
        attack_map["T1048"] = {
            "technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration", "count": 1, "evidence": ["Exfiltration pattern IOC detected"],
            "source_atlas": "AML.T0050",
        }

    return sorted(attack_map.values(), key=lambda x: -x["count"])


def _derive_kill_chain(findings, iocs, atlas_mapping):
    """Derive kill chain stage presence from findings, IOCs, and ATLAS mappings."""
    stages = {s: {"detected": False, "evidence": []} for s in KILL_CHAIN_STAGES}

    for ioc in iocs:
        ioc_type = ioc.get("ioc_type", ioc.get("type", "")).lower()
        str(ioc.get("value", ioc.get("ioc", ""))).lower()
        if ioc_type in ("ip", "domain", "url"):
            stages["Reconnaissance"]["detected"] = True
            stages["Reconnaissance"]["evidence"].append(f"Network indicator: {ioc.get('value', ioc.get('ioc', ''))}")
        if ioc_type == "command":
            stages["Weaponization"]["detected"] = True
            stages["Weaponization"]["evidence"].append(f"Command: {ioc.get('value', ioc.get('ioc', ''))}")
        if ioc_type in ("url", "domain"):
            stages["Delivery"]["detected"] = True
            stages["Delivery"]["evidence"].append(f"Delivery vector: {ioc.get('value', ioc.get('ioc', ''))}")
        if ioc_type == "api_key":
            stages["Exploitation"]["detected"] = True
            stages["Exploitation"]["evidence"].append(f"Exposed credential: {str(ioc.get('value', ''))[:20]}...")
        if ioc_type == "exfil_pattern":
            stages["Actions on Objectives"]["detected"] = True
            stages["Actions on Objectives"]["evidence"].append(f"Exfiltration: {ioc.get('value', ioc.get('ioc', ''))}")

    f_text_all = " ".join(f.get("title", "") + " " + f.get("description", "") for f in findings).lower()
    if any(kw in f_text_all for kw in ("recon", "discover", "scan", "enumerate")):
        stages["Reconnaissance"]["detected"] = True
    if any(kw in f_text_all for kw in ("weaponiz", "payload", "exploit", "adversarial input")):
        stages["Weaponization"]["detected"] = True
    if any(kw in f_text_all for kw in ("phishing", "delivery", "social engineer", "drive-by")):
        stages["Delivery"]["detected"] = True
    if any(kw in f_text_all for kw in ("exploit", "vulnerability", "injection", "bypass", "jailbreak")):
        stages["Exploitation"]["detected"] = True
    if any(kw in f_text_all for kw in ("install", "persist", "backdoor", "implant")):
        stages["Installation"]["detected"] = True
    if any(kw in f_text_all for kw in ("c2", "command and control", "beacon", "callback")):
        stages["Command & Control"]["detected"] = True
    if any(kw in f_text_all for kw in ("exfiltrat", "data leak", "impact", "destruction", "ransom")):
        stages["Actions on Objectives"]["detected"] = True

    for entry in atlas_mapping:
        if isinstance(entry, dict):
            tid = entry.get("technique_id", "")
            if tid in ATLAS_TO_ATTACK:
                stages["Exploitation"]["detected"] = True
                stages["Exploitation"]["evidence"].append(f"ATLAS {tid} detected")

    return [{"stage": k, "detected": v["detected"], "evidence": v["evidence"]} for k, v in stages.items()]


def _derive_priority_actions(findings, iocs, risk_scores, kill_chain):
    """Derive top priority actions from all available data."""
    actions = []
    risk_scores.get("score", 0) if isinstance(risk_scores, dict) else 0

    cred_iocs = [i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() == "api_key"]
    cred_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("credential", "api key", "token", "secret", "password"))]
    if cred_iocs or cred_findings:
        n_cred = len(cred_iocs) + len(cred_findings)
        platforms = {i.get("platform", "unknown") for i in cred_iocs} | {f.get("platform", "unknown") for f in cred_findings}
        actions.append({
            "urgency": "CRITICAL",
            "action": f"Rotate exposed API keys and credentials — {n_cred} credential(s) found across {len(platforms)} platform(s)",
            "evidence": [f"Credential exposure: {c.get('value', c.get('ioc', ''))[:30]}..." for c in cred_iocs[:3]] + [f.get("title", "") for f in cred_findings[:2]],
            "category": "credentials",
        })

    exfil_iocs = [i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() == "exfil_pattern"]
    exfil_findings = [f for f in findings if "exfil" in (f.get("title", "") + " " + f.get("description", "")).lower()]
    if exfil_iocs or exfil_findings:
        actions.append({
            "urgency": "CRITICAL",
            "action": f"Investigate active data exfiltration — {len(exfil_iocs) + len(exfil_findings)} exfiltration indicator(s) detected",
            "evidence": [f.get("title", "") for f in exfil_findings[:3]],
            "category": "exfiltration",
        })

    jail_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("jailbreak", "injection", "bypass"))]
    if jail_findings:
        actions.append({
            "urgency": "HIGH",
            "action": f"Harden AI safety guardrails — {len(jail_findings)} jailbreak/injection attempt(s) detected",
            "evidence": [f.get("title", "") for f in jail_findings[:3]],
            "category": "jailbreak",
        })

    net_iocs = [i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() in ("ip", "url", "domain")]
    if net_iocs and len(net_iocs) > 3:
        actions.append({
            "urgency": "HIGH",
            "action": f"Block suspicious network indicators — {len(net_iocs)} suspicious IP/URL/domain IOC(s) detected",
            "evidence": [f"{i.get('ioc_type', i.get('type', ''))}: {i.get('value', i.get('ioc', ''))}" for i in net_iocs[:3]],
            "category": "network",
        })

    agent_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("autonomous", "agent", "tool chain", "self-directed"))]
    if agent_findings:
        actions.append({
            "urgency": "MEDIUM",
            "action": f"Implement human-in-the-loop controls — {len(agent_findings)} autonomous agent behavior(s) detected",
            "evidence": [f.get("title", "") for f in agent_findings[:3]],
            "category": "autonomy",
        })

    detected_stages = [s for s in kill_chain if s.get("detected")]
    if len(detected_stages) >= 3:
        actions.append({
            "urgency": "CRITICAL",
            "action": f"Multi-stage attack chain detected — {len(detected_stages)} of 7 kill chain stages present, conduct full incident response",
            "evidence": [s["stage"] for s in detected_stages],
            "category": "kill_chain",
        })

    if not actions:
        actions.append({
            "urgency": "LOW",
            "action": "Continue routine monitoring — no critical or high-priority actions identified",
            "evidence": [],
            "category": "monitoring",
        })

    return actions[:5]


def _derive_cross_platform_correlations(iocs, findings, platforms):
    """Find IOCs and findings that appear across multiple platforms."""
    correlations = []
    ioc_groups = {}
    for ioc in iocs:
        key = (ioc.get("ioc_type", ioc.get("type", "")).lower(), str(ioc.get("value", ioc.get("ioc", ""))))
        plat = ioc.get("platform", "unknown")
        if key not in ioc_groups:
            ioc_groups[key] = set()
        ioc_groups[key].add(plat)

    for (ioc_type, ioc_val), plat_set in ioc_groups.items():
        if len(plat_set) > 1:
            correlations.append({
                "indicator": f"{ioc_type}: {ioc_val[:60]}",
                "type": ioc_type,
                "platforms": sorted(plat_set),
                "platform_count": len(plat_set),
                "correlation_type": "shared_indicator",
                "severity": "high",
            })

    sev_platforms = {}
    for f in findings:
        sev = f.get("severity", "info")
        plat = f.get("platform", "unknown")
        if sev not in sev_platforms:
            sev_platforms[sev] = set()
        sev_platforms[sev].add(plat)

    for sev, plat_set in sev_platforms.items():
        if len(plat_set) > 1:
            correlations.append({
                "indicator": f"{sev.title()}-severity findings across platforms",
                "type": "severity_correlation",
                "platforms": sorted(plat_set),
                "platform_count": len(plat_set),
                "correlation_type": "severity_pattern",
                "severity": sev,
            })

    return correlations


def _derive_conversation_summary(custody_data, timeline, iocs):
    """Derive conversation forensics summary from available data."""
    # Check for conversation data in custody
    conversations = custody_data.get("conversation_sessions", []) if isinstance(custody_data, dict) else []
    if not conversations and isinstance(timeline, list):
        conv_sessions = []
        for platform in {str(e.get("platform", "unknown")) for e in timeline if isinstance(e, dict)}:
            plat_events = [e for e in timeline if isinstance(e, dict) and e.get("platform") == platform]
            conv_sessions.append({
                "platform": platform,
                "session_id": f"session-{platform}",
                "turns": len(plat_events),
                "user_turns": len([e for e in plat_events if "user" in (e.get("description", "") + e.get("artifact_type", "")).lower()]),
                "assistant_turns": len([e for e in plat_events if "assistant" in (e.get("description", "") + e.get("artifact_type", "")).lower()]),
                "jailbreak_attempts": 0,
                "tool_calls": 0,
                "risk_assessment": "info",
            })
        conversations = conv_sessions

    return {
        "total_sessions": len(conversations),
        "sessions": conversations,
        "jailbreak_attempts_total": sum(s.get("jailbreak_attempts", 0) for s in conversations),
        "tool_calls_total": sum(s.get("tool_calls", 0) for s in conversations),
    }


def _derive_enhanced_risk(risk_scores, findings, iocs):
    """Build 8-category enhanced risk breakdown."""
    cat_scores = risk_scores.get("category_scores", {}) if isinstance(risk_scores, dict) else {}
    if isinstance(cat_scores, dict):
        # Map the 4 existing categories + add 4 more
        enhanced = {}
        for cat in ("credentials", "exfiltration", "jailbreak", "autonomy"):
            score = cat_scores.get(cat, 0)
            enhanced[cat] = {"score": score, "confidence": "high" if score > 0 else "low"}
    else:
        enhanced = {}

    # Add additional risk categories
    f_text = " ".join(f.get("title", "") + " " + f.get("description", "") for f in findings).lower()
    {i.get("ioc_type", i.get("type", "")).lower() for i in iocs}

    # Network exposure
    net_score = min(25, 5 * len([i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() in ("ip", "url", "domain")]))
    enhanced["network_exposure"] = {"score": net_score, "confidence": "medium" if net_score > 0 else "low"}

    # Supply chain
    supply_score = 15 if any(kw in f_text for kw in ("model", "dependency", "package", "plugin")) else 0
    enhanced["supply_chain"] = {"score": supply_score, "confidence": "medium" if supply_score > 0 else "low"}

    # Data integrity
    integrity_score = 10 if any(kw in f_text for kw in ("tamper", "modify", "integrity", "hash")) else 0
    enhanced["data_integrity"] = {"score": integrity_score, "confidence": "low"}

    # Compliance
    compliance_score = 5 if "credential" in f_text or "api_key" in f_text or "api key" in f_text else 0
    enhanced["compliance"] = {"score": compliance_score, "confidence": "low"}

    return enhanced


@main.command()
@click.argument("evidence_dir")
@click.option("--mitre-atlas", is_flag=True, help="Map findings to MITRE ATLAS")
@click.option("--mitre-attack", is_flag=True, help="Map findings to MITRE ATT&CK")
@click.option("--risk-score", is_flag=True, help="Calculate risk scores")
@click.option("--secret-hunt", is_flag=True, help="Scan conversation turns for leaked secrets")
@click.option("--export-conversations", "export_conv", is_flag=True, help="Export conversation history to CSV + manifest")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def analyze(evidence_dir, mitre_atlas, mitre_attack, risk_score, secret_hunt, export_conv, verbose):
    """Analyze collected AI forensic evidence."""
    from ionsec_trace.analyzer import ATLASMapper, IOCExtractor, RiskScorer, UnifiedTimeline

    console.print(f"[bold]Analyzing evidence from {evidence_dir}[/bold]")

    # Build timeline
    timeline = UnifiedTimeline(evidence_dir)
    timeline.load()
    events = timeline.events
    console.print(f"  [green]Timeline:[/green] {len(events)} events")

    # Extract IOCs
    ioc_extractor = IOCExtractor(evidence_dir)
    ioc_extractor.extract()
    iocs = ioc_extractor.iocs
    console.print(f"  [green]IOCs:[/green] {len(iocs)} indicators found")
    if iocs:
        ioc_types = {}
        for ioc in iocs:
            ioc_types[ioc.ioc_type] = ioc_types.get(ioc.ioc_type, 0) + 1
        for ioc_type, count in sorted(ioc_types.items(), key=lambda x: -x[1]):
            console.print(f"    {ioc_type}: {count}")

    # MITRE ATLAS mapping
    atlas_mapping = []
    if mitre_atlas:
        mapper = ATLASMapper()
        atlas_mapping = mapper.map_iocs(iocs)
        console.print(f"  [green]ATLAS mappings:[/green] {len(atlas_mapping)} technique mappings")
        for mapping in atlas_mapping[:10]:
            console.print(f"    {mapping.technique_id}: {mapping.technique_name}")

    # Risk scoring
    risk = None
    if risk_score:
        scorer = RiskScorer()
        risk = scorer.calculate_overall_risk([], iocs)
        console.print(f"  [green]Overall Risk Score:[/green] {risk.score}/100 ({risk.severity})")
        for category, score in risk.category_scores.items():
            console.print(f"    {category}: {score}/25")

    # Load custody data for enriched analysis
    results_path = Path(evidence_dir) / "analysis_results.json"
    custody_path = Path(evidence_dir) / "CHAIN_OF_CUSTODY.json"
    custody_data = {}
    if custody_path.exists():
        try:
            with open(custody_path, encoding="utf-8") as fh:
                custody_data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass

    # Get findings
    findings = custody_data.get("findings", [])

    # Build IOC dicts for analysis
    ioc_dicts = [
        {
            "ioc_type": i.ioc_type,
            "value": i.value,
            "context": i.context,
            "platform": i.platform,
            "source_file": i.source_file,
            "severity": str(i.severity) if hasattr(i.severity, '__str__') else "info",
        }
        for i in iocs
    ]

    # Build timeline dicts
    timeline_dicts = [
        {
            "timestamp": e.timestamp if hasattr(e, 'timestamp') else str(e),
            "platform": e.platform if hasattr(e, 'platform') else "unknown",
            "artifact_type": e.artifact_type if hasattr(e, 'artifact_type') else "unknown",
            "description": e.description if hasattr(e, 'description') else str(e),
            "severity": str(e.severity.value) if hasattr(e, 'severity') and hasattr(e.severity, 'value') else (str(e.severity) if hasattr(e, 'severity') else "info"),
            "source_path": e.source_path if hasattr(e, 'source_path') else "",
            "user": e.user if hasattr(e, 'user') else None,
            "is_collection_event": e.is_collection_event if hasattr(e, 'is_collection_event') else False,
            "content_preview": e.content_preview if hasattr(e, 'content_preview') else "",
        }
        for e in events
    ]

    # Build ATLAS dicts
    atlas_dicts = [
        {
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "description": m.description,
            "platforms": m.platforms,
        }
        for m in atlas_mapping
    ] if mitre_atlas else []

    # Risk scores dict
    risk_dicts = {}
    if risk:
        risk_dicts = {
            "score": risk.score,
            "severity": str(risk.severity),
            "category_scores": risk.category_scores,
        }

    # Derive new DFIR-grade analysis data
    mitre_attack_mappings = _derive_attack_mapping(findings, ioc_dicts, atlas_dicts) if (mitre_atlas or mitre_attack) else []
    kill_chain = _derive_kill_chain(findings, ioc_dicts, atlas_dicts)
    priority_actions = _derive_priority_actions(findings, ioc_dicts, risk_dicts, kill_chain)
    cross_platform_correlations = _derive_cross_platform_correlations(
        ioc_dicts, findings,
        list({getattr(i, 'platform', 'unknown') for i in iocs})
    )
    conversation_summary = _derive_conversation_summary(custody_data, timeline_dicts, ioc_dicts)
    enhanced_risk = _derive_enhanced_risk(risk_dicts, findings, ioc_dicts)

    # AI-specific IOC detection (enhanced analysis)
    ai_indicators = []
    ai_indicator_dicts = []
    attack_narratives = []
    try:
        from ionsec_trace.analyzer.ai_ioc_detector import AIIOCDetector
        from ionsec_trace.analyzer.enhanced_risk_scorer import EnhancedRiskScorer
        ai_detector = AIIOCDetector(evidence_dir)
        ai_detector.detect()
        ai_indicators = ai_detector.indicators[:500]  # Cap for performance
        ai_indicator_dicts = [
            {"indicator_type": ind.indicator_type, "severity": str(ind.severity),
             "value": ind.value[:80] if ind.value else "", "context": ind.context[:100] if ind.context else "",
             "platform": ind.platform, "source_file": ind.source_file,
             "confidence": float(ind.confidence), "attack_phase": ind.attack_phase,
             "mitre_atlas": ind.mitre_atlas, "mitre_attack": ind.mitre_attack,
             "recommendation": ind.recommendation}
            for ind in ai_indicators
        ]
        # Cross-platform correlations from detector
        detector_correlations = ai_detector.cross_reference()
        if detector_correlations:
            # Merge with existing correlations
            for c in detector_correlations:
                if isinstance(c, dict):
                    cross_platform_correlations.append(c)
                elif isinstance(c, str):
                    cross_platform_correlations.append({"type": "cross_platform", "description": c, "platforms": []})

        # Enhanced risk scoring
        enhanced_scorer = EnhancedRiskScorer()
        enhanced_risk_result = enhanced_scorer.score_from_indicators(
            ai_detector.findings[:200], ai_detector.indicators[:200]
        )
        # Override the basic enhanced_risk dict with the actual enhanced risk scorer result
        enhanced_risk = {
            "score": enhanced_risk_result.score,
            "severity": enhanced_risk_result.severity,
            "categories": enhanced_risk_result.categories,
            "confidence": float(enhanced_risk_result.confidence),
            "kill_chain_stages": enhanced_risk_result.kill_chain_stages,
        }
        attack_narratives = [
            {"narrative_id": n.narrative_id, "title": n.title,
             "kill_chain_stages": n.kill_chain_stages, "platforms": n.platforms,
             "severity": str(n.severity), "confidence": float(n.confidence),
             "recommendation": n.recommendation}
            for n in enhanced_risk_result.narratives
        ]
        priority_actions = [
            pa if isinstance(pa, dict) else {"action": pa, "urgency": "MEDIUM", "evidence": []}
            for pa in enhanced_risk_result.priority_actions
        ]
        kill_chain = [
            {"stage": s, "detected": True, "evidence": []}
            for s in KILL_CHAIN_STAGES if s in enhanced_risk_result.kill_chain_stages
        ] + [
            {"stage": s, "detected": False, "evidence": []}
            for s in KILL_CHAIN_STAGES if s not in enhanced_risk_result.kill_chain_stages
        ]
        # Merge ATT&CK techniques from AI indicators
        ai_attack_ids = set()
        for ind in ai_indicators:
            for tid in ind.mitre_attack:
                ai_attack_ids.add(tid)
        for tid in ai_attack_ids:
            if tid not in {m.get("technique_id") for m in mitre_attack_mappings}:
                info = MITRE_ATTACK_TECHNIQUES.get(tid, {"name": tid, "tactic": "Unknown"})
                mitre_attack_mappings.append({
                    "technique_id": tid, "technique_name": info["name"],
                    "tactic": info["tactic"], "count": 1, "evidence": [f"AI-specific indicator: {tid}"],
                })

        console.print(f"  [green]AI-specific indicators:[/green] {len(ai_detector.indicators)}")
        console.print(f"  [green]AI indicator types:[/green] {dict(ai_detector.summary_by_type())}")
        console.print(f"  [green]Enhanced risk:[/green] {enhanced_risk_result.score}/100 ({enhanced_risk_result.severity})")
        console.print(f"  [green]Kill chain:[/green] {len(enhanced_risk_result.kill_chain_stages)}/{len(KILL_CHAIN_STAGES)} stages")
        console.print(f"  [green]Attack narratives:[/green] {len(attack_narratives)}")
        console.print(f"  [green]Priority actions:[/green] {len(priority_actions)}")
    except Exception as e:
        console.print(f"  [yellow]AI-specific analysis skipped:[/yellow] {e}")

    # Write all analysis results
    results = {
        "timeline": timeline_dicts,
        "iocs": ioc_dicts,
        "atlas_mapping": atlas_dicts,
        "risk_scores": risk_dicts,
        "platforms": list({getattr(i, 'platform', 'unknown') for i in iocs}),
        # New DFIR-grade fields
        "attack_narratives": attack_narratives,
        "kill_chain_stages": kill_chain,
        "mitre_attack": mitre_attack_mappings,
        "priority_actions": priority_actions,
        "cross_platform_correlations": cross_platform_correlations,
        "conversation_summary": conversation_summary,
        "enhanced_risk": enhanced_risk,
        "ai_indicators": ai_indicator_dicts,
    }

    # Conversation secret hunt (optional)
    if secret_hunt:
        try:
            from ionsec_trace.analyzer import ConversationParser, ConversationSecretHunt
            parser = ConversationParser.from_evidence_dir(evidence_dir)
            hunt = ConversationSecretHunt()
            hunt_result = hunt.scan_parser(parser)
            results["conversation_secret_hunt"] = hunt_result.to_dict()
            console.print(f"  [green]Conversation secret hunt:[/green] {hunt_result.total} finding(s) "
                          f"across {hunt_result.flagged_turns} turn(s), {hunt_result.unique_secrets} unique secret(s)")
            for sev, count in hunt_result.by_severity.items():
                if count:
                    console.print(f"    {sev}: {count}")
        except Exception as e:
            console.print(f"  [yellow]Conversation secret hunt skipped:[/yellow] {e}")

    # Conversation export (optional)
    if export_conv:
        try:
            from ionsec_trace.analyzer import ConversationParser, export_conversation_package
            parser = ConversationParser.from_evidence_dir(evidence_dir)
            export_paths = export_conversation_package(parser, evidence_dir)
            results["conversation_export"] = export_paths
            console.print(f"  [green]Conversation export:[/green] {len(parser.turns)} turns")
            for kind, path in export_paths.items():
                console.print(f"    {kind}: {path}")
        except Exception as e:
            console.print(f"  [yellow]Conversation export skipped:[/yellow] {e}")

    results_path.write_text(json.dumps(results, indent=2, default=str))
    console.print(f"  [green]Analysis results written to:[/green] {results_path}")
    console.print(f"  [green]Kill chain:[/green] {sum(1 for s in kill_chain if s.get('detected'))}/{len(kill_chain)} stages detected")
    console.print(f"  [green]ATT&CK mappings:[/green] {len(mitre_attack_mappings)} techniques")
    console.print(f"  [green]Priority actions:[/green] {len(priority_actions)}")
    console.print(f"  [green]Cross-platform correlations:[/green] {len(cross_platform_correlations)}")


@main.command()
@click.argument("evidence_dir")
@click.option("--format", "fmt", type=click.Choice(["html", "json", "stix", "all"]), default="all", help="Report format")
def report(evidence_dir, fmt):
    """Generate forensic report from analyzed evidence."""
    from ionsec_trace.reporter import generate_all
    formats = ["html", "json", "stix"] if fmt == "all" else [fmt]
    results = generate_all(evidence_dir, formats=formats)
    for fmt_name, path in results.items():
        console.print(f"  [green]{fmt_name}[/green]: {path}")


@main.command()
def scan():
    """Quick scan — discover + risk score, no file collection."""
    from ionsec_trace.collector import discover_all
    results = discover_all(verbose=False)
    console.print("[bold]Quick Scan Results:[/bold]")
    console.print(f"  AI platforms detected: {len(results)}")
    for r in results:
        console.print(f"  • {r}")


# ---------------------------------------------------------------------------
# DFIR-IRIS integration
# ---------------------------------------------------------------------------

def _iris_host_api_key(host, apikey):
    """Resolve IRIS host/api key from CLI args or environment."""
    host = host or os.environ.get("IRIS_HOST")
    apikey = apikey or os.environ.get("IRIS_API_KEY")
    if not host:
        raise click.ClickException(
            "IRIS host is required. Pass --host or set IRIS_HOST."
        )
    if not apikey:
        raise click.ClickException(
            "IRIS API key is required. Pass --api-key or set IRIS_API_KEY."
        )
    return host, apikey


@main.group()
def iris():
    """Push TRACE evidence to a DFIR-IRIS case."""


@iris.command("push")
@click.argument("evidence_dir")
@click.option("--host", envvar="IRIS_HOST", help="IRIS server URL (or IRIS_HOST env)")
@click.option("--api-key", "apikey", envvar="IRIS_API_KEY", help="IRIS API key (or IRIS_API_KEY env)")
@click.option("--case-id", "case_id", type=int, default=None, help="Push into an existing case instead of creating one")
@click.option("--case-name", default="TRACE — AI Evidence Collection", help="Name of the case to create")
@click.option("--customer", default="TRACE", help="Customer name for the case (created if missing)")
@click.option("--classification", default="not-classified", help="IRIS case classification")
@click.option("--soc-id", default="", help="SOC ticket reference for the case")
@click.option("--no-create-customer", is_flag=True, help="Do not auto-create the customer")
@click.option("--no-evidence-files", is_flag=True, help="Do not upload collected files to Datastore")
@click.option("--no-timeline", is_flag=True, help="Do not push timeline events")
@click.option("--insecure", is_flag=True, help="Skip TLS certificate verification")
def iris_push(evidence_dir, host, apikey, case_id, case_name, customer,
              classification, soc_id, no_create_customer, no_evidence_files,
              no_timeline, insecure):
    """Push collected TRACE evidence into a DFIR-IRIS case."""
    from ionsec_trace.integration.iris import push_to_iris

    host, apikey = _iris_host_api_key(host, apikey)

    console.print(f"[bold]Pushing TRACE evidence from {evidence_dir} to IRIS {host}[/bold]")
    try:
        result = push_to_iris(
            evidence_dir=evidence_dir,
            host=host,
            apikey=apikey,
            case_id=case_id,
            case_name=case_name,
            customer=customer,
            classification=classification,
            soc_id=soc_id,
            create_customer=not no_create_customer,
            push_evidence_files=not no_evidence_files,
            push_timeline=not no_timeline,
            ssl_verify=not insecure,
        )
    except Exception as exc:
        console.print(f"[bold red]IRIS push failed:[/bold red] {exc}")
        raise SystemExit(1) from exc

    console.print(f"  [green]Case:[/green] {result['case_id']} "
                  f"({'created' if result['created_case'] else 'existing'})")
    for key, val in result["summary"].items():
        console.print(f"  {key.replace('_', ' ').title()}: {val}")
    console.print(f"  [green]Steps OK:[/green] {result['ok_count']}/{result['total_count']}")

    if result["errors"]:
        console.print("[yellow]Partial failures:[/yellow]")
        for err in result["errors"]:
            console.print(f"  [yellow]  {err['item']}: {err['error']}[/yellow]")
        raise SystemExit(1)


@iris.command("check")
@click.option("--host", envvar="IRIS_HOST", help="IRIS server URL (or IRIS_HOST env)")
@click.option("--api-key", "apikey", envvar="IRIS_API_KEY", help="IRIS API key (or IRIS_API_KEY env)")
@click.option("--insecure", is_flag=True, help="Skip TLS certificate verification")
def iris_check(host, apikey, insecure):
    """Verify connectivity and API key against a DFIR-IRIS instance."""
    from ionsec_trace.integration.iris import IrisIntegration

    host, apikey = _iris_host_api_key(host, apikey)

    console.print(f"[bold]Checking IRIS connectivity: {host}[/bold]")
    integration = IrisIntegration(host=host, apikey=apikey, ssl_verify=not insecure)
    try:
        status = integration.check()
    except Exception as exc:
        console.print(f"[bold red]IRIS check failed:[/bold red] {exc}")
        raise SystemExit(1) from exc

    console.print(f"  [green]Connected:[/green] {status['host']}")
    console.print(f"  [green]Agent:[/green] {status['agent']}")
    console.print(f"  [green]Visible cases:[/green] {status['case_count']}")


if __name__ == "__main__":
    main()
