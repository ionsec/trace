"""
TRACE HTML Report Generator.

Generates a self-contained forensic HTML report from the chain-of-custody
evidence directory with TRACE branding (dark terminal-green theme).

DFIR-grade output includes: executive summary, attack narratives,
MITRE ATT&CK mapping, kill chain analysis, priority actions,
cross-platform correlation, and conversation forensics.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import BaseLoader, Environment

from ionsec_trace.collector.base import (
    Finding,
    Severity,
)

# Severity palette — kept in sync with the --danger/--high/--warning/--info CSS
# custom properties in _HTML_TEMPLATE.
SEV_COLORS = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffaa00",
    "low": "#00aaff",
    "info": "#8a8a9e",
}

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

# Mapping from ATLAS technique IDs to ATT&CK technique IDs
ATLAS_TO_ATTACK = {
    "AML.T0010": ["T1190", "T1059"],  # Prompt Injection -> Exploit Public-Facing App, Command Interpreter
    "AML.T0011": ["T1190", "T1059"],  # LLM Jailbreak
    "AML.T0025": ["T1565", "T1078"],   # Modify Model -> Data Manipulation, Valid Accounts
    "AML.T0043": ["T1203"],            # Craft Adversarial Input -> Client Execution
    "AML.T0048": ["T1071", "T1105"],   # AI Tool Integration -> App Layer Protocol, Transfer
    "AML.T0049": ["T1059", "T1548"],   # Exploit AI Tool Integration -> Scripting, Abuse Elevation
    "AML.T0050": ["T1048", "T1567"],   # LLM Data Exfiltration -> Exfil Over Alt Protocol, Web Service
    "AML.T0052": ["T1087", "T1083"],   # LLM Prompt Leak -> Account Discovery, File Discovery
    "AML.T0054": ["T1486"],            # AI-Generated Content -> Data Encrypted for Impact
    "AML.T0055": ["T1552"],            # LLM Credential Theft -> Unsecured Credentials
}

# Kill chain stages
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]


# ---------------------------------------------------------------------------
# Kill chain heuristic — map findings/IOCs to kill chain stages
# ---------------------------------------------------------------------------

def _heuristic_kill_chain(findings: list[dict], iocs: list[dict], atlas_mapping: list[dict]) -> list[dict]:
    """Derive kill chain stage presence from findings, IOCs, and ATLAS mappings."""
    stages: dict[str, dict] = {s: {"detected": False, "evidence": []} for s in KILL_CHAIN_STAGES}

    # IOC-based detection
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

    # Finding-based detection
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

    # ATLAS mapping -> infer stages
    for entry in atlas_mapping:
        tid = entry.get("technique_id", "") if isinstance(entry, dict) else str(entry)
        if tid in ATLAS_TO_ATTACK:
            stages["Exploitation"]["detected"] = True
            stages["Exploitation"]["evidence"].append(f"ATLAS {tid} detected")

    return [{"stage": k, "detected": v["detected"], "evidence": v["evidence"]} for k, v in stages.items()]


def _derive_attack_mapping(findings: list[dict], iocs: list[dict], atlas_mapping: list[dict]) -> list[dict]:
    """Derive MITRE ATT&CK technique mappings from findings, IOCs, and ATLAS data."""
    attack_map: dict[str, dict] = {}

    # From ATLAS mapping — map through the cross-reference table
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

    # From finding keywords
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

    # From IOC types
    ioc_types = {ioc.get("ioc_type", ioc.get("type", "")).lower() for ioc in iocs}
    if "api_key" in ioc_types and "T1552" not in attack_map:
        attack_map["T1552"] = {
            "technique_id": "T1552", "technique_name": "Unsecured Credentials",
            "tactic": "Credential Access", "count": 1, "evidence": ["API key IOC detected"], "source_atlas": "AML.T0055",
        }
    if "exfil_pattern" in ioc_types and "T1048" not in attack_map:
        attack_map["T1048"] = {
            "technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration", "count": 1, "evidence": ["Exfiltration pattern IOC detected"], "source_atlas": "AML.T0050",
        }

    return sorted(attack_map.values(), key=lambda x: -x["count"])


def _derive_priority_actions(
    findings: list[dict],
    iocs: list[dict],
    risk_scores: dict,
    kill_chain: list[dict],
) -> list[dict]:
    """Derive top priority actions from all available data."""
    actions: list[dict] = []
    risk_scores.get("score", 0) if isinstance(risk_scores, dict) else 0
    risk_scores.get("category_scores", {}) if isinstance(risk_scores, dict) else {}

    # Credential rotation
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

    # Exfiltration response
    exfil_iocs = [i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() == "exfil_pattern"]
    exfil_findings = [f for f in findings if "exfil" in (f.get("title", "") + " " + f.get("description", "")).lower()]
    if exfil_iocs or exfil_findings:
        actions.append({
            "urgency": "CRITICAL",
            "action": f"Investigate active data exfiltration — {len(exfil_iocs) + len(exfil_findings)} exfiltration indicator(s) detected",
            "evidence": [f.get("title", "") for f in exfil_findings[:3]],
            "category": "exfiltration",
        })

    # Jailbreak response
    jail_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("jailbreak", "injection", "bypass"))]
    if jail_findings:
        actions.append({
            "urgency": "HIGH",
            "action": f"Harden AI safety guardrails — {len(jail_findings)} jailbreak/injection attempt(s) detected",
            "evidence": [f.get("title", "") for f in jail_findings[:3]],
            "category": "jailbreak",
        })

    # Network containment
    net_iocs = [i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() in ("ip", "url", "domain")]
    if net_iocs and len(net_iocs) > 3:
        actions.append({
            "urgency": "HIGH",
            "action": f"Block suspicious network indicators — {len(net_iocs)} suspicious IP/URL/domain IOC(s) detected",
            "evidence": [f"{i.get('ioc_type', i.get('type', ''))}: {i.get('value', i.get('ioc', ''))}" for i in net_iocs[:3]],
            "category": "network",
        })

    # Agent autonomy controls
    agent_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("autonomous", "agent", "tool chain", "self-directed"))]
    if agent_findings:
        actions.append({
            "urgency": "MEDIUM",
            "action": f"Implement human-in-the-loop controls — {len(agent_findings)} autonomous agent behavior(s) detected",
            "evidence": [f.get("title", "") for f in agent_findings[:3]],
            "category": "autonomy",
        })

    # Kill chain gap
    detected_stages = [s for s in kill_chain if s["detected"]]
    if len(detected_stages) >= 3:
        actions.append({
            "urgency": "CRITICAL",
            "action": f"Multi-stage attack chain detected — {len(detected_stages)} of 7 kill chain stages present, conduct full incident response",
            "evidence": [s["stage"] for s in detected_stages],
            "category": "kill_chain",
        })

    # General monitoring
    if not actions:
        actions.append({
            "urgency": "LOW",
            "action": "Continue routine monitoring — no critical or high-priority actions identified",
            "evidence": [],
            "category": "monitoring",
        })

    return actions[:5]


def _derive_attack_narratives(
    findings: list[dict],
    iocs: list[dict],
    kill_chain: list[dict],
    risk_scores: dict,
) -> list[dict]:
    """Derive attack narratives from findings, IOCs, and kill chain analysis."""
    narratives: list[dict] = []
    risk_scores.get("score", 0) if isinstance(risk_scores, dict) else 0

    # Credential exposure narrative
    cred_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("credential", "api key", "token", "secret"))]
    cred_iocs = [i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() == "api_key"]
    if cred_findings or cred_iocs:
        platforms = list({f.get("platform", "unknown") for f in cred_findings} | {i.get("platform", "unknown") for i in cred_iocs})
        sev = "critical" if len(cred_iocs) > 0 else "high"
        narratives.append({
            "title": "Credential Exposure",
            "severity": sev,
            "confidence": "high" if cred_iocs else "medium",
            "kill_chain_stages": ["Reconnaissance", "Exploitation"],
            "timeline": [f.get("timestamp", "") for f in cred_findings if f.get("timestamp")] or ["Unknown"],
            "affected_platforms": platforms[:5],
            "recommendation": "Rotate all exposed credentials immediately. Implement secrets scanning in CI/CD pipelines. Use a secrets manager for all API keys and tokens.",
            "evidence_refs": [f.get("id", "") for f in cred_findings[:5]],
            "ioc_refs": [i.get("value", i.get("ioc", ""))[:40] for i in cred_iocs[:5]],
        })

    # Jailbreak/injection narrative
    jail_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("jailbreak", "injection", "bypass", "prompt"))]
    if jail_findings:
        platforms = list({f.get("platform", "unknown") for f in jail_findings})
        narratives.append({
            "title": "AI Safety Bypass Attempts",
            "severity": "critical" if any(f.get("severity") == "critical" for f in jail_findings) else "high",
            "confidence": "high",
            "kill_chain_stages": ["Weaponization", "Delivery", "Exploitation"],
            "timeline": [f.get("timestamp", "") for f in jail_findings if f.get("timestamp")] or ["Unknown"],
            "affected_platforms": platforms[:5],
            "recommendation": "Strengthen input sanitization and safety guardrails. Review prompt handling and implement injection detection. Monitor for recurring attack patterns.",
            "evidence_refs": [f.get("id", "") for f in jail_findings[:5]],
            "ioc_refs": [],
        })

    # Data exfiltration narrative
    exfil_findings = [f for f in findings if "exfil" in (f.get("title", "") + " " + f.get("description", "")).lower()]
    exfil_iocs = [i for i in iocs if i.get("ioc_type", i.get("type", "")).lower() == "exfil_pattern"]
    if exfil_findings or exfil_iocs:
        platforms = list({f.get("platform", "unknown") for f in exfil_findings} | {i.get("platform", "unknown") for i in exfil_iocs})
        narratives.append({
            "title": "Data Exfiltration Risk",
            "severity": "critical" if exfil_iocs else "high",
            "confidence": "high" if exfil_iocs else "medium",
            "kill_chain_stages": ["Collection", "Exfiltration", "Actions on Objectives"],
            "timeline": [f.get("timestamp", "") for f in exfil_findings if f.get("timestamp")] or ["Unknown"],
            "affected_platforms": platforms[:5],
            "recommendation": "Investigate active data exfiltration paths. Implement network egress controls. Monitor outbound traffic from AI platform hosts.",
            "evidence_refs": [f.get("id", "") for f in exfil_findings[:5]],
            "ioc_refs": [i.get("value", i.get("ioc", ""))[:40] for i in exfil_iocs[:5]],
        })

    # Agent autonomy narrative
    agent_findings = [f for f in findings if any(kw in (f.get("title", "") + " " + f.get("description", "")).lower() for kw in ("autonomous", "agent", "tool", "self-directed"))]
    if agent_findings:
        platforms = list({f.get("platform", "unknown") for f in agent_findings})
        narratives.append({
            "title": "Autonomous Agent Activity",
            "severity": "medium",
            "confidence": "medium",
            "kill_chain_stages": ["Exploitation", "Installation"],
            "timeline": [f.get("timestamp", "") for f in agent_findings if f.get("timestamp")] or ["Unknown"],
            "affected_platforms": platforms[:5],
            "recommendation": "Implement human-in-the-loop controls for agent tool usage. Review and restrict agent permission boundaries.",
            "evidence_refs": [f.get("id", "") for f in agent_findings[:5]],
            "ioc_refs": [],
        })

    return narratives


def _risk_interpretation(score: int) -> str:
    """Convert a numeric risk score to a plain-English interpretation."""
    if score >= 90:
        return "CRITICAL: Active threats detected requiring immediate incident response. Escalate to security team now."
    if score >= 70:
        return "HIGH: Significant threats identified. Prioritize remediation within 24 hours."
    if score >= 40:
        return "MEDIUM: Potential risks detected. Schedule remediation and increase monitoring."
    if score >= 20:
        return "LOW: Minor risks identified. Routine monitoring recommended."
    return "MINIMAL: No immediate threats detected. Continue standard monitoring."


def _derive_cross_platform_correlations(iocs: list[dict], findings: list[dict], platforms: list) -> list[dict]:
    """Find IOCs and findings that appear across multiple platforms."""
    correlations: list[dict] = []

    # Group IOCs by (type, value) to find cross-platform occurrences
    ioc_groups: dict[tuple, set] = {}
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

    # Group findings by severity across platforms
    sev_platforms: dict[str, set] = {}
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


def _derive_conversation_summary(analysis: dict) -> dict:
    """Derive a conversation forensics summary from analysis data."""
    # Try to get conversation data from analysis results
    conversations = analysis.get("conversation_sessions", [])
    if not conversations:
        # Try to build from timeline events
        timeline = analysis.get("timeline", [])
        if isinstance(timeline, list) and timeline:
            [e for e in timeline if isinstance(e, dict) and "user" in (e.get("description", "") + e.get("artifact_type", "")).lower()]
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


# ---------------------------------------------------------------------------
# Jinja2 template — self-contained, no external CSS/JS dependencies
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TRACE — Forensic Report {{ report_id }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Montserrat:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
/* ===== Reset & Base ===== */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#050507;--surface:#0a0a0f;--surface2:#1a1a2e;--surface3:#2a2a3e;
  --accent:#e63946;--accent-bright:#ff3b4a;--accent-bg:rgba(230,57,70,.08);
  --text:#c4c4d4;--text-dim:#8a8a9e;--text-bright:#fff;
  --danger:#ff4444;--high:#ff8800;--warning:#ffaa00;--info:#00aaff;--info2:#00c8ff;
  --border:#2a2a3e;--radius:8px;
  --mono:'JetBrains Mono','Fira Code','Cascadia Code',Consolas,monospace;
  --sans:'Montserrat',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
}
html{font-size:15px;scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.65}
a{color:var(--accent)}
h1{font-family:var(--sans);font-size:1.9rem;font-weight:800;color:var(--accent);letter-spacing:-.02em}
h2{font-family:var(--sans);font-size:1.25rem;font-weight:700;color:var(--accent);margin-bottom:1rem}
h3{font-family:var(--sans);font-size:1rem;font-weight:600;color:var(--text-bright);margin:1.2rem 0 .5rem}
h4{font-family:var(--sans);font-size:.9rem;font-weight:700;color:var(--accent);margin:.8rem 0 .4rem}
p{margin:.5rem 0}
code,pre{font-family:var(--mono);background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:.12rem .35rem;font-size:.8rem;color:var(--text-bright)}
pre{padding:.75rem 1rem;overflow-x:auto;margin:.5rem 0}
.path{word-break:break-all}

/* ===== Layout ===== */
.container{max-width:1200px;margin:0 auto;padding:1.5rem 1rem 3rem}

/* ===== Branding Header ===== */
.brand{display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;padding:1.25rem 1.5rem;background:var(--surface);border:1px solid var(--border);border-radius:0;border-left:4px solid var(--accent)}
.brand-logo{font-family:var(--sans);font-size:1.5rem;font-weight:800;color:var(--accent);white-space:nowrap;letter-spacing:-.02em}
.brand-logo span{color:var(--text-dim)}
.brand-meta{font-size:.8rem;color:var(--text-dim);line-height:1.6}
.brand-meta code{font-size:.75rem}

/* ===== Filter bar ===== */
.filter-bar{display:flex;flex-wrap:wrap;gap:.5rem;margin:0 0 1rem}
.filter-input,.filter-select{background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text-bright);padding:.4rem .7rem;font-family:var(--mono);font-size:.8rem;outline:none}
.filter-input{flex:1;min-width:200px}
.filter-input:focus,.filter-select:focus{border-color:var(--accent)}
.filter-select{min-width:150px}

/* ===== Stat Strip ===== */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin:1.25rem 0}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:.9rem 1rem;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}
.stat .stat-label{font-family:var(--mono);font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;color:var(--text-dim)}
.stat .stat-value{font-family:var(--mono);font-size:1.7rem;font-weight:700;color:var(--text-bright);line-height:1.2}
.stat .stat-value.accent{color:var(--accent)}
.stat .stat-value.danger{color:var(--danger)}
.stat .stat-value.warn{color:var(--warning)}
.stat .stat-value.info{color:var(--info)}
.stat .stat-sub{font-size:.72rem;color:var(--text-dim)}

/* ===== Tabs ===== */
.tabs{display:flex;flex-wrap:wrap;gap:.35rem;margin:1.5rem 0 1rem;position:sticky;top:0;z-index:50;background:rgba(5,5,7,.92);backdrop-filter:blur(6px);padding:.5rem 0;border-bottom:1px solid var(--border)}
.tab-btn{font-family:var(--mono);font-size:.78rem;color:var(--text-dim);background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.35rem .8rem;cursor:pointer;transition:all .15s}
.tab-btn:hover{color:var(--accent-bright);border-color:var(--accent)}
.tab-btn.active{color:var(--text-bright);background:var(--accent);border-color:var(--accent);font-weight:700}
.tab-panel{display:none;animation:fadeIn .25s ease}
.tab-panel.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

/* ===== Cards ===== */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1rem;overflow:hidden}
.card-header{display:flex;justify-content:space-between;align-items:center;padding:.7rem 1rem;cursor:pointer;font-family:var(--mono);font-size:.82rem;color:var(--accent);border-bottom:1px solid var(--border);background:var(--accent-bg);user-select:none}
.card-header:hover{background:rgba(230,57,70,.14)}
.card-header .toggle{font-size:.7rem;color:var(--text-dim);margin-left:.5rem}
.card-body{padding:1rem;font-size:.88rem;line-height:1.6}
.card-body.collapsed{display:none}

/* ===== Tables ===== */
table{width:100%;border-collapse:collapse;font-size:.82rem;margin:.5rem 0}
th{text-align:left;font-family:var(--mono);color:var(--accent);border-bottom:2px solid var(--border);padding:.5rem .4rem;white-space:nowrap}
td{padding:.45rem .4rem;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:var(--accent-bg)}

/* ===== Severity ===== */
.sev-critical{color:var(--danger)}.sev-high{color:var(--high)}.sev-medium{color:var(--warning)}.sev-low{color:var(--info)}.sev-info{color:var(--text-dim)}
.badges{display:flex;flex-wrap:wrap;gap:.5rem;margin:.75rem 0}
.badge{display:inline-flex;align-items:center;gap:.3rem;padding:.22rem .6rem;border-radius:8px;font-size:.72rem;font-family:var(--mono);border:1px solid var(--border);background:var(--surface2);color:var(--text-dim)}
.badge.sev-critical{border-color:var(--danger);color:var(--danger);background:rgba(255,68,68,.08)}
.badge.sev-high{border-color:var(--high);color:var(--high);background:rgba(255,136,0,.08)}
.badge.sev-medium{border-color:var(--warning);color:var(--warning);background:rgba(255,170,0,.08)}
.badge.sev-low{border-color:var(--info);color:var(--info);background:rgba(0,170,255,.08)}
.badge.sev-info{border-color:var(--text-dim);color:var(--text-dim);background:var(--surface2)}

/* ===== Map ===== */
.map-wrap{background:radial-gradient(circle at 50% 40%,#12121c 0%,#050507 70%);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:1rem}
.map-wrap h3{display:flex;align-items:center;gap:.5rem}
.map-legend{display:flex;flex-wrap:wrap;gap:.75rem;margin:.5rem 0 1rem;font-family:var(--mono);font-size:.7rem;color:var(--text-dim)}
.map-legend .lg{display:inline-flex;align-items:center;gap:.35rem}
.map-legend .dot{width:11px;height:11px;border-radius:50%;display:inline-block}
#attackMap{width:100%;height:auto;display:block;cursor:crosshair}
.map-node{cursor:pointer;transition:opacity .15s}
.map-node circle{transition:r .2s,filter .2s}
.map-node text{font-family:var(--mono);font-size:11px;fill:var(--text-bright);pointer-events:none}
.map-node .node-sub{font-size:9px;fill:var(--text-dim)}
.map-node:hover circle{filter:drop-shadow(0 0 8px currentColor)}
.map-node.selected circle{stroke:#fff;stroke-width:2.5}
.map-node.dimmed{opacity:.18}
.map-edge{stroke:var(--accent);stroke-width:1.5;stroke-dasharray:4 3;opacity:.5;transition:opacity .15s}
.map-edge.dimmed{opacity:.05}
.map-edge.highlight{opacity:.95;stroke-width:2.5;stroke-dasharray:none}
.map-detail{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;min-height:120px}
.map-detail .md-title{font-family:var(--mono);font-size:1rem;color:var(--accent);margin-bottom:.5rem}
.map-detail .md-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.5rem}
.map-detail .md-cell{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:.5rem .6rem}
.map-detail .md-cell .k{font-size:.65rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em}
.map-detail .md-cell .v{font-family:var(--mono);font-size:1.05rem;color:var(--text-bright)}
.map-empty{color:var(--text-dim);font-family:var(--mono);padding:2rem;text-align:center}

/* ===== Charts ===== */
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem;margin:1rem 0}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem}
.chart-card h4{font-family:var(--mono);font-size:.8rem;color:var(--accent);margin:0 0 .5rem;text-transform:uppercase;letter-spacing:.05em}
.chart-empty{color:var(--text-dim);font-family:var(--mono);font-size:.75rem;text-align:center;padding:1.5rem 0}

/* Horizontal bars */
.hbars{display:flex;flex-direction:column;gap:.6rem;padding:.4rem 0}
.hbar{display:flex;align-items:center;gap:.5rem}
.hbar-track{flex:1;height:20px;background:#12121c;border-radius:3px;overflow:hidden;position:relative}
.hbar-fill{height:100%;border-radius:3px;transition:width .6s cubic-bezier(.2,.8,.2,1);print-color-adjust:exact;-webkit-print-color-adjust:exact}
.hbar-name{position:absolute;left:7px;top:1px;font-family:var(--mono);font-size:.66rem;color:var(--text)}
.hbar-val{font-family:var(--mono);font-size:.72rem;color:var(--text-bright);font-weight:700;text-align:right;min-width:30px}

/* Radial gauge / donut */
.radial{display:flex;align-items:center;justify-content:center;padding:.5rem 0}
.radial-ring{position:relative;width:150px;height:150px;border-radius:50%;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.radial-hole{position:absolute;border-radius:50%;background:var(--surface);display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge .radial-hole{inset:14px}
.donut .radial-hole{inset:22px}
.radial-num{font-family:var(--mono);font-size:2.2rem;font-weight:700;color:var(--text-bright);line-height:1}
.donut .radial-num{font-size:1.55rem}
.radial-sub{font-family:var(--mono);font-size:.72rem;color:var(--text-dim)}

/* Vertical bars */
.vbars{display:flex;align-items:flex-end;gap:4px;height:120px;padding:.4rem 0;overflow-x:auto}
.vbar{flex:1 0 auto;min-width:16px;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:100%;gap:4px}
.vbar-fill{width:100%;background:var(--accent);border-radius:2px;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.vbar-label{font-family:var(--mono);font-size:.53rem;color:var(--text-dim);white-space:nowrap}
.chart-legend{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.5rem;font-family:var(--mono);font-size:.68rem;color:var(--text-dim)}
.chart-legend .lg{display:inline-flex;align-items:center;gap:.3rem}
.chart-legend .sw{width:10px;height:10px;border-radius:2px;display:inline-block}

/* ===== Timeline ===== */
.timeline{position:relative;padding-left:1.5rem;border-left:2px solid var(--border);margin:1rem 0}
.timeline-item{position:relative;margin-bottom:1.1rem}
.timeline-item::before{content:'';position:absolute;left:-1.85rem;top:.35rem;width:.65rem;height:.65rem;border-radius:50%;background:var(--accent);border:2px solid var(--bg)}
.timeline-ts{font-family:var(--mono);font-size:.75rem;color:var(--text-dim)}
.timeline-body{margin-top:.2rem}

/* ===== Kill chain ===== */
.kill-chain-bar{display:flex;width:100%;margin:.5rem 0;border-radius:var(--radius);overflow:hidden;border:1px solid var(--border)}
.kill-chain-stage{flex:1;padding:.4rem .3rem;text-align:center;font-family:var(--mono);font-size:.62rem;color:var(--text-dim);background:var(--surface2);border-right:1px solid var(--border);transition:all .2s}
.kill-chain-stage:last-child{border-right:none}
.kill-chain-stage.detected{color:var(--text-bright);font-weight:700}
.kill-chain-stage.stage-reconnaissance.detected{background:rgba(0,170,255,.18)}
.kill-chain-stage.stage-weaponization.detected{background:rgba(255,170,0,.18)}
.kill-chain-stage.stage-delivery.detected{background:rgba(255,136,0,.18)}
.kill-chain-stage.stage-exploitation.detected{background:rgba(255,68,68,.18)}
.kill-chain-stage.stage-installation.detected{background:rgba(200,0,200,.18)}
.kill-chain-stage.stage-c2.detected{background:rgba(255,0,100,.18)}
.kill-chain-stage.stage-actions.detected{background:rgba(200,0,0,.18)}

/* ===== Priority actions ===== */
.priority-action{padding:.75rem 1rem;margin:.5rem 0;border-radius:var(--radius);border-left:4px solid var(--text-dim);background:var(--surface2)}
.priority-action.urgency-CRITICAL{border-left-color:var(--danger);background:rgba(255,68,68,.06)}
.priority-action.urgency-HIGH{border-left-color:var(--high);background:rgba(255,136,0,.06)}
.priority-action.urgency-MEDIUM{border-left-color:var(--warning);background:rgba(255,170,0,.06)}
.priority-action.urgency-LOW{border-left-color:var(--info);background:rgba(0,170,255,.06)}
.priority-action .action-number{font-family:var(--mono);font-size:.75rem;color:var(--text-dim)}
.priority-action .action-urgency{font-family:var(--mono);font-size:.75rem;font-weight:700}
.priority-action .action-text{font-size:.9rem;margin-top:.2rem}

/* ===== Narrative ===== */
.narrative-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin:.5rem 0}
.narrative-card h4{font-family:var(--mono);color:var(--accent);margin-bottom:.5rem}
.narrative-meta{display:flex;flex-wrap:wrap;gap:.5rem;margin:.5rem 0}

/* ===== Correlation ===== */
.corr-badge{display:inline-block;padding:.15rem .5rem;border-radius:6px;font-size:.72rem;font-family:var(--mono);margin:.1rem}

/* ===== Conversation ===== */
.conv-session{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:.75rem 1rem;margin:.5rem 0}
.jailbreak-badge{display:inline-block;padding:.15rem .5rem;border-radius:6px;font-size:.72rem;background:rgba(255,68,68,.15);color:var(--danger);font-family:var(--mono);margin-left:.5rem}

/* ===== Risk meter ===== */
.risk-meter{width:100%;max-width:400px;height:20px;background:var(--surface2);border-radius:6px;overflow:hidden;border:1px solid var(--border);margin:.5rem 0}
.risk-fill{height:100%;border-radius:6px;transition:width .6s}

/* ===== Footer ===== */
footer{margin-top:3rem;text-align:center;font-size:.72rem;color:var(--text-dim);font-family:var(--mono)}

/* ===== Print ===== */
@media print{
  body{background:#fff;color:#111;font-size:10pt}
  .tabs{display:none}
  .tab-panel{display:block!important}
  .brand{border:1px solid #ccc;background:#fafafa}
  .brand-logo{color:#e63946}
  h1,h2,h3,h4{color:#e63946}
  .card{border:1px solid #ccc;page-break-inside:avoid}
  .card-body.collapsed{display:block!important}
  .card-header{background:#f0f0f0;color:#e63946}
  th{color:#e63946;border-color:#ccc}
  table{font-size:8pt}
  .stat{background:#fafafa;border:1px solid #ccc}
  .stat .stat-value{color:#111}
  .map-wrap{background:#fff;border:1px solid #ccc}
  .map-node text{fill:#111}
  .map-node .node-sub{fill:#555}
  .chart-card{background:#fff;border:1px solid #ccc;page-break-inside:avoid}
  .hbar-track{background:#eee}
  .hbar-name,.hbar-val{color:#111}
  .radial-hole{background:#fff}
  .radial-num{color:#111}
  .timeline-item::before{background:#e63946;border-color:#fff}
  .badge{border-color:#ccc;color:#555}
  .risk-meter{border:1px solid #ccc;background:#eee}
  a{color:#e63946!important;text-decoration:none}
  pre,code{background:#f5f5f5;border-color:#ddd;color:#111}
  .kill-chain-stage{border-color:#ccc}
  .priority-action{border-left-width:4px}
}
</style>
</head>
<body>
<div class="container">

<!-- ===== Branding ===== -->
<div class="brand">
  <div class="brand-logo">TRACE</div>
  <div class="brand-meta">
    Forensic Report &middot; {{ report_id }}<br>
    Generated {{ generated_at }} &middot; TRACE v{{ trace_version }}<br>
    {% if source_os %}Source OS: <code>{{ source_os }}</code> &middot; {% endif %}
    {% if hostname %}Host: <code>{{ hostname }}</code> &middot; {% endif %}
    Evidence dir: <code>{{ evidence_dir }}</code>
  </div>
</div>

<!-- ===== Stat Strip ===== -->
<div class="stats">
  <div class="stat"><div class="stat-label">Risk Score</div><div class="stat-value {{ 'danger' if overall_risk >= 80 else ('warn' if overall_risk >= 60 else ('info' if overall_risk >= 40 else 'accent')) }}">{{ overall_risk }}<span style="font-size:.9rem">/100</span></div><div class="stat-sub">{{ risk_interpretation.split(':')[0] }}</div></div>
  <div class="stat"><div class="stat-label">Files Collected</div><div class="stat-value accent">{{ total_artifacts }}</div><div class="stat-sub">evidence artifacts</div></div>
  <div class="stat"><div class="stat-label">IOCs</div><div class="stat-value info">{{ total_iocs }}</div><div class="stat-sub">indicators of compromise</div></div>
  <div class="stat"><div class="stat-label">Platforms</div><div class="stat-value">{{ platform_count }}</div><div class="stat-sub">{{ platforms | join(', ') or 'none' }}</div></div>
  <div class="stat"><div class="stat-label">Findings</div><div class="stat-value">{{ total_findings }}</div><div class="stat-sub">{{ critical_count }} critical &middot; {{ high_count }} high</div></div>
  <div class="stat"><div class="stat-label">Kill Chain</div><div class="stat-value {{ 'danger' if kill_chain_detected_count >= 3 else 'accent' }}">{{ kill_chain_detected_count }}<span style="font-size:.9rem">/{{ kill_chain_total }}</span></div><div class="stat-sub">stages detected</div></div>
</div>

<!-- ===== Tabs ===== -->
<nav class="tabs" id="tabs">
  <button class="tab-btn active" data-tab="overview">Overview</button>
  <button class="tab-btn" data-tab="map">Attack Map</button>
  <button class="tab-btn" data-tab="findings">Findings</button>
  <button class="tab-btn" data-tab="iocs">IOCs</button>
  <button class="tab-btn" data-tab="timeline">Timeline</button>
  <button class="tab-btn" data-tab="mitre">MITRE</button>
  <button class="tab-btn" data-tab="killchain">Kill Chain</button>
  <button class="tab-btn" data-tab="actions">Actions</button>
  <button class="tab-btn" data-tab="narratives">Narratives</button>
  <button class="tab-btn" data-tab="correlation">Correlation</button>
  <button class="tab-btn" data-tab="conversation">Conversation</button>
  <button class="tab-btn" data-tab="secrethunt">Secret Hunt</button>
  <button class="tab-btn" data-tab="risk">Risk</button>
  <button class="tab-btn" data-tab="evidence">Evidence</button>
  <button class="tab-btn" data-tab="appendix">Appendix</button>
</nav>

<!-- ===== OVERVIEW ===== -->
<section class="tab-panel active" id="panel-overview">
  <h2>Executive Summary</h2>
  <div class="card"><div class="card-body">
    <p>{{ summary_text }}</p>
    <p><strong>{{ overall_risk }}/100</strong> &mdash; {{ risk_interpretation }}</p>
    <div class="risk-meter"><div class="risk-fill" style="width:{{ overall_risk }}%;background:{% if overall_risk >= 80 %}var(--danger){% elif overall_risk >= 60 %}var(--high){% elif overall_risk >= 40 %}var(--warning){% elif overall_risk >= 20 %}var(--info){% else %}var(--accent){% endif %}"></div></div>
    <div class="badges">
      {% for plat in platforms %}<span class="badge">{{ plat }}</span>{% endfor %}
      {% for sev_label, count in severity_counts.items() %}{% if count %}<span class="badge sev-{{ sev_label }}">{{ sev_label | title }}: {{ count }}</span>{% endif %}{% endfor %}
    </div>
  </div></div>

  <h2>Charts &amp; Stats</h2>
  <div class="charts">
    <div class="chart-card">
      <h4>Risk Score Gauge</h4>
      <div class="radial gauge">
        <div class="radial-ring" style="background:conic-gradient({{ risk_color }} {{ overall_risk }}%,var(--surface3) 0)" role="img" aria-label="Risk score {{ overall_risk }} of 100">
          <div class="radial-hole"><div class="radial-num">{{ overall_risk }}</div><div class="radial-sub">/ 100</div></div>
        </div>
      </div>
      <div class="chart-legend"><span class="lg"><span class="sw" style="background:var(--danger)"></span>Critical</span><span class="lg"><span class="sw" style="background:var(--high)"></span>High</span><span class="lg"><span class="sw" style="background:var(--warning)"></span>Medium</span><span class="lg"><span class="sw" style="background:var(--info)"></span>Low</span></div>
    </div>
    <div class="chart-card">
      <h4>Findings by Severity</h4>
      {% if total_findings %}
      <div class="hbars">
        {% for b in severity_bars %}
        <div class="hbar"><div class="hbar-track"><div class="hbar-fill" style="width:{{ b.pct }};background:{{ b.color }}"></div><span class="hbar-name">{{ b.label }}</span></div><span class="hbar-val">{{ b.value }}</span></div>
        {% endfor %}
      </div>
      {% else %}<p class="chart-empty">No findings</p>{% endif %}
    </div>
    <div class="chart-card">
      <h4>Severity Distribution</h4>
      {% if donut_gradient %}
      <div class="radial donut">
        <div class="radial-ring" style="background:{{ donut_gradient }}" role="img" aria-label="Severity distribution across {{ donut_total }} findings">
          <div class="radial-hole"><div class="radial-num">{{ donut_total }}</div></div>
        </div>
      </div>
      {% else %}<p class="chart-empty">No findings</p>{% endif %}
    </div>
    <div class="chart-card">
      <h4>IOCs by Type</h4>
      {% if ioc_bars %}
      <div class="hbars">
        {% for b in ioc_bars %}
        <div class="hbar"><div class="hbar-track"><div class="hbar-fill" style="width:{{ b.pct }};background:{{ b.color }}"></div><span class="hbar-name">{{ b.label }}</span></div><span class="hbar-val" style="min-width:44px">{{ b.value }}</span></div>
        {% endfor %}
      </div>
      {% else %}<p class="chart-empty">No IOCs</p>{% endif %}
    </div>
    <div class="chart-card">
      <h4>Platform Inventory</h4>
      {% if platform_bars %}
      <div class="hbars">
        {% for b in platform_bars %}
        <div class="hbar"><div class="hbar-track"><div class="hbar-fill" style="width:{{ b.pct }};background:{{ b.color }}"></div><span class="hbar-name">{{ b.label }}</span></div><span class="hbar-val">{{ b.value }}</span></div>
        {% endfor %}
      </div>
      {% else %}<p class="chart-empty">No platforms detected</p>{% endif %}
    </div>
    <div class="chart-card">
      <h4>Timeline Activity</h4>
      {% if timeline_bars %}
      <div class="vbars">
        {% for b in timeline_bars %}
        <div class="vbar" title="{{ b.label }}: {{ b.value }} events"><div class="vbar-fill" style="height:{{ b.pct }}"></div><span class="vbar-label">{{ b.label }}</span></div>
        {% endfor %}
      </div>
      {% else %}<p class="chart-empty">No timeline events</p>{% endif %}
    </div>
    <div class="chart-card">
      <h4>MITRE ATT&amp;CK Techniques</h4>
      {% if mitre_bars %}
      <div class="hbars">
        {% for b in mitre_bars %}
        <div class="hbar"><div class="hbar-track"><div class="hbar-fill" style="width:{{ b.pct }};background:{{ b.color }}"></div><span class="hbar-name">{{ b.label }}</span></div><span class="hbar-val">{{ b.value }}</span></div>
        {% endfor %}
      </div>
      {% else %}<p class="chart-empty">No MITRE mappings</p>{% endif %}
    </div>
    <div class="chart-card">
      <h4>Enhanced Risk Categories</h4>
      {% if risk_cat_bars %}
      <div class="hbars">
        {% for b in risk_cat_bars %}
        <div class="hbar"><div class="hbar-track"><div class="hbar-fill" style="width:{{ b.pct }};background:{{ b.color }}"></div><span class="hbar-name">{{ b.label }}</span></div><span class="hbar-val">{{ b.value }}</span></div>
        {% endfor %}
      </div>
      {% else %}<p class="chart-empty">No enhanced risk data</p>{% endif %}
    </div>
  </div>

  <h2>Top Priority Actions</h2>
  {% if priority_actions %}
  {% for action in priority_actions[:3] %}
  <div class="priority-action urgency-{{ action.urgency }}">
    <span class="action-number">#{{ loop.index }}</span>
    <span class="action-urgency sev-{{ 'critical' if action.urgency == 'CRITICAL' else ('high' if action.urgency == 'HIGH' else ('medium' if action.urgency == 'MEDIUM' else 'low')) }}">[{{ action.urgency }}]</span>
    <div class="action-text">{{ action.action }}</div>
  </div>
  {% endfor %}
  {% else %}<p style="color:var(--text-dim)">No priority actions identified.</p>{% endif %}
</section>

<!-- ===== ATTACK MAP ===== -->
<section class="tab-panel" id="panel-map">
  <h2>Attack Surface Map</h2>
  <p style="color:var(--text-dim);font-size:.85rem">Interactive map of detected AI platforms. Node color reflects the highest-severity finding on that platform; connecting lines show cross-platform correlations. Click a node to inspect it.</p>
  <div class="map-wrap">
    <h3>Platform Correlation Map</h3>
    <div class="map-legend">
      <span class="lg"><span class="dot" style="background:var(--danger)"></span>Critical</span>
      <span class="lg"><span class="dot" style="background:var(--high)"></span>High</span>
      <span class="lg"><span class="dot" style="background:var(--warning)"></span>Medium</span>
      <span class="lg"><span class="dot" style="background:var(--info)"></span>Low</span>
      <span class="lg"><span class="dot" style="background:#888"></span>Info</span>
      <span class="lg"><span style="color:var(--accent)">- - -</span> Correlation</span>
    </div>
    <svg id="attackMap" viewBox="0 0 800 420" role="img" aria-label="Attack surface map"></svg>
    <div class="map-detail" id="mapDetail">
      <div class="md-title" id="mdTitle">Select a platform node</div>
      <div class="md-grid" id="mdGrid"></div>
    </div>
  </div>
</section>

<!-- ===== FINDINGS ===== -->
<section class="tab-panel" id="panel-findings">
  <h2>Findings</h2>
  <div class="filter-bar">
    <input type="text" id="findingsSearch" class="filter-input" placeholder="Filter findings…" oninput="filterFindings(this.value)">
    <select id="findingsSeverity" class="filter-select" onchange="filterFindings(document.getElementById('findingsSearch').value)">
      <option value="">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="info">Info</option>
    </select>
  </div>
  {% if findings %}
  <div id="findingsList">
  {% for f in findings %}
  <div class="card finding-card" data-severity="{{ f.severity }}" data-text="{{ (f.title ~ ' ' ~ f.description ~ ' ' ~ f.platform) | lower }}">
    <div class="card-header" onclick="toggleCard(this)">
      <span><span class="sev-{{ f.severity }}">{{ f.severity | title }}</span> &mdash; {{ f.title }}</span>
      <span class="toggle">[+]</span>
    </div>
    <div class="card-body collapsed">
      <p>{{ f.description }}</p>
      {% if f.evidence %}<h4>Evidence</h4><ul>{% for ev in f.evidence %}<li><code>{{ ev }}</code></li>{% endfor %}</ul>{% endif %}
      {% if f.iocs %}<h4>IOCs</h4><ul>{% for ioc in f.iocs %}<li>{{ ioc }}</li>{% endfor %}</ul>{% endif %}
      {% if f.mitre_atlas %}<h4>MITRE ATLAS</h4><ul>{% for ma in f.mitre_atlas %}<li>{{ ma }}</li>{% endfor %}</ul>{% endif %}
      {% if f.recommendation %}<h4>Recommendation</h4><p>{{ f.recommendation }}</p>{% endif %}
      <p style="font-size:.75rem;color:var(--text-dim)">ID: {{ f.id }} &middot; Platform: {{ f.platform }} &middot; Risk: {{ f.risk_score }}</p>
    </div>
  </div>
  {% endfor %}
  </div>
  <p id="findingsEmpty" style="color:var(--text-dim);display:none">No findings match the current filter.</p>
  {% else %}<p style="color:var(--text-dim)">No findings recorded.</p>{% endif %}
</section>

<!-- ===== IOCS ===== -->
<section class="tab-panel" id="panel-iocs">
  <h2>IOC Extractor Results</h2>
  {% if iocs %}
  <div class="card"><div class="card-body">
    <p><strong>{{ iocs | length }}</strong> indicators of compromise extracted.</p>
    <table>
      <tr><th>Type</th><th>Count</th></tr>
      {% for type, count in ioc_summary.items() %}<tr><td><span class="ioc-type" style="font-family:var(--mono);color:var(--accent);font-size:.78rem">{{ type }}</span></td><td>{{ count }}</td></tr>{% endfor %}
    </table>
  </div></div>
  <details>
  <summary style="font-family:var(--mono);color:var(--accent);cursor:pointer;margin:1rem 0">Show top {{ iocs[:200] | length }} IOCs (of {{ iocs | length }} — full list in report.json)</summary>
  <div class="card"><div class="card-body">
    <table class="sortable" id="iocTable">
      <tr><th data-sort="ioc_type">Type</th><th data-sort="value">Value</th><th data-sort="source">Source</th><th data-sort="severity">Severity</th></tr>
      {% for ioc in iocs[:200] %}<tr><td><span class="ioc-type" style="font-family:var(--mono);color:var(--accent);font-size:.78rem">{{ ioc.ioc_type }}</span></td><td><code>{{ ioc.value }}</code></td><td>{{ ioc.source }}</td><td><span class="sev-{{ ioc.severity }}">{{ ioc.severity | title }}</span></td></tr>{% endfor %}
    </table>
  </div></div>
  </details>
  {% else %}<p style="color:var(--text-dim)">No IOCs extracted.</p>{% endif %}
</section>

<!-- ===== TIMELINE ===== -->
<section class="tab-panel" id="panel-timeline">
  <h2>Event Timeline</h2>
  {% if timeline %}
  <div class="timeline">
    {% for event in timeline[:500] %}
    <div class="timeline-item"{% if event.get('is_collection_event') %} style="opacity:0.55;font-style:italic"{% endif %}>
      <div class="timeline-ts">{{ event.timestamp }}</div>
      <div class="timeline-body">
        <strong>{{ event.platform }}</strong> &mdash; {{ event.description }}
        {% if event.severity %}<span class="sev-{{ event.severity if event.severity is string else event.severity.value }}"> [{{ event.severity if event.severity is string else event.severity.value | title }}]</span>{% endif %}
        {% if event.get('content_preview') %}<br><small style="color:var(--text-dim)">{{ event.content_preview | e }}</small>{% endif %}
      </div>
    </div>
    {% endfor %}
    {% if timeline | length > 500 %}<p style="color:var(--text-dim);text-align:center;margin-top:1rem">Showing 500 of {{ timeline | length }} events. See <code>report.json</code> for the full timeline.</p>{% endif %}
  </div>
  {% else %}<p style="color:var(--text-dim)">No timeline events recorded.</p>{% endif %}
</section>

<!-- ===== MITRE ===== -->
<section class="tab-panel" id="panel-mitre">
  <h2>MITRE ATLAS Mapping</h2>
  {% if atlas_mapping %}
  <div class="card"><div class="card-body">
    <p><strong>{{ atlas_mapping | length }}</strong> ATLAS technique mappings.</p>
    <table>
      <tr><th>Technique ID</th><th>Technique Name</th><th>Count</th></tr>
      {% for entry in atlas_summary %}<tr><td><code>{{ entry.technique_id }}</code></td><td>{{ entry.technique_name }}</td><td>{{ entry.count }}</td></tr>{% endfor %}
    </table>
  </div></div>
  {% else %}<p style="color:var(--text-dim)">No MITRE ATLAS mappings available.</p>{% endif %}

  <h2 style="margin-top:2rem">MITRE ATT&amp;CK Mapping</h2>
  {% if mitre_attack %}
  <div class="card"><div class="card-body">
    <p><strong>{{ mitre_attack | length }}</strong> ATT&amp;CK technique mappings derived from evidence.</p>
    <table>
      <tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Count</th><th>Evidence</th></tr>
      {% for tech in mitre_attack %}<tr><td><code>{{ tech.technique_id }}</code></td><td>{{ tech.technique_name }}</td><td>{{ tech.tactic }}</td><td>{{ tech.count }}</td><td style="font-size:.78rem">{{ tech.evidence[:2] | join('; ') if tech.evidence else '—' }}</td></tr>{% endfor %}
    </table>
  </div></div>
  {% else %}<p style="color:var(--text-dim)">No MITRE ATT&amp;CK mappings derived from available evidence.</p>{% endif %}
</section>

<!-- ===== KILL CHAIN ===== -->
<section class="tab-panel" id="panel-killchain">
  <h2>Kill Chain Analysis</h2>
  {% if kill_chain_stages %}
  <div style="margin:1rem 0">
    <div class="kill-chain-bar">
      {% for stage in kill_chain_stages %}
      {% set stage_class = "detected" if stage.detected else "" %}
      {% if stage.stage == "Reconnaissance" %}{% set stage_id = "stage-reconnaissance" %}{% elif stage.stage == "Weaponization" %}{% set stage_id = "stage-weaponization" %}{% elif stage.stage == "Delivery" %}{% set stage_id = "stage-delivery" %}{% elif stage.stage == "Exploitation" %}{% set stage_id = "stage-exploitation" %}{% elif stage.stage == "Installation" %}{% set stage_id = "stage-installation" %}{% elif stage.stage == "Command & Control" %}{% set stage_id = "stage-c2" %}{% else %}{% set stage_id = "stage-actions" %}{% endif %}
      <div class="kill-chain-stage {{ stage_class }} {{ stage_id }}" title="{{ stage.stage }}{% if stage.detected %}: Detected{% else %}: Not detected{% endif %}">
        {{ stage.stage.split(' ')[0][:6] }}<br>{% if stage.detected %}✓{% else %}—{% endif %}
      </div>
      {% endfor %}
    </div>
    <p style="font-size:.8rem;color:var(--text-dim);margin-top:.3rem">{{ kill_chain_detected_count }} of {{ kill_chain_total }} stages detected</p>
  </div>
  <div class="card"><div class="card-body">
    <table>
      <tr><th>Stage</th><th>Status</th><th>Evidence</th></tr>
      {% for stage in kill_chain_stages %}
      <tr><td><strong>{{ stage.stage }}</strong></td><td>{% if stage.detected %}<span style="color:var(--danger)">✓ Detected</span>{% else %}<span style="color:var(--text-dim)">— Not detected</span>{% endif %}</td><td>{% if stage.evidence %}{{ stage.evidence | join('; ') }}{% else %}—{% endif %}</td></tr>
      {% endfor %}
    </table>
  </div></div>
  {% else %}<p style="color:var(--text-dim)">No kill chain data available.</p>{% endif %}
</section>

<!-- ===== ACTIONS ===== -->
<section class="tab-panel" id="panel-actions">
  <h2>Priority Actions</h2>
  {% if priority_actions %}
  {% for action in priority_actions %}
  <div class="priority-action urgency-{{ action.urgency }}">
    <span class="action-number">#{{ loop.index }}</span>
    <span class="action-urgency sev-{{ 'critical' if action.urgency == 'CRITICAL' else ('high' if action.urgency == 'HIGH' else ('medium' if action.urgency == 'MEDIUM' else 'low')) }}">[{{ action.urgency }}]</span>
    <div class="action-text">{{ action.action }}</div>
    {% if action.evidence %}<div style="font-size:.8rem;color:var(--text-dim);margin-top:.3rem">Evidence: {% for ev in action.evidence[:3] %}<code>{{ ev }}</code>{% if not loop.last %}, {% endif %}{% endfor %}</div>{% endif %}
  </div>
  {% endfor %}
  {% else %}<p style="color:var(--text-dim)">No priority actions identified.</p>{% endif %}
</section>

<!-- ===== NARRATIVES ===== -->
<section class="tab-panel" id="panel-narratives">
  <h2>Attack Narratives</h2>
  {% if attack_narratives %}
  {% for narrative in attack_narratives %}
  <div class="narrative-card">
    <h4><span class="sev-{{ 'critical' if narrative.severity == 'critical' else ('high' if narrative.severity == 'high' else ('medium' if narrative.severity == 'medium' else 'low')) }}">{{ narrative.severity | title }}</span> &mdash; {{ narrative.title }}</h4>
    <div class="narrative-meta">
      <span class="badge">Confidence: {{ narrative.confidence }}</span>
      {% for stage in narrative.kill_chain_stages %}<span class="badge sev-high">{{ stage }}</span>{% endfor %}
    </div>
    <p style="margin:.5rem 0"><strong>Affected platforms:</strong> {{ narrative.affected_platforms | join(', ') or 'Unknown' }}</p>
    <p style="font-size:.85rem">{{ narrative.recommendation }}</p>
    {% if narrative.evidence_refs %}<p style="font-size:.8rem;color:var(--text-dim)">Evidence: {% for ref in narrative.evidence_refs %}<code>{{ ref }}</code>{% if not loop.last %}, {% endif %}{% endfor %}</p>{% endif %}
    {% if narrative.ioc_refs %}<p style="font-size:.8rem;color:var(--text-dim)">IOCs: {% for ref in narrative.ioc_refs %}<code>{{ ref }}</code>{% if not loop.last %}, {% endif %}{% endfor %}</p>{% endif %}
  </div>
  {% endfor %}
  {% else %}<p style="color:var(--text-dim)">No attack narratives identified.</p>{% endif %}
</section>

<!-- ===== CORRELATION ===== -->
<section class="tab-panel" id="panel-correlation">
  <h2>Cross-Platform Correlation</h2>
  {% if cross_platform_correlations %}
  <div class="card"><div class="card-body">
    <p><strong>{{ cross_platform_correlations | length }}</strong> cross-platform correlation(s) detected.</p>
    <table>
      <tr><th>Indicator</th><th>Type</th><th>Platforms</th><th>Severity</th></tr>
      {% for corr in cross_platform_correlations %}
      <tr><td><code>{{ corr.indicator }}</code></td><td>{{ corr.correlation_type }}</td><td>{% for p in corr.platforms %}<span class="corr-badge" style="background:var(--accent-bg);border:1px solid var(--accent)">{{ p }}</span>{% endfor %}</td><td><span class="sev-{{ corr.severity }}">{{ corr.severity | title }}</span></td></tr>
      {% endfor %}
    </table>
  </div></div>
  {% else %}<p style="color:var(--text-dim)">No cross-platform correlations detected.</p>{% endif %}
</section>

<!-- ===== CONVERSATION ===== -->
<section class="tab-panel" id="panel-conversation">
  <h2>Conversation Forensics</h2>
  {% if conversation_summary and conversation_summary.total_sessions > 0 %}
  <div class="card"><div class="card-body">
    <p><strong>{{ conversation_summary.total_sessions }}</strong> conversation session(s) analyzed. <strong>{{ conversation_summary.jailbreak_attempts_total }}</strong> jailbreak attempt(s) detected. <strong>{{ conversation_summary.tool_calls_total }}</strong> tool call(s) recorded.</p>
    {% for session in conversation_summary.sessions %}
    <div class="conv-session">
      <strong>{{ session.get('platform', 'Unknown') }}</strong>
      <span style="color:var(--text-dim);font-size:.85rem">&middot; Session: {{ session.get('session_id', 'N/A') }}</span>
      {% if session.get('jailbreak_attempts', 0) > 0 %}<span class="jailbreak-badge">⚠ {{ session.get('jailbreak_attempts') }} jailbreak(s)</span>{% endif %}
      <br>
      <span style="font-size:.82rem">Turns: {{ session.get('turns', 0) }} &middot; User: {{ session.get('user_turns', 0) }} &middot; Assistant: {{ session.get('assistant_turns', 0) }} &middot; Tool calls: {{ session.get('tool_calls', 0) }}</span>
      <br>
      <span style="font-size:.78rem;color:var(--text-dim)">Risk: {{ session.get('risk_assessment', 'info') }}</span>
    </div>
    {% endfor %}
  </div></div>
  {% else %}<p style="color:var(--text-dim)">No conversation forensics data available.</p>{% endif %}
</section>

<!-- ===== SECRET HUNT ===== -->
<section class="tab-panel" id="panel-secrethunt">
  <h2>Conversation Secret Hunt</h2>
  {% if conversation_secret_hunt and conversation_secret_hunt.total > 0 %}
  <div class="card"><div class="card-body">
    <p><strong>{{ conversation_secret_hunt.total }}</strong> secret finding(s) across <strong>{{ conversation_secret_hunt.flagged_turns }}</strong> turn(s), <strong>{{ conversation_secret_hunt.unique_secrets }}</strong> unique secret(s).</p>
    {% if conversation_secret_hunt.by_severity %}
    <div style="margin:.5rem 0">
      {% for sev, count in conversation_secret_hunt.by_severity.items() %}
      {% if count %}<span class="badge sev-{{ sev }}">{{ sev | title }}: {{ count }}</span>{% endif %}
      {% endfor %}
    </div>
    {% endif %}
    {% if conversation_secret_hunt.by_leak_direction %}
    <p style="font-size:.85rem;color:var(--text-dim)">Leak direction:
      {% for dir, count in conversation_secret_hunt.by_leak_direction.items() %}
      {% if count %}<code>{{ dir }}</code> ({{ count }}){% if not loop.last %}, {% endif %}{% endif %}
      {% endfor %}
    </p>
    {% endif %}
    <table>
      <tr><th>Severity</th><th>Type</th><th>Redacted</th><th>Direction</th><th>Field</th><th>Platform</th><th>Session</th><th>Timestamp</th></tr>
      {% for f in conversation_secret_hunt.findings[:200] %}
      <tr>
        <td><span class="sev-{{ f.severity }}">{{ f.severity | title }}</span></td>
        <td><code>{{ f.secret_type }}</code></td>
        <td><code>{{ f.redacted }}</code></td>
        <td>{{ f.leak_direction or '—' }}</td>
        <td>{{ f.evidence_field }}</td>
        <td>{{ f.platform }}</td>
        <td style="font-size:.78rem">{{ f.session_id }}</td>
        <td style="font-size:.78rem">{{ f.timestamp }}</td>
      </tr>
      {% endfor %}
    </table>
    {% if conversation_secret_hunt.findings | length > 200 %}<p style="color:var(--text-dim);font-size:.8rem;margin-top:.5rem">Showing 200 of {{ conversation_secret_hunt.findings | length }} findings. See <code>report.json</code> for the full list.</p>{% endif %}
  </div></div>
  {% else %}<p style="color:var(--text-dim)">No conversation secret hunt data available. Run <code>trace analyze --secret-hunt</code> to scan conversation turns for leaked secrets.</p>{% endif %}
</section>

<!-- ===== RISK ===== -->
<section class="tab-panel" id="panel-risk">
  <h2>Risk Assessment</h2>
  <div class="card"><div class="card-body">
    <p>Overall risk score: <strong>{{ overall_risk }}</strong> / 100 &mdash; {{ risk_interpretation }}</p>
    <div class="risk-meter"><div class="risk-fill" style="width:{{ overall_risk }}%;background:{% if overall_risk >= 80 %}var(--danger){% elif overall_risk >= 60 %}var(--high){% elif overall_risk >= 40 %}var(--warning){% elif overall_risk >= 20 %}var(--info){% else %}var(--accent){% endif %}"></div></div>
    {% if risk_details %}
    <table>
      <tr><th>Category</th><th>Score</th><th>Details</th></tr>
      {% for rd in risk_details %}<tr><td>{{ rd.category }}</td><td>{{ rd.score }}</td><td>{{ rd.details }}</td></tr>{% endfor %}
    </table>
    {% endif %}
    {% if enhanced_risk and enhanced_risk.categories %}
    <h3 style="margin-top:1rem">Enhanced Risk Breakdown</h3>
    <table>
      <tr><th>Category</th><th>Score (0-12.5)</th><th>Level</th></tr>
      {% for cat, score in enhanced_risk.categories.items() %}
      <tr><td>{{ cat | replace('_', ' ') | title }}</td><td>{{ score }}</td><td>{% if score >= 10 %}<span class="sev-critical">Critical</span>{% elif score >= 7 %}<span class="sev-high">High</span>{% elif score >= 4 %}<span class="sev-medium">Medium</span>{% elif score > 0 %}<span class="sev-low">Low</span>{% else %}<span class="sev-info">None</span>{% endif %}</td></tr>
      {% endfor %}
    </table>
    {% endif %}
  </div></div>
</section>

<!-- ===== EVIDENCE ===== -->
<section class="tab-panel" id="panel-evidence">
  <h2>Evidence Manifest</h2>
  {% for artifact in artifacts %}
  <div class="card">
    <div class="card-header" onclick="toggleCard(this)">
      <span>{{ artifact.artifact_type | upper }} — {{ artifact.original_path | basename }}</span>
      <span class="toggle">[+]</span>
    </div>
    <div class="card-body collapsed">
      <table>
        <tr><th style="width:30%">Property</th><th>Value</th></tr>
        <tr><td>Original Path</td><td><code class="path">{{ artifact.original_path }}</code></td></tr>
        <tr><td>Platform</td><td>{{ artifact.platform }}</td></tr>
        <tr><td>Artifact Type</td><td>{{ artifact.artifact_type }}</td></tr>
        <tr><td>Source OS</td><td>{{ artifact.source_os }}</td></tr>
        <tr><td>SHA-256</td><td><code>{{ artifact.sha256 }}</code></td></tr>
        <tr><td>Size</td><td>{{ artifact.size_bytes | filesizeformat }}</td></tr>
        <tr><td>Collected At</td><td>{{ artifact.collected_at }}</td></tr>
        <tr><td>Collector Version</td><td>{{ artifact.collector_version }}</td></tr>
      </table>
    </div>
  </div>
  {% endfor %}

  <h2 style="margin-top:2rem">Platform Inventory</h2>
  {% if platform_details %}
  <div class="card"><div class="card-body">
    <table>
      <tr><th>Platform</th><th>Category</th><th>Artifacts</th><th>Findings</th><th>Max Severity</th></tr>
      {% for p in platform_details %}<tr><td><strong>{{ p.name }}</strong></td><td>{{ p.category }}</td><td>{{ p.artifact_count }}</td><td>{{ p.finding_count }}</td><td><span class="sev-{{ p.max_severity }}">{{ p.max_severity | title }}</span></td></tr>{% endfor %}
    </table>
  </div></div>
  {% else %}<p style="color:var(--text-dim)">No platform inventory data available.</p>{% endif %}
</section>

<!-- ===== APPENDIX ===== -->
<section class="tab-panel" id="panel-appendix">
  <h2>Appendices</h2>
  <div class="card"><div class="card-body">
    <h3>A. Chain of Custody</h3>
    <p>Full chain-of-custody metadata stored in <code>CHAIN_OF_CUSTODY.json</code>.</p>
    {% if custody_metadata %}
    <table>
      <tr><th>Key</th><th>Value</th></tr>
      {% for k, v in custody_metadata.items() %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}
    </table>
    {% endif %}
    <h3 style="margin-top:1.5rem">B. Report Metadata</h3>
    <table>
      <tr><td>Report ID</td><td>{{ report_id }}</td></tr>
      <tr><td>Generated</td><td>{{ generated_at }}</td></tr>
      <tr><td>Tool</td><td>TRACE v{{ trace_version }}</td></tr>
      <tr><td>Evidence Dir</td><td>{{ evidence_dir }}</td></tr>
    </table>
  </div></div>
</section>

<footer>
  TRACE &mdash; Tool for Reconnaissance of AI &amp; Compute Evidence &mdash; {{ generated_at }}
</footer>

</div><!-- /container -->

<script>
/* ===== Tab navigation ===== */
(function(){
  var btns = document.querySelectorAll('.tab-btn');
  var panels = document.querySelectorAll('.tab-panel');
  function activate(name){
    btns.forEach(function(b){ b.classList.toggle('active', b.getAttribute('data-tab') === name); });
    panels.forEach(function(p){ p.classList.toggle('active', p.id === 'panel-' + name); });
  }
  btns.forEach(function(b){
    b.addEventListener('click', function(){ activate(b.getAttribute('data-tab')); });
  });
})();

/* ===== Card toggle ===== */
function toggleCard(header){
  var body = header.nextElementSibling;
  var toggle = header.querySelector('.toggle');
  if(body.classList.contains('collapsed')){
    body.classList.remove('collapsed');
    toggle.textContent = '[-]';
  } else {
    body.classList.add('collapsed');
    toggle.textContent = '[+]';
  }
}

/* ===== Findings filter ===== */
function filterFindings(query){
  var q = (query || '').toLowerCase().trim();
  var sev = document.getElementById('findingsSeverity').value;
  var cards = document.querySelectorAll('.finding-card');
  var visible = 0;
  cards.forEach(function(card){
    var text = card.getAttribute('data-text') || '';
    var cardSev = card.getAttribute('data-severity') || '';
    var matchText = !q || text.indexOf(q) !== -1;
    var matchSev = !sev || cardSev === sev;
    var show = matchText && matchSev;
    card.style.display = show ? '' : 'none';
    if(show) visible++;
  });
  var empty = document.getElementById('findingsEmpty');
  if(empty) empty.style.display = visible === 0 ? '' : 'none';
}

/* ===== Sortable tables ===== */
(function(){
  var sevRank = {critical:5, high:4, medium:3, low:2, info:1};
  document.querySelectorAll('table.sortable').forEach(function(table){
    var headers = table.querySelectorAll('th[data-sort]');
    headers.forEach(function(th, idx){
      th.style.cursor = 'pointer';
      th.addEventListener('click', function(){
        var key = th.getAttribute('data-sort');
        var tbody = table.querySelector('tbody') || table;
        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
        var asc = th.getAttribute('data-asc') !== '1';
        rows.sort(function(a, b){
          var av = a.cells[idx] ? a.cells[idx].textContent.trim() : '';
          var bv = b.cells[idx] ? b.cells[idx].textContent.trim() : '';
          if(key === 'severity'){ return (sevRank[av]||0) - (sevRank[bv]||0); }
          return av.localeCompare(bv);
        });
        if(!asc) rows.reverse();
        rows.forEach(function(r){ tbody.appendChild(r); });
        headers.forEach(function(h){ h.removeAttribute('data-asc'); });
        th.setAttribute('data-asc', asc ? '1' : '0');
      });
    });
  });
})();

/* ===== Data ===== */
var MAP_DATA = {{ map_data | tojson }};

/* ===== Interactive Attack Map ===== */
(function(){
  var svg = document.getElementById('attackMap');
  if(!svg) return;
  var W = 800, H = 420;
  var nodes = MAP_DATA.nodes || [];
  var edges = MAP_DATA.edges || [];
  var detail = document.getElementById('mapDetail');
  var mdTitle = document.getElementById('mdTitle');
  var mdGrid = document.getElementById('mdGrid');

  if(nodes.length === 0){
    svg.innerHTML = '';
    mdTitle.textContent = 'No platforms detected';
    mdGrid.innerHTML = '';
    return;
  }

  // Layout: place nodes on a circle (or grid for many nodes)
  var cx = W / 2, cy = H / 2;
  var radius = Math.min(W, H) / 2 - 70;
  var positions = {};
  if(nodes.length === 1){
    positions[nodes[0].id] = {x: cx, y: cy};
  } else {
    nodes.forEach(function(n, i){
      var ang = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
      positions[n.id] = {x: cx + radius * Math.cos(ang), y: cy + radius * Math.sin(ang)};
    });
  }

  // Edges
  var edgeHtml = '';
  edges.forEach(function(e, i){
    var a = positions[e.source], b = positions[e.target];
    if(!a || !b) return;
    var midX = (a.x + b.x) / 2, midY = (a.y + b.y) / 2;
    edgeHtml += '<line class="map-edge" id="edge-'+i+'" x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'"/>';
    edgeHtml += '<text class="map-edge" x="'+midX+'" y="'+(midY-6)+'" text-anchor="middle" style="font-size:9px;fill:var(--text-dim)">'+e.label+'</text>';
  });

  // Nodes
  var nodeHtml = '';
  nodes.forEach(function(n, i){
    var p = positions[n.id];
    var r = 26 + n.risk_index * 4;
    nodeHtml += '<g class="map-node" id="node-'+i+'" data-id="'+n.id+'" data-index="'+i+'">';
    nodeHtml += '<circle cx="'+p.x+'" cy="'+p.y+'" r="'+r+'" fill="'+n.color+'" fill-opacity="0.18" stroke="'+n.color+'" stroke-width="2"/>';
    nodeHtml += '<text x="'+p.x+'" y="'+(p.y-2)+'" text-anchor="middle">'+n.name+'</text>';
    nodeHtml += '<text class="node-sub" x="'+p.x+'" y="'+(p.y+14)+'" text-anchor="middle">'+n.finding_count+' findings</text>';
    nodeHtml += '</g>';
  });

  svg.innerHTML = edgeHtml + nodeHtml;

  function renderDetail(n){
    mdTitle.textContent = n.name + (n.category ? ' — ' + n.category : '');
    var cells = [
      ['Max Severity', n.max_severity],
      ['Findings', n.finding_count],
      ['Artifacts', n.artifact_count],
      ['IOCs', n.ioc_count]
    ];
    mdGrid.innerHTML = cells.map(function(c){
      return '<div class="md-cell"><div class="k">'+c[0]+'</div><div class="v">'+c[1]+'</div></div>';
    }).join('');
  }

  function selectNode(idx){
    var all = svg.querySelectorAll('.map-node');
    var allEdges = svg.querySelectorAll('.map-edge');
    all.forEach(function(g){ g.classList.remove('selected','dimmed'); });
    allEdges.forEach(function(l){ l.classList.remove('highlight','dimmed'); });
    if(idx === null || idx === undefined){
      mdTitle.textContent = 'Select a platform node';
      mdGrid.innerHTML = '';
      return;
    }
    var g = all[idx];
    g.classList.add('selected');
    var id = g.getAttribute('data-id');
    var n = nodes[idx];
    // Highlight connected edges
    allEdges.forEach(function(l){
      var src = l.getAttribute('x1') + ',' + l.getAttribute('y1');
      var tgt = l.getAttribute('x2') + ',' + l.getAttribute('y2');
      var p = positions[id];
      var isConnected = (src === p.x + ',' + p.y) || (tgt === p.x + ',' + p.y);
      if(isConnected){ l.classList.add('highlight'); }
    });
    // Dim non-connected nodes
    var connected = new Set([id]);
    edges.forEach(function(e){
      if(e.source === id) connected.add(e.target);
      if(e.target === id) connected.add(e.source);
    });
    all.forEach(function(g2){
      var nid = g2.getAttribute('data-id');
      if(nid !== id && !connected.has(nid)) g2.classList.add('dimmed');
    });
    renderDetail(n);
  }

  svg.querySelectorAll('.map-node').forEach(function(g){
    g.addEventListener('click', function(){
      var idx = parseInt(g.getAttribute('data-index'), 10);
      selectNode(idx);
    });
  });

  // Click empty space to deselect
  svg.addEventListener('click', function(ev){
    if(ev.target === svg) selectNode(null);
  });
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Helper: Jinja2 filters
# ---------------------------------------------------------------------------

def _basename(path: str) -> str:
    return os.path.basename(path)


def _filesizeformat(value: int) -> str:
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024  # type: ignore[assignment]
    return f"{value:.1f} TB"


# ---------------------------------------------------------------------------
# HTMLReportGenerator
# ---------------------------------------------------------------------------

class HTMLReportGenerator:
    """Generate a self-contained forensic HTML report from evidence directory."""

    def __init__(self, evidence_dir: str):
        self.evidence_dir = Path(evidence_dir)
        self.custody: dict = {}
        self.artifacts: list[dict] = []
        self.findings: list[dict] = []
        self.iocs: list[dict] = []
        self.timeline: list[dict] = []
        self.atlas_mapping: list[dict] = []
        self.risk_scores: dict = {}
        self.platforms: list[str] = []
        # New DFIR-grade data
        self.attack_narratives: list[dict] = []
        self.kill_chain_stages: list[dict] = []
        self.mitre_attack: list[dict] = []
        self.priority_actions: list[dict] = []
        self.cross_platform_correlations: list[dict] = []
        self.conversation_summary: dict = {}
        self.enhanced_risk: dict = {}
        self.conversation_secret_hunt: dict = {}

    # ----- data loading -----

    def _load_custody(self) -> None:
        path = self.evidence_dir / "CHAIN_OF_CUSTODY.json"
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                self.custody = json.load(fh)
        else:
            self.custody = {}

    def _extract_artifacts(self) -> None:
        """Extract CollectedFile records from custody data."""
        self.artifacts = self.custody.get("collected_files", [])
        if not self.artifacts and "artifacts" in self.custody:
            self.artifacts = self.custody["artifacts"]
        if not self.artifacts and "files" in self.custody:
            self.artifacts = self.custody["files"]

    def _load_analysis(self) -> None:
        """Load analysis results from analysis_results.json if available."""
        path = self.evidence_dir / "analysis_results.json"
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                self._analysis = json.load(fh)
        else:
            self._analysis = {}

    def _extract_findings(self) -> None:
        """Extract Finding records from custody data."""
        raw = self.custody.get("findings", [])
        self.findings = []
        for f in raw:
            if isinstance(f, dict):
                self.findings.append(f)
            elif isinstance(f, Finding):
                self.findings.append({
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                    "platform": f.platform,
                    "artifact_type": f.artifact_type,
                    "evidence": f.evidence,
                    "iocs": f.iocs,
                    "mitre_atlas": f.mitre_atlas,
                    "risk_score": f.risk_score,
                    "recommendation": f.recommendation,
                })

    def _extract_iocs(self) -> None:
        """Extract IOC list — prefer analysis_results.json, fallback to custody."""
        if self._analysis and "iocs" in self._analysis:
            self.iocs = self._analysis["iocs"]
        elif self.custody.get("iocs"):
            self.iocs = self.custody["iocs"]
        else:
            self.iocs = self.custody.get("ioc_results", [])

    def _extract_timeline(self) -> None:
        """Extract timeline events — prefer analysis_results.json."""
        if self._analysis and "timeline" in self._analysis:
            raw = self._analysis["timeline"]
            # Normalize severity to plain strings and ensure all fields are present
            self.timeline = []
            for e in raw:
                if not isinstance(e, dict):
                    continue
                sev = e.get("severity", "info")
                # Handle Severity.INFO enum-style strings
                if isinstance(sev, str) and sev.startswith("Severity."):
                    sev = sev.split(".", 1)[1].lower()
                elif hasattr(sev, "value"):
                    sev = sev.value
                self.timeline.append({
                    "timestamp": e.get("timestamp", ""),
                    "platform": e.get("platform", "unknown"),
                    "artifact_type": e.get("artifact_type", "unknown"),
                    "description": e.get("description", ""),
                    "severity": str(sev).lower() if sev else "info",
                    "source_path": e.get("source_path", ""),
                    "user": e.get("user"),
                    "is_collection_event": e.get("is_collection_event", False),
                    "content_preview": e.get("content_preview", ""),
                })
        elif self.custody.get("timeline"):
            self.timeline = self.custody["timeline"]
        else:
            parsed = self.custody.get("parsed_artifacts", [])
            self.timeline = []
            for pa in parsed:
                if isinstance(pa, dict) and pa.get("timestamp"):
                    self.timeline.append({
                        "timestamp": pa["timestamp"],
                        "platform": pa.get("platform", "unknown"),
                        "artifact_type": pa.get("artifact_type", "unknown"),
                        "description": pa.get("description", pa.get("artifact_type", "artifact")),
                        "severity": pa.get("severity", "info") if isinstance(pa.get("severity"), str) else "info",
                        "is_collection_event": True,
                        "content_preview": "",
                    })

    def _extract_atlas(self) -> None:
        """Extract MITRE ATLAS mapping — prefer analysis_results.json."""
        if self._analysis and "atlas_mapping" in self._analysis:
            self.atlas_mapping = self._analysis["atlas_mapping"]
        elif self.custody.get("atlas_mapping"):
            self.atlas_mapping = self.custody["atlas_mapping"]
        else:
            seen: dict[str, dict] = {}
            for f in self.findings:
                for ma in f.get("mitre_atlas", []):
                    if isinstance(ma, str):
                        seen.setdefault(ma, {"technique_id": ma, "technique": ma, "tactic": "unknown", "finding_count": 0})
                        seen[ma]["finding_count"] += 1
                    elif isinstance(ma, dict):
                        key = ma.get("technique_id", str(ma))
                        if key not in seen:
                            seen[key] = {
                                "technique_id": ma.get("technique_id", ""),
                                "technique": ma.get("technique", ""),
                                "tactic": ma.get("tactic", ""),
                                "finding_count": 0,
                            }
                        seen[key]["finding_count"] += 1
            self.atlas_mapping = list(seen.values())

    def _summarize_atlas(self) -> list[dict]:
        """Summarize ATLAS mappings by technique, collapsing duplicates."""
        counts: dict[str, dict] = {}
        for entry in self.atlas_mapping:
            if isinstance(entry, dict):
                tid = entry.get("technique_id", "unknown")
                if tid not in counts:
                    counts[tid] = {"technique_id": tid, "technique_name": entry.get("technique_name", entry.get("technique", "")), "count": 0}
                counts[tid]["count"] += 1
        return sorted(counts.values(), key=lambda x: -x["count"])

    def _extract_risk(self) -> None:
        """Extract risk scores — prefer analysis_results.json, fallback to custody."""
        if self._analysis and "risk_scores" in self._analysis and self._analysis["risk_scores"]:
            self.risk_scores = self._analysis["risk_scores"]
        elif self.custody.get("risk_scores"):
            self.risk_scores = self.custody["risk_scores"]
        else:
            total = sum(f.get("risk_score", 0) for f in self.findings)
            self.risk_scores = {
                "overall": min(total, 100),
                "categories": [],
            }
        # Normalize: accept both "score" and "overall" keys for the headline risk
        if isinstance(self.risk_scores, dict) and "score" not in self.risk_scores and "overall" in self.risk_scores:
            self.risk_scores["score"] = self.risk_scores["overall"]

    def _extract_platforms(self) -> None:
        """Derive unique platform list — prefer analysis_results.json, fallback to artifacts."""
        if self._analysis and "platforms" in self._analysis and self._analysis["platforms"]:
            self.platforms = self._analysis["platforms"]
        else:
            seen: set[str] = set()
            self.platforms = []
            for a in self.artifacts:
                p = a.get("platform", "")
                if p and p not in seen:
                    seen.add(p)
                    self.platforms.append(p)

    def _extract_dfir_data(self) -> None:
        """Extract DFIR-grade analysis data from analysis_results.json or derive it."""
        # Attack narratives — prefer analysis_results.json, normalize format
        if self._analysis and "attack_narratives" in self._analysis:
            raw_narratives = self._analysis["attack_narratives"]
            self.attack_narratives = []
            for n in raw_narratives:
                if isinstance(n, dict):
                    # Normalize severity from enum repr
                    sev = n.get("severity", "medium")
                    if isinstance(sev, str) and sev.startswith("Severity."):
                        sev = sev.split(".")[-1].lower()
                    # Normalize platforms -> affected_platforms
                    platforms = n.get("platforms", n.get("affected_platforms", []))
                    # Normalize evidence_refs
                    evidence_refs = n.get("evidence_refs", n.get("indicators", []))
                    self.attack_narratives.append({
                        "narrative_id": n.get("narrative_id", ""),
                        "title": n.get("title", "Unknown Narrative"),
                        "kill_chain_stages": n.get("kill_chain_stages", []),
                        "affected_platforms": platforms if isinstance(platforms, list) else [platforms],
                        "severity": sev.lower() if isinstance(sev, str) else sev,
                        "confidence": float(n.get("confidence", 0.5)),
                        "recommendation": n.get("recommendation", ""),
                        "evidence_refs": evidence_refs if isinstance(evidence_refs, list) else [],
                        "ioc_refs": n.get("ioc_refs", []),
                    })
                else:
                    self.attack_narratives.append({
                        "narrative_id": "", "title": str(n),
                        "kill_chain_stages": [], "affected_platforms": [],
                        "severity": "medium", "confidence": 0.5,
                        "recommendation": "", "evidence_refs": [], "ioc_refs": [],
                    })
        else:
            self.attack_narratives = _derive_attack_narratives(
                self.findings, self.iocs, self.kill_chain_stages, self.risk_scores
            ) if self.kill_chain_stages else _derive_attack_narratives(
                self.findings, self.iocs,
                _heuristic_kill_chain(self.findings, self.iocs, self.atlas_mapping),
                self.risk_scores,
            )

        # Kill chain stages — prefer analysis_results.json
        if self._analysis and "kill_chain_stages" in self._analysis:
            raw_stages = self._analysis["kill_chain_stages"]
            # Normalize: accept list of strings or list of dicts
            if raw_stages and isinstance(raw_stages[0], str):
                stage_names = set(raw_stages)
                self.kill_chain_stages = [
                    {"stage": s, "detected": s in stage_names, "evidence": []}
                    for s in KILL_CHAIN_STAGES
                ]
            else:
                self.kill_chain_stages = raw_stages
        else:
            self.kill_chain_stages = _heuristic_kill_chain(self.findings, self.iocs, self.atlas_mapping)

        # MITRE ATT&CK — prefer analysis_results.json, normalize format
        if self._analysis and "mitre_attack" in self._analysis:
            raw_attack = self._analysis["mitre_attack"]
            self.mitre_attack = []
            for t in raw_attack:
                if isinstance(t, dict):
                    self.mitre_attack.append(t)
                elif isinstance(t, str):
                    # Look up technique name from our catalog
                    info = MITRE_ATTACK_TECHNIQUES.get(t, {"name": t, "tactic": "Unknown"})
                    self.mitre_attack.append({
                        "technique_id": t,
                        "technique_name": info.get("name", t),
                        "tactic": info.get("tactic", "Unknown"),
                        "count": 1,
                    })
        else:
            self.mitre_attack = _derive_attack_mapping(self.findings, self.iocs, self.atlas_mapping)

        # Priority actions — prefer analysis_results.json
        if self._analysis and "priority_actions" in self._analysis:
            raw_actions = self._analysis["priority_actions"]
            # Normalize: accept list of strings or list of dicts
            self.priority_actions = []
            for a in raw_actions:
                if isinstance(a, str):
                    # Determine urgency from content
                    urgency = "MEDIUM"
                    if any(kw in a.upper() for kw in ("CRITICAL", "IMMEDIATELY", "IMMEDIATE", "ROTATE", "BLOCK")):
                        urgency = "CRITICAL"
                    elif any(kw in a.upper() for kw in ("URGENT", "REVIEW", "AUDIT", "DISABLE")):
                        urgency = "HIGH"
                    self.priority_actions.append({"action": a, "urgency": urgency, "evidence": []})
                elif isinstance(a, dict):
                    self.priority_actions.append(a)
        else:
            self.priority_actions = _derive_priority_actions(
                self.findings, self.iocs, self.risk_scores, self.kill_chain_stages
            )

        # Cross-platform correlations — prefer analysis_results.json
        if self._analysis and "cross_platform_correlations" in self._analysis:
            self.cross_platform_correlations = self._analysis["cross_platform_correlations"]
        else:
            self.cross_platform_correlations = _derive_cross_platform_correlations(
                self.iocs, self.findings, self.platforms
            )

        # Conversation summary — prefer analysis_results.json
        if self._analysis and "conversation_summary" in self._analysis:
            self.conversation_summary = self._analysis["conversation_summary"]
        else:
            self.conversation_summary = _derive_conversation_summary(self._analysis)

        # Enhanced risk — prefer analysis_results.json
        if self._analysis and "enhanced_risk" in self._analysis:
            self.enhanced_risk = self._analysis["enhanced_risk"]
        else:
            # Derive from risk_scores
            cat_scores = self.risk_scores.get("category_scores", {}) if isinstance(self.risk_scores, dict) else {}
            self.enhanced_risk = {}
            for cat in ("credentials", "exfiltration", "jailbreak", "autonomy"):
                score = cat_scores.get(cat, 0) if isinstance(cat_scores, dict) else 0
                self.enhanced_risk[cat] = {"score": score, "confidence": "high" if score > 0 else "low"}

        # Conversation secret hunt — prefer analysis_results.json
        if self._analysis and "conversation_secret_hunt" in self._analysis:
            self.conversation_secret_hunt = self._analysis["conversation_secret_hunt"]

    # ----- template rendering -----

    def _build_map_data(self, platform_details: list[dict]) -> dict:
        """Build node/edge data for the interactive attack-surface map."""
        sev_order = ["info", "low", "medium", "high", "critical"]
        sev_color = {
            "critical": "#ff4444",
            "high": "#ff8800",
            "medium": "#ffaa00",
            "low": "#00aaff",
            "info": "#888888",
        }
        # Per-platform IOC counts
        ioc_by_plat: dict[str, int] = {}
        for i in self.iocs:
            p = i.get("platform", "unknown")
            ioc_by_plat[p] = ioc_by_plat.get(p, 0) + 1

        nodes = []
        for p in platform_details:
            sev = p.get("max_severity", "info")
            nodes.append({
                "id": p["name"],
                "name": p["name"],
                "category": p.get("category", ""),
                "artifact_count": p.get("artifact_count", 0),
                "finding_count": p.get("finding_count", 0),
                "ioc_count": ioc_by_plat.get(p["name"], 0),
                "max_severity": sev,
                "color": sev_color.get(sev, "#888888"),
                "risk_index": sev_order.index(sev) if sev in sev_order else 0,
            })

        # Edges from cross-platform correlations (shared indicators / severity patterns)
        edges = []
        seen_edges: set[tuple] = set()
        for corr in self.cross_platform_correlations:
            plats = corr.get("platforms", [])
            for i in range(len(plats)):
                for j in range(i + 1, len(plats)):
                    a, b = plats[i], plats[j]
                    key = tuple(sorted((a, b)))
                    if key in seen_edges:
                        continue
                    seen_edges.add(key)
                    edges.append({
                        "source": a,
                        "target": b,
                        "label": corr.get("correlation_type", "correlation"),
                        "severity": corr.get("severity", "medium"),
                    })

        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def _bar(label: str, value: Any, maximum: float, color: str, display: str | None = None) -> dict:
        """One horizontal bar: width is a percentage of ``maximum`` (min 2% so a
        non-zero value is always visible)."""
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0
        pct = 0.0 if maximum <= 0 else max(2.0, round(numeric / maximum * 100))
        return {
            "label": label,
            "value": display if display is not None else value,
            "pct": f"{pct:g}%",
            "color": color,
        }

    def _build_chart_data(
        self,
        severity_counts: dict[str, int],
        overall_risk: int,
        platform_details: list[dict],
        ioc_summary: dict[str, int],
    ) -> dict[str, Any]:
        """Pre-compute every chart as plain geometry so the report renders (and
        prints) without JavaScript."""
        risk_color = (
            SEV_COLORS["critical"] if overall_risk >= 80
            else SEV_COLORS["high"] if overall_risk >= 60
            else SEV_COLORS["medium"] if overall_risk >= 40
            else SEV_COLORS["low"] if overall_risk >= 20
            else "#e63946"
        )

        # Findings by severity — bars share the largest count as their scale.
        sev_order = ["critical", "high", "medium", "low", "info"]
        sev_max = max([severity_counts.get(s, 0) for s in sev_order] + [1])
        severity_bars = [
            self._bar(s.title(), severity_counts.get(s, 0), sev_max, SEV_COLORS[s])
            for s in sev_order
        ]

        # Severity distribution — a conic-gradient donut built from cumulative stops.
        donut_total = sum(severity_counts.get(s, 0) for s in sev_order)
        stops: list[str] = []
        cursor = 0.0
        for s in sev_order:
            count = severity_counts.get(s, 0)
            if not count or not donut_total:
                continue
            end = cursor + count / donut_total * 100
            stops.append(f"{SEV_COLORS[s]} {cursor:.4g}% {end:.4g}%")
            cursor = end
        donut_gradient = f"conic-gradient({', '.join(stops)})" if stops else ""

        ioc_max = max(list(ioc_summary.values()) + [1])
        ioc_bars = [
            self._bar(t, c, ioc_max, "#e63946", display=f"{c:,}")
            for t, c in list(ioc_summary.items())[:10]
        ]

        plat_max = max([p.get("artifact_count", 0) for p in platform_details] + [1])
        platform_bars = [
            self._bar(
                p.get("name", "unknown"),
                p.get("artifact_count", 0),
                plat_max,
                SEV_COLORS.get(p.get("max_severity", "info"), SEV_COLORS["info"]),
            )
            for p in platform_details
        ]

        # Timeline activity — events bucketed per day.
        buckets: dict[str, int] = {}
        for event in self.timeline:
            day = str(event.get("timestamp", ""))[:10] or "unknown"
            buckets[day] = buckets.get(day, 0) + 1
        days = sorted(buckets)[-30:]
        day_max = max([buckets[d] for d in days] + [1])
        timeline_bars = [
            {
                "label": d[5:] if len(d) >= 10 else d,
                "value": buckets[d],
                "pct": f"{max(2, round(buckets[d] / day_max * 100)):g}%",
            }
            for d in days
        ]

        mitre_top = list(self.mitre_attack)[:8]
        mitre_max = max([t.get("count", 1) for t in mitre_top] + [1])
        mitre_bars = [
            self._bar(t.get("technique_id", "?"), t.get("count", 1), mitre_max, SEV_COLORS["high"])
            for t in mitre_top
        ]

        risk_cats = self.enhanced_risk.get("categories", {}) if isinstance(self.enhanced_risk, dict) else {}
        risk_cat_bars = []
        for cat, raw in risk_cats.items():
            score = raw.get("score", 0) if isinstance(raw, dict) else raw
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = 0.0
            level = (
                "critical" if score >= 10
                else "high" if score >= 7
                else "medium" if score >= 4
                else "low" if score > 0
                else "info"
            )
            risk_cat_bars.append(
                self._bar(cat.replace("_", " "), score, 12.5, SEV_COLORS[level], display=f"{score:g}")
            )

        return {
            "risk_color": risk_color,
            "severity_bars": severity_bars,
            "donut_gradient": donut_gradient,
            "donut_total": donut_total,
            "ioc_bars": ioc_bars,
            "platform_bars": platform_bars,
            "timeline_bars": timeline_bars,
            "mitre_bars": mitre_bars,
            "risk_cat_bars": risk_cat_bars,
        }

    def _build_context(self) -> dict[str, Any]:
        """Build the Jinja2 template context dict."""
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        overall_risk = self.risk_scores.get("score", 0) if isinstance(self.risk_scores, dict) else 0

        # Platform details
        platform_details: list[dict] = []
        plat_map: dict[str, dict] = {}
        for a in self.artifacts:
            p = a.get("platform", "unknown")
            if p not in plat_map:
                plat_map[p] = {"name": p, "category": a.get("category", ""), "artifact_count": 0, "finding_count": 0, "max_severity": "info"}
            plat_map[p]["artifact_count"] += 1
        for f in self.findings:
            p = f.get("platform", "unknown")
            if p in plat_map:
                plat_map[p]["finding_count"] += 1
                sev = f.get("severity", "info").lower()
                sev_order = ["info", "low", "medium", "high", "critical"]
                if sev_order.index(sev) > sev_order.index(plat_map[p]["max_severity"]):
                    plat_map[p]["max_severity"] = sev
        platform_details = list(plat_map.values())

        risk_details = self.risk_scores.get("category_scores", []) if isinstance(self.risk_scores, dict) else []
        # Convert category_scores dict to list format if needed
        if isinstance(risk_details, dict):
            risk_details = [{"category": k, "score": v, "details": ""} for k, v in risk_details.items()]

        # Kill chain summary
        kill_chain_detected = [s for s in self.kill_chain_stages if s.get("detected")]
        kill_chain_detected_count = len(kill_chain_detected)
        kill_chain_detected_names = [s["stage"] for s in kill_chain_detected]
        kill_chain_total = len(KILL_CHAIN_STAGES)

        # Build summary
        n_findings = len(self.findings)
        n_iocs = len(self.iocs)
        n_artifacts = len(self.artifacts)
        sev_text = ", ".join(f"{c} {s}" for s, c in severity_counts.items() if c) or "no findings"
        summary_text = (
            f"TRACE collected {n_artifacts} artifacts from {len(self.platforms)} platform(s) "
            f"({', '.join(self.platforms) or 'none detected'}). "
            f"Analysis identified {n_findings} findings ({sev_text}) "
            f"and {n_iocs} indicator(s) of compromise. "
            f"Overall risk score: {overall_risk}/100."
        )

        # Custody metadata
        skip_keys = {"collected_files", "artifacts", "findings", "parsed_artifacts", "iocs", "ioc_results", "timeline", "atlas_mapping", "risk_scores"}
        custody_metadata = {k: v for k, v in self.custody.items() if k not in skip_keys and not isinstance(v, (list, dict))}

        source_os = self.custody.get("source_os", "")
        hostname = self.custody.get("hostname", self.custody.get("host", ""))

        ioc_summary = dict(sorted(
            ((ioc.get("ioc_type", "unknown"), sum(1 for i in self.iocs if i.get("ioc_type") == ioc.get("ioc_type")))
             for ioc in self.iocs),
            key=lambda x: -x[1]
        )) if self.iocs else {}

        charts = self._build_chart_data(severity_counts, overall_risk, platform_details, ioc_summary)

        return {
            **charts,
            "report_id": str(uuid.uuid4())[:8].upper(),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "trace_version": "1.0.1",
            "evidence_dir": str(self.evidence_dir),
            "source_os": source_os,
            "hostname": hostname,
            "summary_text": summary_text,
            "risk_interpretation": _risk_interpretation(overall_risk),
            "platforms": self.platforms,
            "severity_counts": severity_counts,
            "overall_risk": overall_risk,
            "artifacts": self.artifacts,
            "findings": self.findings,
            "iocs": self.iocs,
            "ioc_summary": ioc_summary,
            "timeline": self.timeline,
            "atlas_mapping": self.atlas_mapping,
            "atlas_summary": self._summarize_atlas(),
            "mitre_attack": self.mitre_attack,
            "risk_details": risk_details,
            "platform_details": platform_details,
            "custody_metadata": custody_metadata,
            # New DFIR sections
            "attack_narratives": self.attack_narratives,
            "kill_chain_stages": self.kill_chain_stages,
            "kill_chain_detected_count": kill_chain_detected_count,
            "kill_chain_detected_names": kill_chain_detected_names,
            "kill_chain_total": kill_chain_total,
            "priority_actions": self.priority_actions,
            "cross_platform_correlations": self.cross_platform_correlations,
            "conversation_summary": self.conversation_summary,
            "enhanced_risk": self.enhanced_risk,
            "enhanced_risk_categories": self.enhanced_risk.get("categories", {}) if isinstance(self.enhanced_risk, dict) else {},
            "conversation_secret_hunt": self.conversation_secret_hunt,
            # Interactive map + charts data
            "map_data": self._build_map_data(platform_details),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "info_count": severity_counts.get("info", 0),
            "total_findings": n_findings,
            "total_iocs": n_iocs,
            "total_artifacts": n_artifacts,
            "platform_count": len(self.platforms),
        }

    def generate(self) -> Path:
        self._load_custody()
        self._load_analysis()
        self._extract_artifacts()
        self._extract_findings()
        self._extract_iocs()
        self._extract_timeline()
        self._extract_atlas()
        self._extract_risk()
        self._extract_platforms()
        self._extract_dfir_data()

        env = Environment(loader=BaseLoader(), autoescape=True)
        env.filters["basename"] = _basename
        env.filters["filesizeformat"] = _filesizeformat
        template = env.from_string(_HTML_TEMPLATE)

        context = self._build_context()
        html = template.render(**context)

        output = self.evidence_dir / "report.html"
        output.write_text(html, encoding="utf-8")
        return output
