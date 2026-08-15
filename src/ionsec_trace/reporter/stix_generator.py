"""
TRACE STIX 2.1 Generator.

Generates a valid STIX 2.1 bundle from TRACE findings and IOCs that can
be ingested by MISP, OpenCTI, or any Threat Intelligence platform.

DFIR-grade output includes: AttackPattern SDOs for ATT&CK and ATLAS,
Relationship SROs connecting Indicators to AttackPatterns, Grouping SDOs
for incident correlation, CourseOfAction SDOs with remediation steps,
Note SDOs for attack narratives, and proper confidence scores.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ionsec_trace.collector.base import (
    Finding,
    Severity,
)

# Reuse shared analysis logic
from ionsec_trace.reporter.html_report import (
    MITRE_ATTACK_TECHNIQUES,
    _derive_attack_mapping,
    _derive_attack_narratives,
    _derive_priority_actions,
    _heuristic_kill_chain,
)

# ---------------------------------------------------------------------------
# STIX 2.1 helpers
# ---------------------------------------------------------------------------

def _stix_id(obj_type: str) -> str:
    """Generate a deterministic-looking STIX ID for *obj_type*."""
    return f"{obj_type}--{uuid.uuid4()}"


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sev_to_str(sev: Any) -> str:
    if isinstance(sev, Severity):
        return sev.value
    if isinstance(sev, str):
        return sev.lower()
    return str(sev)


def _finding_to_dict(f: Any) -> dict:
    if isinstance(f, Finding):
        return {
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
        }
    if isinstance(f, dict):
        return f
    return {}


# ---------------------------------------------------------------------------
# ATT&CK technique → remediation CourseOfAction mapping
# ---------------------------------------------------------------------------

ATTACK_COURSE_OF_ACTION = {
    "T1190": {"name": "Patch Exploited Public-Facing Applications", "description": "Apply security patches to public-facing applications. Implement WAF rules. Monitor for exploit attempts."},
    "T1133": {"name": "Secure External Remote Services", "description": "Enforce MFA on all remote access. Monitor for unusual remote access patterns. Disable unused remote services."},
    "T1078": {"name": "Protect Valid Accounts", "description": "Rotate compromised credentials immediately. Enforce MFA. Monitor for anomalous login patterns."},
    "T1059": {"name": "Restrict Command and Scripting Interpreter Usage", "description": "Implement application whitelisting. Monitor script execution. Restrict PowerShell/bash access."},
    "T1203": {"name": "Patch Client Application Exploits", "description": "Keep client applications updated. Implement exploit protection (EMET-like)."},
    "T1053": {"name": "Audit Scheduled Tasks", "description": "Monitor scheduled task creation. Review existing scheduled tasks for anomalies."},
    "T1548": {"name": "Monitor Elevation Control Abuse", "description": "Implement least privilege. Monitor for privilege escalation attempts. Audit UAC bypasses."},
    "T1068": {"name": "Patch Privilege Escalation Vulnerabilities", "description": "Apply security patches. Implement least privilege. Monitor for exploitation attempts."},
    "T1087": {"name": "Monitor Account Discovery", "description": "Monitor for account enumeration commands. Implement account access auditing."},
    "T1083": {"name": "Monitor File and Directory Discovery", "description": "Monitor for unusual file discovery commands. Implement file access auditing."},
    "T1046": {"name": "Monitor Network Service Discovery", "description": "Monitor for port scanning and service enumeration. Implement network segmentation."},
    "T1005": {"name": "Protect Data on Local System", "description": "Encrypt sensitive data at rest. Implement access controls. Monitor for data staging."},
    "T1039": {"name": "Secure Network Shared Drives", "description": "Restrict share permissions. Monitor for unusual access patterns. Encrypt shared data."},
    "T1114": {"name": "Protect Email Collections", "description": "Monitor for email access anomalies. Implement email DLP controls."},
    "T1041": {"name": "Monitor C2 Exfiltration Channels", "description": "Monitor for data in C2 channels. Implement traffic analysis. Block known C2 infrastructure."},
    "T1048": {"name": "Block Alternative Exfiltration Protocols", "description": "Implement egress filtering. Monitor for DNS/ICMP tunneling. Block unauthorized protocols."},
    "T1567": {"name": "Monitor Web Service Exfiltration", "description": "Monitor outbound uploads to cloud services. Implement DLP. Block unauthorized file sharing."},
    "T1071": {"name": "Monitor Application Layer Protocol Use", "description": "Monitor for unusual protocol use. Implement TLS inspection. Block known malicious domains."},
    "T1573": {"name": "Decrypt and Inspect Encrypted Channels", "description": "Implement TLS inspection. Monitor certificate pinning. Block unauthorized encrypted tunnels."},
    "T1105": {"name": "Monitor Ingress Tool Transfers", "description": "Monitor for tool downloads. Block known malicious download sources. Implement application whitelisting."},
    "T1486": {"name": "Protect Against Data Encryption for Impact", "description": "Maintain offline backups. Monitor for mass file encryption. Implement ransomware detection."},
    "T1565": {"name": "Detect Data Manipulation", "description": "Implement file integrity monitoring. Monitor for unauthorized data changes. Maintain data backups."},
    "T1552": {"name": "Secure Unsecured Credentials", "description": "Rotate all exposed credentials immediately. Implement secrets scanning. Use a secrets manager. Remove hardcoded credentials."},
    "T1119": {"name": "Detect Automated Collection", "description": "Monitor for scripted data access patterns. Implement rate limiting on data access."},
    "T1189": {"name": "Protect Against Drive-by Compromise", "description": "Keep browsers updated. Implement content security policies. Monitor for exploit kits."},
    "T1200": {"name": "Monitor for Hardware Additions", "description": "Monitor USB/device connections. Implement device whitelisting. Physical security controls."},
    "T1592": {"name": "Monitor Victim Host Reconnaissance", "description": "Monitor for host information gathering. Implement honeypots. Detect scanning activity."},
    "T1595": {"name": "Detect Active Scanning", "description": "Monitor for port scans and vulnerability scans. Implement rate limiting. Use IDS/IPS."},
    "T1590": {"name": "Monitor Network Information Gathering", "description": "Monitor for DNS enumeration and network scanning. Implement network segmentation."},
}

# ATLAS-specific courses of action
ATLAS_COURSE_OF_ACTION = {
    "AML.T0010": {"name": "Implement Prompt Injection Detection", "description": "Deploy input sanitization and injection detection. Rate-limit API calls. Monitor for adversarial prompt patterns."},
    "AML.T0011": {"name": "Harden LLM Safety Guardrails", "description": "Strengthen safety filter coverage. Implement multi-layer content filtering. Monitor for bypass attempts."},
    "AML.T0025": {"name": "Protect Model Integrity", "description": "Verify model file integrity with hashes. Monitor for unauthorized model modifications. Implement model signing."},
    "AML.T0043": {"name": "Detect Adversarial Inputs", "description": "Implement input anomaly detection. Monitor for perturbation patterns. Use adversarial training."},
    "AML.T0048": {"name": "Secure AI Tool Integrations", "description": "Audit AI tool permissions. Implement least privilege for tool access. Monitor tool invocation patterns."},
    "AML.T0049": {"name": "Prevent AI Tool Exploitation", "description": "Implement tool call validation. Restrict tool execution scope. Monitor for tool abuse patterns."},
    "AML.T0050": {"name": "Prevent LLM Data Exfiltration", "description": "Implement output filtering. Monitor for data leakage in LLM responses. Rate-limit data access."},
    "AML.T0052": {"name": "Protect System Prompts", "description": "Implement prompt hardening. Monitor for system prompt extraction attempts. Use prompt obfuscation."},
    "AML.T0054": {"name": "Detect AI-Generated Malicious Content", "description": "Implement AI content detection. Monitor for AI-generated phishing/malware. Block suspicious outputs."},
    "AML.T0055": {"name": "Secure AI Credentials", "description": "Rotate all exposed AI API keys immediately. Implement secrets scanning. Use a secrets manager for all AI credentials."},
}


# ---------------------------------------------------------------------------
# IOC → STIX pattern mapping
# ---------------------------------------------------------------------------

_IOC_PATTERN_MAP = {
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "ipv6": lambda v: f"[ipv6-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "email": lambda v: f"[email-addr:value = '{v}']",
    "file_sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "file_sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "file_md5": lambda v: f"[file:hashes.MD5 = '{v}']",
    "file_path": lambda v: f"[file:parent_directory_ref = '{v}']",
    "cidr": lambda v: f"[ipv4-addr:value = '{v}']",
    "registry_key": lambda v: f"[windows-registry-key:key = '{v}']",
    "port": lambda v: f"[network-traffic:dst_port = {v}]",
    "user_agent": lambda v: f"[user-agent:string = '{v}']",
}


def _ioc_to_stix_pattern(ioc: dict) -> str:
    """Convert a TRACE IOC dict to a STIX 2.1 indicator pattern string."""
    ioc_type = ioc.get("ioc_type", ioc.get("type", "")).lower()
    value = ioc.get("value", ioc.get("ioc", ""))
    if not value:
        return "[unknown:value = '']"
    if ioc_type in _IOC_PATTERN_MAP:
        return _IOC_PATTERN_MAP[ioc_type](value)
    # Fallback heuristic
    import re
    if "." in value and not value.startswith("/") and "/" not in value:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            return f"[ipv4-addr:value = '{value}']"
        return f"[domain-name:value = '{value}']"
    if value.startswith(("http://", "https://")):
        return f"[url:value = '{value}']"
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
        return f"[file:hashes.'SHA-256' = '{value}']"
    if len(value) == 40 and all(c in "0123456789abcdef" for c in value.lower()):
        return f"[file:hashes.'SHA-1' = '{value}']"
    if len(value) == 32 and all(c in "0123456789abcdef" for c in value.lower()):
        return f"[file:hashes.MD5 = '{value}']"
    return f"[x-ionsec:ioc.value = '{value}']"


def _ioc_to_stix_type(ioc: dict) -> str:
    """Determine the SCO type for an IOC."""
    ioc_type = ioc.get("ioc_type", ioc.get("type", "")).lower()
    type_map = {
        "ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name",
        "url": "url", "email": "email-addr",
        "file_sha256": "file", "file_sha1": "file", "file_md5": "file",
        "file_path": "file", "cidr": "ipv4-addr",
        "registry_key": "windows-registry-key", "port": "network-traffic",
        "user_agent": "user-agent",
    }
    return type_map.get(ioc_type, "x-ionsec-ioc")


# ---------------------------------------------------------------------------
# Severity → STIX label mapping
# ---------------------------------------------------------------------------

def _sev_to_labels(sev: str) -> list[str]:
    labels = ["trace"]
    sev = sev.lower()
    if sev == "critical":
        labels.append("critical-severity")
    elif sev == "high":
        labels.append("high-severity")
    elif sev == "medium":
        labels.append("medium-severity")
    elif sev == "low":
        labels.append("low-severity")
    else:
        labels.append("informational")
    return labels


def _sev_to_confidence(sev: str) -> int:
    """Map severity to a STIX confidence score (0-100)."""
    sev = sev.lower()
    confidence_map = {
        "critical": 95, "high": 85, "medium": 65, "low": 40, "info": 20,
    }
    return confidence_map.get(sev, 30)


# ---------------------------------------------------------------------------
# STIXGenerator
# ---------------------------------------------------------------------------

class STIXGenerator:
    """Generate a STIX 2.1 bundle from TRACE findings and IOCs."""

    def __init__(self, evidence_dir: str):
        self.evidence_dir = Path(evidence_dir)
        self.custody: dict = {}
        self._analysis: dict = {}

    def _load_custody(self) -> None:
        path = self.evidence_dir / "CHAIN_OF_CUSTODY.json"
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                self.custody = json.load(fh)
        else:
            self.custody = {}

    def _load_analysis(self) -> None:
        path = self.evidence_dir / "analysis_results.json"
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                self._analysis = json.load(fh)
        else:
            self._analysis = {}

    def _analysis_or_custody(self, key: str, default=None):
        """Prefer analysis_results.json over custody data."""
        if self._analysis and key in self._analysis and self._analysis[key]:
            return self._analysis[key]
        if self.custody.get(key):
            return self.custody[key]
        return default if default is not None else []

    def _get_findings(self) -> list[dict]:
        raw = self.custody.get("findings", [])
        return [_finding_to_dict(f) for f in raw]

    def _get_iocs(self) -> list[dict]:
        result = self._analysis_or_custody("iocs")
        if result:
            return result
        result = self._analysis_or_custody("ioc_results")
        return result if result else []

    def _get_atlas_mapping(self) -> list[dict]:
        return self._analysis_or_custody("atlas_mapping")

    def _get_mitre_attack(self) -> list[dict]:
        result = self._analysis_or_custody("mitre_attack")
        if result:
            return result
        return _derive_attack_mapping(self._get_findings(), self._get_iocs(), self._get_atlas_mapping())

    def _get_attack_narratives(self) -> list[dict]:
        result = self._analysis_or_custody("attack_narratives")
        if result:
            return result
        findings = self._get_findings()
        iocs = self._get_iocs()
        risk_scores = self._analysis_or_custody("risk_scores", {})
        kill_chain = self._analysis_or_custody("kill_chain_stages")
        if not kill_chain:
            kill_chain = _heuristic_kill_chain(findings, iocs, self._get_atlas_mapping())
        return _derive_attack_narratives(findings, iocs, kill_chain, risk_scores)

    def _get_priority_actions(self) -> list[dict]:
        result = self._analysis_or_custody("priority_actions")
        if result:
            return result
        findings = self._get_findings()
        iocs = self._get_iocs()
        risk_scores = self._analysis_or_custody("risk_scores", {})
        kill_chain = self._analysis_or_custody("kill_chain_stages")
        if not kill_chain:
            kill_chain = _heuristic_kill_chain(findings, iocs, self._get_atlas_mapping())
        return _derive_priority_actions(findings, iocs, risk_scores, kill_chain)

    def generate(self) -> Path:
        """Generate a STIX 2.1 bundle and write to evidence_dir/report.stix.json."""
        self._load_custody()
        self._load_analysis()

        findings = self._get_findings()
        iocs = self._get_iocs()
        atlas_mapping = self._get_atlas_mapping()
        mitre_attack = self._get_mitre_attack()
        narratives = self._get_attack_narratives()
        priority_actions = self._get_priority_actions()

        objects: list[dict] = []
        ts = _timestamp()

        # Track IDs for relationships
        indicator_ids: list[str] = []
        indicator_by_value: dict[str, str] = {}  # value -> indicator_id
        attack_pattern_ids: dict[str, str] = {}  # technique_id -> attack_pattern_id
        observed_ids: list[str] = []
        coa_ids: list[str] = []

        # ---- 1. Identity (TRACE) ----
        identity_id = _stix_id("identity")
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": ts,
            "modified": ts,
            "name": "TRACE",
            "identity_class": "organization",
            "sectors": ["technology", "cybersecurity"],
            "contact_information": "trace@ionsec.io",
        })

        # ---- 2. Indicators (from IOCs) ----
        for ioc in iocs:
            indicator_id = _stix_id("indicator")
            indicator_ids.append(indicator_id)
            ioc_val = ioc.get("value", ioc.get("ioc", ""))
            indicator_by_value[ioc_val] = indicator_id
            pattern = _ioc_to_stix_pattern(ioc)
            severity = _sev_to_str(ioc.get("severity", "info"))
            labels = _sev_to_labels(severity)
            confidence = _sev_to_confidence(severity)
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "name": f"TRACE IOC: {ioc_val}",
                "description": ioc.get("description", f"Indicator of compromise detected by TRACE: {ioc_val}"),
                "indicator_types": ["malicious-activity", "suspicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ts,
                "confidence": confidence,
                "labels": labels,
                "x_trace_ioc_type": ioc.get("ioc_type", ioc.get("type", "")),
                "x_trace_source": ioc.get("source", ioc.get("source_file", "")),
                "x_trace_platform": ioc.get("platform", ""),
            })

        # ---- 3. Observed Data (from findings) ----
        for f in findings:
            observed_id = _stix_id("observed-data")
            observed_ids.append(observed_id)
            objects_ref = []
            for f_ioc in f.get("iocs", []):
                f_ioc_str = str(f_ioc)
                if f_ioc_str in indicator_by_value:
                    objects_ref.append(indicator_by_value[f_ioc_str])

            severity = _sev_to_str(f.get("severity", "info"))
            objects.append({
                "type": "observed-data",
                "spec_version": "2.1",
                "id": observed_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "first_observed": f.get("timestamp", ts),
                "last_observed": f.get("timestamp", ts),
                "number_observed": 1,
                "object_refs": objects_ref if objects_ref else [],
                "x_trace_finding_id": f.get("id", ""),
                "x_trace_title": f.get("title", ""),
                "x_trace_description": f.get("description", ""),
                "x_trace_severity": severity,
                "x_trace_platform": f.get("platform", ""),
                "x_trace_risk_score": f.get("risk_score", 0),
                "labels": _sev_to_labels(severity),
            })

        # ---- 4. AttackPattern SDOs for ATT&CK techniques ----
        for tech in mitre_attack:
            # Normalize: accept both dict and string formats
            if isinstance(tech, str):
                tech = {"technique_id": tech, "technique_name": tech, "count": 1, "tactic": "Unknown", "evidence": []}
            attack_id = tech.get("technique_id", "")
            if not attack_id or attack_id in attack_pattern_ids:
                continue
            ap_id = _stix_id("attack-pattern")
            attack_pattern_ids[attack_id] = ap_id
            info = MITRE_ATTACK_TECHNIQUES.get(attack_id, {"name": attack_id, "tactic": "Unknown"})
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "name": tech.get("technique_name", info["name"]),
                "description": (tech.get("evidence", [""])[0] if isinstance(tech.get("evidence"), list) and tech.get("evidence") else str(tech.get("evidence", ""))) or tech.get("technique_name", attack_id),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": attack_id,
                        "url": f"https://attack.mitre.org/techniques/{attack_id}/",
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": info.get("tactic", "Unknown").lower().replace(" ", "-"),
                    }
                ],
                "labels": ["trace", "mitre-attack"],
                "confidence": min(85, 50 + tech.get("count", 0) * 15),
                "x_trace_technique_id": attack_id,
                "x_trace_tactic": tech.get("tactic", info.get("tactic", "Unknown")),
            })

        # ---- 5. AttackPattern SDOs for ATLAS techniques ----
        atlas_ap_ids: dict[str, str] = {}
        for entry in atlas_mapping:
            if not isinstance(entry, dict):
                continue
            atlas_id = entry.get("technique_id", "")
            if atlas_id in atlas_ap_ids:
                continue
            ap_id = _stix_id("attack-pattern")
            atlas_ap_ids[atlas_id] = ap_id
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "name": entry.get("technique_name", atlas_id),
                "description": entry.get("description", ""),
                "external_references": [
                    {
                        "source_name": "mitre-atlas",
                        "external_id": atlas_id,
                        "url": f"https://atlas.mitre.org/techniques/{atlas_id}/",
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-atlas",
                        "phase_name": entry.get("platforms", ["unknown"])[0] if isinstance(entry.get("platforms"), list) else "unknown",
                    }
                ],
                "labels": ["trace", "mitre-atlas"],
                "confidence": min(80, 50 + entry.get("finding_count", 0) * 10) if "finding_count" in entry else 65,
                "x_trace_technique_id": atlas_id,
                "x_trace_framework": "atlas",
            })

        # ---- 6. Relationship SROs — Indicators → AttackPatterns ----
        # For each ATT&CK technique with evidence, create relationships from IOCs
        for tech in mitre_attack:
            if isinstance(tech, str):
                tech = {"technique_id": tech, "technique_name": tech, "count": 1, "tactic": "Unknown", "evidence": []}
            attack_id = tech.get("technique_id", "")
            ap_id = attack_pattern_ids.get(attack_id)
            if not ap_id:
                continue
            # Create relationship from each related indicator
            evidence_list = tech.get("evidence", [])
            for ev in evidence_list[:3]:  # Limit to 3 relationships per technique
                rel_id = _stix_id("relationship")
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created_by_ref": identity_id,
                    "created": ts,
                    "modified": ts,
                    "relationship_type": "indicates",
                    "source_ref": indicator_ids[0] if indicator_ids else identity_id,
                    "target_ref": ap_id,
                    "description": f"IOC indicates ATT&CK technique {attack_id}: {ev}",
                    "confidence": 70,
                    "labels": ["trace"],
                })

        # ATLAS indicator relationships
        for atlas_id, ap_id in atlas_ap_ids.items():
            rel_id = _stix_id("relationship")
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "relationship_type": "indicates",
                "source_ref": indicator_ids[0] if indicator_ids else identity_id,
                "target_ref": ap_id,
                "description": f"IOC indicates ATLAS technique {atlas_id}",
                "confidence": 65,
                "labels": ["trace", "mitre-atlas"],
            })

        # ---- 7. Grouping SDO for incident correlation ----
        grouping_id = _stix_id("grouping")
        grouping_refs = [identity_id, *indicator_ids, *observed_ids, *attack_pattern_ids.values(), *atlas_ap_ids.values()]
        objects.append({
            "type": "grouping",
            "spec_version": "2.1",
            "id": grouping_id,
            "created_by_ref": identity_id,
            "created": ts,
            "modified": ts,
            "name": "TRACE Incident Correlation",
            "description": f"Correlation group for TRACE forensic findings. {len(findings)} findings, {len(iocs)} IOCs across {len({f.get('platform', 'unknown') for f in findings}) or 1} platform(s).",
            "context": "suspicious-activity",
            "object_refs": grouping_refs[:100],  # STIX limit
            "labels": ["trace", "incident-correlation"],
        })

        # ---- 8. CourseOfAction SDOs with actual remediation steps ----
        seen_coa_names: set[str] = set()

        # From ATT&CK techniques
        for tech in mitre_attack:
            if isinstance(tech, str):
                tech = {"technique_id": tech, "technique_name": tech, "count": 1, "tactic": "Unknown", "evidence": []}
            attack_id = tech.get("technique_id", "")
            coa_info = ATTACK_COURSE_OF_ACTION.get(attack_id)
            if coa_info and coa_info["name"] not in seen_coa_names:
                seen_coa_names.add(coa_info["name"])
                coa_id = _stix_id("course-of-action")
                coa_ids.append(coa_id)
                objects.append({
                    "type": "course-of-action",
                    "spec_version": "2.1",
                    "id": coa_id,
                    "created_by_ref": identity_id,
                    "created": ts,
                    "modified": ts,
                    "name": coa_info["name"],
                    "description": coa_info["description"],
                    "labels": ["trace", "remediation", "mitre-attack"],
                    "confidence": 80,
                    "x_trace_technique_id": attack_id,
                })

        # From ATLAS techniques
        for entry in atlas_mapping:
            if not isinstance(entry, dict):
                continue
            atlas_id = entry.get("technique_id", "")
            coa_info = ATLAS_COURSE_OF_ACTION.get(atlas_id)
            if coa_info and coa_info["name"] not in seen_coa_names:
                seen_coa_names.add(coa_info["name"])
                coa_id = _stix_id("course-of-action")
                coa_ids.append(coa_id)
                objects.append({
                    "type": "course-of-action",
                    "spec_version": "2.1",
                    "id": coa_id,
                    "created_by_ref": identity_id,
                    "created": ts,
                    "modified": ts,
                    "name": coa_info["name"],
                    "description": coa_info["description"],
                    "labels": ["trace", "remediation", "mitre-atlas"],
                    "confidence": 80,
                    "x_trace_technique_id": atlas_id,
                    "x_trace_framework": "atlas",
                })

        # From priority actions (top 5)
        for action in priority_actions[:5]:
            if isinstance(action, str):
                action = {"action": action, "urgency": "MEDIUM", "evidence": []}
            coa_name = action.get("action", "Remediation action")[:80]
            if coa_name not in seen_coa_names:
                seen_coa_names.add(coa_name)
                coa_id = _stix_id("course-of-action")
                coa_ids.append(coa_id)
                objects.append({
                    "type": "course-of-action",
                    "spec_version": "2.1",
                    "id": coa_id,
                    "created_by_ref": identity_id,
                    "created": ts,
                    "modified": ts,
                    "name": coa_name,
                    "description": f"{action.get('action', '')} Urgency: {action.get('urgency', 'MEDIUM')}. Evidence: {'; '.join(action.get('evidence', [])[:3])}",
                    "labels": ["trace", "remediation", f"urgency-{action.get('urgency', 'MEDIUM').lower()}"],
                    "confidence": 90 if action.get("urgency") == "CRITICAL" else 75,
                    "x_trace_category": action.get("category", ""),
                })

        # From finding recommendations (fallback)
        for f in findings:
            rec = f.get("recommendation", "")
            if rec and rec not in seen_coa_names:
                seen_coa_names.add(rec)
                coa_id = _stix_id("course-of-action")
                coa_ids.append(coa_id)
                objects.append({
                    "type": "course-of-action",
                    "spec_version": "2.1",
                    "id": coa_id,
                    "created_by_ref": identity_id,
                    "created": ts,
                    "modified": ts,
                    "name": f"Remediation: {f.get('title', 'Finding')}",
                    "description": rec,
                    "labels": ["trace", "remediation"],
                    "confidence": _sev_to_confidence(_sev_to_str(f.get("severity", "info"))),
                    "x_trace_finding_id": f.get("id", ""),
                })

        # ---- 9. Note SDOs for attack narratives ----
        for narrative in narratives:
            note_id = _stix_id("note")
            # Build content from narrative
            content_parts = [
                f"**{narrative.get('title', 'Untitled Narrative')}**",
                f"Severity: {narrative.get('severity', 'unknown').upper()}",
                f"Confidence: {narrative.get('confidence', 'medium')}",
                f"Affected Platforms: {', '.join(narrative.get('affected_platforms', []))}",
                f"Kill Chain Stages: {', '.join(narrative.get('kill_chain_stages', []))}",
                "",
                f"Recommendation: {narrative.get('recommendation', 'No recommendation')}",
            ]
            objects.append({
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "content": "\n".join(content_parts),
                "authors": [identity_id],
                "labels": ["trace", "attack-narrative", f"severity-{narrative.get('severity', 'unknown').lower()}"],
                "confidence": _sev_to_confidence(narrative.get("severity", "medium")),
                "x_trace_narrative_title": narrative.get("title", ""),
                "x_trace_kill_chain_stages": narrative.get("kill_chain_stages", []),
                "x_trace_affected_platforms": narrative.get("affected_platforms", []),
            })

        # ---- 10. Report ----
        report_id = _stix_id("report")
        object_refs = ([identity_id] + indicator_ids + observed_ids
                       + list(attack_pattern_ids.values()) + list(atlas_ap_ids.values())
                       + coa_ids
                       + [obj["id"] for obj in objects if obj["type"] == "note"]
                       + [grouping_id])

        report_description = (
            f"TRACE forensic report. "
            f"{len(findings)} findings, {len(iocs)} IOCs, "
            f"{len(mitre_attack)} ATT&CK techniques, {len(atlas_mapping)} ATLAS techniques, "
            f"{len(narratives)} attack narratives detected across "
            f"{', '.join({f.get('platform', 'unknown') for f in findings}) or 'unknown'} platform(s)."
        )

        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created_by_ref": identity_id,
            "created": ts,
            "modified": ts,
            "name": "TRACE Forensic Report",
            "description": report_description,
            "published": ts,
            "report_types": ["threat-report", "forensic"],
            "object_refs": object_refs[:500],  # STIX practical limit
            "labels": ["trace", "forensic"],
            "confidence": 85,
            "x_trace_version": "1.0.1",
            "x_trace_evidence_dir": str(self.evidence_dir),
        })

        # ---- Bundle ----
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        output = self.evidence_dir / "report.stix.json"
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2, default=str, ensure_ascii=False)
        return output
