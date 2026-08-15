"""
TRACE JSON Report Generator.

Generates a structured JSON report matching the TRACE JSON schema
with all findings, IOCs, timeline, risk scores, MITRE ATLAS mapping,
attack narratives, kill chain analysis, MITRE ATT&CK mapping,
priority actions, cross-platform correlations, conversation summary,
and enhanced risk breakdown.
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

# Reuse DFIR analysis logic from html_report (shared heuristics)
from ionsec_trace.reporter.html_report import (
    _derive_attack_mapping,
    _derive_attack_narratives,
    _derive_conversation_summary,
    _derive_cross_platform_correlations,
    _derive_priority_actions,
    _heuristic_kill_chain,
)


class JSONReportGenerator:
    """Generate a structured JSON report from the chain-of-custody evidence directory."""

    SCHEMA_VERSION = "2.0.0"
    TOOL_VERSION = "1.0.1"

    def __init__(self, evidence_dir: str):
        self.evidence_dir = Path(evidence_dir)
        self.custody: dict = {}
        self._analysis: dict = {}

    # ----- data loading -----

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

    # ----- helpers -----

    @staticmethod
    def _sev_to_str(sev: Any) -> str:
        if isinstance(sev, Severity):
            return sev.value
        if isinstance(sev, str):
            return sev.lower()
        return str(sev)

    @staticmethod
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

    def _get_artifacts(self) -> list[dict]:
        for key in ("collected_files", "artifacts", "files"):
            val = self.custody.get(key, [])
            if val:
                return val
        return []

    def _get_findings(self) -> list[dict]:
        raw = self.custody.get("findings", [])
        return [self._finding_to_dict(f) for f in raw]

    def _get_iocs(self) -> list[dict]:
        result = self._analysis_or_custody("iocs")
        return result if result else self._analysis_or_custody("ioc_results")

    def _get_timeline(self) -> list[dict]:
        result = self._analysis_or_custody("timeline")
        if result:
            return result
        parsed = self.custody.get("parsed_artifacts", [])
        events: list[dict] = []
        for pa in parsed:
            if isinstance(pa, dict) and pa.get("timestamp"):
                events.append({
                    "timestamp": pa["timestamp"],
                    "platform": pa.get("platform", "unknown"),
                    "description": pa.get("artifact_type", "artifact"),
                    "severity": pa.get("severity", "info") if isinstance(pa.get("severity"), str) else "info",
                })
        return events

    def _get_atlas_mapping(self) -> list[dict]:
        result = self._analysis_or_custody("atlas_mapping")
        return result if result else []

    def _get_risk_scores(self) -> dict:
        result = self._analysis_or_custody("risk_scores", {})
        return result if result else {}

    def _get_platforms(self) -> list[dict]:
        artifacts = self._get_artifacts()
        plat_map: dict[str, dict] = {}
        for a in artifacts:
            p = a.get("platform", "unknown")
            if p not in plat_map:
                plat_map[p] = {
                    "name": p,
                    "category": a.get("category", ""),
                    "artifact_count": 0,
                    "finding_count": 0,
                    "max_severity": "info",
                }
            plat_map[p]["artifact_count"] += 1
        for f in self._get_findings():
            p = f.get("platform", "unknown")
            if p in plat_map:
                plat_map[p]["finding_count"] += 1
                sev = self._sev_to_str(f.get("severity", "info"))
                sev_order = ["info", "low", "medium", "high", "critical"]
                if sev_order.index(sev) > sev_order.index(plat_map[p]["max_severity"]):
                    plat_map[p]["max_severity"] = sev
        return list(plat_map.values())

    def _get_attack_narratives(self) -> list[dict]:
        """Get attack narratives — prefer analysis_results.json, else derive."""
        result = self._analysis_or_custody("attack_narratives")
        if result:
            return result
        findings = self._get_findings()
        iocs = self._get_iocs()
        risk_scores = self._get_risk_scores()
        kill_chain = self._get_kill_chain_stages()
        return _derive_attack_narratives(findings, iocs, kill_chain, risk_scores)

    def _get_kill_chain_stages(self) -> list[dict]:
        """Get kill chain stages — prefer analysis_results.json, else derive."""
        result = self._analysis_or_custody("kill_chain_stages")
        if result:
            return result
        return _heuristic_kill_chain(self._get_findings(), self._get_iocs(), self._get_atlas_mapping())

    def _get_mitre_attack(self) -> list[dict]:
        """Get MITRE ATT&CK mapping — prefer analysis_results.json, else derive."""
        result = self._analysis_or_custody("mitre_attack")
        if result:
            return result
        return _derive_attack_mapping(self._get_findings(), self._get_iocs(), self._get_atlas_mapping())

    def _get_priority_actions(self) -> list[dict]:
        """Get priority actions — prefer analysis_results.json, else derive."""
        result = self._analysis_or_custody("priority_actions")
        if result:
            return result
        return _derive_priority_actions(
            self._get_findings(), self._get_iocs(),
            self._get_risk_scores(), self._get_kill_chain_stages()
        )

    def _get_cross_platform_correlations(self) -> list[dict]:
        """Get cross-platform correlations — prefer analysis_results.json, else derive."""
        result = self._analysis_or_custody("cross_platform_correlations")
        if result:
            return result
        platforms = [p.get("name", "") for p in self._get_platforms()]
        return _derive_cross_platform_correlations(self._get_iocs(), self._get_findings(), platforms)

    def _get_conversation_summary(self) -> dict:
        """Get conversation summary — prefer analysis_results.json, else derive."""
        result = self._analysis_or_custody("conversation_summary")
        if result and isinstance(result, dict):
            return result
        return _derive_conversation_summary(self._analysis)

    def _get_enhanced_risk(self) -> dict:
        """Get enhanced risk breakdown — prefer analysis_results.json, else derive from risk_scores."""
        result = self._analysis_or_custody("enhanced_risk")
        if result and isinstance(result, dict):
            return result
        risk_scores = self._get_risk_scores()
        cat_scores = risk_scores.get("category_scores", {}) if isinstance(risk_scores, dict) else {}
        enhanced = {}
        for cat in ("credentials", "exfiltration", "jailbreak", "autonomy"):
            score = cat_scores.get(cat, 0) if isinstance(cat_scores, dict) else 0
            enhanced[cat] = {"score": score, "confidence": "high" if score > 0 else "low"}
        return enhanced

    def _get_conversation_secret_hunt(self) -> dict:
        """Get conversation secret hunt results — prefer analysis_results.json."""
        result = self._analysis_or_custody("conversation_secret_hunt", {})
        return result if isinstance(result, dict) else {}

    # ----- report generation -----

    def generate(self) -> Path:
        """Generate the JSON report and write to evidence_dir/report.json."""
        self._load_custody()
        self._load_analysis()

        artifacts = self._get_artifacts()
        findings = self._get_findings()
        iocs = self._get_iocs()
        timeline = self._get_timeline()
        atlas_mapping = self._get_atlas_mapping()
        risk_scores = self._get_risk_scores()
        platforms = self._get_platforms()
        attack_narratives = self._get_attack_narratives()
        kill_chain_stages = self._get_kill_chain_stages()
        mitre_attack = self._get_mitre_attack()
        priority_actions = self._get_priority_actions()
        cross_platform_correlations = self._get_cross_platform_correlations()
        conversation_summary = self._get_conversation_summary()
        enhanced_risk = self._get_enhanced_risk()
        conversation_secret_hunt = self._get_conversation_secret_hunt()

        # Severity counts
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = self._sev_to_str(f.get("severity", "info"))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report_id = str(uuid.uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()

        # Skip large/nested keys for metadata
        skip_keys = {
            "collected_files", "artifacts", "findings", "parsed_artifacts",
            "iocs", "ioc_results", "timeline", "atlas_mapping", "risk_scores",
            "attack_narratives", "kill_chain_stages", "mitre_attack",
            "priority_actions", "cross_platform_correlations",
            "conversation_summary", "enhanced_risk",
        }
        metadata = {
            "report_id": report_id,
            "generated_at": generated_at,
            "tool": "TRACE",
            "version": self.TOOL_VERSION,
            "schema_version": self.SCHEMA_VERSION,
        }
        for k, v in self.custody.items():
            if k not in skip_keys and not isinstance(v, (list, dict)):
                metadata[k] = v

        # ATLAS summary
        atlas_summary: list[dict] = []
        seen_techniques: dict[str, dict] = {}
        for entry in atlas_mapping:
            if isinstance(entry, dict):
                tid = entry.get("technique_id", "unknown")
                if tid not in seen_techniques:
                    seen_techniques[tid] = {
                        "technique_id": tid,
                        "technique_name": entry.get("technique_name", entry.get("technique", "")),
                        "description": entry.get("description", ""),
                        "platforms": entry.get("platforms", []),
                        "count": 0,
                    }
                seen_techniques[tid]["count"] += 1
        atlas_summary = sorted(seen_techniques.values(), key=lambda x: -x["count"])

        report: dict[str, Any] = {
            "schema_version": self.SCHEMA_VERSION,
            "metadata": metadata,
            "platforms": platforms,
            "evidence_manifest": artifacts,
            "findings": findings,
            "iocs": iocs,
            "timeline": timeline,
            "severity_summary": severity_counts,
            "risk_scores": risk_scores,
            "atlas_mapping": atlas_mapping,
            "atlas_summary": atlas_summary,
            # New DFIR-grade fields
            "attack_narratives": attack_narratives,
            "kill_chain_stages": kill_chain_stages,
            "mitre_attack": mitre_attack,
            "priority_actions": priority_actions,
            "cross_platform_correlations": cross_platform_correlations,
            "conversation_summary": conversation_summary,
            "enhanced_risk": enhanced_risk,
            "conversation_secret_hunt": conversation_secret_hunt,
        }

        output = self.evidence_dir / "report.json"
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str, ensure_ascii=False)
        return output
