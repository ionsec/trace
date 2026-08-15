"""
TRACE Reporter — HTML, JSON, and STIX report generators.

Usage:
    from ionsec_trace.reporter import generate_all
    generate_all("/path/to/evidence_dir")
"""

from pathlib import Path

from ionsec_trace.reporter.html_report import HTMLReportGenerator
from ionsec_trace.reporter.json_report import JSONReportGenerator
from ionsec_trace.reporter.stix_generator import STIXGenerator

__all__ = [
    "HTMLReportGenerator",
    "JSONReportGenerator",
    "STIXGenerator",
    "generate_all",
]


def generate_all(evidence_dir: str, formats: list[str] | None = None) -> dict[str, Path]:
    """Generate all TRACE reports from the evidence directory.

    Each reporter reads from CHAIN_OF_CUSTODY.json and analysis_results.json
    in the evidence directory. The analysis_results.json file should contain
    enriched DFIR data including attack_narratives, kill_chain_stages,
    mitre_attack, priority_actions, cross_platform_correlations,
    conversation_summary, and enhanced_risk fields.

    Args:
        evidence_dir: Path to the evidence directory containing
            CHAIN_OF_CUSTODY.json and collected artifacts.
        formats: List of formats to generate. Defaults to all formats.
            Valid options: "html", "json", "stix".

    Returns:
        Dict mapping format name to the output file path.
    """
    if formats is None:
        formats = ["html", "json", "stix"]

    results: dict[str, Path] = {}

    if "html" in formats:
        gen = HTMLReportGenerator(evidence_dir)
        results["html"] = gen.generate()

    if "json" in formats:
        gen = JSONReportGenerator(evidence_dir)
        results["json"] = gen.generate()

    if "stix" in formats:
        gen = STIXGenerator(evidence_dir)
        results["stix"] = gen.generate()

    return results
