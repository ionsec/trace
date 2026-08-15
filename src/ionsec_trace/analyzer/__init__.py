"""
TRACE Analyzer Package — timeline, IOC extraction, ATLAS mapping, risk scoring,
and conversation content parsing.
"""

from ionsec_trace.analyzer.conversation_export import export_conversation_package
from ionsec_trace.analyzer.conversation_parser import (
    ConversationParser,
    ConversationSession,
    ConversationTurn,
)
from ionsec_trace.analyzer.conversation_secret_hunt import (
    ConversationSecretFinding,
    ConversationSecretHunt,
    ConversationSecretHuntResult,
)
from ionsec_trace.analyzer.ioc_extractor import IOC, IOCExtractor
from ionsec_trace.analyzer.mitre_atlas import ATLAS_TECHNIQUES, ATLASMapper, ATLASTechniqueMatch
from ionsec_trace.analyzer.risk_scorer import RiskScore, RiskScorer
from ionsec_trace.analyzer.timeline import TimelineEvent, UnifiedTimeline

# Optional imports — these may fail if the modules have issues
try:
    from ionsec_trace.analyzer.enhanced_risk_scorer import (
        CATEGORY_LABELS,  # noqa: F401  (re-exported via __all__)
        CATEGORY_NAMES,  # noqa: F401
        AIIndicator,  # noqa: F401
        AttackNarrative,  # noqa: F401
        DetailedRiskScore,  # noqa: F401
        EnhancedRiskScorer,  # noqa: F401
        KillChainStage,  # noqa: F401
    )
    _HAS_ENHANCED_RISK_SCORER = True
except Exception:
    _HAS_ENHANCED_RISK_SCORER = False

try:
    from ionsec_trace.analyzer.ai_ioc_detector import AIIOCDetector as _AIIOCDetector
    _HAS_AI_IOC_DETECTOR = True
except Exception:
    _HAS_AI_IOC_DETECTOR = False

__all__ = [
    "ATLAS_TECHNIQUES",
    "IOC",
    "ATLASMapper",
    "ATLASTechniqueMatch",
    "ConversationParser",
    "ConversationSecretFinding",
    "ConversationSecretHunt",
    "ConversationSecretHuntResult",
    "ConversationSession",
    "ConversationTurn",
    "IOCExtractor",
    "RiskScore",
    "RiskScorer",
    "TimelineEvent",
    "UnifiedTimeline",
    "export_conversation_package",
]

if _HAS_ENHANCED_RISK_SCORER:
    __all__.extend([
        "CATEGORY_LABELS",
        "CATEGORY_NAMES",
        "AIIndicator",
        "AttackNarrative",
        "DetailedRiskScore",
        "EnhancedRiskScorer",
        "KillChainStage",
    ])

if _HAS_AI_IOC_DETECTOR:
    __all__.extend(["AIIOCDetector"])


def analyze_all(evidence_dir, mitre_atlas=False, risk_score=False, ai_ioc=False, verbose=False):
    """Run the full analysis pipeline on an evidence directory."""
    from rich.console import Console
    console = Console()
    console.print(f"[bold]Analyzing evidence from {evidence_dir}[/bold]")

    # Timeline
    timeline = UnifiedTimeline(evidence_dir).load()
    if verbose:
        console.print(timeline)

    # IOC Extraction
    ioc_ext = IOCExtractor(evidence_dir).extract()
    if verbose:
        console.print(ioc_ext)

    # ATLAS mapping (if requested)
    if mitre_atlas:
        ATLASMapper()
        console.print("[dim]ATLAS mapping requires parsed findings — pass Findings to ATLASMapper.map_finding()[/dim]")

    # Risk scoring (if requested)
    if risk_score:
        RiskScorer()
        console.print("[dim]Risk scoring requires findings and IOCs — pass them to RiskScorer.calculate_platform_risk()[/dim]")

    # AI-specific IOC detection
    ai_detector = None
    if ai_ioc and _HAS_AI_IOC_DETECTOR:
        ai_detector = _AIIOCDetector(evidence_dir).detect()
        if verbose:
            console.print(ai_detector)
        console.print(f"  AI-specific IOCs found: {len(ai_detector.indicators)}")

    # Conversation content parsing
    conv_parser = ConversationParser.from_evidence_dir(evidence_dir)
    if verbose:
        for session in conv_parser.sessions:
            console.print(f"  Session {session.session_id}: {len(session.turns)} turns")
        for finding in conv_parser.findings:
            console.print(f"  [{finding.severity.value}] {finding.title}")

    console.print("[bold green]Analysis complete.[/bold green]")
    console.print(f"  Timeline events: {len(timeline.events)}")
    console.print(f"  IOCs found: {len(ioc_ext.iocs)}")
    console.print(f"  IOC summary: {ioc_ext.summary_by_type()}")
    console.print(f"  Conversation sessions: {len(conv_parser.sessions)}")
    console.print(f"  Conversation turns: {len(conv_parser.turns)}")
    console.print(f"  Conversation findings: {len(conv_parser.findings)}")

    result = {
        "timeline": timeline,
        "iocs": ioc_ext,
        "conversation_parser": conv_parser,
    }
    if ai_detector:
        result["ai_iocs"] = ai_detector

    return result
