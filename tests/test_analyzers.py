"""Tests for TRACE analyzers: timeline, IOC extraction, ATLAS mapping, risk scoring."""

import json

from ionsec_trace.analyzer.ioc_extractor import IOC, IOCExtractor
from ionsec_trace.analyzer.mitre_atlas import ATLAS_TECHNIQUES, ATLASMapper, ATLASTechniqueMatch
from ionsec_trace.analyzer.risk_scorer import RiskScore, RiskScorer
from ionsec_trace.analyzer.timeline import TimelineEvent, UnifiedTimeline
from ionsec_trace.collector.base import Finding, Severity

# ===========================================================================
# Timeline Tests
# ===========================================================================

class TestUnifiedTimeline:
    """Test UnifiedTimeline loading and event building."""

    def test_load_from_chain_of_custody(self, fake_evidence_dir):
        tl = UnifiedTimeline(str(fake_evidence_dir))
        result = tl.load()
        assert isinstance(result, UnifiedTimeline)
        assert len(tl.events) >= 1

    def test_load_returns_self(self, fake_evidence_dir):
        tl = UnifiedTimeline(str(fake_evidence_dir))
        assert tl.load() is tl

    def test_events_have_required_fields(self, fake_evidence_dir):
        tl = UnifiedTimeline(str(fake_evidence_dir))
        tl.load()
        for ev in tl.events:
            assert isinstance(ev, TimelineEvent)
            assert hasattr(ev, "timestamp")
            assert hasattr(ev, "platform")
            assert hasattr(ev, "artifact_type")
            assert hasattr(ev, "description")
            assert hasattr(ev, "severity")
            assert hasattr(ev, "source_path")

    def test_events_sorted_chronologically(self, fake_evidence_dir):
        tl = UnifiedTimeline(str(fake_evidence_dir))
        tl.load()
        timestamps = [ev.timestamp for ev in tl.events]
        assert timestamps == sorted(timestamps)

    def test_empty_evidence_dir(self, minimal_evidence_dir):
        tl = UnifiedTimeline(str(minimal_evidence_dir))
        tl.load()
        # No files in the custody data → no events
        assert isinstance(tl.events, list)

    def test_group_by_platform(self, fake_evidence_dir):
        tl = UnifiedTimeline(str(fake_evidence_dir))
        tl.load()
        groups = tl.group_by_platform()
        assert isinstance(groups, dict)
        # All events should be grouped
        total = sum(len(v) for v in groups.values())
        assert total == len(tl.events)

    def test_group_by_user(self, fake_evidence_dir):
        tl = UnifiedTimeline(str(fake_evidence_dir))
        tl.load()
        groups = tl.group_by_user()
        assert isinstance(groups, dict)

    def test_to_json(self, fake_evidence_dir):
        tl = UnifiedTimeline(str(fake_evidence_dir))
        tl.load()
        j = tl.to_json()
        parsed = json.loads(j)
        assert isinstance(parsed, list)

    def test_dir_walk_fallback(self, tmp_path):
        """When no CHAIN_OF_CUSTODY.json, timeline should fall back to dir walk."""
        # Create some files without a custody JSON
        subdir = tmp_path / "ollama"
        subdir.mkdir()
        (subdir / "config.json").write_text('{"model": "test"}', encoding="utf-8")
        tl = UnifiedTimeline(str(tmp_path))
        tl.load()
        assert len(tl.events) >= 1

    def test_timeline_event_to_dict(self):
        ev = TimelineEvent(
            timestamp="2025-01-01T00:00:00+00:00",
            platform="test",
            artifact_type="config",
            description="Test event",
            severity=Severity.INFO,
            source_path="/tmp/test",
        )
        d = ev.to_dict()
        assert d["severity"] == "info"
        assert d["platform"] == "test"


# ===========================================================================
# IOC Extractor Tests
# ===========================================================================

class TestIOCExtractor:
    """Test IOCExtractor scanning and cross-referencing."""

    def test_extract_from_evidence_dir(self, fake_evidence_dir):
        extractor = IOCExtractor(str(fake_evidence_dir))
        result = extractor.extract()
        assert isinstance(result, IOCExtractor)
        assert isinstance(result.iocs, list)
        # The fake config has an API key and a domain
        assert len(result.iocs) >= 1

    def test_api_key_detection(self, fake_evidence_dir):
        extractor = IOCExtractor(str(fake_evidence_dir))
        extractor.extract()
        ioc_types = {ioc.ioc_type for ioc in extractor.iocs}
        assert "api_key" in ioc_types

    def test_ioc_has_required_fields(self, fake_evidence_dir):
        extractor = IOCExtractor(str(fake_evidence_dir))
        extractor.extract()
        for ioc in extractor.iocs:
            assert isinstance(ioc, IOC)
            assert isinstance(ioc.ioc_type, str)
            assert isinstance(ioc.value, str)
            assert len(ioc.value) > 0
            assert isinstance(ioc.severity, Severity)

    def test_ioc_to_dict(self, fake_evidence_dir):
        extractor = IOCExtractor(str(fake_evidence_dir))
        extractor.extract()
        for ioc in extractor.iocs:
            d = ioc.to_dict()
            assert isinstance(d, dict)
            assert "severity" in d
            assert isinstance(d["severity"], str)

    def test_summary_by_type(self, fake_evidence_dir):
        extractor = IOCExtractor(str(fake_evidence_dir))
        extractor.extract()
        summary = extractor.summary_by_type()
        assert isinstance(summary, dict)
        # At least one IOC type should appear
        assert len(summary) >= 1

    def test_to_json(self, fake_evidence_dir):
        extractor = IOCExtractor(str(fake_evidence_dir))
        extractor.extract()
        j = extractor.to_json()
        parsed = json.loads(j)
        assert isinstance(parsed, list)

    def test_empty_evidence_dir(self, minimal_evidence_dir):
        extractor = IOCExtractor(str(minimal_evidence_dir))
        extractor.extract()
        # No files to scan → no IOCs
        assert len(extractor.iocs) == 0


class TestIOCPatterns:
    """Test individual IOC pattern detection with targeted content."""

    def test_ip_detection(self, tmp_path):
        content_dir = tmp_path / "test_platform"
        content_dir.mkdir()
        (content_dir / "log.txt").write_text(
            "Connection from 203.0.113.50 established\n", encoding="utf-8"
        )
        custody = {
            "tool": "TRACE",
            "version": "0.4.0",
            "collected_at": "2025-01-01T00:00:00+00:00",
            "total_files": 1,
            "files": [
                {
                    "original_path": str(content_dir / "log.txt"),
                    "source_os": "linux",
                    "platform": "test_platform",
                    "artifact_type": "log",
                    "size_bytes": 64,
                    "sha256": "d" * 64,
                    "collected_at": "2025-01-01T00:00:00+00:00",
                    "collector_version": "0.4.0",
                }
            ],
        }
        (tmp_path / "CHAIN_OF_CUSTODY.json").write_text(
            json.dumps(custody), encoding="utf-8"
        )
        extractor = IOCExtractor(str(tmp_path))
        extractor.extract()
        ip_iocs = [ioc for ioc in extractor.iocs if ioc.ioc_type == "ip"]
        assert len(ip_iocs) >= 1

    def test_command_detection(self, tmp_path):
        content_dir = tmp_path / "test_platform"
        content_dir.mkdir()
        (content_dir / "log.txt").write_text(
            "Agent executed: rm -rf /var/log\n", encoding="utf-8"
        )
        custody = {
            "tool": "TRACE",
            "version": "0.4.0",
            "collected_at": "2025-01-01T00:00:00+00:00",
            "total_files": 1,
            "files": [
                {
                    "original_path": str(content_dir / "log.txt"),
                    "source_os": "linux",
                    "platform": "test_platform",
                    "artifact_type": "log",
                    "size_bytes": 64,
                    "sha256": "e" * 64,
                    "collected_at": "2025-01-01T00:00:00+00:00",
                    "collector_version": "0.4.0",
                }
            ],
        }
        (tmp_path / "CHAIN_OF_CUSTODY.json").write_text(
            json.dumps(custody), encoding="utf-8"
        )
        extractor = IOCExtractor(str(tmp_path))
        extractor.extract()
        cmd_iocs = [ioc for ioc in extractor.iocs if ioc.ioc_type == "command"]
        assert len(cmd_iocs) >= 1


# ===========================================================================
# ATLAS Mapper Tests
# ===========================================================================

class TestATLASMapper:
    """Test MITRE ATLAS technique mapping."""

    def test_atlas_techniques_catalog_exists(self):
        assert isinstance(ATLAS_TECHNIQUES, dict)
        assert len(ATLAS_TECHNIQUES) >= 5

    def test_map_finding_prompt_injection(self):
        mapper = ATLASMapper()
        finding = Finding(
            id="F-001",
            title="Prompt Injection Attack",
            description="A prompt injection attack was detected in the conversation history.",
            severity=Severity.HIGH,
            platform="ollama",
            artifact_type="conversation",
            evidence=[],
        )
        matches = mapper.map_finding(finding)
        assert len(matches) >= 1
        technique_ids = [m.technique_id for m in matches]
        assert "AML.T0010" in technique_ids

    def test_map_finding_credential_theft(self):
        mapper = ATLASMapper()
        finding = Finding(
            id="F-002",
            title="API Key Exposure",
            description="An API key credential was found in plaintext.",
            severity=Severity.CRITICAL,
            platform="lm_studio",
            artifact_type="config",
            evidence=[],
        )
        matches = mapper.map_finding(finding)
        technique_ids = [m.technique_id for m in matches]
        assert "AML.T0055" in technique_ids

    def test_map_finding_exfiltration(self):
        mapper = ATLASMapper()
        finding = Finding(
            id="F-003",
            title="Data Exfiltration Detected",
            description="Data exfiltration via base64 encoding was detected.",
            severity=Severity.CRITICAL,
            platform="autogpt",
            artifact_type="log",
            evidence=[],
        )
        matches = mapper.map_finding(finding)
        technique_ids = [m.technique_id for m in matches]
        assert "AML.T0050" in technique_ids

    def test_map_iocs_api_key(self, sample_iocs):
        mapper = ATLASMapper()
        matches = mapper.map_iocs(sample_iocs)
        assert len(matches) >= 1
        technique_ids = [m.technique_id for m in matches]
        assert "AML.T0055" in technique_ids  # API key IOC

    def test_map_iocs_command(self, sample_iocs):
        mapper = ATLASMapper()
        matches = mapper.map_iocs(sample_iocs)
        technique_ids = [m.technique_id for m in matches]
        # The "command" IOC should map to AML.T0049
        assert "AML.T0049" in technique_ids

    def test_atlas_technique_match_to_dict(self):
        match = ATLASTechniqueMatch(
            technique_id="AML.T0010",
            technique_name="Prompt Injection",
            description="Test description",
            platforms=["inference", "agent"],
            evidence_summary="Test evidence",
            severity=Severity.HIGH,
            source_type="finding",
            source_id="F-001",
        )
        d = match.to_dict()
        assert d["technique_id"] == "AML.T0010"
        assert d["severity"] == "high"

    def test_empty_findings_no_crash(self):
        mapper = ATLASMapper()
        finding = Finding(
            id="F-004",
            title="Benign Event",
            description="Routine system event with no security implications.",
            severity=Severity.INFO,
            platform="unknown",
            artifact_type="log",
            evidence=[],
        )
        matches = mapper.map_finding(finding)
        # High-severity findings with no keyword match still get AML.T0049
        # But INFO severity with no keywords → empty or AML.T0049 depending on logic
        # The important thing is it doesn't crash
        assert isinstance(matches, list)


# ===========================================================================
# Risk Scorer Tests
# ===========================================================================

class TestRiskScorer:
    """Test RiskScorer risk calculation."""

    def test_platform_risk_with_findings(self, sample_findings, sample_iocs):
        scorer = RiskScorer()
        risk = scorer.calculate_platform_risk(
            platform="ollama",
            findings=sample_findings,
            iocs=sample_iocs,
        )
        assert isinstance(risk, RiskScore)
        assert 0 <= risk.score <= 100
        assert risk.severity in ("Critical", "High", "Medium", "Low")
        assert "credentials" in risk.category_scores
        assert "exfiltration" in risk.category_scores
        assert "jailbreak" in risk.category_scores
        assert "autonomy" in risk.category_scores

    def test_platform_risk_empty_inputs(self):
        scorer = RiskScorer()
        risk = scorer.calculate_platform_risk(
            platform="test",
            findings=[],
            iocs=[],
        )
        assert risk.score == 0
        assert risk.severity == "Low"

    def test_overall_risk(self, sample_findings, sample_iocs):
        scorer = RiskScorer()
        risk = scorer.calculate_overall_risk(
            all_findings=sample_findings,
            all_iocs=sample_iocs,
        )
        assert isinstance(risk, RiskScore)
        assert 0 <= risk.score <= 100

    def test_overall_risk_empty(self):
        scorer = RiskScorer()
        risk = scorer.calculate_overall_risk(all_findings=[], all_iocs=[])
        assert risk.score == 0
        assert risk.severity == "Low"

    def test_credential_scoring_with_api_key(self):
        scorer = RiskScorer()
        findings = [
            Finding(
                id="F-001",
                title="API Key Exposed",
                description="API key found in config",
                severity=Severity.CRITICAL,
                platform="ollama",
                artifact_type="config",
                evidence=[],
            )
        ]
        iocs = [
            IOC(
                ioc_type="api_key",
                value="sk-abc123def456",
                context="Found in config",
                platform="ollama",
                source_file="/tmp/test",
                severity=Severity.CRITICAL,
            )
        ]
        risk = scorer.calculate_platform_risk("ollama", findings, iocs)
        # Credential score should be > 0 because API key was found
        assert risk.category_scores["credentials"] > 0

    def test_severity_from_score(self):
        from ionsec_trace.analyzer.risk_scorer import _severity_from_score
        assert _severity_from_score(95) == "Critical"
        assert _severity_from_score(75) == "High"
        assert _severity_from_score(45) == "Medium"
        assert _severity_from_score(10) == "Low"

    def test_risk_score_to_dict(self):
        rs = RiskScore(
            score=50,
            severity="Medium",
            category_scores={"credentials": 15, "exfiltration": 10, "jailbreak": 15, "autonomy": 10},
            recommendations=["Review credentials."],
        )
        d = rs.to_dict()
        assert d["score"] == 50
        assert d["severity"] == "Medium"
        assert len(d["recommendations"]) == 1

    def test_generate_risk_report(self, sample_findings, sample_iocs):
        scorer = RiskScorer()
        scorer.calculate_overall_risk(sample_findings, sample_iocs)
        report = scorer.generate_risk_report()
        assert isinstance(report, str)
        assert len(report) > 0

    def test_to_json(self, sample_findings, sample_iocs):
        scorer = RiskScorer()
        scorer.calculate_overall_risk(sample_findings, sample_iocs)
        j = scorer.to_json()
        parsed = json.loads(j)
        assert "platform_scores" in parsed
        assert "overall_score" in parsed
