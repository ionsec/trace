"""Tests for the enhanced behavioural risk scorer."""

import json

import pytest

from ionsec_trace.analyzer.enhanced_risk_scorer import (
    CATEGORY_NAMES,
    AIIndicator,
    AttackNarrative,
    ConfidenceLevel,
    DetailedRiskScore,
    EnhancedRiskScorer,
    KillChainStage,
    _make_indicator_id,
    _severity_from_enum,
    _severity_from_score,
)
from ionsec_trace.collector.base import Severity


def _ind(category="credential_exposure", stage="Exploitation", weight=3.0,
         confidence=0.8):
    return AIIndicator(
        indicator_id="IND-test",
        category=category,
        label="test indicator",
        kill_chain_stage=stage,
        confidence=confidence,
        weight=weight,
    )


class TestEnums:
    def test_kill_chain_stage_values(self):
        assert [s.value for s in KillChainStage] == [
            "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
            "Installation", "Command & Control", "Actions on Objectives",
        ]

    def test_confidence_levels(self):
        assert ConfidenceLevel.DIRECT == 1.0
        assert ConfidenceLevel.CORRELATION == 0.2
        assert isinstance(ConfidenceLevel.STRONG, float)

    def test_category_names_count(self):
        assert len(CATEGORY_NAMES) == 8


class TestDataclasses:
    def test_indicator_to_dict(self):
        d = _ind().to_dict()
        assert d["category"] == "credential_exposure"
        assert d["source_ids"] == []
        assert d["platforms"] == []

    def test_narrative_to_dict_serialises_severity(self):
        n = AttackNarrative(
            narrative_id="N-1", title="t", kill_chain_stages=["Exploitation"],
            indicators=["IND-test"], platforms=["ollama"],
            severity=Severity.CRITICAL, confidence=0.8, timeline=[],
            recommendation="rotate",
        )
        assert n.to_dict()["severity"] == "critical"

    def test_detailed_score_serialises_nested_narratives(self):
        n = AttackNarrative(
            narrative_id="N-1", title="t", kill_chain_stages=[],
            indicators=[], platforms=[], severity=Severity.HIGH,
            confidence=0.5, timeline=[], recommendation="r",
        )
        s = DetailedRiskScore(
            score=70, severity="High", categories=dict.fromkeys(CATEGORY_NAMES, 0.0),
            confidence=0.5, kill_chain_stages=[], narratives=[n],
            recommendations=[], priority_actions=[],
        )
        d = s.to_dict()
        assert d["narratives"][0]["title"] == "t"
        assert d["narratives"][0]["severity"] == "high"


class TestHelpers:
    @pytest.mark.parametrize("score,label", [
        (100, "Critical"), (90, "Critical"), (89, "High"), (70, "High"),
        (69, "Medium"), (40, "Medium"), (39, "Low"), (0, "Low"),
    ])
    def test_severity_from_score(self, score, label):
        assert _severity_from_score(score) == label

    def test_severity_from_enum(self):
        assert _severity_from_enum(Severity.HIGH) == "High"

    def test_indicator_id_is_deterministic(self):
        a = _make_indicator_id("label", "credential_exposure", 0.8)
        b = _make_indicator_id("label", "credential_exposure", 0.8)
        assert a == b
        assert a.startswith("IND-") and len(a) == 16


class TestScoring:
    def test_score_categories_clamps_and_rounds(self):
        scorer = EnhancedRiskScorer()
        cats = scorer._score_categories([
            _ind(weight=3.0),
            _ind(weight=20.0),
            _ind(category="not_a_category", weight=9.0),
        ])
        assert set(cats) == set(CATEGORY_NAMES)
        assert cats["credential_exposure"] == 12.5
        assert cats["persistence"] == 0.0

    def test_aggregate_confidence_weighted(self):
        scorer = EnhancedRiskScorer()
        assert scorer._aggregate_confidence([]) == 0.0
        conf = scorer._aggregate_confidence([
            _ind(weight=1.0, confidence=0.4),
            _ind(weight=3.0, confidence=1.0),
        ])
        assert conf == 0.85

    def test_zero_weight_confidence(self):
        scorer = EnhancedRiskScorer()
        assert scorer._aggregate_confidence([_ind(weight=0.0)]) == 0.0

    def test_kill_chain_ordered(self):
        scorer = EnhancedRiskScorer()
        stages = scorer._detect_kill_chain_stages([
            _ind(stage="Exploitation"),
            _ind(stage="Reconnaissance"),
            _ind(stage="Exploitation"),
        ])
        assert stages == ["Reconnaissance", "Exploitation"]

    def test_score_from_indicators(self, sample_findings, sample_iocs):
        scorer = EnhancedRiskScorer()
        score = scorer.score_from_indicators(sample_findings, sample_iocs)
        assert 0 <= score.score <= 100
        assert score.severity in {"Critical", "High", "Medium", "Low"}
        assert set(score.categories) == set(CATEGORY_NAMES)
        assert 0.0 <= score.confidence <= 1.0
        assert isinstance(score.priority_actions, list)
        assert scorer.overall_score is score

    def test_score_platform_filters(self, sample_findings, sample_iocs):
        scorer = EnhancedRiskScorer()
        score = scorer.score_platform("ollama", sample_findings, sample_iocs)
        assert "ollama" in scorer.platform_scores
        assert score.score >= 0

    def test_report_before_and_after_scoring(self, sample_findings, sample_iocs):
        scorer = EnhancedRiskScorer()
        assert "No risk scores calculated yet" in scorer.generate_risk_report()
        scorer.score_from_indicators(sample_findings, sample_iocs)
        report = scorer.generate_risk_report()
        assert isinstance(report, str) and report

    def test_to_json_is_valid(self, sample_findings, sample_iocs):
        scorer = EnhancedRiskScorer()
        scorer.score_from_indicators(sample_findings, sample_iocs)
        parsed = json.loads(scorer.to_json())
        assert parsed["overall_score"]["score"] >= 0
        assert parsed["platform_scores"] == {}
        assert isinstance(parsed["indicators"], list)
