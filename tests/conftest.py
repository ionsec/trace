"""Shared pytest fixtures for TRACE test suite."""

import json

import pytest

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    Finding,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)

# ---------------------------------------------------------------------------
# Sample data helpers
# ---------------------------------------------------------------------------

def _iso_now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def make_collected_file(**overrides):
    """Create a sample CollectedFile with sensible defaults."""
    defaults = {
        "original_path": "/tmp/trace_test/sample_config.json",
        "source_os": "linux",
        "platform": "ollama",
        "artifact_type": "config",
        "size_bytes": 256,
        "sha256": "a" * 64,
        "collected_at": _iso_now(),
        "collector_version": "0.4.0",
    }
    defaults.update(overrides)
    return CollectedFile(**defaults)


def make_parsed_artifact(**overrides):
    """Create a sample ParsedArtifact with sensible defaults."""
    defaults = {
        "platform": "ollama",
        "artifact_type": "config",
        "severity": Severity.MEDIUM,
        "data": {"key": "value"},
        "source_file": "/tmp/trace_test/sample_config.json",
        "timestamp": _iso_now(),
        "iocs": [],
        "mitre_atlas": [],
        "risk_score": 0,
    }
    defaults.update(overrides)
    return ParsedArtifact(**defaults)


def make_finding(**overrides):
    """Create a sample Finding with sensible defaults."""
    defaults = {
        "id": "FIND-001",
        "title": "Exposed API Key",
        "description": "An API key was found in plaintext configuration.",
        "severity": Severity.CRITICAL,
        "platform": "ollama",
        "artifact_type": "config",
        "evidence": ["/tmp/trace_test/sample_config.json"],
        "iocs": ["sk-abc123def456"],
        "mitre_atlas": ["AML.T0055"],
        "risk_score": 85,
        "recommendation": "Rotate the exposed key immediately.",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def make_chain_of_custody(
    artifacts=None,
    findings=None,
    iocs=None,
    extra=None,
):
    """Build a CHAIN_OF_CUSTODY.json dict with sample data."""
    if artifacts is None:
        artifacts = [
            {
                "original_path": "/home/user/.ollama/config.json",
                "source_os": "linux",
                "platform": "ollama",
                "artifact_type": "config",
                "size_bytes": 512,
                "sha256": "b" * 64,
                "collected_at": _iso_now(),
                "collector_version": "0.4.0",
            },
            {
                "original_path": "/home/user/.ollama/models/manifest.json",
                "source_os": "linux",
                "platform": "ollama",
                "artifact_type": "model_manifest",
                "size_bytes": 1024,
                "sha256": "c" * 64,
                "collected_at": _iso_now(),
                "collector_version": "0.4.0",
            },
        ]
    if findings is None:
        findings = [
            {
                "id": "FIND-001",
                "title": "Exposed API Key in Ollama Config",
                "description": "An OpenAI API key was found in plaintext.",
                "severity": "critical",
                "platform": "ollama",
                "artifact_type": "config",
                "evidence": ["/home/user/.ollama/config.json"],
                "iocs": ["sk-abc123def456"],
                "mitre_atlas": ["AML.T0055"],
                "risk_score": 85,
                "recommendation": "Rotate the exposed key immediately.",
            },
        ]
    if iocs is None:
        iocs = [
            {
                "ioc_type": "api_key",
                "value": "sk-abc123def456",
                "context": "Found in ollama config file",
                "platform": "ollama",
                "source_file": "/home/user/.ollama/config.json",
                "severity": "critical",
            },
            {
                "ioc_type": "domain",
                "value": "evil.example.com",
                "context": "Suspicious domain in config",
                "platform": "ollama",
                "source_file": "/home/user/.ollama/config.json",
                "severity": "medium",
            },
        ]
    data = {
        "tool": "TRACE",
        "version": "0.4.0",
        "collected_at": _iso_now(),
        "total_files": len(artifacts),
        "files": artifacts,
        "collected_files": artifacts,   # Also store under collected_files for reporter compat
        "findings": findings,
        "iocs": iocs,
    }
    if extra:
        data.update(extra)
    return data


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_evidence_dir(tmp_path):
    """Create a temporary evidence directory with CHAIN_OF_CUSTODY.json
    and a few sample artifact files that the analyzers/reporters can scan."""
    custody = make_chain_of_custody()

    # Write CHAIN_OF_CUSTODY.json — use paths inside tmp_path so they exist
    # Update artifact paths to point inside our temp dir
    config_dir = tmp_path / "ollama"
    config_dir.mkdir()
    config_file = config_dir / "config.json"
    config_content = json.dumps({
        "api_key": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901",
        "model": "llama3",
        "server": "https://evil.example.com/api",
    })
    config_file.write_text(config_content, encoding="utf-8")

    manifest_file = config_dir / "manifest.json"
    manifest_content = json.dumps({"models": [{"name": "llama3", "size": "4.7GB"}]})
    manifest_file.write_text(manifest_content, encoding="utf-8")

    # Update custody paths to point to real files
    custody["files"][0]["original_path"] = str(config_file)
    custody["files"][1]["original_path"] = str(manifest_file)

    # Also update IOC source paths
    for ioc in custody["iocs"]:
        if "source_file" in ioc:
            ioc["source_file"] = str(config_file)

    custody_path = tmp_path / "CHAIN_OF_CUSTODY.json"
    custody_path.write_text(json.dumps(custody, indent=2), encoding="utf-8")

    return tmp_path


@pytest.fixture
def minimal_evidence_dir(tmp_path):
    """A minimal evidence directory with just CHAIN_OF_CUSTODY.json (no real files)."""
    custody = {
        "tool": "TRACE",
        "version": "0.4.0",
        "collected_at": _iso_now(),
        "total_files": 0,
        "files": [],
    }
    custody_path = tmp_path / "CHAIN_OF_CUSTODY.json"
    custody_path.write_text(json.dumps(custody, indent=2), encoding="utf-8")
    return tmp_path


@pytest.fixture
def sample_findings():
    """A list of sample Finding objects for testing analyzers/reporters."""
    return [
        make_finding(
            id="FIND-001",
            title="Exposed API Key in Ollama Config",
            description="An OpenAI API key was found in plaintext configuration.",
            severity=Severity.CRITICAL,
            platform="ollama",
            artifact_type="config",
            iocs=["sk-abc123def456"],
            risk_score=85,
        ),
        make_finding(
            id="FIND-002",
            title="Prompt Injection Attempt Detected",
            description="A prompt injection attempt was found in conversation history.",
            severity=Severity.HIGH,
            platform="lm_studio",
            artifact_type="conversation",
            iocs=[],
            risk_score=60,
        ),
        make_finding(
            id="FIND-003",
            title="Suspicious Command Execution",
            description="An AI agent executed a suspicious command: rm -rf /tmp/data",
            severity=Severity.HIGH,
            platform="autogpt",
            artifact_type="log",
            iocs=["rm -rf /tmp/data"],
            risk_score=55,
        ),
    ]


@pytest.fixture
def sample_iocs():
    """A list of sample IOC objects for testing analyzers/reporters."""
    from ionsec_trace.analyzer.ioc_extractor import IOC
    return [
        IOC(
            ioc_type="api_key",
            value="sk-abc123def456",
            context="Found in config file",
            platform="ollama",
            source_file="/home/user/.ollama/config.json",
            severity=Severity.CRITICAL,
        ),
        IOC(
            ioc_type="domain",
            value="evil.example.com",
            context="Suspicious domain in config",
            platform="ollama",
            source_file="/home/user/.ollama/config.json",
            severity=Severity.MEDIUM,
        ),
        IOC(
            ioc_type="command",
            value="rm -rf /tmp/data",
            context="Destructive command in log",
            platform="autogpt",
            source_file="/home/user/.autogpt/logs/output.log",
            severity=Severity.HIGH,
        ),
    ]


class MockCollector(BaseCollector):
    """A concrete mock collector for testing BaseCollector API."""

    PLATFORM_NAME = "mock_platform"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    VERSION = "0.4.0"

    def discover(self) -> bool:
        return True

    def collect(self) -> list:
        return [make_collected_file(platform="mock_platform")]

    def parse(self) -> list:
        return [make_parsed_artifact(platform="mock_platform")]


@pytest.fixture
def mock_collector(tmp_path):
    """Return a MockCollector instance pointed at a temp directory."""
    return MockCollector(output_dir=str(tmp_path))


@pytest.fixture
def sample_custody_data():
    """Return raw custody dict for tests that need direct data access."""
    return make_chain_of_custody()
