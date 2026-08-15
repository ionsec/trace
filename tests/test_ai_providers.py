"""Tests for the AI provider catalog, network AI collector, and code scanner."""



from ionsec_trace.collector.ai_providers import (
    AI_FRAMEWORKS,
    AI_PROVIDER_DOMAINS,
    MCP_CONFIG_FILES,
    classify_domain,
    classify_import,
    is_ai_domain,
    is_ai_import,
)
from ionsec_trace.collector.code_scanner import CodeScannerCollector
from ionsec_trace.collector.network_ai import NetworkAICollector

# ===========================================================================
# AI provider catalog
# ===========================================================================

class TestAIProviderCatalog:
    def test_catalog_nonempty(self):
        assert len(AI_PROVIDER_DOMAINS) >= 50
        assert len(AI_FRAMEWORKS) >= 50
        assert len(MCP_CONFIG_FILES) >= 5

    def test_classify_known_domain(self):
        info = classify_domain("api.openai.com")
        assert info is not None
        assert info["provider"] == "OpenAI"
        assert info["category"] == "inference"

    def test_classify_subdomain(self):
        info = classify_domain("api-inference.huggingface.co")
        assert info is not None
        assert info["provider"] == "HuggingFace"

    def test_classify_unknown_domain(self):
        assert classify_domain("example.com") is None
        assert classify_domain("") is None

    def test_is_ai_domain(self):
        assert is_ai_domain("api.anthropic.com")
        assert not is_ai_domain("google.com")

    def test_classify_known_import(self):
        info = classify_import("langchain_core.agents")
        assert info is not None
        assert info["framework"] == "LangChain Core"

    def test_classify_unknown_import(self):
        assert classify_import("os") is None
        assert classify_import("") is None

    def test_is_ai_import(self):
        assert is_ai_import("crewai")
        assert not is_ai_import("requests")


# ===========================================================================
# Network AI collector
# ===========================================================================

class TestNetworkAICollector:
    def test_discover_always_true(self, tmp_path):
        c = NetworkAICollector(output_dir=str(tmp_path))
        assert c.discover() is True

    def test_extract_domain(self, tmp_path):
        c = NetworkAICollector(output_dir=str(tmp_path))
        # lsof NAME format: localhost:port->remote:port
        assert c._extract_domain("127.0.0.1:54321->api.openai.com:443") == "api.openai.com"
        assert c._extract_domain("127.0.0.1:54321->1.2.3.4:443") is None  # IP skipped
        assert c._extract_domain("127.0.0.1:54321->localhost:8080") is None  # localhost skipped

    def test_extract_port(self, tmp_path):
        c = NetworkAICollector(output_dir=str(tmp_path))
        assert c._extract_port("api.openai.com:443") == "443"

    def test_parse_returns_list(self, tmp_path):
        c = NetworkAICollector(output_dir=str(tmp_path))
        artifacts = c.parse()
        assert isinstance(artifacts, list)


# ===========================================================================
# Code scanner collector
# ===========================================================================

class TestCodeScannerCollector:
    def test_discover_always_true(self, tmp_path):
        c = CodeScannerCollector(output_dir=str(tmp_path))
        assert c.discover() is True

    def test_has_ai_signal_framework_import(self, tmp_path):
        c = CodeScannerCollector(output_dir=str(tmp_path))
        assert c._has_ai_signal("from langchain_core.agents import Agent\n")
        assert c._has_ai_signal("import crewai\n")

    def test_has_ai_signal_api_key(self, tmp_path):
        c = CodeScannerCollector(output_dir=str(tmp_path))
        assert c._has_ai_signal("api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456'\n")

    def test_has_ai_signal_benign(self, tmp_path):
        c = CodeScannerCollector(output_dir=str(tmp_path))
        assert not c._has_ai_signal("import os\nimport json\n")

    def test_parse_ai_framework(self, tmp_path):
        # Create a code file with an AI import
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "app.py").write_text("from langchain_core.agents import Agent\n", encoding="utf-8")
        c = CodeScannerCollector(output_dir=str(tmp_path))
        # Manually register the file as collected
        from ionsec_trace.collector.base import CollectedFile
        c.collected_files.append(CollectedFile(
            original_path=str(proj / "app.py"),
            source_os="linux",
            platform="code_scanner",
            artifact_type="ai_code_file",
            size_bytes=40,
            sha256="a" * 64,
            collected_at="2026-01-01T00:00:00+00:00",
        ))
        artifacts = c.parse()
        types = {a.artifact_type for a in artifacts}
        assert "ai_framework" in types

    def test_parse_hardcoded_key(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "config.py").write_text(
            "api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456'\n", encoding="utf-8")
        c = CodeScannerCollector(output_dir=str(tmp_path))
        from ionsec_trace.collector.base import CollectedFile
        c.collected_files.append(CollectedFile(
            original_path=str(proj / "config.py"),
            source_os="linux",
            platform="code_scanner",
            artifact_type="ai_code_file",
            size_bytes=50,
            sha256="b" * 64,
            collected_at="2026-01-01T00:00:00+00:00",
        ))
        artifacts = c.parse()
        types = {a.artifact_type for a in artifacts}
        assert "hardcoded_api_key" in types
