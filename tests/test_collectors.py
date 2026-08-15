"""Tests for the core collector imports and their BaseCollector API compliance.

Each collector must:
  1. Be importable from its module
  2. Inherit from BaseCollector
  3. Implement discover(), collect(), and parse()
  4. discover() returns bool
  5. collect() returns list
  6. parse() returns list

The remaining collectors (network AI, code scanner, Docker AI, browser AI,
Unsloth, Shadow AI, Antigravity, Devin, VSCodium, Eigent) each have their own
dedicated test files (test_ai_providers.py, test_docker_browser_ai.py, etc.).
"""

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
# Core collector classes (newer collectors have dedicated test files)
# ---------------------------------------------------------------------------

COLLECTOR_IMPORTS = [
    ("ionsec_trace.collector.ollama", "OllamaCollector"),
    ("ionsec_trace.collector.hermes", "HermesCollector"),
    ("ionsec_trace.collector.lm_studio", "LMStudioCollector"),
    ("ionsec_trace.collector.gpt4all", "GPT4AllCollector"),
    ("ionsec_trace.collector.text_gen_webui", "TextGenWebUICollector"),
    ("ionsec_trace.collector.llama_cpp", "LlamaCppCollector"),
    ("ionsec_trace.collector.kobold_cpp", "KoboldCppCollector"),
    ("ionsec_trace.collector.autogpt", "AutoGPTCollector"),
    ("ionsec_trace.collector.crewai", "CrewAICollector"),
    ("ionsec_trace.collector.aider", "AiderCollector"),
    ("ionsec_trace.collector.shell_gpt", "ShellGPTCollector"),
    ("ionsec_trace.collector.cursor", "CursorCollector"),
    ("ionsec_trace.collector.claude_code", "ClaudeCodeCollector"),
    ("ionsec_trace.collector.huggingface", "HuggingFaceCacheCollector"),
]


class TestBaseDataClasses:
    """Test the base data classes that collectors rely on."""

    def test_collected_file_creation(self):
        cf = CollectedFile(
            original_path="/tmp/test.json",
            source_os="linux",
            platform="ollama",
            artifact_type="config",
            size_bytes=128,
            sha256="a" * 64,
            collected_at="2025-01-01T00:00:00+00:00",
        )
        assert cf.original_path == "/tmp/test.json"
        assert cf.platform == "ollama"
        assert cf.size_bytes == 128
        assert cf.collector_version == "1.0.1"

    def test_collected_file_to_dict(self):
        cf = CollectedFile(
            original_path="/tmp/test.json",
            source_os="linux",
            platform="ollama",
            artifact_type="config",
            size_bytes=128,
            sha256="a" * 64,
            collected_at="2025-01-01T00:00:00+00:00",
        )
        d = cf.to_dict()
        assert isinstance(d, dict)
        assert d["original_path"] == "/tmp/test.json"
        assert d["sha256"] == "a" * 64

    def test_parsed_artifact_creation(self):
        pa = ParsedArtifact(
            platform="ollama",
            artifact_type="config",
            severity=Severity.MEDIUM,
            data={"key": "val"},
            source_file="/tmp/test.json",
        )
        assert pa.platform == "ollama"
        assert pa.severity == Severity.MEDIUM
        assert pa.iocs == []
        assert pa.mitre_atlas == []

    def test_finding_creation(self):
        f = Finding(
            id="F-001",
            title="Test Finding",
            description="A test finding.",
            severity=Severity.HIGH,
            platform="ollama",
            artifact_type="config",
            evidence=["/tmp/test.json"],
        )
        assert f.id == "F-001"
        assert f.severity == Severity.HIGH
        assert f.risk_score == 0

    def test_severity_enum(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_platform_category_enum(self):
        assert PlatformCategory.INFERENCE.value == "inference"
        assert PlatformCategory.AGENT.value == "agent"
        assert PlatformCategory.DEVTOOL.value == "devtool"
        assert PlatformCategory.CLOUD.value == "cloud"


class TestBaseCollectorAbstract:
    """Test that BaseCollector enforces the abstract interface."""

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseCollector(output_dir="/tmp/trace_test")

    def test_mock_collector_satisfies_interface(self, mock_collector):
        assert isinstance(mock_collector, BaseCollector)
        assert mock_collector.PLATFORM_NAME == "mock_platform"
        assert mock_collector.PLATFORM_CATEGORY == PlatformCategory.INFERENCE


class TestMockCollectorAPI:
    """Test that a concrete collector satisfies the BaseCollector API contract."""

    def test_discover_returns_bool(self, mock_collector):
        result = mock_collector.discover()
        assert isinstance(result, bool)

    def test_discover_returns_true(self, mock_collector):
        assert mock_collector.discover() is True

    def test_collect_returns_list(self, mock_collector):
        result = mock_collector.collect()
        assert isinstance(result, list)

    def test_collect_returns_collected_files(self, mock_collector):
        result = mock_collector.collect()
        assert len(result) >= 1
        assert isinstance(result[0], CollectedFile)

    def test_parse_returns_list(self, mock_collector):
        result = mock_collector.parse()
        assert isinstance(result, list)

    def test_parse_returns_parsed_artifacts(self, mock_collector):
        result = mock_collector.parse()
        assert len(result) >= 1
        assert isinstance(result[0], ParsedArtifact)

    def test_timestamp_returns_iso_format(self, mock_collector):
        ts = mock_collector.timestamp()
        assert isinstance(ts, str)
        assert "T" in ts  # ISO 8601

    def test_detect_os_returns_string(self, mock_collector):
        os_name = mock_collector.detect_os()
        assert isinstance(os_name, str)
        assert os_name in ("linux", "windows", "macos")

    def test_calculate_hash_for_existing_file(self, mock_collector, tmp_path):
        test_file = tmp_path / "test_hash.txt"
        test_file.write_text("hello world", encoding="utf-8")
        h = mock_collector.calculate_hash(str(test_file))
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest

    def test_safe_read_json(self, mock_collector, tmp_path):
        jf = tmp_path / "test.json"
        jf.write_text('{"key": "value"}', encoding="utf-8")
        result = mock_collector.safe_read_json(str(jf))
        assert result == {"key": "value"}

    def test_safe_read_json_invalid(self, mock_collector, tmp_path):
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("not json at all{{{", encoding="utf-8")
        result = mock_collector.safe_read_json(str(bad_json))
        assert result is None

    def test_safe_read_json_missing(self, mock_collector):
        result = mock_collector.safe_read_json("/nonexistent/path/file.json")
        assert result is None

    def test_safe_read_file(self, mock_collector, tmp_path):
        tf = tmp_path / "readme.txt"
        tf.write_text("some content here", encoding="utf-8")
        result = mock_collector.safe_read_file(str(tf))
        assert result == "some content here"

    def test_safe_read_file_missing(self, mock_collector):
        result = mock_collector.safe_read_file("/nonexistent/path/file.txt")
        assert result is None


class TestCollectorImports:
    """Test that all 27 collectors can be imported and have the right interface."""

    @pytest.mark.parametrize("module_path,class_name", COLLECTOR_IMPORTS)
    def test_import_collector(self, module_path, class_name):
        import importlib
        module = importlib.import_module(module_path)
        collector_cls = getattr(module, class_name)
        assert issubclass(collector_cls, BaseCollector)

    @pytest.mark.parametrize("module_path,class_name", COLLECTOR_IMPORTS)
    def test_collector_has_platform_name(self, module_path, class_name):
        import importlib
        module = importlib.import_module(module_path)
        collector_cls = getattr(module, class_name)
        assert hasattr(collector_cls, "PLATFORM_NAME")
        assert isinstance(collector_cls.PLATFORM_NAME, str)
        assert len(collector_cls.PLATFORM_NAME) > 0

    @pytest.mark.parametrize("module_path,class_name", COLLECTOR_IMPORTS)
    def test_collector_has_platform_category(self, module_path, class_name):
        import importlib
        module = importlib.import_module(module_path)
        collector_cls = getattr(module, class_name)
        assert hasattr(collector_cls, "PLATFORM_CATEGORY")
        assert isinstance(collector_cls.PLATFORM_CATEGORY, PlatformCategory)

    @pytest.mark.parametrize("module_path,class_name", COLLECTOR_IMPORTS)
    def test_collector_instantiation(self, module_path, class_name, tmp_path):
        import importlib
        module = importlib.import_module(module_path)
        collector_cls = getattr(module, class_name)
        instance = collector_cls(output_dir=str(tmp_path))
        assert isinstance(instance, BaseCollector)

    @pytest.mark.parametrize("module_path,class_name", COLLECTOR_IMPORTS)
    def test_discover_returns_bool(self, module_path, class_name, tmp_path):
        import importlib
        module = importlib.import_module(module_path)
        collector_cls = getattr(module, class_name)
        instance = collector_cls(output_dir=str(tmp_path))
        result = instance.discover()
        assert isinstance(result, bool)

    @pytest.mark.parametrize("module_path,class_name", COLLECTOR_IMPORTS)
    def test_collect_returns_list(self, module_path, class_name, tmp_path):
        import importlib
        module = importlib.import_module(module_path)
        collector_cls = getattr(module, class_name)
        instance = collector_cls(output_dir=str(tmp_path))
        result = instance.collect()
        assert isinstance(result, list)

    @pytest.mark.parametrize("module_path,class_name", COLLECTOR_IMPORTS)
    def test_parse_returns_list(self, module_path, class_name, tmp_path):
        import importlib
        module = importlib.import_module(module_path)
        collector_cls = getattr(module, class_name)
        instance = collector_cls(output_dir=str(tmp_path))
        result = instance.parse()
        assert isinstance(result, list)


class TestAllCollectorsList:
    """Test the ALL_COLLECTORS registry."""

    def test_all_collectors_count(self):
        from ionsec_trace.collector import ALL_COLLECTORS
        assert len(ALL_COLLECTORS) >= 14

    def test_all_collectors_are_base_subclasses(self):
        from ionsec_trace.collector import ALL_COLLECTORS
        for cls in ALL_COLLECTORS:
            assert issubclass(cls, BaseCollector)
