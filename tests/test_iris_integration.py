"""Tests for the TRACE → DFIR-IRIS integration.

The DFIR-IRIS client is optional, so the integration module is tested with a
fake/mock client rather than a live IRIS instance. We patch the lazy client
imports (`dfir_iris_client.session.ClientSession` and
`dfir_iris_client.case.Case`) used by `ionsec_trace.integration.iris`.
"""

import json
from datetime import datetime, timezone
from typing import ClassVar
from unittest.mock import patch

import pytest

from ionsec_trace.integration.iris import (
    _IOC_TYPE_MAP,
    IrisIntegration,
    push_to_iris,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeApiResponse:
    """Minimal stand-in for dfir_iris_client.helper.utils.ApiResponse."""

    def __init__(self, data=None, error=None):
        self._data = data
        self._error = error

    def is_error(self):
        return self._error is not None

    def is_success(self):
        return self._error is None

    def get_data(self):
        return self._data

    def get_msg(self):
        return self._error or ""


class FakeSession:
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs


class FakeCase:
    """A case object that records every call for later assertion."""

    instances: ClassVar[list["FakeCase"]] = []  # all created instances, for assertions

    def __init__(self, session=None, case_id=None):
        self._s = session
        self._cid = case_id
        self.calls = []
        FakeCase.instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def set_cid(self, cid):
        self._cid = cid
        self.calls.append(("set_cid", cid))
        return True

    # --- used by _resolve_or_create_case ---
    def list_cases(self):
        self.calls.append(("list_cases", {}))
        return FakeApiResponse(data=[{"case_id": 1}])

    def add_case(self, **kwargs):
        self.calls.append(("add_case", kwargs))
        if kwargs.get("case_customer") == "BROKEN":
            return FakeApiResponse(error="customer not found")
        return FakeApiResponse(data={"case_id": 42})

    # --- used by _push_findings_notes ---
    def add_notes_directory(self, **kwargs):
        self.calls.append(("add_notes_directory", kwargs))
        return FakeApiResponse(data={"id": 7})

    def add_note(self, **kwargs):
        self.calls.append(("add_note", kwargs))
        return FakeApiResponse(data={"note_id": 1})

    # --- used by _push_iocs ---
    def add_ioc(self, **kwargs):
        self.calls.append(("add_ioc", kwargs))
        if kwargs.get("value") == "BAD-IOC":
            return FakeApiResponse(error="invalid ioc type")
        return FakeApiResponse(data={"ioc_id": 1})

    # --- used by _push_timeline ---
    def add_event(self, **kwargs):
        self.calls.append(("add_event", kwargs))
        return FakeApiResponse(data={"event_id": 1})

    # --- used by _push_priority_tasks ---
    def add_task(self, **kwargs):
        self.calls.append(("add_task", kwargs))
        return FakeApiResponse(data={"task_id": 1})

    # --- used by _push_host_asset ---
    def add_asset(self, **kwargs):
        self.calls.append(("add_asset", kwargs))
        return FakeApiResponse(data={"asset_id": 9})

    # --- used by _push_evidence_files ---
    def list_ds_tree(self, **kwargs):
        self.calls.append(("list_ds_tree", kwargs))
        return FakeApiResponse(data={"d-1": {"is_root": True, "type": "directory", "children": {}}})

    def add_ds_file(self, **kwargs):
        self.calls.append(("add_ds_file", kwargs))
        return FakeApiResponse(data={"file_id": 3})


def _write_evidence(tmp_path, hostname="host-1", with_analysis=True):
    """Write CHAIN_OF_CUSTODY.json and analysis_results.json into tmp_path."""
    now = datetime.now(timezone.utc).isoformat()

    # Create a real file referenced by custody so evidence upload has a source.
    config = tmp_path / "ollama" / "config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"model": "llama3", "api_key": "«redacted:sk-…»"}), encoding="utf-8")

    custody = {
        "tool": "TRACE",
        "version": "0.4.0",
        "collected_at": now,
        "hostname": hostname,
        "source_os": "linux",
        "files": [
            {
                "original_path": str(config),
                "source_os": "linux",
                "platform": "ollama",
                "artifact_type": "config",
                "size_bytes": config.stat().st_size,
                "sha256": "a" * 64,
                "collected_at": now,
            }
        ],
        "collected_files": [
            {
                "original_path": str(config),
                "source_os": "linux",
                "platform": "ollama",
                "artifact_type": "config",
                "size_bytes": config.stat().st_size,
                "sha256": "a" * 64,
                "collected_at": now,
            }
        ],
        "findings": [
            {
                "id": "FIND-001",
                "title": "Exposed API Key",
                "description": "An OpenAI API key was found in plaintext config.",
                "severity": "critical",
                "platform": "ollama",
                "artifact_type": "config",
                "evidence": [str(config)],
                "iocs": ["«redacted:sk-…»"],
                "mitre_atlas": ["AML.T0055"],
                "risk_score": 85,
                "recommendation": "Rotate the exposed key.",
            }
        ],
        "iocs": [
            {"ioc_type": "api_key", "value": "«redacted:sk-…»", "context": "in config",
             "platform": "ollama", "severity": "critical"},
            {"ioc_type": "domain", "value": "evil.example.com", "context": "suspicious",
             "platform": "ollama", "severity": "medium"},
            {"ioc_type": "ip", "value": "203.0.113.50", "context": "conn", "platform": "ollama",
             "severity": "medium"},
        ],
    }
    (tmp_path / "CHAIN_OF_CUSTODY.json").write_text(json.dumps(custody, indent=2), encoding="utf-8")

    if with_analysis:
        analysis = {
            "iocs": custody["iocs"],
            "timeline": [
                {"timestamp": "2025-01-15T10:00:00+00:00", "platform": "ollama",
                 "description": "Config collected", "severity": "info"},
            ],
            "priority_actions": [
                {"action": "Rotate exposed API keys", "urgency": "CRITICAL", "evidence": ["FIND-001"]},
            ],
            "risk_scores": {"score": 85, "severity": "critical"},
        }
        (tmp_path / "analysis_results.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")

    return tmp_path


@pytest.fixture(autouse=True)
def _reset_fakecase():
    FakeCase.reset()
    yield
    FakeCase.reset()


@pytest.fixture
def iris_evidence(tmp_path):
    return _write_evidence(tmp_path)


@pytest.fixture
def iris_evidence_no_analysis(tmp_path):
    return _write_evidence(tmp_path, with_analysis=False)


def _patch_client():
    """Patch the lazy client imports used by the integration module."""
    return patch("ionsec_trace.integration.iris._lazy_import_client",
                 return_value=(FakeSession, FakeCase))


# ---------------------------------------------------------------------------
# IOC type mapping
# ---------------------------------------------------------------------------

class TestIocTypeMapping:
    def test_core_trace_types_map_to_iris(self):
        assert _IOC_TYPE_MAP["ip"] == "ip-any"
        assert _IOC_TYPE_MAP["domain"] == "domain"
        assert _IOC_TYPE_MAP["url"] == "url"
        assert _IOC_TYPE_MAP["email"] == "email"
        assert _IOC_TYPE_MAP["hash_md5"] == "md5"
        assert _IOC_TYPE_MAP["hash_sha1"] == "sha1"
        assert _IOC_TYPE_MAP["hash_sha256"] == "sha256"
        assert _IOC_TYPE_MAP["filepath"] == "file-path"

    def test_unknown_types_fall_back_to_other(self):
        assert _IOC_TYPE_MAP.get("unknown_thing", "other") == "other"


# ---------------------------------------------------------------------------
# Integration behavior
# ---------------------------------------------------------------------------

class TestIrisIntegration:
    def test_check_reports_ok(self):
        with _patch_client():
            intg = IrisIntegration(host="https://iris.local", apikey="key")
            status = intg.check()
            assert status["ok"] is True
            assert status["host"] == "https://iris.local"
            assert status["agent"] == "trace"
            assert status["case_count"] == 1  # FakeCase.list_cases returns one case

    def test_push_creates_case_and_pushes_everything(self, iris_evidence):
        with _patch_client():
            result = push_to_iris(
                evidence_dir=str(iris_evidence),
                host="https://iris.local",
                apikey="key",
            )
            assert result["ok"] is True
            assert result["created_case"] is True
            assert result["case_id"] == 42
            assert result["ok_count"] == result["total_count"]

        # Exactly one case instance should have been created.
        assert len(FakeCase.instances) == 1
        case = FakeCase.instances[0]
        calls = case.calls
        names = [name for name, _ in calls]

        # Every step must have been attempted, in the expected order.
        assert calls[0][0] == "add_case"
        add_case_kwargs = calls[0][1]
        assert add_case_kwargs["case_name"] == "TRACE — AI Evidence Collection"
        assert add_case_kwargs["case_customer"] == "TRACE"
        assert add_case_kwargs["case_classification"] == "not-classified"
        assert add_case_kwargs["soc_id"] == ""
        assert add_case_kwargs["create_customer"] is True
        assert "TRACE" in add_case_kwargs["case_description"]
        assert "add_asset" in names
        assert "add_notes_directory" in names
        assert "add_note" in names
        assert names.count("add_ioc") == 3       # 3 IOCs in the fixture
        assert "add_task" in names
        assert "add_event" in names
        assert "list_ds_tree" in names
        assert "add_ds_file" in names

        # IOC type mapping must be applied.
        ioc_calls = [kwargs for name, kwargs in calls if name == "add_ioc"]
        ioc_types = [c["ioc_type"] for c in ioc_calls]
        assert "other" in ioc_types       # api_key -> other
        assert "domain" in ioc_types      # domain
        assert "ip-any" in ioc_types      # ip -> ip-any

        # Evidence file uploaded with file_is_evidence=True.
        ds_calls = [kwargs for name, kwargs in calls if name == "add_ds_file"]
        assert len(ds_calls) == 1
        assert ds_calls[0]["file_is_evidence"] is True
        assert ds_calls[0]["filename"] == "config.json"

    def test_push_into_existing_case_skips_create(self, iris_evidence):
        with _patch_client():
            result = push_to_iris(
                evidence_dir=str(iris_evidence),
                host="https://iris.local",
                apikey="key",
                case_id=99,
            )
            assert result["ok"] is True
            assert result["created_case"] is False
            assert result["case_id"] == 99

    def test_push_reports_individual_step_failures(self, iris_evidence):
        # Inject a bad IOC that will fail; the rest should still succeed.
        with _patch_client():
            # We can't easily inject mid-run, so test the isolated _push_iocs directly.
            intg = IrisIntegration(host="https://iris.local", apikey="key")
            case = FakeCase(session=FakeSession(), case_id=1)
            bag = intg._load_evidence(str(iris_evidence))
            # add an IOC with value BAD-IOC -> FakeCase returns error
            bag["analysis"]["iocs"] = [
                {"ioc_type": "domain", "value": "BAD-IOC", "context": "x",
                 "platform": "ollama", "severity": "medium"}
            ]
            results = intg._push_iocs(case, bag)
            assert len(results) == 1
            assert results[0]["ok"] is False
            assert results[0]["error"] == "invalid ioc type"

    def test_push_no_analysis_data_still_creates_case(self, iris_evidence_no_analysis):
        with _patch_client():
            result = push_to_iris(
                evidence_dir=str(iris_evidence_no_analysis),
                host="https://iris.local",
                apikey="key",
            )
            assert result["ok"] is True
            assert result["case_id"] == 42

    def test_case_description_reflects_risk(self, iris_evidence):
        with _patch_client():
            intg = IrisIntegration(host="https://iris.local", apikey="key")
            bag = intg._load_evidence(str(iris_evidence))
            desc = intg._build_case_description(bag)
            assert "TRACE" in desc
            assert "85" in desc  # risk score
            assert "host-1" in desc

    def test_finding_to_markdown_contains_fields(self, iris_evidence):
        with _patch_client():
            intg = IrisIntegration(host="https://iris.local", apikey="key")
            md = intg._finding_to_markdown({"severity": "high", "platform": "ollama",
                                             "artifact_type": "log", "description": "desc",
                                             "mitre_atlas": ["AML.T0055"],
                                             "recommendation": "act"})
            assert "high" in md
            assert "AML.T0055" in md
            assert "act" in md


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

class TestIrisCli:
    def test_iris_group_present(self):
        from click.testing import CliRunner

        from ionsec_trace.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["iris", "--help"])
        assert result.exit_code == 0
        assert "push" in result.output
        assert "check" in result.output

    def test_iris_push_requires_host(self, iris_evidence):
        from click.testing import CliRunner

        from ionsec_trace.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["iris", "push", str(iris_evidence)])
        assert result.exit_code != 0
        assert "IRIS host is required" in result.output

    def test_iris_push_missing_api_key(self, iris_evidence):
        from click.testing import CliRunner

        from ionsec_trace.cli import main
        runner = CliRunner()
        result = runner.invoke(
            main, ["iris", "push", str(iris_evidence), "--host", "https://iris.local"]
        )
        assert result.exit_code != 0
        assert "IRIS API key is required" in result.output

    def test_iris_check_requires_host(self):
        from click.testing import CliRunner

        from ionsec_trace.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["iris", "check"])
        assert result.exit_code != 0
        assert "IRIS host is required" in result.output

    def test_iris_push_success_path(self, iris_evidence):
        from unittest.mock import patch

        from click.testing import CliRunner

        from ionsec_trace.cli import main

        fake = {
            "ok": True,
            "case_id": 42,
            "created_case": True,
            "summary": {"findings": 1, "iocs": 3, "timeline_events": 1,
                        "priority_actions": 1, "evidence_files_uploaded": 1},
            "ok_count": 7,
            "total_count": 7,
            "errors": [],
        }
        runner = CliRunner()
        with patch("ionsec_trace.integration.iris.push_to_iris", return_value=fake) as m:
            result = runner.invoke(
                main, ["iris", "push", str(iris_evidence), "--host", "https://iris.local",
                       "--api-key", "k", "--case-id", "42"]
            )
        assert result.exit_code == 0
        assert "Case: 42 (created)" in result.output
        assert "Steps OK: 7/7" in result.output
        # Case-id is forwarded.
        assert m.call_args[1]["case_id"] == 42

    def test_iris_push_partial_failure_exits_nonzero(self, iris_evidence):
        from unittest.mock import patch

        from click.testing import CliRunner

        from ionsec_trace.cli import main

        fake = {
            "ok": True,
            "case_id": 42,
            "created_case": True,
            "summary": {"findings": 1, "iocs": 3, "timeline_events": 1,
                        "priority_actions": 1, "evidence_files_uploaded": 1},
            "ok_count": 6,
            "total_count": 7,
            "errors": [{"item": "ioc:xxx", "error": "invalid ioc type"}],
        }
        runner = CliRunner()
        with patch("ionsec_trace.integration.iris.push_to_iris", return_value=fake):
            result = runner.invoke(
                main, ["iris", "push", str(iris_evidence), "--host", "https://iris.local",
                       "--api-key", "k"]
            )
        assert result.exit_code != 0
        assert "Partial failures" in result.output
        assert "invalid ioc type" in result.output
