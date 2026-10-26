"""Tests for the click CLI. No network, no live tools, no real evidence dirs."""

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from ionsec_trace.cli import main


def _write_minimal_custody(d):
    p = Path(d)
    p.mkdir(parents=True, exist_ok=True)
    (p / "CHAIN_OF_CUSTODY.json").write_text(json.dumps({
        "tool": "TRACE",
        "version": "0.4.0",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "total_files": 0,
        "files": [],
    }))


def test_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "TRACE, version" in result.output


def test_help_lists_commands():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    for cmd in ("discover", "collect", "analyze", "report", "scan", "iris"):
        assert cmd in result.output


def test_discover_runs():
    result = CliRunner().invoke(main, ["discover"])
    assert result.exit_code == 0
    assert ("No AI platforms detected" in result.output
            or "Discovered" in result.output)


def test_scan_runs():
    result = CliRunner().invoke(main, ["scan"])
    assert result.exit_code == 0
    assert "AI platforms detected:" in result.output


def test_analyze_on_minimal_evidence(tmp_path):
    _write_minimal_custody(str(tmp_path))
    result = CliRunner().invoke(main, ["analyze", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Timeline:" in result.output
    assert (tmp_path / "analysis_results.json").exists()


def test_analyze_with_flags(tmp_path):
    _write_minimal_custody(str(tmp_path))
    result = CliRunner().invoke(
        main, ["analyze", str(tmp_path), "--mitre-atlas", "--risk-score", "-v"])
    assert result.exit_code == 0, result.output


def test_report_json_on_minimal_evidence(tmp_path):
    _write_minimal_custody(str(tmp_path))
    result = CliRunner().invoke(main, ["report", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.json").exists()


def test_report_rejects_bad_format(tmp_path):
    result = CliRunner().invoke(main, ["report", str(tmp_path), "--format", "docx"])
    assert result.exit_code != 0


def test_iris_check_requires_host(monkeypatch):
    monkeypatch.delenv("IRIS_HOST", raising=False)
    result = CliRunner().invoke(main, ["iris", "check"])
    assert "IRIS host is required" in result.output


def test_iris_push_requires_host(tmp_path, monkeypatch):
    monkeypatch.delenv("IRIS_HOST", raising=False)
    _write_minimal_custody(str(tmp_path))
    result = CliRunner().invoke(main, ["iris", "push", str(tmp_path)])
    assert "IRIS host is required" in result.output


def test_collect_passes_flags(monkeypatch, tmp_path):
    calls = {}

    def fake_collect_all(output_dir, platforms, do_hash, chain_of_custody, deep):
        calls["kwargs"] = {
            "output_dir": output_dir,
            "platforms": platforms,
            "do_hash": do_hash,
            "chain_of_custody": chain_of_custody,
            "deep": deep,
        }

    import ionsec_trace.collector as collector_mod
    monkeypatch.setattr(collector_mod, "collect_all", fake_collect_all)
    result = CliRunner().invoke(
        main,
        ["collect", "-o", str(tmp_path / "evidence"),
         "-p", "ollama,hermes", "--no-hash", "--deep"],
    )
    assert result.exit_code == 0, result.output
    assert calls["kwargs"]["platforms"] == ["ollama", "hermes"]
    assert calls["kwargs"]["do_hash"] is False
    assert calls["kwargs"]["deep"] is True


def test_collect_defaults_to_all_platforms(monkeypatch, tmp_path):
    calls = {}

    def fake_collect_all(output_dir, platforms, do_hash, chain_of_custody, deep):
        calls["platforms"] = platforms

    import ionsec_trace.collector as collector_mod
    monkeypatch.setattr(collector_mod, "collect_all", fake_collect_all)
    result = CliRunner().invoke(main, ["collect", "-o", str(tmp_path / "e")])
    assert result.exit_code == 0
    assert calls["platforms"] is None
