# Contributing to TRACE

Thank you for your interest in contributing to TRACE (Tool for Reconnaissance of AI & Compute Evidence)!

TRACE is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. By contributing, you agree that your contributions are licensed under the same terms. See `LICENSE` for details.

## Project Layout

The package is `ionsec_trace`, living under `src/ionsec_trace/`:

```
src/ionsec_trace/
├── cli.py            # Click CLI entry point (`trace` console script)
├── collector/        # Platform collectors (discover/collect/parse)
│   ├── base.py       # BaseCollector ABC, dataclasses, enums, helpers
│   └── __init__.py   # Registers all collectors in ALL_COLLECTORS
├── analyzer/         # Timeline, IOC extraction, ATLAS mapping, risk scoring
├── reporter/         # HTML, JSON, and STIX report generators
└── hash/             # Hashing utilities
tests/                # pytest suite
velociraptor/         # Velociraptor artifacts (TRACE.AI.*.yaml)
```

## Development Setup

```bash
git clone https://github.com/ionsec/trace.git
cd trace
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The `[dev]` extra installs `pytest`, `pytest-cov`, and `ruff`. If you prefer `uv`, `uv sync --extra dev` works as well.

## Adding a New Collector

1. Create a new file in `src/ionsec_trace/collector/your_platform.py`
2. Inherit from `BaseCollector` and implement the three abstract methods:
   - `discover()` → returns `bool` (True if platform is detected)
   - `collect()` → returns `list[CollectedFile]`
   - `parse()` → returns `list[ParsedArtifact]`
3. Register the collector in `src/ionsec_trace/collector/__init__.py`:
   - Add an import at the top (e.g. `from ionsec_trace.collector.your_platform import YourPlatformCollector`)
   - Append the class to the `ALL_COLLECTORS` list
4. Add tests in `tests/test_collectors.py`

### Collector Template

```python
from ionsec_trace.collector.base import (
    BaseCollector, CollectedFile, ParsedArtifact,
    PlatformCategory, Severity,
)

class MyCollector(BaseCollector):
    PLATFORM_NAME = "my_platform"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE  # or AGENT, DEVTOOL, CLOUD
    VERSION = "1.0.1"
    PROCESS_NAMES = ["my_platform"]
    SERVICE_PORTS = [8080]

    # Per-OS default paths
    LINUX_PATHS = ["~/.myplatform"]
    MACOS_PATHS = ["~/Library/Application Support/MyPlatform"]
    WINDOWS_PATHS = ["%APPDATA%\\MyPlatform"]

    def discover(self) -> bool:
        """Detect if platform is installed."""
        ...

    def collect(self) -> list[CollectedFile]:
        """Collect forensic artifacts."""
        ...

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected artifacts into structured findings."""
        ...
```

### BaseCollector API

- **Enums** — `PlatformCategory` (`INFERENCE`, `AGENT`, `DEVTOOL`, `CLOUD`) and `Severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **`CollectedFile`** fields: `original_path`, `source_os`, `platform`, `artifact_type`, `size_bytes`, `sha256`, `collected_at`, `collector_version`.
- **`ParsedArtifact`** fields: `platform`, `artifact_type`, `severity`, `data`, `source_file`, `timestamp`, `iocs`, `mitre_atlas`, `risk_score`.
- **Helpers** (available on `self`):
  - `calculate_hash(file_path)` — SHA-256 of a file
  - `timestamp()` — current UTC time in ISO 8601
  - `detect_os()` — `"linux"`, `"macos"`, or `"windows"`
  - `get_user_home_dirs()` — home dirs for all users on the system
  - `safe_read_json(file_path)` — parse JSON, returns `None` on failure
  - `safe_read_file(file_path, max_bytes=10*1024*1024)` — read text up to a size cap, returns `None` on failure

## Adding an Analyzer

Analyzers live in `src/ionsec_trace/analyzer/` and operate on collected evidence to produce findings, timelines, IOCs, ATLAS mappings, or risk scores.

1. Create a new file in `src/ionsec_trace/analyzer/your_analyzer.py`
2. Follow the existing patterns (e.g. `UnifiedTimeline`, `IOCExtractor`, `ATLASMapper`, `RiskScorer`, `ConversationParser`)
3. Export public classes from `src/ionsec_trace/analyzer/__init__.py` and add them to `__all__`
4. Add tests in `tests/test_analyzers.py`

## Adding a Reporter

Reporters live in `src/ionsec_trace/reporter/` and render evidence into output formats.

1. Create a new file in `src/ionsec_trace/reporter/your_report.py`
2. Follow the existing pattern (`HTMLReportGenerator`, `JSONReportGenerator`, `STIXGenerator`) — each takes an `evidence_dir` and exposes a `generate()` method
3. Export the class from `src/ionsec_trace/reporter/__init__.py` and add it to `__all__`; wire it into `generate_all()` if it should run by default
4. Add tests in `tests/test_reporters.py`

## Adding a Velociraptor Artifact

1. Create `velociraptor/TRACE.AI.YourPlatform.yaml`
2. Follow the existing pattern (multi-OS sources with preconditions)
3. Include parameters: `CollectChatHistory`, `CollectLogs`, `DeepCollection` (add platform-specific ones such as `CollectModelManifests` or `CollectAPIResponses` where relevant)
4. Validate YAML: `python3 -c "import yaml; yaml.safe_load(open('your.yaml'))"`

## Code Style

- Python 3.10+ (the project targets `py310`)
- Type hints required
- Docstrings on all public methods
- Max line length: 120 characters
- Imports: `from ionsec_trace.collector.base import ...` (NOT `from trace.` — `trace` conflicts with the Python standard library module)
- Lint with `ruff` (configured in `pyproject.toml`): `ruff check .`

## Forensic Soundness Requirements

All collectors MUST:
1. **Never modify source files** — read-only access only
2. **Compute SHA-256** of every collected file via `self.calculate_hash()`
3. **Use UTC timestamps** via `self.timestamp()` (ISO 8601)
4. **Handle missing files gracefully** — `self.safe_read_file()` and `self.safe_read_json()`
5. **Redact API keys** in parsed artifacts — never expose full key values

## Running Tests

```bash
pytest tests/ -v
```

The suite lives in `tests/` (`test_collectors.py`, `test_analyzers.py`, `test_reporters.py`, `test_ai_ioc_detector.py`). Run `ruff check .` before submitting to catch style issues.

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-collector`)
3. Commit with clear messages
4. Run the test suite and `ruff check .`
5. Open a Pull Request against `main`

## Reporting Issues

- Security vulnerabilities: security@ionsec.io
- Bug reports and feature requests: GitHub Issues
