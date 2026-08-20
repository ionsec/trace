# Installing TRACE

TRACE ships two ways:

- **Python package** (`ionsec-trace`) — the full CLI with `discover`, `collect`,
  `analyze`, `report`, `scan`, and `iris` subcommands.
- **Single self-contained Go binary** — near-identical capabilities and the same forensic
  data model with no Python required. Runs `discover`, `scan`, `collect`, and
  `report`.

Both produce interchangeable, forensically sound evidence (read-only
collection, SHA-256 hashing, chain of custody, UTC timestamps). Pick whichever
fits your environment. The one capability difference: the Go binary
collects SQLite conversation stores but does not parse them — use the Python CLI
when you need SQLite conversation parsing.

---

## 1. Python installation (full CLI)

### Requirements

- **Python 3.10+**
- `pip` (or `uv` if you prefer)

### From PyPI

```bash
pip install ionsec-trace
```

We recommend installing into a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows

pip install --upgrade pip
pip install ionsec-trace
```

If you use `uv`:

```bash
uv venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows
uv pip install ionsec-trace
```

### From source (development / latest)

```bash
git clone https://github.com/ionsec/trace.git
cd trace
python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows
pip install -e .
```

For the development extra (pytest, ruff) use `pip install -e ".[dev]"`, or
`uv sync --extra dev`. The optional `iris` extra pulls in the DFIR-IRIS client:

```bash
pip install -e ".[dev,iris]"
```

### Verify

```bash
trace --version
# TRACE, version 1.0.1
```

---

## 2. Go binary (no Python required)

TRACE ships as a **single self-contained Go binary** for macOS, Linux, and
Windows, so anyone can run shadow-AI detection and collection without installing
Python.

### Option A — use a prebuilt binary

Prebuilt executables live in `go/bin/` in the repository:

| File | Target |
|------|--------|
| `go/bin/trace-darwin-arm64` | macOS (Apple Silicon) |
| `go/bin/trace-darwin-amd64` | macOS (Intel) |
| `go/bin/trace-linux-amd64` | Linux x86-64 |
| `go/bin/trace-linux-arm64` | Linux ARM64 |
| `go/bin/trace-windows-amd64.exe` | Windows x86-64 |

Copy the matching binary somewhere on your `PATH`, or invoke it directly. On
macOS/Linux, mark it executable first:

```bash
chmod +x go/bin/trace-darwin-arm64
go/bin/trace-darwin-arm64 --version
```

### Option B — build it yourself

The Go source in `go/` has a single pure-Go dependency (a Zstandard decoder, for
DeepSeek Harness transcripts), so it cross-compiles cleanly with no cgo. With Go
installed:

```bash
make -C go all
```

This builds every target into `go/bin/`. You can also build a single binary for
your current platform:

```bash
make -C go build        # -> go/bin/trace
```

or cross-compile manually, e.g.:

```bash
GOOS=linux GOARCH=amd64 go build -o bin/trace-linux-amd64 ./go/cmd/trace
```

### Run the Go binary

```bash
# One-shot: discover → deep collect → HTML + JSON reports
./bin/trace-darwin-arm64 run -o /tmp/evidence

# Detect shadow-AI tools
./bin/trace-darwin-arm64 discover

# Quick risk summary (no files written)
./bin/trace-darwin-arm64 scan

# Collect forensic artifacts + chain of custody
./bin/trace-darwin-arm64 collect -o /tmp/evidence

# Analyze evidence (IOCs, secrets, conversations, MITRE, kill chain, risk)
./bin/trace-darwin-arm64 analyze /tmp/evidence

# Generate HTML, JSON and STIX 2.1 reports
./bin/trace-darwin-arm64 report -o /tmp/evidence --format all
```

The Go binary implements near-identical capabilities to the Python CLI over the same
forensic data model, producing interchangeable evidence. Its collection pipeline is **curated** — it
retains only analyst-parseable artifacts and parses SQLite databases into
analyst-facing summaries rather than collecting them raw. Note: the Go binary
collects SQLite conversation stores but does not parse them — use the Python CLI when you
need SQLite conversation parsing.

---

## 3. Platform notes

### macOS

- The Python CLI reads user home directories under `/Users/<name>/`; run it with
  the privileges of the user whose evidence you are collecting.
- Apple Silicon users should pick `trace-darwin-arm64`; Intel users
  `trace-darwin-amd64`.
- The first time you run an unsigned Go binary, macOS Gatekeeper may block it:
  right-click → **Open** to allow it once, or build your own copy with
  `make -C go all`.

### Linux

- Works out of the box with either the Python CLI or the Go binary.
- To collect evidence across *all* users on a multi-user system, run with
  elevated privileges:

  ```bash
  sudo trace collect --output /evidence/
  ```

### Windows

- Install Python from python.org (check "Add to PATH") and use a virtual
  environment as shown above.
- Use `trace-windows-amd64.exe` for the Go binary.
- Run from PowerShell or Command Prompt. For collection across all user
  profiles, run as Administrator:

  ```powershell
  trace collect --output C:\evidence\
  trace-windows-amd64.exe collect -o C:\evidence --deep
  ```

- Always give `--output` / `-o` a Windows path (`C:\evidence`, `.\evidence`).
  The POSIX examples elsewhere in the docs use `/evidence`, which on Windows is
  rooted but has no drive letter: it resolves against the drive of the current
  directory, so evidence lands in `C:\evidence` — or the run fails at the drive
  root without Administrator rights. TRACE prints the resolved absolute path
  and warns about the driveless form; read that line to confirm where the
  evidence went.

---

## 4. First run

### Discover what AI tools are present

```bash
trace discover
# or, for the Go binary:
./bin/trace-darwin-arm64 discover
```

This scans all **27 collectors** across local inference engines, agent
frameworks, AI development tools, cloud caches, live network AI traffic,
source-code AI scanning, Docker AI workloads, and browser-based AI assistants.
For a fast non-persisting summary (no files written):

```bash
trace scan
```

### A minimal collect → report cycle

```bash
# 1. Collect evidence (all platforms) into a directory
trace collect --output /tmp/evidence --deep

# 2. Analyze: timeline, IOCs, MITRE ATLAS/ATT&CK, risk score
trace analyze /tmp/evidence --mitre-atlas --risk-score

# 3. Generate HTML + JSON + STIX reports
trace report /tmp/evidence --format all
```

Each `collect` writes a `CHAIN_OF_CUSTODY.json` manifest with SHA-256 hashes,
timestamps, and the tool version. Reports land inside the evidence directory:
`TRACE_Report_<id>.html`, `TRACE_Report_<id>.json`, and
`TRACE_Report_<id>.stix.json`.

---

## 5. Dependencies & footprint

The Python package installs `click`, `rich`, `pyyaml`, and `jinja2` (plus
optional `dfir-iris-client` for the `iris` subcommands). No external databases,
services, or API keys are required for local collection. The Go binary is
statically linked and has **zero** runtime dependencies to install.

---

## 6. Troubleshooting

- **`trace: command not found`** — your virtual environment is not activated, or
  the Go binary is not on `PATH`. Re-activate the venv, or invoke the binary by
  its full path.
- **Python stdlib `trace` conflict** — the package is imported as `ionsec_trace`,
  never `trace`. Import errors like `cannot import name 'BaseCollector' from
  'trace'` mean Python picked up the stdlib module; use the correct import in
  your own code.
- **Permission denied on evidence** — run with privileges covering the target
  user home directories (see platform notes above).
- **SQLite locking** — TRACE opens databases read-only; if a service is actively
  writing, stop it before collection or use `--no-hash`.

See [GUIDE.md](GUIDE.md) for the full user guide and
[WALKTHROUGH.md](WALKTHROUGH.md) for an end-to-end investigation.
