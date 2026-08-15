# TRACE — Walkthrough

## Complete Forensic Investigation: From Discovery to Report

This walkthrough demonstrates a full forensic investigation using TRACE on a system running Ollama and Hermes Agent.

---

## Step 1: Installation

```bash
# Install from PyPI (when published)
pip install ionsec-trace

# Or install from source
git clone https://github.com/ionsec/trace.git
cd trace
pip install -e .
```

Verify installation:
```bash
$ trace --version
TRACE, version 1.0.1
```

> **Go binary (no Python required):** TRACE also ships as a single
> self-contained Go binary. Use a prebuilt executable from `go/bin/`
> (`trace-darwin-arm64`, `trace-linux-amd64`, `trace-windows-amd64.exe`, …), or
> build your own with `make -C go all`. It supports `run` (one-shot:
> discover → deep collect → HTML+JSON), `discover`, `scan`, `collect`, and
> `report`, e.g. `./go/bin/trace-darwin-arm64 run -o /tmp/evidence`. Its
> collection pipeline is **curated** — it retains only analyst-parseable
> artifacts and parses SQLite databases into analyst-facing summaries. See
> [INSTALLATION.md](INSTALLATION.md) for full instructions.

---

## Step 2: Discovery — What AI platforms are on this system?

```bash
$ trace discover
Discovered 5 AI platform(s):
  • ollama (inference)
  • hermes (agent)
  • text_generation_webui (inference)
  • llama_cpp (inference)
  • huggingface (cloud)
```

TRACE automatically scans for 27 platforms across 4 categories:
- **Inference**: Ollama, LM Studio, GPT4All, text-generation-webui, llama.cpp, KoboldCpp, LiteLLM, Bifrost, Unsloth
- **Agent**: DeepSeek Harness (dsh), Hermes, AutoGPT, CrewAI, Aider, Shell-GPT, Devin, Eigent, Shadow AI, Docker AI
- **DevTool**: Cursor, Claude Code, Antigravity, VSCodium, Code Scanner
- **Cloud**: HuggingFace cache, Network AI, Browser AI

The **Shadow AI** collector is a meta-collector that aggregates evidence of
unmanaged/unsanctioned AI usage. The **Docker AI**, **Browser AI**, **Network AI**,
and **Code Scanner** collectors detect AI workloads in containers, browser-based
AI assistants (Brave Leo, Perplexity, Copilot, ChatGPT, Gemini), live
process→domain AI traffic, and AI framework usage in source code.

---

## Step 3: Collection — Gather forensic artifacts

```bash
$ trace collect --output /tmp/trace_evidence --deep

ollama: collecting...
  Collected 14 artifacts
  Parsed 12 artifacts
hermes: collecting...
  Collected 60 artifacts
  Parsed 5 artifacts
huggingface: collecting...
  Collected 68 artifacts
  Parsed 12 artifacts

Collection complete: 144 artifacts from 4 platform(s)
```

The `--deep` flag enables collection of session-level data (conversations, chat history). Without it, only config and metadata are collected.

### What gets collected?

| Platform | Evidence Types |
|----------|---------------|
| Ollama | Config, model manifests, Ed25519 signing keys, CLI history, conversation DB |
| Hermes | Sessions, state.db, memories, cron, secrets, skills, logs, config, auth |
| HuggingFace | Model configs, refs, snapshots, auth token |

### Chain of Custody

Every collection produces a `CHAIN_OF_CUSTODY.json`:
```json
{
  "tool": "TRACE",
  "version": "1.0.1",
  "collected_at": "2026-08-13T08:56:55.425142+00:00",
  "total_files": 144,
  "files": [
    {
      "original_path": "/root/.ollama/config.json",
      "source_os": "linux",
      "platform": "ollama",
      "artifact_type": "config",
      "size_bytes": 42,
      "sha256": "91b20e0c0e0ee29df7a197457686231c...",
      "collected_at": "2026-08-13T08:56:55.425142+00:00"
    }
  ]
}
```

---

## Step 4: Analysis — Extract IOCs, map to ATLAS, score risk

```bash
$ trace analyze /tmp/trace_evidence --mitre-atlas --risk-score

Analyzing evidence from /tmp/trace_evidence
  Timeline: 144 events
  IOCs: 8261 indicators found
    filepath: 5670
    url: 1428
    domain: 369
    hash_sha1: 186
    exfil_pattern: 142
    hash_sha256: 127
    ip: 123
    command: 113
    email: 54
    hash_md5: 49
  ATLAS mappings: 2235 technique mappings
    AML.T0048: AI Tool Integration
    AML.T0025: Modify Model
    AML.T0050: LLM Data Exfiltration
  Overall Risk Score: 12/100 (Low)
    credentials: 0/25
    exfiltration: 10/25
    jailbreak: 0/25
    autonomy: 2/25
```

### IOC Types Explained

| Type | What it finds |
|------|---------------|
| `filepath` | Model paths, config paths, cache paths |
| `url` | API endpoints, model download URLs |
| `domain` | huggingface.co, api.openai.com, ollama.com |
| `api_key` | OpenAI (sk-*), GitHub (ghp_*), Anthropic, xAI patterns |
| `exfil_pattern` | Base64 encoding, pipe-to-network patterns |
| `command` | Shell commands referencing AI tools |

### Risk Scoring

| Category | Weight | What it measures |
|----------|--------|-----------------|
| Credentials | 0-25 | Exposed API keys, auth tokens, .env files |
| Exfiltration | 0-25 | URLs/domains in conversations, outbound data patterns |
| Jailbreak | 0-25 | Prompt injection patterns, system prompt leakage |
| Autonomy | 0-25 | Agent frameworks, autonomous execution evidence |

---

## Step 5: Reporting — Generate forensic reports

```bash
$ trace report /tmp/trace_evidence --format all

  html: /tmp/trace_evidence/TRACE_Report_<id>.html
  json: /tmp/trace_evidence/TRACE_Report_<id>.json
  stix: /tmp/trace_evidence/TRACE_Report_<id>.stix.json
```

### HTML Report

Self-contained, **interactive** forensic report with TRACE branding (crimson `#e63946` accent on dark surfaces). No CDN dependencies — the interactive attack-surface map and charts are embedded in the single HTML file:
- Executive Summary
- Interactive Attack-Surface Map
- Evidence Manifest (collapsible per-artifact details)
- Platform Inventory
- Conversation Timeline
- IOC Summary
- MITRE ATLAS / ATT&CK Mapping
- Kill Chain & Priority Actions
- Risk Assessment

### JSON Report

Structured machine-readable report:
```json
{
  "schema_version": "1.0",
  "metadata": { "tool": "TRACE", "version": "1.0.1" },
  "platforms": [...],
  "evidence_manifest": [...],
  "findings": [...],
  "iocs": [...],
  "timeline": [...],
  "severity_summary": {...},
  "risk_scores": {...},
  "atlas_mapping": [...]
}
```

### STIX 2.1 Report

Valid STIX bundle for ingestion into MISP, OpenCTI, or any TI platform:
```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [
    { "type": "identity", ... },
    { "type": "indicator", "pattern": "[url:value = '...']", ... },
    { "type": "report", ... }
  ]
}
```

---

## Step 6: Velociraptor Deployment (Fleet Collection)

For large-scale deployment, use the Velociraptor artifact pack:

```bash
# Upload artifacts to Velociraptor server
# Via GUI: Server Config → Artifacts → Upload
# Via CLI:
velociraptor --config server.config.yaml artifact upload TRACE.AI.Inference.yaml
velociraptor --config server.config.yaml artifact upload TRACE.AI.Agents.yaml
velociraptor --config server.config.yaml artifact upload TRACE.AI.DevTools.yaml
velociraptor --config server.config.yaml artifact upload TRACE.AI.APIKeys.yaml
velociraptor --config server.config.yaml artifact upload TRACE.AI.HuggingFace.yaml
velociraptor --config server.config.yaml artifact upload TRACE.AI.Network.yaml
velociraptor --config server.config.yaml artifact upload TRACE.AI.Processes.yaml
```

### Collect from a specific endpoint

```vql
SELECT * FROM Artifact(
  TRACE.AI.Inference(
    CollectChatHistory=TRUE,
    CollectLogs=TRUE,
    DeepCollection=FALSE
  )
) WHERE Platform = "ollama"
```

### Hunt across all endpoints

```vql
-- Find all endpoints running Ollama
SELECT * FROM Artifact(TRACE.AI.Processes)
WHERE ProcessName =~ "ollama"
```

---

## Forensic Soundness

Every collection is forensically sound:

1. **Read-only** — All collectors only read; no source modification
2. **SHA-256** — Every file hashed at collection time
3. **Chain of custody** — Manifest with tool version, timestamps, per-file hashes
4. **UTC timestamps** — All timestamps in ISO 8601 UTC
5. **Append-only** — No deletion capability
6. **Minimal footprint** — No agents, registry changes, or persistent processes

---

## Next Steps

- **Validate on Windows/macOS**: Test collector paths on target OS
- **Performance testing**: Test on systems with 100K+ files
- **Custom collectors**: See CONTRIBUTING.md for adding new platforms
- **Report templates**: Customize HTML report with TRACE branding

---

*TRACE — Leave no model untraced.*