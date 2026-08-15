# TRACE — User Guide

**Tool for Reconnaissance of AI & Compute Evidence**

Version 1.0.1 · AGPL-3.0-or-later · [ionsec.io](https://ionsec.io)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [CLI Reference](#4-cli-reference)
   - [discover](#discover)
   - [collect](#collect)
   - [analyze](#analyze)
   - [report](#report)
   - [scan](#scan)
5. [Supported Platforms](#5-supported-platforms)
   - [Local Inference Engines](#local-inference-engines)
   - [Agent Frameworks](#agent-frameworks)
   - [AI Development Tools](#ai-development-tools)
6. [Collectors — What TRACE Collects](#6-collectors--what-trace-collects)
   - [Artifact Types](#artifact-types)
   - [Per-Platform Details](#per-platform-details)
7. [Analyzers](#7-analyzers)
   - [Unified Timeline](#unified-timeline)
   - [IOC Extractor](#ioc-extractor)
   - [MITRE ATLAS Mapper](#mitre-atlas-mapper)
   - [Risk Scorer](#risk-scorer)
8. [Reporters](#8-reporters)
   - [HTML Report](#html-report)
   - [JSON Report](#json-report)
   - [STIX 2.1 Report](#stix-21-report)
9. [Velociraptor Integration](#9-velociraptor-integration)
10. [Forensic Soundness](#10-forensic-soundness)
11. [Typical Workflows](#11-typical-workflows)
    - [Incident Response](#incident-response)
    - [Compliance Audit](#compliance-audit)
    - [Fleet-wide AI Discovery](#fleet-wide-ai-discovery)
12. [Configuration](#12-configuration)
13. [Troubleshooting](#13-troubleshooting)
14. [Architecture](#14-architecture)
15. [Extending TRACE](#15-extending-trace)
16. [License](#16-license)

---

## 1. Introduction

TRACE is a forensically sound artifact collector and analyzer for AI tools — the evidence left behind by local inference engines, agent frameworks, and AI-assisted development tools. It answers questions like:

- **What AI tools have been used on this system?** (discovery)
- **What data did they touch or exfiltrate?** (collection & analysis)
- **What is the risk posture?** (scoring & ATLAS mapping)
- **Can I hand this to a SIEM or threat intel platform?** (reporting)

TRACE is designed for DFIR professionals, security auditors, and incident responders who need to enumerate, collect, and analyze AI-related forensic artifacts across Windows, macOS, and Linux endpoints.

### Key Principles

| Principle | Implementation |
|---|---|
| **Read-only** | All file reads are immutable. SQLite databases are opened in read-only mode. No source files are ever modified. |
| **Verifiable** | SHA-256 hash of every collected file, verified after copy. |
| **Auditable** | Chain-of-custody manifest with timestamps, examiner metadata, and tool version. |
| **Cross-platform** | Windows, macOS, and Linux paths for every platform. |
| **Dual delivery** | CLI for single-endpoint collection; Velociraptor VQL artifacts for fleet-wide deployment. |

---

## 2. Installation

### From PyPI

```bash
pip install ionsec-trace
```

### From Source

```bash
git clone https://github.com/ionsec/trace.git
cd trace
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate     # Windows
pip install -e .
```

### Go Binary (no Python required)

TRACE also ships as a **single self-contained Go binary** with the same
capabilities as the Python CLI — `run`, `discover`, `scan`, `collect`,
`analyze`, `report` and `iris`, without installing Python. Use a prebuilt
executable from `go/bin/` (`trace-darwin-arm64`, `trace-linux-amd64`,
`trace-windows-amd64.exe`, …), or build your own:

```bash
make -C go all    # builds bin/trace-{darwin,linux,windows}-{amd64,arm64}
```

```bash
./bin/trace-darwin-arm64 run -o /evidence/case-001/   # one-shot: discover → collect → analyze → reports
./bin/trace-darwin-arm64 discover
./bin/trace-darwin-arm64 analyze /evidence/case-001/ --secret-hunt
./bin/trace-darwin-arm64 report -o /evidence/case-001/ --format all
```

The Go binary implements the same platform catalog, secret-detection rule set,
IOC extraction, conversation forensics, MITRE mapping, kill-chain
reconstruction, risk scoring and report formats as the Python CLI, over one
shared forensic data model.
Its collection pipeline is **curated** — it retains only analyst-parseable
artifacts and parses SQLite databases into analyst-facing summaries rather than
collecting them raw. See [INSTALLATION.md](INSTALLATION.md) for the full walkthrough.

### Verify

```bash
trace --version
# TRACE, version 1.0.1
```

### Dependencies

TRACE requires Python 3.10+ and installs the following automatically:

| Package | Purpose |
|---|---|
| `click >= 8.1` | CLI framework |
| `rich >= 13.0` | Terminal formatting and tables |
| `pyyaml >= 6.0` | YAML parsing (Velociraptor artifacts) |
| `jinja2 >= 3.1` | HTML report templating |

No external databases, services, or API keys are needed for local collection.

---

## 3. Quick Start

```bash
# 1. Discover what AI tools are present
trace discover

# 2. Collect all forensic evidence
trace collect --output /evidence/case-001/

# 3. Analyze with ATLAS mapping and risk scoring
trace analyze /evidence/case-001/ --mitre-atlas --risk-score

# 4. Generate all report formats
trace report /evidence/case-001/ --format all
```

### One-Liner Quick Scan

For a fast, non-persisting check of what AI tools exist on a system:

```bash
trace scan
```

This runs discovery and prints a summary without writing any files.

---

## 4. CLI Reference

### `discover`

Detect AI platforms installed or used on the local system.

```bash
trace discover [--verbose/-v]
```

| Flag | Description |
|---|---|
| `--verbose` / `-v` | Show artifact paths for each discovered platform |

Scans all registered collectors and reports which platforms are present. Use this before a full collection to scope your evidence gathering.

**Example output:**

```
Discovered 5 AI platform(s):
  • ollama (inference)
  • hermes (agent)
  • text-generation-webui (inference)
  • huggingface (cloud)
  • lm_studio (inference)
```

With `--verbose`, each platform also lists the artifact paths it detected (config files, history databases, model manifests, etc.).

---

### `collect`

Collect forensic artifacts from detected AI platforms.

```bash
trace collect --output DIR [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--output` / `-o` | *required* | Output directory for evidence |
| `--platforms` / `-p` | all | Comma-separated platform list (e.g., `ollama,hermes`) |
| `--hash` / `--no-hash` | `--hash` | SHA-256 hash every collected file |
| `--chain-of-custody` / `--no-chain-of-custody` | `--chain-of-custody` | Write a `CHAIN_OF_CUSTODY.json` manifest |
| `--deep` | off | Include session history, large databases, and verbose artifacts |

**Examples:**

```bash
# Collect everything, all platforms
trace collect --output /evidence/case-001/

# Collect only Ollama and Hermes evidence
trace collect --output /evidence/case-001/ --platforms ollama,hermes

# Deep collection (includes chat history, session JSONL, etc.)
trace collect --output /evidence/case-001/ --deep

# Skip hashing (faster, but forensically weaker)
trace collect --output /evidence/case-001/ --no-hash
```

**Output structure:**

```
/evidence/case-001/
├── CHAIN_OF_CUSTODY.json        # Manifest with hashes, timestamps, tool version
├── ollama/
│   ├── config.json              # Ollama configuration
│   ├── history                  # CLI command history
│   ├── models_manifest/         # Model manifests and blobs
│   └── ...
├── hermes/
│   ├── config.yaml              # Hermes configuration
│   ├── state.db                 # Session/message database (read-only copy)
│   └── ...
└── ...
```

> **Note:** The `--deep` flag is recommended for full incident response but significantly increases collection time and output size. It includes large files such as SQLite databases, session JSONL files, and model manifests. For quick triage, omit `--deep`.

---

### `analyze`

Run analysis pipelines on collected evidence.

```bash
trace analyze EVIDENCE_DIR [OPTIONS]
```

| Flag | Description |
|---|---|
| `--mitre-atlas` | Map findings to MITRE ATLAS techniques |
| `--mitre-attack` | Map findings to MITRE ATT&CK techniques |
| `--risk-score` | Calculate risk scores (0–100) per category |
| `--verbose` / `-v` | Show detailed analysis output |

**Example:**

```bash
trace analyze /evidence/case-001/ --mitre-atlas --mitre-attack --risk-score
```

**Output:**

```
Analyzing evidence from /evidence/case-001/
  Timeline: 144 events
  IOCs: 8261 indicators found
    ip: 342
    url: 2890
    domain: 1540
    api_key: 28
    ...
  ATLAS mappings: 2235 technique mappings
    AML.T0010: Prompt Injection
    AML.T0011: LLM Jailbreak
    AML.T0050: LLM Data Exfiltration
    ...
  Overall Risk Score: 12/100 (Low)
    credentials: 3/25
    exfiltration: 2/25
    jailbreak: 4/25
    autonomy: 3/25
```

---

### `report`

Generate forensic reports from analyzed evidence.

```bash
trace report EVIDENCE_DIR [OPTIONS]
```

| Flag | Choices | Default | Description |
|---|---|---|---|
| `--format` / `-f` | `html`, `json`, `stix`, `all` | `all` | Report format(s) to generate |

**Examples:**

```bash
# Generate all report formats
trace report /evidence/case-001/ --format all

# Generate only an HTML forensic report
trace report /evidence/case-001/ --format html

# Generate JSON for SIEM ingestion and STIX for threat intel
trace report /evidence/case-001/ --format json,stix
```

Output files are written inside the evidence directory:

| Format | Filename | Purpose |
|---|---|---|
| HTML | `TRACE_Report_<id>.html` | Human-readable interactive forensic report (TRACE-branded) |
| JSON | `TRACE_Report_<id>.json` | Machine-readable, TRACE JSON schema v1.0.0 |
| STIX | `TRACE_Report_<id>.stix.json` | STIX 2.1 bundle for MISP / OpenCTI / TI platforms |

---

### `scan`

Quick non-persisting discovery scan — discovers platforms and reports a summary without writing files.

```bash
trace scan
```

Equivalent to `trace discover` with a summary count. Useful for rapid triage where you don't need full evidence collection.

---

## 5. Supported Platforms

### Local Inference Engines

| Platform | Category | Key Artifacts |
|---|---|---|
| **Ollama** | inference | Config, model manifests, CLI history, ed25519 keys, process info |
| **LM Studio** | inference | Config, model metadata, conversation history, download cache |
| **GPT4All** | inference | Chat history SQLite, model metadata, config |
| **text-generation-webui** | inference | Chat logs, model configs, LoRA adapters, training params |
| **llama.cpp** | inference | Binary config, prompt files, model paths |
| **KoboldCpp** | inference | Config JSON, session history, model info |
| **LiteLLM** | inference | Config, proxy logs, model routing, API key usage |
| **Bifrost** | inference | Config, session data, model info |
| **Unsloth** | inference | Config, training artifacts, model metadata |
| **HuggingFace Hub** | cloud | Cached model metadata, auth tokens, download cache |

### Agent Frameworks

| Platform | Category | Key Artifacts |
|---|---|---|
| **Hermes Agent** | agent | state.db, session JSONL, config.yaml, .env, skills, memories, cron |
| **AutoGPT** | agent | Workspace files, agent logs, config |
| **CrewAI** | agent | Crew definitions, execution logs, tool configs |
| **Aider** | agent | Chat history, .aider.conf.yml, model metadata |
| **Shell-GPT** | agent | Shell history, chat sessions, config |
| **Devin** | agent | Session data, workspace files, execution logs |
| **Eigent** | agent | Agent config, session data, execution logs |
| **Shadow AI** | agent | Meta-collector aggregating evidence of unmanaged/unsanctioned AI usage |

### AI Development Tools

| Platform | Category | Key Artifacts |
|---|---|---|
| **Cursor** | devtool | Settings, extensions, workspace storage, AI conversation logs |
| **Claude Code** | devtool | Session data, config, conversation history |
| **DeepSeek Harness** | agent | Session transcripts (Zstandard `session.jsonl.zstd`), `.credentials.yaml`, plugin/MCP composition, skills, `AGENTS.md` |
| **Antigravity** | devtool | Settings, workspace storage, AI conversation data |
| **VSCodium** | devtool | Settings, extensions, workspace storage, AI conversation logs |
| **Code Scanner** | devtool | AI framework imports, MCP server configs, hardcoded API keys in source |

### Live Network, Container & Browser AI

| Platform | Category | Key Artifacts |
|---|---|---|
| **Network AI** | cloud | Live process→domain AI traffic classification against 100+ AI providers |
| **Docker AI** | agent | Docker AI (Gordon) and hosted LLM images/containers (ollama, LocalAI, vLLM, OpenWebUI) |
| **Browser AI** | cloud | Browser-based AI assistant evidence: Brave Leo, Perplexity, Copilot, ChatGPT, Claude, Gemini web |

---

## 6. Collectors — What TRACE Collects

TRACE ships with **27 collectors** spanning local inference engines, agent
frameworks, AI development tools, and live network/container/browser AI.

### Artifact Types

Every collected file is classified by an artifact type:

| Type | Description |
|---|---|
| `config` | Configuration files (JSON, YAML, TOML, .env) |
| `conversation` | Chat/conversation history databases and files |
| `model_manifest` | Model index files, digest references, size metadata |
| `credential` | API keys, tokens, certificates, ed25519 keys |
| `log` | Service logs, application logs |
| `session` | Per-session data (JSONL, SQLite rows) |
| `history` | Shell/CLI command history |
| `cache` | Downloaded models, cached responses |
| `process` | Running process information (volatile evidence) |
| `network` | Network connections and listening ports (volatile evidence) |

### Per-Platform Details

#### Ollama

- `~/.ollama/config.json` — runtime configuration
- `~/.ollama/history` — CLI command history
- `~/.ollama/models/manifests/` — model manifests (registry namespace, tag, digest)
- `~/.ollama/models/blobs/` — model layer blobs (skipped unless `--deep`)
- `~/.ollama/id_ed25519` — private signing key (credential)
- `~/.ollama/id_ed25519.pub` — public key
- Running Ollama process info and network connections on port 11434
- API `/api/tags` model inventory (when service is running)
- System paths: `/usr/share/ollama/.ollama` (Linux system install)

#### Hermes Agent

- `~/.hermes/config.yaml` — main configuration (model, providers, toolsets)
- `~/.hermes/.env` — environment variables (API keys, secrets)
- `~/.hermes/auth.json` — OAuth tokens, credential pool
- `~/.hermes/state.db` — SQLite database: sessions, messages, FTS indexes, billing
- `~/.hermes/sessions/*.jsonl` — per-session full conversation logs (`--deep`)
- `~/.hermes/memories/` — persistent memory files
- `~/.hermes/skills/` — skill definitions and templates
- `~/.hermes/cron/` — scheduled job definitions and execution history
- Gateway state files: `gateway_state.json`, `gateway.pid`, `gateway.lock`

#### LM Studio

- `~/.cache/lm-studio/` — model cache and configuration (Linux/macOS)
- `%APPDATA%\LM Studio\` — configuration (Windows)
- Conversation history and download metadata

#### GPT4All

- `~/.local/share/gpt4all/` — chat history SQLite database
- Model metadata and configuration files

#### text-generation-webui

- `~/.cache/text-generation-webui/` — oobabooga installation directory
- Chat logs in `history/` subdirectory
- Model configurations and LoRA adapter settings

#### llama.cpp

- Detected via binary presence (`llama-cli`, `llama-server`, `main`)
- Configuration files and prompt files
- Running process info

#### KoboldCpp

- `~/.cache/koboldcpp/` — config JSON and session data
- Model paths and koboldcpp settings

#### LiteLLM

- `~/.config/litellm/` — configuration and proxy settings
- Model routing config, proxy logs, and API key usage records

#### Bifrost

- `~/.config/bifrost/` — configuration and session data
- Model info and runtime settings

#### Unsloth

- `~/.cache/unsloth/` — training artifacts and model metadata
- Configuration and fine-tuning session data

#### AutoGPT

- `~/.auto-gpt/` or `~/AutoGPT/` — workspace and agent files
- Agent configuration and execution logs

#### CrewAI

- Crew definition YAML/JSON files
- Execution logs and tool configuration

#### Aider

- `~/.aider.conf.yml` — Aider configuration
- `~/.aider.chat.history.md` — conversation history
- `.aider*` project-level files

#### Shell-GPT

- `~/.config/shell-gpt/` — configuration and session data
- Chat history and API usage logs

#### Devin

- `~/.devin/` — session data, workspace files, and execution logs
- Agent configuration and task history

#### Eigent

- `~/.eigent/` — agent configuration and session data
- Execution logs and tool usage records

#### Shadow AI

- Meta-collector that aggregates evidence of unmanaged or unsanctioned AI usage across the system
- Correlates artifacts from other collectors to surface shadow-AI activity

#### Cursor

- Cursor extension and settings directories
- Workspace storage and AI conversation data
- Platform-specific paths: `~/.cursor/` (Linux/macOS), `%APPDATA%\Cursor\` (Windows)

#### Claude Code

- `~/.claude/` — session data and configuration
- Conversation history and model metadata

#### Antigravity

- `~/.antigravity/` — settings and workspace storage
- AI conversation data and model metadata

#### VSCodium

- `~/.config/VSCodium/` — settings, extensions, and workspace storage
- AI conversation logs and extension data

#### Network AI

- Live detection of AI network traffic: correlates running processes with outbound connections
- Classifies destination domains against a catalog of 100+ AI providers (OpenAI, Anthropic, Gemini, Bedrock, etc.)
- Volatile evidence — captured before file artifacts

#### Code Scanner

- Scans source code for AI framework imports (LangChain, CrewAI, AutoGen, 80+ others)
- Detects MCP server registrations and configurations
- Flags hardcoded API keys in source trees

#### Docker AI

- Detects Docker's AI assistant **Gordon** and its configuration
- Enumerates hosted LLM workloads (ollama, LocalAI, vLLM, OpenWebUI, etc.) in running containers and the local model registry

#### Browser AI

- Captures browser-based AI assistant evidence from browser history and per-site conversation stores
- Covers Brave Leo, Perplexity, Microsoft Copilot, ChatGPT, Claude, and Gemini web

#### HuggingFace Hub

- `~/.cache/huggingface/` — model cache, metadata, auth tokens
- `~/.cache/huggingface/hub/` — downloaded model repos
- `~/.cache/huggingface/token` — authentication token (credential)

---

## 7. Analyzers

### Unified Timeline

The timeline analyzer reconstructs a chronological sequence of all AI-related activity from the collected evidence. It reads the chain-of-custody manifest and parsed artifacts, then orders events by timestamp.

**Timeline event fields:**

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 UTC timestamp |
| `platform` | Source platform (e.g., `ollama`, `hermes`) |
| `artifact_type` | Category (e.g., `conversation`, `config`, `credential`) |
| `description` | Human-readable event description |
| `severity` | `critical`, `high`, `medium`, `low`, or `info` |
| `source_path` | Original file path on the endpoint |
| `user` | Associated user (if determinable) |

**Usage (CLI):**

```bash
trace analyze /evidence/case-001/
```

**Usage (Python API):**

```python
from ionsec_trace.analyzer import UnifiedTimeline

timeline = UnifiedTimeline("/evidence/case-001/")
timeline.load()
for event in timeline.events:
    print(f"{event.timestamp} [{event.severity.value}] {event.platform}: {event.description}")
```

---

### IOC Extractor

Scans all collected files for indicators of compromise using pattern-matching regexes.

**IOC types detected:**

| Type | Description |
|---|---|
| `ip` | IPv4 addresses |
| `url` | HTTP/HTTPS URLs |
| `domain` | Domain names |
| `email` | Email addresses |
| `hash` | MD5, SHA-1, SHA-256 hashes |
| `filepath` | Suspicious file paths |
| `command` | Shell commands in conversation data |
| `api_key` | Exposed API keys and tokens |
| `exfil_pattern` | Data exfiltration patterns (base64, pipes to network) |

**Usage (CLI):**

```bash
trace analyze /evidence/case-001/ --mitre-atlas --risk-score
```

**Usage (Python API):**

```python
from ionsec_trace.analyzer import IOCExtractor

extractor = IOCExtractor("/evidence/case-001/")
extractor.extract()
for ioc in extractor.iocs:
    print(f"[{ioc.ioc_type}] {ioc.value} ({ioc.severity.value}) — {ioc.context}")
```

---

### MITRE ATLAS Mapper

Maps extracted IOCs and findings to MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) techniques. ATLAS is the AI-specific extension of the MITRE ATT&CK framework.

**Selected technique mappings:**

| ATLAS ID | Technique | Applicable Platforms |
|---|---|---|
| AML.T0010 | Prompt Injection | inference, agent, devtool |
| AML.T0011 | LLM Jailbreak | inference, agent |
| AML.T0025 | Modify Model | inference, cloud |
| AML.T0043 | Craft Adversarial Input | inference, agent, devtool |
| AML.T0048 | AI Tool Integration | agent, devtool |
| AML.T0049 | Exploit AI Tool Integration | agent, devtool |
| AML.T0050 | LLM Data Exfiltration | inference, agent |
| AML.T0052 | LLM Prompt Leak | inference, agent |
| AML.T0055 | Credential Harvesting | agent, devtool |

**Usage (CLI):**

```bash
trace analyze /evidence/case-001/ --mitre-atlas
```

**Usage (Python API):**

```python
from ionsec_trace.analyzer import ATLASMapper, IOCExtractor

extractor = IOCExtractor("/evidence/case-001/")
extractor.extract()

mapper = ATLASMapper()
mappings = mapper.map_iocs(extractor.iocs)
for m in mappings:
    print(f"{m.technique_id}: {m.technique_name}")
```

---

### Risk Scorer

Calculates a composite risk score from 0 to 100 across four categories:

| Category | Max Points | Indicators |
|---|---|---|
| **Credentials** | 25 | Exposed API keys, tokens in config/logs, hardcoded secrets, shared credentials |
| **Exfiltration** | 25 | Base64 encoding, pipes to network, outbound data patterns, URL patterns in prompts |
| **Jailbreak** | 25 | Known jailbreak prompts, instruction override patterns, system prompt extraction |
| **Autonomy** | 25 | Unsandboxed tool execution, autonomous agent actions, unrestricted tool access |

**Severity classification:**

| Score Range | Severity |
|---|---|
| 0–39 | Low |
| 40–69 | Medium |
| 70–89 | High |
| 90–100 | Critical |

**Usage (CLI):**

```bash
trace analyze /evidence/case-001/ --risk-score
```

**Usage (Python API):**

```python
from ionsec_trace.analyzer import RiskScorer

scorer = RiskScorer()
risk = scorer.calculate_overall_risk(findings=[], iocs=extractor.iocs)
print(f"Score: {risk.score}/100 ({risk.severity})")
print(f"Credentials: {risk.category_scores['credentials']}/25")
print(f"Exfiltration: {risk.category_scores['exfiltration']}/25")
```

---

### AI IOC Detector

The AI-specific IOC detector extends the base IOC extractor with patterns tailored to AI tooling — model identifiers, prompt-injection payloads, AI API endpoints, and agent-specific indicators. It flags evidence that generic IOC scanning would miss.

**AI-specific IOC types detected:**

| Type | Description |
|---|---|
| `model_id` | Model names/identifiers (e.g., `llama3`, `gpt-4`, `mistral`) |
| `ai_api_endpoint` | AI service API endpoints (Ollama, OpenAI, Anthropic, etc.) |
| `prompt_injection` | Prompt-injection and jailbreak payload patterns |
| `agent_command` | Agent framework commands and tool-call patterns |

**Usage (CLI):**

```bash
trace analyze /evidence/case-001/ --mitre-atlas --risk-score
```

**Usage (Python API):**

```python
from ionsec_trace.analyzer import AIIOCDetector

detector = AIIOCDetector("/evidence/case-001/")
detector.extract()
for ioc in detector.iocs:
    print(f"[{ioc.ioc_type}] {ioc.value} ({ioc.severity.value})")
```

---

### Enhanced Risk Scorer

The enhanced risk scorer builds on the base `RiskScorer` with a richer behavioral model. It scores across **8 behavioral categories**, reconstructs a **kill chain**, produces **attack narratives**, and derives **priority actions** for responders.

**Behavioral categories:**

| Category | What it measures |
|---|---|
| Credential exposure | Exposed API keys, tokens, .env files |
| Data exfiltration | Outbound data patterns, URLs/domains in conversations |
| Prompt injection | Injection payloads, system prompt leakage |
| Jailbreak | Known jailbreak prompts, instruction override patterns |
| Autonomy | Agent frameworks, autonomous execution evidence |
| Model tampering | Evidence of model modification or poisoning |
| Tool abuse | Unsandboxed or unrestricted tool execution |
| Persistence | Scheduled jobs, cron, auto-start AI services |

**Outputs:**

- **Kill chain** — maps findings to attack lifecycle stages (reconnaissance → exfiltration)
- **Attack narratives** — human-readable story of the suspected attack sequence
- **Priority actions** — ranked remediation steps for incident responders

**Usage (CLI):**

```bash
trace analyze /evidence/case-001/ --risk-score
```

**Usage (Python API):**

```python
from ionsec_trace.analyzer import EnhancedRiskScorer

scorer = EnhancedRiskScorer()
result = scorer.score(findings=findings, iocs=iocs)
print(f"Score: {result.score}/100 ({result.severity})")
print(f"Kill chain: {result.kill_chain}")
print(f"Priority actions: {result.priority_actions}")
```

---

### Conversation Parser

The conversation parser extracts structured content from chat/session logs (JSONL, SQLite, markdown) collected from AI tools. It normalizes messages, roles, tool calls, and timestamps into a uniform structure for downstream analysis.

Tool-call evidence is promoted to first-class fields — `tool_command`, `tool_input`, `tool_description`, and `workspace` — so analysts can review the exact shell command and structured arguments an AI assistant invoked. Identical user prompts that appear across multiple platforms are deduplicated, with the kept turn's `also_in_tools` list preserving every platform that ran the same prompt.

**Usage (Python API):**

```python
from ionsec_trace.analyzer import ConversationParser

parser = ConversationParser("/evidence/case-001/")
conversations = parser.parse()
for convo in conversations:
    print(f"{convo.platform}: {len(convo.messages)} messages")
```

### Conversation Secret Hunt

Run `trace analyze --secret-hunt` to scan conversation turns (prompts, responses, and tool-call evidence) for leaked secrets. Each finding is enriched with:

- **Leak direction** — whether the secret flowed `user→service` (typed by the subject) or `service→user` (returned by the model / a tool result)
- **Per-field provenance** — which evidence field (content, tool_command, tool_input, tool_description) carried the secret, with start/end offsets
- **Salted fingerprint** — a stable per-scan hash so the same secret can be correlated across rows, sessions, and platforms

Findings are permanently redacted (first4…last4 + length); cleartext never crosses the result path. Results appear in the HTML report's **Secret Hunt** tab and in `report.json` under `conversation_secret_hunt`.

### Conversation Export

Run `trace analyze --export-conversations` to write a shareable evidence package: a `*_timeline.csv` of the parsed turns plus a `manifest.json` recording the SHA-256 of every source artifact, so the originals can be independently re-verified.

---

## 8. Reporters

### HTML Report

A self-contained, **interactive** forensic report with TRACE branding. No external CSS or JS dependencies — everything (including the interactive map and charts) is embedded in a single HTML file, so it works offline and can be shared as a standalone artifact.

**Features:**
- TRACE-branded theme (crimson `#e63946` accent on dark surfaces)
- **Interactive attack-surface map** — clickable node graph of platforms, findings, and their relationships
- **Interactive charts** — findings by severity, IOCs by type, and platform inventory (SVG, no CDN)
- Responsive layout with collapsible sections and tabbed navigation
- Findings table with severity color coding
- IOC summary with type breakdowns
- MITRE ATLAS and MITRE ATT&CK technique mapping tables
- Kill chain analysis and priority actions
- Risk score breakdown with category bars
- Chain-of-custody summary with SHA-256 hashes

```bash
trace report /evidence/case-001/ --format html
# Output: /evidence/case-001/TRACE_Report_<id>.html
```

---

### JSON Report

Structured JSON output following the TRACE JSON schema v1.0.0. Suitable for SIEM ingestion, automation, or programmatic processing.

**Schema structure:**

```json
{
  "schema_version": "1.0.0",
  "tool": "TRACE",
  "tool_version": "1.0.1",
  "report_id": "uuid",
  "generated_at": "ISO-8601",
  "evidence_dir": "/path/to/evidence",
  "summary": { ... },
  "findings": [ ... ],
  "iocs": [ ... ],
  "timeline": [ ... ],
  "atlas_mappings": [ ... ],
  "risk_score": { ... },
  "chain_of_custody": { ... }
}
```

```bash
trace report /evidence/case-001/ --format json
# Output: /evidence/case-001/TRACE_Report_<id>.json
```

---

### STIX 2.1 Report

A STIX 2.1 bundle containing Identity, Indicator, ObservedData, Report, and CourseOfAction objects. Compatible with MISP, OpenCTI, and other threat intelligence platforms.

**STIX object mapping:**

| TRACE Concept | STIX Object Type |
|---|---|
| Organization | `identity` |
| IOCs | `indicator` + `observed-data` |
| Findings | `report` |
| ATLAS techniques | `course-of-action` (mitigation) |
| Attack pattern | `attack-pattern` |

```bash
trace report /evidence/case-001/ --format stix
# Output: /evidence/case-001/TRACE_Report_<id>.stix.json
```

---

## 9. Velociraptor Integration

TRACE ships 15 validated Velociraptor VQL artifacts for fleet-wide AI evidence collection. These are located in the `velociraptor/` directory of the repository.

### Available Artifacts

| Artifact Name | Scope | Sources |
|---|---|---|
| `TRACE.AI.Inference` | Local inference engines | Ollama, LM Studio, GPT4All, text-generation-webui, llama.cpp, KoboldCpp, LiteLLM, Bifrost, Unsloth |
| `TRACE.AI.Agents` | Agent frameworks | Hermes, AutoGPT, CrewAI, Aider, Shell-GPT, Devin, Eigent, Shadow AI |
| `TRACE.AI.DevTools` | AI development tools | Cursor, Claude Code, Antigravity, VSCodium |
| `TRACE.AI.APIKeys` | Credential scanning | .env files, config files, shell history |
| `TRACE.AI.HuggingFace` | HuggingFace Hub | Model cache, metadata, auth tokens |
| `TRACE.AI.Network` | Network connections | AI service ports, DNS cache, active connections |
| `TRACE.AI.Processes` | Running processes | AI-related processes with network cross-reference |
| `TRACE.AI.NetworkAI` | Live network AI | Process→AI-domain traffic classification |
| `TRACE.AI.CodeScanner` | Source code AI | AI framework imports, MCP configs, hardcoded API keys |
| `TRACE.AI.Docker` | Docker AI | Gordon, AI model registry, AI containers/images |
| `TRACE.AI.Browser` | Browser AI | Brave Leo, browser history for AI sites, IndexedDB stores |
| `TRACE.AI.ShadowAI` | Shadow AI | Unsanctioned AI tool detection meta-collector |
| `TRACE.AI.Binary.Linux` | Go binary | Downloads and runs the TRACE Go binary on Linux endpoints (discover/scan/run) |
| `TRACE.AI.Binary.macOS` | Go binary | Downloads and runs the TRACE Go binary on macOS endpoints (discover/scan/run) |
| `TRACE.AI.Binary.Windows` | Go binary | Downloads and runs the TRACE Go binary on Windows endpoints (discover/scan/run) |

### Deploying to Velociraptor

1. **Upload the YAML files** to your Velociraptor server:

   ```bash
   # Via Velociraptor GUI: Server Artifacts → Upload
   # Or via velociraptor CLI:
   velociraptor artifacts upload velociraptor/TRACE.AI.Inference.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Agents.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.DevTools.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.APIKeys.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.HuggingFace.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Network.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.NetworkAI.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Processes.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.CodeScanner.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Docker.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Browser.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.ShadowAI.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Binary.Linux.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Binary.macOS.yaml
   velociraptor artifacts upload velociraptor/TRACE.AI.Binary.Windows.yaml
   ```

2. **Create a hunt** targeting the desired OS and artifact:

   ```
   Hunt → Add → TRACE.AI.Inference
   ```

3. **Review collected results** in the Velociraptor GUI under the hunt results.

### Artifact Parameters

Each artifact supports the following configurable parameters:

| Parameter | Default | Description |
|---|---|---|
| `CollectChatHistory` | `true` | Collect conversation/chat databases (may contain PII) |
| `CollectModelManifests` | `true` | Collect model manifest files |
| `CollectLogs` | `true` | Collect service and application logs |
| `CollectAPIResponses` | `false` | Query running AI services for live model lists |
| `DeepCollection` | `false` | Include session-level data (larger, skip for quick triage) |

---

## 10. Forensic Soundness

TRACE is designed to meet the evidentiary standards expected in digital forensics:

### Read-Only Collection

- All file reads are immutable — TRACE never modifies source files.
- SQLite databases are opened in read-only mode (`file:path?mode=ro`) to prevent locking.
- Volatile evidence (processes, network connections) is collected first before file artifacts.

### SHA-256 Hashing

- Every collected file is hashed with SHA-256.
- Hashes are recorded in the chain-of-custody manifest and can be verified at any time.
- Large files (>100 MB, typically model weights) have hashing skipped unless `--deep` is set.

### Chain of Custody

The `CHAIN_OF_CUSTODY.json` manifest records:

```json
{
  "tool": "TRACE",
  "version": "1.0.1",
  "collected_at": "2026-08-13T14:30:00+00:00",
  "total_files": 144,
  "files": [
    {
      "original_path": "/root/.ollama/config.json",
      "source_os": "linux",
      "platform": "ollama",
      "artifact_type": "config",
      "size_bytes": 234,
      "sha256": "e3b0c44298fc1c14...",
      "collected_at": "2026-08-13T14:30:01+00:00",
      "collector_version": "1.0.1"
    }
  ]
}
```

### Timestamps

- All timestamps are in ISO 8601 UTC format.
- Collection order is deterministic for reproducibility.

### Evidence Integrity

- The evidence package is append-only — TRACE never overwrites or modifies collected files.
- The chain-of-custody manifest is written after all collections complete.
- File hashes are verified after copy operations.

---

## 11. Typical Workflows

### Incident Response

When investigating a potentially compromised AI endpoint:

```bash
# 1. Quick triage — what's on this system?
trace scan

# 2. Collect everything (including volatile evidence)
trace collect --output /evidence/ir-2026-08-13/ --deep

# 3. Analyze with full ATLAS mapping and risk scoring
trace analyze /evidence/ir-2026-08-13/ --mitre-atlas --risk-score

# 4. Generate reports for stakeholders and SIEM
trace report /evidence/ir-2026-08-13/ --format all
```

**Key tip:** Always collect volatile evidence (processes, network connections) first. TRACE does this automatically, but if you're running manual collection alongside TRACE, capture process listings and network state before touching disk artifacts.

### Compliance Audit

For periodic audits of AI tool usage in regulated environments:

```bash
# 1. Discover what AI tools employees are using
trace discover --verbose

# 2. Collect evidence (no deep mode needed for routine audits)
trace collect --output /evidence/audit-q3-2026/

# 3. Focus on credential exposure and risk scoring
trace analyze /evidence/audit-q3-2026/ --risk-score

# 4. Generate HTML report for auditors
trace report /evidence/audit-q3-2026/ --format html
```

### Fleet-wide AI Discovery

Using Velociraptor for enterprise-scale collection:

1. Upload all 15 `TRACE.AI.*.yaml` artifacts to your Velociraptor server.
2. Create a hunt targeting all endpoints with `TRACE.AI.Processes` (lightweight) for initial discovery.
3. For endpoints with hits, deploy `TRACE.AI.Inference`, `TRACE.AI.Agents`, and `TRACE.AI.DevTools` with `CollectChatHistory=true` and `DeepCollection=true`.
4. For credential auditing, deploy `TRACE.AI.APIKeys` across the fleet.
5. Export results and feed them into the TRACE CLI analyzer:

   ```bash
   trace analyze /velociraptor-export/ --mitre-atlas --risk-score
   trace report /velociraptor-export/ --format json,stix
   ```

---

## 12. Configuration

TRACE does not require a configuration file. All behavior is controlled through CLI flags.

### Environment Variables

| Variable | Description |
|---|---|
| `TRACE_OUTPUT_DIR` | Default output directory (overridden by `--output`) |
| `TRACE_NO_COLOR` | Disable colored output (set to `1`) |
| `TRACE_LOG_LEVEL` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Selective Collection

Use `--platforms` to target specific platforms, reducing collection time and evidence size:

```bash
# Only collect from inference engines
trace collect --output /evidence/ --platforms ollama,lm_studio,gpt4all,text_gen_webui,llama_cpp,kobold_cpp,litellm,bifrost,unsloth

# Only collect from agent frameworks
trace collect --output /evidence/ --platforms hermes,autogpt,crewai,aider,shell_gpt,devin,eigent,shadow_ai

# Only collect from development tools
trace collect --output /evidence/ --platforms cursor,claude_code,antigravity,vscodium
```

---

## 13. Troubleshooting

### "No AI platforms detected"

This means TRACE's `discover` command didn't find any AI tool artifacts on the system. Possible causes:

1. **No AI tools installed** — Nothing to collect.
2. **Non-default install paths** — Some tools may be installed in custom locations TRACE doesn't check. Run `trace discover --verbose` to see which paths are being searched.
3. **Permission denied** — TRACE may not have read access to user home directories. Run with appropriate privileges.

### Permission errors

TRACE reads files in user home directories. On multi-user systems, you may need elevated privileges:

```bash
# Linux/macOS — run as root to access all user directories
sudo trace collect --output /evidence/

# Windows — run as Administrator
trace collect --output C:\evidence\
```

### SQLite locking errors

If a tool is actively writing to a SQLite database (e.g., Hermes `state.db`), TRACE opens it in read-only mode to avoid locks. If you still encounter errors, consider:

- Stopping the AI service before collection.
- Using `--no-hash` to skip the hash-verification read pass.

### Large collections

Model files (especially from Ollama and HuggingFace) can be multi-gigabyte. By default, TRACE:

- Skips hashing for files >100 MB (unless `--deep`).
- Does not copy model blob files unless `--deep` is set.
- Records file existence and metadata even when content is skipped.

If you need full disk copies of models, use `--deep` — but expect collection times of 10+ minutes and output sizes of 50+ GB.

### Python stdlib `trace` conflict

The package name is `ionsec_trace`, not `trace`. If you see import errors like `cannot import name 'BaseCollector' from 'trace'`, it means Python is importing the stdlib `trace` module instead of `ionsec_trace`. Ensure you're using the correct import:

```python
# ✅ Correct
from ionsec_trace.collector.base import BaseCollector

# ❌ Wrong — imports stdlib
from trace.collector.base import BaseCollector
```

---

## 14. Architecture

```
ionsec_trace/
├── cli.py                  # Click CLI: discover, collect, analyze, report, scan
├── collector/
│   ├── base.py             # BaseCollector ABC, CollectedFile, ParsedArtifact, Finding
│   ├── ollama.py           # OllamaCollector
│   ├── hermes.py            # HermesCollector
│   ├── lm_studio.py         # LMStudioCollector
│   ├── gpt4all.py           # GPT4AllCollector
│   ├── text_gen_webui.py    # TextGenWebUICollector
│   ├── llama_cpp.py         # LlamaCppCollector
│   ├── kobold_cpp.py        # KoboldCppCollector
│   ├── autogpt.py           # AutoGPTCollector
│   ├── crewai.py            # CrewAICollector
│   ├── aider.py             # AiderCollector
│   ├── shell_gpt.py         # ShellGPTCollector
│   ├── cursor.py            # CursorCollector
│   ├── claude_code.py       # ClaudeCodeCollector
│   ├── huggingface.py       # HuggingFaceCacheCollector
│   ├── litellm.py           # LiteLLMCollector
│   ├── bifrost.py           # BifrostCollector
│   ├── unsloth.py           # UnslothCollector
│   ├── shadow_ai.py         # ShadowAICollector (meta-collector)
│   ├── antigravity.py       # AntigravityCollector
│   ├── devin.py             # DevinCollector
│   ├── vscodium.py          # VSCodiumCollector
│   ├── eigent.py            # EigentCollector
│   ├── network_ai.py        # NetworkAICollector (live process→domain AI traffic)
│   ├── code_scanner.py      # CodeScannerCollector (AI framework imports, MCP, API keys)
│   ├── docker_ai.py         # DockerAICollector (Gordon + hosted LLM containers)
│   └── browser_ai.py        # BrowserAICollector (Brave Leo, Perplexity, Copilot, ChatGPT, Gemini web)
├── analyzer/
│   ├── __init__.py          # analyze_all() unified entry
│   ├── timeline.py          # UnifiedTimeline, TimelineEvent
│   ├── ioc_extractor.py     # IOCExtractor, IOC
│   ├── mitre_atlas.py       # ATLASMapper, ATLASTechniqueMatch
│   ├── risk_scorer.py       # RiskScorer, RiskScore
│   ├── ai_ioc_detector.py   # AIIOCDetector (AI-specific IOC detection)
│   ├── enhanced_risk_scorer.py  # EnhancedRiskScorer (8 categories, kill chain, narratives, actions)
│   └── conversation_parser.py   # ConversationParser
├── reporter/
│   ├── __init__.py          # generate_all() entry point
│   ├── html_report.py       # HTMLReportGenerator (interactive, TRACE-branded)
│   ├── json_report.py       # JSONReportGenerator (TRACE JSON schema)
│   └── stix_generator.py   # STIXGenerator (STIX 2.1 bundle)
└── hash/                    # SHA-256, fuzzy hash utilities
```

### Data Flow

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  discover   │────▶│   collect    │────▶│   analyze    │────▶│    report    │
│ (scan for   │     │ (read files, │     │ (timeline,   │     │ (HTML, JSON, │
│  platforms)  │     │  hash, copy) │     │  IOCs, ATLAS,│     │  STIX 2.1)  │
└─────────────┘     └──────────────┘     │  risk score)  │     └──────────────┘
                                          └──────────────┘
                                                │
                                          ┌─────┴─────┐
                                          │  EVIDENCE  │
                                          │  DIRECTORY │
                                          │  (input +  │
                                          │   output)  │
                                          └───────────┘
```

### BaseCollector ABC

All collectors inherit from `BaseCollector`, which provides:

| Method/Attribute | Purpose |
|---|---|
| `discover()` | Detect if the platform is present |
| `collect()` | Collect forensic artifacts (returns `list[CollectedFile]`) |
| `parse()` | Parse collected files into structured `ParsedArtifact` and `Finding` |
| `calculate_hash()` | SHA-256 hash of a file |
| `timestamp()` | Current UTC ISO 8601 timestamp |
| `detect_os()` | Detect current operating system |
| `get_user_home_dirs()` | Enumerate all user home directories |
| `safe_read_json()` | Safely read and parse JSON files |
| `safe_read_file()` | Safely read text files with size limits |

---

## 15. Extending TRACE

### Adding a New Collector

1. Create a new file `src/ionsec_trace/collector/my_platform.py`:

```python
from ionsec_trace.collector.base import (
    BaseCollector, CollectedFile, ParsedArtifact, Finding,
    PlatformCategory, Severity,
)

class MyPlatformCollector(BaseCollector):
    PLATFORM_NAME = "my_platform"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["my_platform"]
    SERVICE_PORTS = [8080]

    LINUX_PATHS = ["~/.my_platform/"]
    MACOS_PATHS = ["~/.my_platform/"]
    WINDOWS_PATHS = ["%APPDATA%\\MyPlatform\\"]

    def discover(self) -> bool:
        # Return True if the platform is detected
        ...

    def collect(self) -> list[CollectedFile]:
        # Collect all forensic artifacts
        ...

    def parse(self) -> list[ParsedArtifact]:
        # Parse collected files into structured data
        ...
```

2. Register it in `src/ionsec_trace/collector/__init__.py`:

```python
from ionsec_trace.collector.my_platform import MyPlatformCollector

ALL_COLLECTORS = [
    # ...existing collectors...
    MyPlatformCollector,
]
```

3. Reinstall: `pip install -e .`

4. Test: `trace discover` should now detect your platform.

### Collector Implementation Notes

- **Dual-list pattern:** Always append to both the local `collected` list AND `self.collected_files`. The return value feeds the caller; `self.collected_files` feeds `parse()`.
- **API key redaction:** In `parse()`, redact actual key values to `[REDACTED]` but preserve key names. Use `Severity.CRITICAL` for credential artifacts and flag with MITRE ATLAS `AML.T0055`.
- **SQLite read-only:** Always open databases with `sqlite3.connect(f"file:{path}?mode=ro", uri=True)` to avoid locking.
- **Large file handling:** Skip `calculate_hash()` for files >100 MB unless `--deep` is set; use `sha256="skipped_large_file"` instead.
- **Import namespace:** Always use `from ionsec_trace.collector.base import ...` — never `from trace.collector.base import ...` (conflicts with Python stdlib).

### Adding a New Analyzer

Analyzers follow the same pattern as collectors — implement the analysis logic and integrate it into the CLI's `analyze` command. See `src/ionsec_trace/analyzer/` for examples.

### Adding a New Reporter

Reporters read from the evidence directory and generate output in a new format. See `src/ionsec_trace/reporter/` for examples. Register new formats in the `generate_all()` function in `reporter/__init__.py` and in the CLI's `--format` choice list.

### Adding a Velociraptor Artifact

1. Create a new YAML file in `velociraptor/TRACE.AI.<Name>.yaml`.
2. Follow the existing artifact structure (see `TRACE.AI.Inference.yaml` for reference).
3. Include OS preconditions (`SELECT OS FROM info() WHERE OS = 'linux'` etc.).
4. Validate the YAML: `python -c "import yaml; yaml.safe_load(open('your.yaml'))"`.
5. Test by uploading to a Velociraptor server and running against a target endpoint.

---

## 16. License

TRACE is released under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**.

```
TRACE — Tool for Reconnaissance of AI & Compute Evidence
Copyright (C) 2026 TRACE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.
```

---

**TRACE** · [ionsec.io](https://ionsec.io) · [github.com/ionsec/trace](https://github.com/ionsec/trace)