# AI Agent Frameworks: Forensic Artifact Reference

> Comprehensive catalog of disk artifacts left by AI agent frameworks and assistant tools.
> Generated for DFIR collection tool development. All paths are default locations.

---

## 1. Hermes Agent

**Type:** AI assistant with MCP, skills, cron, memory  
**Platforms:** Linux, macOS, Windows (WSL)

### Configuration & Auth
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.hermes/config.yaml` | All | Main config (model, providers, toolsets, agent settings) | YAML |
| `~/.hermes/.env` | All | Environment variables (API keys, secrets) | dotenv |
| `~/.hermes/auth.json` | All | OAuth tokens, credential pool (access/refresh tokens) | JSON |
| `~/.hermes/secrets/` | All | Stored secrets directory | JSON files |
| `~/.hermes/gateway_state.json` | All | Gateway runtime state (PID, platforms, connection status) | JSON |
| `~/.hermes/gateway.pid` | All | Gateway process PID file | Text |
| `~/.hermes/gateway.lock` | All | Gateway lock file | Text |

### Session & Conversation History
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.hermes/state.db` | All | SQLite DB: sessions, messages, FTS indexes, billing, routing | SQLite |
| `~/.hermes/state.db-shm` | All | SQLite shared memory | Binary |
| `~/.hermes/state.db-wal` | All | SQLite WAL journal | Binary |
| `~/.hermes/verification_evidence.db` | All | Verification/checkpoint evidence | SQLite |
| `~/.hermes/kanban.db` | All | Kanban task database | SQLite |
| `~/.hermes/sessions/` | All | Per-session JSONL files (full tool calls, messages) | JSONL |
| `~/.hermes/sessions/sessions.json` | All | Session index | JSON |
| `~/.hermes/.hermes_history` | All | CLI history file (timestamped commands) | Text |

**state.db Schema (key tables):**
- `sessions`: id, source, user_id, model, system_prompt, started_at, ended_at, end_reason, message_count, tool_call_count, input/output/cache/reasoning tokens, billing_*, title, cwd, git_branch, git_repo_root, chat_id, chat_type, thread_id
- `messages`: id, session_id, role, content, tool_call_id, tool_calls, tool_name, timestamp, token_count, finish_reason, reasoning, reasoning_content, platform_message_id
- `state_meta`: key-value store
- `compression_locks`: session_id, holder, acquired_at, expires_at
- `gateway_routing`: scope, session_key, entry_json, updated_at
- `messages_fts` / `messages_fts_trigram`: Full-text search indexes

### Memory & Skills
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.hermes/memories/MEMORY.md` | All | Agent's persistent memory notes | Markdown |
| `~/.hermes/memories/USER.md` | All | User profile/preferences | Markdown |
| `~/.hermes/memories/*/` | All | Memory subdirectories (e.g., cyber-intel/) | Markdown |
| `~/.hermes/skills/` | All | Skill definitions (SKILL.md + references/templates/scripts) | Markdown + mixed |
| `~/.hermes/.skills_prompt_snapshot.json` | All | Cached skills prompt | JSON |
| `~/.hermes/SOUL.md` | All | Agent personality/behavior file | Markdown |

### Cron & Automation
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.hermes/cron/jobs.json` | All | Scheduled job definitions | JSON |
| `~/.hermes/cron/executions.db` | All | Cron execution history | SQLite |
| `~/.hermes/cron/output/` | All | Cron job output logs | Text/JSON |
| `~/.hermes/cron/ticker_heartbeat` | All | Last heartbeat timestamp | Text |
| `~/.hermes/cron/ticker_last_success` | All | Last successful tick | Text |

### Logs
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.hermes/logs/agent.log` | All | Main agent log (rotated: agent.log.1) | Text |
| `~/.hermes/logs/errors.log` | All | Error log | Text |
| `~/.hermes/logs/gateway.log` | All | Gateway process log | Text |
| `~/.hermes/logs/gateway-exit-diag.log` | All | Gateway exit diagnostics | Text |
| `~/.hermes/logs/mcp-stderr.log` | All | MCP server stderr | Text |
| `~/.hermes/logs/update.log` | All | Update log | Text |
| `~/.hermes/interrupt_debug.log` | All | Interrupt debug info | Text |

### Other Artifacts
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.hermes/cache/` | All | Cache dir (model catalog, BWS cache, screenshots, documents) | Mixed |
| `~/.hermes/checkpoints/` | All | Session checkpoints | JSON |
| `~/.hermes/state-snapshots/` | All | Pre-update state snapshots | JSON |
| `~/.hermes/pairing/` | All | Telegram/Discord pairing state | JSON |
| `~/.hermes/webhook_subscriptions.json` | All | Webhook subscriptions | JSON |
| `~/.hermes/channel_directory.json` | All | Channel routing directory | JSON |
| `~/.hermes/context_length_cache.yaml` | All | Model context length cache | YAML |
| `~/.hermes/models_dev_cache.json` | All | Model dev cache | JSON |
| `~/.hermes/ollama_cloud_models_cache.json` | All | Ollama cloud models cache | JSON |
| `~/.hermes/profiles/` | All | Multi-profile configurations | YAML/JSON |
| `~/.hermes/kanban/` | All | Kanban board state files | Mixed |
| `~/.hermes/audio_cache/` | All | TTS audio cache | MP3 files |

---

## 2. OpenClaw family (OpenClaw / Clawdbot / Moltbot / NanoClaw)

**Type:** Open source autonomous agent runtime  \
**Platforms:** Linux, macOS, Windows  \
**Status:** The project was renamed multiple times under trademark pressure — **Clawdbot → Moltbot → OpenClaw** — all within January 2026. **NanoClaw** is a lighter-weight variant of the same runtime. All four share the same underlying architecture and forensic surface, so a responder should treat them as one family and check for every name.

### Rename history (all one project)

| Name | Period | Notes |
|------|--------|-------|
| **Clawdbot** | early Jan 2026 | Original name |
| **Moltbot** | Jan 2026 | First rename under trademark pressure |
| **OpenClaw** | Jan 2026 → present | Current name; viral adoption, dense incident record |
| **NanoClaw** | 2026 | Lightweight variant of the same runtime |

### Known Artifacts

| Path | Description | Format |
|------|-------------|--------|
| `~/.openclaw/` | OpenClaw config, gateway state, skills, session data | Directory |
| `~/.clawdbot/` | Clawdbot-era config/data (pre-rename) | Directory |
| `~/.moltbot/` | Moltbot-era config/data (pre-rename) | Directory |
| `~/.nanoclaw/` | NanoClaw config/data | Directory |
| `~/.config/openclaw/` | OpenClaw config (Linux) | Directory |
| project-local `.openclaw/` | Per-project agent state | Directory |

### Forensic significance

OpenClaw is an always-on autonomous agent that executes shell commands, reads and writes files, browses, and acts across a user's accounts. Its gateway config, skills, and session state are the evidence of what the agent was told to do and what it did. The family has a dense incident record (CVE-2026-25253 one-click RCE, thousands of publicly reachable instances, a registry supply-chain campaign), so detecting any of the four names is a high-priority shadow-AI signal.

### Detection

The TRACE Shadow AI meta-collector detects all four names (`openclaw`, `clawdbot`, `moltbot`, `nanoclaw`) by config path and CLI binary, flagging each as **high** risk.

---

## 3. AutoGPT

**Type:** Autonomous AI agent  
**Platforms:** Linux, macOS, Windows

### Configuration & Workspace
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.autogpt/` | All | Main config/data directory | Directory |
| `~/AutoGPT/` or project dir | All | Working directory (workspace) | Directory |
| `.env` (in project dir) | All | API keys (OPENAI_API_KEY, etc.) | dotenv |
| `ai_settings.yaml` | All | Agent personality/goals config | YAML |
| `auto_gpt_workspace/` | All | Default workspace for file I/O | Directory |

### Memory & Persistence
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.autogpt/auto_gpt_workspace/` | All | Persistent workspace | Directory |
| `{workspace}/auto_gpt_workspace/` | All | Per-project workspace | Files |
| `workspace/` (in agent work dir) | All | Agent-created files | Mixed |
| `output_auto_gpt.md` | All | Agent output log | Markdown |
| `file_logger.txt` | All | File operation log | Text |

### Browser/Interaction Logs
- AutoGPT uses a local browser (Playwright) that may leave traces in `~/.browser/` or browser profile dirs.

---

## 4. BabyAGI

**Type:** Task-driven autonomous agent  
**Platforms:** Python (cross-platform)

### Configuration & Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `.env` (in project dir) | All | API keys | dotenv |
| `babyagi.py` (in project dir) | All | Main script (config embedded) | Python |
| `{project_dir}/` | All | Task lists, objectives stored in memory (in-process by default) | — |

### Persistent Artifacts
- **Default:** BabyAGI stores tasks and objectives in-memory only during execution.
- **With extensions:** ChromaDB/Pinecone/Weaviate vector stores may be used at configured paths.
- **ChromaDB default:** `chroma_db/` or `chroma_db_data/` in project directory (SQLite + parquet files).
- **No standard config directory** — all config is via `.env` and command-line args.

---

## 5. CrewAI

**Type:** Multi-agent orchestration framework  
**Platforms:** Python (cross-platform)

### Configuration
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `.env` (in project dir) | All | API keys (OPENAI_API_KEY, etc.) | dotenv |
| `crewai.toml` or `pyproject.toml` | All | Project config | TOML |
| `~/.crewai/` | All | CLI config/cache directory | Mixed |

### Memory & Knowledge Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `{project_dir}/memory/` | All | Local long-term memory (ChromaDB) | SQLite + parquet |
| `{project_dir}/knowledge/` | All | Knowledge base embeddings | ChromaDB |
| `{project_dir}/.crewai/` | All | Crew metadata | JSON |
| `crewai_reset_memories` CLI | All | Command to clear memories | — |

**ChromaDB storage** (used by CrewAI memory/knowledge):
- `chroma.sqlite3` — vector metadata SQLite DB
- `{collection_id}/data_level0.parquet` — embedding vectors
- `{collection_id}/metadata_level0.parquet` — document metadata

### CLI Artifacts
- `crewai create crew` scaffolding creates `src/`, `knowledge/`, `memory/` directories.

---

## 6. LangChain / LangGraph

**Type:** Agent framework (library)  
**Platforms:** Python/TypeScript (cross-platform)

### Configuration
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `.env` (in project dir) | All | API keys (OPENAI_API_KEY, etc.) | dotenv |
| `~/.langchain/` | All | LangChain config/cache | Mixed |
| `~/.cache/langchain/` | All | LangChain cache directory | Mixed |

### Checkpoint/State Storage (LangGraph)
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `checkpoints.sqlite` (default) | All | LangGraph checkpoint DB | SQLite |
| Custom path via `SqliteSaver(conn)` | All | Configurable checkpoint DB | SQLite |
| `~/.cache/langchain/` | All | LLM response cache | Mixed |

**LangGraph SQLite Checkpoint Schema:**
- `checkpoints` table: thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, type, checkpoint (blob), metadata (JSON)
- `checkpoint_writes` table: thread_id, checkpoint_ns, checkpoint_id, task_id, idx, channel, type, value (blob)
- `checkpoint_blobs` table: thread_id, checkpoint_ns, channel, version, type, blob_data

### LangSmith Traces (cloud, but may cache locally)
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.cache/langchain/` | All | Local LLM cache | Mixed |
| `LANGCHAIN_TRACING_V2=true` | — | Enables trace upload to LangSmith (cloud) | — |

---

## 7. Microsoft AutoGen

**Type:** Multi-agent conversation framework  
**Platforms:** Python/.NET (cross-platform)

### Configuration
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `.env` (in project dir) | All | API keys (OPENAI_API_KEY, AZURE_OPENAI_API_KEY, etc.) | dotenv |
| `OAI_CONFIG_LIST` or `OAI_CONFIG_LIST.json` | All | Model configuration list | JSON |

### Cache & Memory
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.cache/autogen/` | All | DiskCache store directory | DiskCache format |
| `{project_dir}/.cache/` | All | Project-level cache | DiskCache format |
| `~/.cache/diskcache/` | Linux | Default DiskCache root | Mixed |

**DiskCache format:** Python `diskcache` library stores key-value pairs with metadata in SQLite (`cache.db`) plus blob files in a subdirectory structure.

### .NET AutoGen Artifacts
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `{project_dir}/seed-memory/` | All | Pre-seeded agent memory | Mixed |
| `{project_dir}/config/appsettings.json` | All | .NET app config | JSON |

---

## 8. OpenHands (formerly OpenDevin)

**Type:** AI software engineer  
**Platforms:** Docker-based (server), Python

### Configuration
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.openhands/` | Linux/macOS | Main config directory | Directory |
| `%APPDATA%\OpenHands\` | Windows | Main config directory | Directory |
| `~/.openhands/config.toml` | All | Main config file | TOML |
| `.env` (in project dir) | All | API keys | dotenv |
| `~/.openhands/state/` | All | Runtime state directory | Mixed |

### Session & Conversation Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.openhands/sessions/` | All | Session data | JSON |
| `~/.openhands/projects/` | All | Project metadata | JSON |

### Workspace
- OpenHands runs code in Docker containers. Workspace files persist in Docker volumes.
- Local artifacts include the Docker volume mount at the configured workspace path.

---

## 9. Devin

**Type:** AI software engineer (closed-source/SaaS)  
**Platforms:** Web-based

### Local Artifacts
- **Devin is primarily SaaS/cloud-based** — minimal local artifacts.
- Browser history/cookies for `app.devin.ai` or `devin.ai`.
- If using CLI integration, check `~/.devin/` for any local config.
- Email/calendar integrations may leave OAuth tokens in browser storage.

---

## 10. Aider

**Type:** AI pair programming (terminal)  
**Platforms:** Linux, macOS, Windows

### Configuration & History
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `.aider.chat.history.md` | Per-project | Chat history (Markdown) | Markdown |
| `.aider.input.history` | Per-project | Input command history | Text |
| `.aider.llm.history` | Per-project | Raw LLM API conversation log | Text/JSON |
| `.aider.model.settings.yml` | Per-project | Model-specific settings overrides | YAML |
| `.aider.model.metadata.json` | Per-project | Model metadata | JSON |
| `.aiderignore` | Per-project | Files to exclude from Aider's scope | Text |
| `~/.aider.conf.yml` | All | User-level config | YAML |
| `.gitignore` additions | Per-project | Aider adds `.aider*` patterns | Text |

**Key:** Most Aider artifacts are **project-local** (in the git root of the project being edited), NOT in `~/.aider/`.

### API Keys
- OpenAI: `OPENAI_API_KEY` env var
- Anthropic: `ANTHROPIC_API_KEY` env var
- Other providers: Various env vars (no local key file storage by default)

### Git Artifacts
- Aider creates commits with messages referencing `aider`.
- `git log --author="aider"` or `git log --grep="aider"` to find Aider commits.

---

## 11. Cursor

**Type:** AI code editor (fork of VS Code)  
**Platforms:** Linux, macOS, Windows

### Configuration & Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.cursor/` | Linux/macOS | Main config/data directory | Directory |
| `%APPDATA%\Cursor\` | Windows | Main config/data directory | Directory |
| `~/.cursor/User/globalStorage/` | Linux/macOS | Extension global storage (includes AI data) | Mixed |
| `~/.cursor/User/globalStorage/storage.json` | Linux/macOS | Global state storage | JSON |
| `~/.cursor/extensions/` | Linux/macOS | Installed extensions | VSIX |
| `~/.cursor/User/settings.json` | Linux/macOS | User settings (AI config, models) | JSON |
| `~/.cursor/logs/` | Linux/macOS | Cursor logs | Text |

### AI-Specific Artifacts
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.cursor/User/globalStorage/continue/` | Linux/macOS | If Continue extension installed | Mixed |
| `~/.cursor/User/workspaceStorage/` | Linux/macOS | Per-workspace state (hash-based dirs) | JSON |
| `.cursorrules` | Per-project | Project-level AI rules | Text |
| `.cursor/rules/` | Per-project | Project-level AI rules directory | Text/MD |
| `.cursor/index/` | Per-project | Codebase indexing cache | Binary |

### macOS-Specific
| Path | Description |
|------|-------------|
| `~/Library/Application Support/Cursor/` | App data |
| `~/Library/Caches/Cursor/` | Cache |
| `~/Library/Preferences/com.cursor.*.plist` | Preferences |

---

## 12. Claude Code

**Type:** Anthropic CLI agent  
**Platforms:** Linux, macOS, Windows (WSL)

### Configuration & Memory
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.claude/` | All | Main config/data directory | Directory |
| `~/.claude/config.json` | All | User settings (model, permissions) | JSON |
| `~/.claude/credentials.json` | All | Auth tokens/credentials | JSON |
| `~/.claude/statsig/` | All | Statsig feature flag cache | Mixed |
| `~/.claude/projects/` | All | Per-project state | JSON |
| `~/.claude/todos/` | All | Per-session TODO lists | JSON |
| `CLAUDE.md` | Per-project (root) | Project-level instructions | Markdown |
| `.claude/` | Per-project | Project-specific settings directory | Directory |
| `.claude/settings.json` | Per-project | Project permissions/settings | JSON |
| `.claude/rules/` | Per-project | Project-specific rules | Markdown |
| `.claude/commands/` | Per-project | Custom slash commands | Markdown |
| `AGENTS.md` | Per-project | Agent instructions (shared across tools) | Markdown |

### Session & Conversation
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.claude/projects/{hash}/` | All | Per-project session data (hash of project path) | JSON |
| `~/.claude/projects/{hash}/sessions/` | All | Session transcripts | JSON |

### API Keys
- `ANTHROPIC_API_KEY` env var
- OAuth tokens in `~/.claude/credentials.json`
- If using third-party providers: keys in env vars or `~/.claude/config.json`

---

## 13. Codex CLI (OpenAI)

**Type:** OpenAI CLI agent  
**Platforms:** Linux, macOS, Windows (WSL)

### Configuration & Auth
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.codex/` | All | Main config directory | Directory |
| `~/.codex/config.toml` | All | User configuration | TOML |
| `~/.codex/auth.json` | All | Auth tokens (OAuth device flow, ChatGPT tokens) | JSON |
| `~/.codex/environments/` | All | Environment configs | TOML |
| `~/.codex/skills/` | All | Skills definitions | Markdown |

### Session & History
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `.codex/` | Per-project | Project-level skills, environments | Mixed |
| `AGENTS.md` | Per-project | Agent instructions | Markdown |

### API Keys
- `OPENAI_API_KEY` env var
- OAuth tokens in `~/.codex/auth.json`
- ChatGPT device flow tokens (access_token, refresh_token)

---

## 14. Warp

**Type:** AI terminal emulator  
**Platforms:** macOS, Linux

### Configuration & Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.warp/` | Linux/macOS | Main config directory | Directory |
| `~/.local/share/warp/` | Linux | Data directory (XDG) | Directory |
| `~/Library/Application Support/dev.warp.Warp-Stable/` | macOS | App data | Directory |
| `~/Library/Application Support/dev.warp.Warp-Stable/warp_history.db` | macOS | Command history SQLite DB | SQLite |
| `~/.warp/themes/` | All | Custom themes | YAML |
| `~/.warp/key_bindings.yaml` | All | Key bindings | YAML |
| `~/.warp/preferences.yaml` | All | User preferences | YAML |
| `~/.warp/ai_conversations/` | All | AI conversation history | JSON |
| `~/.warp/launch_config.yaml` | All | Launch config | YAML |

### Key Artifacts
- `warp_history.db` — SQLite database with full command history, timestamps, working directory, exit code.
- AI conversations stored as JSON with prompt/response pairs.
- Terminal recordings (if enabled) stored in data directory.

---

## 15. GitHub Copilot

**Type:** AI code assistant (VS Code / JetBrains extension)  
**Platforms:** Linux, macOS, Windows

### VS Code Extension Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.config/github-copilot/` | Linux | Copilot CLI config | JSON |
| `~/Library/Application Support/GitHub Copilot/` | macOS | Copilot config | JSON |
| `%APPDATA%\GitHub Copilot\` | Windows | Copilot config | JSON |
| `{vscode_extensions}/github.copilot/` | All | Extension files | Mixed |
| `{vscode_extensions}/github.copilot-chat/` | All | Chat extension | Mixed |
| `~/.vscode/extensions/github.copilot-*/` | All | Extension install dir | Mixed |
| `~/.vscode/data/User/globalStorage/github.copilot/` | All | Extension storage | Mixed |

### Auth & OAuth
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.config/github-copilot/hosts.json` | Linux | GitHub OAuth token | JSON |
| `~/Library/Application Support/GitHub Copilot/hosts.json` | macOS | GitHub OAuth token | JSON |
| `%APPDATA%\GitHub Copilot\hosts.json` | Windows | GitHub OAuth token | JSON |
| `{vscode_globalStorage}/github.copilot/login` | All | Login state | JSON |

### Copilot CLI
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.config/github-copilot/` | Linux | CLI config + tokens | JSON |
| `~/Library/Application Support/GitHub Copilot/` | macOS | CLI config + tokens | JSON |

---

## 16. Continue

**Type:** Open-source AI code assistant  
**Platforms:** Linux, macOS, Windows (VS Code / JetBrains)

### Configuration
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.continue/` | All | Main config directory (`CONTINUE_GLOBAL_DIR` env override) | Directory |
| `~/.continue/config.json` | All | Main config file (models, context providers, etc.) | JSON |
| `~/.continue/config.yaml` | All | Alt config (YAML) | YAML |
| `~/.continue/config.ts` | All | Alt config (TypeScript) | TS |
| `~/.continue/.continueignore` | All | Ignore patterns | Text |
| `~/.continue/.local` | All | Local environment marker | Text |
| `~/.continue/.staging` | All | Staging environment marker | Text |
| `~/.continue/sharedConfig.json` | All | Shared config | JSON |

### Sessions & History
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.continue/sessions/` | All | Chat session storage | JSON per session |
| `~/.continue/sessions/sessions.json` | All | Session index | JSON |
| `~/.continue/index/` | All | Codebase index | Mixed |
| `~/.continue/index/globalContext.json` | All | Global context | JSON |
| `~/.continue/.diffs/` | All | Diff history | Files |
| `~/.continue/.utils/` | All | Utils (esbuild binary, etc.) | Binary |
| `~/.continue/.utils/repo_map.txt` | All | Codebase map cache | Text |

### API Keys
- Stored in `~/.continue/config.json` or `config.yaml` (provider API keys)
- Or via environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)

---

## 17. Cline

**Type:** VS Code AI extension (autonomous coding)  
**Platforms:** Linux, macOS, Windows

### Configuration & Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.cline/` | All | Main data directory (`CLINE_DATA_DIR` env override) | Directory |
| `~/.cline/data/` | All | Data subdirectory (global state, tasks, history) | Mixed |
| `~/.cline/data/globalState.json` | All | Global state (settings, API config, task history refs) | JSON |
| `~/.cline/data/secrets.json` | All | API keys and secrets (mode 0o600) | JSON |
| `~/.cline/data/settings.json` | All | Settings | JSON |
| `~/.cline/data/sessions.db` | All | Session store (SQLite) | SQLite |
| `~/.cline/data/tasks/` | All | Per-task directories | Directories |
| `~/.cline/data/tasks/{taskId}/` | All | Task-specific state | Mixed |
| `~/.cline/data/tasks/{taskId}/api_conversation_history.json` | All | Raw API conversation | JSON |
| `~/.cline/data/tasks/{taskId}/ui_messages.json` | All | UI message log | JSON |
| `~/.cline/data/tasks/{taskId}/context_history.json` | All | Context tracking | JSON |
| `~/.cline/data/tasks/{taskId}/task_metadata.json` | All | Task metadata | JSON |
| `~/.cline/data/workspaceState.json` | All | Workspace-specific state (hash-based path) | JSON |

### Workspace-Local
| Path | Description | Format |
|------|-------------|--------|
| `.clinerules` | Project rules | Text/MD |
| `.clinerules/workflows/` | Project workflows | Text/MD |
| `.clinerules/skills/` | Project skills | Text/MD |
| `.cline/skills/` | Cline project skills | Text/MD |
| `.claude/skills/` | Claude-compatible skills | Text/MD |

### macOS Documents Path
| Path | Description |
|------|-------------|
| `~/Documents/Cline/Rules/` | Custom rules |
| `~/Documents/Cline/MCP/` | MCP server configs |
| `~/Documents/Cline/Hooks/` | Hook scripts |
| `~/Documents/Cline/Workflows/` | Custom workflows |

---

## 18. Amp (Sourcegraph)

**Type:** AI coding agent  
**Platforms:** CLI, VS Code extension

### Configuration & Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.amp/` | All | Main config directory | Directory |
| `~/.amp/config.json` | All | Configuration | JSON |
| `~/.amp/auth.json` | All | Sourcegraph auth tokens | JSON |
| `~/.amp/sessions/` | All | Session history | JSON |

**Note:** Amp is relatively new (2025) and artifact locations may evolve. The `~/.amp/` directory is the primary forensic target.

---

## 19. Jupyter AI

**Type:** Jupyter AI assistant  
**Platforms:** Python/Jupyter (cross-platform)

### Configuration
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.jupyter/` | All | Jupyter config directory | Mixed |
| `~/.jupyter/jupyter_ai_config.py` | All | Jupyter AI config | Python |
| `~/.jupyter/jupyter_ai_config.json` | All | Jupyter AI config | JSON |
| `~/.jupyter/jupyter_server_config.py` | All | Jupyter server config (AI provider settings) | Python |
| `~/.jupyter/jupyter_server_config.json` | All | Jupyter server config | JSON |
| `{notebook_dir}/.jupyter/` | Per-project | Per-project Jupyter config | Mixed |

### Chat History
- Jupyter AI chat history is stored **in the browser** (localStorage/IndexedDB in JupyterLab frontend).
- No server-side chat persistence by default.
- Server logs may contain AI request metadata in Jupyter server logs.

### API Keys
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc. in env vars
- Or configured in `jupyter_ai_config.py`/`jupyter_server_config.py`

---

## 20. Shell-GPT (sgpt)

**Type:** CLI AI assistant  
**Platforms:** Linux, macOS, Windows

### Configuration & Storage
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `~/.config/shell_gpt/` | Linux | Main config directory (XDG) | Directory |
| `~/Library/Application Support/shell_gpt/` | macOS | Main config directory | Directory |
| `%APPDATA%\shell_gpt\` | Windows | Main config directory | Directory |
| `~/.config/shell_gpt/.sgptrc` | All | Config file (key=value) | Text |
| `~/.config/shell_gpt/roles/` | All | Custom role definitions | Text |
| `~/.config/shell_gpt/functions/` | All | Custom function definitions | Text |

### Chat Cache (ephemeral by default)
| Path | OS | Description | Format |
|------|-----|-------------|--------|
| `/tmp/chat_cache/` | Linux | Chat session cache (temp) | JSON |
| `/tmp/cache/` | Linux | General cache (temp) | Mixed |

**Config format (`.sgptrc`):**
```
OPENAI_API_KEY=sk-...
DEFAULT_MODEL=gpt-4o
CHAT_CACHE_LENGTH=100
CHAT_CACHE_PATH=/tmp/chat_cache
CACHE_LENGTH=100
CACHE_PATH=/tmp/cache
ROLE_STORAGE_PATH=~/.config/shell_gpt/roles
DEFAULT_COLOR=magenta
```

**Key:** Chat cache is in `/tmp/` by default and is **ephemeral** — cleared on reboot. The config file stores the API key in plaintext.

---

## Cross-Tool Forensic Patterns

### API Key Locations Summary

| Tool | API Key Location | Format |
|------|-----------------|--------|
| Hermes Agent | `~/.hermes/auth.json`, `~/.hermes/.env`, `~/.hermes/config.yaml` | JSON/dotenv/YAML |
| AutoGPT | `.env` (project dir) | dotenv |
| Aider | `OPENAI_API_KEY` env var | env var |
| Claude Code | `~/.claude/credentials.json`, `ANTHROPIC_API_KEY` env var | JSON/env |
| Codex CLI | `~/.codex/auth.json`, `OPENAI_API_KEY` env var | JSON/env |
| Cline | `~/.cline/data/secrets.json` | JSON (mode 0o600) |
| Continue | `~/.continue/config.json` or `.yaml` | JSON/YAML |
| Shell-GPT | `~/.config/shell_gpt/.sgptrc` | Text (key=value) |
| GitHub Copilot | `~/.config/github-copilot/hosts.json` | JSON |
| Cursor | `~/.cursor/User/globalStorage/` | Mixed |
| Warp | `~/.warp/` | YAML/JSON |
| CrewAI | `.env` (project dir) | dotenv |
| LangChain | `OPENAI_API_KEY` env var, `~/.cache/langchain/` | env var |
| BabyAGI | `.env` (project dir) | dotenv |

### Session/Conversation Storage Summary

| Tool | Storage Type | Format | Persistence |
|------|--------------|--------|-------------|
| Hermes Agent | SQLite DB + JSONL files | SQLite + JSONL | Permanent |
| Claude Code | JSON files | JSON | Permanent |
| Cline | SQLite DB + JSON task dirs | SQLite + JSON | Permanent |
| Continue | JSON session files | JSON | Permanent |
| Aider | Markdown + text files | MD/Text | Permanent (project-local) |
| AutoGPT | Workspace files | Mixed | Permanent |
| CrewAI | ChromaDB (SQLite + parquet) | Vector DB | Permanent |
| LangGraph | SQLite checkpoints | SQLite | Configurable |
| AutoGen | DiskCache (SQLite + blobs) | Mixed | Configurable |
| Codex CLI | Config/session files | TOML/JSON | Permanent |
| Shell-GPT | /tmp/ cache | JSON | Ephemeral |
| Warp | SQLite DB | SQLite | Permanent |
| Cursor | VS Code storage (JSON) | JSON | Permanent |
| Copilot | Extension storage | Mixed | Permanent |
| Jupyter AI | Browser localStorage | IndexedDB | Ephemeral |

### Shell History Artifacts

Tools that add entries to shell history (`.bash_history`, `.zsh_history`, `.python_history`):
- **Hermes Agent**: `~/.hermes/.hermes_history`
- **Aider**: `.aider.input.history` (per project)
- **Shell-GPT**: Regular shell history entries (commands starting with `sgpt`)
- **AutoGPT**: Regular shell history entries
- **BabyAGI**: Regular shell history entries
- **Warp**: Own SQLite history DB (also writes to shell history)
- **Codex CLI**: Regular shell history entries

### Forensic Collection Priority (High-Value Targets)

**Tier 1 — Most forensically rich:**
1. **Hermes Agent**: `~/.hermes/` (SQLite DB with full conversation + billing, JSONL sessions, memory files, cron, auth tokens, logs)
2. **Cline**: `~/.cline/` (SQLite sessions, task history with full API conversations, secrets)
3. **Claude Code**: `~/.claude/` (credentials, project state, session data)
4. **Continue**: `~/.continue/` (sessions, config with API keys, codebase index)

**Tier 2 — Rich but more limited:**
5. **Cursor**: `~/.cursor/` (workspace storage, AI configs)
6. **Warp**: `~/.warp/` + `warp_history.db` (full command history)
7. **Aider**: Project-local `.aider.*` files (chat history, LLM history)
8. **Codex CLI**: `~/.codex/` (auth, config, skills)

**Tier 3 — Config-focused or ephemeral:**
9. **Shell-GPT**: `~/.config/shell_gpt/` (config with API key, roles; chat cache is ephemeral)
10. **GitHub Copilot**: Extension storage, `hosts.json` (OAuth tokens)
11. **CrewAI**: Project-local ChromaDB files (memory/knowledge)
12. **LangGraph**: `checkpoints.sqlite` (configurable location)
13. **Jupyter AI**: Browser-only chat, server config for API keys

---

## Collection Commands (Linux/macOS)

```bash
# Hermes Agent
find ~/.hermes/ -type f 2>/dev/null

# Claude Code  
find ~/.claude/ -type f 2>/dev/null
find / -maxdepth 5 -name "CLAUDE.md" -o -name ".claude" -type d 2>/dev/null

# Cline
find ~/.cline/ -type f 2>/dev/null
find ~/.cursor/ -path "*/cline/*" -type f 2>/dev/null

# Continue
find ~/.continue/ -type f 2>/dev/null

# Aider (project-local)
find / -maxdepth 5 -name ".aider.chat.history.md" -o -name ".aider.llm.history" -o -name ".aider.input.history" 2>/dev/null

# Shell-GPT
find ~/.config/shell_gpt/ -type f 2>/dev/null
find /tmp/chat_cache/ /tmp/cache/ -type f 2>/dev/null

# Cursor
find ~/.cursor/ -type f -name "*.json" 2>/dev/null

# Warp
find ~/.warp/ -type f 2>/dev/null
find ~/Library/Application\ Support/dev.warp.Warp-Stable/ -type f 2>/dev/null  # macOS

# GitHub Copilot
find ~/.config/github-copilot/ -type f 2>/dev-dev/null
find ~/Library/Application\ Support/GitHub\ Copilot/ -type f 2>/dev/null  # macOS

# Codex CLI
find ~/.codex/ -type f 2>/dev/null

# AutoGPT
find ~/.autogpt/ -type f 2>/dev/null
find / -maxdepth 5 -name "ai_settings.yaml" -o -name "auto_gpt_workspace" -type d 2>/dev/null

# CrewAI (project-local)
find / -maxdepth 5 -name "chroma.sqlite3" -path "*/crewai/*" 2>/dev/null

# LangGraph
find / -maxdepth 5 -name "checkpoints.sqlite" 2>/dev/null
```

---

## Windows-Specific Paths

| Tool | Windows Path |
|------|-------------|
| Hermes Agent | `%USERPROFILE%\.hermes\` |
| Claude Code | `%USERPROFILE%\.claude\` |
| Cline | `%USERPROFILE%\.cline\` |
| Continue | `%USERPROFILE%\.continue\` |
| Cursor | `%APPDATA%\Cursor\` |
| Warp | `%LOCALAPPDATA%\Warp\` |
| GitHub Copilot | `%APPDATA%\GitHub Copilot\` |
| Shell-GPT | `%APPDATA%\shell_gpt\` |
| AutoGPT | `%USERPROFILE%\.autogpt\` |
| Aider | Per-project (same as Linux) |
| Codex CLI | `%USERPROFILE%\.codex\` |
| Jupyter AI | `%USERPROFILE%\.jupyter\` |