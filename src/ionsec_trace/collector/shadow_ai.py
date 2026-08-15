"""
Shadow AI meta-collector for TRACE.

Detects a broad set of unsanctioned / unofficial AI tools that employees may
install without IT approval ("Shadow AI"). For each detected tool, records a
ParsedArtifact with the tool name, whether it is installed, its config path,
and a risk note.

Collects only config/metadata files (not huge model files).
"""

import os
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class ShadowAICollector(BaseCollector):
    PLATFORM_NAME = "shadow_ai"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = []
    SERVICE_PORTS = []

    # ── Walk limits (configurable) ─────────────────────────────
    # Depth cap for non-transcript config/blob trees. Transcript/session
    # files (see TRANSCRIPT_EXTENSIONS) are walked to any depth so that
    # sub-agent transcripts nested deep in agent trees are captured.
    MAX_DEPTH = 3
    # Hard cap on the number of files collected per tool directory. When the
    # cap is hit, the excess is counted and recorded as a truncation in the
    # chain-of-custody manifest rather than silently dropped.
    MAX_FILES_PER_TOOL = 200
    # File extensions treated as transcript/session data and walked fully.
    TRANSCRIPT_EXTENSIONS = (".jsonl", ".json")

    def __init__(self, output_dir, deep=False, max_depth=None, max_files_per_tool=None):
        super().__init__(output_dir, deep=deep)
        # Allow per-instance override, then env var, then class default.
        self.max_depth = (
            max_depth
            if max_depth is not None
            else int(os.environ.get("TRACE_MAX_DEPTH", self.MAX_DEPTH))
        )
        self.max_files_per_tool = (
            max_files_per_tool
            if max_files_per_tool is not None
            else int(os.environ.get("TRACE_MAX_FILES_PER_TOOL", self.MAX_FILES_PER_TOOL))
        )
        self.transcript_extensions = self.TRANSCRIPT_EXTENSIONS

    LINUX_PATHS = []
    MACOS_PATHS = []
    WINDOWS_PATHS = []

    # Curated list of known shadow-AI tools and their artifact paths.
    # Each entry: (tool_name, [relative config paths], risk_level, risk_note)
    # risk_level: "high" for agent runtimes w/ network access, "low" for simple CLIs.
    SHADOW_AI_TOOLS = [
        ("deepseek_harness", [".dsh"], "high",
         "DeepSeek Harness (dsh) agent runtime with tool + network access"),
        ("cursor", [".cursor", ".config/Cursor"], "high",
         "AI code editor with network access and telemetry"),
        ("claude_code", [".claude"], "high",
         "Claude Code agent runtime with terminal + network access"),
        ("codex_cli", [".codex"], "high",
         "OpenAI Codex CLI agent with terminal + network access"),
        ("aider", [".aider", ".aider.conf.yml", ".aider.input.history"], "low",
         "AI pair-programming CLI"),
        ("continue", [".continue"], "high",
         "Continue IDE extension with network access"),
        ("cline", [".cline"], "high",
         "Cline autonomous coding agent with terminal access"),
        ("warp", [".warp"], "low",
         "Warp terminal with AI features"),
        ("shell_gpt", [".shell_gpt"], "low",
         "Shell-GPT command-line AI assistant"),
        ("ollama", [".ollama"], "medium",
         "Local LLM runtime (may expose API on localhost)"),
        ("lm_studio", ["Library/Application Support/LM Studio", ".lmstudio",
                       "AppData/Local/LM-Studio"], "medium",
         "LM Studio local LLM GUI"),
        ("jan", [".jan"], "medium",
         "Jan local LLM desktop app"),
        ("anythingllm", [".anythingllm", "Library/Application Support/anythingllm-desktop"],
         "medium", "AnythingLLM local LLM workspace"),
        ("openclaw", [".openclaw", ".config/openclaw"], "high",
         "OpenClaw agent runtime with tool/network access"),
        ("clawdbot", [".clawdbot", ".config/clawdbot"], "high",
         "Clawdbot agent runtime with tool/network access"),
        ("moltbot", [".moltbot", ".config/moltbot"], "high",
         "Moltbot agent runtime with tool/network access"),
        ("nanoclaw", [".nanoclaw", ".config/nanoclaw"], "high",
         "NanoClaw lightweight agent runtime with tool/network access"),
        ("openinterpreter", [".open-interpreter"], "high",
         "Open Interpreter agent with terminal + network access"),
        ("autogen", [".autogen"], "medium",
         "AutoGen multi-agent framework"),
        ("langchain", [".langchain"], "low",
         "LangChain framework traces"),
        ("copilot", [".copilot", ".config/github-copilot"], "medium",
         "GitHub Copilot with network access"),
        ("gemini_cli", [".gemini"], "high",
         "Gemini CLI agent with terminal + network access"),
        ("amazon_q", [".aws/amazonq", ".config/amazonq"], "medium",
         "Amazon Q developer agent"),
        ("windsurf", [".codeium", ".config/Windsurf"], "high",
         "Windsurf AI editor with network access"),
        ("kilo_code", [".kilo"], "high",
         "Kilo Code agent with terminal + network access"),
        ("roo_code", [".roo"], "high",
         "Roo Code agent with terminal + network access"),
        ("goose", [".config/goose", ".goose"], "high",
         "Goose agent runtime with terminal + network access"),
        ("openhands", [".openhands", ".config/openhands"], "high",
         "OpenHands autonomous agent with network access"),
        ("devika", [".devika"], "high",
         "Devika autonomous agent with network access"),
        ("swe_agent", [".swe-agent"], "high",
         "SWE-agent autonomous coding agent"),
        ("gpt_engineer", [".gpt_engineer"], "medium",
         "GPT Engineer code generation tool"),
        ("tabby", [".tabby"], "low",
         "Tabby self-hosted coding assistant"),
        ("fitten", [".fitten"], "low",
         "Fitten Code AI assistant"),
        ("codeium", [".codeium"], "low",
         "Codeium AI assistant"),
        ("blackbox", [".blackbox"], "low",
         "Blackbox AI assistant"),
        ("replit", [".replit"], "low",
         "Replit AI workspace config"),
        ("v0", [".v0"], "low",
         "Vercel v0 AI design tool"),
        ("bolt", [".bolt"], "low",
         "Bolt.new AI app builder"),
        ("lovable", [".lovable"], "low",
         "Lovable AI app builder"),
        ("cursor_rules", [".cursorrules"], "low",
         "Cursor rules file (indicates Cursor usage)"),
        ("antigravity", [".antigravity", ".config/Antigravity",
                         "Library/Application Support/Antigravity"], "high",
         "Google Antigravity AI IDE with network access"),
        ("devin", [".devin", ".config/devin",
                   "Library/Application Support/Devin"], "high",
         "Devin autonomous AI software engineer (Desktop)"),
        ("vscodium", [".config/VSCodium",
                      "Library/Application Support/VSCodium"], "low",
         "VSCodium open-source VS Code build (may host AI extensions)"),
        ("eigent", [".eigent", ".config/eigent",
                    "Library/Application Support/Eigent"], "high",
         "Eigent AI agent with terminal + network access"),
        ("gordon", [".docker/gordon"], "high",
         "Docker AI assistant (Gordon) with terminal + network access"),
        ("docker_ai", [".docker/models", ".docker/gordon"], "medium",
         "Docker-hosted AI workloads (LLM images, model registry)"),
        ("browser_ai", ["Library/Application Support/BraveSoftware",
                        "Library/Application Support/Google/Chrome",
                        "Library/Application Support/Microsoft Edge"], "medium",
         "Browser-based AI assistants (Brave Leo, Perplexity, Copilot, ChatGPT, Gemini)"),
    ]

    # ── Discover ──────────────────────────────────────────────

    def discover(self) -> bool:
        """Return True if ANY shadow AI tool is found on the system."""
        return len(self._detect_tools()) > 0

    def _detect_tools(self) -> list[dict]:
        """Detect which shadow-AI tools are present. Returns list of dicts."""
        found = []
        homes = self.get_user_home_dirs()

        for tool_name, rel_paths, risk, note in self.SHADOW_AI_TOOLS:
            config_path = None
            for rel in rel_paths:
                for home in homes:
                    candidate = home / rel
                    if candidate.exists():
                        config_path = str(candidate)
                        break
                if config_path:
                    break

            # Also check for a matching CLI binary
            binary = self._find_binary(tool_name)
            if config_path or binary:
                found.append({
                    "tool": tool_name,
                    "installed": True,
                    "config_path": config_path,
                    "binary": binary,
                    "risk": risk,
                    "note": note,
                })

        return found

    def _find_binary(self, tool_name: str) -> str | None:
        """Check for a CLI binary matching the tool name."""
        import shutil
        candidates = {
            "cursor": ["cursor", "cursor-agent"],
            "claude_code": ["claude"],
            "codex_cli": ["codex"],
            "aider": ["aider"],
            "continue": ["continue"],
            "cline": ["cline"],
            "warp": ["warp"],
            "shell_gpt": ["sgpt", "shell_gpt"],
            "ollama": ["ollama"],
            "lm_studio": ["lmstudio"],
            "jan": ["jan"],
            "anythingllm": ["anythingllm"],
            "openclaw": ["openclaw", "claw"],
            "clawdbot": ["clawdbot"],
            "moltbot": ["moltbot"],
            "nanoclaw": ["nanoclaw", "nano-claw"],
            "openinterpreter": ["interpreter"],
            "autogen": ["autogen"],
            "langchain": ["langchain"],
            "copilot": ["copilot"],
            "gemini_cli": ["gemini"],
            "amazon_q": ["q"],
            "windsurf": ["windsurf"],
            "kilo_code": ["kilo"],
            "roo_code": ["roo"],
            "goose": ["goose"],
            "openhands": ["openhands"],
            "devika": ["devika"],
            "swe_agent": ["swe-agent"],
            "gpt_engineer": ["gpt-engineer"],
            "tabby": ["tabby"],
            "fitten": ["fitten"],
            "codeium": ["codeium"],
            "blackbox": ["blackbox"],
            "replit": ["replit"],
            "v0": ["v0"],
            "bolt": ["bolt"],
            "lovable": ["lovable"],
        }
        for name in candidates.get(tool_name, []):
            path = shutil.which(name)
            if path:
                return path
        return None

    # ── Collect ───────────────────────────────────────────────

    def collect(self) -> list[CollectedFile]:
        """Collect config/metadata files of detected shadow-AI tools."""
        collected = []
        self._detected = self._detect_tools()

        for tool in self._detected:
            config_path = tool.get("config_path")
            if not config_path:
                continue
            p = Path(config_path)
            if p.is_file():
                cf = self._make_collected_file(p, "config")
                collected.append(cf)
                self.collected_files.append(cf)
            elif p.is_dir():
                collected.extend(self._collect_config_dir(p))

        return collected

    def _make_collected_file(self, path: Path, artifact_type: str) -> CollectedFile:
        return CollectedFile(
            original_path=str(path),
            source_os=self.detect_os(),
            platform=self.PLATFORM_NAME,
            artifact_type=artifact_type,
            size_bytes=path.stat().st_size,
            sha256=self.calculate_hash(str(path)),
            collected_at=self.timestamp(),
        )

    def _collect_config_dir(self, directory: Path) -> list[CollectedFile]:
        """Collect config/metadata files from a tool directory (no huge model files).

        Transcript/session files (``.jsonl``/``.json``) are walked to any depth so
        that sub-agent transcripts nested deep in agent trees are captured. Other
        config/blob trees are bounded by ``self.max_depth``. The total number of
        files collected per tool is bounded by ``self.max_files_per_tool``; when the
        cap is hit, the number of skipped files is recorded as a truncation entry
        (see ``self.truncations``) and a warning is emitted.
        """
        collected = []
        skipped = 0
        truncated = False
        try:
            for f in directory.rglob("*"):
                if not f.is_file():
                    continue
                # Enforce recursion depth limit, except for transcript/session files
                # which are walked fully so deep sub-agent transcripts are captured.
                try:
                    rel = f.relative_to(directory)
                    is_transcript = f.name.lower().endswith(self.transcript_extensions)
                    if not is_transcript and len(rel.parts) > self.max_depth:
                        continue
                except ValueError:
                    continue
                # Cap total files per tool
                if len(collected) >= self.max_files_per_tool:
                    truncated = True
                    skipped += 1
                    continue
                # Skip large model/binary files
                try:
                    if f.stat().st_size > 5 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                name = f.name.lower()
                # Only collect config/metadata-like files
                if name.endswith((".json", ".yaml", ".yml", ".toml", ".env",
                                  ".log", ".txt", ".md", ".sqlite", ".db",
                                  ".sqlite3", ".jsonl", ".history", ".conf")):
                    artifact_type = "config"
                    if name.endswith((".log", ".txt")):
                        artifact_type = "log"
                    elif name.endswith((".sqlite", ".db", ".sqlite3")):
                        artifact_type = "database"
                    elif name.endswith(".env"):
                        artifact_type = "credential"
                    elif name.endswith((".jsonl", ".json")):
                        artifact_type = "transcript"
                    cf = self._make_collected_file(f, artifact_type)
                    collected.append(cf)
                    self.collected_files.append(cf)
        except OSError:
            pass
        if truncated:
            self._record_truncation(directory, skipped)
        return collected

    def _record_truncation(self, directory: Path, skipped: int) -> None:
        """Record that collection from a tool directory was clipped by the cap."""
        import logging
        logging.getLogger(__name__).warning(
            "shadow_ai: collection from %s truncated at %d files; %d file(s) skipped",
            directory, self.max_files_per_tool, skipped,
        )
        truncations = getattr(self, "truncations", None)
        if truncations is None:
            truncations = []
            self.truncations = truncations
        truncations.append({
            "platform": self.PLATFORM_NAME,
            "directory": str(directory),
            "max_files": self.max_files_per_tool,
            "skipped": skipped,
        })

    # ── Parse ─────────────────────────────────────────────────

    def parse(self) -> list[ParsedArtifact]:
        """Produce one ParsedArtifact per detected shadow-AI tool."""
        artifacts = []
        detected = getattr(self, "_detected", None)
        if detected is None:
            detected = self._detect_tools()

        for tool in detected:
            severity = self._severity_for_risk(tool["risk"])
            data = {
                "tool": tool["tool"],
                "installed": tool["installed"],
                "config_path": tool.get("config_path"),
                "binary": tool.get("binary"),
                "risk_note": tool["note"],
            }
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="shadow_ai_tool",
                severity=severity,
                data=data,
                source_file=tool.get("config_path") or tool.get("binary") or "",
                risk_score=self._risk_score(tool["risk"]),
            ))

        return artifacts

    def _severity_for_risk(self, risk: str) -> Severity:
        if risk == "high":
            return Severity.HIGH
        elif risk == "medium":
            return Severity.MEDIUM
        return Severity.LOW

    def _risk_score(self, risk: str) -> int:
        return {"high": 8, "medium": 5, "low": 2}.get(risk, 2)
