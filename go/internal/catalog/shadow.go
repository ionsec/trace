package catalog

// ShadowTool is one shadow-AI tool TRACE looks for in a user home directory:
// the relative paths that prove its presence, a risk level and an analyst note.
//
// Mirrors ShadowAICollector.SHADOW_AI_TOOLS in the Python build.
type ShadowTool struct {
	Name  string
	Paths []string
	Risk  string
	Note  string
}

// ShadowTools is the full shadow-AI detection table.
var ShadowTools = []ShadowTool{
	{
		Name:  "deepseek_harness",
		Paths: []string{".dsh"},
		Risk:  "high",
		Note:  "DeepSeek Harness (dsh) agent runtime with tool + network access",
	},
	{
		Name:  "cursor",
		Paths: []string{".cursor", ".config/Cursor"},
		Risk:  "high",
		Note:  "AI code editor with network access and telemetry",
	},
	{
		Name:  "claude_code",
		Paths: []string{".claude"},
		Risk:  "high",
		Note:  "Claude Code agent runtime with terminal + network access",
	},
	{
		Name:  "codex_cli",
		Paths: []string{".codex"},
		Risk:  "high",
		Note:  "OpenAI Codex CLI agent with terminal + network access",
	},
	{
		Name:  "aider",
		Paths: []string{".aider", ".aider.conf.yml", ".aider.input.history"},
		Risk:  "low",
		Note:  "AI pair-programming CLI",
	},
	{
		Name:  "continue",
		Paths: []string{".continue"},
		Risk:  "high",
		Note:  "Continue IDE extension with network access",
	},
	{
		Name:  "cline",
		Paths: []string{".cline"},
		Risk:  "high",
		Note:  "Cline autonomous coding agent with terminal access",
	},
	{
		Name:  "warp",
		Paths: []string{".warp"},
		Risk:  "low",
		Note:  "Warp terminal with AI features",
	},
	{
		Name:  "shell_gpt",
		Paths: []string{".shell_gpt"},
		Risk:  "low",
		Note:  "Shell-GPT command-line AI assistant",
	},
	{
		Name:  "ollama",
		Paths: []string{".ollama"},
		Risk:  "medium",
		Note:  "Local LLM runtime (may expose API on localhost)",
	},
	{
		Name:  "lm_studio",
		Paths: []string{"Library/Application Support/LM Studio", ".lmstudio", "AppData/Local/LM-Studio"},
		Risk:  "medium",
		Note:  "LM Studio local LLM GUI",
	},
	{
		Name:  "jan",
		Paths: []string{".jan"},
		Risk:  "medium",
		Note:  "Jan local LLM desktop app",
	},
	{
		Name:  "anythingllm",
		Paths: []string{".anythingllm", "Library/Application Support/anythingllm-desktop"},
		Risk:  "medium",
		Note:  "AnythingLLM local LLM workspace",
	},
	{
		Name:  "openclaw",
		Paths: []string{".openclaw", ".config/openclaw"},
		Risk:  "high",
		Note:  "OpenClaw agent runtime with tool/network access",
	},
	{
		Name:  "clawdbot",
		Paths: []string{".clawdbot", ".config/clawdbot"},
		Risk:  "high",
		Note:  "Clawdbot agent runtime with tool/network access",
	},
	{
		Name:  "moltbot",
		Paths: []string{".moltbot", ".config/moltbot"},
		Risk:  "high",
		Note:  "Moltbot agent runtime with tool/network access",
	},
	{
		Name:  "nanoclaw",
		Paths: []string{".nanoclaw", ".config/nanoclaw"},
		Risk:  "high",
		Note:  "NanoClaw lightweight agent runtime with tool/network access",
	},
	{
		Name:  "openinterpreter",
		Paths: []string{".open-interpreter"},
		Risk:  "high",
		Note:  "Open Interpreter agent with terminal + network access",
	},
	{
		Name:  "autogen",
		Paths: []string{".autogen"},
		Risk:  "medium",
		Note:  "AutoGen multi-agent framework",
	},
	{
		Name:  "langchain",
		Paths: []string{".langchain"},
		Risk:  "low",
		Note:  "LangChain framework traces",
	},
	{
		Name:  "copilot",
		Paths: []string{".copilot", ".config/github-copilot"},
		Risk:  "medium",
		Note:  "GitHub Copilot with network access",
	},
	{
		Name:  "gemini_cli",
		Paths: []string{".gemini"},
		Risk:  "high",
		Note:  "Gemini CLI agent with terminal + network access",
	},
	{
		Name:  "amazon_q",
		Paths: []string{".aws/amazonq", ".config/amazonq"},
		Risk:  "medium",
		Note:  "Amazon Q developer agent",
	},
	{
		Name:  "windsurf",
		Paths: []string{".codeium", ".config/Windsurf"},
		Risk:  "high",
		Note:  "Windsurf AI editor with network access",
	},
	{
		Name:  "kilo_code",
		Paths: []string{".kilo"},
		Risk:  "high",
		Note:  "Kilo Code agent with terminal + network access",
	},
	{
		Name:  "roo_code",
		Paths: []string{".roo"},
		Risk:  "high",
		Note:  "Roo Code agent with terminal + network access",
	},
	{
		Name:  "goose",
		Paths: []string{".config/goose", ".goose"},
		Risk:  "high",
		Note:  "Goose agent runtime with terminal + network access",
	},
	{
		Name:  "openhands",
		Paths: []string{".openhands", ".config/openhands"},
		Risk:  "high",
		Note:  "OpenHands autonomous agent with network access",
	},
	{
		Name:  "devika",
		Paths: []string{".devika"},
		Risk:  "high",
		Note:  "Devika autonomous agent with network access",
	},
	{
		Name:  "swe_agent",
		Paths: []string{".swe-agent"},
		Risk:  "high",
		Note:  "SWE-agent autonomous coding agent",
	},
	{
		Name:  "gpt_engineer",
		Paths: []string{".gpt_engineer"},
		Risk:  "medium",
		Note:  "GPT Engineer code generation tool",
	},
	{
		Name:  "tabby",
		Paths: []string{".tabby"},
		Risk:  "low",
		Note:  "Tabby self-hosted coding assistant",
	},
	{
		Name:  "fitten",
		Paths: []string{".fitten"},
		Risk:  "low",
		Note:  "Fitten Code AI assistant",
	},
	{
		Name:  "codeium",
		Paths: []string{".codeium"},
		Risk:  "low",
		Note:  "Codeium AI assistant",
	},
	{
		Name:  "blackbox",
		Paths: []string{".blackbox"},
		Risk:  "low",
		Note:  "Blackbox AI assistant",
	},
	{
		Name:  "replit",
		Paths: []string{".replit"},
		Risk:  "low",
		Note:  "Replit AI workspace config",
	},
	{
		Name:  "v0",
		Paths: []string{".v0"},
		Risk:  "low",
		Note:  "Vercel v0 AI design tool",
	},
	{
		Name:  "bolt",
		Paths: []string{".bolt"},
		Risk:  "low",
		Note:  "Bolt.new AI app builder",
	},
	{
		Name:  "lovable",
		Paths: []string{".lovable"},
		Risk:  "low",
		Note:  "Lovable AI app builder",
	},
	{
		Name:  "cursor_rules",
		Paths: []string{".cursorrules"},
		Risk:  "low",
		Note:  "Cursor rules file (indicates Cursor usage)",
	},
	{
		Name:  "antigravity",
		Paths: []string{".antigravity", ".config/Antigravity", "Library/Application Support/Antigravity"},
		Risk:  "high",
		Note:  "Google Antigravity AI IDE with network access",
	},
	{
		Name:  "devin",
		Paths: []string{".devin", ".config/devin", "Library/Application Support/Devin"},
		Risk:  "high",
		Note:  "Devin autonomous AI software engineer (Desktop)",
	},
	{
		Name:  "vscodium",
		Paths: []string{".config/VSCodium", "Library/Application Support/VSCodium"},
		Risk:  "low",
		Note:  "VSCodium open-source VS Code build (may host AI extensions)",
	},
	{
		Name:  "eigent",
		Paths: []string{".eigent", ".config/eigent", "Library/Application Support/Eigent"},
		Risk:  "high",
		Note:  "Eigent AI agent with terminal + network access",
	},
	{
		Name:  "gordon",
		Paths: []string{".docker/gordon"},
		Risk:  "high",
		Note:  "Docker AI assistant (Gordon) with terminal + network access",
	},
	{
		Name:  "docker_ai",
		Paths: []string{".docker/models", ".docker/gordon"},
		Risk:  "medium",
		Note:  "Docker-hosted AI workloads (LLM images, model registry)",
	},
	{
		Name:  "browser_ai",
		Paths: []string{"Library/Application Support/BraveSoftware", "Library/Application Support/Google/Chrome", "Library/Application Support/Microsoft Edge"},
		Risk:  "medium",
		Note:  "Browser-based AI assistants (Brave Leo, Perplexity, Copilot, ChatGPT, Gemini)",
	},
}

// LlamaCppInstallDirs are the well-known llama.cpp build locations.
var LlamaCppInstallDirs = []string{"~/llama.cpp", "~/src/llama.cpp", "~/build/llama.cpp", "/opt/llama.cpp", "/usr/local/bin"}

// CodeScanDirs are the source directories scanned for embedded AI usage.
var CodeScanDirs = []string{"~/projects", "~/code", "~/repos", "~/src", "~/work", "~/Developer", "~/development", "~/Documents"}

// HermesRoot is the Hermes agent state directory, relative to a user home.
const HermesRoot = ".hermes"
