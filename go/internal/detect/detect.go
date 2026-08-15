// Package detect implements shadow-AI tool discovery and scanning for
// the Go TRACE CLI. It mirrors the Python ionsec_trace.collector.shadow_ai
// collector, keeping the curated tool catalog and detection logic in sync.
package detect

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ionsec/trace/go/internal/model"
)

// tool is a single entry in the curated shadow-AI catalog.
type tool struct {
	name     string
	relPaths []string
	risk     string
	note     string
	category string
	binaries []string
}

// shadowCatalog mirrors src/ionsec_trace/collector/shadow_ai.py SHADOW_AI_TOOLS,
// enriched with the binary names and category each tool belongs to.
var shadowCatalog = []tool{
	{"cursor", []string{".cursor", ".config/Cursor", "Library/Application Support/Cursor", "AppData/Roaming/Cursor"}, "high", "AI code editor with network access and telemetry", "devtool", []string{"cursor", "cursor-agent"}},
	{"deepseek_harness", []string{".dsh"}, "high", "DeepSeek Harness (dsh) agent runtime with tool + network access", "agent", []string{"dsh"}},
	{"claude_code", []string{".claude"}, "high", "Claude Code agent runtime with terminal + network access", "devtool", []string{"claude"}},
	{"codex_cli", []string{".codex"}, "high", "OpenAI Codex CLI agent with terminal + network access", "devtool", []string{"codex"}},
	{"aider", []string{".aider", ".aider.conf.yml", ".aider.input.history"}, "low", "AI pair-programming CLI", "devtool", []string{"aider"}},
	{"continue", []string{".continue"}, "high", "Continue IDE extension with network access", "devtool", []string{"continue"}},
	{"cline", []string{".cline"}, "high", "Cline autonomous coding agent with terminal access", "devtool", []string{"cline"}},
	{"warp", []string{".warp"}, "low", "Warp terminal with AI features", "devtool", []string{"warp"}},
	{"shell_gpt", []string{".shell_gpt", ".config/shell-gpt"}, "low", "Shell-GPT command-line AI assistant", "devtool", []string{"sgpt", "shell_gpt"}},
	{"ollama", []string{".ollama"}, "medium", "Local LLM runtime (may expose API on localhost)", "inference", []string{"ollama"}},
	{"lm_studio", []string{"Library/Application Support/LM Studio", ".lmstudio", "AppData/Local/LM-Studio"}, "medium", "LM Studio local LLM GUI", "inference", []string{"lmstudio"}},
	{"jan", []string{".jan"}, "medium", "Jan local LLM desktop app", "inference", []string{"jan"}},
	{"anythingllm", []string{".anythingllm", "Library/Application Support/anythingllm-desktop"}, "medium", "AnythingLLM local LLM workspace", "inference", []string{"anythingllm"}},
	{"openclaw", []string{".openclaw", ".config/openclaw"}, "high", "OpenClaw agent runtime with tool/network access", "agent", []string{"openclaw", "claw"}},
	{"clawdbot", []string{".clawdbot", ".config/clawdbot"}, "high", "Clawdbot agent runtime with tool/network access", "agent", []string{"clawdbot"}},
	{"moltbot", []string{".moltbot", ".config/moltbot"}, "high", "Moltbot agent runtime with tool/network access", "agent", []string{"moltbot"}},
	{"nanoclaw", []string{".nanoclaw", ".config/nanoclaw"}, "high", "NanoClaw lightweight agent runtime with tool/network access", "agent", []string{"nanoclaw", "nano-claw"}},
	{"openinterpreter", []string{".open-interpreter"}, "high", "Open Interpreter agent with terminal + network access", "agent", []string{"interpreter"}},
	{"autogen", []string{".autogen"}, "medium", "AutoGen multi-agent framework", "agent", []string{"autogen"}},
	{"langchain", []string{".langchain"}, "low", "LangChain framework traces", "agent", []string{"langchain"}},
	{"copilot", []string{".copilot", ".config/github-copilot"}, "medium", "GitHub Copilot with network access", "devtool", []string{"copilot"}},
	{"gemini_cli", []string{".gemini"}, "high", "Gemini CLI agent with terminal + network access", "devtool", []string{"gemini"}},
	{"amazon_q", []string{".aws/amazonq", ".config/amazonq"}, "medium", "Amazon Q developer agent", "devtool", []string{"q", "amazon-q"}},
	{"windsurf", []string{".codeium", ".config/Windsurf"}, "high", "Windsurf AI editor with network access", "devtool", []string{"windsurf"}},
	{"kilo_code", []string{".kilo"}, "high", "Kilo Code agent with terminal + network access", "devtool", []string{"kilo"}},
	{"roo_code", []string{".roo"}, "high", "Roo Code agent with terminal + network access", "devtool", []string{"roo"}},
	{"goose", []string{".config/goose", ".goose"}, "high", "Goose agent runtime with terminal + network access", "agent", []string{"goose"}},
	{"openhands", []string{".openhands", ".config/openhands"}, "high", "OpenHands autonomous agent with network access", "agent", []string{"openhands"}},
	{"devika", []string{".devika"}, "high", "Devika autonomous agent with network access", "agent", []string{"devika"}},
	{"swe_agent", []string{".swe-agent"}, "high", "SWE-agent autonomous coding agent", "agent", []string{"swe-agent"}},
	{"gpt_engineer", []string{".gpt_engineer"}, "medium", "GPT Engineer code generation tool", "agent", []string{"gpt-engineer"}},
	{"tabby", []string{".tabby"}, "low", "Tabby self-hosted coding assistant", "devtool", []string{"tabby"}},
	{"fitten", []string{".fitten"}, "low", "Fitten Code AI assistant", "devtool", []string{"fitten"}},
	{"codeium", []string{".codeium"}, "low", "Codeium AI assistant", "devtool", []string{"codeium"}},
	{"blackbox", []string{".blackbox"}, "low", "Blackbox AI assistant", "devtool", []string{"blackbox"}},
	{"replit", []string{".replit"}, "low", "Replit AI workspace config", "devtool", []string{"replit"}},
	{"v0", []string{".v0"}, "low", "Vercel v0 AI design tool", "devtool", []string{"v0"}},
	{"bolt", []string{".bolt"}, "low", "Bolt.new AI app builder", "devtool", []string{"bolt"}},
	{"lovable", []string{".lovable"}, "low", "Lovable AI app builder", "devtool", []string{"lovable"}},
	{"cursor_rules", []string{".cursorrules"}, "low", "Cursor rules file (indicates Cursor usage)", "devtool", nil},
	{"antigravity", []string{".antigravity", ".config/Antigravity", "Library/Application Support/Antigravity", "AppData/Roaming/Antigravity"}, "high", "Google Antigravity AI IDE with network access", "devtool", []string{"antigravity"}},
	{"devin", []string{".devin", ".config/devin", "Library/Application Support/Devin"}, "high", "Devin autonomous AI software engineer (Desktop)", "agent", []string{"devin"}},
	{"vscodium", []string{".config/VSCodium", "Library/Application Support/VSCodium", "AppData/Roaming/VSCodium"}, "low", "VSCodium open-source VS Code build (may host AI extensions)", "devtool", nil},
	{"eigent", []string{".eigent", ".config/eigent", "Library/Application Support/Eigent"}, "high", "Eigent AI agent with terminal + network access", "agent", []string{"eigent"}},
	{"gordon", []string{".docker/gordon"}, "high", "Docker AI assistant (Gordon) with terminal + network access", "agent", []string{"gordon"}},
	{"docker_ai", []string{".docker/models", ".docker/gordon"}, "medium", "Docker-hosted AI workloads (LLM images, model registry)", "inference", nil},
	{"browser_ai", []string{"Library/Application Support/BraveSoftware", "Library/Application Support/Google/Chrome", "Library/Application Support/Microsoft Edge"}, "medium", "Browser-based AI assistants (Brave Leo, Perplexity, Copilot, ChatGPT, Gemini)", "cloud", nil},
}

// homeDirs returns candidate user home directories for the current OS,
// including the primary user plus common secondary locations.
func homeDirs() []string {
	dirs := []string{}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		dirs = append(dirs, h)
	}
	switch runtime.GOOS {
	case "linux":
		dirs = append(dirs, "/home")
	case "darwin":
		dirs = append(dirs, "/Users")
	case "windows":
		dirs = append(dirs, "C:\\Users")
	}
	return dirs
}

// findBinary returns the first matching executable on PATH for the given
// candidate names, or "" if none is found.
func findBinary(candidates []string) string {
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil && p != "" {
			return p
		}
	}
	return ""
}

// aiImagePatterns are substrings of Docker image names that indicate an
// AI/LLM workload.
var aiImagePatterns = []string{
	"ollama", "localai", "vllm", "text-generation-webui", "textgen",
	"llama-cpp", "llamacpp", "gpt4all", "jan", "anythingllm",
	"open-webui", "openwebui", "litellm", "bifrost", "unsloth",
	"koboldcpp", "tabby", "gpt-engineer", "openhands", "autogpt",
	"crewai", "langchain", "chromadb", "weaviate", "qdrant",
	"comfyui", "stable-diffusion", "automatic1111",
}

// aiDockerImages lists installed Docker images whose name matches an AI pattern.
func aiDockerImages() []string {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}
	out, err := exec.Command("docker", "images", "--format", "{{.Repository}}:{{.Tag}}").Output()
	if err != nil {
		return nil
	}
	var images []string
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.ToLower(line)
		for _, p := range aiImagePatterns {
			if strings.Contains(l, p) {
				images = append(images, strings.TrimSpace(line))
				break
			}
		}
	}
	return images
}

// resolvePath joins a home directory and a relative artifact path, handling
// Windows-style separators on the relevant OS.
func resolvePath(home, rel string) string {
	rel = strings.ReplaceAll(rel, "/", string(filepath.Separator))
	rel = strings.ReplaceAll(rel, "\\", string(filepath.Separator))
	return filepath.Join(home, rel)
}

// detect returns the list of shadow-AI tools present on the endpoint,
// mirroring the Python _detect_tools logic.
func detect() []model.Detection {
	var found []model.Detection
	homes := homeDirs()

	for _, t := range shadowCatalog {
		cfgPath := ""
		for _, rel := range t.relPaths {
			for _, home := range homes {
				cand := resolvePath(home, rel)
				if st, err := os.Stat(cand); err == nil {
					_ = st
					cfgPath = cand
					break
				}
			}
			if cfgPath != "" {
				break
			}
		}

		binary := findBinary(t.binaries)
		if cfgPath != "" || binary != "" {
			found = append(found, model.Detection{
				Tool:       t.name,
				Installed:  true,
				ConfigPath: cfgPath,
				Binary:     binary,
				Risk:       t.risk,
				Note:       t.note,
				Category:   t.category,
			})
		}
	}

	// Catalogued platforms (per-OS artifact roots) — union with the shadow-AI
	// table above, which wins on name collisions since its notes are curated.
	seen := map[string]bool{}
	for _, d := range found {
		seen[d.Tool] = true
	}
	for _, d := range discoverPlatforms() {
		if seen[d.Tool] {
			// Enrich the curated entry with every root we found.
			for i := range found {
				if found[i].Tool == d.Tool && len(found[i].Roots) == 0 {
					found[i].Roots = d.Roots
				}
			}
			continue
		}
		seen[d.Tool] = true
		found = append(found, d)
	}

	// Live Docker AI workloads — even if no .docker/models dir exists.
	if imgs := aiDockerImages(); len(imgs) > 0 {
		found = append(found, model.Detection{
			Tool:       "docker_ai_images",
			Installed:  true,
			ConfigPath: strings.Join(imgs[:min(len(imgs), 5)], ", "),
			Risk:       "medium",
			Note:       "Docker-hosted AI/LLM images running locally",
			Category:   "inference",
		})
	}

	return found
}

// Discover returns the list of shadow-AI tools present on the endpoint.
func Discover() []model.Detection {
	return detect()
}

// AnyPresent reports whether at least one shadow-AI tool was detected.
func AnyPresent() bool {
	return len(detect()) > 0
}
