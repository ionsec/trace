// Package catalog holds the TRACE platform catalog: every AI platform TRACE
// knows about, with its per-OS artifact roots, process names and service ports.
//
// It mirrors the Python collector catalog in src/ionsec_trace/collector/ so the
// Go and Python builds discover and collect the same platforms.
package catalog

// Platform describes one AI platform TRACE can discover and collect.
type Platform struct {
	Name      string
	Category  string
	Linux     []string
	MacOS     []string
	Windows   []string
	Processes []string
	Ports     []int
	// Secondary are roots that belong to this platform but are shared with
	// other tools, so they are collected once the platform is confirmed present
	// and never counted as evidence of it. ~/.agents is the motivating case:
	// dsh reads skills from it, but so do other agent runtimes, and treating it
	// as a detection signal reports dsh on hosts that have never run it.
	Secondary []string
}

// Platforms is the full catalog, in the same order as the Python registry.
var Platforms = []Platform{
	{
		Name:      "ollama",
		Category:  "inference",
		Linux:     []string{"/root/.ollama", "/usr/share/ollama/.ollama"},
		MacOS:     []string{"~/.ollama", "~/Library/Application Support/Ollama"},
		Windows:   []string{"%USERPROFILE%\\.ollama", "%LOCALAPPDATA%\\Ollama"},
		Processes: []string{"ollama", "ollama serve"},
		Ports:     []int{11434},
	},
	{
		Name:      "deepseek_harness",
		Category:  "agent",
		Linux:     []string{"~/.dsh"},
		MacOS:     []string{"~/.dsh"},
		Windows:   []string{"%USERPROFILE%\\.dsh"},
		Secondary: []string{"~/.agents"},
		Processes: []string{"dsh", "dsh-acp-demo"},
		Ports:     []int{3080},
	},
	{
		Name:      "hermes",
		Category:  "agent",
		Processes: []string{"hermes"},
	},
	{
		Name:      "lm_studio",
		Category:  "inference",
		Linux:     []string{"~/.cache/lm-studio/"},
		MacOS:     []string{"~/Library/Application Support/LM Studio/", "~/Library/Caches/lm-studio/"},
		Windows:   []string{"%APPDATA%\\LM Studio\\", "%LOCALAPPDATA%\\LM Studio\\"},
		Processes: []string{"lm-studio", "LM Studio"},
		Ports:     []int{1234},
	},
	{
		Name:      "gpt4all",
		Category:  "inference",
		Linux:     []string{"~/.gpt4all/"},
		MacOS:     []string{"~/Library/Application Support/gpt4all/"},
		Windows:   []string{"%APPDATA%\\gpt4all\\"},
		Processes: []string{"gpt4all", "GPT4All", "chat"},
		Ports:     []int{4891},
	},
	{
		Name:      "text_generation_webui",
		Category:  "inference",
		Linux:     []string{"~/text-generation-webui/", "/opt/text-generation-webui/"},
		MacOS:     []string{"~/text-generation-webui/"},
		Windows:   []string{"%USERPROFILE%\\text-generation-webui\\", "C:\\text-generation-webui\\"},
		Processes: []string{"text-generation-webui", "server.py", "oobabooga"},
		Ports:     []int{7860, 5000},
	},
	{
		Name:      "llama_cpp",
		Category:  "inference",
		Processes: []string{"llama-server", "llama-cli", "llama-cpp", "main", "server"},
		Ports:     []int{8080},
	},
	{
		Name:      "kobold_cpp",
		Category:  "inference",
		Linux:     []string{"~/.koboldcpp", "/opt/koboldcpp", "/usr/local/bin/koboldcpp"},
		MacOS:     []string{"~/.koboldcpp", "~/Library/Application Support/KoboldCpp"},
		Windows:   []string{"%USERPROFILE%\\.koboldcpp", "%LOCALAPPDATA%\\KoboldCpp", "%PROGRAMFILES%\\KoboldCpp"},
		Processes: []string{"koboldcpp", "koboldcpp.py"},
		Ports:     []int{5001},
	},
	{
		Name:      "autogpt",
		Category:  "agent",
		Linux:     []string{"~/.autogpt"},
		MacOS:     []string{"~/.autogpt"},
		Windows:   []string{"%USERPROFILE%\\.autogpt"},
		Processes: []string{"autogpt", "Auto-GPT"},
	},
	{
		Name:      "crewai",
		Category:  "agent",
		Linux:     []string{"~/.crewai"},
		MacOS:     []string{"~/.crewai"},
		Windows:   []string{"%USERPROFILE%\\.crewai"},
		Processes: []string{"crewai"},
	},
	{
		Name:      "aider",
		Category:  "devtool",
		Linux:     []string{"~/.aider"},
		MacOS:     []string{"~/.aider"},
		Windows:   []string{"%USERPROFILE%\\.aider"},
		Processes: []string{"aider"},
	},
	{
		Name:      "shell_gpt",
		Category:  "devtool",
		Linux:     []string{"~/.shell_gpt"},
		MacOS:     []string{"~/.shell_gpt"},
		Windows:   []string{"%USERPROFILE%\\.shell_gpt"},
		Processes: []string{"sgpt"},
	},
	{
		Name:      "cursor",
		Category:  "devtool",
		Linux:     []string{"~/.cursor"},
		MacOS:     []string{"~/Library/Application Support/Cursor"},
		Windows:   []string{"%APPDATA%\\Cursor"},
		Processes: []string{"cursor", "Cursor"},
	},
	{
		Name:      "claude_code",
		Category:  "devtool",
		Linux:     []string{"~/.claude"},
		MacOS:     []string{"~/.claude"},
		Windows:   []string{"%USERPROFILE%\\.claude"},
		Processes: []string{"claude", "claude-code"},
	},
	{
		Name:      "huggingface",
		Category:  "cloud",
		Linux:     []string{"~/.cache/huggingface", "~/.huggingface"},
		MacOS:     []string{"~/.cache/huggingface", "~/.huggingface"},
		Windows:   []string{"%USERPROFILE%\\.cache\\huggingface", "%USERPROFILE%\\.huggingface"},
		Processes: []string{"huggingface-cli", "transformers", "huggingface"},
	},
	{
		Name:      "litellm",
		Category:  "inference",
		Linux:     []string{"~/.litellm", "/etc/litellm"},
		MacOS:     []string{"~/.litellm", "/etc/litellm", "~/Library/Application Support/litellm"},
		Windows:   []string{"%APPDATA%\\litellm", "%PROGRAMDATA%\\litellm"},
		Processes: []string{"litellm"},
		Ports:     []int{4000},
	},
	{
		Name:      "bifrost",
		Category:  "inference",
		Linux:     []string{"~/.bifrost", "/etc/bifrost", "/var/lib/bifrost"},
		MacOS:     []string{"~/.bifrost", "/etc/bifrost", "/var/lib/bifrost", "~/Library/Application Support/bifrost"},
		Windows:   []string{"%APPDATA%\\bifrost", "%PROGRAMDATA%\\bifrost"},
		Processes: []string{"bifrost"},
		Ports:     []int{8080, 8443},
	},
	{
		Name:      "unsloth",
		Category:  "inference",
		Linux:     []string{"~/.unsloth", "~/.cache/unsloth", "~/.config/unsloth", "~/.local/share/unsloth"},
		MacOS:     []string{"~/.unsloth", "~/.cache/unsloth", "~/.config/unsloth", "~/.local/share/unsloth", "~/Library/Application Support/unsloth"},
		Windows:   []string{"%USERPROFILE%\\.unsloth", "%LOCALAPPDATA%\\unsloth", "%APPDATA%\\unsloth"},
		Processes: []string{"unsloth", "unsloth-studio"},
	},
	{
		Name:     "shadow_ai",
		Category: "agent",
	},
	{
		Name:      "antigravity",
		Category:  "devtool",
		Linux:     []string{"~/.antigravity", "~/.config/Antigravity"},
		MacOS:     []string{"~/Library/Application Support/Antigravity"},
		Windows:   []string{"%APPDATA%\\Antigravity"},
		Processes: []string{"antigravity", "Antigravity"},
	},
	{
		Name:      "devin",
		Category:  "agent",
		Linux:     []string{"~/.devin", "~/.config/devin"},
		MacOS:     []string{"~/Library/Application Support/Devin"},
		Windows:   []string{"%APPDATA%\\Devin"},
		Processes: []string{"devin", "Devin"},
	},
	{
		Name:      "vscodium",
		Category:  "devtool",
		Linux:     []string{"~/.config/VSCodium"},
		MacOS:     []string{"~/Library/Application Support/VSCodium"},
		Windows:   []string{"%APPDATA%\\VSCodium"},
		Processes: []string{"codium", "VSCodium"},
	},
	{
		Name:      "eigent",
		Category:  "agent",
		Linux:     []string{"~/.eigent", "~/.config/eigent"},
		MacOS:     []string{"~/.eigent", "~/.config/eigent", "~/Library/Application Support/Eigent"},
		Windows:   []string{"%USERPROFILE%\\.eigent", "%APPDATA%\\Eigent"},
		Processes: []string{"eigent"},
	},
	{
		Name:     "network_ai",
		Category: "cloud",
	},
	{
		Name:     "code_scanner",
		Category: "devtool",
	},
	{
		Name:      "docker_ai",
		Category:  "agent",
		Linux:     []string{"~/.docker"},
		MacOS:     []string{"~/.docker"},
		Windows:   []string{"%USERPROFILE%\\.docker"},
		Processes: []string{"docker", "docker desktop", "gordon"},
	},
	{
		Name:      "browser_ai",
		Category:  "cloud",
		Linux:     []string{"~/.config/google-chrome", "~/.config/microsoft-edge", "~/.config/BraveSoftware"},
		MacOS:     []string{"~/Library/Application Support/Google/Chrome", "~/Library/Application Support/Microsoft Edge", "~/Library/Application Support/BraveSoftware", "~/Library/Application Support/Arc", "~/Library/Application Support/Google/Chrome Canary"},
		Windows:   []string{"%LOCALAPPDATA%\\Google\\Chrome", "%LOCALAPPDATA%\\Microsoft\\Edge", "%LOCALAPPDATA%\\BraveSoftware"},
		Processes: []string{"brave", "chrome", "msedge", "firefox", "arc", "opera"},
	},
}

// ByName returns the catalog entry for a platform name.
func ByName(name string) (Platform, bool) {
	for _, p := range Platforms {
		if p.Name == name {
			return p, true
		}
	}
	return Platform{}, false
}
