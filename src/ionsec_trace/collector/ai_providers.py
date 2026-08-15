"""
AI provider domain catalog for TRACE.

A curated catalog of known AI/LLM provider domains and the AI frameworks,
MCP servers, and agent runtimes that indicate shadow-AI usage. Used by the
NetworkAICollector (process-to-domain classification) and the
CodeScannerCollector (framework-import and MCP-config detection) to turn
raw traffic and source code into classified AI signals.

This is the "known agents" list that tools like AgentSonar and PatronAI
maintain — but kept as a single, versioned, testable catalog that both the
network and code collectors share.
"""

# ---------------------------------------------------------------------------
# AI / LLM provider domains
# ---------------------------------------------------------------------------
# Each entry: (domain_suffix, provider_name, category)
# category ∈ {inference, agent, embedding, image, audio, video, search, code}
AI_PROVIDER_DOMAINS = [
    # Inference / chat
    ("api.openai.com", "OpenAI", "inference"),
    ("openai.com", "OpenAI", "inference"),
    ("api.anthropic.com", "Anthropic", "inference"),
    ("anthropic.com", "Anthropic", "inference"),
    ("api.deepseek.com", "DeepSeek", "inference"),
    ("deepseek.com", "DeepSeek", "inference"),
    ("api.mistral.ai", "Mistral", "inference"),
    ("mistral.ai", "Mistral", "inference"),
    ("api.groq.com", "Groq", "inference"),
    ("groq.com", "Groq", "inference"),
    ("api.cohere.com", "Cohere", "inference"),
    ("cohere.com", "Cohere", "inference"),
    ("api.together.xyz", "Together AI", "inference"),
    ("together.xyz", "Together AI", "inference"),
    ("api.replicate.com", "Replicate", "inference"),
    ("replicate.com", "Replicate", "inference"),
    ("api.stability.ai", "Stability AI", "image"),
    ("stability.ai", "Stability AI", "image"),
    ("api.eleuther.ai", "EleutherAI", "inference"),
    ("eleuther.ai", "EleutherAI", "inference"),
    ("api.fireworks.ai", "Fireworks AI", "inference"),
    ("fireworks.ai", "Fireworks AI", "inference"),
    ("api.perplexity.ai", "Perplexity", "search"),
    ("perplexity.ai", "Perplexity", "search"),
    ("api.x.ai", "xAI", "inference"),
    ("x.ai", "xAI", "inference"),
    ("api.grok.x", "xAI Grok", "inference"),
    ("grok.x", "xAI Grok", "inference"),
    ("api.llama.ai", "Meta Llama", "inference"),
    ("llama.com", "Meta Llama", "inference"),
    ("api.gemini.google.com", "Google Gemini", "inference"),
    ("generativelanguage.googleapis.com", "Google Gemini", "inference"),
    ("aiplatform.googleapis.com", "Google Vertex AI", "inference"),
    ("vertexai.googleapis.com", "Google Vertex AI", "inference"),
    ("api.azure.com", "Azure OpenAI", "inference"),
    ("openai.azure.com", "Azure OpenAI", "inference"),
    ("bedrock-runtime.amazonaws.com", "AWS Bedrock", "inference"),
    ("bedrock.amazonaws.com", "AWS Bedrock", "inference"),
    ("api.aws.amazon.com", "AWS AI", "inference"),
    ("inference.ai.azure.com", "Azure AI", "inference"),
    ("api.databricks.com", "Databricks", "inference"),
    ("adb-*.azuredatabricks.net", "Databricks", "inference"),
    ("api.watsonx.ai", "IBM watsonx", "inference"),
    ("watsonx.ai", "IBM watsonx", "inference"),
    ("api.nvidia.com", "NVIDIA NIM", "inference"),
    ("integrate.api.nvidia.com", "NVIDIA NIM", "inference"),
    ("api.ibm.com", "IBM AI", "inference"),
    ("api.sambanova.ai", "SambaNova", "inference"),
    ("sambanova.ai", "SambaNova", "inference"),
    ("api.cerebras.ai", "Cerebras", "inference"),
    ("cerebras.ai", "Cerebras", "inference"),
    ("api.scale.com", "Scale AI", "inference"),
    ("scale.com", "Scale AI", "inference"),
    ("api.anyscale.com", "Anyscale", "inference"),
    ("anyscale.com", "Anyscale", "inference"),
    ("api.baseten.co", "Baseten", "inference"),
    ("baseten.co", "Baseten", "inference"),
    ("api.runpod.ai", "RunPod", "inference"),
    ("runpod.ai", "RunPod", "inference"),
    ("api.modal.com", "Modal", "inference"),
    ("modal.com", "Modal", "inference"),
    ("api.lambdalabs.com", "Lambda", "inference"),
    ("lambdalabs.com", "Lambda", "inference"),
    ("api.predibase.com", "Predibase", "inference"),
    ("predibase.com", "Predibase", "inference"),
    ("api.octoai.cloud", "OctoAI", "inference"),
    ("octoai.cloud", "OctoAI", "inference"),
    ("api.deepinfra.com", "DeepInfra", "inference"),
    ("deepinfra.com", "DeepInfra", "inference"),
    ("api.lemonfox.ai", "Lemonfox", "inference"),
    ("lemonfox.ai", "Lemonfox", "inference"),
    ("api.portkey.ai", "Portkey", "inference"),
    ("portkey.ai", "Portkey", "inference"),
    ("api.helicone.ai", "Helicone", "inference"),
    ("helicone.ai", "Helicone", "inference"),
    ("api.langfuse.com", "Langfuse", "inference"),
    ("langfuse.com", "Langfuse", "inference"),
    ("api.langsmith.com", "LangSmith", "inference"),
    ("langsmith.com", "LangSmith", "inference"),
    ("api.wandb.ai", "Weights & Biases", "inference"),
    ("wandb.ai", "Weights & Biases", "inference"),
    ("api.huggingface.co", "HuggingFace", "inference"),
    ("huggingface.co", "HuggingFace", "inference"),
    ("cdn-lfs.huggingface.co", "HuggingFace", "inference"),
    ("api-inference.huggingface.co", "HuggingFace", "inference"),
    ("api.ollama.com", "Ollama Cloud", "inference"),
    ("ollama.com", "Ollama", "inference"),
    ("api.lmstudio.ai", "LM Studio", "inference"),
    ("lmstudio.ai", "LM Studio", "inference"),
    ("api.gpt4all.io", "GPT4All", "inference"),
    ("gpt4all.io", "GPT4All", "inference"),
    ("api.unsloth.ai", "Unsloth", "inference"),
    ("unsloth.ai", "Unsloth", "inference"),
    ("api.vllm.ai", "vLLM", "inference"),
    ("vllm.ai", "vLLM", "inference"),
    ("api.litellm.ai", "LiteLLM", "inference"),
    ("litellm.ai", "LiteLLM", "inference"),
    ("api.bifrost.ai", "Bifrost", "inference"),
    ("bifrost.ai", "Bifrost", "inference"),
    ("api.jan.ai", "Jan", "inference"),
    ("jan.ai", "Jan", "inference"),
    ("api.anythingllm.com", "AnythingLLM", "inference"),
    ("anythingllm.com", "AnythingLLM", "inference"),
    ("api.localai.io", "LocalAI", "inference"),
    ("localai.io", "LocalAI", "inference"),
    ("api.koboldai.net", "KoboldAI", "inference"),
    ("koboldai.net", "KoboldAI", "inference"),
    ("api.text-gen.com", "text-generation-webui", "inference"),
    ("api.llamacpp.ai", "llama.cpp", "inference"),
    ("llamacpp.ai", "llama.cpp", "inference"),
    # Embedding / vector
    ("api.openai.com", "OpenAI Embeddings", "embedding"),
    ("api.cohere.com", "Cohere Embeddings", "embedding"),
    ("api.voyageai.com", "Voyage AI", "embedding"),
    ("voyageai.com", "Voyage AI", "embedding"),
    ("api.jina.ai", "Jina AI", "embedding"),
    ("jina.ai", "Jina AI", "embedding"),
    ("api.mixedbread.ai", "MixedBread", "embedding"),
    ("mixedbread.ai", "MixedBread", "embedding"),
    # Image / video / audio generation
    ("api.midjourney.com", "Midjourney", "image"),
    ("midjourney.com", "Midjourney", "image"),
    ("api.runwayml.com", "Runway", "video"),
    ("runwayml.com", "Runway", "video"),
    ("api.elevenlabs.io", "ElevenLabs", "audio"),
    ("elevenlabs.io", "ElevenLabs", "audio"),
    ("api.assemblyai.com", "AssemblyAI", "audio"),
    ("assemblyai.com", "AssemblyAI", "audio"),
    ("api.deepgram.com", "Deepgram", "audio"),
    ("deepgram.com", "Deepgram", "audio"),
    ("api.whisper.ai", "Whisper", "audio"),
    ("api.suno.ai", "Suno", "audio"),
    ("suno.ai", "Suno", "audio"),
    ("api.udio.com", "Udio", "audio"),
    ("udio.com", "Udio", "audio"),
    ("api.ideogram.ai", "Ideogram", "image"),
    ("ideogram.ai", "Ideogram", "image"),
    ("api.leonardo.ai", "Leonardo AI", "image"),
    ("leonardo.ai", "Leonardo AI", "image"),
    ("api.fliki.ai", "Fliki", "video"),
    ("fliki.ai", "Fliki", "video"),
    # Code assistants / agents
    ("api.githubcopilot.com", "GitHub Copilot", "code"),
    ("copilot-proxy.githubusercontent.com", "GitHub Copilot", "code"),
    ("api.cursor.sh", "Cursor", "code"),
    ("cursor.sh", "Cursor", "code"),
    ("api.anthropic.com", "Claude Code", "code"),
    ("api.openai.com", "Codex", "code"),
    ("api.aider.chat", "Aider", "code"),
    ("aider.chat", "Aider", "code"),
    ("api.windsurf.com", "Windsurf", "code"),
    ("windsurf.com", "Windsurf", "code"),
    ("api.codeium.com", "Codeium", "code"),
    ("codeium.com", "Codeium", "code"),
    ("api.tabby.sh", "Tabby", "code"),
    ("tabby.sh", "Tabby", "code"),
    ("api.continue.dev", "Continue", "code"),
    ("continue.dev", "Continue", "code"),
    ("api.cline.bot", "Cline", "code"),
    ("cline.bot", "Cline", "code"),
    ("api.roocode.com", "Roo Code", "code"),
    ("roocode.com", "Roo Code", "code"),
    ("api.kilocode.com", "Kilo Code", "code"),
    ("kilocode.com", "Kilo Code", "code"),
    ("api.gemini.google.com", "Gemini CLI", "code"),
    ("api.aws.amazon.com", "Amazon Q", "code"),
    ("api.devin.ai", "Devin", "code"),
    ("devin.ai", "Devin", "code"),
    ("api.antigravity.google", "Antigravity", "code"),
    ("antigravity.google", "Antigravity", "code"),
    ("api.eigent.ai", "Eigent", "code"),
    ("eigent.ai", "Eigent", "code"),
    ("api.openclaw.ai", "OpenClaw", "agent"),
    ("openclaw.ai", "OpenClaw", "agent"),
    ("api.clawdbot.ai", "Clawdbot", "agent"),
    ("clawdbot.ai", "Clawdbot", "agent"),
    ("api.moltbot.ai", "Moltbot", "agent"),
    ("moltbot.ai", "Moltbot", "agent"),
    ("api.nanoclaw.ai", "NanoClaw", "agent"),
    ("nanoclaw.ai", "NanoClaw", "agent"),
    ("api.openhands.ai", "OpenHands", "agent"),
    ("openhands.ai", "OpenHands", "agent"),
    ("api.autogpt.ai", "AutoGPT", "agent"),
    ("autogpt.ai", "AutoGPT", "agent"),
    ("api.crewai.com", "CrewAI", "agent"),
    ("crewai.com", "CrewAI", "agent"),
    ("api.langchain.com", "LangChain", "agent"),
    ("langchain.com", "LangChain", "agent"),
    ("api.langgraph.com", "LangGraph", "agent"),
    ("langgraph.com", "LangGraph", "agent"),
    ("api.autogen.ai", "AutoGen", "agent"),
    ("autogen.ai", "AutoGen", "agent"),
    ("api.openinterpreter.com", "Open Interpreter", "agent"),
    ("openinterpreter.com", "Open Interpreter", "agent"),
    ("api.goose.ai", "Goose", "agent"),
    ("goose.ai", "Goose", "agent"),
    ("api.sweagent.com", "SWE-agent", "agent"),
    ("sweagent.com", "SWE-agent", "agent"),
    ("api.gptengineer.com", "GPT Engineer", "agent"),
    ("gptengineer.com", "GPT Engineer", "agent"),
    ("api.devika.ai", "Devika", "agent"),
    ("devika.ai", "Devika", "agent"),
    ("api.replit.com", "Replit", "code"),
    ("replit.com", "Replit", "code"),
    ("api.v0.dev", "Vercel v0", "code"),
    ("v0.dev", "Vercel v0", "code"),
    ("api.bolt.new", "Bolt.new", "code"),
    ("bolt.new", "Bolt.new", "code"),
    ("api.lovable.dev", "Lovable", "code"),
    ("lovable.dev", "Lovable", "code"),
    ("api.blackbox.ai", "Blackbox AI", "code"),
    ("blackbox.ai", "Blackbox AI", "code"),
    ("api.fitten.ai", "Fitten Code", "code"),
    ("fitten.ai", "Fitten Code", "code"),
    ("api.amazonq.dev", "Amazon Q", "code"),
    ("amazonq.dev", "Amazon Q", "code"),
    ("api.warp.dev", "Warp", "code"),
    ("warp.dev", "Warp", "code"),
    ("api.shellgpt.ai", "Shell-GPT", "code"),
    ("shellgpt.ai", "Shell-GPT", "code"),
    ("api.gemini.google.com", "Gemini", "inference"),
    # MCP / tool servers
    ("api.mcp.ai", "MCP", "agent"),
    ("mcp.ai", "MCP", "agent"),
    ("api.modelcontextprotocol.io", "MCP", "agent"),
    ("modelcontextprotocol.io", "MCP", "agent"),
]

# ---------------------------------------------------------------------------
# AI framework / library import signatures (for code scanning)
# ---------------------------------------------------------------------------
# Each entry: (import_prefix, framework_name, category)
AI_FRAMEWORKS = [
    ("langchain", "LangChain", "agent"),
    ("langchain_core", "LangChain Core", "agent"),
    ("langchain_community", "LangChain Community", "agent"),
    ("langgraph", "LangGraph", "agent"),
    ("langsmith", "LangSmith", "inference"),
    ("llama_index", "LlamaIndex", "agent"),
    ("llamaindex", "LlamaIndex", "agent"),
    ("crewai", "CrewAI", "agent"),
    ("autogen", "AutoGen", "agent"),
    ("autogen_agentchat", "AutoGen AgentChat", "agent"),
    ("openai", "OpenAI SDK", "inference"),
    ("anthropic", "Anthropic SDK", "inference"),
    ("mistralai", "Mistral SDK", "inference"),
    ("cohere", "Cohere SDK", "inference"),
    ("together", "Together SDK", "inference"),
    ("replicate", "Replicate SDK", "inference"),
    ("groq", "Groq SDK", "inference"),
    ("deepseek", "DeepSeek SDK", "inference"),
    ("google.generativeai", "Google Gemini SDK", "inference"),
    ("vertexai", "Google Vertex AI SDK", "inference"),
    ("boto3", "AWS SDK (Bedrock)", "inference"),
    ("azure.ai", "Azure AI SDK", "inference"),
    ("openai_whisper", "Whisper", "audio"),
    ("whisper", "Whisper", "audio"),
    ("transformers", "HuggingFace Transformers", "inference"),
    ("torch", "PyTorch", "inference"),
    ("tensorflow", "TensorFlow", "inference"),
    ("keras", "Keras", "inference"),
    ("unsloth", "Unsloth", "inference"),
    ("vllm", "vLLM", "inference"),
    ("litellm", "LiteLLM", "inference"),
    ("bifrost", "Bifrost", "inference"),
    ("ollama", "Ollama", "inference"),
    ("llama_cpp", "llama.cpp", "inference"),
    ("llamacpp", "llama.cpp", "inference"),
    ("gpt4all", "GPT4All", "inference"),
    ("text_generation", "text-generation-webui", "inference"),
    ("koboldcpp", "KoboldCpp", "inference"),
    ("localai", "LocalAI", "inference"),
    ("jan", "Jan", "inference"),
    ("anythingllm", "AnythingLLM", "inference"),
    ("haystack", "Haystack", "agent"),
    ("dspy", "DSPy", "agent"),
    ("semantic_kernel", "Semantic Kernel", "agent"),
    ("instructor", "Instructor", "agent"),
    ("guidance", "Guidance", "agent"),
    ("outlines", "Outlines", "agent"),
    ("pydantic_ai", "Pydantic AI", "agent"),
    ("smolagents", "SmolAgents", "agent"),
    ("openinterpreter", "Open Interpreter", "agent"),
    ("interpreter", "Open Interpreter", "agent"),
    ("openhands", "OpenHands", "agent"),
    ("autogpt", "AutoGPT", "agent"),
    ("sweagent", "SWE-agent", "agent"),
    ("gpt_engineer", "GPT Engineer", "agent"),
    ("devika", "Devika", "agent"),
    ("goose", "Goose", "agent"),
    ("openclaw", "OpenClaw", "agent"),
    ("clawdbot", "Clawdbot", "agent"),
    ("moltbot", "Moltbot", "agent"),
    ("nanoclaw", "NanoClaw", "agent"),
    ("aider", "Aider", "code"),
    ("codex", "Codex", "code"),
    ("claude", "Claude Code", "code"),
    ("cursor", "Cursor", "code"),
    ("windsurf", "Windsurf", "code"),
    ("codeium", "Codeium", "code"),
    ("tabby", "Tabby", "code"),
    ("continue", "Continue", "code"),
    ("cline", "Cline", "code"),
    ("roo", "Roo Code", "code"),
    ("kilo", "Kilo Code", "code"),
    ("devin", "Devin", "code"),
    ("eigent", "Eigent", "code"),
    ("antigravity", "Antigravity", "code"),
    ("replit", "Replit", "code"),
    ("v0", "Vercel v0", "code"),
    ("bolt", "Bolt.new", "code"),
    ("lovable", "Lovable", "code"),
    ("blackbox", "Blackbox AI", "code"),
    ("fitten", "Fitten Code", "code"),
    ("amazonq", "Amazon Q", "code"),
    ("warp", "Warp", "code"),
    ("shellgpt", "Shell-GPT", "code"),
    ("sgpt", "Shell-GPT", "code"),
    ("mcp", "MCP", "agent"),
    ("fastmcp", "FastMCP", "agent"),
    ("mcp_server", "MCP Server", "agent"),
]

# ---------------------------------------------------------------------------
# MCP server config file patterns (for code scanning)
# ---------------------------------------------------------------------------
MCP_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
    ".claude.json",
    ".continue/config.json",
    ".continue/config.yaml",
    ".cline/mcp_settings.json",
    ".roo/mcp.json",
    ".windsurf/mcp.json",
    "mcp_servers.json",
    "mcp-servers.json",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_domain(domain: str):
    """Classify a domain against the AI provider catalog.

    Returns a dict with provider/category info, or None if not a known AI domain.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return None
    # Exact or suffix match (subdomains of a known provider)
    for suffix, provider, category in AI_PROVIDER_DOMAINS:
        suffix = suffix.lower()
        if domain == suffix or domain.endswith("." + suffix):
            return {
                "domain": domain,
                "provider": provider,
                "category": category,
                "matched_suffix": suffix,
            }
    return None


def is_ai_domain(domain: str) -> bool:
    """Return True if the domain is a known AI provider."""
    return classify_domain(domain) is not None


def classify_import(import_name: str):
    """Classify a Python import against the AI framework catalog.

    Returns a dict with framework/category info, or None if not a known AI framework.
    """
    import_name = (import_name or "").strip().lower()
    if not import_name:
        return None
    # Match the import prefix (e.g. "langchain_core" matches "langchain_core.agents")
    for prefix, framework, category in AI_FRAMEWORKS:
        if import_name == prefix or import_name.startswith(prefix + "."):
            return {
                "import": import_name,
                "framework": framework,
                "category": category,
                "matched_prefix": prefix,
            }
    return None


def is_ai_import(import_name: str) -> bool:
    """Return True if the import is a known AI framework."""
    return classify_import(import_name) is not None
