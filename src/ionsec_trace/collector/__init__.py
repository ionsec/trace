"""
TRACE collectors — discover and collect AI forensic artifacts.
"""

from ionsec_trace.collector.aider import AiderCollector
from ionsec_trace.collector.amazon_q import AmazonQCollector
from ionsec_trace.collector.amp import AmpCollector
from ionsec_trace.collector.antigravity import AntigravityCollector
from ionsec_trace.collector.anythingllm import AnythingLLMCollector
from ionsec_trace.collector.augment import AugmentCollector
from ionsec_trace.collector.autogpt import AutoGPTCollector
from ionsec_trace.collector.bifrost import BifrostCollector
from ionsec_trace.collector.browser_ai import BrowserAICollector
from ionsec_trace.collector.claude_code import ClaudeCodeCollector
from ionsec_trace.collector.cline import ClineCollector
from ionsec_trace.collector.code_scanner import CodeScannerCollector
from ionsec_trace.collector.codex import CodexCLICollector
from ionsec_trace.collector.continue_dev import ContinueCollector
from ionsec_trace.collector.copilot import CopilotCollector
from ionsec_trace.collector.crewai import CrewAICollector
from ionsec_trace.collector.cursor import CursorCollector
from ionsec_trace.collector.deepseek_harness import DeepSeekHarnessCollector
from ionsec_trace.collector.desktop_chat import DesktopChatCollector
from ionsec_trace.collector.devin import DevinCollector
from ionsec_trace.collector.docker_ai import DockerAICollector
from ionsec_trace.collector.eigent import EigentCollector
from ionsec_trace.collector.gemini_cli import GeminiCLICollector
from ionsec_trace.collector.goose import GooseCollector
from ionsec_trace.collector.gpt4all import GPT4AllCollector
from ionsec_trace.collector.grok import GrokCollector
from ionsec_trace.collector.hermes import HermesCollector
from ionsec_trace.collector.huggingface import HuggingFaceCacheCollector
from ionsec_trace.collector.jan import JanCollector
from ionsec_trace.collector.kilo import KiloCollector
from ionsec_trace.collector.kimi_code import KimiCodeCollector
from ionsec_trace.collector.kiro import KiroCollector
from ionsec_trace.collector.kobold_cpp import KoboldCppCollector
from ionsec_trace.collector.lemonade import LemonadeCollector
from ionsec_trace.collector.litellm import LiteLLMCollector
from ionsec_trace.collector.llama_cpp import LlamaCppCollector
from ionsec_trace.collector.lm_studio import LMStudioCollector
from ionsec_trace.collector.localai import LocalAICollector
from ionsec_trace.collector.network_ai import NetworkAICollector
from ionsec_trace.collector.ollama import OllamaCollector
from ionsec_trace.collector.open_webui import OpenWebUICollector
from ionsec_trace.collector.opencode import OpenCodeCollector
from ionsec_trace.collector.pi_family import PiFamilyCollector
from ionsec_trace.collector.qwen_code import QwenCodeCollector
from ionsec_trace.collector.shadow_ai import ShadowAICollector
from ionsec_trace.collector.shell_gpt import ShellGPTCollector
from ionsec_trace.collector.text_gen_webui import TextGenWebUICollector
from ionsec_trace.collector.unsloth import UnslothCollector
from ionsec_trace.collector.vllm import VLLMCollector
from ionsec_trace.collector.vscodium import VSCodiumCollector
from ionsec_trace.collector.warp import WarpCollector
from ionsec_trace.collector.zed import ZedCollector

# All collectors registered here
ALL_COLLECTORS = [
    OllamaCollector,
    HermesCollector,
    DeepSeekHarnessCollector,
    LMStudioCollector,
    GPT4AllCollector,
    TextGenWebUICollector,
    LlamaCppCollector,
    KoboldCppCollector,
    AutoGPTCollector,
    CrewAICollector,
    AiderCollector,
    ShellGPTCollector,
    CursorCollector,
    ClaudeCodeCollector,
    CodexCLICollector,
    GeminiCLICollector,
    GooseCollector,
    KiroCollector,
    AmazonQCollector,
    ZedCollector,
    PiFamilyCollector,
    AugmentCollector,
    ContinueCollector,
    GrokCollector,
    AmpCollector,
    KiloCollector,
    KimiCodeCollector,
    QwenCodeCollector,
    JanCollector,
    AnythingLLMCollector,
    LocalAICollector,
    OpenWebUICollector,
    VLLMCollector,
    LemonadeCollector,
    DesktopChatCollector,
    OpenCodeCollector,
    ClineCollector,
    CopilotCollector,
    WarpCollector,
    HuggingFaceCacheCollector,
    LiteLLMCollector,
    BifrostCollector,
    UnslothCollector,
    ShadowAICollector,
    AntigravityCollector,
    DevinCollector,
    VSCodiumCollector,
    EigentCollector,
    NetworkAICollector,
    CodeScannerCollector,
    DockerAICollector,
    BrowserAICollector,
    # Phase 3 — to be implemented:
    # LangChainCollector,
    # AutoGenCollector,
    # JupyterAICollector,
    # APIKeyScanner,
]


def discover_all(verbose=False):
    """Discover all AI platforms on the system."""
    found = []
    for CollectorClass in ALL_COLLECTORS:
        collector = CollectorClass(output_dir="/tmp/trace_scan")
        try:
            if collector.discover():
                found.append(f"{collector.PLATFORM_NAME} ({collector.PLATFORM_CATEGORY.value})")
                if verbose:
                    for cf in collector.collected_files:
                        found.append(f"  └─ {cf.artifact_type}: {cf.original_path}")
        except Exception as e:
            if verbose:
                found.append(f"{collector.PLATFORM_NAME} — error: {e}")
    return found


def collect_all(output_dir, platforms=None, do_hash=True, chain_of_custody=True, deep=False):
    """Collect artifacts from specified platforms (or all discovered)."""
    from pathlib import Path

    from rich.console import Console

    console = Console()
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    all_collected = []
    all_truncations = []

    for CollectorClass in ALL_COLLECTORS:
        collector = CollectorClass(output_dir=output_dir, deep=deep)
        name = collector.PLATFORM_NAME

        if platforms and name not in [p.strip() for p in platforms]:
            continue

        try:
            if not collector.discover():
                console.print(f"[dim]{name}: not found, skipping[/dim]")
                continue

            console.print(f"[bold blue]{name}:[/bold blue] collecting...")
            collected = collector.collect()
            all_collected.extend(collected)
            console.print(f"  Collected {len(collected)} artifacts")

            # Surface any collection truncations (e.g. per-tool file caps).
            truncations = getattr(collector, "truncations", None)
            if truncations:
                all_truncations.extend(truncations)
                for t in truncations:
                    console.print(
                        f"[yellow]{name}: truncated at {t['max_files']} files "
                        f"({t['skipped']} skipped) in {t['directory']}[/yellow]"
                    )

            parsed = collector.parse()
            console.print(f"  Parsed {len(parsed)} artifacts")

        except Exception as e:
            console.print(f"[red]{name}: error — {e}[/red]")

    # Write chain of custody manifest
    if chain_of_custody and all_collected:
        import json
        manifest_path = Path(output_dir) / "CHAIN_OF_CUSTODY.json"
        manifest = {
            "tool": "TRACE",
            "version": "1.1.0",
            "collected_at": all_collected[0].collected_at if all_collected else "",
            "total_files": len(all_collected),
            "files": [cf.to_dict() for cf in all_collected],
            "truncations": all_truncations,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))
        console.print(f"[green]Chain of custody manifest written to {manifest_path}[/green]")

    console.print(
        f"\n[bold green]Collection complete: {len(all_collected)} artifacts "
        f"from {len({cf.platform for cf in all_collected})} platform(s)[/bold green]"
    )
