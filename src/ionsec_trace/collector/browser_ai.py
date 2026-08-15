"""
Browser-based AI forensic artifact collector for TRACE.

Collects evidence of browser-based AI assistant usage — the conversation
history, cached responses, and site data left behind by web AI assistants:

  - Brave Leo (built-in assistant): AIChat/ dir in the Brave profile
  - Browser history (SQLite) entries for AI sites: chatgpt.com, claude.ai,
    perplexity.ai, gemini.google.com, copilot.microsoft.com, leo.brave.com,
    etc.
  - IndexedDB / Local Storage per-AI-site data (conversation stores)
  - Browser extension data for AI assistants

These artifacts answer "what did the user ask an AI assistant in their
browser" — a rich source of shadow-AI and data-exposure evidence that
endpoint collectors miss.
"""

import sqlite3
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class BrowserAICollector(BaseCollector):
    PLATFORM_NAME = "browser_ai"
    PLATFORM_CATEGORY = PlatformCategory.CLOUD
    PROCESS_NAMES = ["brave", "chrome", "msedge", "firefox", "arc", "opera"]
    SERVICE_PORTS = []

    # AI assistant domains we look for in browser history / site data.
    AI_DOMAINS = [
        "chatgpt.com", "openai.com", "claude.ai", "anthropic.com",
        "perplexity.ai", "gemini.google.com", "bard.google.com",
        "aistudio.google.com", "copilot.microsoft.com", "bing.com/chat",
        "leo.brave.com", "brave.com", "poe.com", "character.ai",
        "huggingface.co/chat", "chat.mistral.ai", "deepseek.com",
        "grok.com", "x.ai", "you.com", "phind.com", "cognition.ai",
        "devin.ai", "replit.com", "cursor.sh", "windsurf.com",
    ]

    # Browser config directories per platform.
    LINUX_PATHS = ["~/.config/google-chrome", "~/.config/microsoft-edge", "~/.config/BraveSoftware"]
    MACOS_PATHS = [
        "~/Library/Application Support/Google/Chrome",
        "~/Library/Application Support/Microsoft Edge",
        "~/Library/Application Support/BraveSoftware",
        "~/Library/Application Support/Arc",
        "~/Library/Application Support/Google/Chrome Canary",
    ]
    WINDOWS_PATHS = [
        "%LOCALAPPDATA%\\Google\\Chrome",
        "%LOCALAPPDATA%\\Microsoft\\Edge",
        "%LOCALAPPDATA%\\BraveSoftware",
    ]

    # ── Discover ──────────────────────────────────────────────

    def discover(self) -> bool:
        """Detect browser AI usage: browser present with AI history or Leo."""
        for browser_root in self._browser_roots():
            if not browser_root.exists():
                continue
            # Brave Leo built-in assistant
            if (browser_root / "Default" / "AIChat").exists():
                return True
            if self._profile_history(browser_root):
                return True
        return False

    # ── Helpers ───────────────────────────────────────────────

    def _browser_roots(self) -> list[Path]:
        """Return browser config roots across all users."""
        roots = []
        for home in self.get_user_home_dirs():
            for rel in (self.MACOS_PATHS if self.detect_os() == "macos"
                        else self.LINUX_PATHS if self.detect_os() == "linux"
                        else self.WINDOWS_PATHS):
                p = Path(rel).expanduser()
                if not p.exists():
                    p = home / rel.lstrip("~/").lstrip("%LOCALAPPDATA%\\").lstrip("\\")
                roots.append(p)
        return roots

    def _profile_dirs(self, browser_root: Path) -> list[Path]:
        """Return profile dirs (Default, Profile N) for a browser root."""
        profiles = []
        for name in ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"]:
            p = browser_root / name
            if p.is_dir():
                profiles.append(p)
        return profiles

    def _profile_history(self, browser_root: Path) -> Path | None:
        """Return the most recent History SQLite file for a browser root."""
        best = None
        best_mtime = 0
        for profile in self._profile_dirs(browser_root):
            h = profile / "History"
            if h.is_file() and h.stat().st_mtime > best_mtime:
                best = h
                best_mtime = h.stat().st_mtime
        return best

    def _ai_urls_from_history(self, history_path: Path) -> list[dict]:
        """Query the browser History SQLite for AI-site visits (read-only)."""
        urls = []
        try:
            conn = sqlite3.connect(f"file:{history_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Read-only, no modifications
            cur.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                WHERE url LIKE '%chatgpt.com%' OR url LIKE '%openai.com%'
                   OR url LIKE '%claude.ai%' OR url LIKE '%perplexity.ai%'
                   OR url LIKE '%gemini.google.com%' OR url LIKE '%bard.google.com%'
                   OR url LIKE '%copilot.microsoft.com%' OR url LIKE '%leo.brave.com%'
                   OR url LIKE '%grok.com%' OR url LIKE '%poe.com%'
                   OR url LIKE '%deepseek.com%' OR url LIKE '%mistral.ai%'
                ORDER BY last_visit_time DESC
                LIMIT 500
            """)
            for row in cur.fetchall():
                urls.append({
                    "url": row["url"],
                    "title": row["title"] or "",
                    "visit_count": row["visit_count"],
                    "last_visit_time": self._webkit_to_iso(row["last_visit_time"]),
                })
            conn.close()
        except (sqlite3.Error, OSError):
            pass
        return urls

    @staticmethod
    def _webkit_to_iso(webkit_time: int) -> str:
        """Convert a Chromium WebKit timestamp (microseconds since 1601) to ISO UTC."""
        if not webkit_time:
            return ""
        from datetime import datetime, timedelta, timezone
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        try:
            return (epoch + timedelta(microseconds=webkit_time)).isoformat()
        except Exception:
            return ""

    def _ai_site_data(self, browser_root: Path) -> list[Path]:
        """Collect IndexedDB / AI-chat site data for AI domains.

        Returns the specific AI-domain IndexedDB stores (conversation data) —
        not generic Local Storage, which is high-volume noise.
        """
        found = []
        for profile in self._profile_dirs(browser_root):
            # IndexedDB: per-origin dirs named https_<ai-domain>_0.indexeddb.*
            idb = profile / "IndexedDB"
            if idb.is_dir():
                for d in idb.iterdir():
                    if d.is_dir() and any(dom.replace(".", "_") in d.name.lower() for dom in self.AI_DOMAINS):
                        found.append(d)
        return found

    # ── Collect ───────────────────────────────────────────────

    def collect(self) -> list[CollectedFile]:
        """Collect browser AI artifacts: history + per-site data."""
        collected = []

        for browser_root in self._browser_roots():
            if not browser_root.exists():
                continue

            # Brave Leo built-in assistant (conversation data)
            for profile in self._profile_dirs(browser_root):
                leo = profile / "AIChat"
                if leo.is_dir():
                    for f in leo.rglob("*"):
                        if f.is_file() and f.stat().st_size < 2 * 1024 * 1024:
                            cf = self._mk_cf(f, "brave_leo_data")
                            collected.append(cf)
                            self.collected_files.append(cf)

            # Per-AI-site IndexedDB / Local Storage
            for sd in self._ai_site_data(browser_root):
                for f in sd.rglob("*"):
                    if f.is_file() and f.stat().st_size < 5 * 1024 * 1024:
                        cf = self._mk_cf(f, "ai_site_data")
                        collected.append(cf)
                        self.collected_files.append(cf)

        return collected

    def _mk_cf(self, path: Path, artifact_type: str) -> CollectedFile:
        return CollectedFile(
            original_path=str(path),
            source_os=self.detect_os(),
            platform=self.PLATFORM_NAME,
            artifact_type=artifact_type,
            size_bytes=path.stat().st_size,
            sha256=self.calculate_hash(str(path)),
            collected_at=self.timestamp(),
        )

    # ── Parse ─────────────────────────────────────────────────

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected browser AI artifacts into structured findings."""
        artifacts = []

        # Analyze browser history for AI-site visits (even if not collected)
        for browser_root in self._browser_roots():
            if not browser_root.exists():
                continue
            history = self._profile_history(browser_root)
            if not history:
                continue
            ai_urls = self._ai_urls_from_history(history)
            if not ai_urls:
                continue

            # Group by AI provider
            by_provider: dict[str, list[dict]] = {}
            for u in ai_urls:
                provider = self._provider_for_url(u["url"])
                by_provider.setdefault(provider, []).append(u)

            for provider, urls in by_provider.items():
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="browser_ai_history",
                    severity=Severity.MEDIUM,
                    data={
                        "provider": provider,
                        "visit_count": sum(u["visit_count"] for u in urls),
                        "url_count": len(urls),
                        "sample_urls": [u["url"] for u in urls[:20]],
                    },
                    source_file=str(history),
                    mitre_atlas=["AML.T0048"],  # AI Tool Integration
                ))

        # Brave Leo data
        for cf in self.collected_files:
            if cf.artifact_type == "brave_leo_data":
                content = self.safe_read_file(cf.original_path, max_bytes=1024 * 1024)
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="brave_leo_data",
                    severity=Severity.MEDIUM,
                    data={
                        "path": cf.original_path,
                        "preview": (content or "")[:2000],
                    },
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0048"],
                ))
            elif cf.artifact_type == "ai_site_data":
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="ai_site_data",
                    severity=Severity.LOW,
                    data={
                        "path": cf.original_path,
                        "size_bytes": cf.size_bytes,
                    },
                    source_file=cf.original_path,
                ))

        return artifacts

    @staticmethod
    def _provider_for_url(url: str) -> str:
        """Map a URL to the AI provider name."""
        url_l = url.lower()
        providers = [
            ("chatgpt.com", "OpenAI ChatGPT"), ("chat.openai.com", "OpenAI ChatGPT"),
            ("chatgpt", "OpenAI ChatGPT"), ("openai.com", "OpenAI"),
            ("claude.ai", "Anthropic Claude"), ("anthropic", "Anthropic"),
            ("perplexity", "Perplexity"), ("gemini.google", "Google Gemini"),
            ("bard.google", "Google Bard"), ("aistudio", "Google AI Studio"),
            ("copilot", "Microsoft Copilot"), ("leo.brave", "Brave Leo"),
            ("grok", "xAI Grok"), ("poe.com", "Poe"),
            ("deepseek", "DeepSeek"), ("mistral", "Mistral"),
            ("character.ai", "Character AI"), ("huggingface", "HuggingFace Chat"),
            ("you.com", "You.com"), ("phind", "Phind"),
            ("devin.ai", "Devin"), ("cognition", "Cognition/Devin"),
            ("replit", "Replit"), ("cursor.sh", "Cursor"),
            ("windsurf", "Windsurf"),
        ]
        for key, name in providers:
            if key in url_l:
                return name
        return "Unknown AI provider"
