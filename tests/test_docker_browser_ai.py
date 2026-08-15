"""Tests for the Docker AI and browser-based AI collectors."""

import sqlite3

from ionsec_trace.collector.browser_ai import BrowserAICollector
from ionsec_trace.collector.docker_ai import DockerAICollector

# ===========================================================================
# Docker AI collector
# ===========================================================================

class TestDockerAICollector:
    def test_discover_false_when_absent(self, tmp_path):
        c = DockerAICollector(output_dir=str(tmp_path))
        # Point home away from any real docker dirs
        c.get_user_home_dirs = lambda: [tmp_path]
        assert c.discover() is False

    def test_gordon_dir_detection(self, tmp_path):
        gordon = tmp_path / ".docker" / "gordon"
        gordon.mkdir(parents=True)
        (gordon / "config.json").write_text('{"version":"2"}')
        c = DockerAICollector(output_dir=str(tmp_path))
        c.get_user_home_dirs = lambda: [tmp_path]
        assert c.discover() is True

    def test_collect_gordon_artifacts(self, tmp_path):
        gordon = tmp_path / ".docker" / "gordon"
        threads = gordon / "threads" / "abc123"
        threads.mkdir(parents=True)
        (gordon / "config.json").write_text('{"version":"2"}')
        (gordon / "history").write_text("hello\n")
        (threads / "convo.json").write_text('{"messages":[]}')
        c = DockerAICollector(output_dir=str(tmp_path))
        c.get_user_home_dirs = lambda: [tmp_path]
        files = c.collect()
        types = {f.artifact_type for f in files}
        assert "gordon_config" in types
        assert "gordon_history" in types
        assert "gordon_conversation" in types

    def test_parse_returns_list(self, tmp_path):
        c = DockerAICollector(output_dir=str(tmp_path))
        assert isinstance(c.parse(), list)

    def test_ai_image_patterns(self):
        c = DockerAICollector(output_dir="/tmp")
        assert any(p == "ollama" for p in c.AI_IMAGE_PATTERNS)
        assert any(p == "localai" for p in c.AI_IMAGE_PATTERNS)
        assert any(p == "vllm" for p in c.AI_IMAGE_PATTERNS)


# ===========================================================================
# Browser AI collector
# ===========================================================================

class TestBrowserAICollector:
    def test_provider_for_url(self):
        assert BrowserAICollector._provider_for_url("https://claude.ai/chat") == "Anthropic Claude"
        assert BrowserAICollector._provider_for_url("https://www.perplexity.ai/") == "Perplexity"
        assert BrowserAICollector._provider_for_url("https://chatgpt.com/") == "OpenAI ChatGPT"
        assert BrowserAICollector._provider_for_url("https://copilot.microsoft.com/") == "Microsoft Copilot"
        assert BrowserAICollector._provider_for_url("https://leo.brave.com/") == "Brave Leo"
        assert BrowserAICollector._provider_for_url("https://unknown.com/") == "Unknown AI provider"

    def test_webkit_to_iso(self):
        iso = BrowserAICollector._webkit_to_iso(0)
        assert iso == ""  # zero -> empty
        # 13300000000000000 microseconds since 1601 is a valid 2021-ish date
        iso2 = BrowserAICollector._webkit_to_iso(13300000000000000)
        assert iso2.startswith("202")

    def test_collect_no_browsers(self, tmp_path):
        c = BrowserAICollector(output_dir=str(tmp_path))
        c.get_user_home_dirs = lambda: [tmp_path]
        c._browser_roots = list
        assert c.collect() == []

    def test_ai_domains_catalog(self):
        c = BrowserAICollector(output_dir="/tmp")
        assert "chatgpt.com" in c.AI_DOMAINS
        assert "claude.ai" in c.AI_DOMAINS
        assert "perplexity.ai" in c.AI_DOMAINS
        assert "copilot.microsoft.com" in c.AI_DOMAINS
        assert "leo.brave.com" in c.AI_DOMAINS
        assert "gemini.google.com" in c.AI_DOMAINS

    def test_ai_urls_from_history(self, tmp_path):
        # Build a real SQLite History DB with an AI URL
        history = tmp_path / "History"
        conn = sqlite3.connect(str(history))
        conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
        conn.execute("INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?,?,?,?)",
                     ("https://chatgpt.com/c/abc", "ChatGPT session", 3, 13300000000000000))
        conn.commit()
        conn.close()

        c = BrowserAICollector(output_dir=str(tmp_path))
        urls = c._ai_urls_from_history(history)
        assert len(urls) >= 1
        assert urls[0]["url"].startswith("https://chatgpt.com")
