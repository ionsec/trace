#!/usr/bin/env python3
"""Build an interactive docs site from the markdown files in docs/.

Renders each docs/*.md into site/docs/<name>.html using the TRACE brand
aesthetic, upgraded into a proper interactive documentation experience:

  - Sticky left sidebar with the full doc list + per-page sub-navigation
  - Client-side full-text search over all pages
  - Scroll-spy (active section highlighting as you scroll)
  - One-click copy on code blocks
  - Prev / next page navigation
  - Responsive mobile drawer
  - TRACE crimson-on-dark branding

Run from the repo root:

    python site/build_docs.py
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

from markdown_it import MarkdownIt
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.util import ClassNotFound

ROOT = Path(__file__).resolve().parent.parent
DOCS_SRC = ROOT / "docs"
DOCS_OUT = ROOT / "site" / "docs"

# Ordered doc index for sidebar + prev/next nav
DOC_INDEX = [
    ("INSTALLATION", "Installation", "install"),
    ("GUIDE", "User Guide", "guide"),
    ("WALKTHROUGH", "Walkthrough", "walkthrough"),
    ("ai-agent-forensic-artifacts", "Forensic Artifacts", "artifacts"),
    ("velociraptor-artifact-research", "Velociraptor Research", "velo"),
]

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} · TRACE Docs</title>
  <meta name="description" content="{description}">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='4' fill='%23000'/><text x='4' y='24' font-size='22' fill='%23e63946'>⌗</text></svg>">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');

    :root {{
      --red: #e63946; --red-bright: #ff3b4a;
      --bg: #050507; --surface: #0a0a0f; --surface2: #1a1a2e;
      --border: #2a2a3e; --muted: #8a8a9e;
      --blue: #7c9cff; --green: #4ade80;
      --text: #c4c4d4; --bright: #fff;
      --sidebar-w: 264px;
    }}

    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    html {{ background: var(--bg); color: var(--text); scroll-behavior: smooth; scroll-padding-top: 72px; }}
    body {{ font-family: 'Montserrat', system-ui, sans-serif; background: var(--bg); line-height: 1.7; }}

    ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: #222; border-radius: 4px; }}
    ::-webkit-scrollbar-thumb:hover {{ background: var(--red); }}

    /* ---------- Top nav ---------- */
    .topnav {{
      position: sticky; top: 0; z-index: 100;
      backdrop-filter: blur(20px) saturate(180%);
      -webkit-backdrop-filter: blur(20px) saturate(180%);
      background: rgba(5,5,7,0.85);
      border-bottom: 1px solid var(--border);
    }}
    .topnav-inner {{
      max-width: 1280px; margin: 0 auto; padding: 0 24px;
      display: flex; align-items: center; justify-content: space-between; height: 60px;
      gap: 16px;
    }}
    .topnav .brand {{ font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #fff; font-size: 16px; text-decoration: none; }}
    .topnav .brand span {{ color: var(--red); }}
    .topnav .links {{ display: flex; align-items: center; gap: 20px; }}
    .topnav a.link {{ color: var(--muted); text-decoration: none; font-size: 14px; transition: color 0.2s; }}
    .topnav a.link:hover {{ color: var(--red); }}

    /* ---------- Search ---------- */
    .searchbox {{ position: relative; }}
    .searchbox input {{
      background: var(--surface2); border: 1px solid var(--border); border-radius: 6px;
      color: #fff; padding: 8px 14px 8px 34px; width: 220px; font-family: 'Montserrat', sans-serif;
      font-size: 13px; outline: none; transition: border-color 0.2s, width 0.2s;
    }}
    .searchbox input:focus {{ border-color: var(--red); width: 280px; }}
    .searchbox input::placeholder {{ color: var(--muted); }}
    .searchbox .icon {{
      position: absolute; left: 10px; top: 50%; transform: translateY(-50%);
      width: 16px; height: 16px; color: var(--muted); pointer-events: none;
    }}
    .search-results {{
      position: absolute; right: 0; top: 42px; width: 360px; max-height: 380px; overflow-y: auto;
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      box-shadow: 0 12px 40px rgba(0,0,0,0.6); display: none; z-index: 200;
    }}
    .search-results.show {{ display: block; }}
    .search-results a {{
      display: block; padding: 10px 14px; text-decoration: none; color: var(--text);
      border-bottom: 1px solid rgba(42,42,62,0.5);
    }}
    .search-results a:hover {{ background: var(--surface2); }}
    .search-results .sr-title {{ color: #fff; font-size: 13px; font-weight: 600; }}
    .search-results .sr-page {{ color: var(--muted); font-size: 11px; font-family: 'JetBrains Mono', monospace; }}
    .search-results .sr-excerpt {{ color: var(--muted); font-size: 12px; margin-top: 3px; }}
    .search-results .sr-none {{ padding: 14px; color: var(--muted); font-size: 13px; }}

    /* ---------- Layout ---------- */
    .layout {{ display: flex; max-width: 1280px; margin: 0 auto; }}
    .sidebar {{
      width: var(--sidebar-w); flex-shrink: 0; position: sticky; top: 60px; height: calc(100vh - 60px);
      overflow-y: auto; border-right: 1px solid var(--border); padding: 24px 16px;
    }}
    .sidebar-section {{ margin-bottom: 24px; }}
    .sidebar-section > .label {{
      font-family: 'JetBrains Mono', monospace; font-size: 11px; text-transform: uppercase;
      letter-spacing: 0.08em; color: var(--muted); margin-bottom: 10px;
    }}
    .sidebar a.docs-item {{
      display: block; padding: 7px 10px; border-radius: 6px; color: var(--text);
      text-decoration: none; font-size: 14px; font-weight: 500; transition: background 0.15s, color 0.15s;
    }}
    .sidebar a.docs-item:hover {{ background: var(--surface2); }}
    .sidebar a.docs-item.active {{ background: rgba(230,57,70,0.12); color: var(--red-bright); }}
    .sidebar a.doc-anchor {{
      display: block; padding: 4px 10px 4px 22px; border-radius: 4px; color: var(--muted);
      text-decoration: none; font-size: 13px; transition: color 0.15s, background 0.15s;
    }}
    .sidebar a.doc-anchor:hover {{ color: var(--text); background: var(--surface2); }}
    .sidebar a.doc-anchor.active {{ color: var(--red-bright); }}

    .main {{ flex: 1; min-width: 0; padding: 40px 48px 80px; }}

    /* ---------- Breadcrumb + title ---------- */
    .breadcrumb {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--muted); margin-bottom: 12px; }}
    .breadcrumb a {{ color: var(--muted); text-decoration: none; }}
    .breadcrumb a:hover {{ color: var(--red); }}
    .doc-title {{ font-size: 34px; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 6px; line-height: 1.15; color: #fff; }}
    .doc-meta {{ color: var(--muted); font-size: 13px; margin-bottom: 28px; font-family: 'JetBrains Mono', monospace; }}

    /* ---------- Content ---------- */
    .content h2, .content h3, .content h4 {{
      color: #fff; font-weight: 700; letter-spacing: -0.01em; margin: 44px 0 14px; line-height: 1.3;
      scroll-margin-top: 80px;
    }}
    .content h2 {{ font-size: 24px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }}
    .content h3 {{ font-size: 19px; }}
    .content h4 {{ font-size: 16px; }}

    .content p, .content ul, .content ol, .content blockquote {{ margin: 0 0 16px; }}
    .content ul, .content ol {{ padding-left: 24px; }}
    .content li {{ margin-bottom: 6px; }}
    .content li::marker {{ color: var(--red); }}

    .content a {{ color: var(--red-bright); text-decoration: none; border-bottom: 1px solid rgba(230,57,70,0.3); }}
    .content a:hover {{ border-bottom-color: var(--red-bright); }}

    .content strong {{ color: #fff; }}

    .content blockquote {{
      border-left: 3px solid var(--red); background: var(--surface);
      padding: 14px 20px; border-radius: 0 8px 8px 0; color: var(--muted);
    }}
    .content blockquote p {{ margin: 0; }}

    .content code {{
      font-family: 'JetBrains Mono', monospace; font-size: 0.85em;
      background: var(--surface2); color: var(--red-bright); padding: 2px 6px; border-radius: 4px;
    }}

    /* Code block with copy button */
    .codeblock {{ position: relative; background: #0d0d0d; border: 1px solid var(--border); border-radius: 10px; margin: 0 0 20px; overflow: hidden; }}
    .codeblock .copy-btn {{
      position: absolute; top: 10px; right: 10px; background: var(--surface2); border: 1px solid var(--border);
      color: var(--muted); border-radius: 5px; padding: 4px 10px; font-size: 11px; cursor: pointer;
      font-family: 'JetBrains Mono', monospace; transition: color 0.2s, border-color 0.2s; opacity: 0;
    }}
    .codeblock:hover .copy-btn {{ opacity: 1; }}
    .codeblock .copy-btn:hover {{ color: var(--red-bright); border-color: var(--red); }}
    .codeblock pre {{ padding: 18px 20px; overflow-x: auto; line-height: 1.6; margin: 0; }}
    .codeblock pre code {{ background: none; color: #d4d4d4; padding: 0; font-size: 13px; }}

    .content table {{ width: 100%; border-collapse: collapse; margin: 0 0 24px; font-size: 14px; display: block; overflow-x: auto; }}
    .content th, .content td {{ border: 1px solid var(--border); padding: 10px 14px; text-align: left; vertical-align: top; }}
    .content th {{
      background: var(--surface2); color: #fff; font-weight: 600;
      font-family: 'JetBrains Mono', monospace; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em;
    }}
    .content tr:nth-child(even) td {{ background: rgba(26,26,46,0.3); }}
    .content hr {{ border: none; border-top: 1px solid var(--border); margin: 32px 0; }}
    .content img {{ max-width: 100%; border-radius: 8px; border: 1px solid var(--border); }}

    /* Inline "rf" research figures already in GUIDE/WALKTHROUGH are plain HTML tables/blocks */
    .content figure {{ margin: 24px 0; }}

    /* ---------- Prev / next ---------- */
    .pager {{
      display: flex; justify-content: space-between; gap: 16px; margin-top: 56px;
      border-top: 1px solid var(--border); padding-top: 24px;
    }}
    .pager a {{
      text-decoration: none; color: var(--text); padding: 12px 18px; border: 1px solid var(--border);
      border-radius: 8px; max-width: 46%; transition: border-color 0.2s, color 0.2s; flex: 1;
    }}
    .pager a:hover {{ border-color: var(--red); color: var(--red-bright); }}
    .pager a.next {{ text-align: right; }}
    .pager .pager-label {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
    .pager .pager-title {{ font-size: 14px; font-weight: 600; color: #fff; margin-top: 2px; }}
    .pager a:hover .pager-title {{ color: var(--red-bright); }}

    /* ---------- Footer ---------- */
    .footer {{ border-top: 1px solid var(--border); padding: 24px; text-align: center; color: #555; font-size: 12px; font-family: 'JetBrains Mono', monospace; }}
    .footer a {{ color: var(--muted); text-decoration: none; }}
    .footer a:hover {{ color: var(--red); }}

    /* ---------- Mobile ---------- */
    .menu-btn {{ display: none; background: none; border: 1px solid var(--border); color: #fff; border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 18px; }}
    @media (max-width: 900px) {{
      .menu-btn {{ display: block; }}
      .topnav .links a.link {{ display: none; }}
      .searchbox input {{ width: 150px; }}
      .searchbox input:focus {{ width: 180px; }}
      .sidebar {{ position: fixed; left: 0; top: 60px; height: calc(100vh - 60px); transform: translateX(-100%); transition: transform 0.25s ease; z-index: 150; background: var(--bg); }}
      .sidebar.open {{ transform: translateX(0); }}
      .main {{ padding: 28px 20px 60px; }}
      .search-results {{ width: min(360px, 90vw); }}
    }}
    @media (max-width: 640px) {{
      .doc-title {{ font-size: 26px; }}
      .content pre {{ font-size: 12px; }}
    }}
  </style>
</head>
<body>
  <nav class="topnav">
    <div class="topnav-inner">
      <div style="display:flex;align-items:center;gap:12px;">
        <button class="menu-btn" id="menu-btn" aria-label="Toggle navigation">☰</button>
        <a class="brand" href="../index.html">TRACE</a>
      </div>
      <div style="display:flex;align-items:center;gap:16px;">
        <div class="links">
          <a class="link" href="../index.html">Home</a>
          <a class="link" href="https://github.com/ionsec/trace" target="_blank" rel="noopener">GitHub</a>
        </div>
        <div class="searchbox">
          <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          <input type="text" id="search-input" placeholder="Search docs…" autocomplete="off">
          <div class="search-results" id="search-results"></div>
        </div>
      </div>
    </div>
  </nav>

  <div class="layout">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-section">
        <div class="label">Documentation</div>
        {sidebar_docs}
      </div>
      <div class="sidebar-section" id="toc-section">
        <div class="label">On this page</div>
        <div id="page-toc">{toc}</div>
      </div>
    </aside>

    <main class="main">
      <div class="breadcrumb"><a href="../index.html">Home</a> / <a href="GUIDE.html">Docs</a> / {title}</div>
      <h1 class="doc-title">{title}</h1>
      <div class="doc-meta">{meta}</div>
      <div class="content">
{body}
      </div>
      <nav class="pager">
        {prev_link}
        {next_link}
      </nav>
    </main>
  </div>

  <footer class="footer">
    TRACE · AGPL-3.0-or-later · <a href="https://github.com/ionsec/trace">GitHub</a>
  </footer>

  <script>
    // Search index (built at generation time)
    const SEARCH_INDEX = {search_index};
    const CURRENT_PAGE = "{current}";

    // Small HTML-escaping helper (no html global in the browser)
    function esc(s) {{
      const div = document.createElement('div');
      div.textContent = s == null ? '' : String(s);
      return div.innerHTML;
    }}

    // ---------- Search ----------
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');
    searchInput.addEventListener('input', () => {{
      const q = searchInput.value.trim().toLowerCase();
      if (q.length < 2) {{ searchResults.classList.remove('show'); searchResults.innerHTML = ''; return; }}
      const hits = [];
      for (const page of SEARCH_INDEX) {{
        for (const item of page.items) {{
          if (item.text.toLowerCase().includes(q)) {{
            const idx = item.text.toLowerCase().indexOf(q);
            const start = Math.max(0, idx - 40);
            const excerpt = (start > 0 ? '…' : '') + item.text.slice(start, start + 90) + '…';
            hits.push({{ page: page.title, file: page.file, href: item.href, title: item.title, excerpt }});
          }}
        }}
      }}
      searchResults.innerHTML = '';
      if (hits.length === 0) {{
        searchResults.innerHTML = '<div class="sr-none">No results for “' + esc(q) + '”</div>';
      }} else {{
        hits.slice(0, 12).forEach(h => {{
          const a = document.createElement('a');
          a.href = h.href;
          a.innerHTML = '<div class="sr-title">' + esc(h.title) + '</div>' +
            '<div class="sr-page">' + esc(h.page) + '</div>' +
            '<div class="sr-excerpt">' + esc(h.excerpt) + '</div>';
          searchResults.appendChild(a);
        });
      }}
      searchResults.classList.add('show');
    }});
    document.addEventListener('click', (e) => {{
      if (!searchResults.contains(e.target) && e.target !== searchInput) {{
        searchResults.classList.remove('show');
      }}
    }});

    // ---------- Scroll-spy ----------
    const tocLinks = document.querySelectorAll('#page-toc a.doc-anchor');
    const headings = [];
    tocLinks.forEach(a => {{
      const target = document.querySelector(a.getAttribute('href'));
      if (target) headings.push({{ el: target, link: a }});
    }});
    const spy = new IntersectionObserver((entries) => {{
      entries.forEach(entry => {{
        if (entry.isIntersecting) {{
          tocLinks.forEach(l => l.classList.remove('active'));
          const match = headings.find(h => h.el === entry.target);
          if (match) match.link.classList.add('active');
        }}
      }});
    }}, {{ rootMargin: '-80px 0px -70% 0px' }});
    headings.forEach(h => spy.observe(h.el));

    // ---------- Code copy buttons ----------
    document.querySelectorAll('.codeblock').forEach((block) => {{
      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.textContent = 'Copy';
      btn.addEventListener('click', () => {{
        const code = block.querySelector('code').innerText;
        navigator.clipboard.writeText(code).then(() => {{
          btn.textContent = 'Copied!';
          setTimeout(() => {{ btn.textContent = 'Copy'; }}, 1500);
        }});
      }});
      block.appendChild(btn);
    }});

    // ---------- Mobile menu ----------
    document.getElementById('menu-btn').addEventListener('click', () => {{
      document.getElementById('sidebar').classList.toggle('open');
    }});
    document.getElementById('sidebar').addEventListener('click', (e) => {{
      if (e.target.closest('a')) document.getElementById('sidebar').classList.remove('open');
    }});
  </script>
</body>
</html>
"""


def render_code(code: str, lang: str | None) -> str:
    """Highlight a fenced code block with Pygments, wrapped in a copyable block."""
    try:
        lexer = get_lexer_by_name(lang) if lang else guess_lexer(code)
    except ClassNotFound:
        lexer = None
    if lexer is None:
        return f'<div class="codeblock"><pre><code>{html.escape(code)}</code></pre></div>'
    formatter = HtmlFormatter(nowrap=True)
    highlighted = highlight(code, lexer, formatter)
    return f'<div class="codeblock"><pre><code>{highlighted}</code></pre></div>'


def slugify(text: str) -> str:
    """Create an anchor slug matching the page-toc links."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def build_toc(html_body: str) -> tuple[str, list]:
    """Extract h2/h3 headings into nested TOC links with anchor hrefs.

    Returns (toc_html, toc_anchors) where toc_anchors is a list of
    {href, text} for scroll-spy wiring.
    """
    anchors = []
    lines = ["<ul>"]
    for m in re.finditer(r"<h([23])[^>]*>(.*?)</h\1>", html_body, re.S):
        level = int(m.group(1))
        text = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        slug = slugify(text)
        anchors.append({"href": f"#{slug}", "text": text, "level": level})
        lines.append(
            f'<li><a class="doc-anchor" href="#{slug}" data-level="{level}">{html.escape(text)}</a></li>'
        )
    lines.append("</ul>")
    return "\n".join(lines), anchors


def rewrite_doc_links(html: str) -> str:
    """Point cross-document links at their rendered pages.

    The markdown sources link to each other as `GUIDE.md`, which only resolves
    inside the repository. On the site those must become `GUIDE.html`, or the
    link 404s.
    """
    known = {name for name, _, _ in DOC_INDEX}

    def replace(match: re.Match) -> str:
        target, anchor = match.group(1), match.group(2) or ""
        if target not in known:
            return match.group(0)
        return f'href="{target}.html{anchor}"'

    return re.sub(r'href="([A-Za-z0-9_-]+)\.md(#[^"]*)?"', replace, html)


def main() -> None:
    # PAGE_TEMPLATE uses {{ }} for CSS/JS literal braces (format-style escaping).
    # Since we inject via .replace() (not .format()), collapse them to single
    # braces so the generated JS/CSS is valid.
    template = PAGE_TEMPLATE.replace("{{", "{").replace("}}", "}")

    md = MarkdownIt("commonmark", {"html": True, "linkify": True, "typographer": True})
    md.enable("table")

    default_fence = md.renderer.rules["fence"]

    def fence(tokens, idx, options, env):
        token = tokens[idx]
        code = token.content.rstrip("\n")
        lang = token.info.strip().split()[0] if token.info else None
        return render_code(code, lang)

    md.renderer.rules["fence"] = fence

    DOCS_OUT.mkdir(parents=True, exist_ok=True)

    # First pass: render all pages to build search index + collect anchors
    rendered: dict[str, dict] = {}

    for file, label, _ in DOC_INDEX:
        src = DOCS_SRC / f"{file}.md"
        if not src.exists():
            continue
        text = src.read_text(encoding="utf-8")
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) == 3:
                text = parts[2]

        html_body = md.render(text)
        html_body = rewrite_doc_links(html_body)

        # Extract title from first h1, strip it from body
        title_match = re.search(r"<h1[^>]*>(.*?)</h1>", html_body, re.S)
        title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip() if title_match else label
        body = re.sub(r"<h1[^>]*>.*?</h1>", "", html_body, count=1, flags=re.S).strip()

        # TOC anchors
        toc_html, anchors = build_toc(body)

        # Search index items: headings + first paragraph after each heading
        index_items = []
        for m in re.finditer(r"<h([23])[^>]*>(.*?)</h\1>(.*?)(?=<h[23]|$)", body, re.S):
            heading = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            slug = slugify(heading)
            snippet = re.sub(r"<[^>]+>", " ", m.group(3)).strip()
            snippet = re.sub(r"\s+", " ", snippet)[:120]
            index_items.append({
                "title": heading,
                "text": (heading + " " + snippet).strip(),
                "href": f"{file}.html#{slug}",
            })

        rendered[file] = {
            "title": title, "label": label, "body": body, "toc": toc_html,
            "anchors": anchors, "index_items": index_items,
            "meta": f"{file} · {len(text.split())} words",
        }

    files_rendered = [file for file, _, _ in DOC_INDEX if file in rendered]

    # Build search index (all pages)
    search_index = [
        {
            "title": rendered[f]["label"],
            "file": f,
            "items": rendered[f]["index_items"],
        }
        for f in files_rendered
    ]

    # Second pass: write pages with prev/next + search index
    files = [file for file, _, _ in DOC_INDEX if file in rendered]
    for i, file in enumerate(files):
        r = rendered[file]
        prev_file = files[i - 1] if i > 0 else None
        next_file = files[i + 1] if i < len(files) - 1 else None

        prev_link = ""
        if prev_file:
            prev_link = (
                f'<a class="prev" href="{prev_file}.html">'
                f'<div class="pager-label">← Previous</div>'
                f'<div class="pager-title">{rendered[prev_file]["label"]}</div></a>'
            )
        else:
            prev_link = '<a style="visibility:hidden"></a>'

        next_link = ""
        if next_file:
            next_link = (
                f'<a class="next" href="{next_file}.html">'
                f'<div class="pager-label">Next →</div>'
                f'<div class="pager-title">{rendered[next_file]["label"]}</div></a>'
            )
        else:
            next_link = '<a style="visibility:hidden"></a>'

        # Sidebar with current-page highlight
        sidebar_docs = "\n".join(
            f'<a class="docs-item{(" active" if f == file else "")}" href="{f}.html">{rendered[f]["label"]}</a>'
            for f in files
        )

        page = template
        for key, value in {
            "{title}": r["title"],
            "{description}": f"{r['title']} — TRACE documentation",
            "{meta}": r["meta"],
            "{body}": r["body"],
            "{toc}": r["toc"],
            "{sidebar_docs}": sidebar_docs,
            "{prev_link}": prev_link,
            "{next_link}": next_link,
            "{search_index}": json.dumps(search_index),
            "{current}": file,
        }.items():
            page = page.replace(key, value)

        out = DOCS_OUT / f"{file}.html"
        out.write_text(page, encoding="utf-8")
        print(f"  wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
