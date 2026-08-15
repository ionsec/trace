"""
ConversationExport — export parsed AI conversation history to a shareable
evidence package.

Writes a folder containing:

  * ``<name>_timeline.csv`` — the parsed turns (respects the current filter),
    with the full evidence columns an analyst needs;
  * ``manifest.json`` — every source file path, row count, size, mtime, and
    SHA-256 hash so the evidence can be independently re-verified;
  * ``README.txt`` — a short description of the bundle.

The manifest hashes the source artifacts (not the CSV), so a downstream
analyst can re-hash the originals against the recorded values to confirm the
package is intact and unmodified.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ionsec_trace.analyzer.conversation_parser import ConversationParser

# Columns in the exported timeline CSV (kept stable for downstream tooling).
CSV_COLUMNS = [
    "timestamp",
    "platform",
    "role",
    "content",
    "model",
    "session_id",
    "source_file",
    "tool_command",
    "tool_input",
    "tool_description",
    "workspace",
    "also_in_tools",
]


def _sha256(path: str) -> str:
    """Hash a file with SHA-256 in a streaming, memory-safe way."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_entry(path: str, row_count: int) -> dict:
    stat = os.stat(path)
    return {
        "path": path,
        "row_count": row_count,
        "size_bytes": stat.st_size,
        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "sha256": _sha256(path),
    }


def export_conversation_package(
    parser: ConversationParser,
    output_dir: str,
    name: str = "ai_history",
) -> dict:
    """Export parsed conversation turns to a CSV + manifest evidence package.

    Args:
        parser: A populated ConversationParser.
        output_dir: Directory to write the package into.
        name: Base name for the output files.

    Returns:
        Dict mapping file kind to the absolute output path.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    turns = parser.turns

    # --- Timeline CSV ---
    csv_path = out / f"{name}_timeline.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for turn in turns:
            writer.writerow({
                "timestamp": turn.timestamp,
                "platform": turn.platform,
                "role": turn.role,
                "content": turn.content,
                "model": turn.model,
                "session_id": turn.session_id,
                "source_file": turn.source_file,
                "tool_command": turn.tool_command,
                "tool_input": turn.tool_input,
                "tool_description": turn.tool_description,
                "workspace": turn.workspace,
                "also_in_tools": ", ".join(turn.also_in_tools),
            })

    # --- Manifest (hash the source artifacts, not the CSV) ---
    source_counts: dict[str, int] = {}
    for turn in turns:
        source_counts[turn.source_file] = source_counts.get(turn.source_file, 0) + 1

    manifest = {
        "tool": "TRACE",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_turns": len(turns),
        "total_sessions": len(parser.sessions),
        "sources": [
            _manifest_entry(path, count)
            for path, count in sorted(source_counts.items())
            if os.path.exists(path)
        ],
    }
    manifest_path = out / f"{name}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # --- README ---
    readme_path = out / "README.txt"
    readme_path.write_text(
        "TRACE AI conversation history export\n"
        "===================================\n"
        f"Exported {len(turns)} turns across {len(parser.sessions)} sessions.\n"
        f"Timeline: {csv_path.name}\n"
        f"Manifest: {manifest_path.name}\n"
        "\n"
        "The manifest records the SHA-256 of each source artifact so the\n"
        "originals can be independently re-verified. The CSV contains the\n"
        "parsed conversation evidence (prompts, responses, tool calls).\n",
        encoding="utf-8",
    )

    return {
        "csv": str(csv_path),
        "manifest": str(manifest_path),
        "readme": str(readme_path),
    }
