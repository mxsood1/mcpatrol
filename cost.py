"""
Cost analysis: how much context budget does this server burn before the agent
does any actual work?

Public reporting (March 2026, multiple sources): mature MCP servers like
GitHub or Notion can consume 8,000+ tokens just from tool descriptions. Stack
two or three servers and you've burned 20-30k tokens before the user types
a single character. This module counts that cost precisely.
"""

import json
import re

# Tiktoken would be more accurate but adds a heavy dependency. We use a
# well-known approximation: ~4 chars per token for English text + JSON.
# For audit-grade signal this is plenty accurate.
CHARS_PER_TOKEN = 4.0


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, round(len(text) / CHARS_PER_TOKEN))


def measure_tool_tokens(tool: dict) -> int:
    """Total tokens that this tool's schema burns in the prompt window."""
    parts = [
        tool.get("name", ""),
        tool.get("description", ""),
        json.dumps(tool.get("inputSchema", {}), separators=(",", ":")),
    ]
    return sum(estimate_tokens(p) for p in parts)


def run_cost_analysis(tools: list, server_info: dict) -> dict:
    """
    Compute token cost per tool, identify bloat, and grade against industry
    benchmarks documented in early-2026 MCP analyses.

    Benchmarks (from public reports):
      - median MCP server: ~4,200 tokens
      - heavy server (GitHub-style):  ~8,000 tokens
      - extreme: 20k+ tokens (multiple servers stacked)
    """
    per_tool = []
    for t in tools:
        tokens = measure_tool_tokens(t)
        per_tool.append({
            "name": t.get("name", "<unnamed>"),
            "tokens": tokens,
            "description_tokens": estimate_tokens(t.get("description", "")),
            "schema_tokens": estimate_tokens(json.dumps(t.get("inputSchema", {}))),
        })
    per_tool.sort(key=lambda x: x["tokens"], reverse=True)
    total = sum(p["tokens"] for p in per_tool)
    avg = total / len(per_tool) if per_tool else 0
    biggest = per_tool[0] if per_tool else None

    # Category vs published benchmarks
    if total < 1500:
        category = "lean"
        note = "Lightweight server. Good agent fit."
    elif total < 4500:
        category = "moderate"
        note = "Around the median for production MCP servers."
    elif total < 8500:
        category = "heavy"
        note = "Heavy. GitHub/Notion-tier overhead — expect agent cost increase."
    elif total < 16000:
        category = "very_heavy"
        note = "Very heavy. Will degrade agent reasoning if combined with other servers."
    else:
        category = "extreme"
        note = "Extreme. This single server can fill a small context window."

    # Detect bloat patterns
    bloat_findings = []
    for p in per_tool:
        if p["tokens"] > 1500:
            bloat_findings.append({
                "tool": p["name"],
                "type": "oversized_tool",
                "tokens": p["tokens"],
                "message": f"`{p['name']}` consumes {p['tokens']} tokens — consider splitting or trimming description.",
            })
        if p["description_tokens"] < 5:
            bloat_findings.append({
                "tool": p["name"],
                "type": "missing_description",
                "tokens": p["tokens"],
                "message": f"`{p['name']}` has no usable description. Agents will misuse this tool.",
            })

    return {
        "total_tokens": total,
        "average_tokens_per_tool": round(avg, 1),
        "biggest_tool": biggest,
        "per_tool": per_tool,
        "category": category,
        "category_note": note,
        "bloat_findings": bloat_findings,
    }
