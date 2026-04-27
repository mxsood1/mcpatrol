"""
Quality scoring: would an agent know how to correctly use these tools?

We send each tool's name + description + schema to Claude and ask it to score
clarity on a 1-10 scale, with a short justification. This is the only probe
that costs API credits — and it's optional (--no-quality).

Cost: ~$0.001 per tool (Sonnet, ~500 input + 100 output tokens). Even a
40-tool server costs about 4 cents to score.
"""

import os
import json
import asyncio
from typing import Optional


SYSTEM_PROMPT = """You are MCPatrol's quality auditor. For each MCP tool description provided, rate how well an AI agent could use the tool correctly based ONLY on the name, description, and schema.

Output strict JSON:
{"score": 1-10, "justification": "1-2 sentences", "improvements": ["concrete suggestion", "another suggestion"]}

Scoring rubric:
- 9-10: crystal clear purpose, complete schema, examples or constraints stated
- 7-8: clear purpose, well-typed schema, minor gaps
- 5-6: understandable but missing edge cases, return shape, or parameter constraints
- 3-4: ambiguous purpose, vague description, weak schema
- 1-2: agent will misuse this tool

Output ONLY the JSON object."""


def _format_tool_for_review(tool: dict) -> str:
    schema = tool.get("inputSchema") or {}
    return (
        f"Name: {tool.get('name', '<unnamed>')}\n"
        f"Description: {tool.get('description') or '(none)'}\n"
        f"Schema: {json.dumps(schema, indent=2)[:1500]}"
    )


async def score_one_tool(client, tool: dict) -> dict:
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _format_tool_for_review(tool)}],
    )
    text = msg.content[0].text.strip()
    # Strip code fences if Claude added any
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {"score": None, "justification": "Failed to parse model response", "improvements": []}
    data["tool"] = tool.get("name")
    return data


async def run_quality_scoring(tools: list) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "skipped": True,
            "reason": "ANTHROPIC_API_KEY not set — set it or run with --no-quality",
        }

    try:
        from anthropic import Anthropic
    except ImportError:
        return {"skipped": True, "reason": "anthropic SDK not installed"}

    client = Anthropic(api_key=api_key)

    # Run scoring concurrently — anthropic SDK is sync, so we use threads
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, _sync_score, client, t)
        for t in tools
    ]
    scores = await asyncio.gather(*tasks, return_exceptions=True)

    valid_scores = []
    per_tool = []
    for s in scores:
        if isinstance(s, Exception):
            per_tool.append({"tool": None, "score": None, "error": str(s)})
            continue
        per_tool.append(s)
        if isinstance(s.get("score"), (int, float)):
            valid_scores.append(s["score"])

    avg = sum(valid_scores) / len(valid_scores) if valid_scores else None
    return {
        "skipped": False,
        "average_score": avg,
        "per_tool": per_tool,
        "tool_count": len(tools),
        "scored_count": len(valid_scores),
    }


def _sync_score(client, tool: dict) -> dict:
    """Synchronous helper for run_in_executor."""
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _format_tool_for_review(tool)}],
    )
    text = msg.content[0].text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {"score": None, "justification": "Failed to parse model response", "improvements": []}
    data["tool"] = tool.get("name")
    return data
