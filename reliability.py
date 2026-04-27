"""
Reliability tests: how does the server perform under repeated calls?

We pick the safest read-only tool we can find and call it ~10 times,
measuring latency. We also check connection stability and error rates.
"""

import asyncio
import statistics
from .security import is_likely_destructive


SAFE_INVOCATION_ARGS = {}  # empty args — most read-only tools accept this


async def run_reliability_tests(client, tools: list) -> dict:
    # Pick the safest tool: prefer ones whose name starts with "list", "get",
    # "ping", "health" — those are usually idempotent and side-effect free.
    target = _pick_safe_tool(tools)
    if not target:
        return {
            "skipped": True,
            "reason": "no clearly read-only tool found to probe",
        }

    n_calls = 10
    latencies = []
    errors = []
    successes = 0

    for i in range(n_calls):
        elapsed_ms, result, error = await client.time_call(
            target["name"], SAFE_INVOCATION_ARGS
        )
        latencies.append(elapsed_ms)
        if error:
            errors.append({"call": i + 1, "error": error[:200]})
        else:
            successes += 1
        # Don't hammer the server — small delay between calls
        await asyncio.sleep(0.1)

    latencies_sorted = sorted(latencies)
    return {
        "skipped": False,
        "tool_used": target["name"],
        "calls": n_calls,
        "successes": successes,
        "errors": errors,
        "min_ms": round(min(latencies), 1),
        "max_ms": round(max(latencies), 1),
        "median_ms": round(statistics.median(latencies), 1),
        "p95_ms": round(latencies_sorted[int(0.95 * (len(latencies_sorted) - 1))], 1),
        "mean_ms": round(statistics.mean(latencies), 1),
        "stdev_ms": round(statistics.stdev(latencies), 1) if len(latencies) > 1 else 0,
    }


def _pick_safe_tool(tools: list):
    # Tier 1: obviously safe verbs
    safe_prefixes = ("ping", "health", "version", "whoami", "status", "info")
    for t in tools:
        name = (t.get("name") or "").lower()
        if any(name.startswith(p) for p in safe_prefixes):
            return t

    # Tier 2: read-only verbs with no required parameters
    for t in tools:
        if is_likely_destructive(t.get("name", "")):
            continue
        schema = t.get("inputSchema") or {}
        required = schema.get("required") or []
        if not required:
            return t

    return None
