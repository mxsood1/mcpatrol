"""
MCPatrol — security & quality scanner for MCP servers.

Usage:
    mcpatrol https://my-mcp-server.com/sse
    mcpatrol https://my-mcp-server.com --output report.html --quick
    mcpatrol --help

Designed for HTTP/SSE MCP servers (the kind running in production).
Stdio (local) servers planned for v2.
"""

import os
import sys
import json
import time
import argparse
import asyncio
import webbrowser
from datetime import datetime
from pathlib import Path

from .client import MCPClient, MCPClientError
from .probes.security import run_security_probes
from .probes.cost import run_cost_analysis
from .probes.quality import run_quality_scoring
from .probes.reliability import run_reliability_tests
from .report import render_report
from .scoring import grade_overall

BANNER = r"""
   __  _____ ___  _____ __           __
  /  |/  / ___/ _ \/ _  / /________ _/ /
 / /|_/ / /__/ ___/ __  / __/ __/ _ `/ /
/_/  /_/\___/_/  /_/ /_/\__/_/  \_,_/_/

       MCP server health scanner
"""


def parse_args():
    p = argparse.ArgumentParser(
        prog="mcpatrol",
        description="Security & quality scanner for MCP servers",
    )
    p.add_argument("url", nargs="?",
                   help="URL of the MCP server (http://, https://, or sse:// endpoint)")
    p.add_argument("--output", "-o", default="mcpatrol-report.html",
                   help="Output HTML report path")
    p.add_argument("--json", default=None,
                   help="Also write raw findings as JSON to this path")
    p.add_argument("--quick", action="store_true",
                   help="Skip slow tests (reliability latency loop)")
    p.add_argument("--no-quality", action="store_true",
                   help="Skip Claude-based quality scoring (free + offline)")
    p.add_argument("--no-open", action="store_true",
                   help="Don't auto-open the report in a browser")
    p.add_argument("--auth-header", default=None,
                   help="Optional Authorization header value (e.g. 'Bearer xyz')")
    p.add_argument("--demo", action="store_true",
                   help="Generate a demo report against a mock server (no network)")
    p.add_argument("--version", action="store_true", help="Print version and exit")
    return p.parse_args()


async def run_audit(args):
    print(BANNER)
    print(f"  scanning: {args.url}")
    print(f"  mode:     {'quick' if args.quick else 'full'}"
          f"{' (no quality)' if args.no_quality else ''}")
    print()

    started = time.time()
    findings = {
        "url": args.url,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "mcpatrol_version": __version__,
    }

    # --- Connect ---
    print("  [1/5] connecting...")
    headers = {}
    if args.auth_header:
        headers["Authorization"] = args.auth_header

    try:
        client = MCPClient(args.url, headers=headers)
        await client.connect()
        server_info = await client.get_server_info()
        tools = await client.list_tools()
        findings["server_info"] = server_info
        findings["tools"] = tools
        print(f"        ✓ connected — {len(tools)} tools advertised")
    except MCPClientError as e:
        print(f"        ✗ failed: {e}")
        findings["fatal_error"] = str(e)
        await write_outputs(args, findings)
        return 1

    # --- Probes ---
    print("  [2/5] cost analysis...")
    findings["cost"] = run_cost_analysis(tools, server_info)
    print(f"        tokens before any work: {findings['cost']['total_tokens']}")

    print("  [3/5] security probes...")
    findings["security"] = await run_security_probes(client, tools)
    n_issues = len(findings["security"].get("issues", []))
    print(f"        {n_issues} issue{'s' if n_issues != 1 else ''} found")

    if args.no_quality:
        print("  [4/5] quality scoring (skipped)")
        findings["quality"] = {"skipped": True}
    else:
        print("  [4/5] quality scoring (Claude-based)...")
        findings["quality"] = await run_quality_scoring(tools)
        avg = findings["quality"].get("average_score")
        if avg is not None:
            print(f"        average tool clarity: {avg:.1f}/10")

    if args.quick:
        print("  [5/5] reliability tests (skipped — quick mode)")
        findings["reliability"] = {"skipped": True}
    else:
        print("  [5/5] reliability tests...")
        findings["reliability"] = await run_reliability_tests(client, tools)
        p95 = findings["reliability"].get("p95_ms")
        if p95 is not None:
            print(f"        p95 latency: {p95:.0f}ms")

    await client.close()

    # --- Score ---
    findings["overall"] = grade_overall(findings)
    findings["duration_seconds"] = round(time.time() - started, 1)

    print()
    print(f"  overall grade: {findings['overall']['grade']}  "
          f"(security={findings['overall']['security_grade']}, "
          f"cost={findings['overall']['cost_grade']}, "
          f"quality={findings['overall']['quality_grade']}, "
          f"reliability={findings['overall']['reliability_grade']})")

    await write_outputs(args, findings)
    return 0


async def write_outputs(args, findings):
    html = render_report(findings)
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"\n  → report: {args.output}")

    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
        print(f"  → json:   {args.json}")

    if not args.no_open:
        try:
            webbrowser.open(f"file://{Path(args.output).resolve()}")
        except Exception:
            pass


def run_demo(args):
    """Render a report against fully synthetic findings — no network, no API calls.
    Used for previewing the UI / generating a demo screenshot."""
    from .demo_data import DEMO_FINDINGS
    print(BANNER)
    print("  generating demo report (no network)...")
    findings = DEMO_FINDINGS.copy()
    findings["scanned_at"] = datetime.utcnow().isoformat() + "Z"
    findings["mcpatrol_version"] = __version__
    findings["overall"] = grade_overall(findings)
    html = render_report(findings)
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"  → report: {args.output}")
    if not args.no_open:
        try:
            webbrowser.open(f"file://{Path(args.output).resolve()}")
        except Exception:
            pass


__version__ = "0.1.0"


def main():
    args = parse_args()
    if args.version:
        print(f"mcpatrol {__version__}")
        return 0
    if args.demo:
        run_demo(args)
        return 0
    if not args.url:
        print("error: provide a URL, or use --demo to preview the report")
        return 2
    return asyncio.run(run_audit(args))


if __name__ == "__main__":
    sys.exit(main())
