"""
Security probes for MCP servers.

Each probe maps to a real, publicly documented MCP attack class (RSAC 2026
talks, the early-2026 security research, the MCP project's own roadmap).

We are deliberately CONSERVATIVE:
  - Probes are read-only or use clearly synthetic inputs.
  - We never call destructive-sounding tools (delete_*, write_*, etc.) during
    the audit.
  - We label each finding with severity + CWE-style category for clarity.

Severity scale: critical | high | medium | low | info
"""

import json
import re
from urllib.parse import urlparse


# Tools we refuse to call during the audit, even if they appear safe by name.
DESTRUCTIVE_PATTERNS = [
    r"^(delete|remove|drop|destroy|purge|wipe|truncate|reset)_?",
    r"^(send|post|publish|tweet|email|notify|alert)_?",
    r"^(create|insert|add|new|write|update|edit|modify|patch|put)_?",
    r"^(execute|run|exec|spawn|launch|start|stop|kill|restart)_?",
    r"^(transfer|pay|charge|refund|withdraw|deposit)_?",
]

# Patterns suggesting the tool is likely safe to invoke
READ_ONLY_PATTERNS = [
    r"^(get|read|fetch|find|search|list|describe|inspect|view|show|query|count|check|status|info|whoami|version|ping|health)_?",
]


def is_likely_destructive(tool_name: str) -> bool:
    """Conservative classifier: when in doubt, treat as destructive."""
    name = tool_name.lower()
    if any(re.match(p, name) for p in READ_ONLY_PATTERNS):
        return False
    if any(re.match(p, name) for p in DESTRUCTIVE_PATTERNS):
        return True
    # Unknown verb — be safe
    return True


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------

async def probe_tls(url: str) -> list:
    """Verify the server is using HTTPS, not plaintext HTTP."""
    issues = []
    parsed = urlparse(url)
    if parsed.scheme == "http":
        issues.append({
            "id": "tls_missing",
            "severity": "high",
            "category": "transport",
            "title": "Plaintext HTTP transport",
            "detail": (
                "The MCP server is reachable over plain HTTP. Tool calls, "
                "arguments, and any returned data are sent unencrypted. Move "
                "to HTTPS with a valid certificate."
            ),
            "cwe": "CWE-319",
        })
    elif parsed.scheme == "https":
        issues.append({
            "id": "tls_present",
            "severity": "info",
            "category": "transport",
            "title": "HTTPS transport in use",
            "detail": "Server uses HTTPS. Good.",
            "cwe": None,
        })
    return issues


async def probe_unauthenticated_access(client) -> list:
    """Did we successfully connect with no auth? That's not always a bug,
    but for a production server it usually is."""
    issues = []
    has_auth = bool(client.headers.get("Authorization"))
    if not has_auth:
        issues.append({
            "id": "no_auth_required",
            "severity": "medium",
            "category": "access_control",
            "title": "Server accepted connection with no Authorization header",
            "detail": (
                "We were able to list tools and prepare calls without "
                "presenting any credentials. For a production server this "
                "is almost always a misconfiguration. If this is intentional "
                "(public read-only demo), ignore this finding."
            ),
            "cwe": "CWE-306",
        })
    return issues


async def probe_tool_injection_surface(tools: list) -> list:
    """
    Look for tool descriptions that contain content that *looks* like
    instructions to the agent — a classic prompt-injection vector.
    Aiden Bai and others publicized this attack class in late 2025/early 2026.
    """
    issues = []
    suspicious_phrases = [
        "ignore previous", "ignore the above", "system:", "assistant:",
        "you must", "you should", "always", "never reveal",
        "<system>", "</system>", "[INST]", "[/INST]",
    ]
    for t in tools:
        desc = (t.get("description") or "").lower()
        hits = [p for p in suspicious_phrases if p in desc]
        if hits:
            issues.append({
                "id": "description_injection",
                "severity": "high",
                "category": "prompt_injection",
                "title": f"Tool `{t.get('name')}` description contains injection-like text",
                "detail": (
                    f"Suspicious phrases in description: {', '.join(hits)}. "
                    "Tool descriptions are processed verbatim by the agent's "
                    "system prompt. Phrases that look like instructions can "
                    "manipulate agent behaviour."
                ),
                "cwe": "CWE-77",
                "tool": t.get("name"),
            })
    return issues


async def probe_schema_quality(tools: list) -> list:
    """
    A tool whose schema doesn't constrain inputs is a weak spot — the agent
    can be coerced (or just confused) into passing arbitrary content.
    """
    issues = []
    for t in tools:
        name = t.get("name", "<unnamed>")
        schema = t.get("inputSchema") or {}
        props = schema.get("properties", {})
        required = set(schema.get("required", []))

        if not props and not required:
            issues.append({
                "id": "schema_empty",
                "severity": "low",
                "category": "schema",
                "title": f"Tool `{name}` has no input schema",
                "detail": (
                    "Without a schema, the agent has no contract for what to "
                    "pass. Add typed properties and mark required fields."
                ),
                "cwe": "CWE-20",
                "tool": name,
            })
            continue

        # Untyped properties
        for prop_name, prop_def in props.items():
            if not prop_def.get("type") and "enum" not in prop_def:
                issues.append({
                    "id": "schema_untyped_property",
                    "severity": "low",
                    "category": "schema",
                    "title": f"`{name}.{prop_name}` has no type",
                    "detail": (
                        "Untyped properties accept anything. Specify a JSON "
                        "Schema type or enum to constrain inputs."
                    ),
                    "cwe": "CWE-20",
                    "tool": name,
                })
    return issues


async def probe_destructive_tool_safety(tools: list) -> list:
    """Destructive tools should clearly warn that they're destructive in the
    description. If they don't, an agent might call them assuming they're
    read-only."""
    issues = []
    warn_words = re.compile(r"\b(destructive|deletes|removes|irreversible|warning|caution|cannot be undone)\b", re.I)
    for t in tools:
        name = t.get("name", "")
        if is_likely_destructive(name):
            desc = t.get("description") or ""
            if not warn_words.search(desc):
                issues.append({
                    "id": "destructive_unmarked",
                    "severity": "medium",
                    "category": "agent_safety",
                    "title": f"`{name}` looks destructive but description doesn't warn",
                    "detail": (
                        "Tool name suggests it modifies state, but the "
                        "description doesn't flag this. Agents may call it "
                        "without seeking user confirmation. Add an explicit "
                        "warning in the description."
                    ),
                    "cwe": "CWE-732",
                    "tool": name,
                })
    return issues


async def probe_error_disclosure(client, tools: list) -> list:
    """
    Pick one read-only-looking tool and call it with deliberately bad args.
    See if the error response leaks tracebacks, file paths, env vars, or
    stack frames — common information disclosure issues.
    """
    issues = []
    target = None
    for t in tools:
        if not is_likely_destructive(t.get("name", "")):
            target = t
            break
    if not target:
        return issues

    # Bad arguments — invalid types, sometimes triggers exception leak
    bad_args = {"__mcpatrol_probe__": {"nested": [None, True, "🛡️" * 50]}}
    elapsed_ms, result, error = await client.time_call(target["name"], bad_args)

    leak_indicators = [
        ("Traceback", "stack_trace_leak"),
        ("File \"/", "filepath_leak"),
        (".py\", line", "stack_trace_leak"),
        ("ENV[", "env_leak"),
        ("os.environ", "env_leak"),
        ("/home/", "filepath_leak"),
        ("/var/", "filepath_leak"),
        ("C:\\Users\\", "filepath_leak"),
        ("DATABASE_URL", "env_leak"),
        ("API_KEY", "env_leak"),
        ("password", "credential_leak"),
        ("secret", "credential_leak"),
    ]

    haystack = (error or "") + json.dumps(result or {})
    for indicator, kind in leak_indicators:
        if indicator in haystack:
            issues.append({
                "id": f"error_disclosure_{kind}",
                "severity": "high",
                "category": "information_disclosure",
                "title": f"Error response leaks `{indicator}` ({kind.replace('_', ' ')})",
                "detail": (
                    f"When sending malformed arguments to `{target['name']}`, "
                    f"the error response contained `{indicator}`. This kind "
                    "of leakage helps attackers map your internals."
                ),
                "cwe": "CWE-209",
                "tool": target["name"],
            })
            break  # one finding per probe
    return issues


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def run_security_probes(client, tools: list) -> dict:
    issues = []

    issues += await probe_tls(client.url)
    issues += await probe_unauthenticated_access(client)
    issues += await probe_tool_injection_surface(tools)
    issues += await probe_schema_quality(tools)
    issues += await probe_destructive_tool_safety(tools)

    try:
        issues += await probe_error_disclosure(client, tools)
    except Exception as e:
        # Don't let one probe failure kill the audit
        issues.append({
            "id": "probe_error",
            "severity": "info",
            "category": "audit",
            "title": "Error-disclosure probe failed to run",
            "detail": f"Probe raised: {e}",
            "cwe": None,
        })

    # Tally for the report card
    counts = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for i in issues:
        counts[i["severity"]] = counts.get(i["severity"], 0) + 1

    return {
        "issues": issues,
        "counts": counts,
    }
