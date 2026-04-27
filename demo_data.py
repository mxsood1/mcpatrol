"""
Demo findings — lets users preview the report (and lets you screenshot it)
without ever hitting the network or burning API credits.

`mcpatrol --demo` renders this exact data into the HTML report.
"""

DEMO_FINDINGS = {
    "url": "https://demo-mcp-server.example.com/sse",
    "duration_seconds": 4.2,
    "server_info": {
        "protocolVersion": "2025-06-18",
        "serverInfo": {"name": "ExampleCRM", "version": "2.4.1"},
    },
    "tools": [{"name": f"tool_{i}"} for i in range(8)],

    "cost": {
        "total_tokens": 9_840,
        "average_tokens_per_tool": 1230,
        "category": "heavy",
        "category_note": "Heavy. GitHub/Notion-tier overhead — expect agent cost increase.",
        "biggest_tool": {"name": "search_records", "tokens": 2_100, "description_tokens": 800, "schema_tokens": 1_300},
        "per_tool": [
            {"name": "search_records", "tokens": 2_100, "description_tokens": 800, "schema_tokens": 1_300},
            {"name": "create_contact", "tokens": 1_650, "description_tokens": 540, "schema_tokens": 1_110},
            {"name": "update_deal", "tokens": 1_440, "description_tokens": 410, "schema_tokens": 1_030},
            {"name": "list_pipelines", "tokens": 1_120, "description_tokens": 380, "schema_tokens": 740},
            {"name": "get_account", "tokens": 980, "description_tokens": 290, "schema_tokens": 690},
            {"name": "delete_deal", "tokens": 920, "description_tokens": 240, "schema_tokens": 680},
            {"name": "send_email", "tokens": 880, "description_tokens": 320, "schema_tokens": 560},
            {"name": "ping", "tokens": 750, "description_tokens": 60, "schema_tokens": 690},
        ],
        "bloat_findings": [],
    },

    "security": {
        "issues": [
            {
                "id": "tls_present", "severity": "info", "category": "transport",
                "title": "HTTPS transport in use",
                "detail": "Server uses HTTPS. Good.",
                "cwe": None,
            },
            {
                "id": "no_auth_required", "severity": "medium", "category": "access_control",
                "title": "Server accepted connection with no Authorization header",
                "detail": "We listed tools without presenting any credentials. For a production server this is almost always a misconfiguration. Add bearer-token or OAuth before exposing this endpoint to agents.",
                "cwe": "CWE-306",
            },
            {
                "id": "destructive_unmarked", "severity": "medium", "category": "agent_safety",
                "title": "`delete_deal` looks destructive but description doesn't warn",
                "detail": "Tool name implies it modifies state, but the description doesn't flag this. Agents may call it without seeking user confirmation. Add an explicit warning ('This permanently deletes the deal and cannot be undone').",
                "cwe": "CWE-732", "tool": "delete_deal",
            },
            {
                "id": "description_injection", "severity": "high", "category": "prompt_injection",
                "title": "Tool `search_records` description contains injection-like text",
                "detail": "Suspicious phrases in description: 'you must', 'always'. Tool descriptions are processed verbatim by the agent's system prompt. Phrases that look like instructions can be exploited by an attacker who controls returned data.",
                "cwe": "CWE-77", "tool": "search_records",
            },
            {
                "id": "error_disclosure_filepath_leak", "severity": "high", "category": "information_disclosure",
                "title": "Error response leaks `/home/` (filepath leak)",
                "detail": "When sending malformed arguments to `get_account`, the error response contained `/home/`. This kind of leakage helps attackers map your internals.",
                "cwe": "CWE-209", "tool": "get_account",
            },
            {
                "id": "schema_untyped_property", "severity": "low", "category": "schema",
                "title": "`update_deal.metadata` has no type",
                "detail": "Untyped properties accept anything. Specify a JSON Schema type or enum to constrain inputs.",
                "cwe": "CWE-20", "tool": "update_deal",
            },
        ],
        "counts": {"critical": 0, "high": 2, "medium": 2, "low": 1, "info": 1},
    },

    "quality": {
        "skipped": False,
        "average_score": 6.8,
        "scored_count": 8,
        "tool_count": 8,
        "per_tool": [
            {"tool": "search_records", "score": 5, "justification": "Purpose unclear — does it search across all records or just contacts? Schema accepts any query string with no example.", "improvements": ["Specify which entity types are searched", "Show example queries"]},
            {"tool": "create_contact", "score": 8, "justification": "Clear purpose, well-typed schema with required fields. Could note default behaviour for missing optional fields.", "improvements": ["Document idempotency behaviour"]},
            {"tool": "update_deal", "score": 6, "justification": "Description is generic. The 'metadata' property is untyped which makes the contract ambiguous.", "improvements": ["Type the metadata property", "Document partial-update semantics"]},
            {"tool": "list_pipelines", "score": 9, "justification": "Crystal clear, no parameters, returns documented shape.", "improvements": []},
            {"tool": "get_account", "score": 7, "justification": "Clear, but doesn't say what happens for missing accounts.", "improvements": ["Document 404/null behaviour"]},
            {"tool": "delete_deal", "score": 4, "justification": "Description doesn't flag that this is destructive and irreversible. Agents may call this without user consent.", "improvements": ["Add explicit destructive warning", "Note this is irreversible"]},
            {"tool": "send_email", "score": 7, "justification": "Reasonable, but no rate-limit or template documentation.", "improvements": ["Mention rate limits"]},
            {"tool": "ping", "score": 9, "justification": "Trivial and obvious.", "improvements": []},
        ],
    },

    "reliability": {
        "skipped": False,
        "tool_used": "ping",
        "calls": 10,
        "successes": 10,
        "errors": [],
        "min_ms": 87.4,
        "max_ms": 412.6,
        "median_ms": 124.3,
        "p95_ms": 318.0,
        "mean_ms": 156.2,
        "stdev_ms": 89.5,
    },
}
