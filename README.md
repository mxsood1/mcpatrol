# 🛡️ MCPatrol

> **Lighthouse for MCP servers.** Point it at any HTTP MCP endpoint and get back a security, cost, and quality report card in 30 seconds.

[![PyPI](https://img.shields.io/pypi/v/mcpatrol.svg)](https://pypi.org/project/mcpatrol/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Why this exists

MCP servers are exploding in production — every major AI lab now supports the protocol, and they're being deployed faster than they're being audited. Public reporting (RSAC 2026, Perplexity CTO at Ask 2026) flagged real problems:

- **Tool descriptions burning 40-50% of context windows** before agents do any work
- **Prompt-injection through tool descriptions** ("rugpull" attacks)
- **Auth handled inconsistently** — many servers ship with bearer-token gaps
- **Error responses leaking** stack traces, file paths, and env vars

MCPatrol is a free, open-source CLI that tests for all of these in one command. No infrastructure, no signup. Audit a server, get an HTML report card, fix what matters.

## Install

```bash
pip install mcpatrol
```

## Use

```bash
# Audit a remote MCP server (HTTP or SSE)
mcpatrol https://my-mcp-server.com/sse

# With auth header
mcpatrol https://my-mcp-server.com/sse --auth-header "Bearer xyz123"

# Skip the slow tests (no latency loop, no Claude scoring)
mcpatrol https://my-mcp-server.com/sse --quick --no-quality

# Generate a demo report (no network, no API calls)
mcpatrol --demo
```

The output is a self-contained `mcpatrol-report.html` that opens in your browser. Share it, screenshot it, commit it to your repo.

## What it checks

| Category | Examples |
|----------|----------|
| **Security** | TLS / plain HTTP, missing auth, prompt-injection in descriptions, error disclosure (stack traces, file paths, env vars), unmarked destructive tools, schema completeness |
| **Cost** | Total tokens burned by tool descriptions before any work happens. Compared against published industry benchmarks (median ~4,200 tokens; heavy ~8,500). |
| **Tool clarity** *(optional, uses Claude API)* | Asks Claude Sonnet to score each tool's description on a 1-10 rubric and suggest improvements |
| **Reliability** | Latency (median, p95, max), success rate over 10 calls, error patterns |

Every finding includes a CWE-style category, severity, and concrete remediation.

## Honest scope

MCPatrol is a **starting point**, not a comprehensive pentest. It catches the common, public attack classes documented in the early-2026 MCP security research. It will not catch sophisticated zero-days, server-side bugs requiring authentication you don't have, or anything that requires source-code access.

Treat it like Lighthouse for the web — a fast first pass that flags the obvious problems, not a SOC 2 audit.

## Quality scoring needs your API key

The optional `--with-quality` mode uses Claude to score tool descriptions. It uses **your** Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
mcpatrol https://my-mcp-server.com/sse
```

Cost: ~$0.001 per tool. Auditing a 40-tool server runs about 4 cents. Skip with `--no-quality` if you'd rather pay zero.

MCPatrol never sees, transmits, or stores your API key — it goes from your env directly to Anthropic.

## What's coming

- [ ] stdio (local) MCP servers via `--launch "command args"`
- [ ] More security probes: SSE state-confusion, race conditions, auth flow tests
- [ ] CI mode: exit non-zero if grade drops below threshold
- [ ] JSON Schema spec for the findings format (so you can build dashboards on it)
- [ ] Markdown summary output (for PR comments)

## Contributing

This is a brand-new project. Open issues, suggest probes, or PR new ones — every probe should map to a real, public attack class with a citation in the docstring.

## License

MIT. Use it, fork it, ship it.

---

Built with care, in public.
