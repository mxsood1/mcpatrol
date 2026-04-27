# LinkedIn Post Drafts — pick one and edit to match your voice

Every version pairs with the same screenshot: the MCPatrol HTML report (run `mcpatrol --demo` to generate it).

---

## Version 1 — The Provocative Stat (recommended)

> Your MCP server is silently burning 40% of your agent's context window before it does any actual work.
>
> So I built a free tool that tells you exactly how bad it is.
>
> [SCREENSHOT OF THE REPORT]
>
> Meet **MCPatrol** — Lighthouse for MCP servers. One command, full audit:
>
> 🛡️ Security: TLS, prompt-injection in tool descriptions, error disclosure, unmarked destructive tools
> 💸 Cost: tokens burned by tool schemas vs. industry benchmarks
> 🎯 Quality: Claude scores each tool's clarity 1-10
> ⚡ Reliability: latency p50/p95/max, error rates
>
> ```
> pip install mcpatrol
> mcpatrol https://your-mcp-server.com
> ```
>
> 30 seconds. A self-contained HTML report opens in your browser. Free, open source, MIT.
>
> Background: Perplexity's CTO publicly moved off MCP in March 2026 citing exactly this problem. RSAC 2026 had a dedicated MCP security track. The industry is racing to fix this. I figured indie devs deserve a tool too.
>
> Repo in the comments. Audit your servers. Post your grade.
>
> #MCP #AI #Security #OpenSource #Anthropic

---

## Version 2 — The Story Hook

> A senior engineer told me last week: "Our agents got 30% slower after we added our third MCP server. We can't figure out why."
>
> I bet I knew why. I built a tool to prove it.
>
> [SCREENSHOT]
>
> **MCPatrol** measures exactly how much of your context window your MCP servers are eating before any work happens. Spoiler: way more than you think.
>
> But it doesn't stop there. It also tests for:
> → Prompt-injection vectors in tool descriptions
> → Error responses that leak filepaths or env vars
> → Destructive tools that don't warn agents
> → Latency degradation
>
> Output: a clean A-F report card. The same way Lighthouse grades web pages.
>
> One command:
> `pip install mcpatrol && mcpatrol your-server-url`
>
> Free, open source, runs locally. Built it after reading the early-2026 MCP security research and realizing nobody had shipped the obvious tool.
>
> Link in comments. Drop your grade if you run it 👇
>
> #BuildInPublic #MCP #AISecurity

---

## Version 3 — The Contrarian

> "MCP is dead. Long live the CLI."
>
> Top of Hacker News, March 2026. The author wasn't wrong — MCP servers in production have real problems. Tool descriptions burning 40% of context. Prompt injection. Error disclosure. Auth gaps.
>
> Most takes were "abandon ship." I had a different one.
>
> I shipped MCPatrol — a 30-second audit tool that shows you exactly which of those problems your servers have, and which they don't.
>
> [SCREENSHOT]
>
> One command. Self-contained HTML report. A-F grades on security, cost, clarity, reliability.
>
> ```
> pip install mcpatrol
> mcpatrol https://my-server.com
> ```
>
> The protocol isn't dead. It just needs the same boring infrastructure every other tech stack got — auditors, linters, CI checks. I built the auditor. PRs welcome on the rest.
>
> Repo: github.com/mxsood1/mcpatrol
>
> #MCP #AI #DeveloperTools

---

## Engagement tips

1. **The screenshot is everything.** Before posting, run `mcpatrol --demo` and crop tight on the hero score card + one or two findings. The dark-mode aesthetic looks great as a thumbnail.
2. **Don't put the GitHub link in the post itself** — LinkedIn deprioritizes outbound links. Put `Repo in the comments 👇` and pin your repo link as the first comment.
3. **Reply to every comment in the first hour.** That's when the algorithm decides if your post is worth boosting.
4. **Cross-post to:**
   - r/MachineLearning (use the Project flair)
   - r/LocalLLaMA
   - Hacker News (Show HN: MCPatrol — security audit tool for MCP servers)
   - Indie Hackers
5. **Hashtag set:** keep it tight. `#MCP #AI #OpenSource` is enough. More than 4-5 hashtags hurts reach on LinkedIn.

## Thumbnail / OG image idea

If you want a custom social card, take the report screenshot and add a single line of text on top: **"How healthy is your MCP server?"** Then your name + URL in the corner. That's the entire creative.

## What to put in your repo's "About" section on GitHub

> Lighthouse for MCP servers — a one-command security, cost, and quality scanner. Get an A-F report card in 30 seconds.

That's the elevator pitch. It tells people what it is in 12 words.
