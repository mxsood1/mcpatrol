"""
HTML report renderer. Self-contained file, opens in any browser.

Aesthetic: dark security-ops dashboard. Monospace headlines, cyan/amber/crimson
status colors, grain texture, no frameworks (just inline CSS). Designed to
look great as a LinkedIn screenshot.
"""

import json
import html as htmllib
from datetime import datetime


def _esc(s) -> str:
    return htmllib.escape(str(s)) if s is not None else ""


def _grade_color(grade: str) -> str:
    """Map a grade letter to a CSS color variable."""
    if not grade or grade == "—":
        return "var(--muted)"
    if grade.startswith("A"):
        return "var(--ok)"
    if grade.startswith("B"):
        return "var(--lime)"
    if grade.startswith("C"):
        return "var(--warn)"
    if grade.startswith("D"):
        return "var(--alarm)"
    return "var(--crit)"


def _severity_badge(sev: str) -> str:
    return f'<span class="badge sev-{sev}">{sev.upper()}</span>'


def render_report(findings: dict) -> str:
    overall = findings.get("overall", {})
    server_info = findings.get("server_info", {})
    server_name = server_info.get("serverInfo", {}).get("name", "MCP server")
    server_version = server_info.get("serverInfo", {}).get("version", "")
    proto_version = server_info.get("protocolVersion", "")

    url = findings.get("url", "")
    scanned_at = findings.get("scanned_at", "")
    duration = findings.get("duration_seconds", 0)

    sec = findings.get("security", {})
    cost = findings.get("cost", {})
    qual = findings.get("quality", {})
    rel = findings.get("reliability", {})

    issues = sec.get("issues", []) if not findings.get("fatal_error") else []
    issues_sorted = sorted(
        issues,
        key=lambda i: ["critical", "high", "medium", "low", "info"].index(i["severity"]),
    )

    cost_table = "\n".join(
        f"<tr><td><code>{_esc(t['name'])}</code></td>"
        f"<td class='num'>{t['tokens']:,}</td>"
        f"<td class='num muted'>{t['description_tokens']:,}</td>"
        f"<td class='num muted'>{t['schema_tokens']:,}</td></tr>"
        for t in (cost.get("per_tool") or [])[:20]
    )

    quality_rows = ""
    if qual and not qual.get("skipped"):
        for q in qual.get("per_tool", [])[:20]:
            score = q.get("score")
            score_html = (
                f"<span class='qscore q{int(score)}'>{score}/10</span>"
                if isinstance(score, (int, float)) else "<span class='muted'>—</span>"
            )
            quality_rows += (
                f"<tr><td><code>{_esc(q.get('tool'))}</code></td>"
                f"<td>{score_html}</td>"
                f"<td>{_esc(q.get('justification', ''))}</td></tr>"
            )

    issues_html = ""
    for i in issues_sorted:
        title = _esc(i.get("title", ""))
        detail = _esc(i.get("detail", ""))
        cwe = i.get("cwe")
        cwe_html = f'<span class="cwe">{_esc(cwe)}</span>' if cwe else ""
        tool_html = (
            f'<span class="tool-tag">on <code>{_esc(i.get("tool"))}</code></span>'
            if i.get("tool") else ""
        )
        issues_html += (
            f'<div class="issue sev-{_esc(i["severity"])}-card">'
            f'  <div class="issue-head">'
            f'    {_severity_badge(i["severity"])}'
            f'    <span class="cat">{_esc(i.get("category", ""))}</span>'
            f'    {cwe_html}'
            f'    {tool_html}'
            f'  </div>'
            f'  <div class="issue-title">{title}</div>'
            f'  <div class="issue-detail">{detail}</div>'
            f"</div>"
        )

    if not issues_html:
        issues_html = '<div class="empty">No issues detected. Either you have a hardened server or the audit was limited — review what we covered.</div>'

    counts = sec.get("counts") or {}
    sev_summary = (
        f"<span class='pill sev-critical'>{counts.get('critical', 0)} critical</span>"
        f"<span class='pill sev-high'>{counts.get('high', 0)} high</span>"
        f"<span class='pill sev-medium'>{counts.get('medium', 0)} medium</span>"
        f"<span class='pill sev-low'>{counts.get('low', 0)} low</span>"
    )

    fatal = findings.get("fatal_error")
    fatal_block = ""
    if fatal:
        fatal_block = (
            '<div class="fatal-banner">'
            f"<strong>Could not connect to server.</strong> {_esc(fatal)}"
            "</div>"
        )

    rel_block = ""
    if rel and not rel.get("skipped"):
        rel_block = f"""
        <div class="card">
          <div class="card-head"><h2>Reliability</h2><span class="grade-mini" style="color:{_grade_color(overall.get('reliability_grade'))}">{_esc(overall.get('reliability_grade'))}</span></div>
          <div class="metrics-row">
            <div class="metric"><div class="metric-label">tool used</div><div class="metric-value mono">{_esc(rel.get('tool_used'))}</div></div>
            <div class="metric"><div class="metric-label">success</div><div class="metric-value">{rel.get('successes', 0)}<span class="metric-suffix">/{rel.get('calls', 0)}</span></div></div>
            <div class="metric"><div class="metric-label">median</div><div class="metric-value">{rel.get('median_ms', 0):.0f}<span class="metric-suffix">ms</span></div></div>
            <div class="metric"><div class="metric-label">p95</div><div class="metric-value">{rel.get('p95_ms', 0):.0f}<span class="metric-suffix">ms</span></div></div>
            <div class="metric"><div class="metric-label">max</div><div class="metric-value">{rel.get('max_ms', 0):.0f}<span class="metric-suffix">ms</span></div></div>
          </div>
        </div>
        """
    elif rel and rel.get("skipped"):
        rel_block = (
            '<div class="card"><div class="card-head"><h2>Reliability</h2></div>'
            f'<div class="muted">Skipped — {_esc(rel.get("reason", "quick mode"))}</div></div>'
        )

    quality_block = ""
    if qual and not qual.get("skipped") and qual.get("average_score") is not None:
        avg = qual["average_score"]
        quality_block = f"""
        <div class="card">
          <div class="card-head">
            <h2>Tool clarity</h2>
            <span class="grade-mini" style="color:{_grade_color(overall.get('quality_grade'))}">{_esc(overall.get('quality_grade'))}</span>
          </div>
          <div class="metrics-row">
            <div class="metric"><div class="metric-label">average score</div><div class="metric-value">{avg:.1f}<span class="metric-suffix">/10</span></div></div>
            <div class="metric"><div class="metric-label">tools scored</div><div class="metric-value">{qual.get('scored_count', 0)}<span class="metric-suffix">/{qual.get('tool_count', 0)}</span></div></div>
          </div>
          <details class="more"><summary>Per-tool scores</summary>
            <table class="data">
              <thead><tr><th>tool</th><th>score</th><th>justification</th></tr></thead>
              <tbody>{quality_rows or '<tr><td colspan="3" class="muted">no data</td></tr>'}</tbody>
            </table>
          </details>
        </div>
        """
    elif qual and qual.get("skipped"):
        reason = _esc(qual.get("reason") or "")
        quality_block = (
            '<div class="card"><div class="card-head"><h2>Tool clarity</h2></div>'
            f'<div class="muted">Skipped. {reason}</div></div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCPatrol report — {_esc(server_name)}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:        #07080a;
    --bg-soft:   #0d0f13;
    --bg-card:   #11141a;
    --border:    #1e2230;
    --border-strong: #2a3040;
    --text:      #e7e9ee;
    --text-soft: #9ba1b0;
    --muted:     #5f6675;
    --ok:        #4ade80;
    --lime:      #a3e635;
    --warn:      #fbbf24;
    --alarm:     #fb923c;
    --crit:      #f43f5e;
    --accent:    #06b6d4;
    --accent-2:  #818cf8;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 14px;
    line-height: 1.55;
    min-height: 100vh;
    background-image:
      radial-gradient(circle at 20% 0%, rgba(6, 182, 212, 0.08), transparent 40%),
      radial-gradient(circle at 80% 100%, rgba(244, 63, 94, 0.06), transparent 40%);
    background-attachment: fixed;
  }}
  /* Subtle grain */
  body::before {{
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: 0.025;
    z-index: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 96px; position: relative; z-index: 1; }}
  .mono {{ font-family: 'JetBrains Mono', ui-monospace, monospace; }}

  /* HEADER */
  header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 28px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }}
  .brand {{ display: flex; align-items: center; gap: 10px; font-weight: 700; letter-spacing: -0.02em; }}
  .brand-mark {{
    width: 28px; height: 28px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    border-radius: 6px;
    position: relative;
  }}
  .brand-mark::after {{
    content: ""; position: absolute; inset: 6px;
    background: var(--bg); border-radius: 2px;
  }}
  .brand-name {{ font-size: 18px; font-family: 'JetBrains Mono', monospace; }}
  .meta {{ font-size: 12px; color: var(--text-soft); text-align: right; font-family: 'JetBrains Mono', monospace; }}
  .meta a {{ color: var(--accent); text-decoration: none; }}

  /* TARGET ROW */
  .target {{
    background: var(--bg-soft);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 22px;
    margin-bottom: 24px;
    display: flex; gap: 18px; align-items: center;
  }}
  .target-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 4px; }}
  .target-url {{ font-family: 'JetBrains Mono', monospace; font-size: 15px; color: var(--text); word-break: break-all; }}

  /* HERO SCORE */
  .hero {{
    display: grid;
    grid-template-columns: 1.4fr 1fr;
    gap: 20px;
    margin-bottom: 28px;
  }}
  .overall {{
    background: linear-gradient(135deg, var(--bg-card), var(--bg-soft));
    border: 1px solid var(--border-strong);
    border-radius: 16px;
    padding: 28px;
    position: relative;
    overflow: hidden;
  }}
  .overall::before {{
    content: ""; position: absolute; top: -50%; right: -20%;
    width: 60%; height: 200%;
    background: radial-gradient(ellipse, rgba(6, 182, 212, 0.12), transparent 70%);
    pointer-events: none;
  }}
  .hero-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.15em; }}
  .hero-grade {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 96px;
    font-weight: 700;
    line-height: 1;
    margin: 4px 0 0;
    letter-spacing: -0.04em;
  }}
  .hero-meta {{ color: var(--text-soft); font-size: 13px; margin-top: 6px; }}

  .grades {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }}
  .grade-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 18px;
  }}
  .grade-label {{ font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.12em; }}
  .grade-value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 36px;
    font-weight: 700;
    line-height: 1;
    margin-top: 4px;
  }}
  .grade-sub {{ color: var(--text-soft); font-size: 12px; margin-top: 4px; }}

  /* CARDS */
  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px;
    margin-bottom: 18px;
  }}
  .card-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }}
  .card-head h2 {{ margin: 0; font-size: 16px; font-weight: 600; letter-spacing: -0.01em; }}
  .grade-mini {{ font-family: 'JetBrains Mono', monospace; font-size: 22px; font-weight: 700; }}

  .metrics-row {{ display: flex; gap: 18px; flex-wrap: wrap; padding: 4px 0 12px; }}
  .metric {{ flex: 1 1 120px; min-width: 110px; }}
  .metric-label {{ font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 4px; }}
  .metric-value {{ font-family: 'JetBrains Mono', monospace; font-size: 22px; font-weight: 600; }}
  .metric-suffix {{ font-size: 12px; color: var(--text-soft); margin-left: 3px; font-weight: 400; }}

  /* TABLES */
  table.data {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
  table.data th, table.data td {{
    text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border);
  }}
  table.data th {{
    font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; font-weight: 500;
  }}
  table.data td.num {{ font-family: 'JetBrains Mono', monospace; text-align: right; }}
  table.data td.muted, .muted {{ color: var(--muted); }}
  table.data code, code {{ font-family: 'JetBrains Mono', monospace; font-size: 12.5px; color: var(--accent); }}

  /* ISSUES */
  .pill {{
    display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 6px;
    font-size: 11px; font-family: 'JetBrains Mono', monospace; margin-right: 6px;
    border: 1px solid var(--border);
  }}
  .pill.sev-critical {{ background: rgba(244, 63, 94, 0.12); color: var(--crit); border-color: rgba(244, 63, 94, 0.4); }}
  .pill.sev-high {{ background: rgba(251, 146, 60, 0.10); color: var(--alarm); border-color: rgba(251, 146, 60, 0.4); }}
  .pill.sev-medium {{ background: rgba(251, 191, 36, 0.10); color: var(--warn); border-color: rgba(251, 191, 36, 0.4); }}
  .pill.sev-low {{ background: rgba(163, 230, 53, 0.08); color: var(--lime); border-color: rgba(163, 230, 53, 0.3); }}

  .issue {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-left: 3px solid var(--border-strong);
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 12px;
  }}
  .issue.sev-critical-card {{ border-left-color: var(--crit); }}
  .issue.sev-high-card     {{ border-left-color: var(--alarm); }}
  .issue.sev-medium-card   {{ border-left-color: var(--warn); }}
  .issue.sev-low-card      {{ border-left-color: var(--lime); }}
  .issue.sev-info-card     {{ border-left-color: var(--accent); }}

  .issue-head {{ display: flex; gap: 8px; align-items: center; margin-bottom: 6px; flex-wrap: wrap; }}
  .badge {{ font-family: 'JetBrains Mono', monospace; font-size: 10px; padding: 3px 8px; border-radius: 4px; font-weight: 700; letter-spacing: 0.05em; }}
  .badge.sev-critical {{ background: var(--crit); color: white; }}
  .badge.sev-high     {{ background: var(--alarm); color: #1a0a00; }}
  .badge.sev-medium   {{ background: var(--warn); color: #1a1000; }}
  .badge.sev-low      {{ background: var(--lime); color: #0a1500; }}
  .badge.sev-info     {{ background: var(--accent); color: #001318; }}
  .cat {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text-soft); }}
  .cwe {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-2); }}
  .tool-tag {{ font-size: 11px; color: var(--text-soft); margin-left: auto; }}
  .tool-tag code {{ color: var(--text); }}
  .issue-title {{ font-weight: 600; font-size: 14.5px; margin: 4px 0 4px; }}
  .issue-detail {{ color: var(--text-soft); font-size: 13px; line-height: 1.55; }}

  .qscore {{ font-family: 'JetBrains Mono', monospace; font-weight: 600; padding: 2px 8px; border-radius: 4px; }}
  .qscore.q9, .qscore.q10 {{ background: rgba(74, 222, 128, 0.12); color: var(--ok); }}
  .qscore.q7, .qscore.q8 {{ background: rgba(163, 230, 53, 0.10); color: var(--lime); }}
  .qscore.q5, .qscore.q6 {{ background: rgba(251, 191, 36, 0.10); color: var(--warn); }}
  .qscore.q3, .qscore.q4 {{ background: rgba(251, 146, 60, 0.10); color: var(--alarm); }}
  .qscore.q1, .qscore.q2 {{ background: rgba(244, 63, 94, 0.12); color: var(--crit); }}

  details.more {{ margin-top: 14px; }}
  details.more summary {{
    cursor: pointer; font-size: 12px; color: var(--text-soft);
    padding: 8px 0; border-top: 1px solid var(--border);
    user-select: none;
  }}
  details.more summary:hover {{ color: var(--text); }}

  .empty {{ padding: 18px; color: var(--text-soft); font-style: italic; text-align: center; }}
  .fatal-banner {{
    background: rgba(244, 63, 94, 0.08); border: 1px solid rgba(244, 63, 94, 0.4);
    color: var(--crit); padding: 16px 18px; border-radius: 10px; margin-bottom: 18px;
  }}

  /* SECTION HEADING */
  .section-h {{
    display: flex; align-items: baseline; justify-content: space-between;
    margin: 32px 0 14px;
  }}
  .section-h h1 {{
    font-size: 13px; text-transform: uppercase; letter-spacing: 0.18em;
    color: var(--text-soft); font-weight: 500; margin: 0;
    font-family: 'JetBrains Mono', monospace;
  }}
  .section-h .pills {{ display: flex; gap: 4px; }}

  footer {{
    margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border);
    color: var(--muted); font-size: 12px; text-align: center;
    font-family: 'JetBrains Mono', monospace;
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}

  @media (max-width: 720px) {{
    .hero {{ grid-template-columns: 1fr; }}
    .hero-grade {{ font-size: 72px; }}
  }}
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="brand">
      <div class="brand-mark"></div>
      <div class="brand-name">mcpatrol</div>
    </div>
    <div class="meta">
      scanned {_esc(scanned_at)}<br>
      duration: {duration}s · v{_esc(findings.get('mcpatrol_version', ''))}
    </div>
  </header>

  {fatal_block}

  <div class="target">
    <div style="flex:1">
      <div class="target-label">target</div>
      <div class="target-url">{_esc(url)}</div>
    </div>
    <div>
      <div class="target-label">server</div>
      <div class="mono">{_esc(server_name)} {_esc(server_version)}</div>
    </div>
    <div>
      <div class="target-label">protocol</div>
      <div class="mono">{_esc(proto_version)}</div>
    </div>
    <div>
      <div class="target-label">tools</div>
      <div class="mono">{len(findings.get('tools', []))}</div>
    </div>
  </div>

  <div class="hero">
    <div class="overall">
      <div class="hero-label">overall grade</div>
      <div class="hero-grade" style="color: {_grade_color(overall.get('grade'))}">{_esc(overall.get('grade', '—'))}</div>
      <div class="hero-meta">composite of security, cost, clarity, reliability</div>
    </div>
    <div class="grades">
      <div class="grade-card">
        <div class="grade-label">Security</div>
        <div class="grade-value" style="color: {_grade_color(overall.get('security_grade'))}">{_esc(overall.get('security_grade', '—'))}</div>
        <div class="grade-sub">{counts.get('high',0) + counts.get('critical',0)} blocking · {counts.get('medium',0)} medium</div>
      </div>
      <div class="grade-card">
        <div class="grade-label">Cost</div>
        <div class="grade-value" style="color: {_grade_color(overall.get('cost_grade'))}">{_esc(overall.get('cost_grade', '—'))}</div>
        <div class="grade-sub">{cost.get('total_tokens', 0):,} tokens / {cost.get('category', '—')}</div>
      </div>
      <div class="grade-card">
        <div class="grade-label">Tool clarity</div>
        <div class="grade-value" style="color: {_grade_color(overall.get('quality_grade'))}">{_esc(overall.get('quality_grade', '—'))}</div>
        <div class="grade-sub">{f'avg {qual.get("average_score", 0):.1f}/10' if qual.get('average_score') else 'not scored'}</div>
      </div>
      <div class="grade-card">
        <div class="grade-label">Reliability</div>
        <div class="grade-value" style="color: {_grade_color(overall.get('reliability_grade'))}">{_esc(overall.get('reliability_grade', '—'))}</div>
        <div class="grade-sub">{f'p95 {rel.get("p95_ms", 0):.0f}ms' if not rel.get('skipped') else 'skipped'}</div>
      </div>
    </div>
  </div>

  <div class="section-h">
    <h1>Security findings</h1>
    <div class="pills">{sev_summary}</div>
  </div>
  {issues_html}

  <div class="section-h"><h1>Cost analysis</h1></div>
  <div class="card">
    <div class="card-head"><h2>Token budget — before any work happens</h2><span class="grade-mini" style="color:{_grade_color(overall.get('cost_grade'))}">{_esc(overall.get('cost_grade', '—'))}</span></div>
    <div class="metrics-row">
      <div class="metric"><div class="metric-label">total</div><div class="metric-value">{cost.get('total_tokens', 0):,}<span class="metric-suffix">tokens</span></div></div>
      <div class="metric"><div class="metric-label">tools</div><div class="metric-value">{len(findings.get('tools', []))}</div></div>
      <div class="metric"><div class="metric-label">avg / tool</div><div class="metric-value">{cost.get('average_tokens_per_tool', 0):.0f}</div></div>
      <div class="metric"><div class="metric-label">category</div><div class="metric-value mono" style="font-size:16px">{_esc(cost.get('category', '—'))}</div></div>
    </div>
    <div class="muted" style="margin-top:6px;font-size:13px">{_esc(cost.get('category_note', ''))}</div>
    <details class="more"><summary>Per-tool token cost</summary>
      <table class="data">
        <thead><tr><th>tool</th><th>total</th><th>desc</th><th>schema</th></tr></thead>
        <tbody>{cost_table or '<tr><td colspan="4" class="muted">no tools</td></tr>'}</tbody>
      </table>
    </details>
  </div>

  {quality_block}

  {rel_block}

  <footer>
    generated by <a href="https://github.com/mxsood1/mcpatrol">mcpatrol</a> ·
    open source · run your own audit: <code>pip install mcpatrol</code>
  </footer>

</div>
</body>
</html>
"""
