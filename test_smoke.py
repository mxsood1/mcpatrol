"""Basic smoke tests for MCPatrol — these run in CI."""

from mcpatrol.scoring import grade_overall, _score_to_grade
from mcpatrol.probes.cost import estimate_tokens, measure_tool_tokens, run_cost_analysis
from mcpatrol.probes.security import is_likely_destructive
from mcpatrol.demo_data import DEMO_FINDINGS
from mcpatrol.report import render_report


def test_score_to_grade():
    assert _score_to_grade(100) == "A+"
    assert _score_to_grade(72) == "B-"
    assert _score_to_grade(0) == "F"


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("hello world") > 0


def test_measure_tool_tokens():
    tool = {
        "name": "test",
        "description": "a test tool",
        "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
    }
    assert measure_tool_tokens(tool) > 0


def test_destructive_classifier():
    assert is_likely_destructive("delete_user")
    assert is_likely_destructive("send_email")
    assert is_likely_destructive("drop_table")
    assert not is_likely_destructive("get_user")
    assert not is_likely_destructive("list_files")
    assert not is_likely_destructive("ping")
    assert not is_likely_destructive("health_check")


def test_cost_analysis_runs():
    tools = [
        {"name": "ping", "description": "Ping the server.", "inputSchema": {}},
        {"name": "search", "description": "Search records by query.", "inputSchema": {"type": "object"}},
    ]
    result = run_cost_analysis(tools, {})
    assert "total_tokens" in result
    assert result["category"] in ("lean", "moderate", "heavy", "very_heavy", "extreme")


def test_grade_overall_runs():
    overall = grade_overall(DEMO_FINDINGS)
    assert "grade" in overall
    assert overall["grade"] in (
        "A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F", "—"
    )


def test_report_renders():
    findings = dict(DEMO_FINDINGS)
    findings["overall"] = grade_overall(findings)
    findings["mcpatrol_version"] = "0.1.0"
    findings["scanned_at"] = "2026-04-27T12:00:00Z"
    html = render_report(findings)
    assert "<html" in html
    assert "MCPatrol" in html.lower() or "mcpatrol" in html
    # Check the report includes our hero grade
    assert findings["overall"]["grade"] in html
