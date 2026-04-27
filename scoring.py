"""
Grading: convert raw findings into A-F report card grades.

We use a deduction model — start at 100, subtract for issues. This is
predictable and auditable, which matters for a security tool.
"""


SEVERITY_DEDUCTIONS = {
    "critical": 30,
    "high":     15,
    "medium":   7,
    "low":      2,
    "info":     0,
}


def _score_to_grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 90: return "A"
    if score >= 85: return "A-"
    if score >= 80: return "B+"
    if score >= 75: return "B"
    if score >= 70: return "B-"
    if score >= 65: return "C+"
    if score >= 60: return "C"
    if score >= 55: return "C-"
    if score >= 50: return "D+"
    if score >= 45: return "D"
    if score >= 40: return "D-"
    return "F"


def grade_security(findings: dict) -> tuple:
    """Return (score_0_to_100, grade)."""
    score = 100
    for issue in findings.get("issues", []):
        score -= SEVERITY_DEDUCTIONS.get(issue["severity"], 0)
    score = max(0, score)
    return score, _score_to_grade(score)


def grade_cost(findings: dict) -> tuple:
    """Token cost mapped to grade. Lower tokens = better grade."""
    total = findings.get("total_tokens", 0)
    # Industry-grade thresholds from public reporting
    if total < 800:
        return 100, "A+"
    if total < 2000:
        return 92, "A"
    if total < 4500:
        return 80, "B+"
    if total < 8500:
        return 65, "C+"
    if total < 16000:
        return 45, "D"
    return 25, "F"


def grade_quality(findings: dict) -> tuple:
    """Average tool clarity score (1-10) → grade."""
    if findings.get("skipped"):
        return None, "—"
    avg = findings.get("average_score")
    if avg is None:
        return None, "—"
    score_pct = (avg / 10) * 100
    return round(score_pct), _score_to_grade(round(score_pct))


def grade_reliability(findings: dict) -> tuple:
    if findings.get("skipped"):
        return None, "—"
    successes = findings.get("successes", 0)
    calls = findings.get("calls", 0)
    if calls == 0:
        return None, "—"
    success_rate = successes / calls
    p95 = findings.get("p95_ms", 0)

    base = success_rate * 100  # 100 for full success
    # Latency penalty
    if p95 > 5000:
        base -= 25
    elif p95 > 2000:
        base -= 15
    elif p95 > 1000:
        base -= 8
    elif p95 > 500:
        base -= 3

    base = max(0, round(base))
    return base, _score_to_grade(base)


def grade_overall(all_findings: dict) -> dict:
    sec_score, sec_grade = grade_security(all_findings.get("security", {}))
    cost_score, cost_grade = grade_cost(all_findings.get("cost", {}))
    qual_score, qual_grade = grade_quality(all_findings.get("quality", {}))
    rel_score, rel_grade = grade_reliability(all_findings.get("reliability", {}))

    # Weighted overall — security is most important
    weights = []
    if sec_score is not None: weights.append((sec_score, 0.45))
    if cost_score is not None: weights.append((cost_score, 0.20))
    if qual_score is not None: weights.append((qual_score, 0.20))
    if rel_score is not None: weights.append((rel_score, 0.15))

    if weights:
        total_weight = sum(w for _, w in weights)
        overall_score = sum(s * w for s, w in weights) / total_weight
        overall_grade = _score_to_grade(round(overall_score))
    else:
        overall_score = None
        overall_grade = "—"

    return {
        "score": round(overall_score) if overall_score is not None else None,
        "grade": overall_grade,
        "security_score": sec_score,
        "security_grade": sec_grade,
        "cost_score": cost_score,
        "cost_grade": cost_grade,
        "quality_score": qual_score,
        "quality_grade": qual_grade,
        "reliability_score": rel_score,
        "reliability_grade": rel_grade,
    }
