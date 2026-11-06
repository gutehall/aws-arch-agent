"""The report's opening summary (DM3-550): top fixes, one line per pillar, quick wins.

Built from rule output only, so it is the same with or without an LLM, and the same on
every run for the same findings. A "fix" is one rule: fixing it covers every resource it
reported. The pillar lines add up to the findings below them, counts and savings alike.
"""
from __future__ import annotations

from typing import Any, List

from aws_arch_agent.models import Finding

TOP_N = 5
_SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}
_EFFORT_RANK = {"low": 0, "medium": 1, "high": 2}


def _cents(f: Finding) -> int:
    return round((f.monthly_savings_usd or 0.0) * 100)


def _savings(findings: List[Finding]) -> float:
    """Summed in whole cents, so pillar and fix savings add up exactly to the total."""
    return sum(_cents(f) for f in findings) / 100


def _location(f: Finding) -> str | None:
    if not f.file:
        return None
    return f"{f.file}:{f.line}" if f.line else f.file


def _fixes(findings: List[Finding]) -> list[dict[str, Any]]:
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.id, []).append(f)
    fixes = []
    for rule_id, items in by_rule.items():
        worst = min(items, key=lambda f: _SEVERITY_RANK[f.severity])
        # Prefer a finding with a file to point at; then the first by location.
        first = sorted(items, key=lambda f: (f.file is None, _location(f) or "", f.evidence or ""))[0]
        fixes.append({
            "id": rule_id,
            "title": worst.title,
            "severity": worst.severity,
            "category": worst.category,
            "findings": len(items),
            "monthly_savings_usd": _savings(items),
            "effort": worst.effort,
            "suggested_code": any(f.suggested_code for f in items),
            "first_location": _location(first),
        })
    return fixes


def _ranked(fixes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Severity, then estimated saving, then how many resources the fix covers, then id."""
    return sorted(fixes, key=lambda x: (
        _SEVERITY_RANK[x["severity"]], -x["monthly_savings_usd"], -x["findings"], x["id"]))


def theme_counts(findings: List[Finding]) -> list[tuple[str, int]]:
    """(theme, findings) in the fixed theme order, for themes that have any."""
    from aws_arch_agent.rules.themes import THEMES

    counts = {name: sum(1 for f in findings if name in f.themes) for name in THEMES}
    return [(name, n) for name, n in counts.items() if n]


def build_summary(findings: List[Finding]) -> dict[str, Any]:
    fixes = _fixes(findings)
    pillars: dict[str, list[Finding]] = {}
    for f in findings:
        pillars.setdefault(f.category, []).append(f)
    pillar_rows = []
    for name in sorted(pillars, key=lambda n: (-len(pillars[n]), n)):
        items = pillars[name]
        counts = {sev: sum(1 for f in items if f.severity == sev) for sev in ("High", "Medium", "Low")}
        pillar_rows.append({
            "name": name, "findings": len(items), "by_severity": counts,
            "monthly_savings_usd": _savings(items),
        })
    quick = [x for x in fixes if x["effort"] == "low" and x["suggested_code"]]
    quick = sorted(quick, key=lambda x: (
        -x["monthly_savings_usd"], _SEVERITY_RANK[x["severity"]], -x["findings"], x["id"]))
    from aws_arch_agent.rules.themes import THEMES

    theme_rows = []
    for name in THEMES:
        items = [f for f in findings if name in f.themes]
        if items:
            theme_rows.append({
                "name": name, "findings": len(items),
                "by_severity": {sev: sum(1 for f in items if f.severity == sev) for sev in ("High", "Medium", "Low")},
                "monthly_savings_usd": _savings(items),
            })
    return {
        "themes": theme_rows,
        "findings": len(findings),
        "by_severity": {sev: sum(1 for f in findings if f.severity == sev) for sev in ("High", "Medium", "Low")},
        "monthly_savings_usd": _savings(findings),
        "top_fixes": _ranked(fixes)[:TOP_N],
        "pillars": pillar_rows,
        "quick_wins": quick[:TOP_N],
    }


def _usd(value: float) -> str:
    return f"${value:,.2f}"


def pillar_line(row: dict[str, Any]) -> str:
    counts = ", ".join(f"{n} {sev}" for sev, n in row["by_severity"].items() if n)
    line = f"{row['name']}: {row['findings']} finding{'s' if row['findings'] != 1 else ''} ({counts})"
    if row["monthly_savings_usd"]:
        line += f", about {_usd(row['monthly_savings_usd'])}/month possible savings (estimate)"
    return line


def fix_line(fix: dict[str, Any]) -> str:
    covers = f"{fix['findings']} resource{'s' if fix['findings'] != 1 else ''}"
    line = f"[{fix['id']}] {fix['title']} ({fix['severity']}, {covers}"
    if fix["monthly_savings_usd"]:
        line += f", saves about {_usd(fix['monthly_savings_usd'])}/month (estimate)"
    line += f", {fix['effort']} effort)"
    if fix.get("first_location"):
        line += f", e.g. {fix['first_location']}"
    return line


def markdown_lines(summary: dict[str, Any]) -> List[str]:
    """The summary as Markdown; empty when there are no findings."""
    if not summary["findings"]:
        return []
    sev = summary["by_severity"]
    out = [
        "## Summary",
        f"{summary['findings']} findings: {sev['High']} High, {sev['Medium']} Medium, {sev['Low']} Low."
        + (f" About {_usd(summary['monthly_savings_usd'])}/month possible savings (estimate)."
           if summary["monthly_savings_usd"] else ""),
        "",
        "**Top fixes** (by severity, then saving, then resources covered):",
    ]
    out += [f"{i}. {fix_line(fix)}" for i, fix in enumerate(summary["top_fixes"], 1)]
    out += ["", "**By pillar:**"]
    out += [f"- {pillar_line(row)}" for row in summary["pillars"]]
    if summary.get("themes"):
        out += ["", "**By theme** (a finding can be in more than one):"]
        out += [f"- {pillar_line(row)}" for row in summary["themes"]]
    if summary["quick_wins"]:
        out += ["", "**Quick wins** (low effort, with suggested code):"]
        out += [f"- {fix_line(fix)}" for fix in summary["quick_wins"]]
    out.append("")
    return out
