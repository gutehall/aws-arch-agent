"""HTML report renderer: one self-contained page (inline CSS and tab script).

The page loads no external assets; its only external URLs are AWS documentation links.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2.sandbox import SandboxedEnvironment

from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.docs import doc_links
from aws_arch_agent.report.markdown import estimate_lines, price_line, suppression_text
from aws_arch_agent.report.summary import build_summary, pillar_line, theme_counts
from aws_arch_agent.rules import lenses, well_architected

SEVERITIES = ("High", "Medium", "Low")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_TEMPLATES = Path(__file__).parent / "templates"
_TEMPLATE = "report.html"


def _environment() -> SandboxedEnvironment:
    # Sandboxed and autoescaped: evidence and suggested code come from scanned repos.
    return SandboxedEnvironment(autoescape=True, trim_blocks=True, lstrip_blocks=True)


def _template_source() -> str:
    return (_TEMPLATES / _TEMPLATE).read_text(encoding="utf-8")


def _location(f: Finding) -> str:
    if not f.file:
        return ""
    return f"{f.file}:{f.line}" if f.line else f.file


def _row(f: Finding, flag: bool | None) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "pillar": f.category,
        "environment": (
            None if not f.environment
            else "unknown (judged as prod)" if f.environment == "unknown" else f.environment
        ),
        "location": _location(f),
        "evidence": f.evidence or "",
        "recommendation": f.recommendation.strip(),
        "suggested_code": (f.suggested_code or "").strip(),
        "estimates": estimate_lines(f),
        "themes": list(f.themes),
        "docs": doc_links(f),
        "baseline": None if flag is None else ("accepted" if flag else "new"),
        "verdict": f.verdict,
        "suppressed": suppression_text(f),
        "suppression_reason": f.suppression.reason if f.suppression else None,
    }


def _cards(rows: list[dict]) -> list[dict]:
    """One card per rule and severity, in row order, with each finding as a location.

    Severity stays exact so the severity tabs still filter cards. A recommendation or
    suggested code the findings share is shown once on the card; one that differs stays
    with its location. The card's themes are every location's, for the theme filter."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        groups.setdefault((row["id"], row["severity"]), []).append(row)
    cards = []
    for items in groups.values():
        first = items[0]
        shared = {key: first[key] if all(r[key] == first[key] for r in items) else None
                  for key in ("recommendation", "suggested_code")}
        flags = {r["baseline"] for r in items}
        cards.append({
            "id": first["id"], "title": first["title"], "severity": first["severity"],
            "pillar": first["pillar"], "docs": first["docs"],
            "themes": sorted({t for r in items for t in r["themes"]}),
            "baseline": None if flags == {None} else ("new" if "new" in flags else "accepted"),
            "suppressed": all(r["suppressed"] for r in items),
            "recommendation": shared["recommendation"], "suggested_code": shared["suggested_code"],
            "locations": items,
        })
    return cards


def render_html(
    ctx: RepoContext,
    findings: list[Finding],
    warnings: list[str] | None = None,
    generated: datetime | None = None,
    baselined: list[bool] | None = None,
) -> str:
    """Render context, findings, and warnings as one HTML page with no external assets.

    baselined (one flag per finding, in order) labels each finding accepted or new, as
    the markdown report does with --enforce-baseline. Every finding stays on the page.
    """
    if baselined is not None and len(baselined) != len(findings):
        raise ValueError("baselined needs one flag per finding")
    flags = baselined if baselined is not None else [None] * len(findings)
    ordered = sorted(
        zip(findings, flags),
        key=lambda pair: (
            _SEVERITY_RANK.get(pair[0].severity, len(SEVERITIES)), pair[0].category, pair[0].id
        ),
    )
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    cards = _cards([_row(f, flag) for f, flag in ordered])
    summary = build_summary(findings)
    template = _environment().from_string(_template_source())
    return template.render(
        repo=ctx.repo_path,
        source=ctx.source,
        files_scanned=ctx.files_scanned,
        prices=price_line(ctx),
        cost=ctx.notes.get("cost") if isinstance(ctx.notes.get("cost"), dict) else None,
        cost_hint=ctx.notes.get("cost_hint"),
        generated=(generated or datetime.now()).strftime("%Y-%m-%d %H:%M"),
        severities=SEVERITIES,
        counts=counts,
        theme_counts=theme_counts(findings),
        answers=well_architected.html_rows(well_architected.answers(findings, ctx.rules_run)),
        lens_groups=lenses.html_groups(lenses.answers_for(ctx, findings)),
        total=len(findings),
        warnings=list(warnings or []),
        findings=cards,
        summary=summary,
        pillar_lines=[pillar_line(row) for row in summary["pillars"]],
        theme_lines=[pillar_line(row) for row in summary["themes"]],
        hypotheses=ctx.hypotheses,
        baseline=None if baselined is None else {
            "accepted": sum(1 for b in baselined if b),
            "new": sum(1 for b in baselined if not b),
        },
    )
