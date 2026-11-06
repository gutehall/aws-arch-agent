"""HTML report renderer: one self-contained page (inline CSS and tab script).

The page loads no external assets; its only external URLs are AWS documentation links.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2.sandbox import SandboxedEnvironment

from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.docs import doc_links
from aws_arch_agent.report.markdown import estimate_lines, price_line
from aws_arch_agent.report.summary import build_summary, fix_line, pillar_line, theme_counts

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
    rows = [
        {
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
        }
        for f, flag in ordered
    ]
    template = _environment().from_string(_template_source())
    return template.render(
        repo=ctx.repo_path,
        source=ctx.source,
        files_scanned=ctx.files_scanned,
        prices=price_line(ctx),
        cost=ctx.notes.get("cost") if isinstance(ctx.notes.get("cost"), dict) else None,
        generated=(generated or datetime.now()).strftime("%Y-%m-%d %H:%M"),
        severities=SEVERITIES,
        counts=counts,
        summary=build_summary(findings),
        theme_counts=theme_counts(findings),
        fix_line=fix_line,
        pillar_line=pillar_line,
        total=len(findings),
        warnings=list(warnings or []),
        findings=rows,
        baseline=None if baselined is None else {
            "accepted": sum(1 for b in baselined if b),
            "new": sum(1 for b in baselined if not b),
        },
    )
