"""HTML report renderer: one self-contained page (inline CSS and tab script)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2.sandbox import SandboxedEnvironment

from aws_arch_agent.models import Finding, RepoContext

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
) -> str:
    """Render context, findings, and warnings as one HTML page with no external assets."""
    ordered = sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK.get(f.severity, len(SEVERITIES)), f.category, f.id),
    )
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    rows = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "pillar": f.category,
            "location": _location(f),
            "evidence": f.evidence or "",
            "recommendation": f.recommendation.strip(),
            "suggested_code": (f.suggested_code or "").strip(),
        }
        for f in ordered
    ]
    template = _environment().from_string(_template_source())
    return template.render(
        repo=ctx.repo_path,
        source=ctx.source,
        files_scanned=ctx.files_scanned,
        generated=(generated or datetime.now()).strftime("%Y-%m-%d %H:%M"),
        severities=SEVERITIES,
        counts=counts,
        total=len(findings),
        warnings=list(warnings or []),
        findings=rows,
    )
