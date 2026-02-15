"""Markdown report renderer for context and findings."""
from __future__ import annotations
from datetime import datetime
from typing import List, Dict
from aws_arch_agent.models import Finding, RepoContext


def _group(findings: List[Finding]) -> Dict[str, List[Finding]]:
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        groups.setdefault(f.severity, []).append(f)
    # stable ordering
    for k in groups:
        groups[k] = sorted(groups[k], key=lambda x: (x.category, x.id))
    return groups


def render_markdown(ctx: RepoContext, findings: List[Finding]) -> str:
    """Build a full Markdown report (title, repo info, findings by severity, next actions)."""
    groups = _group(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines: List[str] = []
    lines.append("# AWS Architecture Review Report")
    lines.append("")
    lines.append(f"- Repo: `{ctx.repo_path}`")
    lines.append(f"- Language: **{ctx.language}**")
    lines.append(f"- Files scanned: **{ctx.files_scanned}**")
    lines.append(f"- Generated: {now}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("This is an automated first-pass review. Always validate findings manually.")
    lines.append("")

    order = ["High", "Medium", "Low"]
    for sev in order:
        if sev not in groups:
            continue
        lines.append(f"## {sev} Priority Findings")
        lines.append("")
        for f in groups[sev]:
            loc = ""
            if f.file:
                loc = f"File: `{f.file}`"
                if f.line:
                    loc += f" (line {f.line})"
            lines.append(f"### [{f.id}] {f.title}")
            lines.append(f"- Category: **{f.category}**")
            lines.append(f"- Severity: **{f.severity}**")
            if loc:
                lines.append(f"- {loc}")
            if f.evidence:
                lines.append("")
                lines.append("**Evidence**")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
            lines.append("")
            lines.append("**Recommendation**")
            lines.append(f.recommendation.strip())
            if f.suggested_code:
                lines.append("")
                lines.append("**Suggested Code**")
                lines.append("```")
                lines.append(f.suggested_code.strip())
                lines.append("```")
            lines.append("")
        lines.append("")

    lines.append("## Suggested Next Actions")
    lines.append("1. Address High findings first (security/perms/network).")
    lines.append("2. Run `cdk synth` and verify outputs (V2 can automate this).")
    lines.append("3. Add alarms and log retention for cost and control.")
    lines.append("")
    return "\n".join(lines)
