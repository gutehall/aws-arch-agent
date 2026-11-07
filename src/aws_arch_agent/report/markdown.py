"""Markdown report renderer for context and findings."""
from __future__ import annotations
from datetime import datetime
from typing import List, Dict
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.summary import build_summary, markdown_lines


def _group(findings: List[Finding]) -> Dict[str, List[Finding]]:
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        groups.setdefault(f.severity, []).append(f)
    # stable ordering
    for k in groups:
        groups[k] = sorted(groups[k], key=lambda x: (x.category, x.id))
    return groups


def price_line(ctx: RepoContext) -> str | None:
    """The region and snapshot date cost estimates use, or None when the scan set none."""
    note = ctx.notes.get("prices")
    if not isinstance(note, dict) or not note.get("region"):
        return None
    entries = note.get("regions") or [
        {"region": note["region"], "snapshot_date": note.get("snapshot_date"), "source": ""}
    ]
    parts = []
    for e in entries:
        source = f"{e['source']}; " if e.get("source") else ""
        if e.get("snapshot_date"):
            parts.append(f"{e['region']} ({source}AWS price list of {e['snapshot_date']})")
        else:
            parts.append(f"{e['region']} ({source}not in the price snapshot, so no cost estimates)")
    return "on-demand, " + ", ".join(parts)


def estimate_lines(f: Finding) -> List[str]:
    """Labelled estimate lines for a finding; empty when it has no estimate."""
    out: List[str] = []
    if f.monthly_cost_usd is not None:
        out.append(f"Estimated cost: **${f.monthly_cost_usd:,.2f}/month** (estimate)")
    if f.monthly_savings_usd is not None:
        out.append(f"Estimated saving: **${f.monthly_savings_usd:,.2f}/month** (estimate)")
    if out and f.estimate_basis:
        out.append(f"Estimate basis: {f.estimate_basis}")
    return out


def _usd(value: float) -> str:
    return f"${value:,.2f}"


def cost_section(ctx: RepoContext) -> List[str]:
    """The estimated monthly cost section; empty when the scan priced no template."""
    cost = ctx.notes.get("cost")
    if not isinstance(cost, dict) or not cost.get("stacks"):
        return []
    when = f", AWS prices of {cost['snapshot_date']}" if cost.get("snapshot_date") else ""
    out = [
        "## Estimated Monthly Cost (estimate)",
        f"{cost['basis']} {'Regions' if ',' in cost['region'] else 'Region'} {cost['region']}{when}.",
        "",
        "| Template / module | Region | Resources priced | Estimated monthly cost |",
        "|---|---|---:|---:|",
    ]
    for stack in cost["stacks"]:
        name = str(stack["name"]).replace("|", "\\|")
        region = stack.get("region") or cost["region"]
        out.append(f"| `{name}` | {region} | {stack['resources_priced']} | {_usd(stack['monthly_usd'])} |")
    priced = sum(s["resources_priced"] for s in cost["stacks"])
    out.append(f"| **Total** | | {priced} | **{_usd(cost['total_monthly_usd'])}** |")
    out.append("")
    if cost.get("top_resources"):
        out.append(f"Top {len(cost['top_resources'])} resources by estimated cost:")
        for i, r in enumerate(cost["top_resources"], 1):
            where = f"`{r['file']}`" + (f" (line {r['line']})" if r.get("line") else "")
            out.append(f"{i}. `{r['name']}` ({r['type']}) in {where}: {_usd(r['monthly_usd'])}/month. {r['basis']}")
        out.append("")
    if cost.get("savings_findings"):
        out.append(
            f"Possible savings from {cost['savings_findings']} finding(s) in this report: "
            f"**{_usd(cost['savings_monthly_usd'])}/month** (estimate; not subtracted from the total)."
        )
        out.append("")
    if cost.get("not_priced"):
        listed = ", ".join(f"{t} ×{n}" for t, n in cost["not_priced"].items())
        out.append(f"Not priced (usage-based, or not in the price snapshot): {listed}.")
        out.append("")
    return out


def insert_summary(report: str, findings: List[Finding]) -> str:
    """Put the rule-built summary into a report the LLM polished without it.

    It goes before "## Executive Summary" when that heading survived polishing, otherwise
    after the first heading, so its counts and savings are never rewritten.
    """
    block = "\n".join(markdown_lines(build_summary(findings)))
    if not block:
        return report
    marker = "## Executive Summary"
    if marker in report:
        return report.replace(marker, block + "\n" + marker, 1)
    head, sep, rest = report.partition("\n")
    return f"{head}\n\n{block}\n{rest}" if sep else f"{report}\n\n{block}"


def render_markdown(
    ctx: RepoContext,
    findings: List[Finding],
    warnings: List[str] | None = None,
    include_summary: bool = True,
    group_by: str = "severity",
) -> str:
    """Build a full Markdown report (title, repo info, findings by severity, next actions)."""
    groups = _group(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines: List[str] = []
    lines.append("# AWS Architecture Review Report")
    lines.append("")
    lines.append(f"- Repo: `{ctx.repo_path}`")
    lines.append(f"- Source: **{ctx.source}**")
    lines.append(f"- Language: **{ctx.language}**")
    lines.append(f"- Files scanned: **{ctx.files_scanned}**")
    prices = price_line(ctx)
    if prices:
        lines.append(f"- Prices: {prices}")
    lines.append(f"- Generated: {now}")
    lines.append("")
    if include_summary:
        lines.extend(markdown_lines(build_summary(findings)))
    lines.append("## Executive Summary")
    lines.append("This is an automated first-pass review. Always validate findings manually.")
    lines.append("")
    lines.extend(cost_section(ctx))

    if warnings:
        lines.append("## Analysis Warnings")
        lines.append("Some rules failed during analysis; results may be incomplete.")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    sections: List[tuple[str, List[Finding]]]
    if group_by == "theme":
        from aws_arch_agent.rules.themes import THEMES

        rank = {"High": 0, "Medium": 1, "Low": 2}
        ordered = sorted(findings, key=lambda x: (rank.get(x.severity, 3), x.category, x.id))
        sections = [(f"Theme: {name}", [f for f in ordered if name in f.themes]) for name in THEMES]
        sections.append(("No theme", [f for f in ordered if not f.themes]))
    else:
        sections = [(f"{sev} Priority Findings", groups[sev]) for sev in ("High", "Medium", "Low") if sev in groups]
    for heading, items in sections:
        if not items:
            continue
        lines.append(f"## {heading}")
        lines.append("")
        for f in items:
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
            if f.environment:
                shown = "unknown (judged as prod)" if f.environment == "unknown" else f.environment
                lines.append(f"- Environment: **{shown}**")
            if f.themes:
                lines.append(f"- Themes: {', '.join(f.themes)}")
            lines.extend(f"- {line}" for line in estimate_lines(f))
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
