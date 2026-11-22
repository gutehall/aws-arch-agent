"""Markdown report renderer for context and findings."""
from __future__ import annotations
from datetime import datetime
import re
from typing import List, Dict
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.summary import _span_text, build_summary, markdown_lines
from aws_arch_agent.rules import lenses, well_architected
from aws_arch_agent.tools.files import truncation_message


def _fence(text: str) -> str:
    """A code fence the text cannot close: longer than its longest backtick run, at least three."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _group(findings: List[Finding]) -> Dict[str, List[Finding]]:
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        groups.setdefault(f.severity, []).append(f)
    # stable ordering
    for k in groups:
        groups[k] = sorted(groups[k], key=lambda x: (x.category, x.id))
    return groups


def price_line(ctx: RepoContext) -> str | None:
    """The region, price source and AWS price list date estimates use, or None when the scan set none."""
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
            origin = f"{e['pricing_source']}, " if e.get("pricing_source") else ""
            stale = ", some from an expired cache" if e.get("stale") else ""
            parts.append(f"{e['region']} ({source}{origin}AWS price list of {e['snapshot_date']}{stale})")
        else:
            parts.append(f"{e['region']} ({source}no prices used)")
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


def suppression_text(f: Finding) -> str | None:
    """How a suppressed finding is labelled, without the reason; None when not suppressed."""
    s = f.suppression
    if s is None:
        return None
    where = "inline comment" if s.kind == "inline" else "template Metadata"
    expiry = f", expires {s.expires}" if s.expires else ""
    return f"suppressed ({where}{expiry})"


def _usd(value: float) -> str:
    return f"${value:,.2f}"


def budget_line(cost: dict) -> str | None:
    """The budget result in one line, or None when no budget is set."""
    budget = cost.get("budget")
    if not isinstance(budget, dict):
        return None
    if not budget.get("passed"):
        return "**Budget: FAILED** — " + "; ".join(budget.get("breaches") or []) + "."
    limits = []
    if budget.get("max_monthly_usd") is not None:
        limits.append(f"at most {_usd(budget['max_monthly_usd'])}/month")
    if budget.get("max_increase_usd") is not None:
        limits.append(f"a rise of at most {_usd(budget['max_increase_usd'])}/month")
    if budget.get("max_increase_percent") is not None:
        limits.append(f"a rise of at most {budget['max_increase_percent']:g}%")
    skipped = f" Not checked: {'; '.join(budget['not_checked'])}." if budget.get("not_checked") else ""
    return f"**Budget: passed** ({', '.join(limits)}).{skipped}"


def _signed(value: float) -> str:
    return ("+" if value >= 0 else "-") + _usd(abs(value))


def diff_lines(cost: dict) -> List[str]:
    """The cost diff as a summary line and a table of changed resources; empty without one."""
    change = cost.get("diff")
    if not isinstance(change, dict):
        return []
    pct = f", {change['delta_percent']:+g}%" if change.get("delta_percent") is not None else ""
    source = f" `{_span_text(change['source'])}`" if change.get("source") else ""
    out = [
        "### Cost change",
        f"Compared with{source}: {_usd(change['previous_monthly_usd'])} → "
        f"{_usd(change['current_monthly_usd'])}/month (**{_signed(change['delta_monthly_usd'])}{pct}**).",
        "",
    ]
    rows = (
        [("added", r["name"], r["stack"], None, r["monthly_usd"], r["monthly_usd"]) for r in change.get("added") or []]
        + [("removed", r["name"], r["stack"], r["monthly_usd"], None, -r["monthly_usd"]) for r in change.get("removed") or []]
        + [("changed", r["name"], r["stack"], r["previous_monthly_usd"], r["current_monthly_usd"], r["delta_monthly_usd"])
           for r in change.get("changed") or []]
    )
    if rows:
        out += ["| Change | Resource | Template / module | Before | After | Delta |", "|---|---|---|---:|---:|---:|"]
        for kind, name, stack, before, after, delta in rows:
            out.append(
                f"| {kind} | `{_span_text(str(name))}` | `{_span_text(str(stack))}` | "
                f"{_usd(before) if before is not None else ''} | {_usd(after) if after is not None else ''} | {_signed(delta)} |"
            )
        out.append("")
    return out


def cost_section(ctx: RepoContext) -> List[str]:
    """The estimated monthly cost section; empty when the scan priced no template."""
    cost = ctx.notes.get("cost")
    if not isinstance(cost, dict) or not cost.get("stacks"):
        if ctx.notes.get("cost_hint"):
            return ["## Estimated Monthly Cost (estimate)", str(ctx.notes["cost_hint"]), ""]
        return []
    when = f", AWS prices of {cost['snapshot_date']}" if cost.get("snapshot_date") else ""
    out = ["## Estimated Monthly Cost (estimate)"]
    budget = budget_line(cost)
    if budget:
        out += [budget, ""]
    out += [
        f"{cost['basis']} {'Regions' if ',' in cost['region'] else 'Region'} {cost['region']}{when}.",
        "",
    ]
    usage = cost.get("usage_monthly_usd") or 0
    if usage:
        out += [
            f"Fixed (from the IaC): **{_usd(cost.get('fixed_monthly_usd', 0.0))}/month**. "
            f"Usage assumed (from the usage profile): **{_usd(usage)}/month**.",
            "",
        ]
    out += [
        "| Template / module | Region | Resources priced | Estimated monthly cost |",
        "|---|---|---:|---:|",
    ]
    for stack in cost["stacks"]:
        name = str(stack["name"]).replace("|", "\\|")
        region = stack.get("region") or cost["region"]
        out.append(f"| `{_span_text(name)}` | {region} | {stack['resources_priced']} | {_usd(stack['monthly_usd'])} |")
    priced = sum(s["resources_priced"] for s in cost["stacks"])
    out.append(f"| **Total** | | {priced} | **{_usd(cost['total_monthly_usd'])}** |")
    out.append("")
    if cost.get("top_resources"):
        out.append(f"Top {len(cost['top_resources'])} resources by estimated cost:")
        for i, r in enumerate(cost["top_resources"], 1):
            where = f"`{_span_text(r['file'])}`" + (f" (line {r['line']})" if r.get("line") else "")
            tag = " *(usage assumed)*" if r.get("usage_assumed") else ""
            out.append(f"{i}. `{_span_text(r['name'])}` ({r['type']}) in {where}: {_usd(r['monthly_usd'])}/month{tag}. {r['basis']}")
        out.append("")
    out.extend(diff_lines(cost))
    if cost.get("savings_findings"):
        out.append(
            f"Possible savings from {cost['savings_findings']} finding(s) in this report: "
            f"**{_usd(cost['savings_monthly_usd'])}/month** (estimate; not subtracted from the total)."
        )
        out.append("")
    if cost.get("not_priced"):
        listed = ", ".join(f"{t} ×{n}" for t, n in cost["not_priced"].items())
        out.append(f"Not priced (usage-based, or no AWS price found): {listed}.")
        out.append("")
    return out


def render_markdown(
    ctx: RepoContext,
    findings: List[Finding],
    warnings: List[str] | None = None,
    group_by: str = "severity",
) -> str:
    """Build a full Markdown report (title, repo info, findings by severity, next actions)."""
    groups = _group(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines: List[str] = []
    lines.append("# AWS Architecture Review Report")
    lines.append("")
    lines.append(f"- Repo: `{_span_text(ctx.repo_path)}`")
    lines.append(f"- Source: **{ctx.source}**")
    lines.append(f"- Language: **{ctx.language}**")
    lines.append(f"- Files scanned: **{ctx.files_scanned}**")
    truncated = truncation_message(ctx.notes)
    if truncated:
        lines.append(f"- Note: {truncated}")
    prices = price_line(ctx)
    if prices:
        lines.append(f"- Prices: {prices}")
    lines.append(f"- Generated: {now}")
    suppressed = sum(1 for f in findings if f.suppression is not None)
    if suppressed:
        lines.append(
            f"- Suppressed: **{suppressed}** finding(s), labelled below; they do not count for --fail-on"
        )
    lines.append("")
    lines.extend(markdown_lines(build_summary(findings)))
    answers = well_architected.answers(findings, ctx.rules_run)
    lines.extend(well_architected.markdown_lines(answers))
    lines.extend(lenses.markdown_lines(lenses.answers_for(ctx, findings)))
    lines.append("## Executive Summary")
    lines.append("This is an automated first-pass review. Always validate findings manually.")
    lines.append("")
    lines.extend(cost_section(ctx))

    if warnings:
        lines.append("## Analysis Warnings")
        lines.append("Some rules failed during analysis; results may be incomplete.")
        lines.append("")
        for w in warnings:
            # A code span: warnings can name files from the scanned repo.
            lines.append(f"- `{_span_text(w)}`")
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
                loc = f"File: `{_span_text(f.file)}`"
                if f.line:
                    loc += f" (line {f.line})"
            lines.append(f"### [{f.id}] {f.title}")
            label = suppression_text(f)
            if label and f.suppression is not None:
                # A code span: the reason is text from the scanned repo.
                reason = f" — `{_span_text(f.suppression.reason)}`" if f.suppression.reason else ""
                lines.append(f"- Status: **{label}**{reason}")
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
            if f.verdict:
                # A code span: the scanned repo can steer this text, and a viewer would load
                # an image or follow a link written in it.
                lines.append(f"- LLM verdict: **{f.verdict.label}** — `{_span_text(f.verdict.why)}`")
            if f.evidence:
                fence = _fence(f.evidence)
                lines.append("")
                lines.append("**Evidence**")
                lines.append(fence)
                lines.append(f.evidence)
                lines.append(fence)
            lines.append("")
            lines.append("**Recommendation**")
            lines.append(f.recommendation.strip())
            if f.suggested_code:
                lines.append("")
                lines.append("**Suggested Code**")
                code = f.suggested_code.strip()
                fence = _fence(code)
                lines.append(fence)
                lines.append(code)
                lines.append(fence)
            lines.append("")
        lines.append("")

    if ctx.hypotheses:
        lines.append("## Unverified hypotheses")
        lines.append(
            "The model named these catalog rules in files with no finding. No check confirmed them. "
            "They are not findings and do not affect fail-on, the baseline, or SARIF."
        )
        lines.append("")
        for h in ctx.hypotheses:
            # Code spans: the scanned repo can steer this text, as with a verdict's why.
            lines.append(
                f"- [{h.rule_id}] {h.title}: `{_span_text(h.file)}` (line {h.line}) — `{_span_text(h.why)}`"
            )
        lines.append("")

    lines.append("## Suggested Next Actions")
    lines.append("1. Address High findings first (security/perms/network).")
    lines.append("2. Run `cdk synth` and verify outputs (V2 can automate this).")
    lines.append("3. Add alarms and log retention for cost and control.")
    lines.append("")
    return "\n".join(lines)
