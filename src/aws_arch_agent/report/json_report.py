"""JSON report renderer for CI and tooling (context + findings)."""
from __future__ import annotations

import json
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.summary import build_summary
from aws_arch_agent.rules import well_architected


def _finding_dict(f: Finding) -> dict:
    """The finding's fields, plus the model's verdict on it when there is one."""
    item = f.model_dump()
    if f.verdict:
        item["verdict"] = f.verdict.model_dump()
    return item


def render_json(
    ctx: RepoContext,
    findings: list[Finding],
    warnings: list[str] | None = None,
) -> str:
    """Serialize context and findings to JSON (Pydantic model_dump)."""
    data = {
        "context": ctx.model_dump(),
        "summary": build_summary(findings),
        "answers": [a.to_dict() for a in well_architected.answers(findings)],
        "llm": ctx.llm.to_dict(),
        "findings": [_finding_dict(f) for f in findings],
    }
    if ctx.hypotheses:
        data["hypotheses"] = [h.model_dump() for h in ctx.hypotheses]
    if ctx.hypothesis_llm.status != "skipped":
        data["hypotheses_llm"] = ctx.hypothesis_llm.to_dict()
    if warnings:
        data["warnings"] = warnings
    return json.dumps(data, indent=2)
