"""SARIF report renderer for GitHub Code Scanning."""
from __future__ import annotations

import json
from typing import Any

from aws_arch_agent.models import Finding, RepoContext

_SEVERITY_TO_LEVEL = {
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


def _location(f: Finding) -> dict[str, Any]:
    uri = f.file or "unknown"
    loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    if f.line is not None:
        loc["physicalLocation"]["region"] = {"startLine": f.line}
    return loc


def render_sarif(ctx: RepoContext, findings: list[Finding], warnings: list[str] | None = None) -> str:
    """Serialize findings as SARIF 2.1.0 for upload-sarif workflows."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "name": f.id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.recommendation},
                "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(f.severity, "warning")},
            }
        results.append(
            {
                "ruleId": f.id,
                "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.recommendation},
                "locations": [_location(f)],
            }
        )

    run: dict[str, Any] = {
        "tool": {"driver": {"name": "aws-arch-agent", "rules": list(rules.values())}},
        "results": results,
        "automationDetails": {"description": {"text": f"Scan of {ctx.repo_path}"}},
    }
    if warnings:
        for w in warnings:
            results.append(
                {
                    "ruleId": "AWS-ARCH-AGENT-WARNING",
                    "level": "warning",
                    "message": {"text": w},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": ctx.repo_path}}}],
                }
            )

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(doc, indent=2)
