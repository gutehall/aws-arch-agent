"""SARIF report renderer for GitHub Code Scanning."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from aws_arch_agent import __version__
from aws_arch_agent.baseline import finding_fingerprint
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.docs import doc_links

INFORMATION_URI = "https://github.com/gutehall/aws-arch-agent"
FINGERPRINT_KEY = "awsArchAgent/v1"

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


def fingerprint(f: Finding) -> str:
    """Stable result identity across line moves: rule ID, repo-relative file, evidence hash."""
    fp = finding_fingerprint(f)
    key = "|".join([fp.rule_id, fp.file or "", fp.evidence_hash or ""])
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def inline_suppression(f: Finding) -> dict[str, Any] | None:
    """The SARIF suppression for an in-source suppression, or None when there is none."""
    s = f.suppression
    if s is None:
        return None
    where = "inline comment" if s.kind == "inline" else "template Metadata"
    parts = [s.reason or f"Suppressed by {where}"]
    if s.expires:
        parts.append(f"expires {s.expires}")
    return {"kind": "inSource", "status": "accepted", "justification": "; ".join(parts)}


BASELINE_SUPPRESSION = {"kind": "external", "status": "accepted", "justification": "Accepted in baseline"}


def render_sarif(ctx: RepoContext, findings: list[Finding], warnings: list[str] | None = None) -> str:
    """Serialize findings as SARIF 2.1.0 for upload-sarif workflows."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        if f.id not in rules:
            rules[f.id] = {
                **({"properties": {"tags": list(f.themes)}} if f.themes else {}),
                "id": f.id,
                "name": f.id,
                "helpUri": doc_links(f)[0]["url"],
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.recommendation},
                "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(f.severity, "warning")},
            }
        result: dict[str, Any] = {
            "ruleId": f.id,
            "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.recommendation},
            "locations": [_location(f)],
            "partialFingerprints": {FINGERPRINT_KEY: fingerprint(f)},
        }
        suppression = inline_suppression(f)
        if suppression:
            result["suppressions"] = [suppression]
        estimate: dict[str, Any] = {
            key: value for key, value in (
                ("estimatedMonthlyCostUsd", f.monthly_cost_usd),
                ("estimatedMonthlySavingsUsd", f.monthly_savings_usd),
                ("estimateBasis", f.estimate_basis),
            ) if value is not None
        }
        if f.environment:
            estimate["environment"] = f.environment
        if f.themes:
            estimate["themes"] = list(f.themes)
        if estimate:
            result["properties"] = estimate
        results.append(result)
    if warnings:
        rules["AWS-ARCH-AGENT-WARNING"] = {
            "id": "AWS-ARCH-AGENT-WARNING",
            "name": "AWS-ARCH-AGENT-WARNING",
            "shortDescription": {"text": "Scan check failed"},
            "fullDescription": {
                "text": "A rule, template read, or cdk synth step failed. The result message is the warning."
            },
            "defaultConfiguration": {"level": "warning"},
        }
        for w in warnings:
            results.append(
                {
                    "ruleId": "AWS-ARCH-AGENT-WARNING",
                    "level": "warning",
                    "message": {"text": w},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": ctx.repo_path}}}],
                }
            )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "aws-arch-agent",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "automationDetails": {"description": {"text": f"Scan of {ctx.repo_path}"}},
    }

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(doc, indent=2)
