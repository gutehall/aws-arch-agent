"""Same-file matching for rules that pair a resource with a mitigating keyword."""
from __future__ import annotations

from typing import cast

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules.base import Rule
from aws_arch_agent.tools.paths import normalize_rel_path

Hit = tuple[str, int, str]


def _file_key(path: str) -> str:
    return normalize_rel_path(path) or path


def unmatched_resources(resources: list[Hit], mitigations: list[Hit]) -> list[Hit]:
    """Resources whose file has no mitigating hit.

    A keyword in another file does not clear a resource.
    """
    covered = {_file_key(path) for path, _line, _text in mitigations}
    return [hit for hit in resources if _file_key(hit[0]) not in covered]


def findings_when_same_file(
    rule: Rule,
    anchors: list[Hit],
    signals: list[Hit],
    recommendation: str,
    suggested_code: str | None = None,
) -> list[Finding]:
    """One finding per signal whose file also contains an anchor.

    A signal in another file does not attach to an anchor.
    """
    anchor_files = {_file_key(path) for path, _line, _text in anchors}
    findings: list[Finding] = []
    for path, line, text in signals:
        if _file_key(path) not in anchor_files:
            continue
        findings.append(
            Finding(
                id=rule.id,
                title=rule.title,
                severity=cast(Severity, rule.severity),
                category=rule.category,
                file=path,
                line=line,
                evidence=text,
                recommendation=recommendation,
                suggested_code=suggested_code,
            )
        )
    return findings


def findings_for_unmatched(
    rule: Rule,
    resources: list[Hit],
    mitigations: list[Hit],
    recommendation: str,
    suggested_code: str | None = None,
) -> list[Finding]:
    """One finding per unmatched resource, at that resource's file and line."""
    findings: list[Finding] = []
    for path, line, text in unmatched_resources(resources, mitigations):
        findings.append(
            Finding(
                id=rule.id,
                title=rule.title,
                severity=cast(Severity, rule.severity),
                category=rule.category,
                file=path,
                line=line,
                evidence=text,
                recommendation=recommendation,
                suggested_code=suggested_code,
            )
        )
    return findings
