"""Shared rule execution for V1 and V2 pipelines."""
from __future__ import annotations

import logging
from pathlib import Path

from aws_arch_agent.models import Finding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ("Low", "Medium", "High")


def filter_by_severity(findings: list[Finding], severity_threshold: str | None) -> list[Finding]:
    """Keep findings at or above the given severity threshold."""
    if not severity_threshold:
        return findings
    try:
        idx = SEVERITY_ORDER.index(severity_threshold.capitalize())
        allowed = set(SEVERITY_ORDER[idx:])
        return [f for f in findings if f.severity in allowed]
    except ValueError:
        return findings


def run_all_rules(
    repo_path: Path,
    rules: list,
    languages: list[str],
) -> tuple[list[Finding], list[str]]:
    """Run rules for each language; return findings and warning messages for failed rules."""
    findings: list[Finding] = []
    warnings: list[str] = []
    for lang in languages:
        for rule in rules:
            try:
                findings.extend(rule.run(repo_path, lang))
            except Exception as e:
                msg = f"Rule {rule.id} failed for {lang}: {e}"
                warnings.append(msg)
                logger.warning(msg)
    return findings, warnings
