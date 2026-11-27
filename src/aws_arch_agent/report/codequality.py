"""GitLab Code Quality report renderer (the merge request widget's JSON array).

Format: https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format. The
fingerprint is the SARIF one (rule ID, repo-relative file, evidence), so a moved line keeps it.
GitLab shows every entry as an open issue, so the caller leaves out findings an inline
suppression or the baseline accepted; SARIF records those as suppressions instead.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from aws_arch_agent.models import Finding
from aws_arch_agent.report.sarif import fingerprint

# High stays major, so one high finding does not read as a blocker in the widget.
SEVERITY = {"High": "major", "Medium": "minor", "Low": "info"}


def _entry(f: Finding) -> dict[str, Any]:
    # A repo-level finding has no file; GitLab needs a path, so it points at the repo root.
    location: dict[str, Any] = {"path": f.file or ".", "lines": {"begin": f.line or 1}}
    return {
        "description": f"{f.title}: {f.recommendation}" if f.recommendation else f.title,
        "check_name": f.id,
        "fingerprint": fingerprint(f),
        "severity": SEVERITY.get(f.severity, "minor"),
        "location": location,
        "categories": [f.category] if f.category else [],
    }


def render_codequality(findings: Iterable[Finding]) -> str:
    """The findings as a Code Quality JSON array."""
    return json.dumps([_entry(f) for f in findings], indent=2)
