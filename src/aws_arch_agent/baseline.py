"""Baseline / suppression support for gradual CI adoption."""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.tools.paths import normalize_rel_path

DEFAULT_BASELINE_NAME = ".aws-arch-agent-baseline.json"


def finding_fingerprint(f: Finding) -> tuple[str, str | None, int | None]:
    """Stable key for baseline matching."""
    return (f.id, normalize_rel_path(f.file), f.line)


def load_baseline(path: Path) -> set[tuple[str, str | None, int | None]]:
    """Load accepted finding fingerprints from a baseline JSON file."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    entries = data.get("accepted", [])
    result: set[tuple[str, str | None, int | None]] = set()
    for item in entries:
        if isinstance(item, dict):
            file_path = item.get("file")
            if isinstance(file_path, str):
                file_path = normalize_rel_path(file_path)
            result.add((item.get("id", ""), file_path, item.get("line")))
        elif isinstance(item, list) and len(item) >= 1:
            result.add((item[0], item[1] if len(item) > 1 else None, item[2] if len(item) > 2 else None))
    return result


def save_baseline(path: Path, fingerprints: set[tuple[str, str | None, int | None]]) -> None:
    """Write baseline file from fingerprints."""
    accepted = [{"id": fp[0], "file": fp[1], "line": fp[2]} for fp in sorted(fingerprints)]
    path.write_text(json.dumps({"accepted": accepted}, indent=2), encoding="utf-8")


def filter_new_findings(
    findings: list[Finding],
    baseline: set[tuple[str, str | None, int | None]],
) -> list[Finding]:
    """Return findings not present in the baseline."""
    return [f for f in findings if finding_fingerprint(f) not in baseline]


def merge_into_baseline(
    existing: set[tuple[str, str | None, int | None]],
    findings: list[Finding],
) -> set[tuple[str, str | None, int | None]]:
    """Add all current findings to the baseline set."""
    updated = set(existing)
    for f in findings:
        updated.add(finding_fingerprint(f))
    return updated
