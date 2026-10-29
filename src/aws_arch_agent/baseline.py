"""Baseline / suppression support for gradual CI adoption."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from aws_arch_agent.models import Finding
from aws_arch_agent.tools.paths import normalize_rel_path

DEFAULT_BASELINE_NAME = ".aws-arch-agent-baseline.json"

Fingerprint = tuple[str, str | None, int | None]


class BaselineError(ValueError):
    """Baseline file is unreadable or invalid."""


def finding_fingerprint(f: Finding) -> Fingerprint:
    """Stable key for baseline matching."""
    return (f.id, normalize_rel_path(f.file), f.line)


def _coerce_line(value: Any) -> int | None:
    """Accept int, numeric string, or null. "15" matches 15."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise BaselineError(f"baseline line must be an integer or null, got {value!r}")
    if isinstance(value, int):
        return value
    text = value.strip()
    try:
        return int(text)
    except ValueError as exc:
        raise BaselineError(f"baseline line must be an integer or null, got {value!r}") from exc


def _sort_key(fp: Fingerprint) -> tuple[str, str, bool, int]:
    """Order None lines after numbered lines without comparing None to int."""
    rule_id, file_path, line = fp
    return (rule_id, file_path or "", line is None, line if line is not None else 0)


def _entry_fingerprint(item: Any) -> Fingerprint:
    if isinstance(item, dict):
        rule_id = item.get("id", "")
        file_path = item.get("file")
        line_value = item.get("line")
    elif isinstance(item, list) and item:
        rule_id = item[0]
        file_path = item[1] if len(item) > 1 else None
        line_value = item[2] if len(item) > 2 else None
    else:
        raise BaselineError(f"baseline accepted entry is invalid: {item!r}")
    if not isinstance(rule_id, str):
        raise BaselineError(f"baseline id must be a string, got {rule_id!r}")
    if file_path is not None:
        if not isinstance(file_path, str):
            raise BaselineError(f"baseline file must be a string or null, got {file_path!r}")
        file_path = normalize_rel_path(file_path)
    return (rule_id, file_path, _coerce_line(line_value))


def load_baseline(path: Path) -> set[Fingerprint]:
    """Load accepted finding fingerprints from a baseline JSON file.

    A missing file is an empty set. A corrupt file raises BaselineError.
    """
    if not path.exists():
        return set()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"Failed to read baseline {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"Corrupt baseline {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError(f"Corrupt baseline {path}: expected a JSON object")
    entries = data.get("accepted", [])
    if not isinstance(entries, list):
        raise BaselineError(f"Corrupt baseline {path}: accepted must be a list")
    return {_entry_fingerprint(item) for item in entries}


def save_baseline(path: Path, fingerprints: set[Fingerprint]) -> None:
    """Write baseline file atomically. A failed write leaves the previous file intact."""
    accepted = [
        {"id": fp[0], "file": fp[1], "line": fp[2]} for fp in sorted(fingerprints, key=_sort_key)
    ]
    payload = json.dumps({"accepted": accepted}, indent=2)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def filter_new_findings(
    findings: list[Finding],
    baseline: set[Fingerprint],
) -> list[Finding]:
    """Return findings not present in the baseline."""
    return [f for f in findings if finding_fingerprint(f) not in baseline]


def merge_into_baseline(
    existing: set[Fingerprint],
    findings: list[Finding],
) -> set[Fingerprint]:
    """Add all current findings to the baseline set."""
    updated = set(existing)
    for f in findings:
        updated.add(finding_fingerprint(f))
    return updated
