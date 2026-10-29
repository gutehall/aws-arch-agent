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

# Static findings: (id, file, line). CloudFormation findings have no line, so the
# fourth element is the evidence string (logical id plus resource type).
Fingerprint = tuple[str, str | None, int | None] | tuple[str, str | None, int | None, str]


class BaselineError(ValueError):
    """Baseline file is unreadable or invalid."""


def finding_fingerprint(f: Finding) -> Fingerprint:
    """Stable key for baseline matching.

    Findings with a line stay (id, file, line). CloudFormation findings have no
    line, so they also include evidence. Two resources of one rule stay distinct.
    """
    file_path = normalize_rel_path(f.file)
    if f.line is None and f.evidence and f.id.startswith("CF-"):
        return (f.id, file_path, None, f.evidence)
    return (f.id, file_path, f.line)


def _parts(fp: tuple) -> tuple[str, str | None, int | None, str | None]:
    qualifier = fp[3] if len(fp) > 3 else None
    return (fp[0], fp[1], fp[2], qualifier)


def _files_match(baseline_file: str | None, finding_file: str | None) -> bool:
    """Match a stored path to a finding path.

    Two relative paths match only when equal. An older absolute path matches
    the repo-relative path when the absolute path ends with it.
    """
    stored = normalize_rel_path(baseline_file)
    current = normalize_rel_path(finding_file)
    if stored == current:
        return True
    if not stored or not current:
        return False
    stored_abs = stored.startswith("/")
    current_abs = current.startswith("/")
    if stored_abs == current_abs:
        return False
    longer, shorter = (stored, current) if stored_abs else (current, stored)
    return longer.endswith("/" + shorter)


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


def _sort_key(fp: Fingerprint) -> tuple[str, str, bool, int, str]:
    """Order None lines after numbered lines without comparing None to int."""
    rule_id, file_path, line, qualifier = _parts(fp)
    return (rule_id, file_path or "", line is None, line if line is not None else 0, qualifier or "")


def _qualifier(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise BaselineError(f"baseline logical_id must be a string, got {value!r}")
    return value


def _entry_fingerprint(item: Any) -> Fingerprint:
    qualifier_value: Any = None
    if isinstance(item, dict):
        rule_id = item.get("id", "")
        file_path = item.get("file")
        line_value = item.get("line")
        if "logical_id" in item:
            qualifier_value = item.get("logical_id")
    elif isinstance(item, list) and item:
        rule_id = item[0]
        file_path = item[1] if len(item) > 1 else None
        line_value = item[2] if len(item) > 2 else None
        if len(item) > 3:
            qualifier_value = item[3]
    else:
        raise BaselineError(f"baseline accepted entry is invalid: {item!r}")
    if not isinstance(rule_id, str):
        raise BaselineError(f"baseline id must be a string, got {rule_id!r}")
    if file_path is not None:
        if not isinstance(file_path, str):
            raise BaselineError(f"baseline file must be a string or null, got {file_path!r}")
        file_path = normalize_rel_path(file_path)
    qualifier = _qualifier(qualifier_value)
    line = _coerce_line(line_value)
    if qualifier is None:
        return (rule_id, file_path, line)
    return (rule_id, file_path, line, qualifier)


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
    accepted = []
    for fp in sorted(fingerprints, key=_sort_key):
        rule_id, file_path, line, qualifier = _parts(fp)
        entry: dict[str, Any] = {"id": rule_id, "file": file_path, "line": line}
        if qualifier is not None:
            entry["logical_id"] = qualifier
        accepted.append(entry)
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


def is_baselined(finding: Finding, baseline: set[Fingerprint]) -> bool:
    """True when this finding was accepted.

    An older absolute path matches the same repo-relative path. An entry with
    no logical id does not match a line-less finding, so one accepted bucket
    cannot hide every other bucket in the template.
    """
    fp = finding_fingerprint(finding)
    if fp in baseline:
        return True
    rule_id, file_path, line, qualifier = _parts(fp)
    for item in baseline:
        accepted_id, accepted_file, accepted_line, accepted_qualifier = _parts(item)
        if accepted_id != rule_id or accepted_line != line:
            continue
        if not _files_match(accepted_file, file_path):
            continue
        if accepted_qualifier is None and qualifier is not None:
            continue
        if accepted_qualifier == qualifier:
            return True
    return False


def filter_new_findings(
    findings: list[Finding],
    baseline: set[Fingerprint],
) -> list[Finding]:
    """Return findings not present in the baseline."""
    return [f for f in findings if not is_baselined(f, baseline)]


def merge_into_baseline(
    existing: set[Fingerprint],
    findings: list[Finding],
) -> set[Fingerprint]:
    """Add all current findings to the baseline set."""
    updated = set(existing)
    for f in findings:
        updated.add(finding_fingerprint(f))
    return updated
