"""Baseline / suppression support for gradual CI adoption."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, NamedTuple

from aws_arch_agent.models import Finding
from aws_arch_agent.tools.paths import normalize_rel_path

DEFAULT_BASELINE_NAME = ".aws-arch-agent-baseline.json"


class Fingerprint(NamedTuple):
    """Identity of an accepted finding.

    ``evidence_hash`` distinguishes two findings in one file. ``match_file`` is
    set only when loading an older entry that stored a line and no evidence, so
    that entry still matches after the line moves.
    """

    rule_id: str
    file: str | None
    evidence_hash: str | None
    logical_id: str | None = None
    match_file: bool = False


class BaselineError(ValueError):
    """Baseline file is unreadable or invalid."""


def _evidence_hash(evidence: str | None) -> str | None:
    if not evidence:
        return None
    return hashlib.sha256(evidence.encode()).hexdigest()[:16]


def finding_fingerprint(f: Finding) -> Fingerprint:
    """Stable key for baseline matching. The line number is not part of the key."""
    evidence = f.evidence if isinstance(f.evidence, str) and f.evidence else None
    return Fingerprint(
        f.id,
        normalize_rel_path(f.file),
        _evidence_hash(evidence),
        evidence,
    )


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


def _sort_key(fp: Fingerprint) -> tuple[str, str, str, str, bool]:
    return (
        fp.rule_id,
        fp.file or "",
        fp.evidence_hash or "",
        fp.logical_id or "",
        fp.match_file,
    )


def _logical_id(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise BaselineError(f"baseline logical_id must be a string, got {value!r}")
    return value


def _stored_hash(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise BaselineError(f"baseline evidence_hash must be a string, got {value!r}")
    return value


def _fingerprint_from_parts(
    rule_id: str,
    file_path: str | None,
    line: int | None,
    logical_id: str | None,
    evidence_hash: str | None,
    *,
    has_evidence_hash: bool,
) -> Fingerprint:
    if has_evidence_hash:
        return Fingerprint(rule_id, file_path, evidence_hash, logical_id)
    if logical_id is not None:
        return Fingerprint(rule_id, file_path, _evidence_hash(logical_id), logical_id)
    # Older static entries stored a line and no evidence. Match the file, not the line.
    if line is not None:
        return Fingerprint(rule_id, file_path, None, None, True)
    return Fingerprint(rule_id, file_path, None)


def _entry_fingerprint(item: Any) -> Fingerprint:
    logical_value: Any = None
    evidence_value: Any = None
    has_evidence_hash = False
    if isinstance(item, dict):
        rule_id = item.get("id", "")
        file_path = item.get("file")
        line_value = item.get("line") if "line" in item else None
        if "logical_id" in item:
            logical_value = item.get("logical_id")
        if "evidence_hash" in item:
            has_evidence_hash = True
            evidence_value = item.get("evidence_hash")
    elif isinstance(item, list) and item:
        rule_id = item[0]
        file_path = item[1] if len(item) > 1 else None
        line_value = item[2] if len(item) > 2 else None
        if len(item) > 3:
            logical_value = item[3]
    else:
        raise BaselineError(f"baseline accepted entry is invalid: {item!r}")
    if not isinstance(rule_id, str):
        raise BaselineError(f"baseline id must be a string, got {rule_id!r}")
    if file_path is not None:
        if not isinstance(file_path, str):
            raise BaselineError(f"baseline file must be a string or null, got {file_path!r}")
        file_path = normalize_rel_path(file_path)
    return _fingerprint_from_parts(
        rule_id,
        file_path,
        _coerce_line(line_value),
        _logical_id(logical_value),
        _stored_hash(evidence_value) if has_evidence_hash else None,
        has_evidence_hash=has_evidence_hash,
    )


def load_baseline(path: Path) -> set[Fingerprint]:
    """Load accepted finding fingerprints from a baseline JSON file.

    A missing file is an empty set. A corrupt file raises BaselineError.
    Older files that stored a line number still load. The line is not used as a key.
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
        entry: dict[str, Any] = {
            "id": fp.rule_id,
            "file": fp.file,
            "evidence_hash": fp.evidence_hash,
        }
        if fp.logical_id is not None:
            entry["logical_id"] = fp.logical_id
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

    An older absolute path matches the same repo-relative path. An entry that
    only stored a line matches the same id and file at any line. An entry with
    no evidence does not match a finding that has evidence, so one accepted
    bucket cannot hide every other bucket in the template.
    """
    fp = finding_fingerprint(finding)
    if fp in baseline:
        return True
    for item in baseline:
        if item.rule_id != fp.rule_id or not _files_match(item.file, fp.file):
            continue
        if item.match_file:
            return True
        if item.evidence_hash is not None and item.evidence_hash == fp.evidence_hash:
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
