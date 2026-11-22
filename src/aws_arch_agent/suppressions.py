"""Suppress findings where the code says so, and skip rules per path.

Two in-source forms mark a finding as suppressed. The finding stays in the report, labelled,
and does not count for --fail-on:

1. A comment directive on the finding's line or the line just above it, after `#` or `//`:

       # aws-arch-agent: ignore CF-S3-001, CF-S3-003 reason="logs bucket" expires=2027-01-31

   One or more rule IDs, then optional reason="..." and expires=YYYY-MM-DD.
2. CloudFormation resource Metadata, for the findings anchored at that resource's logical ID:

       Metadata:
         aws-arch-agent:
           ignore: [CF-S3-001, {id: CF-S3-003, reason: logs bucket, expires: 2027-01-31}]

A suppression is active through its expires day. Past it, the finding is reported again and
the scan warns. A malformed directive or Metadata entry is a warning and suppresses nothing.

Config `rules.exclude_paths` is separate: it drops findings of the listed rules in files whose
repo-relative path matches a glob, like `rules.exclude` does for the whole repo.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Literal

from aws_arch_agent.models import Finding, Suppression
from aws_arch_agent.rules.environments import _glob
from aws_arch_agent.tools.cfn_yaml import parse_template_with_lines
from aws_arch_agent.tools.files import read_text_safe
from aws_arch_agent.tools.paths import normalize_rel_path

_DIRECTIVE = re.compile(r"(?:#|//)\s*aws-arch-agent\s*:\s*ignore(?![\w-])(?P<rest>.*)$", re.IGNORECASE)
_REASON = re.compile(r"""(?<![\w-])reason\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')""", re.IGNORECASE)
_EXPIRES = re.compile(r"(?<![\w-])expires\s*=\s*(?P<value>\S*)", re.IGNORECASE)
_RULE_ID = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# A trailing block-comment close or end of a JS comment is not part of the directive.
_TAIL = re.compile(r"\s*(?:\*/|-->)\s*$")
_TEMPLATE_SUFFIXES = {".json", ".yaml", ".yml", ".template"}
_METADATA_KEY = "aws-arch-agent"


class _Rule:
    """One suppression for a set of rule IDs, from one directive or Metadata entry."""

    __slots__ = ("ids", "kind", "reason", "expires")

    def __init__(
        self,
        ids: Iterable[str],
        kind: Literal["inline", "metadata"],
        reason: str | None,
        expires: date | None,
    ):
        self.ids = {i.upper() for i in ids}
        self.kind: Literal["inline", "metadata"] = kind
        self.reason = reason
        self.expires = expires

    def model(self) -> Suppression:
        return Suppression(
            kind=self.kind,
            reason=self.reason,
            expires=self.expires.isoformat() if self.expires else None,
        )


def _parse_date(value: str) -> date | None:
    if not _DATE.fullmatch(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def parse_directive(line: str) -> _Rule | str | None:
    """The directive in one source line: a rule, an error message, or None when there is none."""
    match = _DIRECTIVE.search(line)
    if match is None:
        return None
    rest = _TAIL.sub("", match.group("rest"))
    reason: str | None = None
    expires: date | None = None
    reason_match = _REASON.search(rest)
    if reason_match:
        reason = reason_match.group("dq") if reason_match.group("dq") is not None else reason_match.group("sq")
        rest = rest[: reason_match.start()] + " " + rest[reason_match.end():]
    expires_match = _EXPIRES.search(rest)
    if expires_match:
        raw = expires_match.group("value")
        expires = _parse_date(raw)
        if expires is None:
            return f"expires must be a date as YYYY-MM-DD, got {raw!r}"
        rest = rest[: expires_match.start()] + " " + rest[expires_match.end():]
    tokens = [t for t in re.split(r"[\s,]+", rest) if t]
    if not tokens:
        return "no rule IDs after ignore"
    bad = [t for t in tokens if not _RULE_ID.fullmatch(t)]
    if bad:
        return f"not a rule ID: {bad[0]!r}"
    return _Rule(tokens, "inline", reason or None, expires)


def _metadata_rules(resource: Any) -> tuple[list[_Rule], list[str]]:
    """The rules in one resource's Metadata, and what was malformed in it."""
    if not isinstance(resource, Mapping):
        return [], []
    metadata = resource.get("Metadata")
    if not isinstance(metadata, Mapping) or _METADATA_KEY not in metadata:
        return [], []
    block = metadata[_METADATA_KEY]
    if not isinstance(block, Mapping) or not isinstance(block.get("ignore"), list):
        return [], [f"Metadata.{_METADATA_KEY} must be a mapping with an ignore list"]
    rules: list[_Rule] = []
    errors: list[str] = []
    for entry in block["ignore"]:
        if isinstance(entry, str) and _RULE_ID.fullmatch(entry.strip()):
            rules.append(_Rule([entry.strip()], "metadata", None, None))
            continue
        if not isinstance(entry, Mapping):
            errors.append(f"ignore entry must be a rule ID or a mapping with id, got {entry!r}")
            continue
        rule_id, reason, raw_expires = entry.get("id"), entry.get("reason"), entry.get("expires")
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id.strip()):
            errors.append(f"ignore entry needs id as a rule ID, got {rule_id!r}")
            continue
        if reason is not None and not isinstance(reason, str):
            errors.append(f"reason of {rule_id} must be a string, got {reason!r}")
            continue
        expires: date | None = None
        if raw_expires is not None:
            # YAML reads an unquoted 2027-01-31 as a date.
            if isinstance(raw_expires, datetime):  # an unquoted timestamp
                expires = raw_expires.date()
            elif isinstance(raw_expires, date):
                expires = raw_expires
            elif isinstance(raw_expires, str):
                expires = _parse_date(raw_expires.strip())
            if expires is None:
                errors.append(f"expires of {rule_id} must be a date as YYYY-MM-DD, got {raw_expires!r}")
                continue
        rules.append(_Rule([rule_id.strip()], "metadata", reason or None, expires))
    return rules, errors


class _FileIndex:
    """Directives and Metadata of one file, read once."""

    def __init__(self, path: Path):
        # Split on "\n" only: finding lines count "\n", and splitlines() also breaks on \f,
        # \x1c and others, which would put a directive on the wrong line.
        self._text = read_text_safe(path)
        self.lines = [line.rstrip("\r") for line in self._text.split("\n")]
        self._directives: dict[int, _Rule | str | None] = {}
        self._metadata: dict[int, tuple[str, list[_Rule], list[str]]] | None = None
        self._path = path

    def directive(self, line: int) -> _Rule | str | None:
        """The directive on a 1-based line."""
        if line not in self._directives:
            text = self.lines[line - 1] if 1 <= line <= len(self.lines) else ""
            self._directives[line] = parse_directive(text) if "aws-arch-agent" in text.lower() else None
        return self._directives[line]

    def metadata(self, line: int) -> tuple[str, list[_Rule], list[str]] | None:
        """(logical ID, rules, errors) of the resource whose logical ID is on this line."""
        if self._metadata is None:
            self._metadata = {}
            if self._path.suffix.lower() in _TEMPLATE_SUFFIXES and _METADATA_KEY in self._text:
                try:
                    doc, lines = parse_template_with_lines(self._path, self._text)
                except Exception:
                    doc, lines = None, {}
                resources = doc.get("Resources") if isinstance(doc, Mapping) else None
                if isinstance(resources, Mapping):
                    for logical_id, at in lines.items():
                        rules, errors = _metadata_rules(resources.get(logical_id))
                        if rules or errors:
                            self._metadata[at] = (logical_id, rules, errors)
        return self._metadata.get(line)


def _resolve(file: str, repo_path: Path) -> Path:
    path = Path(file)
    return path if path.is_absolute() else repo_path / path


def apply(findings: list[Finding], repo_path: Path, today: date | None = None) -> list[str]:
    """Set Finding.suppression from directives and Metadata; return warnings for expired and
    malformed suppressions. Findings without a file and line cannot be suppressed this way."""
    today = today or date.today()
    indexes: dict[str, _FileIndex] = {}
    warnings: list[str] = []

    def warn(message: str) -> None:
        if message not in warnings:
            warnings.append(message)

    for finding in findings:
        finding.suppression = None
        if not finding.file or not finding.line:
            continue
        index = indexes.get(finding.file)
        if index is None:
            index = indexes[finding.file] = _FileIndex(_resolve(finding.file, repo_path))
        candidates: list[tuple[_Rule, str]] = []
        for line in (finding.line, finding.line - 1):
            if line < 1:
                continue
            found = index.directive(line)
            where = f"{finding.file}:{line}"
            if isinstance(found, str):
                warn(f"Malformed aws-arch-agent ignore directive at {where}: {found}; it suppresses nothing.")
            elif found is not None:
                candidates.append((found, where))
        meta = index.metadata(finding.line)
        if meta is not None:
            logical_id, rules, errors = meta
            where = f"{finding.file}:{finding.line}"
            for error in errors:
                warn(f"Malformed aws-arch-agent Metadata on {logical_id} at {where}: {error}; ignored.")
            candidates.extend((rule, where) for rule in rules)
        rule_id = finding.id.upper()
        for rule, where in candidates:
            if rule_id not in rule.ids:
                continue
            if rule.expires is not None and rule.expires < today:
                warn(
                    f"Suppression of {finding.id} at {where} expired on {rule.expires.isoformat()}; "
                    "the finding is reported again."
                )
                continue
            finding.suppression = rule.model()
            break
    return warnings


def active(findings: Iterable[Finding]) -> list[Finding]:
    """The findings no active suppression covers: the ones --fail-on counts."""
    return [f for f in findings if f.suppression is None]


def exclude_by_path(
    findings: list[Finding], exclude_paths: Mapping[str, list[str]] | None
) -> list[Finding]:
    """Drop findings of the rules config `rules.exclude_paths` lists for the finding's file."""
    if not exclude_paths:
        return findings
    patterns = [(_glob(pattern), {i.upper() for i in ids}) for pattern, ids in exclude_paths.items()]
    kept: list[Finding] = []
    for finding in findings:
        path = normalize_rel_path(finding.file)
        if path and any(finding.id.upper() in ids and glob.match(path) for glob, ids in patterns):
            continue
        kept.append(finding)
    return kept
