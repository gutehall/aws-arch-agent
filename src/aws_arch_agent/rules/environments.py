"""Which environment a stack is for, and rules that depend on it (DM3-544).

A stack is one CloudFormation template (cdk synth output included) or one Terraform root
module. Its environment is, in order:

1. config `environments`: the first key that matches. A key is a glob matched against the
   stack's repo-relative path and its name (`infra/dev/**`, `*-prod*`), or `tag:<value>`
   for an Environment tag value. Values are prod, staging or dev.
2. the stack's Environment tag, when every tagged resource in it agrees on one value.
3. common words in the path, file or stack name: prod, production, prd; staging, stage,
   stg, uat; dev, development, test, qa, sandbox, sbx. If words for more than one
   environment appear, prod wins over staging over dev.

Otherwise it is unknown, which is judged as prod: a missed prod finding is worse than an
extra dev one. Terraform workspaces exist only at run time; match the directory instead.
"""
from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, List, Literal, cast

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules.resource_model import Resource

Environment = Literal["prod", "staging", "dev"]
Judged = Literal["prod", "staging", "dev", "unknown"]
ENVIRONMENTS: tuple[Environment, ...] = ("prod", "staging", "dev")

_WORDS: dict[str, Environment] = {
    **{w: "prod" for w in ("prod", "production", "prd", "live")},
    **{w: "staging" for w in ("staging", "stage", "stg", "uat", "preprod")},
    **{w: "dev" for w in ("dev", "development", "test", "testing", "qa", "sandbox", "sbx")},
}

# Rules that depend on the environment: None skips the rule there, a severity replaces it.
# Not listed: judged the same everywhere. Unknown and prod are never changed.
RULE_POLICY: dict[str, dict[Environment, Severity | None]] = {
    # Production durability advice that is wrong for a throwaway stack.
    "CF-RDS-003": {"dev": None},           # Multi-AZ
    "CF-RDS-005": {"dev": None},           # deletion protection
    "CF-DEL-001": {"dev": None},           # retain on delete
    "CF-RDS-002": {"dev": "Low"},          # backup retention
    "CF-DDB-001": {"dev": "Low"},          # point-in-time recovery
    "CF-S3-003": {"dev": "Low"},           # versioning
}

_config: dict[str, Environment] = {}
_repo_path: Path | None = None


@contextmanager
def use_environments(config: Mapping[str, str] | None, repo_path: Path | None) -> Iterator[None]:
    """Resolve environments with this config, relative to this repo, for a scan."""
    global _config, _repo_path
    previous = (_config, _repo_path)
    _config = {k: cast(Environment, v) for k, v in (config or {}).items()}
    _repo_path = repo_path
    try:
        yield
    finally:
        _config, _repo_path = previous


def _words(text: str) -> list[str]:
    """Lowercase words of a path or name: MyAppDevStack -> my app dev stack."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w]


def from_words(*texts: str) -> Environment | None:
    found = {_WORDS[w] for text in texts for w in _words(text) if w in _WORDS}
    for env in ENVIRONMENTS:  # prod first
        if env in found:
            return env
    return None


def _stack_name(template_path: Path) -> str:
    name = template_path.name
    return name[: -len(".template.json")] if name.endswith(".template.json") else template_path.stem


def _relative(template_path: Path) -> str:
    """The path inside the repo. Directories above the repo say nothing about the
    environment, so outside a scan (no repo) or outside the repo only the file name counts."""
    if _repo_path is not None:
        try:
            return template_path.resolve().relative_to(_repo_path.resolve()).as_posix()
        except ValueError:
            pass
    return template_path.name


def _tag_value(resources: Iterable[Resource]) -> str | None:
    """The Environment tag every tagged resource in the stack agrees on, if any."""
    values: set[str] = set()
    for res in resources:
        tags = res.properties.get("Tags")
        pairs: dict[Any, Any] = {}
        if isinstance(tags, dict):
            pairs = tags
        elif isinstance(tags, list):
            pairs = {t.get("Key"): t.get("Value") for t in tags if isinstance(t, dict)}
        merged = {**(res.inherited_tags or {}), **pairs}
        value = merged.get("Environment")
        if isinstance(value, str):
            values.add(value)
    return values.pop() if len(values) == 1 else None


def resolve(template_path: Path, resources: Iterable[Resource]) -> Judged:
    resources = list(resources)
    path, name = _relative(template_path), _stack_name(template_path)
    tag = _tag_value(resources)
    for key, env in _config.items():
        if key.startswith("tag:"):
            if tag is not None and tag == key[4:]:
                return env
        elif fnmatch.fnmatchcase(path, key) or fnmatch.fnmatchcase(name, key):
            return env
    if tag is not None:
        by_tag = from_words(tag)
        if by_tag is not None:
            return by_tag
    return from_words(path, name) or "unknown"


def apply(findings: List[Finding], template_path: Path, resources: Iterable[Resource]) -> List[Finding]:
    """Record the stack's environment on each finding and apply RULE_POLICY.

    Returns the findings the environment keeps (some are skipped in dev).
    """
    env = resolve(template_path, resources)
    out: List[Finding] = []
    for f in findings:
        f.environment = env
        if env != "unknown" and env != "prod":
            policy = RULE_POLICY.get(f.id, {})
            if env in policy:
                severity = policy[env]
                if severity is None:
                    continue
                f.severity = severity
        out.append(f)
    return out
