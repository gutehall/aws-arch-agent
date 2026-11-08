"""Which environment a stack is for, and rules that depend on it.

A stack is one CloudFormation template (cdk synth output included) or one Terraform root
module. Its environment is, in order:

1. config `environments`: the first key that matches decides. A key is a glob matched
   against the stack's repo-relative path and its name (`infra/dev/**`, `*-prod*`; `*`
   stays in one segment, `**` spans them), or `tag:<value>` for an Environment tag value.
   Values are prod, staging or dev.
2. otherwise the most-prod of the stack's signals: its Environment tag values, and common
   words in the path, file or stack name (prod, production, prd, live; staging, stage,
   stg, uat, preprod; dev, development, test, testing, qa, sandbox, sbx). An Environment
   tag the scan cannot read, or does not recognise, counts as prod.

With no signal it is unknown, which is judged as prod: a missed prod finding is worse than
an extra dev one. Terraform workspaces exist only at run time; match the directory instead.
"""
from __future__ import annotations

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
    # Multi-AZ and retain-on-delete are prod-only: CF-ENV-001 says the opposite in dev and
    # staging, so no stack gets both pieces of advice.
    "CF-RDS-003": {"dev": None, "staging": None},  # Multi-AZ
    "CF-RDS-005": {"dev": None},           # deletion protection
    "CF-DEL-001": {"dev": None, "staging": None},  # retain on delete
    "CF-OS-007": {"dev": None, "staging": None},  # three data nodes across zones
    # Never-expiring logs: CF-ENV-005 asks for 30 days or less there instead of 30-365.
    "CF-CW-001": {"dev": None, "staging": None},
    # DynamoDB autoscaling: CF-ENV-006 says on demand there instead.
    "CF-DDB-003": {"dev": None, "staging": None},
    "CF-RDS-002": {"dev": "Low"},          # backup retention
    "CF-DDB-001": {"dev": "Low"},          # point-in-time recovery
    "CF-S3-003": {"dev": "Low"},           # versioning
}

# CDK source rules that recommend production durability. They cannot see a stack, so they
# are dropped when every stack the scan resolved is dev or staging.
# COST-003 (DynamoDB autoscaling) is dropped too: CF-ENV-006 says use on demand instead.
PROD_ONLY_STATIC = ("REL-001", "REL-016", "COST-003")

_config: dict[str, Environment] = {}
_repo_path: Path | None = None
_seen: set[str] = set()  # environments resolved for stacks in this scan
_seen_outside_synth = False  # a stack not from cdk.out (e.g. --templates) was resolved


def only_nonprod() -> bool:
    """True when every stack of the CDK app is dev or staging.

    Only cdk synth output covers the whole app; with --templates the scan may see only
    some stacks, so the CDK source rules are kept then.
    """
    return bool(_seen) and _seen <= {"dev", "staging"} and not _seen_outside_synth


@contextmanager
def use_environments(config: Mapping[str, str] | None, repo_path: Path | None) -> Iterator[None]:
    """Resolve environments with this config, relative to this repo, for a scan."""
    global _config, _repo_path, _seen, _seen_outside_synth
    previous = (_config, _repo_path, _seen, _seen_outside_synth)
    _config = {k: cast(Environment, v) for k, v in (config or {}).items()}
    _repo_path = repo_path
    _seen, _seen_outside_synth = set(), False
    try:
        yield
    finally:
        _config, _repo_path, _seen, _seen_outside_synth = previous


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


_RANK: dict[Environment, int] = {"prod": 0, "staging": 1, "dev": 2}


def _most_prod(candidates: Iterable[Environment]) -> Environment | None:
    found: list[Environment] = list(candidates)
    if not found:
        return None
    return sorted(found, key=lambda env: _RANK[env])[0]


def _tag_values(resources: Iterable[Resource]) -> tuple[set[str], bool]:
    """Literal Environment tag values in the stack, and whether any was unreadable."""
    values: set[str] = set()
    unreadable = False
    for res in resources:
        if "Tags" in res.unresolved or res.inherited_tags is None:
            unreadable = True  # tags from a variable: Environment may be anything
            continue
        tags = res.properties.get("Tags")
        pairs: dict[Any, Any] = {}
        if isinstance(tags, dict):
            if tags and all(k == "Ref" or str(k).startswith("Fn::") for k in tags):
                unreadable = True
                continue
            pairs = tags
        elif isinstance(tags, list):
            pairs = {t.get("Key"): t.get("Value") for t in tags if isinstance(t, dict)}
        merged = {**(res.inherited_tags or {}), **pairs}
        if "Environment" in merged:
            value = merged["Environment"]
            if type(value) is str:
                values.add(value)
            else:
                unreadable = True  # a Ref, Fn::If, var.env: not judged as anything but prod
    return values, unreadable


def _glob(pattern: str) -> re.Pattern[str]:
    """A path glob where * and ? stay inside one segment and ** spans segments."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def resolve(template_path: Path, resources: Iterable[Resource]) -> Judged:
    """Config wins outright. Otherwise the most-prod signal among tags and names wins,
    and an Environment tag the scan cannot read counts as prod."""
    resources = list(resources)
    path, name = _relative(template_path), _stack_name(template_path)
    values, unreadable = _tag_values(resources)
    for key, env in _config.items():
        if key.startswith("tag:"):
            if key[4:] in values:
                return env
        elif _glob(key).match(path) or _glob(key).match(name):
            return env
    signals: list[Environment] = []
    if unreadable:
        signals.append("prod")
    for value in values:
        by_tag = from_words(value)
        signals.append(by_tag if by_tag is not None else "prod")  # an unrecognised value: prod
    by_name = from_words(path, name)
    if by_name is not None:
        signals.append(by_name)
    return _most_prod(signals) or "unknown"


def apply(findings: List[Finding], template_path: Path, resources: Iterable[Resource]) -> List[Finding]:
    """Record the stack's environment on each finding and apply RULE_POLICY.

    Returns the findings the environment keeps (some are skipped in dev).
    """
    resources = list(resources)
    env = resolve(template_path, resources)
    if resources:
        global _seen_outside_synth
        _seen.add(env)
        if "cdk.out" not in template_path.parts:
            _seen_outside_synth = True
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
