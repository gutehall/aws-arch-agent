"""Read IAM policy documents in CloudFormation shape and find over-broad Allow statements.

A document is a dict with a `Statement` (one statement or a list). Values the scan
cannot know are not plain `str`: CloudFormation intrinsics are dicts, and Terraform
references and variables are str subclasses or markers. `literals` skips them, so they
never compare equal to "*" and a statement is never flagged on a guess.

Allow statements with NotAction or NotResource are not analyzed yet.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# Action verbs that only read. "s3:Get*" is a read wildcard; "s3:*" is not.
_READ_VERB = re.compile(
    r"^(Get|List|Describe|Head|Lookup|Search|View|BatchGet|Query|Scan|Select|Check|"
    r"Validate|Simulate|Estimate|Preview|Test|Read|Discover)",
    re.IGNORECASE,  # IAM action names are case-insensitive
)

# Write actions that have no resource-level permissions, so Resource "*" is the only
# option. Flagging them would be noise on every Lambda with tracing or a VPC config.
NO_RESOURCE_LEVEL: frozenset[str] = frozenset({
    "xray:puttracesegments",
    "xray:puttelemetryrecords",
    "cloudwatch:putmetricdata",
    "ec2:createnetworkinterface",
    "ec2:deletenetworkinterface",
    "ec2:assignprivateipaddresses",
    "ec2:unassignprivateipaddresses",
})


@dataclass(frozen=True)
class Broad:
    """The broadest problem found in one policy document."""

    kind: str  # "all_actions" | "service_actions" | "write_on_all_resources"
    actions: tuple[str, ...]


def as_document(value: Any) -> dict | None:
    """A policy document dict, or None when it is absent, unknown, or not a policy.

    Accepts a dict or a JSON string (Terraform plans and *.tf.json store JSON text).
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if not isinstance(value, dict):
        return None
    return value if "Statement" in value else None


def statements(doc: dict) -> list[dict]:
    raw = doc.get("Statement")
    if isinstance(raw, dict):
        raw = [raw]
    return [s for s in raw if isinstance(s, dict)] if isinstance(raw, list) else []


def literals(value: Any) -> list[str]:
    """Known string values of a field. Unknown entries are skipped."""
    items = value if isinstance(value, list) else [value]
    return [v for v in items if type(v) is str]


def _is_allow(stmt: dict) -> bool:
    return stmt.get("Effect") == "Allow"


def is_read_action(action: str) -> bool:
    _service, _, verb = action.partition(":")
    return bool(verb) and bool(_READ_VERB.match(verb))


def broadest(doc: dict) -> list[Broad]:
    """Return one Broad per kind found, broadest kinds only once.

    all_actions: an Allow with Action "*".
    service_actions: an Allow with "<service>:*".
    write_on_all_resources: an Allow with Resource "*" and a write action that supports
    resource-level permissions. Statements already reported as all_actions or
    service_actions are not reported again here.
    """
    found: dict[str, set[str]] = {}
    for stmt in statements(doc):
        if not _is_allow(stmt):
            continue
        actions = literals(stmt.get("Action"))
        if "*" in actions:
            found.setdefault("all_actions", set()).add("*")
            continue
        service_wide = sorted(a for a in actions if a.endswith(":*"))
        if service_wide:
            found.setdefault("service_actions", set()).update(service_wide)
            continue
        if "*" not in literals(stmt.get("Resource")):
            continue
        writes = sorted(
            a for a in actions
            if not is_read_action(a) and a.lower() not in NO_RESOURCE_LEVEL
        )
        if writes:
            found.setdefault("write_on_all_resources", set()).update(writes)
    order = ("all_actions", "service_actions", "write_on_all_resources")
    return [Broad(kind, tuple(sorted(found[kind]))) for kind in order if kind in found]


# --- role trust policies -------------------------------------------------------

# Services that assume a role on behalf of other resources, possibly in other accounts,
# so a trust without aws:SourceAccount or aws:SourceArn is open to the confused deputy.
# Compute execution roles (lambda, ec2, ecs-tasks, ...) are not listed: they act for
# one resource in the same account.
CONFUSED_DEPUTY_SERVICES: frozenset[str] = frozenset({
    "backup", "cloudtrail", "config", "datasync", "delivery.logs", "events", "firehose",
    "logs", "s3", "scheduler", "sns", "ssm", "transfer",
})
_SOURCE_KEYS = frozenset({"aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths"})
GITHUB_OIDC = "token.actions.githubusercontent.com"
_ACCOUNT = re.compile(r"^(?:arn:aws[\w-]*:iam::)?(\d{12})(?::|$)")


@dataclass(frozen=True)
class Trust:
    """One kind of over-open trust found in a role's trust policy."""

    kind: str  # "anyone" | "cross_account" | "service" | "github_oidc"
    principals: tuple[str, ...]


def _assumes(stmt: dict) -> bool:
    actions = [a.lower() for a in literals(stmt.get("Action"))]
    return any(a in ("*", "sts:*") or a.startswith("sts:assumerole") for a in actions)


def _condition_keys(stmt: dict) -> set[str] | None:
    """Lowercased condition keys under any operator, or None when the Condition is unknown."""
    condition = stmt.get("Condition")
    if condition is None:
        return set()
    if not isinstance(condition, dict):
        return None
    keys: set[str] = set()
    for operator, body in condition.items():
        if type(operator) is not str or not isinstance(body, dict):
            return None
        keys.update(k.lower() for k in body if type(k) is str)
    return keys


def _principal_values(principal: Any, key: str) -> list[str]:
    if isinstance(principal, dict):
        return literals(principal.get(key))
    return []


def trust_problems(doc: dict) -> list[Trust]:
    """Over-open Allow statements in a role trust policy, one Trust per kind.

    anyone: Principal "*" or {"AWS": "*"} with no condition at all.
    cross_account: a literal account principal without an sts:ExternalId condition. A
    template rarely knows its own account, so a literal account id is taken as another.
    service: a CONFUSED_DEPUTY_SERVICES principal without aws:SourceAccount/SourceArn.
    github_oidc: GitHub Actions OIDC without a condition on the token's sub.
    Unknown principals, actions or conditions give nothing.
    """
    found: dict[str, set[str]] = {}
    for stmt in statements(doc):
        if stmt.get("Effect") != "Allow" or "NotPrincipal" in stmt or not _assumes(stmt):
            continue
        keys = _condition_keys(stmt)
        if keys is None:
            continue
        principal = stmt.get("Principal")
        # {"*": ["*"]} is how data "aws_iam_policy_document" writes `type = "*"`.
        aws = ["*"] if principal == "*" else (
            _principal_values(principal, "AWS") + _principal_values(principal, "*")
        )
        if "*" in aws and not keys:
            found.setdefault("anyone", set()).add("*")
        if "sts:externalid" not in keys:
            accounts = {m.group(1) for m in map(_ACCOUNT.match, aws) if m}
            found.setdefault("cross_account", set()).update(accounts)
        if not keys & _SOURCE_KEYS:
            for service in _principal_values(principal, "Service"):
                name = service.lower().removesuffix(".amazonaws.com")
                if name in CONFUSED_DEPUTY_SERVICES:
                    found.setdefault("service", set()).add(service)
        federated = principal.get("Federated") if isinstance(principal, dict) else None
        if GITHUB_OIDC in json.dumps(federated, default=str) and f"{GITHUB_OIDC}:sub" not in keys:
            found.setdefault("github_oidc", set()).add(GITHUB_OIDC)
    order = ("anyone", "github_oidc", "cross_account", "service")
    return [Trust(kind, tuple(sorted(found[kind]))) for kind in order if found.get(kind)]
