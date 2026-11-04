"""Read IAM policy documents in CloudFormation shape and find over-broad Allow statements.

A document is a dict with a `Statement` (one statement or a list). Values the scan
cannot know (CloudFormation intrinsics, Terraform references and variables) are dicts,
so they never compare equal to "*" and a statement is never flagged on a guess.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# Action verbs that only read. "s3:Get*" is a read wildcard; "s3:*" is not.
_READ_VERB = re.compile(
    r"^(Get|List|Describe|Head|Lookup|Search|View|BatchGet|Query|Scan|Select|Check|"
    r"Validate|Simulate|Estimate|Preview|Test|Read|Discover)"
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
