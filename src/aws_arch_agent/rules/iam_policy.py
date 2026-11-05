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

    kind: str  # "admin" | "all_actions" | "service_actions" | "write_on_all_resources"
    actions: tuple[str, ...]


# The AWS managed policy that grants Action "*" on Resource "*". Exact name only:
# AdministratorAccess-Amplify and AdministratorAccess-AWSElasticBeanstalk are scoped.
ADMIN_POLICY = "AdministratorAccess"
_ADMIN_ARN = re.compile(r"^arn:(?:aws[\w-]*|\$\{[^}]+\}):iam::aws:policy/AdministratorAccess$")
# The ARN inside an intrinsic, e.g. CDK's Fn::Join ["", ["arn:", Ref Partition, ":iam::aws:policy/..."]]
# or Fn::Sub "arn:${AWS::Partition}:iam::aws:policy/...".
_ADMIN_ARN_IN_TEXT = re.compile(r':iam::aws:policy/AdministratorAccess(?=")')


def is_admin_policy_arn(value: Any) -> bool:
    """True when a managed policy ARN, literal or inside an intrinsic, is AdministratorAccess.

    A Terraform template string ("arn:${data.aws_partition.current.partition}:...") is a
    str subclass and is read as text; only the partition may vary. An intrinsic with a
    Fn::If is not guessed: the admin ARN may be only one branch.
    """
    if isinstance(value, str):
        return bool(_ADMIN_ARN.match(value))
    if isinstance(value, dict):
        text = json.dumps(value, default=str)
        return '"Fn::If"' not in text and bool(_ADMIN_ARN_IN_TEXT.search(text))
    return False


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

    admin: an Allow with Action "*" and Resource "*" (full admin access). A document with
    one is not also reported as all_actions.
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
            kind = "admin" if "*" in literals(stmt.get("Resource")) else "all_actions"
            found.setdefault(kind, set()).add("*")
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
    if "admin" in found:
        found.pop("all_actions", None)
    order = ("admin", "all_actions", "service_actions", "write_on_all_resources")
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
# Condition keys that limit who the caller is. Others (aws:SecureTransport, aws:SourceIp)
# still leave a "*" trust open to every account.
_CALLER_KEYS = _SOURCE_KEYS | frozenset({
    "aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
    "aws:userid", "sts:externalid",
})
GITHUB_OIDC = "token.actions.githubusercontent.com"
_GITHUB_SUB = f"{GITHUB_OIDC}:sub"
_ACCOUNT = re.compile(r"^(?:arn:aws[\w-]*:iam::)?(\d{12})(?::|$)")
# The account inside an intrinsic, e.g. CDK AccountPrincipal: Fn::Join [..., ":iam::111122223333:root"].
_ACCOUNT_IN_TEXT = re.compile(r":iam::(\d{12}):")
# config.amazonaws.com, logs.us-east-1.amazonaws.com -> config, logs
_SERVICE = re.compile(r"^(.+?)(?:\.[a-z]{2}(?:-[a-z]+)+-\d)?\.amazonaws\.com(?:\.cn)?$")


@dataclass(frozen=True)
class Trust:
    """One kind of over-open trust found in a role's trust policy."""

    kind: str  # "anyone" | "cross_account" | "service" | "github_oidc"
    principals: tuple[str, ...]


def _assumes(stmt: dict) -> bool:
    """Action grants sts:AssumeRole*. NotAction is not analyzed, as in broadest()."""
    actions = [a.lower() for a in literals(stmt.get("Action"))]
    return any(a in ("*", "sts:*") or a.startswith("sts:assumerole") for a in actions)


def _conditions(stmt: dict) -> dict[str, list[Any]] | None:
    """Lowercased condition key -> its values under any operator, or None when unknown."""
    condition = stmt.get("Condition")
    if condition is None:
        return {}
    if not isinstance(condition, dict):
        return None
    out: dict[str, list[Any]] = {}
    for operator, body in condition.items():
        if type(operator) is not str or not isinstance(body, dict):
            return None
        for key, value in body.items():
            if type(key) is str:
                out.setdefault(key.lower(), []).extend(value if isinstance(value, list) else [value])
    return out


def _principal_values(principal: Any, key: str) -> list[str]:
    if isinstance(principal, dict):
        return literals(principal.get(key))
    return []


def _accounts(principal: Any) -> set[str]:
    """Account ids named by AWS principals, literal or inside an intrinsic."""
    if not isinstance(principal, dict):
        return set()
    raw = principal.get("AWS")
    found: set[str] = set()
    for value in raw if isinstance(raw, list) else [raw]:
        if type(value) is str:
            match = _ACCOUNT.match(value)
            if match:
                found.add(match.group(1))
        elif isinstance(value, dict):
            found.update(_ACCOUNT_IN_TEXT.findall(json.dumps(value, default=str)))
    return found


def _any_repository(values: list[Any]) -> bool:
    """True when a GitHub sub condition still matches every repository."""
    if not values or any(type(v) is not str for v in values):
        return not values
    return all(v == "*" or v.lower().startswith("repo:*") for v in values)


def trust_problems(doc: dict) -> list[Trust]:
    """Over-open Allow statements in a role trust policy, one Trust per kind.

    anyone: Principal "*" or {"AWS": "*"} with no condition that limits the caller
    (aws:PrincipalOrgID, aws:PrincipalArn, aws:SourceAccount, sts:ExternalId, ...).
    cross_account: an account principal without an sts:ExternalId condition. A template
    rarely knows its own account, so a literal account id is taken as another.
    service: a CONFUSED_DEPUTY_SERVICES principal without aws:SourceAccount/SourceArn.
    github_oidc: GitHub Actions OIDC whose sub condition is missing or matches any repo.
    Unknown principals, actions or conditions give nothing.
    """
    found: dict[str, set[str]] = {}
    for stmt in statements(doc):
        if stmt.get("Effect") != "Allow" or "NotPrincipal" in stmt or not _assumes(stmt):
            continue
        conditions = _conditions(stmt)
        if conditions is None:
            continue
        keys = set(conditions)
        principal = stmt.get("Principal")
        # {"*": ["*"]} is how data "aws_iam_policy_document" writes `type = "*"`.
        aws = ["*"] if principal == "*" else (
            _principal_values(principal, "AWS") + _principal_values(principal, "*")
        )
        if "*" in aws and not keys & _CALLER_KEYS:
            found.setdefault("anyone", set()).add("*")
        if "sts:externalid" not in keys:
            found.setdefault("cross_account", set()).update(_accounts(principal))
        if not keys & _SOURCE_KEYS:
            for service in _principal_values(principal, "Service"):
                match = _SERVICE.match(service.lower())
                if match and match.group(1) in CONFUSED_DEPUTY_SERVICES:
                    found.setdefault("service", set()).add(service)
        federated = principal.get("Federated") if isinstance(principal, dict) else None
        github = federated is not None and (
            GITHUB_OIDC in json.dumps(federated, default=str)
            or any(k.startswith(f"{GITHUB_OIDC}:") for k in keys)
        )
        if github and _any_repository(conditions.get(_GITHUB_SUB, [])):
            found.setdefault("github_oidc", set()).add(GITHUB_OIDC)
    order = ("anyone", "github_oidc", "cross_account", "service")
    return [Trust(kind, tuple(sorted(found[kind]))) for kind in order if found.get(kind)]


# --- resource policies -----------------------------------------------------------

# Condition keys that limit who can use a resource policy statement with Principal "*".
# aws:SourceIp is not one: the resource stays open to anyone on that network.
_RESOURCE_LIMIT_KEYS = _CALLER_KEYS | frozenset({
    "aws:sourcevpce", "aws:sourcevpc", "kms:calleraccount", "kms:viaservice",
})


def _is_anyone(principal: Any) -> bool:
    """Principal "*", {"AWS": "*"}, or {"*": ["*"]} (data "aws_iam_policy_document" type "*")."""
    if principal == "*":
        return True
    return "*" in _principal_values(principal, "AWS") + _principal_values(principal, "*")


def public_actions(doc: dict) -> list[str] | None:
    """Actions any principal is allowed, or None when no statement is open to everyone.

    An Allow with Principal "*" counts unless a condition limits the caller (aws:SourceArn,
    aws:SourceAccount, aws:PrincipalOrgID, aws:SourceVpce, ...). Unknown conditions and
    NotPrincipal statements give nothing. Actions the scan cannot read are left out of the
    list; the statement is still open.
    """
    found: set[str] | None = None
    for stmt in statements(doc):
        if stmt.get("Effect") != "Allow" or "NotPrincipal" in stmt:
            continue
        if not _is_anyone(stmt.get("Principal")):
            continue
        conditions = _conditions(stmt)
        if conditions is None or set(conditions) & _RESOURCE_LIMIT_KEYS:
            continue
        found = (found or set()) | set(literals(stmt.get("Action")))
    return None if found is None else sorted(found)
