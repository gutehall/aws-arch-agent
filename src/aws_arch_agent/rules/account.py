"""Opt-in read of a live AWS account for the org-gated controls (`--live-account`).

The static scan stays the default and makes no AWS call. With the flag, a few read-only
describe/list calls show whether account-level services (Security Hub, GuardDuty, Config,
CloudTrail, Budgets, Access Analyzer, Inspector) are already on.
A rule whose service was read becomes active even without `rules.org`. A rule whose service
is on has its finding dropped, so the practice reads as met. A service that could not be
read (no credentials, no permission) is a warning, and its rule stays off.

Purchases (RDS Reserved Instances, ElastiCache reserved nodes, Savings Plans) are read after
the scan, and only when it found the compute they cover: a template resource (observe()) or
the CDK rule's own finding. An active purchase drops the finding; none found adds the
finding; a purchase that could not be read is a warning, never a finding.

Account-level controls a template cannot show are read at the same point, for every scan:
the FSBP controls S3.1, EC2.7 and IAM.7 and a cost export (ACCT-*, one finding per control
that is off), and Macie (SEC-065) and Storage Lens (COST-018) under their rule ids. The
ACCT-* ids are not CDK rules or template checks, so they count as run only when the live
read answered them. A cost export also clears REPO-069.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, cast

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules.cost import (
    ElastiCacheReservedNodes,
    RdsReservedInstances,
    S3StorageLens,
    SavingsPlansOpportunity,
)
from aws_arch_agent.rules.security_iam import MacieNotEnabled

ClientFactory = Callable[..., Any]  # (service_name, region_name=...) -> boto3-style client

_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
           "UnauthorizedException", "AccessDeniedToResource"}


@dataclass
class AccountFacts:
    """What the account read found. `checked` rules ran; `enabled` ones are cleared."""

    account_id: str | None = None
    checked: set[str] = field(default_factory=set)
    enabled: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    # For the purchase reads after the scan: the client, and the compute types the scan saw.
    client: ClientFactory | None = field(default=None, repr=False, compare=False)
    seen: set[str] = field(default_factory=set, repr=False, compare=False)
    late_read: bool = field(default=False, repr=False, compare=False)

    def notes(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "checked": sorted(self.checked),
            "enabled": sorted(self.enabled),
        }


class _NotReadable(Exception):
    """A service whose state could not be read; the message is the report warning."""


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    return str(error.get("Code", "")) if isinstance(error, dict) else ""


def _read(label: str, permission: str, call: Callable[[], Any]) -> Any:
    try:
        return call()
    except Exception as exc:  # a botocore ClientError, or no credentials
        code = _code(exc)
        if code in _DENIED:
            raise _NotReadable(f"{label}: access denied ({permission}); not read") from exc
        reason = code or type(exc).__name__
        raise _NotReadable(f"{label}: not read ({reason})") from exc


# Each check returns True (on), False (off), or raises _NotReadable.
def _security_hub(client: ClientFactory, _acct: str) -> tuple[bool, bool]:
    sh = client("securityhub")
    try:
        sh.describe_hub()
    except Exception as exc:
        if _code(exc) == "InvalidAccessException":  # the account is not subscribed
            return False, False
        raise _NotReadable(_msg("Security Hub", "securityhub:DescribeHub", exc)) from exc
    standards = _read("Security Hub standards", "securityhub:GetEnabledStandards",
                      lambda: sh.get_enabled_standards().get("StandardsSubscriptions") or [])
    return True, bool(standards)


def _msg(label: str, permission: str, exc: Exception) -> str:
    code = _code(exc)
    if code in _DENIED:
        return f"{label}: access denied ({permission}); not read"
    return f"{label}: not read ({code or type(exc).__name__})"


def _guardduty(client: ClientFactory) -> bool:
    gd = client("guardduty")
    ids = _read("GuardDuty", "guardduty:ListDetectors", lambda: gd.list_detectors().get("DetectorIds") or [])
    def enabled(detector_id: str) -> bool:
        got = _read("GuardDuty", "guardduty:GetDetector", lambda: gd.get_detector(DetectorId=detector_id))
        return bool(got.get("Status") == "ENABLED")

    return any(enabled(i) for i in ids)


def _cloudtrail(client: ClientFactory) -> bool:
    ct = client("cloudtrail")
    trails = _read("CloudTrail", "cloudtrail:DescribeTrails",
                   lambda: ct.describe_trails().get("trailList") or [])
    def logging(trail: dict) -> bool:
        name = trail.get("TrailARN") or trail.get("Name")
        got = _read("CloudTrail", "cloudtrail:GetTrailStatus", lambda: ct.get_trail_status(Name=name))
        return bool(got.get("IsLogging"))

    return any(logging(t) for t in trails)


def _config(client: ClientFactory) -> bool:
    cfg = client("config")
    status = _read("AWS Config", "config:DescribeConfigurationRecorderStatus",
                   lambda: cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus") or [])
    return any(s.get("recording") for s in status)


def _budgets(client: ClientFactory, account: str) -> bool:
    b = client("budgets", region_name="us-east-1")
    return bool(_read("AWS Budgets", "budgets:DescribeBudgets",
                      lambda: b.describe_budgets(AccountId=account, MaxResults=1).get("Budgets")))


def _analyzer(client: ClientFactory) -> bool:
    aa = client("accessanalyzer")
    found = _read("IAM Access Analyzer", "access-analyzer:ListAnalyzers",
                  lambda: aa.list_analyzers().get("analyzers") or [])
    return any(a.get("status") == "ACTIVE" for a in found)


def _inspector(client: ClientFactory, account: str) -> bool:
    ins = client("inspector2")
    got = _read("Inspector", "inspector2:BatchGetAccountStatus",
                lambda: ins.batch_get_account_status(accountIds=[account]).get("accounts") or [])
    return any((a.get("state") or {}).get("status") == "ENABLED" for a in got)


def _any_page(label: str, permission: str, call: Callable[..., Any], items: str, token: str,
              next_key: str, active: Callable[[dict], bool], **kw: Any) -> bool:
    """Page through a list call (Marker or nextToken) and stop at the first active item."""
    page_kw: dict[str, Any] = {}
    seen: set[str] = set()
    while True:
        page = _read(label, permission, lambda: call(**kw, **page_kw))
        if any(active(i) for i in page.get(items) or []):
            return True
        nxt = page.get(next_key)
        if not nxt or nxt in seen:  # a token the API repeats would never end the loop
            return False
        seen.add(nxt)
        page_kw = {token: nxt}


def _rds_reserved(client: ClientFactory) -> bool:
    rds = client("rds")
    return _any_page("RDS Reserved Instances", "rds:DescribeReservedDBInstances",
                     rds.describe_reserved_db_instances, "ReservedDBInstances", "Marker", "Marker",
                     lambda r: r.get("State") == "active")


def _cache_reserved(client: ClientFactory) -> bool:
    ec = client("elasticache")
    return _any_page("ElastiCache reserved nodes", "elasticache:DescribeReservedCacheNodes",
                     ec.describe_reserved_cache_nodes, "ReservedCacheNodes", "Marker", "Marker",
                     lambda r: r.get("State") == "active")


def _savings_plan(client: ClientFactory) -> bool:
    sp = client("savingsplans", region_name="us-east-1")
    return _any_page("Savings Plans", "savingsplans:DescribeSavingsPlans",
                     sp.describe_savings_plans, "savingsPlans", "nextToken", "nextToken",
                     lambda p: p.get("state", "active") == "active", states=["active"])


# Rule id, the canonical compute types it covers, the read, and what "none" means.
_PURCHASES: tuple[tuple[str, frozenset[str], Callable[[ClientFactory], bool], str], ...] = (
    ("COST-005", frozenset({"db_instance", "rds_cluster"}), _rds_reserved,
     "No active RDS Reserved Instance in the account and Region"),
    ("COST-009", frozenset({"elasticache_cluster", "elasticache_replication_group"}), _cache_reserved,
     "No active ElastiCache reserved node in the account and Region"),
    ("COST-016", frozenset({"instance", "autoscaling_group", "lambda_function", "ecs_service"}), _savings_plan,
     "No active Savings Plan in the account"),
)
_PURCHASE_TYPES = frozenset().union(*(types for _r, types, _c, _e in _PURCHASES))


@dataclass(frozen=True)
class AccountControl:
    """An account-level control the live read answers (`control` is its FSBP id, or empty).
    Shaped like a Rule for the report."""

    id: str
    control: str
    title: str
    severity: str
    category: str
    themes: tuple[str, ...]
    recommendation: str
    read: Callable[[ClientFactory, str], tuple[bool, str]]
    # Rules the same read answers: cleared when the control is on. When one of them already
    # fired, the control adds no second finding for the same gap.
    clears: tuple[str, ...] = ()
    # An account-wide setting an app stack does not own: off unless rules.org or rules.include.
    org: bool = False


def _read_or_absent(label: str, permission: str, call: Callable[[], Any], absent: str) -> Any:
    """_read, but the error code `absent` (nothing configured) returns None instead."""
    try:
        return call()
    except Exception as exc:
        if _code(exc) == absent:
            return None
        raise _NotReadable(_msg(label, permission, exc)) from exc


_BPA_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _s3_account_bpa(client: ClientFactory, account: str) -> tuple[bool, str]:
    s3c = client("s3control")
    got = _read_or_absent("S3 account Block Public Access", "s3:GetAccountPublicAccessBlock",
                          lambda: s3c.get_public_access_block(AccountId=account),
                          "NoSuchPublicAccessBlockConfiguration")
    if got is None:
        return False, "No account-level S3 Block Public Access configuration"
    config = got.get("PublicAccessBlockConfiguration") or {}
    off = [k for k in _BPA_SETTINGS if not config.get(k)]
    return not off, f"Account-level S3 Block Public Access has {', '.join(off)} off"


def _ebs_default_encryption(client: ClientFactory, _account: str) -> tuple[bool, str]:
    ec2 = client("ec2")
    got = _read("EBS encryption by default", "ec2:GetEbsEncryptionByDefault",
                lambda: ec2.get_ebs_encryption_by_default())
    return bool(got.get("EbsEncryptionByDefault")), "EBS encryption by default is off in the Region read"


# FSBP IAM.7 asks for upper case, lower case, numbers and symbols. The length, reuse and age
# minimums are the CIS ones Security Hub checks next to it (IAM.15: 14 characters, IAM.16:
# 24 remembered passwords, CIS 1.2 1.11: 90 days).
PASSWORD_MIN_LENGTH = 14
PASSWORD_REUSE_PREVENTION = 24
PASSWORD_MAX_AGE_DAYS = 90
_PASSWORD_CLASSES = ("RequireUppercaseCharacters", "RequireLowercaseCharacters", "RequireNumbers", "RequireSymbols")


def _password_policy(client: ClientFactory, _account: str) -> tuple[bool, str]:
    iam = client("iam")
    got = _read_or_absent("IAM password policy", "iam:GetAccountPasswordPolicy",
                          lambda: iam.get_account_password_policy(), "NoSuchEntity")
    if got is None:
        return False, "The account has no IAM password policy"
    policy = got.get("PasswordPolicy") or {}
    weak = [k for k in _PASSWORD_CLASSES if not policy.get(k)]
    if int(policy.get("MinimumPasswordLength") or 0) < PASSWORD_MIN_LENGTH:
        weak.append(f"MinimumPasswordLength under {PASSWORD_MIN_LENGTH}")
    if int(policy.get("PasswordReusePrevention") or 0) < PASSWORD_REUSE_PREVENTION:
        weak.append(f"PasswordReusePrevention under {PASSWORD_REUSE_PREVENTION}")
    age = policy.get("MaxPasswordAge")
    if not age or int(age) > PASSWORD_MAX_AGE_DAYS:
        weak.append(f"MaxPasswordAge unset or over {PASSWORD_MAX_AGE_DAYS}")
    return not weak, "IAM password policy misses: " + ", ".join(weak)


def _cost_export(client: ClientFactory, _account: str) -> tuple[bool, str]:
    """A Cost and Usage Report or a Data Exports export. Either one is enough; when one read
    fails and the other finds none, the answer is unknown."""
    cur = client("cur", region_name="us-east-1")
    exports = client("bcm-data-exports", region_name="us-east-1")
    reads = (
        lambda: _any_page("Cost and Usage Report", "cur:DescribeReportDefinitions",
                          cur.describe_report_definitions, "ReportDefinitions", "NextToken", "NextToken",
                          lambda _r: True),
        lambda: _any_page("Data Exports", "bcm-data-exports:ListExports",
                          exports.list_exports, "Exports", "NextToken", "NextToken", lambda _e: True),
    )
    failed: _NotReadable | None = None
    for call in reads:
        try:
            if call():
                return True, ""
        except _NotReadable as exc:
            failed = failed or exc
    if failed is not None:
        raise failed
    return False, "No Cost and Usage Report and no Data Exports export in the account"


ACCOUNT_CONTROLS: tuple[AccountControl, ...] = (
    AccountControl(
        "ACCT-001", "S3.1", "S3 Block Public Access is not fully on for the account", "Medium", "Security",
        ("security-baseline", "data-protection", "network-exposure"),
        "Turn on all four account-level S3 Block Public Access settings (FSBP S3.1): "
        "aws s3control put-public-access-block, or Terraform aws_s3_account_public_access_block. "
        "Bucket-level settings (CF-S3-001) do not cover buckets created outside this repo.",
        _s3_account_bpa,
    ),
    AccountControl(
        "ACCT-002", "EC2.7", "EBS encryption by default is off", "Medium", "Security",
        ("security-baseline", "data-protection"),
        "Turn on EBS encryption by default in each Region you use (FSBP EC2.7): "
        "aws ec2 enable-ebs-encryption-by-default, or Terraform aws_ebs_encryption_by_default.",
        _ebs_default_encryption,
    ),
    AccountControl(
        "ACCT-003", "IAM.7", "IAM account password policy is weaker than the FSBP and CIS minimums", "Medium",
        "Security", ("security-baseline", "identity"),
        "Set an account password policy (FSBP IAM.7, CIS IAM.15 and IAM.16) that requires upper and lower "
        f"case, numbers and symbols, at least {PASSWORD_MIN_LENGTH} characters, prevents reuse of the last "
        f"{PASSWORD_REUSE_PREVENTION} passwords and expires them within {PASSWORD_MAX_AGE_DAYS} days: "
        "aws iam update-account-password-policy, or Terraform aws_iam_account_password_policy. "
        "Better still, sign people in through IAM Identity Center.",
        _password_policy,
    ),
    AccountControl(
        "ACCT-004", "", "No Cost and Usage Report or data export in the account", "Low", "Cost", ("finops",),
        "Turn on a detailed cost source in the management (payer) account: an AWS Data Exports "
        "export (CUR 2.0) or a Cost and Usage Report to S3, so cost can be broken down by account, "
        "service and tag. Terraform aws_bcmdataexports_export or aws_cur_report_definition.",
        _cost_export, clears=("REPO-069",), org=True,
    ),
)
ACCOUNT_CONTROL_IDS = frozenset(c.id for c in ACCOUNT_CONTROLS)
ORG_CONTROL_IDS = frozenset(c.id for c in ACCOUNT_CONTROLS if c.org)


def read(client: ClientFactory) -> AccountFacts:
    """Read the account through `client(service, region_name=None)`. Never raises."""
    facts = AccountFacts()

    def done(rules: tuple[str, ...], on: bool) -> None:
        facts.checked.update(rules)
        if on:
            facts.enabled.update(rules)

    try:
        facts.account_id = _read("Account", "sts:GetCallerIdentity",
                                 lambda: client("sts").get_caller_identity()["Account"])
    except _NotReadable as exc:
        facts.warnings.append(f"{exc}; no account control was read")
        return facts
    acct = facts.account_id or ""
    facts.client = client

    state: dict[str, bool] = {}

    def run(key: str, rules: tuple[str, ...], call: Callable[[], bool]) -> None:
        try:
            on = call()
        except _NotReadable as exc:
            facts.warnings.append(str(exc))
            return
        state[key] = on
        done(rules, on)

    try:
        hub, standards = _security_hub(client, acct)
        state["securityhub"] = hub
        done(("SEC-026",), hub)
        done(("REPO-136", "REPO-162"), standards)
    except _NotReadable as exc:
        facts.warnings.append(str(exc))
    run("guardduty", ("SEC-027",), lambda: _guardduty(client))
    run("cloudtrail", ("OPS-001",), lambda: _cloudtrail(client))
    run("config", ("OPS-014",), lambda: _config(client))
    run("budgets", ("COST-014",), lambda: _budgets(client, acct))
    run("analyzer", ("REPO-141",), lambda: _analyzer(client))
    run("inspector", ("REPO-145",), lambda: _inspector(client, acct))
    # REPO-163 asks for GuardDuty or Security Hub: both must be read to say it is unanswered.
    if "guardduty" in state and "securityhub" in state:
        done(("REPO-163",), state["guardduty"] or state["securityhub"])
    return facts


def boto3_client_factory(region: str | None = None) -> ClientFactory:
    """Real clients. boto3 is imported here only, so a default scan never loads it."""
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "--live-account needs boto3: pip install 'aws-arch-agent[account]'"
        ) from exc
    session = boto3.session.Session(region_name=region)

    def factory(service: str, region_name: str | None = None) -> Any:
        return session.client(service, region_name=region_name or region or session.region_name or "us-east-1")

    return factory


def read_live(region: str | None = None) -> AccountFacts:
    """The `--live-account` read with real credentials. A missing boto3 is a warning."""
    try:
        factory = boto3_client_factory(region)
    except RuntimeError as exc:
        return AccountFacts(warnings=[str(exc)])
    return read(factory)


_facts: ContextVar[AccountFacts | None] = ContextVar("account_facts", default=None)


@contextmanager
def use_facts(facts: AccountFacts | None) -> Iterator[None]:
    token = _facts.set(facts)
    try:
        yield
    finally:
        _facts.reset(token)


def live_checked() -> frozenset[str]:
    """Org rule ids whose service the live read covered: they run even without rules.org."""
    facts = _facts.get()
    return frozenset(facts.checked) if facts else frozenset()


def observe(resources: Iterable) -> None:
    """Record the compute types among a file's normalized resources, for the purchase reads."""
    facts = _facts.get()
    if facts is not None:
        facts.seen.update(r.type for r in resources if r.type in _PURCHASE_TYPES)


def _message(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    return str(error.get("Message", "")) if isinstance(error, dict) else ""


def _macie(client: ClientFactory, _account: str) -> tuple[bool, str]:
    m = client("macie2")
    try:
        got = m.get_macie_session()
    except Exception as exc:
        # Macie answers an account where it is off with AccessDeniedException "Macie is not
        # enabled". A missing permission is the same code with an "is not authorized" message.
        if _code(exc) == "AccessDeniedException" and "not enabled" in _message(exc).lower():
            return False, "Macie is not enabled in the account and Region"
        raise _NotReadable(_msg("Macie", "macie2:GetMacieSession", exc)) from exc
    status = got.get("status")
    return status == "ENABLED", f"Macie session is {status or 'not enabled'}"


def _storage_lens(client: ClientFactory, account: str) -> tuple[bool, str]:
    s3c = client("s3control")
    on = _any_page("S3 Storage Lens", "s3:ListStorageLensConfigurations",
                   s3c.list_storage_lens_configurations, "StorageLensConfigurationList", "NextToken", "NextToken",
                   lambda c: bool(c.get("IsEnabled")), AccountId=account)
    return on, "No enabled S3 Storage Lens dashboard in the account"


# Account rules with a CDK rule id the live read answers on every scan.
_SERVICES: tuple[tuple[Any, Callable[[ClientFactory, str], tuple[bool, str]]], ...] = (
    (MacieNotEnabled, _macie),
    (S3StorageLens, _storage_lens),
)


def _late_findings(facts: AccountFacts, findings: list, wanted: Callable[[str], bool]) -> list:
    """Read the account controls, and each purchase whose compute the scan found; return the
    findings to add."""
    if facts.client is None or facts.late_read:
        return []
    facts.late_read = True
    rules = {r.id: r for r in (RdsReservedInstances, ElastiCacheReservedNodes, SavingsPlansOpportunity)}
    fired = {f.id for f in findings}
    out = []
    for rid, types, call, none in _PURCHASES:
        if not wanted(rid) or not (facts.seen & types or rid in fired):
            continue  # no matching compute: the purchase API is not called
        try:
            on = call(facts.client)
        except _NotReadable as exc:
            facts.warnings.append(f"{exc} ({rid} purchase check)")
            continue
        facts.checked.add(rid)
        if on:
            facts.enabled.add(rid)
        elif rid not in fired:
            rule = rules[rid]
            out.append(Finding(
                id=rid, title=rule.title, severity=cast(Severity, rule.severity), category=rule.category,
                file=None, line=None, evidence=f"{none} (live account read)",
                recommendation=rule.recommendation,
            ))
    for rule, read_service in _SERVICES:
        if not wanted(rule.id):
            continue
        try:
            on, detail = read_service(facts.client, facts.account_id or "")
        except _NotReadable as exc:
            facts.warnings.append(f"{exc} ({rule.id})")
            continue
        facts.checked.add(rule.id)
        if on:
            facts.enabled.add(rule.id)
        elif rule.id not in fired:
            out.append(Finding(
                id=rule.id, title=rule.title, severity=cast(Severity, rule.severity), category=rule.category,
                file=None, line=None, evidence=f"{detail} (live account read)",
                recommendation=rule.recommendation,
            ))
    for control in ACCOUNT_CONTROLS:
        if not wanted(control.id):
            continue
        fsbp = f", FSBP {control.control}" if control.control else ""
        try:
            on, detail = control.read(facts.client, facts.account_id or "")
        except _NotReadable as exc:
            facts.warnings.append(f"{exc} ({control.id}{fsbp})")
            continue
        facts.checked.add(control.id)
        if on:
            facts.enabled.add(control.id)
            facts.checked.update(control.clears)
            facts.enabled.update(control.clears)
        elif not fired & set(control.clears):
            out.append(Finding(
                id=control.id, title=control.title, severity=cast(Severity, control.severity),
                category=control.category, file=None, line=None,
                evidence=f"{detail} (live account read{fsbp})",
                recommendation=control.recommendation, themes=list(control.themes),
            ))
    return out


def apply(
    findings: list,
    notes: dict | None = None,
    rules_include: list[str] | None = None,
    rules_exclude: list[str] | None = None,
    rules_org: bool = False,
) -> list:
    """Read the purchases the scan's compute calls for and the account controls, then drop the
    findings of rules whose service or purchase the account has on.

    An org control (ACCT-004) has the gate of the org rules (agent/v1.py ORG_RULE_IDS): read
    only with rules.org, or when rules.include names it or a rule it clears."""
    facts = _facts.get()
    if facts is None:
        return findings

    def wanted(rid: str) -> bool:
        if rid in (rules_exclude or ()):
            return False
        also = next((c.clears for c in ACCOUNT_CONTROLS if c.id == rid and c.org), ())
        if rules_include is not None:
            return rid in rules_include or bool(set(also) & set(rules_include))
        return rules_org or rid not in ORG_CONTROL_IDS

    findings = [*findings, *_late_findings(facts, findings, wanted)]
    if notes is not None:
        notes["live_account"] = facts.notes()
    return [f for f in findings if f.id not in facts.enabled]
