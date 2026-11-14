"""Opt-in read of a live AWS account for the org-gated controls (`--live-account`).

The static scan stays the default and makes no AWS call. With the flag, a few read-only
describe/list calls show whether account-level services (Security Hub, GuardDuty, Config,
CloudTrail, Budgets, a cost and usage report, Access Analyzer, Inspector) are already on.
A rule whose service was read becomes active even without `rules.org`. A rule whose service
is on has its finding dropped, so the practice reads as met. A service that could not be
read (no credentials, no permission) is a warning, and its rule stays off.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

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


def _cur(client: ClientFactory) -> bool:
    cur = client("cur", region_name="us-east-1")
    return bool(_read("Cost and Usage Report", "cur:DescribeReportDefinitions",
                      lambda: cur.describe_report_definitions(MaxResults=5).get("ReportDefinitions")))


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
    run("cur", ("REPO-069",), lambda: _cur(client))
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


def apply(findings: list, notes: dict | None = None) -> list:
    """Drop the findings of rules whose service the account has on."""
    facts = _facts.get()
    if facts is None:
        return findings
    if notes is not None:
        notes["live_account"] = facts.notes()
    return [f for f in findings if f.id not in facts.enabled]
