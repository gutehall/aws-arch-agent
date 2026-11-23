"""--live-account: an opt-in, read-only look at the account for the org-gated controls."""
import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from aws_arch_agent.agent.v1 import ORG_RULE_IDS, analyze_v1
from aws_arch_agent.cli import app
from aws_arch_agent.rules import account
from aws_arch_agent.rules.well_architected import answers

runner = CliRunner()


class _Denied(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class _Stub:
    """A boto3-style client with canned replies; a value that is an Exception is raised."""

    def __init__(self, replies: dict[str, Any]) -> None:
        self.replies = replies

    def __getattr__(self, op: str) -> Any:
        def call(**_kw: Any) -> Any:
            reply = self.replies[op]
            if isinstance(reply, Exception):
                raise reply
            return reply
        return call


def _factory(by_service: dict[str, dict[str, Any]]) -> Any:
    def factory(service: str, region_name: str | None = None) -> _Stub:
        return _Stub(by_service[service])
    return factory


_BPA_ON = {"PublicAccessBlockConfiguration": {
    "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
_STRONG_POLICY = {"PasswordPolicy": {
    "MinimumPasswordLength": 14, "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True,
    "RequireNumbers": True, "RequireSymbols": True, "PasswordReusePrevention": 24, "MaxPasswordAge": 90}}
_LENS_ON = {"StorageLensConfigurationList": [{"Id": "default-account-dashboard", "IsEnabled": True}]}
_CONTROLS_ON: dict[str, dict[str, Any]] = {
    "s3control": {"get_public_access_block": _BPA_ON, "list_storage_lens_configurations": _LENS_ON},
    "ec2": {"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True}},
    "iam": {"get_account_password_policy": _STRONG_POLICY},
    "macie2": {"get_macie_session": {"status": "ENABLED"}},
    "cur": {"describe_report_definitions": {"ReportDefinitions": [{"ReportName": "r"}]}},
    "bcm-data-exports": {"list_exports": {"Exports": []}},
}


# What the after-scan reads clear on an account with every control on.
_LATE_ON = account.ACCOUNT_CONTROL_IDS | {"SEC-065", "COST-018", "REPO-069"}


def _account(hub: Any) -> dict[str, dict[str, Any]]:
    return {
        "sts": {"get_caller_identity": {"Account": "111122223333"}},
        "securityhub": {"describe_hub": hub, "get_enabled_standards": {"StandardsSubscriptions": [{"x": 1}]}},
        "guardduty": {"list_detectors": {"DetectorIds": []}},
        "cloudtrail": {"describe_trails": {"trailList": []}},
        "config": {"describe_configuration_recorder_status": {"ConfigurationRecordersStatus": []}},
        "budgets": {"describe_budgets": {"Budgets": []}},
        "accessanalyzer": {"list_analyzers": {"analyzers": []}},
        "inspector2": {"batch_get_account_status": {"accounts": []}},
        **_CONTROLS_ON,
    }


def _repo(root: Path) -> Path:
    (root / "cdk.json").write_text('{"app": "npx ts-node bin/app.ts"}\n', encoding="utf-8")
    (root / "lib").mkdir()
    (root / "lib" / "stack.ts").write_text(
        'import * as s3 from "aws-cdk-lib/aws-s3";\nnew s3.Bucket(this, "B");\n', encoding="utf-8"
    )
    return root


def _ids(findings: list) -> set[str]:
    return {f.id for f in findings}


def test_security_hub_on_clears_the_rules_it_backs(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _r, _c, plain, _w = analyze_v1(repo, use_llm=False, rules_org=True)
    assert {"SEC-026", "REPO-136"} <= _ids(plain)  # the org rules fire with no Security Hub in the repo
    facts = account.read(_factory(_account({"HubArn": "arn"})))
    _r, ctx, findings, warnings = analyze_v1(repo, use_llm=False, rules_org=True, account_facts=facts)
    assert not {"SEC-026", "REPO-136", "REPO-162", "REPO-163"} & _ids(findings)
    assert facts.enabled == {"SEC-026", "REPO-136", "REPO-162", "REPO-163"} | _LATE_ON
    assert ctx.notes["live_account"]["enabled"] == [
        "ACCT-001", "ACCT-002", "ACCT-003", "ACCT-004", "COST-018", "REPO-069", "REPO-136", "REPO-162",
        "REPO-163", "SEC-026", "SEC-065"]
    assert warnings == []


def test_security_hub_off_still_reports_and_runs_the_rule_without_rules_org(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    facts = account.read(_factory(_account(_Denied("InvalidAccessException"))))
    assert "SEC-026" in facts.checked and "SEC-026" not in facts.enabled
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)  # no rules_org
    assert "SEC-026" in _ids(findings)
    assert "SEC-026" in ctx.rules_run


def test_a_cleared_practice_reads_as_met_only_with_the_live_read(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False)
    assert "SEC-026" not in ctx.rules_run  # no flag: the org rule is off
    facts = account.read(_factory(_account({"HubArn": "arn"})))
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert "SEC-026" in ctx.rules_run and "SEC-026" not in _ids(findings)
    sec04 = next(a for a in answers(findings, ctx.rules_run) if a.question.id == "SEC 4")
    assert "SEC04-BP03" not in sec04.not_checked


def test_a_missing_permission_is_a_warning_and_the_rule_stays_off(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    facts = account.read(_factory(_account(_Denied("AccessDeniedException"))))
    assert "SEC-026" not in facts.checked
    assert any("Security Hub: access denied (securityhub:DescribeHub)" in w for w in facts.warnings)
    _r, ctx, _f, warnings = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert "SEC-026" not in ctx.rules_run
    assert any("Security Hub" in w for w in warnings)


def test_no_credentials_reads_nothing(tmp_path: Path) -> None:
    class NoCreds(Exception):
        pass

    def factory(service: str, region_name: str | None = None) -> Any:
        raise NoCreds("Unable to locate credentials")

    facts = account.read(factory)
    assert facts.checked == set() and facts.enabled == set()
    assert facts.warnings and "no account control was read" in facts.warnings[0]


def test_every_live_rule_is_an_org_rule() -> None:
    facts = account.read(_factory({
        **_account({"HubArn": "arn"}),
        "guardduty": {"list_detectors": {"DetectorIds": ["d"]}, "get_detector": {"Status": "ENABLED"}},
        "cloudtrail": {"describe_trails": {"trailList": [{"TrailARN": "t"}]},
                       "get_trail_status": {"IsLogging": True}},
        "config": {"describe_configuration_recorder_status": {"ConfigurationRecordersStatus": [{"recording": True}]}},
        "budgets": {"describe_budgets": {"Budgets": [{"BudgetName": "b"}]}},
        "accessanalyzer": {"list_analyzers": {"analyzers": [{"status": "ACTIVE"}]}},
        "inspector2": {"batch_get_account_status": {"accounts": [{"state": {"status": "ENABLED"}}]}},
    }))
    assert facts.checked == facts.enabled
    assert facts.checked <= ORG_RULE_IDS
    assert {"SEC-027", "OPS-001", "OPS-014", "COST-014", "REPO-141", "REPO-145", "REPO-163"} <= facts.enabled


def test_the_default_scan_never_reads_the_account(tmp_path: Path, monkeypatch: Any) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("the default scan must not read the account")

    monkeypatch.setattr(account, "read_live", boom)
    monkeypatch.setattr(account, "boto3_client_factory", boom)
    repo = _repo(tmp_path)
    result = runner.invoke(app, ["--repo", str(repo), "--no-llm", "--out", str(tmp_path / "r.md")])
    assert result.exit_code == 0, result.output
    assert account.live_checked() == frozenset()


def test_cli_flag_reads_the_account_and_notes_it(tmp_path: Path, monkeypatch: Any) -> None:
    facts = account.read(_factory(_account({"HubArn": "arn"})))
    monkeypatch.setattr(account, "read_live", lambda region=None: facts)
    repo = _repo(tmp_path)
    out = tmp_path / "r.json"
    result = runner.invoke(app, ["--repo", str(repo), "--no-llm", "--live-account",
                                 "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "SEC-026" not in {f["id"] for f in data["findings"]}
    assert data["context"]["notes"]["live_account"]["enabled"] == [
        "ACCT-001", "ACCT-002", "ACCT-003", "COST-018", "REPO-136", "REPO-162", "REPO-163", "SEC-026", "SEC-065"]


# Purchases (COST-005, COST-009, COST-016): read only when the scan has the matching compute.
_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
{body}"""
_RDS = "  Db:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      Engine: postgres\n"
_CACHE = "  Cache:\n    Type: AWS::ElastiCache::CacheCluster\n    Properties:\n      Engine: redis\n"
_LAMBDA = "  Fn:\n    Type: AWS::Lambda::Function\n    Properties:\n      Runtime: python3.12\n"
_BUCKET = "  B:\n    Type: AWS::S3::Bucket\n"


def _cf_repo(root: Path, *bodies: str) -> Path:
    (root / "template.yaml").write_text(_TEMPLATE.format(body="".join(bodies)), encoding="utf-8")
    return root


def _recording(by_service: dict[str, dict[str, Any]], calls: list[str]) -> Any:
    def factory(service: str, region_name: str | None = None) -> Any:
        stub = _Stub(by_service[service])

        class Rec:
            def __getattr__(self, op: str) -> Any:
                calls.append(f"{service}.{op}")
                return getattr(stub, op)
        return Rec()
    return factory


def _purchases(rds: Any, cache: Any, plans: Any) -> dict[str, dict[str, Any]]:
    return {
        **_account({"HubArn": "arn"}),
        "rds": {"describe_reserved_db_instances": rds},
        "elasticache": {"describe_reserved_cache_nodes": cache},
        "savingsplans": {"describe_savings_plans": plans},
    }


_PRESENT = _purchases({"ReservedDBInstances": [{"State": "active"}]},
                      {"ReservedCacheNodes": [{"State": "active"}]},
                      {"savingsPlans": [{"state": "active"}]})
_ABSENT = _purchases({"ReservedDBInstances": [{"State": "retired"}]},
                     {"ReservedCacheNodes": []},
                     {"savingsPlans": []})
_DENIED_ALL = _purchases(_Denied("AccessDenied"), _Denied("UnauthorizedOperation"), _Denied("AccessDeniedException"))
_PURCHASE_IDS = {"COST-005", "COST-009", "COST-016"}


def test_active_purchases_clear_the_rules(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _RDS, _CACHE, _LAMBDA)
    calls: list[str] = []
    facts = account.read(_recording(_PRESENT, calls))
    _r, ctx, findings, warnings = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert not _PURCHASE_IDS & _ids(findings)
    assert _PURCHASE_IDS <= facts.enabled
    assert {"rds.describe_reserved_db_instances", "elasticache.describe_reserved_cache_nodes",
            "savingsplans.describe_savings_plans"} <= set(calls)
    assert set(ctx.notes["live_account"]["enabled"]) >= _PURCHASE_IDS
    assert not any("purchase check" in w for w in warnings)


def test_no_purchase_is_a_finding_under_the_rule(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _RDS, _CACHE, _LAMBDA)
    facts = account.read(_factory(_ABSENT))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    got = {f.id: f for f in findings if f.id in _PURCHASE_IDS}
    assert set(got) == _PURCHASE_IDS
    assert got["COST-005"].title == "RDS not using Reserved Instances (savings opportunity)"
    assert got["COST-005"].severity == "Low"
    assert "live account read" in (got["COST-016"].evidence or "")
    assert _PURCHASE_IDS <= facts.checked and not _PURCHASE_IDS & facts.enabled


def test_a_denied_purchase_read_is_a_warning_not_a_finding(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _RDS, _CACHE, _LAMBDA)
    facts = account.read(_factory(_DENIED_ALL))
    _r, _c, findings, warnings = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert not _PURCHASE_IDS & _ids(findings)
    assert not _PURCHASE_IDS & facts.checked
    assert any("RDS Reserved Instances: access denied (rds:DescribeReservedDBInstances)" in w for w in warnings)
    assert any("ElastiCache reserved nodes: access denied" in w for w in warnings)
    assert any("Savings Plans: access denied" in w and "COST-016" in w for w in warnings)


def test_no_matching_compute_does_not_call_the_purchase_apis(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    calls: list[str] = []
    facts = account.read(_recording(_ABSENT, calls))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert not any(c.split(".")[0] in {"rds", "elasticache", "savingsplans"} for c in calls)
    assert not _PURCHASE_IDS & _ids(findings)


def test_only_the_matching_purchase_is_read(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _LAMBDA)
    calls: list[str] = []
    facts = account.read(_recording(_ABSENT, calls))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert "rds.describe_reserved_db_instances" not in calls
    assert "elasticache.describe_reserved_cache_nodes" not in calls
    assert "savingsplans.describe_savings_plans" in calls
    assert {"COST-016"} == _PURCHASE_IDS & _ids(findings)


def test_an_excluded_purchase_rule_is_not_read(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _RDS)
    calls: list[str] = []
    facts = account.read(_recording(_ABSENT, calls))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts, rules_exclude=["COST-005"])
    assert "rds.describe_reserved_db_instances" not in calls
    assert "COST-005" not in _ids(findings)


def test_a_cdk_rds_finding_is_cleared_by_a_reservation(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "lib" / "db.ts").write_text('new rds.DatabaseInstance(this, "Db", {});\n', encoding="utf-8")
    _r, _c, plain, _w = analyze_v1(repo, use_llm=False)
    assert "COST-005" in _ids(plain)
    facts = account.read(_factory(_PRESENT))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert "COST-005" not in _ids(findings)


def test_an_active_purchase_on_page_two_counts(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _RDS, _CACHE, _LAMBDA)
    seen: list[dict[str, Any]] = []

    def paged(items: str, token: str, item: dict[str, Any]) -> Any:
        def call(**kw: Any) -> dict[str, Any]:
            seen.append(kw)
            if token not in kw:
                return {items: [{"State": "retired", "state": "retired"}], token: "p2"}
            assert kw[token] == "p2"
            return {items: [item]}
        return call

    class Paged:
        def __init__(self, ops: dict[str, Any]) -> None:
            self.ops = ops

        def __getattr__(self, op: str) -> Any:
            return self.ops[op]

    base = _factory(_account({"HubArn": "arn"}))
    clients = {
        "rds": Paged({"describe_reserved_db_instances":
                      paged("ReservedDBInstances", "Marker", {"State": "active"})}),
        "elasticache": Paged({"describe_reserved_cache_nodes":
                              paged("ReservedCacheNodes", "Marker", {"State": "active"})}),
        "savingsplans": Paged({"describe_savings_plans":
                               paged("savingsPlans", "nextToken", {"state": "active"})}),
    }

    def factory(service: str, region_name: str | None = None) -> Any:
        return clients[service] if service in clients else base(service, region_name)

    facts = account.read(factory)
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert not _PURCHASE_IDS & _ids(findings)
    assert _PURCHASE_IDS <= facts.enabled
    assert len(seen) == 6  # two pages per purchase


# Account-level FSBP controls (S3.1, EC2.7, IAM.7): one ACCT-* finding per control that is off.
_ACCT = frozenset({"ACCT-001", "ACCT-002", "ACCT-003"})


def _controls(s3: Any, ebs: Any, iam: Any) -> dict[str, dict[str, Any]]:
    return {
        **_account({"HubArn": "arn"}),
        "s3control": {"get_public_access_block": s3},
        "ec2": {"get_ebs_encryption_by_default": ebs},
        "iam": {"get_account_password_policy": iam},
    }


def test_account_controls_on_are_met(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    facts = account.read(_factory(_account({"HubArn": "arn"})))
    _r, ctx, findings, warnings = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert not _ACCT & _ids(findings)
    assert _ACCT <= facts.enabled and _ACCT <= set(ctx.rules_run)
    sec = {a.question.id: a for a in answers(findings, ctx.rules_run)}
    assert "SEC02-BP01" not in sec["SEC 2"].not_checked
    assert not any("FSBP" in w for w in warnings)


def test_account_controls_off_are_one_finding_each(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    weak = {"PasswordPolicy": {**_STRONG_POLICY["PasswordPolicy"], "MinimumPasswordLength": 8,
                               "RequireSymbols": False}}
    facts = account.read(_factory(_controls(
        {"PublicAccessBlockConfiguration": {**_BPA_ON["PublicAccessBlockConfiguration"],
                                            "RestrictPublicBuckets": False}},
        {"EbsEncryptionByDefault": False}, weak)))
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    got = {f.id: f for f in findings if f.id in _ACCT}
    assert set(got) == _ACCT and len([f for f in findings if f.id in _ACCT]) == 3
    assert "RestrictPublicBuckets" in (got["ACCT-001"].evidence or "")
    assert "FSBP EC2.7" in (got["ACCT-002"].evidence or "")
    assert "RequireSymbols" in (got["ACCT-003"].evidence or "")
    assert "MinimumPasswordLength under 14" in (got["ACCT-003"].evidence or "")
    assert got["ACCT-001"].themes and all(f.severity == "Medium" for f in got.values())
    assert _ACCT <= set(ctx.rules_run)


def test_no_configuration_is_off(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    facts = account.read(_factory(_controls(
        _Denied("NoSuchPublicAccessBlockConfiguration"), {"EbsEncryptionByDefault": True}, _Denied("NoSuchEntity"))))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert {"ACCT-001", "ACCT-003"} == _ACCT & _ids(findings)


def test_a_denied_control_read_is_a_warning_not_a_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    facts = account.read(_factory(_controls(
        _Denied("AccessDenied"), _Denied("UnauthorizedOperation"), _Denied("AccessDenied"))))
    _r, ctx, findings, warnings = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert not _ACCT & _ids(findings)
    assert not _ACCT & facts.checked and not _ACCT & set(ctx.rules_run)
    assert any("S3 account Block Public Access: access denied" in w and "FSBP S3.1" in w for w in warnings)
    assert any("EBS encryption by default: access denied (ec2:GetEbsEncryptionByDefault)" in w for w in warnings)
    assert any("IAM password policy: access denied (iam:GetAccountPasswordPolicy)" in w for w in warnings)


def test_an_excluded_control_is_not_read(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    calls: list[str] = []
    facts = account.read(_recording(_controls(_BPA_ON, {"EbsEncryptionByDefault": False}, _STRONG_POLICY), calls))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts, rules_exclude=["ACCT-002"])
    assert "ec2.get_ebs_encryption_by_default" not in calls
    assert "s3control.get_public_access_block" in calls
    assert "ACCT-002" not in _ids(findings)


def test_without_the_flag_no_control_runs(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False)
    assert not _ACCT & _ids(findings) and not _ACCT & set(ctx.rules_run)


# Macie (SEC-065), Storage Lens (COST-018), and a cost export (ACCT-004, clears REPO-069).
def _late(**over: dict[str, Any]) -> dict[str, dict[str, Any]]:
    base = _account({"HubArn": "arn"})
    for service, ops in over.items():
        base[service.replace("_", "-")] = {**base.get(service.replace("_", "-"), {}), **ops}
    return base


class _Error(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.response = {"Error": {"Code": code, "Message": message}}


_MACIE_OFF = _Error("AccessDeniedException", "Macie is not enabled.")
_MACIE_DENIED = _Error("AccessDeniedException",
                       "User: arn:aws:iam::1:user/x is not authorized to perform: macie2:GetMacieSession")
_RDS_RESERVED = {"describe_reserved_db_instances": {"ReservedDBInstances": [{"State": "active"}]}}
_NO_EXPORT = {"cur": {"describe_report_definitions": {"ReportDefinitions": []}},
              "bcm_data_exports": {"list_exports": {"Exports": []}}}


def test_services_on_clear_their_rules(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    facts = account.read(_factory(_account({"HubArn": "arn"})))
    _r, ctx, findings, warnings = analyze_v1(repo, use_llm=False, rules_org=True, account_facts=facts)
    assert not {"SEC-065", "COST-018", "ACCT-004", "REPO-069"} & _ids(findings)
    assert {"SEC-065", "COST-018", "ACCT-004", "REPO-069"} <= facts.enabled
    assert "ACCT-004" in ctx.rules_run
    cost3 = next(a for a in answers(findings, ctx.rules_run) if a.question.id == "COST 3")
    assert "COST03-BP01" not in cost3.not_checked
    assert warnings == []


def test_a_data_export_alone_is_enough(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    facts = account.read(_factory(_late(
        cur={"describe_report_definitions": {"ReportDefinitions": []}},
        bcm_data_exports={"list_exports": {"Exports": [{"ExportArn": "a"}]}})))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts, rules_include=["ACCT-004"])
    assert "ACCT-004" in facts.enabled and "ACCT-004" not in _ids(findings)


def test_services_off_are_findings_under_their_rules(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    facts = account.read(_factory(_late(
        macie2={"get_macie_session": _MACIE_OFF},
        s3control={"list_storage_lens_configurations": {"StorageLensConfigurationList": [
            {"Id": "default-account-dashboard", "IsEnabled": False}]}},
        **_NO_EXPORT)))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts,
                                      rules_include=["SEC-065", "COST-018", "ACCT-004"])
    got = {f.id: f for f in findings}
    assert {"SEC-065", "COST-018", "ACCT-004"} <= set(got)
    assert got["SEC-065"].title == "Amazon Macie not enabled for sensitive data discovery"
    assert "Macie is not enabled" in (got["SEC-065"].evidence or "")
    assert got["COST-018"].title == "S3 Storage Lens not enabled"
    assert "REPO-069" not in got  # not included: ACCT-004 is the one finding


def test_a_paused_macie_session_is_off(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    facts = account.read(_factory(_late(macie2={"get_macie_session": {"status": "PAUSED"}})))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts)
    assert "SEC-065" in _ids(findings)


def test_no_export_with_rules_org_reports_repo_069_once(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _RDS)
    facts = account.read(_factory(_late(rds=_RDS_RESERVED, **_NO_EXPORT)))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, rules_org=True, account_facts=facts)
    assert "REPO-069" in _ids(findings) and "ACCT-004" not in _ids(findings)


def test_an_export_clears_repo_069_under_rules_org(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _RDS)
    _r, _c, plain, _w = analyze_v1(repo, use_llm=False, rules_org=True)
    assert "REPO-069" in _ids(plain)
    facts = account.read(_factory(_late(rds=_RDS_RESERVED)))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, rules_org=True, account_facts=facts)
    assert "REPO-069" not in _ids(findings)


def test_denied_service_reads_are_warnings_not_findings(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    facts = account.read(_factory(_late(
        macie2={"get_macie_session": _MACIE_DENIED},
        s3control={"list_storage_lens_configurations": _Denied("AccessDenied")},
        cur={"describe_report_definitions": _Denied("AccessDeniedException")},
        bcm_data_exports={"list_exports": {"Exports": []}})))
    _r, _c, findings, warnings = analyze_v1(repo, use_llm=False, rules_org=True, account_facts=facts)
    # Not readable adds nothing; REPO-069 stays as rules.org decides (here: no export in the repo).
    assert not {"SEC-065", "COST-018", "ACCT-004"} & _ids(findings)
    assert not {"SEC-065", "COST-018", "ACCT-004"} & facts.checked
    assert any("Macie: access denied (macie2:GetMacieSession)" in w for w in warnings)
    assert any("S3 Storage Lens: access denied" in w for w in warnings)
    assert any("Cost and Usage Report: access denied" in w and "ACCT-004" in w for w in warnings)


def test_an_excluded_service_is_not_read(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    calls: list[str] = []
    facts = account.read(_recording(_late(macie2={"get_macie_session": _MACIE_OFF}), calls))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts, rules_exclude=["SEC-065"])
    assert "macie2.get_macie_session" not in calls and "SEC-065" not in _ids(findings)


def test_an_app_template_without_the_flag_gains_no_macie_finding(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET, _LAMBDA)
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False)
    assert not {"SEC-065", "COST-018", "ACCT-004"} & _ids(findings)


def test_the_cost_export_read_follows_the_org_gate(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    calls: list[str] = []
    facts = account.read(_recording(_late(**_NO_EXPORT), calls))
    _r, ctx, findings, warnings = analyze_v1(repo, use_llm=False, account_facts=facts)  # gate closed
    assert not any(c.split(".")[0] in {"cur", "bcm-data-exports"} for c in calls)
    assert not {"ACCT-004", "REPO-069"} & _ids(findings)
    assert not any("ACCT-004" in w for w in warnings)
    assert "ACCT-004" not in ctx.rules_run
    cost3 = next(a for a in answers(findings, ctx.rules_run) if a.question.id == "COST 3")
    assert "COST03-BP01" in cost3.needs_org  # off, not unmet
    assert "ACCT-004" in ORG_RULE_IDS and account.ORG_CONTROL_IDS <= ORG_RULE_IDS


def test_naming_repo_069_in_rules_include_opens_the_gate(tmp_path: Path) -> None:
    repo = _cf_repo(tmp_path, _BUCKET)
    calls: list[str] = []
    facts = account.read(_recording(_late(**_NO_EXPORT), calls))
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, account_facts=facts, rules_include=["REPO-069"])
    assert "cur.describe_report_definitions" in calls
    assert "ACCT-004" in facts.checked


def test_a_repeated_page_token_ends_the_read() -> None:
    calls: list[dict[str, Any]] = []

    def call(**kw: Any) -> dict[str, Any]:
        calls.append(kw)
        return {"ReservedDBInstances": [{"State": "retired"}], "Marker": "same"}

    found = account._any_page("RDS Reserved Instances", "rds:DescribeReservedDBInstances", call,
                              "ReservedDBInstances", "Marker", "Marker",
                              lambda r: r.get("State") == "active")
    assert found is False
    assert len(calls) == 2  # the first page, then the repeated token once
