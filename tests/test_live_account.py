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


def _account(hub: Any) -> dict[str, dict[str, Any]]:
    return {
        "sts": {"get_caller_identity": {"Account": "111122223333"}},
        "securityhub": {"describe_hub": hub, "get_enabled_standards": {"StandardsSubscriptions": [{"x": 1}]}},
        "guardduty": {"list_detectors": {"DetectorIds": []}},
        "cloudtrail": {"describe_trails": {"trailList": []}},
        "config": {"describe_configuration_recorder_status": {"ConfigurationRecordersStatus": []}},
        "budgets": {"describe_budgets": {"Budgets": []}},
        "cur": {"describe_report_definitions": {"ReportDefinitions": []}},
        "accessanalyzer": {"list_analyzers": {"analyzers": []}},
        "inspector2": {"batch_get_account_status": {"accounts": []}},
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
    assert facts.enabled == {"SEC-026", "REPO-136", "REPO-162", "REPO-163"}
    assert ctx.notes["live_account"]["enabled"] == ["REPO-136", "REPO-162", "REPO-163", "SEC-026"]
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
        "cur": {"describe_report_definitions": {"ReportDefinitions": [{"ReportName": "r"}]}},
        "accessanalyzer": {"list_analyzers": {"analyzers": [{"status": "ACTIVE"}]}},
        "inspector2": {"batch_get_account_status": {"accounts": [{"state": {"status": "ENABLED"}}]}},
    }))
    assert facts.checked == facts.enabled
    assert facts.checked <= ORG_RULE_IDS
    assert {"SEC-027", "OPS-001", "OPS-014", "COST-014", "REPO-069", "REPO-141", "REPO-145", "REPO-163"} <= facts.enabled


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
    assert data["context"]["notes"]["live_account"]["enabled"] == ["REPO-136", "REPO-162", "REPO-163", "SEC-026"]
