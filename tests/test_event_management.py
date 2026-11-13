"""OPS 10: events are prioritised (REPO-109), customers have a channel (REPO-110), alarm state
has a dashboard (REPO-111) and a response is automated (REPO-112)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import (
    CustomerCommunicationMissing,
    EventResponseNotAutomated,
    EventSeverityMissing,
    EventStatusDashboardMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TF_ALARM = (
    'resource "aws_cloudwatch_metric_alarm" "errors" {\n  alarm_name = "api-errors"\n'
    '  metric_name = "5XXError"\n}\n'
)
_TF_ALARM_SEV = _TF_ALARM.replace("api-errors", "sev2-api-errors")
_CFN_ALARM = (
    '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"A": {"Type": '
    '"AWS::CloudWatch::Alarm", "Properties": {"AlarmName": "api-errors", '
    '"MetricName": "5XXError"}}}}'
)
_CDK_ALARM = "new cloudwatch.Alarm(this, 'Errors', { metric, threshold: 1, evaluationPeriods: 1 });\n"
_TF_PLAN = 'resource "aws_ssmincidents_response_plan" "p" {\n  name = "plan"\n}\n'
_TF_PLAN_IMPACT = 'resource "aws_ssmincidents_response_plan" "p" {\n  incident_template {\n    impact = 2\n  }\n}\n'


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str]) -> list:
    # Under prod/: the pytest directory name says "test", which reads as a dev stack.
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops10() -> None:
    for rule_id, bp in (("REPO-109", "OPS10-BP03"), ("REPO-110", "OPS10-BP05"),
                        ("REPO-111", "OPS10-BP06"), ("REPO-112", "OPS10-BP07")):
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


_SOURCES = [
    {"main.tf": _TF_ALARM},
    {"t.json": _CFN_ALARM},
    {"lib/stack.ts": _CDK_ALARM},
]
_IDS = ["terraform", "cloudformation", "cdk"]


@pytest.mark.parametrize("rule_id", ["REPO-109", "REPO-110", "REPO-111", "REPO-112"])
@pytest.mark.parametrize("files", _SOURCES, ids=_IDS)
def test_alarms_alone_fail(tmp_path: Path, rule_id: str, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), rule_id)
    assert hit.question == "OPS 10"
    assert hit.category == "Operational Excellence"
    assert "CloudWatch alarms" in hit.evidence or "alarms" in hit.evidence


@pytest.mark.parametrize("rule_id", ["REPO-109", "REPO-110", "REPO-111", "REPO-112"])
def test_no_alarms_or_plans_does_not_fire(tmp_path: Path, rule_id: str) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}), rule_id)


@pytest.mark.parametrize(
    "files",
    [
        {"main.tf": _TF_ALARM_SEV},
        {"main.tf": _TF_ALARM + '  tags = { Severity = "high" }\n'},
        {"main.tf": _TF_ALARM + "# priority P1\n"},
        {"main.tf": _TF_ALARM + _TF_PLAN_IMPACT},
    ],
    ids=["name", "tag", "comment-priority", "plan-impact"],
)
def test_severity_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-109")


def test_response_plan_without_impact_fails(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, {"main.tf": _TF_PLAN}), "REPO-109")
    assert "response plans" in hit.evidence


@pytest.mark.parametrize(
    "files",
    [
        {"main.tf": _TF_ALARM + 'resource "aws_sns_topic" "customer_status" {}\n'},
        {"lib/stack.ts": _CDK_ALARM + "new sns.Topic(this, 'StatusPageUpdates');\n"},
        {"main.tf": _TF_ALARM, "ses.tf": 'resource "aws_ses_template" "customer_notice" {}\n'},
    ],
    ids=["sns-customer", "cdk-status-page", "ses-customer"],
)
def test_customer_channel_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-110")


def test_operator_topic_only_fails(tmp_path: Path) -> None:
    files = {"main.tf": _TF_ALARM + 'resource "aws_sns_topic" "ops_alarms" {}\n'}
    assert _found(_scan(tmp_path, files), "REPO-110")


@pytest.mark.parametrize(
    "files",
    [
        {"main.tf": _TF_ALARM + 'resource "aws_cloudwatch_dashboard" "d" {\n'
                                '  dashboard_body = jsonencode({widgets = [{type = "alarm"}]})\n}\n'},
        {"lib/stack.ts": _CDK_ALARM + "new cloudwatch.Dashboard(this, 'D', "
                                      "{ widgets: [[new cloudwatch.AlarmStatusWidget({ alarms })]] });\n"},
    ],
    ids=["terraform", "cdk"],
)
def test_alarm_status_dashboard_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-111")


def test_dashboard_without_alarm_widget_fails(tmp_path: Path) -> None:
    files = {"main.tf": _TF_ALARM + 'resource "aws_cloudwatch_dashboard" "d" {\n'
                                    '  dashboard_body = jsonencode({widgets = [{type = "metric"}]})\n}\n'}
    (hit,) = _found(_scan(tmp_path, files), "REPO-111")
    assert "no alarm status widget" in hit.evidence


@pytest.mark.parametrize(
    "files",
    [
        {"main.tf": _TF_ALARM + 'resource "aws_cloudwatch_event_rule" "r" {\n'
                                '  event_pattern = jsonencode({"detail-type" = ["CloudWatch Alarm State Change"]})\n}\n'
                                'resource "aws_cloudwatch_event_target" "t" {\n  arn = aws_lambda_function.f.arn\n}\n'},
        {"main.tf": _TF_ALARM + 'resource "aws_cloudwatch_event_target" "t" {\n'
                                '  arn = "arn:aws:ssm:eu-west-1::automation-definition/Restart:$DEFAULT"\n}\n'},
        {"main.tf": _TF_PLAN + '  action {\n    ssm_automation {\n      document_name = "Restart"\n    }\n  }\n'},
        {"main.tf": _TF_ALARM + 'resource "aws_cloudwatch_metric_alarm" "b" {\n'
                                '  alarm_actions = ["arn:aws:ssm:eu-west-1:1:opsitem"]\n}\n'},
    ],
    ids=["eventbridge-alarm-state", "ssm-automation-target", "plan-action", "alarm-action-opsitem"],
)
def test_automated_response_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-112")


def test_scaling_policy_alone_is_not_an_event_response(tmp_path: Path) -> None:
    files = {"main.tf": _TF_ALARM + 'resource "aws_autoscaling_policy" "p" {}\n'}
    assert _found(_scan(tmp_path, files), "REPO-112")


def test_rules_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "alarm.tf", _TF_ALARM)
    for rule in (EventSeverityMissing(), CustomerCommunicationMissing(),
                 EventStatusDashboardMissing(), EventResponseNotAutomated()):
        assert not rule.run(tmp_path)
