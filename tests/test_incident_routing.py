"""OPS 10: every alarm has an action, and an escalation path follows the first notification."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.registry import ALL_RULES

RULE_BY_ID = {r.id: r for r in ALL_RULES}
PLAN_ARN = "arn:aws:ssm-incidents::111122223333:response-plan/critical"
CONTACT_ARN = "arn:aws:ssm-contacts:eu-west-1:111122223333:contact/oncall"


def _scan(root: Path, text: str, name: str) -> list:
    (root / name).write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _alarm(**props: object) -> dict:
    base = {"Namespace": "AWS/SQS", "MetricName": "ApproximateAgeOfOldestMessage",
            "Statistic": "Maximum", "Period": 60, "EvaluationPeriods": 1, "Threshold": 300,
            "ComparisonOperator": "GreaterThanThreshold"}
    return {"Type": "AWS::CloudWatch::Alarm", "Properties": {**base, **props}}


TOPIC = {"Type": "AWS::SNS::Topic", "Properties": {}}
NOTIFY = {"Topic": TOPIC, "Alarm": _alarm(AlarmActions=[{"Ref": "Topic"}])}


def _ids(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


# --- CF-ALARM-002: an alarm with no action ---

@pytest.mark.parametrize(
    ("resources", "fires"),
    [
        ({"Alarm": _alarm()}, True),
        ({"Alarm": _alarm(AlarmActions=[])}, True),
        ({"Topic": TOPIC, "Alarm": _alarm(AlarmActions=[{"Ref": "Topic"}], ActionsEnabled=False)},
         True),
        ({"Topic": TOPIC, "Alarm": _alarm(AlarmActions=[{"Ref": "Topic"}], ActionsEnabled="false")},
         True),
        ({"Composite": {"Type": "AWS::CloudWatch::CompositeAlarm",
                        "Properties": {"AlarmRule": "ALARM(other)"}}}, True),
        (NOTIFY, False),
        ({"Topic": TOPIC, "Alarm": _alarm(AlarmActions=[{"Ref": "Topic"}], ActionsEnabled=True)},
         False),
        ({"Alarm": _alarm(AlarmActions=[PLAN_ARN])}, False),
        ({"Alarm": _alarm(AlarmActions=[
            "arn:aws:ssm:eu-west-1:111122223333:opsitem:3#CATEGORY=Availability"])}, False),
    ],
)
def test_cf_alarm_002_on_cloudformation(tmp_path: Path, resources: dict, fires: bool) -> None:
    found = _ids(_scan(tmp_path, _cfn(resources), "stack.template.json"), "CF-ALARM-002")
    assert bool(found) is fires
    if fires:
        assert found[0].question == "OPS 10"
        assert found[0].best_practices == ["OPS10-BP02"]


TF_TOPIC = 'resource "aws_sns_topic" "alerts" {\n  name = "alerts"\n}\n'
TF_ALARM = (
    'resource "aws_cloudwatch_metric_alarm" "age" {\n'
    '  alarm_name          = "age"\n  namespace           = "AWS/SQS"\n'
    '  metric_name         = "ApproximateAgeOfOldestMessage"\n'
    '  comparison_operator = "GreaterThanThreshold"\n  evaluation_periods  = 1\n'
    '  threshold           = 300\n%s}\n'
)
TF_NOTIFY = TF_TOPIC + TF_ALARM % "  alarm_actions = [aws_sns_topic.alerts.arn]\n"


@pytest.mark.parametrize(
    ("text", "fires"),
    [
        (TF_ALARM % "", True),
        (TF_ALARM % "  alarm_actions = []\n", True),
        (TF_TOPIC + TF_ALARM % (
            "  alarm_actions = [aws_sns_topic.alerts.arn]\n  actions_enabled = false\n"), True),
        ('resource "aws_cloudwatch_composite_alarm" "c" {\n  alarm_name = "c"\n'
         '  alarm_rule = "ALARM(other)"\n}\n', True),
        (TF_NOTIFY, False),
        (TF_ALARM % "  alarm_actions = var.actions\n", False),
    ],
)
def test_cf_alarm_002_on_terraform(tmp_path: Path, text: str, fires: bool) -> None:
    found = _ids(_scan(tmp_path, text, "main.tf"), "CF-ALARM-002")
    assert bool(found) is fires
    if fires:
        assert found[0].file == "main.tf"
        assert found[0].question == "OPS 10"


# --- CF-ALARM-003: alarms notify, and nothing escalates ---

def _plan(**props: object) -> dict:
    return {"Type": "AWS::SSMIncidents::ResponsePlan",
            "Properties": {"Name": "critical", "IncidentTemplate": {"Title": "t", "Impact": 2},
                           **props}}


def _contact(kind: str, **props: object) -> dict:
    return {"Type": "AWS::SSMContacts::Contact",
            "Properties": {"Alias": "c", "DisplayName": "c", "Type": kind, **props}}


STAGE = {"DurationInMinutes": 5, "Targets": []}


@pytest.mark.parametrize(
    ("extra", "fires"),
    [
        ({}, True),
        ({"Plan": _plan()}, True),
        ({"Plan": _plan(Engagements=[])}, True),
        ({"Person": _contact("PERSONAL", Plan=[STAGE])}, True),
        ({"Plan": _plan(Engagements=[CONTACT_ARN])}, False),
        ({"Plan": _plan(Engagements={"Ref": "Contacts"})}, False),
        ({"Escalation": _contact("ESCALATION")}, False),
        ({"Person": _contact("PERSONAL", Plan=[STAGE, STAGE])}, False),
        ({"Stages": {"Type": "AWS::SSMContacts::Plan",
                     "Properties": {"ContactId": CONTACT_ARN, "Stages": [STAGE, STAGE]}}}, False),
        ({"Nested": {"Type": "AWS::CloudFormation::Stack",
                     "Properties": {"TemplateURL": "https://example.com/t.json"}}}, False),
    ],
)
def test_cf_alarm_003_on_cloudformation(tmp_path: Path, extra: dict, fires: bool) -> None:
    found = _ids(_scan(tmp_path, _cfn({**NOTIFY, **extra}), "stack.template.json"), "CF-ALARM-003")
    assert bool(found) is fires
    if fires:
        assert found[0].question == "OPS 10"
        assert found[0].best_practices == ["OPS10-BP01", "OPS10-BP04"]
        assert "AWS::SSMIncidents::ResponsePlan" in (found[0].suggested_code or "")


@pytest.mark.parametrize(
    ("actions", "fires"),
    [
        ([PLAN_ARN], False),
        ([{"Ref": "Topic"}, {"Ref": "Plan"}], False),
        ([{"Fn::GetAtt": ["Plan", "Arn"]}], False),
        ([{"Fn::Join": ["", ["arn:", {"Ref": "AWS::Partition"},
                             ":ssm-incidents::", {"Ref": "AWS::AccountId"}, ":response-plan/p"]]}],
         False),
        ([{"Fn::Sub": "arn:${AWS::Partition}:ssm-incidents::${AWS::AccountId}:response-plan/p"}],
         False),
        ([{"Ref": "AlarmTargetParameter"}], False),  # a parameter: not known, not judged
        ([{"Fn::Sub": "${Topic}"}], True),
        (["arn:aws:sns:eu-west-1:111122223333:alerts"], True),
    ],
)
def test_cf_alarm_003_reads_the_alarm_actions(tmp_path: Path, actions: list, fires: bool) -> None:
    resources = {"Topic": TOPIC, "Plan": _plan(), "Alarm": _alarm(AlarmActions=actions)}
    found = _ids(_scan(tmp_path, _cfn(resources), "stack.template.json"), "CF-ALARM-003")
    assert bool(found) is fires


def test_cf_alarm_003_needs_an_alarm_that_notifies(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _cfn({"Alarm": _alarm()}), "stack.template.json")
    assert _ids(findings, "CF-ALARM-002")
    assert not _ids(findings, "CF-ALARM-003")


TF_CONTACT = 'resource "aws_ssmcontacts_contact" "c" {\n  alias = "c"\n  type = "%s"\n}\n'
TF_RESPONSE_PLAN = (
    'resource "aws_ssmincidents_response_plan" "p" {\n  name = "p"\n%s'
    '  incident_template {\n    title  = "t"\n    impact = 2\n  }\n}\n'
)
TF_STAGE = '  stage {\n    duration_in_minutes = 5\n  }\n'


@pytest.mark.parametrize(
    ("extra", "fires"),
    [
        ("", True),
        (TF_CONTACT % "PERSONAL", True),
        (TF_RESPONSE_PLAN % "", True),
        ('resource "aws_ssmcontacts_plan" "s" {\n  contact_id = "x"\n' + TF_STAGE + '}\n', True),
        (TF_CONTACT % "ESCALATION", False),
        (TF_RESPONSE_PLAN % '  engagements = [aws_ssmcontacts_contact.c.arn]\n', False),
        (TF_RESPONSE_PLAN % '  engagements = var.contacts\n', False),
        ('resource "aws_ssmcontacts_plan" "s" {\n  contact_id = "x"\n' + TF_STAGE * 2 + '}\n',
         False),
        ('module "oncall" {\n  source = "git::https://example.com/oncall.git"\n}\n', False),
    ],
)
def test_cf_alarm_003_on_terraform(tmp_path: Path, extra: str, fires: bool) -> None:
    found = _ids(_scan(tmp_path, TF_NOTIFY + extra, "main.tf"), "CF-ALARM-003")
    assert bool(found) is fires
    if fires:
        assert found[0].file == "main.tf"
        assert found[0].question == "OPS 10"
        assert "aws_ssmincidents_response_plan" in (found[0].suggested_code or "")


@pytest.mark.parametrize(
    ("actions", "fires"),
    [
        ("[aws_sns_topic.alerts.arn, aws_ssmincidents_response_plan.p.arn]", False),
        (f'["{PLAN_ARN}"]', False),
        ("[data.aws_ssm_parameter.target.value]", False),
        ("[aws_sns_topic.alerts.arn]", True),
    ],
)
def test_cf_alarm_003_reads_terraform_alarm_actions(
        tmp_path: Path, actions: str, fires: bool) -> None:
    text = TF_TOPIC + TF_RESPONSE_PLAN % "" + TF_ALARM % f"  alarm_actions = {actions}\n"
    found = _ids(_scan(tmp_path, text, "main.tf"), "CF-ALARM-003")
    assert bool(found) is fires


# --- OPS-027 on CDK source (positive and negative cases live in rule_cases.json) ---

@pytest.mark.parametrize(
    ("source", "fires"),
    [
        ("new cloudwatch.Alarm(this, 'A', {}).addAlarmAction(new SnsAction(topic));", True),
        ("queue.metricApproximateAgeOfOldestMessage().createAlarm(this, 'Age', {});", True),
        ("new cloudwatch.Alarm(this, 'A', {});\nnew ssmcontacts.CfnContact(this, 'C', {});", False),
        ("new s3.Bucket(this, 'B');", False),
    ],
)
def test_ops_027_on_cdk(tmp_path: Path, source: str, fires: bool) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(source + "\n", encoding="utf-8")
    found = RULE_BY_ID["OPS-027"].run(tmp_path, "typescript")
    assert bool(found) is fires


def test_ops_027_finding_answers_ops10(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "cdk.json").write_text('{"app": "npx ts-node bin/app.ts"}', encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text(
        "new cloudwatch.Alarm(this, 'A', {}).addAlarmAction(new SnsAction(topic));\n",
        encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    found = _ids(findings, "OPS-027")
    assert found and found[0].question == "OPS 10"
    assert found[0].best_practices == ["OPS10-BP01", "OPS10-BP04"]
