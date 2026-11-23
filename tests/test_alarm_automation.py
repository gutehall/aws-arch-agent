"""CF-ALARM-004: an alarm starts automation, not only a notification (OPS10-BP07)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform
from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

_SNS = "arn:aws:sns:eu-west-1:111122223333:ops"


def _found(found: list[Finding]) -> set[str]:
    out = {(f.evidence or "").split(" ")[0] for f in found if f.id == "CF-ALARM-004"}
    assert all(f.severity == "Low" for f in found if f.id == "CF-ALARM-004")
    return out


def _cf(tmp_path: Path, resources: dict) -> set[str]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _found(found)


def _tf(tmp_path: Path, text: str) -> set[str]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _found(run_resource_checks(resources, tmp_path / "main.tf"))


def _alarm(*actions: Any) -> dict:
    return {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/Lambda", "MetricName": "Errors", "AlarmActions": list(actions)}}


_POLICY = {"Type": "AWS::AutoScaling::ScalingPolicy", "Properties": {"AutoScalingGroupName": "g"}}
_STATE_RULE = {"Type": "AWS::Events::Rule", "Properties": {
    "EventPattern": {"source": ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"]},
    "Targets": [{"Id": "fn", "Arn": "arn:aws:lambda:eu-west-1:111122223333:function:respond"}]}}


def test_answers_ops10_bp07_only() -> None:
    assert RULE_BEST_PRACTICES["CF-ALARM-004"] == ("OPS10-BP07",)


def test_cf_notification_or_scaling_only(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"A": _alarm(_SNS)}) == {"A"}
    assert _cf(tmp_path, {"P": _POLICY, "A": _alarm({"Ref": "P"})}) == {"A"}
    scaling = "arn:aws:autoscaling:eu-west-1:111122223333:scalingPolicy:x"
    assert _cf(tmp_path, {"A": _alarm(scaling)}) == {"A"}


def test_cf_automation_actions_pass(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"A": _alarm("arn:aws:automate:eu-west-1:ec2:recover")}) == set()
    fn = {"Type": "AWS::Lambda::Function", "Properties": {}}
    assert _cf(tmp_path, {"Fn": fn, "A": _alarm(_SNS, {"Fn::GetAtt": ["Fn", "Arn"]})}) == set()
    opsitem = {"Fn::Sub": "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:opsitem:3#CATEGORY=Availability"}
    assert _cf(tmp_path, {"A": _alarm(opsitem)}) == set()
    assert _cf(tmp_path, {"A": _alarm({"Ref": "ActionArn"})}) == set()  # a parameter: not judged


def test_cf_alarm_state_rule_or_ssm_target_passes(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"A": _alarm(_SNS), "R": _STATE_RULE}) == set()
    doc = {"Type": "AWS::SSM::Document", "Properties": {"DocumentType": "Automation", "Content": {}}}
    rule = {"Type": "AWS::Events::Rule", "Properties": {"ScheduleExpression": "rate(1 day)", "Targets": [
        {"Id": "doc", "Arn": {"Fn::Sub": "arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:automation-definition/${Doc}"}}]}}
    assert _cf(tmp_path, {"A": _alarm(_SNS), "Doc": doc, "R": rule}) == set()


def test_cf_rule_on_other_events_does_not_count(tmp_path: Path) -> None:
    rule = {"Type": "AWS::Events::Rule", "Properties": {
        "EventPattern": {"source": ["aws.ec2"]}, "Targets": [{"Id": "t", "Arn": _SNS}]}}
    assert _cf(tmp_path, {"A": _alarm(_SNS), "R": rule}) == {"A"}


def test_cf_no_alarm_is_not_judged(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"P": _POLICY}) == set()


def _tf_alarm(actions: str) -> str:
    return ('resource "aws_cloudwatch_metric_alarm" "errors" {\n  alarm_name = "errors"\n'
            '  namespace = "AWS/Lambda"\n  metric_name = "Errors"\n  comparison_operator = "GreaterThanThreshold"\n'
            '  evaluation_periods = 1\n  threshold = 1\n  period = 60\n  statistic = "Sum"\n'
            f'  alarm_actions = [{actions}]\n}}\n')


_TF_TOPIC = 'resource "aws_sns_topic" "ops" {\n  name = "ops"\n}\n'
_TF_POLICY = 'resource "aws_autoscaling_policy" "up" {\n  name = "up"\n  autoscaling_group_name = "g"\n}\n'


def test_tf_notification_or_scaling_only(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_TOPIC + _tf_alarm("aws_sns_topic.ops.arn")) == {"aws_cloudwatch_metric_alarm.errors"}
    assert _tf(tmp_path, _TF_POLICY + _tf_alarm("aws_autoscaling_policy.up.arn")) == {
        "aws_cloudwatch_metric_alarm.errors"}


def test_tf_lambda_action_passes(tmp_path: Path) -> None:
    fn = 'resource "aws_lambda_function" "respond" {\n  function_name = "respond"\n  role = "r"\n}\n'
    assert _tf(tmp_path, fn + _tf_alarm("aws_lambda_function.respond.arn")) == set()


def test_tf_alarm_state_rule_passes(tmp_path: Path) -> None:
    rule = ('resource "aws_cloudwatch_event_rule" "alarms" {\n  name = "alarms"\n'
            '  event_pattern = jsonencode({\n    source = ["aws.cloudwatch"]\n'
            '    "detail-type" = ["CloudWatch Alarm State Change"]\n  })\n}\n'
            'resource "aws_cloudwatch_event_target" "respond" {\n  rule = aws_cloudwatch_event_rule.alarms.name\n'
            '  arn = "arn:aws:lambda:eu-west-1:111122223333:function:respond"\n}\n')
    assert _tf(tmp_path, _TF_TOPIC + _tf_alarm("aws_sns_topic.ops.arn") + rule) == set()


def test_tf_ssm_automation_target_passes(tmp_path: Path) -> None:
    doc = ('resource "aws_ssm_document" "restart" {\n  name = "restart"\n  document_type = "Automation"\n'
           '  content = "{}"\n}\n'
           'resource "aws_cloudwatch_event_rule" "daily" {\n  name = "daily"\n  schedule_expression = "rate(1 day)"\n}\n'
           'resource "aws_cloudwatch_event_target" "restart" {\n  rule = aws_cloudwatch_event_rule.daily.name\n'
           '  arn = aws_ssm_document.restart.arn\n}\n')
    assert _tf(tmp_path, _TF_TOPIC + _tf_alarm("aws_sns_topic.ops.arn") + doc) == set()


def test_tf_remote_module_may_hold_the_rule(tmp_path: Path) -> None:
    module = 'module "ops" {\n  source = "app.terraform.io/acme/ops/aws"\n}\n'
    assert _tf(tmp_path, _TF_TOPIC + _tf_alarm("aws_sns_topic.ops.arn") + module) == set()
