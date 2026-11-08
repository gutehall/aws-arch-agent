"""CloudWatch alarms and dashboards, and what a trail records: CF-ALARM-001..002, CF-DASH-001, CF-CT-004..005."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.config import ConfigError, dashboards_min_resources, load_config
from aws_arch_agent.models import Finding
from aws_arch_agent.rules import stack_cost
from aws_arch_agent.rules.cf_template import (
    run_cf_rules_from_paths,
    run_resource_checks,
    use_dashboard_min_resources,
)
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.resource_model import TF_MODULE_CALL
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-ALARM-001", "CF-ALARM-002", "CF-DASH-001", "CF-CT-004", "CF-CT-005")
_PARAM = {"Ref": "Param"}
_FN = {"Type": "AWS::Lambda::Function", "Properties": {}}
_QUEUE = {"Type": "AWS::SQS::Queue", "Properties": {}}
_TF_FN = 'resource "aws_lambda_function" "f" {\n function_name = "f"\n role = "r"\n}\n'


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            assert f.severity == "Low"
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict, name: str = "t.json") -> dict[str, set[str]]:
    path = tmp_path / name
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _by_id(found)


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _alarm(**props: Any) -> dict:
    return {"Type": "AWS::CloudWatch::Alarm", "Properties": {"AlarmActions": ["arn:aws:sns:eu-west-1:1:t"], **props}}


def _dim(name: str, value: Any) -> dict:
    return {"Dimensions": [{"Name": name, "Value": value}]}


# --- CF-ALARM-001 ---


def test_alarm_001_one_finding_at_first_resource(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"Fn": _FN, "Q": _QUEUE})
    assert found["CF-ALARM-001"] == {"Fn"}


@pytest.mark.parametrize("value", [{"Ref": "Fn"}, {"Fn::GetAtt": ["Fn", "Arn"]}, {"Fn::Sub": "${Fn}"}])
def test_alarm_001_reference_covers_stack(tmp_path: Path, value: Any) -> None:
    found = _cf(tmp_path, {"Fn": _FN, "Q": _QUEUE, "A": _alarm(**_dim("FunctionName", value))})
    assert "CF-ALARM-001" not in found


def test_alarm_001_alarm_on_something_else_does_not_count(tmp_path: Path) -> None:
    resources = {"Fn": _FN, "I": {"Type": "AWS::EC2::Instance", "Properties": {}},
                 "A": _alarm(**_dim("InstanceId", {"Ref": "I"}))}
    assert _cf(tmp_path, resources)["CF-ALARM-001"] == {"Fn"}


@pytest.mark.parametrize("props", [
    _dim("InstanceId", _PARAM),
    _dim("FunctionName", {"Fn::ImportValue": "x"}),
    {"Dimensions": _PARAM},
    {"Namespace": _PARAM},
    {"Metrics": _PARAM},
    {"Metrics": [{"Id": "q", "Expression": "SELECT AVG(Errors) FROM \"AWS/Lambda\""}]},
    {"Metrics": [{"Id": "m", "MetricStat": {"Metric": {"Namespace": "Custom", **_dim("X", _PARAM)}}}]},
], ids=["other-key", "import", "dims", "namespace", "metrics", "query", "metric-param"])
def test_alarm_001_unknown_counts_for_all(tmp_path: Path, props: dict) -> None:
    assert "CF-ALARM-001" not in _cf(tmp_path, {"Fn": _FN, "A": _alarm(**props)})


def test_alarm_001_reads_metric_stat(tmp_path: Path) -> None:
    metric = {"Namespace": "AWS/Lambda", **_dim("FunctionName", {"Ref": "Fn"})}
    alarm = _alarm(Metrics=[{"Id": "e", "Expression": "m*2"}, {"Id": "m", "MetricStat": {"Metric": metric}}])
    assert "CF-ALARM-001" not in _cf(tmp_path, {"Fn": _FN, "A": alarm})


def test_alarm_001_math_alone_does_not_count(tmp_path: Path) -> None:
    metric = {"Namespace": "Custom", **_dim("Team", "a")}
    alarm = _alarm(Metrics=[{"Id": "e", "Expression": "m*2"}, {"Id": "m", "MetricStat": {"Metric": metric}}])
    assert _cf(tmp_path, {"Fn": _FN, "A": alarm})["CF-ALARM-001"] == {"Fn"}


def test_alarm_001_literal_name(tmp_path: Path) -> None:
    named = {"Type": "AWS::Lambda::Function", "Properties": {"FunctionName": "orders"}}
    assert "CF-ALARM-001" not in _cf(tmp_path, {"Fn": named, "A": _alarm(**_dim("FunctionName", "orders"))})
    assert _cf(tmp_path, {"Fn": named, "A": _alarm(**_dim("FunctionName", "other"))})["CF-ALARM-001"] == {"Fn"}
    # The function's name is generated or unknown: the literal may be it.
    assert "CF-ALARM-001" not in _cf(tmp_path, {"Fn": _FN, "A": _alarm(**_dim("FunctionName", "orders"))})


def test_alarm_001_service_metric_with_no_naming_dimension(tmp_path: Path) -> None:
    assert "CF-ALARM-001" not in _cf(tmp_path, {"Fn": _FN, "A": _alarm(Namespace="AWS/Lambda")})
    assert _cf(tmp_path, {"Q": _QUEUE, "A": _alarm(Namespace="AWS/Lambda")})["CF-ALARM-001"] == {"Q"}
    cluster = _alarm(Namespace="AWS/ECS", **_dim("ClusterName", "c"))
    service = {"Type": "AWS::ECS::Service", "Properties": {}}
    assert "CF-ALARM-001" not in _cf(tmp_path, {"S": service, "A": cluster})


def test_alarm_001_composite_does_not_count(tmp_path: Path) -> None:
    composite = {"Type": "AWS::CloudWatch::CompositeAlarm",
                 "Properties": {"AlarmRule": _PARAM, "AlarmActions": ["arn:aws:sns:eu-west-1:1:t"]}}
    assert _cf(tmp_path, {"Fn": _FN, "C": composite})["CF-ALARM-001"] == {"Fn"}


@pytest.mark.parametrize("resource", [
    {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {"Type": "network"}},
    {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {"Type": _PARAM}},
    {"Type": "AWS::S3::Bucket", "Properties": {}},
], ids=["nlb", "unknown-lb", "bucket"])
def test_alarm_001_other_resources_do_not_ask_for_alarms(tmp_path: Path, resource: dict) -> None:
    assert "CF-ALARM-001" not in _cf(tmp_path, {"R": resource})


@pytest.mark.parametrize("name", [
    "LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8aFD4BFC8A",
    "CustomS3AutoDeleteObjectsCustomResourceProviderHandler9D90184F",
])
def test_alarm_001_cdk_helper_function_is_not_a_target(tmp_path: Path, name: str) -> None:
    assert "CF-ALARM-001" not in _cf(tmp_path, {name: _FN})


def test_alarm_001_alb_and_rds_are_targets(tmp_path: Path) -> None:
    alb = {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {}}
    assert _cf(tmp_path, {"L": alb})["CF-ALARM-001"] == {"L"}
    db = {"Type": "AWS::RDS::DBInstance", "Properties": {"DBInstanceClass": "db.t3.micro", "Engine": "postgres"}}
    assert _cf(tmp_path, {"D": db})["CF-ALARM-001"] == {"D"}


def test_alarm_001_nested_stack_may_hold_alarms(tmp_path: Path) -> None:
    nested = {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "https://x/y"}}
    assert "CF-ALARM-001" not in _cf(tmp_path, {"Fn": _FN, "N": nested})


def test_alarm_001_not_in_dev(tmp_path: Path) -> None:
    assert "CF-ALARM-001" not in _cf(tmp_path, {"Fn": _FN}, "dev-stack.json")
    assert "CF-ALARM-001" in _cf(tmp_path, {"Fn": _FN}, "staging-stack.json")


def test_alarm_001_terraform(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_FN)["CF-ALARM-001"] == {"aws_lambda_function.f"}


@pytest.mark.parametrize("body", [
    'dimensions = { FunctionName = aws_lambda_function.f.function_name }',
    'dimensions = { "FunctionName" = aws_lambda_function.f.function_name }',
    'dimensions = { FunctionName = "${aws_lambda_function.f.function_name}" }',
    'dimensions = { InstanceId = var.id }',
    'dimensions = var.dims',
    'dimensions = merge(var.a, var.b)',
    'dimensions = { FunctionName = "f" }',
    'namespace = var.ns',
    'namespace = "AWS/Lambda"',
    'metric_query {\n id = "m"\n metric {\n namespace = "AWS/Lambda"\n metric_name = "Errors"\n'
    ' period = 60\n stat = "Sum"\n dimensions = { FunctionName = aws_lambda_function.f.function_name }\n }\n}',
    'dynamic "metric_query" {\n for_each = var.q\n content {\n id = "m"\n }\n}',
], ids=["ref", "quoted-key", "interpolated", "var-value", "var-map", "merge", "literal-unmapped", "var-namespace",
        "namespace", "metric-query", "dynamic"])
def test_alarm_001_terraform_covered(tmp_path: Path, body: str) -> None:
    text = _TF_FN + f'resource "aws_cloudwatch_metric_alarm" "a" {{\n alarm_actions = ["x"]\n {body}\n}}\n'
    assert "CF-ALARM-001" not in _tf(tmp_path, text)


def test_alarm_001_terraform_alarm_action_is_not_a_reference(tmp_path: Path) -> None:
    text = _TF_FN + ('resource "aws_instance" "i" {\n instance_type = "t3.micro"\n}\n'
                     'resource "aws_cloudwatch_metric_alarm" "a" {\n'
                     ' alarm_actions = [aws_lambda_function.f.arn]\n'
                     ' dimensions = { InstanceId = aws_instance.i.id }\n}\n')
    assert _tf(tmp_path, text)["CF-ALARM-001"] == {"aws_lambda_function.f"}


def test_alarm_001_terraform_remote_module_may_hold_alarms(tmp_path: Path) -> None:
    text = _TF_FN + 'module "m" {\n source = "terraform-aws-modules/vpc/aws"\n}\n'
    assert "CF-ALARM-001" not in _tf(tmp_path, text)


def test_alarm_001_terraform_local_module_is_read(tmp_path: Path) -> None:
    child = tmp_path / "child"
    child.mkdir()
    (child / "main.tf").write_text('resource "aws_cloudwatch_log_group" "g" {}\n', encoding="utf-8")
    text = _TF_FN + 'module "m" {\n source = "./child"\n}\n'
    assert _tf(tmp_path, text)["CF-ALARM-001"] == {"aws_lambda_function.f"}
    (child / "main.tf").write_text('resource "aws_cloudwatch_metric_alarm" "a" {}\n', encoding="utf-8")
    assert "CF-ALARM-001" not in _tf(tmp_path, text)
    # Its own call to a remote module cannot be read.
    (child / "main.tf").write_text('module "x" {\n source = "acme/x/aws"\n}\n', encoding="utf-8")
    assert "CF-ALARM-001" not in _tf(tmp_path, text)


# --- CF-ALARM-002 ---


@pytest.mark.parametrize("props", [{}, {"AlarmActions": []}, {"OKActions": ["arn:aws:sns:eu-west-1:1:t"]}])
def test_alarm_002_no_action(tmp_path: Path, props: dict) -> None:
    alarm = {"Type": "AWS::CloudWatch::Alarm", "Properties": props}
    assert _cf(tmp_path, {"A": alarm})["CF-ALARM-002"] == {"A"}


def test_alarm_002_reads_composite(tmp_path: Path) -> None:
    composite = {"Type": "AWS::CloudWatch::CompositeAlarm", "Properties": {"AlarmRule": "ALARM(x)"}}
    assert _cf(tmp_path, {"C": composite})["CF-ALARM-002"] == {"C"}


@pytest.mark.parametrize("actions", [
    ["arn:aws:sns:eu-west-1:1:t"],
    ["arn:aws-cn:sns:cn-north-1:1:t"],
    [{"Ref": "Topic"}],
    _PARAM,
    {"Fn::If": ["C", ["x"], {"Ref": "AWS::NoValue"}]},
    [_PARAM],
    ["arn:aws:autoscaling:eu-west-1:1:scalingPolicy:x"],
    ["arn:aws:automate:eu-west-1:ec2:reboot"],
    ["arn:aws:ssm:eu-west-1:1:opsitem:3"],
    ["arn:aws:lambda:eu-west-1:1:function:f"],
    [{"Ref": "ScalingPolicy"}],
], ids=["sns", "sns-cn", "ref", "param", "if", "param-in-list", "autoscaling", "ec2", "ssm", "lambda", "policy"])
def test_alarm_002_any_action_passes(tmp_path: Path, actions: Any) -> None:
    alarm = {"Type": "AWS::CloudWatch::Alarm", "Properties": {"AlarmActions": actions}}
    assert "CF-ALARM-002" not in _cf(tmp_path, {"A": alarm})


@pytest.mark.parametrize("reader", [
    {"Type": "AWS::CloudWatch::CompositeAlarm",
     "Properties": {"AlarmRule": {"Fn::Sub": "ALARM(${A})"}, "AlarmActions": ["x"]}},
    {"Type": "AWS::CloudWatch::CompositeAlarm", "Properties": {"AlarmRule": _PARAM, "AlarmActions": ["x"]}},
    {"Type": "AWS::CloudWatch::CompositeAlarm", "Properties": {"AlarmRule": "ALARM(child)", "AlarmActions": ["x"]}},
    {"Type": "AWS::Events::Rule", "Properties": {"EventPattern": {"source": ["aws.cloudwatch"]}}},
    {"Type": "AWS::Events::Rule", "Properties": {"EventPattern": _PARAM}},
    {"Type": "AWS::Route53::HealthCheck", "Properties": {"HealthCheckConfig": {
        "Type": "CLOUDWATCH_METRIC", "AlarmIdentifier": {"Name": {"Ref": "A"}, "Region": "eu-west-1"}}}},
    {"Type": "AWS::CodeDeploy::DeploymentGroup", "Properties": {
        "AlarmConfiguration": {"Alarms": [{"Name": {"Ref": "A"}}]}}},
], ids=["composite-ref", "composite-param", "composite-literal", "event-rule", "event-param", "health-check",
        "codedeploy"])
def test_alarm_002_read_by_another_resource(tmp_path: Path, reader: dict) -> None:
    alarm = {"Type": "AWS::CloudWatch::Alarm", "Properties": {"AlarmName": "child"}}
    assert "A" not in _cf(tmp_path, {"A": alarm, "R": reader}).get("CF-ALARM-002", set())


def test_alarm_002_unrelated_readers_do_not_hide_it(tmp_path: Path) -> None:
    alarm = {"Type": "AWS::CloudWatch::Alarm", "Properties": {"AlarmName": "child"}}
    composite = {"Type": "AWS::CloudWatch::CompositeAlarm", "Properties": {"AlarmRule": "ALARM(other)",
                                                                           "AlarmActions": ["x"]}}
    rule = {"Type": "AWS::Events::Rule", "Properties": {"EventPattern": {"source": ["aws.s3"]}}}
    assert _cf(tmp_path, {"A": alarm, "C": composite, "R": rule})["CF-ALARM-002"] == {"A"}


def test_alarm_002_terraform(tmp_path: Path) -> None:
    text = ('resource "aws_cloudwatch_metric_alarm" "a" {\n alarm_name = "a"\n}\n'
            'resource "aws_cloudwatch_metric_alarm" "b" {\n alarm_name = "b"\n alarm_actions = []\n}\n'
            'resource "aws_cloudwatch_composite_alarm" "c" {\n alarm_name = "c"\n alarm_rule = "ALARM(z)"\n}\n')
    assert _tf(tmp_path, text)["CF-ALARM-002"] == {
        "aws_cloudwatch_metric_alarm.a", "aws_cloudwatch_metric_alarm.b", "aws_cloudwatch_composite_alarm.c"}


@pytest.mark.parametrize("extra", [
    'alarm_actions = var.actions',
    'alarm_actions = [var.topic]',
    'alarm_actions = [aws_autoscaling_policy.p.arn]',
    'alarm_actions = var.on ? [aws_sns_topic.t.arn] : []',
], ids=["var", "var-in-list", "scaling", "conditional"])
def test_alarm_002_terraform_not_judged(tmp_path: Path, extra: str) -> None:
    text = f'resource "aws_cloudwatch_metric_alarm" "a" {{\n alarm_name = "a"\n {extra}\n}}\n'
    assert "CF-ALARM-002" not in _tf(tmp_path, text)


@pytest.mark.parametrize("reader", [
    'resource "aws_cloudwatch_composite_alarm" "c" {\n alarm_actions = ["x"]\n'
    ' alarm_rule = "ALARM(${aws_cloudwatch_metric_alarm.a.alarm_name})"\n}\n',
    'resource "aws_cloudwatch_composite_alarm" "c" {\n alarm_actions = ["x"]\n alarm_rule = var.rule\n}\n',
    'resource "aws_cloudwatch_composite_alarm" "c" {\n alarm_actions = ["x"]\n alarm_rule = "ALARM(a)"\n}\n',
    'resource "aws_cloudwatch_event_rule" "r" {\n'
    ' event_pattern = jsonencode({ source = ["aws.cloudwatch"] })\n}\n',
    'resource "aws_cloudwatch_event_rule" "r" {\n event_pattern = var.pattern\n}\n',
    'module "m" {\n source = "acme/x/aws"\n alarm = aws_cloudwatch_metric_alarm.a.alarm_name\n}\n',
], ids=["composite-ref", "composite-var", "composite-literal", "event-rule", "event-var", "module-input"])
def test_alarm_002_terraform_read_by_another_block(tmp_path: Path, reader: str) -> None:
    text = 'resource "aws_cloudwatch_metric_alarm" "a" {\n alarm_name = "a"\n}\n' + reader
    assert "CF-ALARM-002" not in _tf(tmp_path, text)


# --- CF-DASH-001 ---


def _queues(count: int) -> dict:
    return {f"Q{i}": _QUEUE for i in range(count)}


def _tf_queues(count: int) -> str:
    return "".join(f'resource "aws_sqs_queue" "q{i}" {{}}\n' for i in range(count))


def test_dash_001_more_than_limit(tmp_path: Path) -> None:
    assert "CF-DASH-001" not in _cf(tmp_path, _queues(20))
    assert _cf(tmp_path, _queues(21))["CF-DASH-001"] == {"Q0"}


def test_dash_001_counts_only_modelled_types(tmp_path: Path) -> None:
    unmapped = {f"W{i}": {"Type": "AWS::Foo::Bar", "Properties": {}} for i in range(5)}
    assert "CF-DASH-001" not in _cf(tmp_path, {**_queues(20), **unmapped})


def test_dash_001_dashboard_present(tmp_path: Path) -> None:
    dashboard = {"Type": "AWS::CloudWatch::Dashboard", "Properties": {"DashboardBody": "{}"}}
    assert "CF-DASH-001" not in _cf(tmp_path, {**_queues(21), "D": dashboard})


def test_dash_001_nested_stack_may_hold_one(tmp_path: Path) -> None:
    nested = {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "https://x/y"}}
    assert "CF-DASH-001" not in _cf(tmp_path, {**_queues(21), "N": nested})


def test_dash_001_not_in_dev(tmp_path: Path) -> None:
    assert "CF-DASH-001" not in _cf(tmp_path, _queues(21), "dev-stack.json")


def test_dash_001_limit_is_configurable(tmp_path: Path) -> None:
    with use_dashboard_min_resources(2):
        assert _cf(tmp_path, _queues(3))["CF-DASH-001"] == {"Q0"}
    assert "CF-DASH-001" not in _cf(tmp_path, _queues(3))


def test_dash_001_terraform(tmp_path: Path) -> None:
    assert "CF-DASH-001" not in _tf(tmp_path, _tf_queues(20))
    assert _tf(tmp_path, _tf_queues(21))["CF-DASH-001"] == {"aws_sqs_queue.q0"}
    with_board = _tf_queues(21) + 'resource "aws_cloudwatch_dashboard" "d" {}\n'
    assert "CF-DASH-001" not in _tf(tmp_path, with_board)


def test_dash_001_terraform_module(tmp_path: Path) -> None:
    assert "CF-DASH-001" not in _tf(tmp_path, _tf_queues(21) + 'module "m" {\n source = "acme/x/aws"\n}\n')
    child = tmp_path / "child"
    child.mkdir()
    (child / "main.tf").write_text('resource "aws_cloudwatch_dashboard" "d" {}\n', encoding="utf-8")
    assert "CF-DASH-001" not in _tf(tmp_path, _tf_queues(21) + 'module "m" {\n source = "./child"\n}\n')
    (child / "main.tf").write_text('resource "aws_cloudwatch_metric_alarm" "a" {}\n', encoding="utf-8")
    assert "CF-DASH-001" in _tf(tmp_path, _tf_queues(21) + 'module "m" {\n source = "./child"\n}\n')


def test_module_call_does_not_count_as_a_resource(tmp_path: Path) -> None:
    calls = "".join(f'module "m{i}" {{\n source = "./c"\n}}\n' for i in range(25))
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "main.tf").write_text('resource "aws_cloudwatch_log_group" "g" {}\n', encoding="utf-8")
    assert "CF-DASH-001" not in _tf(tmp_path, calls)


def test_module_call_is_not_listed_as_not_priced() -> None:
    assert stack_cost._free(TF_MODULE_CALL)


def test_dashboards_limit_reaches_the_scan(tmp_path: Path) -> None:
    template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": _queues(3)}
    (tmp_path / "stack.json").write_text(json.dumps(template), encoding="utf-8")
    assert "CF-DASH-001" in {f.id for f in analyze_v1(tmp_path, use_llm=False, dashboards_min_resources=2)[2]}
    assert "CF-DASH-001" not in {f.id for f in analyze_v1(tmp_path, use_llm=False)[2]}


@pytest.mark.parametrize("value", [0, -1, "20", 1.5, True])
def test_dashboards_config_rejects(value: Any) -> None:
    with pytest.raises(ConfigError, match="min_resources"):
        dashboards_min_resources({"min_resources": value})


def test_dashboards_config_shape() -> None:
    assert dashboards_min_resources(None) is None
    assert dashboards_min_resources({"min_resources": 5}) == 5
    with pytest.raises(ConfigError, match="dashboards"):
        dashboards_min_resources({"other": 5})


def test_dashboards_config_loads(tmp_path: Path) -> None:
    (tmp_path / ".aws-arch-agent.yaml").write_text("dashboards:\n  min_resources: 40\n", encoding="utf-8")
    assert load_config(tmp_path).dashboards_min_resources == 40


# --- CF-CT-004 ---


def _trail(**props: Any) -> dict:
    return {"Type": "AWS::CloudTrail::Trail", "Properties": {"IsLogging": True, "S3BucketName": "logs", **props}}


def test_ct_004(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"T": _trail()})["CF-CT-004"] == {"T"}
    for value in ("arn:aws:logs:eu-west-1:1:log-group:g:*", _PARAM, {"Fn::GetAtt": ["G", "Arn"]}):
        assert "CF-CT-004" not in _cf(tmp_path, {"T": _trail(CloudWatchLogsLogGroupArn=value)})


@pytest.mark.parametrize("line", [
    'cloud_watch_logs_group_arn = "arn:aws:logs:eu-west-1:1:log-group:g:*"',
    'cloud_watch_logs_group_arn = var.arn',
    'cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.g.arn}:*"',
], ids=["literal", "var", "ref"])
def test_ct_004_terraform_set(tmp_path: Path, line: str) -> None:
    text = f'resource "aws_cloudtrail" "t" {{\n name = "t"\n s3_bucket_name = "logs"\n {line}\n}}\n'
    assert "CF-CT-004" not in _tf(tmp_path, text)


def test_ct_004_terraform_unset(tmp_path: Path) -> None:
    text = 'resource "aws_cloudtrail" "t" {\n name = "t"\n s3_bucket_name = "logs"\n}\n'
    assert _tf(tmp_path, text)["CF-CT-004"] == {"aws_cloudtrail.t"}


# --- CF-CT-005 ---


def _bucket(name: str | None = "pii-data", **props: Any) -> dict:
    return {"Type": "AWS::S3::Bucket", "Properties": {**({"BucketName": name} if name else {}), **props}}


def _data(*values: Any, kind: str = "AWS::S3::Object") -> dict:
    return {"ReadWriteType": "All", "DataResources": [{"Type": kind, "Values": list(values)}]}


def _advanced(*fields: dict) -> dict:
    return {"FieldSelectors": list(fields)}


_DATA_FIELD = {"Field": "eventCategory", "Equals": ["Data"]}
_S3_FIELD = {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}


@pytest.mark.parametrize("bucket", [
    _bucket("pii-data"),
    _bucket("confidential-docs"),
    _bucket("app-secrets"),
    _bucket("phi.records"),
    _bucket("x", Tags=[{"Key": "DataClass", "Value": "Sensitive"}]),
    _bucket("x", Tags=[{"Key": "PII", "Value": "true"}]),
], ids=["pii", "confidential", "secrets", "phi", "tag-value", "tag-key"])
def test_ct_005_sensitive_bucket(tmp_path: Path, bucket: dict) -> None:
    assert _cf(tmp_path, {"B": bucket, "T": _trail()})["CF-CT-005"] == {"T"}


@pytest.mark.parametrize("bucket", [
    _bucket("plain"),
    _bucket("non-sensitive-data"),
    _bucket("insensitive"),
    _bucket("pii-free"),
    _bucket("philosophy"),
    _bucket("x", Tags=[{"Key": "PII", "Value": "false"}]),
    _bucket("x", Tags=[{"Key": "Description", "Value": "holds no sensitive data"}]),
    _bucket("x", Tags=[{"Key": "DataClass", "Value": _PARAM}]),
    _bucket({"Ref": "PiiBucketName"}),
], ids=["plain", "non", "insensitive", "free", "substring", "key-false", "free-text", "tag-param", "name-param"])
def test_ct_005_not_marked(tmp_path: Path, bucket: dict) -> None:
    assert "CF-CT-005" not in _cf(tmp_path, {"B": bucket, "T": _trail()})


def test_ct_005_needs_trail_and_bucket(tmp_path: Path) -> None:
    assert "CF-CT-005" not in _cf(tmp_path, {"B": _bucket()})
    assert "CF-CT-005" not in _cf(tmp_path, {"T": _trail()})


@pytest.mark.parametrize("props", [
    {"EventSelectors": [{"ReadWriteType": "All"}]},
    {"EventSelectors": [_data("arn:aws:s3:::other/")]},
    {"EventSelectors": [_data({"Fn::Sub": "${Other.Arn}/"})]},
    {"EventSelectors": [_data("arn:aws:lambda", kind="AWS::Lambda::Function")]},
    {"AdvancedEventSelectors": [_advanced({"Field": "eventCategory", "Equals": ["Management"]})]},
    {"AdvancedEventSelectors": [_advanced(_DATA_FIELD, {"Field": "resources.type",
                                                        "Equals": ["AWS::Lambda::Function"]})]},
    {"AdvancedEventSelectors": [_advanced(_DATA_FIELD, _S3_FIELD, {"Field": "resources.ARN",
                                                                   "StartsWith": ["arn:aws:s3:::other/"]})]},
], ids=["management", "other-literal", "other-ref", "other-type", "adv-management", "adv-type", "adv-other"])
def test_ct_005_no_reach(tmp_path: Path, props: dict) -> None:
    resources = {"B": _bucket(), "Other": _bucket("plain"), "T": _trail(**props)}
    assert _cf(tmp_path, resources)["CF-CT-005"] == {"T"}


@pytest.mark.parametrize("props", [
    {"EventSelectors": _PARAM},
    {"AdvancedEventSelectors": _PARAM},
    {"EventSelectors": [_PARAM]},
    {"EventSelectors": [{"DataResources": _PARAM}]},
    {"EventSelectors": [{"DataResources": [_PARAM]}]},
    {"EventSelectors": [_data("arn:aws:s3:::pii-data/")]},
    {"EventSelectors": [_data("arn:aws:s3")]},
    {"EventSelectors": [_data("arn:aws:s3:::")]},
    {"EventSelectors": [_data(_PARAM)]},
    {"EventSelectors": [_data({"Fn::Sub": "${B.Arn}/"})]},
    {"EventSelectors": [{"DataResources": [{"Type": "AWS::S3::Object", "Values": _PARAM}]}]},
    {"AdvancedEventSelectors": [_PARAM]},
    {"AdvancedEventSelectors": [{"FieldSelectors": _PARAM}]},
    {"AdvancedEventSelectors": [_advanced(_DATA_FIELD, _S3_FIELD)]},
    {"AdvancedEventSelectors": [_advanced(_DATA_FIELD, {"Field": "resources.type", "Equals": _PARAM})]},
    {"AdvancedEventSelectors": [_advanced(_DATA_FIELD, _S3_FIELD, {"Field": "resources.ARN",
                                                                   "StartsWith": ["arn:aws:s3:::pii-data/"]})]},
    {"AdvancedEventSelectors": [_advanced(_DATA_FIELD, _S3_FIELD, {"Field": "resources.ARN",
                                                                   "NotStartsWith": ["arn:aws:s3:::x/"]})]},
    {"AdvancedEventSelectors": [_advanced(_DATA_FIELD, _S3_FIELD, {"Field": "resources.ARN", "StartsWith": _PARAM})]},
], ids=["param", "adv-param", "item-param", "data-param", "resource-param", "literal", "all", "all-colons",
        "value-param", "value-ref", "values-param", "adv-item-param", "adv-fields-param", "adv-all", "adv-type-param",
        "adv-literal", "adv-exclusion", "adv-arn-param"])
def test_ct_005_may_reach(tmp_path: Path, props: dict) -> None:
    assert "CF-CT-005" not in _cf(tmp_path, {"B": _bucket(), "T": _trail(**props)})


def test_ct_005_literal_selector_on_unnamed_bucket(tmp_path: Path) -> None:
    resources = {"PiiBucket": _bucket(None), "T": _trail(EventSelectors=[_data("arn:aws:s3:::other/")])}
    assert "CF-CT-005" not in _cf(tmp_path, resources)


def test_ct_005_another_trail_reaches_it(tmp_path: Path) -> None:
    resources = {"B": _bucket(), "T": _trail(), "U": _trail(EventSelectors=[_data("arn:aws:s3:::pii-data/")])}
    assert "CF-CT-005" not in _cf(tmp_path, resources)


def test_ct_005_every_trail_reported_when_none_reaches(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"B": _bucket(), "T": _trail(), "U": _trail()})["CF-CT-005"] == {"T", "U"}


def test_ct_005_trail_log_bucket_is_not_judged(tmp_path: Path) -> None:
    resources = {"AuditSecretLogs": _bucket(None), "T": _trail(S3BucketName={"Ref": "AuditSecretLogs"})}
    assert "CF-CT-005" not in _cf(tmp_path, resources)


_TF_TRAIL = 'resource "aws_cloudtrail" "t" {{\n name = "t"\n s3_bucket_name = "logs"\n {0}\n}}\n'
_TF_BUCKET = 'resource "aws_s3_bucket" "b" {\n bucket = "pii-data"\n}\n'


@pytest.mark.parametrize("body", [
    "",
    'event_selector {\n read_write_type = "All"\n}',
    'event_selector {\n data_resource {\n type = "AWS::S3::Object"\n values = ["arn:aws:s3:::other/"]\n }\n}',
    'event_selector {\n data_resource {\n type = "AWS::Lambda::Function"\n values = ["arn:aws:lambda"]\n }\n}',
    'advanced_event_selector {\n field_selector {\n field = "eventCategory"\n equals = ["Management"]\n }\n}',
], ids=["none", "management", "other", "other-type", "adv-management"])
def test_ct_005_terraform_no_reach(tmp_path: Path, body: str) -> None:
    assert _tf(tmp_path, _TF_BUCKET + _TF_TRAIL.format(body))["CF-CT-005"] == {"aws_cloudtrail.t"}


@pytest.mark.parametrize("body", [
    'event_selector {\n data_resource {\n type = "AWS::S3::Object"\n values = ["arn:aws:s3:::pii-data/"]\n }\n}',
    'event_selector {\n data_resource {\n type = "AWS::S3::Object"\n values = ["arn:aws:s3"]\n }\n}',
    'event_selector {\n data_resource {\n type = "AWS::S3::Object"\n values = ["${aws_s3_bucket.b.arn}/"]\n }\n}',
    'event_selector {\n data_resource {\n type = "AWS::S3::Object"\n values = var.arns\n }\n}',
    'event_selector {\n data_resource {\n type = "AWS::S3::Object"\n values = [var.arn]\n }\n}',
    'event_selector {\n data_resource {\n type = var.kind\n values = ["x"]\n }\n}',
    'event_selector {\n dynamic "data_resource" {\n for_each = var.r\n content {\n type = "x"\n }\n }\n}',
    'dynamic "event_selector" {\n for_each = var.s\n content {\n read_write_type = "All"\n }\n}',
    'dynamic "advanced_event_selector" {\n for_each = var.s\n content {\n name = "x"\n }\n}',
    'advanced_event_selector {\n dynamic "field_selector" {\n for_each = var.s\n content {\n field = "x"\n }\n }\n}',
    'advanced_event_selector {\n field_selector {\n field = "eventCategory"\n equals = ["Data"]\n }\n'
    ' field_selector {\n field = "resources.type"\n equals = ["AWS::S3::Object"]\n }\n}',
    'advanced_event_selector {\n field_selector {\n field = "eventCategory"\n equals = var.c\n }\n}',
], ids=["literal", "all", "ref", "var", "var-in-list", "var-type", "dynamic-data", "dynamic", "dynamic-adv",
        "dynamic-field", "adv-all", "adv-var"])
def test_ct_005_terraform_may_reach(tmp_path: Path, body: str) -> None:
    assert "CF-CT-005" not in _tf(tmp_path, _TF_BUCKET + _TF_TRAIL.format(body))


def test_ct_005_terraform_log_bucket_is_not_judged(tmp_path: Path) -> None:
    text = (_TF_BUCKET + 'resource "aws_cloudtrail" "t" {\n name = "t"\n'
            ' s3_bucket_name = aws_s3_bucket.b.id\n}\n')
    assert "CF-CT-005" not in _tf(tmp_path, text)


def test_ct_005_terraform_tag_from_variable_is_not_judged(tmp_path: Path) -> None:
    text = ('resource "aws_s3_bucket" "b" {\n bucket = "x"\n tags = { DataClass = var.c }\n}\n'
            + _TF_TRAIL.format(""))
    assert "CF-CT-005" not in _tf(tmp_path, text)


# --- every check is complete ---


@pytest.mark.parametrize("check_id", IDS)
def test_has_fix_snippets(check_id: str) -> None:
    assert check_id in SNIPPETS["cloudformation"]
    assert check_id in SNIPPETS["terraform"]
