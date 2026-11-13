"""REL 11: withstanding component failures. Capacity that rides out a failure (REPO-057),
an availability target on the edge (REPO-058), and someone told when availability drops
(REPO-059)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    AvailabilityNotificationMissing,
    AvailabilityTargetMissing,
    StaticStabilityMissing,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object, env: str = "prod") -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / env / _PATHS[source], body)


# REPO-057: a fleet whose literal minimum is one.

ASG_OF_ONE = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Web', { vpc, instanceType, machineImage, "
           "maxCapacity: 4 });\n",
    "cloudformation": {"Web": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "MinSize": "1", "MaxSize": "4"}}},
    "terraform": 'resource "aws_autoscaling_group" "web" {\n  min_size = 1\n  max_size = 4\n}\n',
}
ASG_OF_TWO = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Web', { vpc, instanceType, machineImage, "
           "minCapacity: 2, maxCapacity: 4 });\n",
    "cloudformation": {"Web": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "MinSize": "2", "MaxSize": "4"}}},
    "terraform": 'resource "aws_autoscaling_group" "web" {\n  min_size = 2\n  max_size = 4\n}\n',
}
TASKS_OF_ONE = {
    "cdk": "const service = new ecs.FargateService(this, 'Api', { cluster, taskDefinition, "
           "desiredCount: 2 });\nservice.autoScaleTaskCount({ maxCapacity: 6 });\n",
    "cloudformation": {
        "Api": {"Type": "AWS::ECS::Service", "Properties": {"DesiredCount": 2}},
        "Tasks": {"Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": {
            "ScalableDimension": "ecs:service:DesiredCount", "MinCapacity": 1,
            "MaxCapacity": 6}}},
    "terraform": 'resource "aws_ecs_service" "api" {\n  desired_count = 2\n}\n'
                 'resource "aws_appautoscaling_target" "tasks" {\n'
                 '  scalable_dimension = "ecs:service:DesiredCount"\n'
                 '  min_capacity = 1\n  max_capacity = 6\n}\n',
}
TASKS_OF_TWO = {
    "cdk": "const service = new ecs.FargateService(this, 'Api', { cluster, taskDefinition, "
           "desiredCount: 2 });\nservice.autoScaleTaskCount({ minCapacity: 2, maxCapacity: 6 });\n",
    "cloudformation": {
        "Api": {"Type": "AWS::ECS::Service", "Properties": {"DesiredCount": 2}},
        "Tasks": {"Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": {
            "ScalableDimension": "ecs:service:DesiredCount", "MinCapacity": 2,
            "MaxCapacity": 6}}},
    "terraform": 'resource "aws_ecs_service" "api" {\n  desired_count = 2\n}\n'
                 'resource "aws_appautoscaling_target" "tasks" {\n'
                 '  scalable_dimension = "ecs:service:DesiredCount"\n'
                 '  min_capacity = 2\n  max_capacity = 6\n}\n',
}
SERVICE_OF_ONE = {
    "cdk": "new ecs.FargateService(this, 'Api', { cluster, taskDefinition, desiredCount: 1 });\n",
    "cloudformation": {"Api": {"Type": "AWS::ECS::Service", "Properties": {"DesiredCount": 1}}},
    "terraform": 'resource "aws_ecs_service" "api" {\n  desired_count = 1\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_group_of_one_fails_repo_057(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG_OF_ONE[source])
    (finding,) = StaticStabilityMissing().run(tmp_path)
    assert finding.id == "REPO-057"
    assert "Auto Scaling group" in finding.evidence and "minimum 1" in finding.evidence
    assert finding.file and finding.file.startswith("prod/")


@pytest.mark.parametrize("source", SOURCES)
def test_group_of_two_passes_repo_057(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG_OF_TWO[source])
    assert StaticStabilityMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_task_count_of_one_fails_repo_057(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, TASKS_OF_ONE[source])
    (finding,) = StaticStabilityMissing().run(tmp_path)
    assert "minimum 1" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_task_count_of_two_passes_repo_057(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, TASKS_OF_TWO[source])
    assert StaticStabilityMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_service_of_one_without_scaling_fails_repo_057(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SERVICE_OF_ONE[source])
    (finding,) = StaticStabilityMissing().run(tmp_path)
    assert "desired count 1" in finding.evidence


def test_service_of_one_that_scales_from_two_passes_repo_057(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", SERVICE_OF_ONE["terraform"], TASKS_OF_TWO["terraform"])
    assert StaticStabilityMissing().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
@pytest.mark.parametrize("source", SOURCES)
def test_dev_fleet_of_one_does_not_fire_repo_057(tmp_path: Path, source: str, env: str) -> None:
    _stack(tmp_path, source, ASG_OF_ONE[source], env=env)
    assert StaticStabilityMissing().run(tmp_path) == []


def test_minimum_from_a_variable_is_not_judged(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf",
           'resource "aws_autoscaling_group" "web" {\n  min_size = var.min\n}\n')
    _write(tmp_path / "prod" / "stack.template.json", json.dumps({"Resources": {
        "Web": {"Type": "AWS::AutoScaling::AutoScalingGroup",
                "Properties": {"MinSize": {"Ref": "Min"}, "MaxSize": "4"}}}}))
    _write(tmp_path / "prod" / "stack.ts",
           "new autoscaling.AutoScalingGroup(this, 'Web', { minCapacity: props.min });\n")
    assert StaticStabilityMissing().run(tmp_path) == []


def test_python_cdk_group_of_one(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "autoscaling.AutoScalingGroup(self, 'Web', vpc=vpc, min_capacity=1, max_capacity=4)\n")
    assert StaticStabilityMissing().run(tmp_path)


# REPO-058: an alarm on the edge error or latency metric, or an SLO.

EDGE = {
    "cdk": "const api = new apigateway.RestApi(this, 'Api');\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n}\n',
}
EDGE_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Errors', { metric: api.metricServerError(), "
           "threshold: 1, evaluationPeriods: 1 });\n",
    "cloudformation": {"Errors": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/ApiGateway", "MetricName": "5XXError", "Threshold": 1}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "errors" {\n'
                 '  namespace = "AWS/ApiGateway"\n  metric_name = "5XXError"\n}\n',
}
SLO = {
    "cdk": "new applicationsignals.CfnServiceLevelObjective(this, 'Slo', { name: 'api', sli });\n",
    "cloudformation": {"Slo": {"Type": "AWS::ApplicationSignals::ServiceLevelObjective",
                               "Properties": {"Name": "api"}}},
    "terraform": 'resource "aws_applicationsignals_service_level_objective" "api" {\n'
                 '  name = "api"\n}\n',
}
CANARY = {
    "cdk": "new synthetics.Canary(this, 'Probe', { schedule, test, runtime });\n",
    "cloudformation": {"Probe": {"Type": "AWS::Synthetics::Canary", "Properties": {}}},
    "terraform": 'resource "aws_synthetics_canary" "probe" {\n  name = "probe"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_edge_without_target_fails_repo_058(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source])
    (finding,) = AvailabilityTargetMissing().run(tmp_path)
    assert finding.id == "REPO-058"
    assert "API Gateway" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_edge_alarm_passes_repo_058(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source], EDGE_ALARM[source])
    assert AvailabilityTargetMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_slo_passes_repo_058(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source], SLO[source])
    assert AvailabilityTargetMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_edge_with_only_a_canary_fails_repo_058(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source], CANARY[source])
    assert len(AvailabilityTargetMissing().run(tmp_path)) == 1


def test_no_edge_does_not_fire_repo_058(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_lambda_function" "fn" {\n}\n')
    assert AvailabilityTargetMissing().run(tmp_path) == []


# REPO-059: an alarm that notifies, Incident Manager, Chatbot, or AWS Health events.

COMPUTE = {
    "cdk": "new lambda.Function(this, 'Fn', { runtime, handler, code });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}
SILENT_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Errors', { metric, threshold: 1, evaluationPeriods: 1 });\n",
    "cloudformation": {"Errors": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "MetricName": "Errors", "Namespace": "AWS/Lambda", "Threshold": 1}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "errors" {\n'
                 '  metric_name = "Errors"\n}\n',
}
SNS_ALARM = {
    "cdk": "const alarm = new cloudwatch.Alarm(this, 'Errors', { metric, threshold: 1, "
           "evaluationPeriods: 1 });\nalarm.addAlarmAction(new actions.SnsAction(topic));\n",
    "cloudformation": {
        "Alerts": {"Type": "AWS::SNS::Topic", "Properties": {}},
        "Errors": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
            "MetricName": "Errors", "Namespace": "AWS/Lambda", "Threshold": 1,
            "AlarmActions": [{"Ref": "Alerts"}]}}},
    "terraform": 'resource "aws_sns_topic" "alerts" {}\n'
                 'resource "aws_cloudwatch_metric_alarm" "errors" {\n'
                 '  metric_name = "Errors"\n'
                 '  alarm_actions = [aws_sns_topic.alerts.arn]\n}\n',
}
RESPONSE_PLAN = {
    "cdk": "new ssmincidents.CfnResponsePlan(this, 'Plan', { name: 'p', incidentTemplate });\n",
    "cloudformation": {"Plan": {"Type": "AWS::SSMIncidents::ResponsePlan", "Properties": {}}},
    "terraform": 'resource "aws_ssmincidents_response_plan" "plan" {\n  name = "p"\n}\n',
}
CHATBOT = {
    "cdk": "new chatbot.SlackChannelConfiguration(this, 'Chat', { slackChannelConfigurationName: "
           "'ops', slackWorkspaceId: 'T1', slackChannelId: 'C1' });\n",
    "cloudformation": {"Chat": {"Type": "AWS::Chatbot::SlackChannelConfiguration",
                                "Properties": {}}},
    "terraform": 'resource "aws_chatbot_slack_channel_configuration" "chat" {\n}\n',
}
HEALTH_RULE = {
    "cdk": "new events.Rule(this, 'Health', { eventPattern: { source: ['aws.health'] }, "
           "targets: [new targets.SnsTopic(topic)] });\n",
    "cloudformation": {"Health": {"Type": "AWS::Events::Rule", "Properties": {
        "EventPattern": {"source": ["aws.health"]},
        "Targets": [{"Id": "t", "Arn": {"Ref": "Alerts"}}]}}},
    "terraform": 'resource "aws_cloudwatch_event_rule" "health" {\n'
                 '  event_pattern = jsonencode({ source = ["aws.health"] })\n}\n'
                 'resource "aws_cloudwatch_event_target" "health" {\n'
                 '  rule = aws_cloudwatch_event_rule.health.name\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_silent_alarm_fails_repo_059(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, COMPUTE[source], SILENT_ALARM[source])
    (finding,) = AvailabilityNotificationMissing().run(tmp_path)
    assert finding.id == "REPO-059"
    assert "searched the IaC" in finding.evidence


@pytest.mark.parametrize("control", (SNS_ALARM, RESPONSE_PLAN, CHATBOT, HEALTH_RULE),
                         ids=("sns-alarm", "response-plan", "chatbot", "health-rule"))
@pytest.mark.parametrize("source", SOURCES)
def test_notification_passes_repo_059(tmp_path: Path, source: str, control: dict) -> None:
    _stack(tmp_path, source, COMPUTE[source], control[source])
    assert AvailabilityNotificationMissing().run(tmp_path) == []


def test_alarm_on_a_ref_that_is_not_a_topic_fails_repo_059(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", COMPUTE["cloudformation"], {
        "Errors": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
            "MetricName": "Errors", "Threshold": 1, "AlarmActions": [{"Ref": "Fn"}]}}})
    assert len(AvailabilityNotificationMissing().run(tmp_path)) == 1


def test_health_rule_without_a_target_fails_repo_059(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", COMPUTE["terraform"],
           'resource "aws_cloudwatch_event_rule" "health" {\n'
           '  event_pattern = jsonencode({ source = ["aws.health"] })\n}\n')
    assert len(AvailabilityNotificationMissing().run(tmp_path)) == 1


def test_no_compute_does_not_fire_repo_059(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_s3_bucket" "b" {}\n')
    assert AvailabilityNotificationMissing().run(tmp_path) == []


# Shared: saved reports, mapping, the REL 11 answer.

@pytest.mark.parametrize("rule, fixture", (
    (StaticStabilityMissing, ASG_OF_ONE["terraform"]),
    (AvailabilityTargetMissing, EDGE["terraform"]),
    (AvailabilityNotificationMissing, COMPUTE["terraform"]),
), ids=("REPO-057", "REPO-058", "REPO-059"))
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(
    tmp_path: Path, rule: type, fixture: str,
) -> None:
    _stack(tmp_path, "terraform", fixture)
    (hit,) = rule().run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", text)
    assert len(rule().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", text)
    assert rule().run(empty) == []


@pytest.mark.parametrize("rule_id, practice", (
    ("REPO-057", "REL11-BP05"), ("REPO-058", "REL11-BP07"), ("REPO-059", "REL11-BP06"),
))
def test_rules_map_to_rel11_and_run_by_default(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert rule_id not in ORG_RULE_IDS


def test_rel11_checks_every_best_practice() -> None:
    (rel11,) = [a for a in well_architected.answers([]) if a.question.id == "REL 11"]
    assert rel11.not_checked == () and rel11.met


def test_rel11_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", EDGE["terraform"])
    findings = AvailabilityTargetMissing().run(tmp_path)
    (rel11,) = [a for a in well_architected.answers(findings) if a.question.id == "REL 11"]
    assert not rel11.met
