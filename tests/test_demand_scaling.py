"""REL 7: fleets that cannot grow on demand (REPO-049) and scaling that reacts only to CPU or
memory (REPO-050)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    CpuOnlyScaling,
    FixedSizeFleet,
    fixed_fleets,
    scaling_policies,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / _PATHS[source], body)


def _ids(rule: object, root: Path) -> list[str]:
    return [f.id for f in rule.run(root)]  # type: ignore[attr-defined]


# --- REPO-049: a fleet has a fixed size ---

ECS_SERVICE = {
    "cdk": "const svc = new ecs.FargateService(this, 'Web', { cluster, taskDefinition });\n",
    "cloudformation": {"Web": {"Type": "AWS::ECS::Service", "Properties": {
        "Cluster": {"Ref": "Cluster"}, "DesiredCount": 2}}},
    "terraform": 'resource "aws_ecs_service" "web" {\n  name          = "web"\n'
                 '  desired_count = 2\n}\n',
}
ECS_TARGET = {
    "cdk": "const scaling = svc.autoScaleTaskCount({ maxCapacity: 6 });\n",
    "cloudformation": {"Target": {
        "Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": {
            "ServiceNamespace": "ecs", "ScalableDimension": "ecs:service:DesiredCount",
            "MinCapacity": 2, "MaxCapacity": 6, "ResourceId": "service/c/web"}}},
    "terraform": 'resource "aws_appautoscaling_target" "web" {\n  service_namespace  = "ecs"\n'
                 '  scalable_dimension = "ecs:service:DesiredCount"\n'
                 '  resource_id        = "service/c/web"\n  min_capacity = 2\n'
                 '  max_capacity = 6\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_ecs_service_without_a_scalable_target_fires(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ECS_SERVICE[source])
    (finding,) = FixedSizeFleet().run(tmp_path)
    assert "ECS service" in finding.evidence and "no Application Auto Scaling" in finding.evidence
    assert finding.file == _PATHS[source] and finding.line


@pytest.mark.parametrize("source", SOURCES)
def test_ecs_service_with_a_scalable_target_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ECS_SERVICE[source], ECS_TARGET[source])
    assert fixed_fleets(tmp_path) == []
    assert _ids(FixedSizeFleet(), tmp_path) == []


def test_daemon_and_queue_processing_services_are_not_judged(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk",
           "new ecs.Ec2Service(this, 'Agent', { cluster, taskDefinition, daemon: true });\n"
           "new ecsPatterns.QueueProcessingFargateService(this, 'Worker', { image });\n")
    _write(tmp_path / "main.tf", 'resource "aws_ecs_service" "agent" {\n'
                                 '  scheduling_strategy = "DAEMON"\n}\n')
    assert _ids(FixedSizeFleet(), tmp_path) == []


ASG_FIXED = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Asg', { vpc, instanceType, machineImage, "
           "minCapacity: 3, maxCapacity: 3 });\n",
    "cloudformation": {"Asg": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "MinSize": "3", "MaxSize": "3"}}},
    "terraform": 'resource "aws_autoscaling_group" "asg" {\n  min_size = 3\n  max_size = 3\n}\n',
}
ASG_RANGE = {
    "cdk": "const asg = new autoscaling.AutoScalingGroup(this, 'Asg', { vpc, instanceType, "
           "machineImage, minCapacity: 2, maxCapacity: 8 });\n",
    "cloudformation": {"Asg": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "MinSize": "2", "MaxSize": "8"}}},
    "terraform": 'resource "aws_autoscaling_group" "asg" {\n  min_size = 2\n  max_size = 8\n}\n',
}
ASG_POLICY = {
    "cdk": "asg.scaleOnRequestCount('Requests', { targetRequestsPerMinute: 600 });\n",
    "cloudformation": {"Requests": {"Type": "AWS::AutoScaling::ScalingPolicy", "Properties": {
        "AutoScalingGroupName": {"Ref": "Asg"}, "PolicyType": "TargetTrackingScaling",
        "TargetTrackingConfiguration": {"PredefinedMetricSpecification": {
            "PredefinedMetricType": "ALBRequestCountPerTarget"}, "TargetValue": 100}}}},
    "terraform": 'resource "aws_autoscaling_policy" "requests" {\n'
                 '  autoscaling_group_name = aws_autoscaling_group.asg.name\n'
                 '  policy_type = "TargetTrackingScaling"\n'
                 '  target_tracking_configuration {\n    predefined_metric_specification {\n'
                 '      predefined_metric_type = "ALBRequestCountPerTarget"\n    }\n'
                 '    target_value = 100\n  }\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_group_with_min_equal_to_max_fires_even_with_a_policy(
    tmp_path: Path, source: str
) -> None:
    _stack(tmp_path, source, ASG_FIXED[source], ASG_POLICY[source])
    (finding,) = FixedSizeFleet().run(tmp_path)
    assert "minimum and maximum size both 3" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_group_without_a_scaling_policy_fires(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG_RANGE[source])
    (finding,) = FixedSizeFleet().run(tmp_path)
    assert "no scaling policy in the repo" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_group_with_a_range_and_a_policy_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG_RANGE[source], ASG_POLICY[source])
    assert _ids(FixedSizeFleet(), tmp_path) == []


def test_cdk_group_defaults_to_a_fixed_size_of_one(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk",
           "const asg = new autoscaling.AutoScalingGroup(this, 'Asg', { vpc, instanceType });\n",
           "asg.scaleOnCpuUtilization('Cpu', { targetUtilizationPercent: 50 });\n")
    (finding,) = FixedSizeFleet().run(tmp_path)
    assert "minimum and maximum size both 1" in finding.evidence


def test_sizes_from_variables_and_parameters_are_not_judged(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", 'resource "aws_autoscaling_group" "asg" {\n'
                                 '  min_size = var.size\n  max_size = var.size\n}\n'
                                 + ASG_POLICY["terraform"])
    _write(tmp_path / "lib" / "stack.ts",
           "new autoscaling.AutoScalingGroup(this, 'Asg', { ...props, maxCapacity: 4 });\n")
    _write(tmp_path / "stack.template.json", json.dumps({"Resources": {"Asg": {
        "Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
            "MinSize": {"Ref": "Size"}, "MaxSize": {"Ref": "Size"}}}}}))
    assert _ids(FixedSizeFleet(), tmp_path) == []


PROVISIONED_TABLE = {
    "cdk": "const table = new dynamodb.Table(this, 'Orders', { partitionKey, "
           "billingMode: dynamodb.BillingMode.PROVISIONED, readCapacity: 5, "
           "writeCapacity: 5 });\n",
    "cloudformation": {"Orders": {"Type": "AWS::DynamoDB::Table", "Properties": {
        "KeySchema": [], "ProvisionedThroughput": {
            "ReadCapacityUnits": 5, "WriteCapacityUnits": 5}}}},
    "terraform": 'resource "aws_dynamodb_table" "orders" {\n  name = "orders"\n'
                 '  read_capacity  = 5\n  write_capacity = 5\n  hash_key = "id"\n}\n',
}
TABLE_SCALING = {
    "cdk": "table.autoScaleReadCapacity({ minCapacity: 5, maxCapacity: 50 })"
           ".scaleOnUtilization({ targetUtilizationPercent: 70 });\n",
    "cloudformation": {"ReadTarget": {
        "Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": {
            "ServiceNamespace": "dynamodb",
            "ScalableDimension": "dynamodb:table:ReadCapacityUnits",
            "ResourceId": "table/orders", "MinCapacity": 5, "MaxCapacity": 50}}},
    "terraform": 'resource "aws_appautoscaling_target" "read" {\n'
                 '  service_namespace  = "dynamodb"\n'
                 '  scalable_dimension = "dynamodb:table:ReadCapacityUnits"\n'
                 '  resource_id = "table/orders"\n  min_capacity = 5\n  max_capacity = 50\n}\n',
}
ON_DEMAND_TABLE = {
    "cdk": "new dynamodb.Table(this, 'Orders', { partitionKey, "
           "billingMode: dynamodb.BillingMode.PAY_PER_REQUEST });\n",
    "cloudformation": {"Orders": {"Type": "AWS::DynamoDB::Table", "Properties": {
        "KeySchema": [], "BillingMode": "PAY_PER_REQUEST"}}},
    "terraform": 'resource "aws_dynamodb_table" "orders" {\n  name = "orders"\n'
                 '  billing_mode = "PAY_PER_REQUEST"\n  hash_key = "id"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_provisioned_table_without_auto_scaling_fires(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, PROVISIONED_TABLE[source])
    (finding,) = FixedSizeFleet().run(tmp_path)
    assert "DynamoDB table" in finding.evidence and "provisioned capacity" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_provisioned_table_with_auto_scaling_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, PROVISIONED_TABLE[source], TABLE_SCALING[source])
    assert _ids(FixedSizeFleet(), tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_on_demand_table_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ON_DEMAND_TABLE[source])
    assert _ids(FixedSizeFleet(), tmp_path) == []


def test_evidence_names_each_fleet_with_its_line(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", ECS_SERVICE["terraform"], ASG_FIXED["terraform"],
           PROVISIONED_TABLE["terraform"])
    (finding,) = FixedSizeFleet().run(tmp_path)
    assert "ECS service web at main.tf:1" in finding.evidence
    assert "Auto Scaling group asg at main.tf:5" in finding.evidence
    assert "DynamoDB table orders at main.tf:" in finding.evidence


# --- REPO-050: scaling reacts only to CPU or memory ---

CPU_POLICY = {
    "cdk": "svc.autoScaleTaskCount({ maxCapacity: 6 })"
           ".scaleOnCpuUtilization('Cpu', { targetUtilizationPercent: 60 });\n",
    "cloudformation": {"Cpu": {"Type": "AWS::ApplicationAutoScaling::ScalingPolicy",
                               "Properties": {
        "PolicyName": "cpu", "PolicyType": "TargetTrackingScaling",
        "ScalingTargetId": {"Ref": "Target"},
        "TargetTrackingScalingPolicyConfiguration": {"PredefinedMetricSpecification": {
            "PredefinedMetricType": "ECSServiceAverageCPUUtilization"}, "TargetValue": 60}}}},
    "terraform": 'resource "aws_appautoscaling_policy" "cpu" {\n  name = "cpu"\n'
                 '  policy_type = "TargetTrackingScaling"\n'
                 '  target_tracking_scaling_policy_configuration {\n'
                 '    predefined_metric_specification {\n'
                 '      predefined_metric_type = "ECSServiceAverageCPUUtilization"\n    }\n'
                 '    target_value = 60\n  }\n}\n',
}
REQUEST_POLICY = {
    "cdk": "scaling.scaleOnRequestCount('Requests', { requestsPerTarget: 100, targetGroup });\n",
    "cloudformation": {"Requests": {"Type": "AWS::ApplicationAutoScaling::ScalingPolicy",
                                    "Properties": {
        "PolicyName": "requests", "PolicyType": "TargetTrackingScaling",
        "ScalingTargetId": {"Ref": "Target"},
        "TargetTrackingScalingPolicyConfiguration": {"PredefinedMetricSpecification": {
            "PredefinedMetricType": "ALBRequestCountPerTarget"}, "TargetValue": 100}}}},
    "terraform": 'resource "aws_appautoscaling_policy" "requests" {\n  name = "requests"\n'
                 '  policy_type = "TargetTrackingScaling"\n'
                 '  target_tracking_scaling_policy_configuration {\n'
                 '    predefined_metric_specification {\n'
                 '      predefined_metric_type = "ALBRequestCountPerTarget"\n    }\n'
                 '    target_value = 100\n  }\n}\n',
}
QUEUE_POLICY = {
    "cdk": "scaling.scaleOnMetric('Backlog', { metric: "
           "queue.metricApproximateNumberOfMessagesVisible(), scalingSteps });\n",
    "cloudformation": {
        "Backlog": {"Type": "AWS::ApplicationAutoScaling::ScalingPolicy", "Properties": {
            "PolicyName": "backlog", "PolicyType": "StepScaling",
            "ScalingTargetId": {"Ref": "Target"},
            "StepScalingPolicyConfiguration": {"AdjustmentType": "ChangeInCapacity"}}},
        "BacklogAlarm": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
            "MetricName": "ApproximateNumberOfMessagesVisible", "Namespace": "AWS/SQS",
            "Threshold": 100, "AlarmActions": [{"Ref": "Backlog"}]}}},
    "terraform": 'resource "aws_appautoscaling_policy" "backlog" {\n  name = "backlog"\n'
                 '  policy_type = "StepScaling"\n}\n'
                 'resource "aws_cloudwatch_metric_alarm" "backlog" {\n'
                 '  metric_name = "ApproximateNumberOfMessagesVisible"\n  threshold = 100\n'
                 '  alarm_actions = [aws_appautoscaling_policy.backlog.arn]\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_cpu_only_policies_fire(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ECS_SERVICE[source], ECS_TARGET[source], CPU_POLICY[source])
    (finding,) = CpuOnlyScaling().run(tmp_path)
    assert "reacts to CPU or memory" in finding.evidence
    assert finding.file == _PATHS[source] and finding.line


@pytest.mark.parametrize("source", SOURCES)
def test_a_request_count_policy_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, CPU_POLICY[source], REQUEST_POLICY[source])
    assert {kind for *_, kind in scaling_policies(tmp_path)} == {"cpu", "other"}
    assert _ids(CpuOnlyScaling(), tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_a_queue_depth_policy_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, CPU_POLICY[source], QUEUE_POLICY[source])
    assert _ids(CpuOnlyScaling(), tmp_path) == []


def test_step_scaling_on_a_cpu_alarm_is_cpu(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform",
           'resource "aws_autoscaling_policy" "up" {\n  policy_type = "StepScaling"\n}\n'
           'resource "aws_cloudwatch_metric_alarm" "high" {\n'
           '  metric_name = "CPUUtilization"\n  threshold = 80\n'
           '  alarm_actions = [aws_autoscaling_policy.up.arn]\n}\n')
    assert [f.id for f in CpuOnlyScaling().run(tmp_path)] == ["REPO-050"]


def test_predictive_scaling_and_queue_processing_services_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", CPU_POLICY["cdk"],
           "new ecsPatterns.QueueProcessingFargateService(this, 'Worker', { image });\n")
    assert _ids(CpuOnlyScaling(), tmp_path) == []
    other = tmp_path / "tf"
    _stack(other, "terraform", CPU_POLICY["terraform"],
           'resource "aws_autoscaling_policy" "forecast" {\n'
           '  policy_type = "PredictiveScaling"\n}\n')
    assert _ids(CpuOnlyScaling(), other) == []


def test_no_policy_or_only_dynamodb_utilization_does_not_fire(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", ECS_SERVICE["cdk"])
    assert _ids(CpuOnlyScaling(), tmp_path) == []
    _stack(tmp_path, "cdk", PROVISIONED_TABLE["cdk"], TABLE_SCALING["cdk"])
    assert scaling_policies(tmp_path) == []
    assert _ids(CpuOnlyScaling(), tmp_path) == []


# --- self-match, mapping, and the REL 7 answer ---

_RULES = (FixedSizeFleet, CpuOnlyScaling)
_ALL = ["REPO-049", "REPO-050"]


def test_saved_reports_quoting_the_findings_neither_pass_nor_fire(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", ECS_SERVICE["terraform"], CPU_POLICY["terraform"])
    hits = [f for rule in _RULES for f in rule().run(tmp_path)]
    assert sorted(f.id for f in hits) == _ALL
    report = json.dumps({"findings": [h.model_dump() for h in hits]})
    markdown = "\n".join(f"- {h.title}: {h.evidence}. {h.recommendation}" for h in hits)
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", markdown)
    assert sorted(f.id for rule in _RULES for f in rule().run(tmp_path)) == _ALL
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", markdown)
    assert [f for rule in _RULES for f in rule().run(empty)] == []


def test_rule_text_matches_no_control(tmp_path: Path) -> None:
    """The rules' own words, saved as code, pass no control and declare nothing."""
    words = "\n".join(f"{r.title}\n{r.recommendation}" for r in (rule() for rule in _RULES))
    _stack(tmp_path, "terraform", ECS_SERVICE["terraform"], CPU_POLICY["terraform"])
    _write(tmp_path / "notes.ts", words)
    assert sorted(f.id for rule in _RULES for f in rule().run(tmp_path)) == _ALL
    assert len(scaling_policies(tmp_path)) == 1


def test_rules_map_to_rel7_and_run_by_default() -> None:
    assert well_architected.best_practices_of("REPO-049") == ("REL07-BP03",)
    assert well_architected.best_practices_of("REPO-050") == ("REL07-BP02",)
    assert not set(_ALL) & set(ORG_RULE_IDS)
    for rule in _RULES:
        assert rule.category == "Reliability" and rule.themes == ("resilience",)


def test_rel7_reads_one_answer_with_only_load_testing_unchecked() -> None:
    (rel7,) = [a for a in well_architected.answers([]) if a.question.id == "REL 7"]
    assert rel7.not_checked == ("REL07-BP04",)
    assert not rel7.met and rel7.reason() == "1 of 4 best practices not checked"
    hit = FixedSizeFleet()._finding("fixed fleet")
    (failing,) = [a for a in well_architected.answers([hit]) if a.question.id == "REL 7"]
    assert not failing.met and [f.id for f in failing.findings] == ["REPO-049"]
