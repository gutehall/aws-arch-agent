"""PERF 2: selecting and using compute. Compute utilization metrics collected (REPO-060),
compute that scales with demand (REPO-061), and accelerator utilization watched
(REPO-062)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    AcceleratorUtilizationUnwatched,
    ComputeMetricsMissing,
    StaticComputeFleet,
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


# REPO-060: something collects compute utilization metrics.

SERVICE = {
    "cdk": "new ecs.FargateService(this, 'Api', { cluster, taskDefinition, desiredCount: 2 });\n",
    "cloudformation": {"Api": {"Type": "AWS::ECS::Service", "Properties": {"DesiredCount": 2}}},
    "terraform": 'resource "aws_ecs_service" "api" {\n  desired_count = 2\n}\n',
}
CPU_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Cpu', { metric: service.metricCpuUtilization(), "
           "threshold: 80, evaluationPeriods: 3 });\n",
    "cloudformation": {"Cpu": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/ECS", "MetricName": "CPUUtilization", "Threshold": 80}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "cpu" {\n'
                 '  namespace = "AWS/ECS"\n  metric_name = "CPUUtilization"\n}\n',
}
ERRORS_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Errors', { metric: fn.metricErrors(), threshold: 1, "
           "evaluationPeriods: 1 });\n",
    "cloudformation": {"Errors": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/ECS", "MetricName": "Errors", "Threshold": 1}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "errors" {\n'
                 '  metric_name = "Errors"\n}\n',
}
CONTAINER_INSIGHTS = {
    "cdk": "new ecs.Cluster(this, 'Cluster', { vpc, containerInsightsV2: "
           "ecs.ContainerInsights.ENHANCED });\n",
    "cloudformation": {"Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {
        "ClusterSettings": [{"Name": "containerInsights", "Value": "enabled"}]}}},
    "terraform": 'resource "aws_ecs_cluster" "main" {\n  name = "main"\n  setting {\n'
                 '    name  = "containerInsights"\n    value = "enabled"\n  }\n}\n',
}
INSIGHTS_OFF = {
    "cdk": "new ecs.Cluster(this, 'Cluster', { vpc, containerInsights: false });\n",
    "cloudformation": {"Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {
        "ClusterSettings": [{"Name": "containerInsights", "Value": "disabled"}]}}},
    "terraform": 'resource "aws_ecs_cluster" "main" {\n  setting {\n'
                 '    name  = "containerInsights"\n    value = "disabled"\n  }\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_compute_without_metrics_fails_repo_060(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SERVICE[source])
    (finding,) = ComputeMetricsMissing().run(tmp_path)
    assert finding.id == "REPO-060"
    assert "ECS service in prod/" in finding.evidence
    assert finding.file and finding.file.startswith("prod/")


@pytest.mark.parametrize("control", (CPU_ALARM, CONTAINER_INSIGHTS),
                         ids=("cpu-alarm", "container-insights"))
@pytest.mark.parametrize("source", SOURCES)
def test_metric_collection_passes_repo_060(tmp_path: Path, source: str, control: dict) -> None:
    _stack(tmp_path, source, SERVICE[source], control[source])
    assert ComputeMetricsMissing().run(tmp_path) == []


@pytest.mark.parametrize("control", (ERRORS_ALARM, INSIGHTS_OFF),
                         ids=("errors-alarm", "insights-off"))
@pytest.mark.parametrize("source", SOURCES)
def test_other_metrics_do_not_pass_repo_060(tmp_path: Path, source: str, control: dict) -> None:
    _stack(tmp_path, source, SERVICE[source], control[source])
    assert len(ComputeMetricsMissing().run(tmp_path)) == 1


def test_cloudwatch_agent_and_lambda_duration_pass_repo_060(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_instance" "box" {\n'
           '  iam_instance_profile = "x"\n}\nresource "aws_iam_role_policy_attachment" "cw" {\n'
           '  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"\n}\n')
    assert ComputeMetricsMissing().run(tmp_path) == []
    other = tmp_path / "other"
    _write(other / "prod" / "stack.py",
           "fn = _lambda.Function(self, 'Fn', runtime=r, handler='h', code=c)\n"
           "cloudwatch.Alarm(self, 'Slow', metric=fn.metric_duration(), threshold=1000, "
           "evaluation_periods=3)\n")
    assert ComputeMetricsMissing().run(other) == []


def test_python_cdk_compute_without_metrics_fails_repo_060(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "_lambda.Function(self, 'Fn', runtime=r, handler='h', code=c)\n")
    assert ComputeMetricsMissing().run(tmp_path)


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_dev_compute_does_not_fire_repo_060(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", SERVICE["terraform"], env=env)
    assert ComputeMetricsMissing().run(tmp_path) == []


# REPO-061: production fleets with a scaling policy.

ASG = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Web', { vpc, instanceType, machineImage, "
           "minCapacity: 2, maxCapacity: 6 });\n",
    "cloudformation": {"Web": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "MinSize": "2", "MaxSize": "6"}}},
    "terraform": 'resource "aws_autoscaling_group" "web" {\n  min_size = 2\n  max_size = 6\n}\n',
}
FIXED_ASG = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Web', { vpc, instanceType, machineImage, "
           "minCapacity: 3, maxCapacity: 3 });\nasg.scaleOnRequestCount('Rps', "
           "{ targetRequestsPerMinute: 1000 });\n",
    "cloudformation": {
        "Web": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
            "MinSize": "3", "MaxSize": "3"}},
        "Track": {"Type": "AWS::AutoScaling::ScalingPolicy", "Properties": {
            "PolicyType": "TargetTrackingScaling"}}},
    "terraform": 'resource "aws_autoscaling_group" "web" {\n  min_size = 3\n  max_size = 3\n}\n'
                 'resource "aws_autoscaling_policy" "track" {\n'
                 '  policy_type = "TargetTrackingScaling"\n}\n',
}
ASG_POLICY = {
    "cdk": "asg.scaleOnCpuUtilization('Cpu', { targetUtilizationPercent: 60 });\n",
    "cloudformation": {"Track": {"Type": "AWS::AutoScaling::ScalingPolicy", "Properties": {
        "PolicyType": "TargetTrackingScaling"}}},
    "terraform": 'resource "aws_autoscaling_policy" "track" {\n'
                 '  policy_type = "TargetTrackingScaling"\n}\n',
}
SCHEDULE_ONLY = {
    "cdk": "new autoscaling.ScheduledAction(this, 'Night', { autoScalingGroup: asg, schedule, "
           "desiredCapacity: 2 });\n",
    "cloudformation": {"Night": {"Type": "AWS::AutoScaling::ScheduledAction", "Properties": {
        "DesiredCapacity": 2}}},
    "terraform": 'resource "aws_autoscaling_schedule" "night" {\n  desired_capacity = 2\n}\n',
}
TASK_SCALING = {
    "cdk": "const tasks = service.autoScaleTaskCount({ minCapacity: 2, maxCapacity: 10 });\n"
           "tasks.scaleOnRequestCount('Rps', { requestsPerTarget: 500, targetGroup });\n",
    "cloudformation": {
        "Tasks": {"Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": {
            "ScalableDimension": "ecs:service:DesiredCount", "MinCapacity": 2,
            "MaxCapacity": 10}},
        "Track": {"Type": "AWS::ApplicationAutoScaling::ScalingPolicy", "Properties": {
            "PolicyType": "TargetTrackingScaling"}}},
    "terraform": 'resource "aws_appautoscaling_target" "tasks" {\n'
                 '  scalable_dimension = "ecs:service:DesiredCount"\n'
                 '  min_capacity = 2\n  max_capacity = 10\n}\n'
                 'resource "aws_appautoscaling_policy" "track" {\n'
                 '  policy_type = "TargetTrackingScaling"\n}\n',
}
TARGET_ONLY = {
    "cloudformation": {"Tasks": {"Type": "AWS::ApplicationAutoScaling::ScalableTarget",
                                 "Properties": {"ScalableDimension": "ecs:service:DesiredCount",
                                                "MinCapacity": 2, "MaxCapacity": 10}}},
    "terraform": 'resource "aws_appautoscaling_target" "tasks" {\n'
                 '  scalable_dimension = "ecs:service:DesiredCount"\n'
                 '  min_capacity = 2\n  max_capacity = 10\n}\n',
}
LAMBDA = {
    "cdk": "new lambda.Function(this, 'Fn', { runtime, handler, code });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_service_without_scaling_fails_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SERVICE[source])
    (finding,) = StaticComputeFleet().run(tmp_path)
    assert finding.id == "REPO-061"
    assert "ECS service" in finding.evidence and "no scaling policy" in finding.evidence
    assert finding.file and finding.file.startswith("prod/")


@pytest.mark.parametrize("source", SOURCES)
def test_service_with_task_scaling_passes_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SERVICE[source], TASK_SCALING[source])
    assert StaticComputeFleet().run(tmp_path) == []


@pytest.mark.parametrize("source", ("cloudformation", "terraform"))
def test_scalable_target_without_policy_fails_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SERVICE[source], TARGET_ONLY[source])
    assert len(StaticComputeFleet().run(tmp_path)) == 1


@pytest.mark.parametrize("source", SOURCES)
def test_group_without_policy_fails_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG[source])
    (finding,) = StaticComputeFleet().run(tmp_path)
    assert "Auto Scaling group" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_group_with_policy_passes_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG[source], ASG_POLICY[source])
    assert StaticComputeFleet().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_group_with_only_a_schedule_fails_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG[source], SCHEDULE_ONLY[source])
    assert len(StaticComputeFleet().run(tmp_path)) == 1


@pytest.mark.parametrize("source", SOURCES)
def test_fixed_size_group_fails_even_with_a_policy_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FIXED_ASG[source])
    (finding,) = StaticComputeFleet().run(tmp_path)
    assert "both 3" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_serverless_only_passes_repo_061(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source])
    assert StaticComputeFleet().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_dev_fleet_does_not_fire_repo_061(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", SERVICE["terraform"], env=env)
    assert StaticComputeFleet().run(tmp_path) == []


def test_python_cdk_group_without_policy_fails_repo_061(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "autoscaling.AutoScalingGroup(self, 'Web', vpc=vpc, min_capacity=2, max_capacity=6)\n")
    assert StaticComputeFleet().run(tmp_path)
    _write(tmp_path / "prod" / "scale.py",
           "asg.scale_on_request_count('Rps', target_requests_per_minute=1000)\n")
    assert StaticComputeFleet().run(tmp_path) == []


# REPO-062: accelerator utilization watched.

GPU_HOST = {
    "cdk": "new ec2.Instance(this, 'Trainer', { vpc, machineImage, "
           "instanceType: new ec2.InstanceType('p4d.24xlarge') });\n",
    "cloudformation": {"Trainer": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": "g5.xlarge"}}},
    "terraform": 'resource "aws_instance" "trainer" {\n  instance_type = "trn1.32xlarge"\n}\n',
}
PLAIN_HOST = {
    "cdk": "new ec2.Instance(this, 'Web', { vpc, machineImage, "
           "instanceType: new ec2.InstanceType('m7g.large') });\n"
           "new ec2.Volume(this, 'Disk', { availabilityZone, volumeType: "
           "ec2.EbsDeviceVolumeType.GP3 });\n",
    "cloudformation": {
        "Web": {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "m7g.large"}},
        "Disk": {"Type": "AWS::EC2::Volume", "Properties": {"VolumeType": "gp3"}}},
    "terraform": 'resource "aws_instance" "web" {\n  instance_type = "c7g.2xlarge"\n'
                 '  root_block_device {\n    volume_type = "gp3"\n  }\n}\n',
}
GPU_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Gpu', { metric: new cloudwatch.Metric({ namespace: "
           "'CWAgent', metricName: 'nvidia_smi_utilization_gpu' }), threshold: 20, "
           "evaluationPeriods: 6 });\n",
    "cloudformation": {"Gpu": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "CWAgent", "MetricName": "nvidia_smi_utilization_gpu", "Threshold": 20}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "neuron" {\n'
                 '  namespace = "NeuronMonitor"\n  metric_name = "neuroncore_utilization"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_accelerator_without_alarm_fails_repo_062(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, GPU_HOST[source], CPU_ALARM[source])
    (finding,) = AcceleratorUtilizationUnwatched().run(tmp_path)
    assert finding.id == "REPO-062"
    assert any(t in finding.evidence for t in ("p4d.24xlarge", "g5.xlarge", "trn1.32xlarge"))


@pytest.mark.parametrize("source", SOURCES)
def test_accelerator_alarm_passes_repo_062(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, GPU_HOST[source], GPU_ALARM[source])
    assert AcceleratorUtilizationUnwatched().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_no_accelerator_does_not_fire_repo_062(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, PLAIN_HOST[source])
    assert AcceleratorUtilizationUnwatched().run(tmp_path) == []


@pytest.mark.parametrize("text, hit", (
    ('resource "aws_sagemaker_endpoint_configuration" "e" {\n'
     '  instance_type = "ml.inf2.xlarge"\n}\n', "inf2.xlarge"),
    ('resource "aws_eks_node_group" "gpu" {\n  instance_types = ["g6e.12xlarge"]\n}\n',
     "g6e.12xlarge"),
    ('resource "aws_batch_compute_environment" "b" {\n'
     '  compute_resources {\n    instance_type = ["p5.48xlarge"]\n  }\n}\n', "p5.48xlarge"),
    ('resource "aws_launch_template" "lt" {\n  instance_type = "p6-b200.48xlarge"\n}\n',
     "p6-b200.48xlarge"),
))
def test_accelerator_resources_fire_repo_062(tmp_path: Path, text: str, hit: str) -> None:
    _stack(tmp_path, "terraform", text)
    (finding,) = AcceleratorUtilizationUnwatched().run(tmp_path)
    assert hit in finding.evidence


def test_python_cdk_instance_class_fires_repo_062(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "ec2.Instance(self, 'Trainer', vpc=vpc, machine_image=ami, "
           "instance_type=ec2.InstanceType.of(ec2.InstanceClass.G5, ec2.InstanceSize.XLARGE))\n")
    (finding,) = AcceleratorUtilizationUnwatched().run(tmp_path)
    assert "InstanceClass.G5" in finding.evidence


def test_type_outside_a_compute_resource_does_not_fire_repo_062(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "sizes.json", json.dumps({"gpu": "g5.xlarge"}))
    assert AcceleratorUtilizationUnwatched().run(tmp_path) == []


# Shared: saved reports, mapping, the PERF 2 answer.

@pytest.mark.parametrize("rule, fixture", (
    (ComputeMetricsMissing, SERVICE["terraform"]),
    (StaticComputeFleet, SERVICE["terraform"]),
    (AcceleratorUtilizationUnwatched, GPU_HOST["terraform"]),
), ids=("REPO-060", "REPO-061", "REPO-062"))
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
    ("REPO-060", "PERF02-BP03"), ("REPO-061", "PERF02-BP05"), ("REPO-062", "PERF02-BP06"),
))
def test_rules_map_to_perf2_and_run_by_default(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert rule_id not in ORG_RULE_IDS


def test_perf2_is_fully_checked() -> None:
    (perf2,) = [a for a in well_architected.answers([]) if a.question.id == "PERF 2"]
    assert perf2.not_checked == ()


def test_perf2_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", SERVICE["terraform"])
    findings = StaticComputeFleet().run(tmp_path)
    (perf2,) = [a for a in well_architected.answers(findings) if a.question.id == "PERF 2"]
    assert not perf2.met
