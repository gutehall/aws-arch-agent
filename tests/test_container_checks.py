"""CF-ECS-004..011 and CF-EKS-004: more ECS and EKS settings in templates."""
import json
from datetime import date
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import eks_versions
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

# Fixed day for the checks: 1.33 is past standard support, 1.34 is not.
TODAY = date(2026, 11, 8)


@pytest.fixture(autouse=True)
def _fixed_today(monkeypatch: pytest.MonkeyPatch) -> None:
    real = eks_versions.past_standard_support
    monkeypatch.setattr(eks_versions, "past_standard_support", lambda m, today=None: real(m, today or TODAY))


def _cf(tmp_path: Path, resources: dict, check_id: str) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == check_id]


def _names(findings: list[Finding]) -> set[str]:
    return {f.evidence.split(" ")[0] for f in findings}


def _tf(tmp_path: Path, hcl: str, check_id: str) -> set[str]:
    (tmp_path / "main.tf").write_text(hcl, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    found = _names([f for f in run_resource_checks(resources, tmp_path / "main.tf") if f.id == check_id])
    return {name.split(".")[-1] for name in found}  # aws_ecs_service.x -> x


def _task(containers: list | None = None, **props) -> dict:
    if containers is not None:
        props["ContainerDefinitions"] = containers
    return {"Type": "AWS::ECS::TaskDefinition", "Properties": props}


def _service(**props) -> dict:
    return {"Type": "AWS::ECS::Service", "Properties": props}


def _cluster(*settings, **props) -> dict:
    if settings:
        props["ClusterSettings"] = list(settings)
    return {"Type": "AWS::ECS::Cluster", "Properties": props}


def _eks(**props) -> dict:
    return {"Type": "AWS::EKS::Cluster", "Properties": {"RoleArn": "arn:aws:iam::1:role/eks", **props}}


def _public_ip(value) -> dict:
    return {"AwsvpcConfiguration": {"AssignPublicIp": value}}


def test_host_network_with_privileged_or_root_cloudformation(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Privileged": _task([{"Name": "a", "Privileged": True}], NetworkMode="host"),
        "Root": _task([{"Name": "a", "User": "root"}], NetworkMode="host"),
        "RootGroup": _task([{"Name": "a", "User": "0:0"}], NetworkMode="host"),
        "NonRoot": _task([{"Name": "a", "User": "1000"}], NetworkMode="host"),
        "UserUnset": _task([{"Name": "a"}], NetworkMode="host"),
        "UserParam": _task([{"Name": "a", "User": {"Ref": "U"}}], NetworkMode="host"),
        "PrivilegedParam": _task([{"Name": "a", "Privileged": {"Ref": "P"}}], NetworkMode="host"),
        "Awsvpc": _task([{"Name": "a", "Privileged": True}], NetworkMode="awsvpc"),
        "ModeParam": _task([{"Name": "a", "Privileged": True}], NetworkMode={"Ref": "M"}),
    }, "CF-ECS-004")
    assert _names(found) == {"Privileged", "Root", "RootGroup"}
    assert {f.severity for f in found} == {"High"}


def test_host_network_terraform(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_ecs_task_definition" "bad" {
  network_mode          = "host"
  container_definitions = jsonencode([{ name = "a", privileged = true }])
}
resource "aws_ecs_task_definition" "mode_var" {
  network_mode          = var.mode
  container_definitions = jsonencode([{ name = "a", privileged = true }])
}
resource "aws_ecs_task_definition" "user_var" {
  network_mode          = "host"
  container_definitions = jsonencode([{ name = "a", user = var.user }])
}
resource "aws_ecs_task_definition" "file" {
  network_mode          = "host"
  container_definitions = file("c.json")
}
""", "CF-ECS-004") == {"bad"}


def test_public_ip_cloudformation(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Public": _service(NetworkConfiguration=_public_ip("ENABLED")),
        "Private": _service(NetworkConfiguration=_public_ip("DISABLED")),
        "Param": _service(NetworkConfiguration=_public_ip({"Ref": "P"})),
        "WholeIf": _service(NetworkConfiguration={"Fn::If": ["C", _public_ip("ENABLED"), {}]}),
        "Unset": _service(),
    }, "CF-ECS-005")
    assert _names(found) == {"Public"}
    assert found[0].severity == "Medium"


def test_public_ip_terraform(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_ecs_service" "public" {
  network_configuration {
    subnets          = ["s"]
    assign_public_ip = true
  }
}
resource "aws_ecs_service" "private" {
  network_configuration {
    subnets          = ["s"]
    assign_public_ip = false
  }
}
resource "aws_ecs_service" "from_var" {
  network_configuration {
    subnets          = ["s"]
    assign_public_ip = var.public
  }
}
resource "aws_ecs_service" "unset" {
  network_configuration {
    subnets = var.subnets
  }
}
resource "aws_ecs_service" "dyn" {
  dynamic "network_configuration" {
    for_each = var.nets
    content {
      subnets          = ["s"]
      assign_public_ip = true
    }
  }
}
""", "CF-ECS-005") == {"public"}


def test_pid_mode(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Host": _task(PidMode="host"),
        "Task": _task(PidMode="task"),
        "Param": _task(PidMode={"Ref": "P"}),
        "Unset": _task(),
    }, "CF-ECS-006")
    assert _names(found) == {"Host"}
    assert found[0].severity == "High"
    assert _tf(tmp_path, """
resource "aws_ecs_task_definition" "host" { pid_mode = "host" }
resource "aws_ecs_task_definition" "task" { pid_mode = "task" }
resource "aws_ecs_task_definition" "from_var" { pid_mode = var.pid }
""", "CF-ECS-006") == {"host"}


def test_environment_secrets_cloudformation(tmp_path: Path) -> None:
    def env(name: str, value) -> list:
        return [{"Name": "a", "Environment": [{"Name": name, "Value": value}]}]

    found = _cf(tmp_path, {
        "Password": _task(env("DB_PASSWORD", "hunter2")),
        "AccessKeyId": _task(env("AWS_ACCESS_KEY_ID", "AKIAABCDEFGHIJKLMNOP")),
        "EngineAuth": _task(env("ECS_ENGINE_AUTH_DATA", "abc")),
        "Param": _task(env("DB_PASSWORD", {"Ref": "P"})),
        "Dynamic": _task(env("DB_PASSWORD", "{{resolve:secretsmanager:s}}")),
        "Arn": _task(env("DB_PASSWORD", "arn:aws:secretsmanager:eu-north-1:1:secret:s")),
        "Pointer": _task(env("DB_SECRET_ARN", "s")),
        "Plain": _task(env("LOG_LEVEL", "info")),
        "SecretsBlock": _task([{"Name": "a", "Secrets": [{"Name": "DB_PASSWORD", "ValueFrom": "arn"}]}]),
        "WholeParam": _task([{"Name": "a", "Environment": {"Ref": "E"}}]),
    }, "CF-ECS-007")
    assert _names(found) == {"Password", "AccessKeyId", "EngineAuth"}
    assert {f.severity for f in found} == {"High"}
    assert not any("hunter2" in f.recommendation for f in found)


def test_environment_secrets_terraform(tmp_path: Path) -> None:
    hcl = """
resource "aws_ecs_task_definition" "literal" {
  container_definitions = jsonencode([{
    name = "a"
    environment = [
      { name = "DB_PASSWORD", value = "hunter2" },
      { name = "OTHER", value = var.other },
    ]
  }])
}
resource "aws_ecs_task_definition" "json_text" {
  container_definitions = "[{\\"name\\": \\"a\\", \\"environment\\": [{\\"name\\": \\"API_KEY\\", \\"value\\": \\"k\\"}]}]"
}
resource "aws_ecs_task_definition" "from_var" {
  container_definitions = jsonencode([{
    name = "a"
    environment = [{ name = "DB_PASSWORD", value = var.password }]
  }])
}
resource "aws_ecs_task_definition" "whole_var" {
  container_definitions = jsonencode([{ name = "a", environment = var.env }])
}
"""
    assert _tf(tmp_path, hcl, "CF-ECS-007") == {"literal", "json_text"}
    tasks = [r for r in resources_from_terraform(tmp_path, []) if r.type == "ecs_task_definition"]
    assert "hunter2" not in repr([t.properties for t in tasks])


def test_one_unknown_environment_value_keeps_the_other_container_checks(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_ecs_task_definition" "mixed" {
  container_definitions = jsonencode([{
    name             = "a"
    privileged       = true
    environment      = [{ name = "X", value = var.x }]
    logConfiguration = var.logs
  }])
}
""", "CF-ECS-001") == {"mixed"}


def test_logging_cloudformation(tmp_path: Path) -> None:
    logs = {"LogDriver": "awslogs"}
    found = _cf(tmp_path, {
        "None": _task([{"Name": "a"}]),
        "OneOfTwo": _task([{"Name": "a", "LogConfiguration": logs}, {"Name": "b"}]),
        "NoDriver": _task([{"Name": "a", "LogConfiguration": {"Options": {}}}]),
        "Set": _task([{"Name": "a", "LogConfiguration": logs}]),
        "Param": _task([{"Name": "a", "LogConfiguration": {"Ref": "L"}}]),
        "DriverParam": _task([{"Name": "a", "LogConfiguration": {"LogDriver": {"Ref": "D"}}}]),
        "ContainerIf": _task([{"Fn::If": ["C", {"Name": "a"}, {"Name": "b"}]}]),
        "AllParam": _task(ContainerDefinitions={"Ref": "C"}),
    }, "CF-ECS-008")
    assert _names(found) == {"None", "OneOfTwo", "NoDriver"}
    assert {f.severity for f in found} == {"Medium"}
    assert "b" in next(f for f in found if f.evidence.startswith("OneOfTwo")).recommendation


def test_logging_terraform(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_ecs_task_definition" "none" {
  container_definitions = jsonencode([{ name = "a" }])
}
resource "aws_ecs_task_definition" "set" {
  container_definitions = jsonencode([{ name = "a", logConfiguration = { logDriver = "awslogs" } }])
}
resource "aws_ecs_task_definition" "from_var" {
  container_definitions = jsonencode([{ name = "a", logConfiguration = var.logs }])
}
resource "aws_ecs_task_definition" "driver_var" {
  container_definitions = jsonencode([{ name = "a", logConfiguration = { logDriver = var.driver } }])
}
resource "aws_ecs_task_definition" "file" {
  container_definitions = file("c.json")
}
""", "CF-ECS-008") == {"none"}


def test_platform_version_cloudformation(tmp_path: Path) -> None:
    fargate = {"LaunchType": "FARGATE"}
    found = _cf(tmp_path, {
        "Old": _service(PlatformVersion="1.3.0", **fargate),
        "OldSpot": _service(PlatformVersion="1.3.0", CapacityProviderStrategy=[{"CapacityProvider": "FARGATE_SPOT"}]),
        "Newest": _service(PlatformVersion="1.4.0", **fargate),
        "Latest": _service(PlatformVersion="LATEST", **fargate),
        "MayBeWindows": _service(PlatformVersion="1.0.0", **fargate),
        "Unset": _service(**fargate),
        "Param": _service(PlatformVersion={"Ref": "P"}, **fargate),
        "NotFargate": _service(PlatformVersion="1.3.0", LaunchType="EC2"),
        "LaunchParam": _service(PlatformVersion="1.3.0", LaunchType={"Ref": "L"}),
    }, "CF-ECS-009")
    assert _names(found) == {"Old", "OldSpot"}
    assert {f.severity for f in found} == {"Low"}


def test_platform_version_terraform(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_ecs_service" "old" {
  launch_type      = "FARGATE"
  platform_version = "1.3.0"
}
resource "aws_ecs_service" "latest" {
  launch_type      = "FARGATE"
  platform_version = "LATEST"
}
resource "aws_ecs_service" "from_var" {
  launch_type      = "FARGATE"
  platform_version = var.platform
}
resource "aws_ecs_service" "launch_var" {
  launch_type      = var.launch
  platform_version = "1.3.0"
}
""", "CF-ECS-009") == {"old"}


def test_container_insights_cloudformation(tmp_path: Path) -> None:
    def setting(value) -> dict:
        return {"Name": "containerInsights", "Value": value}

    found = _cf(tmp_path, {
        "Unset": _cluster(ClusterName="c"),
        "Disabled": _cluster(setting("disabled")),
        "Enabled": _cluster(setting("enabled")),
        "Enhanced": _cluster(setting("enhanced")),
        "ValueParam": _cluster(setting({"Ref": "I"})),
        "EntryIf": _cluster({"Fn::If": ["C", setting("enabled"), {"Ref": "AWS::NoValue"}]}),
        "WholeParam": _cluster(ClusterSettings={"Ref": "S"}),
    }, "CF-ECS-010")
    assert _names(found) == {"Unset", "Disabled"}
    assert {f.severity for f in found} == {"Low"}


def test_container_insights_terraform(tmp_path: Path) -> None:
    def cluster(name: str, value: str) -> str:
        return f'resource "aws_ecs_cluster" "{name}" {{\n  setting {{\n    name  = "containerInsights"\n' \
               f'    value = {value}\n  }}\n}}\n'

    assert _tf(tmp_path, 'resource "aws_ecs_cluster" "unset" {\n  name = "c"\n}\n'
               + cluster("disabled", '"disabled"') + cluster("enabled", '"enabled"')
               + cluster("enhanced", '"enhanced"') + cluster("from_var", "var.insights")
               + """
resource "aws_ecs_cluster" "dyn" {
  dynamic "setting" {
    for_each = var.settings
    content {
      name  = "containerInsights"
      value = "disabled"
    }
  }
}
""", "CF-ECS-010") == {"unset", "disabled"}


def test_fargate_size_cloudformation(tmp_path: Path) -> None:
    fargate = {"RequiresCompatibilities": ["FARGATE"]}
    found = _cf(tmp_path, {
        "BetweenPairs": _task(Cpu="256", Memory="600", **fargate),
        "TooMuchMemory": _task(Cpu="256", Memory="4096", **fargate),
        "BadCpu": _task(Cpu="300", Memory="1024", **fargate),
        "Huge": _task(Cpu="16384", Memory="200000", **fargate),
        "Ints": _task(Cpu=256, Memory=600, **fargate),
        "Valid": _task(Cpu="256", Memory="512", **fargate),
        "Large": _task(Cpu="8192", Memory="20480", **fargate),
        "Largest": _task(Cpu="16384", Memory="122880", **fargate),
        "Units": _task(Cpu="1 vCPU", Memory="3 GB", **fargate),
        "CpuParam": _task(Cpu={"Ref": "C"}, Memory="600", **fargate),
        "MemoryUnset": _task(Cpu="256", **fargate),
        "Ec2": _task(Cpu="300", Memory="600", RequiresCompatibilities=["EC2"]),
        "NoCompatibilities": _task(Cpu="300", Memory="600"),
        "CompatibilitiesParam": _task(Cpu="300", Memory="600", RequiresCompatibilities={"Ref": "R"}),
    }, "CF-ECS-011")
    assert _names(found) == {"BetweenPairs", "TooMuchMemory", "BadCpu", "Huge", "Ints"}
    assert {f.severity for f in found} == {"Low"}
    by_name = {f.evidence.split(" ")[0]: f.recommendation for f in found}
    assert "Cpu 256 with Memory 1024" in by_name["BetweenPairs"]
    assert "Cpu 512 with Memory 4096" in by_name["TooMuchMemory"]
    assert "largest" in by_name["Huge"]


def test_fargate_size_terraform(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_ecs_task_definition" "bad" {
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "600"
}
resource "aws_ecs_task_definition" "valid" {
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
}
resource "aws_ecs_task_definition" "ec2" {
  requires_compatibilities = ["EC2"]
  cpu                      = "256"
  memory                   = "600"
}
resource "aws_ecs_task_definition" "cpu_var" {
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = "600"
}
resource "aws_ecs_task_definition" "compat_var" {
  requires_compatibilities = var.compat
  cpu                      = "256"
  memory                   = "600"
}
""", "CF-ECS-011") == {"bad"}


def test_eks_version_cloudformation(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Past": _eks(Version="1.33"),
        "PastUnquotedYaml": _eks(Version=1.3),  # YAML 1.30 -> 1.3
        "OlderThanTable": _eks(Version="1.20"),
        "Current": _eks(Version="1.34"),
        "NewerThanTable": _eks(Version="1.99"),
        "Unset": _eks(),
        "Param": _eks(Version={"Ref": "K8s"}),
        "Odd": _eks(Version="latest"),
    }, "CF-EKS-004")
    assert _names(found) == {"Past", "PastUnquotedYaml", "OlderThanTable"}
    assert {f.severity for f in found} == {"Medium"}
    assert "2026-07-29" in next(f for f in found if f.evidence.startswith("Past ")).recommendation


def test_eks_version_terraform(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_eks_cluster" "past" {
  version = "1.33"
}
resource "aws_eks_cluster" "current" {
  version = "1.34"
}
resource "aws_eks_cluster" "from_var" {
  version = var.k8s
}
resource "aws_eks_cluster" "unset" {
  name = "c"
}
""", "CF-EKS-004") == {"past"}


def test_eks_table_was_checked_in_the_last_6_months() -> None:
    """Re-check https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html and
    update rules/data/eks_versions.json (dates and _as_of) when this fails."""
    assert (date.today() - eks_versions.as_of()).days <= 183


def test_eks_table_agrees_with_the_security_hub_oldest_version() -> None:
    """Security Hub EKS.2 names 1.34 as the oldest supported version on the as-of day."""
    day = date(2026, 11, 8)
    assert eks_versions.past_standard_support(33, day)[0] is True
    assert eks_versions.past_standard_support(34, day)[0] is False


def test_eks_version_ends_on_its_last_day() -> None:
    end = date(2026, 12, 2)
    assert eks_versions.past_standard_support(34, end) == (False, end)
    assert eks_versions.past_standard_support(34, date(2026, 12, 3)) == (True, end)
