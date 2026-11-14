"""CF-ECS-012: an ECS service with no deployment circuit breaker and rollback."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1


def _cfn(props: str) -> str:
    return (
        "Resources:\n  Svc:\n    Type: AWS::ECS::Service\n    Properties:\n      Cluster: c\n"
        + props
    )


def _ids(tmp_path: Path, name: str, text: str) -> set[str]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False)
    return {f.id for f in findings}


@pytest.mark.parametrize("props", [
    "",
    "      DeploymentConfiguration:\n        MaximumPercent: 200\n",
    "      DeploymentConfiguration:\n        DeploymentCircuitBreaker:\n          Enable: false\n          Rollback: true\n",
    "      DeploymentConfiguration:\n        DeploymentCircuitBreaker:\n          Enable: true\n          Rollback: false\n",
    "      DeploymentConfiguration:\n        DeploymentCircuitBreaker:\n          Enable: true\n",
])
def test_cloudformation_flags_a_service_without_rollback(tmp_path: Path, props: str) -> None:
    assert "CF-ECS-012" in _ids(tmp_path, "t.yaml", _cfn(props))


@pytest.mark.parametrize("props", [
    "      DeploymentConfiguration:\n        DeploymentCircuitBreaker:\n          Enable: true\n          Rollback: true\n",
    "      DeploymentController:\n        Type: CODE_DEPLOY\n",
    "      DeploymentController:\n        Type: EXTERNAL\n",
    "      SchedulingStrategy: DAEMON\n",
    "      DeploymentConfiguration: !Ref Config\n",
    "      DeploymentConfiguration:\n        DeploymentCircuitBreaker:\n          Enable: !Ref On\n          Rollback: true\n",
])
def test_cloudformation_is_quiet_when_rollback_is_on_or_unreadable(tmp_path: Path, props: str) -> None:
    assert "CF-ECS-012" not in _ids(tmp_path, "t.yaml", _cfn(props))


def test_terraform_reads_the_circuit_breaker(tmp_path: Path) -> None:
    bare = 'resource "aws_ecs_service" "a" {\n  name = "a"\n}\n'
    assert "CF-ECS-012" in _ids(tmp_path, "main.tf", bare)
    on = (
        'resource "aws_ecs_service" "a" {\n  name = "a"\n  deployment_circuit_breaker {\n'
        "    enable   = true\n    rollback = true\n  }\n}\n"
    )
    assert "CF-ECS-012" not in _ids(tmp_path, "main.tf", on)
    no_rollback = on.replace("rollback = true", "rollback = false")
    assert "CF-ECS-012" in _ids(tmp_path, "main.tf", no_rollback)
    var = on.replace("enable   = true", "enable   = var.on")
    assert "CF-ECS-012" not in _ids(tmp_path, "main.tf", var)
    external = bare.replace('name = "a"', 'name = "a"\n  deployment_controller {\n    type = "CODE_DEPLOY"\n  }')
    assert "CF-ECS-012" not in _ids(tmp_path, "main.tf", external)
