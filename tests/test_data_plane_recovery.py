"""REL 11: a lone EC2 instance has no data plane recovery (REPO-149)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_INSTANCE = 'resource "aws_instance" "web" {\n  ami = "x"\n}\n'


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _hits(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-149"]


def test_rule_answers_rel11() -> None:
    assert RULE_BEST_PRACTICES["REPO-149"] == ("REL11-BP04",)
    assert "REL11-BP04" not in NOT_CHECKED


@pytest.mark.parametrize(
    "files",
    [
        {"i.tf": _INSTANCE},
        {"i.json": '{"Resources": {"I": {"Type": "AWS::EC2::Instance"}}}'},
        {"lib/s.ts": "new ec2.Instance(this, 'W', { instanceType, machineImage, vpc });\n"},
    ],
    ids=["terraform", "cloudformation", "cdk"],
)
def test_lone_instance_fires(tmp_path: Path, files: dict) -> None:
    (hit,) = _hits(_scan(tmp_path, files))
    assert hit.question == "REL 11" and hit.category == "Reliability" and hit.severity == "Low"
    assert hit.file == f"prod/{next(iter(files))}"


@pytest.mark.parametrize(
    "extra",
    [
        {"a.tf": 'resource "aws_autoscaling_group" "a" {\n  min_size = 1\n}\n'},
        {"t.tf": 'resource "aws_lb_target_group" "t" {\n  port = 80\n}\n'},
        {"h.tf": 'resource "aws_route53_health_check" "h" {\n  type = "HTTP"\n}\n'},
        {"a.json": '{"Resources": {"A": {"Type": "AWS::AutoScaling::AutoScalingGroup"}}}'},
        {"lib/a.ts": "new elbv2.ApplicationTargetGroup(this, 'T', { vpc });\n"},
        {"lib/g.ts": "new autoscaling.AutoScalingGroup(this, 'G', { vpc });\n"},
    ],
    ids=["tf-asg", "tf-target-group", "tf-health-check", "cfn-asg", "cdk-target-group", "cdk-asg"],
)
def test_data_plane_recovery_passes(tmp_path: Path, extra: dict) -> None:
    assert not _hits(_scan(tmp_path, {"i.tf": _INSTANCE, **extra}))


def test_no_instance_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"f.tf": 'resource "aws_lambda_function" "f" {}\n'})
    assert not _hits(findings)
