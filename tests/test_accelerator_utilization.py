"""SUS 5: accelerator instances need a utilization alarm or a batch window (REPO-150)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_GPU = 'resource "aws_instance" "gpu" {{\n  instance_type = "{kind}"\n}}\n'


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _hits(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-150"]


def test_rule_answers_sus5() -> None:
    assert RULE_BEST_PRACTICES["REPO-150"] == ("SUS05-BP04",)
    assert "SUS05-BP04" not in NOT_CHECKED


@pytest.mark.parametrize(
    "files",
    [
        {"g.tf": _GPU.format(kind="g5.xlarge")},
        {"g.tf": _GPU.format(kind="p4d.24xlarge")},
        {"g.tf": _GPU.format(kind="inf2.xlarge")},
        {"g.tf": _GPU.format(kind="trn1.32xlarge")},
        {"g.json": '{"Resources": {"I": {"Type": "AWS::EC2::Instance", '
                   '"Properties": {"InstanceType": "g4dn.xlarge"}}}}'},
        {"lib/g.ts": "new ec2.Instance(this, 'G', { instanceType: ec2.InstanceType.of("
                     "ec2.InstanceClass.G5, ec2.InstanceSize.XLARGE) });\n"},
    ],
    ids=["g5", "p4d", "inf2", "trn1", "cfn", "cdk-class"],
)
def test_accelerator_without_watch_or_window_fires(tmp_path: Path, files: dict) -> None:
    (hit,) = _hits(_scan(tmp_path, files))
    assert hit.question == "SUS 5" and hit.category == "Sustainability"
    assert hit.severity == "Low" and hit.file == f"prod/{next(iter(files))}"


@pytest.mark.parametrize(
    "extra",
    [
        {"a.tf": 'resource "aws_cloudwatch_metric_alarm" "a" {\n'
                 '  metric_name = "nvidia_smi_utilization_gpu"\n}\n'},
        {"a.json": '{"Resources": {"A": {"Type": "AWS::CloudWatch::Alarm", '
                   '"Properties": {"MetricName": "GPUUtilization"}}}}'},
        {"s.tf": 'resource "aws_autoscaling_schedule" "s" {\n  recurrence = "0 2 * * *"\n}\n'},
        {"lib/s.ts": "group.scaleOnSchedule('Night', { schedule, minCapacity: 0 });\n"},
    ],
    ids=["tf-alarm", "cfn-alarm", "tf-schedule", "cdk-schedule"],
)
def test_watch_or_window_passes(tmp_path: Path, extra: dict) -> None:
    assert not _hits(_scan(tmp_path, {"g.tf": _GPU.format(kind="g5.xlarge"), **extra}))


@pytest.mark.parametrize("kind", ["t3.micro", "m6g.large", "c7g.xlarge", "r6i.large"])
def test_general_purpose_instances_pass(tmp_path: Path, kind: str) -> None:
    assert not _hits(_scan(tmp_path, {"g.tf": _GPU.format(kind=kind)}))
