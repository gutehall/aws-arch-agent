"""CF-PERF-005: a current x86 EC2 type that has a Graviton class."""
import json
from pathlib import Path

import pytest

from aws_arch_agent import pricing
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.generations import GRAVITON_PATH, graviton_alternative, successors
from aws_arch_agent.rules.terraform_model import resources_from_terraform

H = 730
ID = "CF-PERF-005"


def _cf(tmp_path: Path, resources: dict, check_id: str = ID) -> dict[str, Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return {f.evidence.split(" ")[0]: f for f in run_cf_rules_from_paths([path], repo_path=tmp_path)
            if f.id == check_id}


def _ec2(t) -> dict:
    return {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": t, "MetadataOptions": {"HttpTokens": "required"}}}


def test_done_when(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "X86": _ec2("m7i.large"), "Graviton": _ec2("m7g.large"), "Gpu": _ec2("p5.48xlarge"),
        "Mac": _ec2("mac2.metal"), "Old": _ec2("m4.large"), "Param": _ec2({"Ref": "Type"}),
    })
    assert set(found) == {"X86"}
    f = found["X86"]
    assert f.severity == "Low"
    assert f.recommendation.startswith("m7i.large runs on x86: m7g.large is the same size on Graviton.")
    assert "needs an arm64 build" in f.recommendation


def test_previous_generation_keeps_only_the_generation_finding(tmp_path: Path) -> None:
    both = _cf(tmp_path, {"Old": _ec2("m4.large")}, "CF-GEN-001")
    assert set(both) == {"Old"}
    assert set(_cf(tmp_path, {"Old": _ec2("m4.large")})) == set()


def test_single_instance_is_priced_when_the_snapshot_covers_both(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"X86": _ec2("m7i.large")})["X86"]
    x86, arm = pricing.price("ec2:m7i.large", "us-east-1"), pricing.price("ec2:m7g.large", "us-east-1")
    if x86 is None or arm is None:
        assert found.monthly_cost_usd is None
        return
    assert found.monthly_cost_usd == round(H * x86.usd, 2)
    assert found.monthly_savings_usd == round(round(H * x86.usd, 2) - round(H * arm.usd, 2), 2)
    assert "m7g.large:" in (found.estimate_basis or "")


def test_templates_and_groups_are_not_priced(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
            "InstanceType": "c7i.xlarge", "MetadataOptions": {"HttpTokens": "required"}}}},
        "Lc": {"Type": "AWS::AutoScaling::LaunchConfiguration", "Properties": {
            "InstanceType": "t3.small", "ImageId": "ami-1"}},
        "Asg": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
            "MaxSize": "2", "MinSize": "1", "MixedInstancesPolicy": {
                "LaunchTemplate": {"Overrides": [{"InstanceType": "r6i.large"}, {"InstanceType": "r7g.large"}]},
                "InstancesDistribution": {"SpotAllocationStrategy": "price-capacity-optimized"}}}},
    })
    assert set(found) == {"Lt", "Lc", "Asg"}
    assert "c7g.xlarge" in found["Lt"].recommendation
    assert "t4g.small" in found["Lc"].recommendation
    assert "r6i.large runs on x86: r7g.large" in found["Asg"].recommendation
    for f in found.values():
        assert f.monthly_cost_usd is None and f.monthly_savings_usd is None


@pytest.mark.parametrize("current,expected", [
    ("m7i.xlarge", "m7g.xlarge"),
    ("t3.micro", "t4g.micro"),
    ("m6id.xlarge", "m7gd.xlarge"),
    ("c6i.2xlarge", "c7g.2xlarge"),
    ("m7g.large", None),         # already Graviton
    ("t4g.micro", None),
    ("p5.48xlarge", None),       # GPU
    ("inf2.xlarge", None),       # Inferentia
    ("trn1.2xlarge", None),      # Trainium
    ("mac2.metal", None),        # Mac
    ("m7i.metal-24xl", None),    # bare metal
    ("m7i.48xlarge", None),      # Graviton family has no such size
    ("m4.large", None),          # previous generation: CF-GEN-001 speaks
    ("m7i", None),
])
def test_graviton_alternative(current, expected) -> None:
    assert graviton_alternative(current) == expected


def test_map_is_in_its_own_file_and_never_a_previous_generation_family() -> None:
    data = json.loads(GRAVITON_PATH.read_text(encoding="utf-8"))
    assert set(data) - {"_comment"} == {"families", "sizes"}
    assert set(data["families"].values()) == set(data["sizes"])
    for family in data["families"]:
        assert successors("ec2", f"{family}.large") is None


def test_terraform(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("""
resource "aws_instance" "x86" {
  instance_type = "m7i.large"
}
resource "aws_instance" "arm" {
  instance_type = "m7g.large"
}
resource "aws_instance" "from_var" {
  instance_type = var.type
}
resource "aws_launch_template" "lt" {
  instance_type = "c7i.large"
}
""", encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    found = {f.evidence.split(" ")[0].split(".")[-1]
             for f in run_resource_checks(resources, tmp_path / "main.tf") if f.id == ID}
    assert found == {"x86", "lt"}


def test_savings_are_not_counted_twice_with_right_sizing(tmp_path: Path) -> None:
    """m5.4xlarge: one size smaller saves more than Graviton at the same size, so it keeps the number."""
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"Big": _ec2("m5.4xlarge")}}), encoding="utf-8")
    found = {f.id: f for f in run_cf_rules_from_paths([path], repo_path=tmp_path)}
    arm, size = found["CF-PERF-005"], found["CF-PERF-004"]
    if arm.monthly_cost_usd is None or size.monthly_cost_usd is None:
        pytest.skip("price snapshot lacks the types")
    assert size.monthly_savings_usd and arm.monthly_savings_usd is None
    assert "counted on CF-PERF-004" in (arm.estimate_basis or "")
