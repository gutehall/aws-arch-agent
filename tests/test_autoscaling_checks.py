"""Auto Scaling groups and launch configurations: CF-ASG-001..006."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import (
    CF_COVERS_STATIC,
    CF_PARTLY_COVERS_STATIC,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.environments import RULE_POLICY
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-ASG-001", "CF-ASG-002", "CF-ASG-003", "CF-ASG-004", "CF-ASG-005", "CF-ASG-006")
_PARAM = {"Ref": "Param"}
_MAYBE = {"Fn::If": ["On", "x", {"Ref": "AWS::NoValue"}]}
_GROUP = "AWS::AutoScaling::AutoScalingGroup"
_CONFIG = "AWS::AutoScaling::LaunchConfiguration"


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
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


def _group(**props: Any) -> dict:
    base = {"MinSize": "1", "MaxSize": "4", "VPCZoneIdentifier": ["subnet-a", "subnet-b"]}
    return {"Type": _GROUP, "Properties": {**base, **props}}


def _config(**props: Any) -> dict:
    base = {"ImageId": "ami-1", "InstanceType": "m7g.large", "MetadataOptions": {"HttpTokens": "required"}}
    return {"Type": _CONFIG, "Properties": {**base, **props}}


def _tf_group(extra: str, label: str = "g") -> str:
    return f'''
resource "aws_autoscaling_group" "{label}" {{
  min_size = 1
  max_size = 4
  {extra}
}}
'''


def _tf_config(extra: str) -> str:
    return f'''
resource "aws_launch_configuration" "c" {{
  image_id      = "ami-1"
  instance_type = "m7g.large"
  {extra}
}}
'''


_TF_IMDS_ON = 'metadata_options {\n    http_tokens = "required"\n  }'


# --- CF-ASG-001: load balancer without ELB health checks (AutoScaling.1) ---


@pytest.mark.parametrize("props", [
    {"TargetGroupARNs": ["arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/a/b"]},
    {"TargetGroupARNs": [{"Ref": "Tg"}]},
    {"LoadBalancerNames": ["clb"]},
    {"LoadBalancerNames": ["clb"], "HealthCheckType": "EC2"},
    {"TargetGroupARNs": ["arn"], "HealthCheckType": "EC2,EBS"},
])
def test_load_balancer_without_elb_health_check_cf(tmp_path: Path, props: dict) -> None:
    assert _cf(tmp_path, {"G": _group(**props)}).get("CF-ASG-001") == {"G"}


@pytest.mark.parametrize("props", [
    {},
    {"TargetGroupARNs": []},
    {"TargetGroupARNs": ["arn"], "HealthCheckType": "ELB"},
    {"TargetGroupARNs": ["arn"], "HealthCheckType": "EC2,ELB"},
    {"TargetGroupARNs": ["arn"], "HealthCheckType": _PARAM},
    {"TargetGroupARNs": _PARAM},
    {"LoadBalancerNames": _PARAM},
    {"TargetGroupARNs": [_MAYBE]},
])
def test_load_balancer_not_reported_cf(tmp_path: Path, props: dict) -> None:
    assert "CF-ASG-001" not in _cf(tmp_path, {"G": _group(**props)})


@pytest.mark.parametrize("extra", [
    'target_group_arns = ["arn"]',
    "target_group_arns = [aws_lb_target_group.t.arn]",
    "target_group_arns = [var.target_group_arn]",
    'target_group_arns = ["arn", var.other]',
    'load_balancers = ["clb"]',
    'target_group_arns = ["arn"]\n  health_check_type = "EC2"',
])
def test_load_balancer_without_elb_health_check_tf(tmp_path: Path, extra: str) -> None:
    assert _tf(tmp_path, _tf_group(extra)).get("CF-ASG-001") == {"aws_autoscaling_group.g"}


@pytest.mark.parametrize("extra", [
    "",
    "target_group_arns = []",
    'target_group_arns = ["arn"]\n  health_check_type = "ELB"',
    'target_group_arns = ["arn"]\n  health_check_type = var.health',
    "target_group_arns = var.target_groups",
    "load_balancers = var.names",
])
def test_load_balancer_not_reported_tf(tmp_path: Path, extra: str) -> None:
    assert "CF-ASG-001" not in _tf(tmp_path, _tf_group(extra))


def test_attachment_counts_only_for_its_group(tmp_path: Path) -> None:
    text = _tf_group("", "a") + _tf_group("", "b") + '''
resource "aws_autoscaling_attachment" "x" {
  autoscaling_group_name = aws_autoscaling_group.a.id
  lb_target_group_arn    = aws_lb_target_group.t.arn
}
'''
    assert _tf(tmp_path, text).get("CF-ASG-001") == {"aws_autoscaling_group.a"}


def test_attachment_by_literal_name(tmp_path: Path) -> None:
    text = _tf_group('name = "web"') + '''
resource "aws_autoscaling_attachment" "x" {
  autoscaling_group_name = "web"
  elb                    = "clb"
}
'''
    assert _tf(tmp_path, text).get("CF-ASG-001") == {"aws_autoscaling_group.g"}


def test_attachment_that_cannot_be_tied_is_not_reported(tmp_path: Path) -> None:
    text = _tf_group("") + '''
resource "aws_autoscaling_attachment" "x" {
  autoscaling_group_name = var.group
  lb_target_group_arn    = "arn"
}
'''
    assert "CF-ASG-001" not in _tf(tmp_path, text)


def test_attachment_with_elb_health_check_is_not_reported(tmp_path: Path) -> None:
    text = _tf_group('health_check_type = "ELB"') + '''
resource "aws_autoscaling_attachment" "x" {
  autoscaling_group_name = aws_autoscaling_group.g.name
  lb_target_group_arn    = "arn"
}
'''
    assert "CF-ASG-001" not in _tf(tmp_path, text)


# --- CF-ASG-002: one Availability Zone (AutoScaling.2) ---


@pytest.mark.parametrize("props", [
    {"VPCZoneIdentifier": ["subnet-a"]},
    {"VPCZoneIdentifier": [{"Fn::GetAtt": ["S", "SubnetId"]}]},
    {"VPCZoneIdentifier": [{"Fn::Select": [0, _PARAM]}]},
    {"VPCZoneIdentifier": None, "AvailabilityZones": ["eu-west-1a"]},
])
def test_one_az_cf(tmp_path: Path, props: dict) -> None:
    group = _group(**props)
    group["Properties"] = {k: v for k, v in group["Properties"].items() if v is not None}
    assert _cf(tmp_path, {"G": group}).get("CF-ASG-002") == {"G"}


@pytest.mark.parametrize("props", [
    {},
    {"VPCZoneIdentifier": [_PARAM]},
    {"VPCZoneIdentifier": _PARAM},
    {"VPCZoneIdentifier": {"Fn::Split": [",", _PARAM]}},
    {"VPCZoneIdentifier": ["subnet-a,subnet-b"]},
    {"VPCZoneIdentifier": [{"Fn::ImportValue": "Subnets"}]},
    {"VPCZoneIdentifier": [{"Fn::Join": [",", _PARAM]}]},
    {"VPCZoneIdentifier": [_MAYBE]},
    {"VPCZoneIdentifier": [{"Ref": "AWS::NoValue"}]},
    {"VPCZoneIdentifier": [_PARAM, {"Ref": "Other"}]},
    {"VPCZoneIdentifier": _PARAM, "AvailabilityZones": _PARAM},
    {"VPCZoneIdentifier": [], "AvailabilityZones": ["eu-west-1a", "eu-west-1b"]},
    {"VPCZoneIdentifier": [], "AvailabilityZones": [_PARAM]},
])
def test_one_az_not_reported_cf(tmp_path: Path, props: dict) -> None:
    assert "CF-ASG-002" not in _cf(tmp_path, {"G": _group(**props)})


def _subnet(az: Any) -> dict:
    return {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/24",
                                                       "AvailabilityZone": az}}


def test_subnets_in_this_template_read_as_cf_lam_008(tmp_path: Path) -> None:
    same = {"A": _subnet("eu-west-1a"), "B": _subnet("eu-west-1a"),
            "G": _group(VPCZoneIdentifier=[{"Ref": "A"}, {"Ref": "B"}])}
    assert _cf(tmp_path, same).get("CF-ASG-002") == {"G"}
    spread = {"A": _subnet("eu-west-1a"), "B": _subnet("eu-west-1b"),
              "G": _group(VPCZoneIdentifier=[{"Ref": "A"}, {"Ref": "B"}])}
    assert "CF-ASG-002" not in _cf(tmp_path, spread)
    unknown = {"A": _subnet("eu-west-1a"), "B": _subnet(_PARAM),
               "G": _group(VPCZoneIdentifier=[{"Ref": "A"}, {"Ref": "B"}])}
    assert "CF-ASG-002" not in _cf(tmp_path, unknown)


@pytest.mark.parametrize("extra", [
    'vpc_zone_identifier = ["subnet-a"]',
    "vpc_zone_identifier = [aws_subnet.a.id]",
    'availability_zones = ["eu-west-1a"]',
])
def test_one_az_tf(tmp_path: Path, extra: str) -> None:
    assert _tf(tmp_path, _tf_group(extra)).get("CF-ASG-002") == {"aws_autoscaling_group.g"}


@pytest.mark.parametrize("extra", [
    "",
    "vpc_zone_identifier = var.subnet_ids",
    "vpc_zone_identifier = [var.subnet_id]",
    "vpc_zone_identifier = aws_subnet.a[*].id",
    "vpc_zone_identifier = [for s in aws_subnet.a : s.id]",
    'vpc_zone_identifier = [join(",", aws_subnet.a[*].id)]',
    'vpc_zone_identifier = ["subnet-a", "subnet-b"]',
    "vpc_zone_identifier = [var.a, var.b]",
    "availability_zones = var.azs",
    "availability_zones = [var.az]",
    'availability_zones = ["eu-west-1a", "eu-west-1b"]',
])
def test_one_az_not_reported_tf(tmp_path: Path, extra: str) -> None:
    assert "CF-ASG-002" not in _tf(tmp_path, _tf_group(extra))


def test_one_az_is_prod_advice() -> None:
    assert RULE_POLICY["CF-ASG-002"] == {"dev": None, "staging": None}


def test_one_az_is_silent_in_dev(tmp_path: Path) -> None:
    (tmp_path / "dev").mkdir()
    found = _cf(tmp_path, {"G": _group(VPCZoneIdentifier=["subnet-a"])}, name="dev/app-dev.json")
    assert "CF-ASG-002" not in found


# --- CF-ASG-003: launch configuration without IMDSv2 (AutoScaling.3) ---


@pytest.mark.parametrize("options", [None, {}, {"HttpTokens": "optional"}])
def test_imds_cf(tmp_path: Path, options: Any) -> None:
    config = _config()
    if options is None:
        del config["Properties"]["MetadataOptions"]
    else:
        config["Properties"]["MetadataOptions"] = options
    assert _cf(tmp_path, {"C": config}).get("CF-ASG-003") == {"C"}


def test_imds_severity_is_high_when_unset(tmp_path: Path) -> None:
    config = _config()
    del config["Properties"]["MetadataOptions"]
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"C": config}}), encoding="utf-8")
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[])
    assert [f.severity for f in found if f.id == "CF-ASG-003"] == ["High"]


@pytest.mark.parametrize("options", [
    {"HttpTokens": "required"},
    {"HttpEndpoint": "disabled"},
    {"HttpTokens": _PARAM},
    {"HttpEndpoint": _PARAM},
    _PARAM,
])
def test_imds_not_reported_cf(tmp_path: Path, options: Any) -> None:
    assert "CF-ASG-003" not in _cf(tmp_path, {"C": _config(MetadataOptions=options)})


@pytest.mark.parametrize("extra", ["", 'metadata_options {\n    http_tokens = "optional"\n  }'])
def test_imds_tf(tmp_path: Path, extra: str) -> None:
    assert _tf(tmp_path, _tf_config(extra)).get("CF-ASG-003") == {"aws_launch_configuration.c"}


@pytest.mark.parametrize("extra", [
    _TF_IMDS_ON,
    'metadata_options {\n    http_endpoint = "disabled"\n  }',
    "metadata_options {\n    http_tokens = var.tokens\n  }",
    'dynamic "metadata_options" {\n    for_each = var.o\n    content {\n      http_tokens = "required"\n    }\n  }',
])
def test_imds_not_reported_tf(tmp_path: Path, extra: str) -> None:
    assert "CF-ASG-003" not in _tf(tmp_path, _tf_config(extra))


def test_launch_template_stays_with_cf_ec2_001(tmp_path: Path) -> None:
    template = {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {}}}
    assert "CF-ASG-003" not in _cf(tmp_path, {"T": template})


def test_launch_configuration_is_not_reported_as_cf_ec2_001(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"C": _config(MetadataOptions={})}}), encoding="utf-8")
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[])
    assert "CF-EC2-001" not in {f.id for f in found}


# --- CF-ASG-004: launch configuration with public IPs (AutoScaling.5) ---


@pytest.mark.parametrize("value", [True, "true"])
def test_public_ip_cf(tmp_path: Path, value: Any) -> None:
    assert _cf(tmp_path, {"C": _config(AssociatePublicIpAddress=value)}).get("CF-ASG-004") == {"C"}


@pytest.mark.parametrize("value", [False, "false", _PARAM])
def test_public_ip_not_reported_cf(tmp_path: Path, value: Any) -> None:
    assert "CF-ASG-004" not in _cf(tmp_path, {"C": _config(AssociatePublicIpAddress=value)})
    assert "CF-ASG-004" not in _cf(tmp_path, {"C": _config()})


def test_public_ip_tf(tmp_path: Path) -> None:
    text = _tf_config(f"{_TF_IMDS_ON}\n  associate_public_ip_address = true")
    assert _tf(tmp_path, text) == {"CF-ASG-004": {"aws_launch_configuration.c"}}


@pytest.mark.parametrize("extra", ["", "associate_public_ip_address = false", "associate_public_ip_address = var.public"])
def test_public_ip_not_reported_tf(tmp_path: Path, extra: str) -> None:
    assert "CF-ASG-004" not in _tf(tmp_path, _tf_config(extra))


# --- CF-ASG-005: group on a launch configuration (AutoScaling.9) ---


def test_launch_configuration_in_use_cf(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"G": _group(LaunchConfigurationName="legacy")}).get("CF-ASG-005") == {"G"}
    found = _cf(tmp_path, {"C": _config(), "G": _group(LaunchConfigurationName={"Ref": "C"})})
    assert found.get("CF-ASG-005") == {"G"}


@pytest.mark.parametrize("props", [
    {},
    {"LaunchTemplate": {"LaunchTemplateId": "lt-1", "Version": "1"}},
    {"LaunchConfigurationName": _PARAM},
    {"LaunchConfigurationName": {"Fn::If": ["On", {"Ref": "C"}, {"Ref": "AWS::NoValue"}]}},
    {"LaunchConfigurationName": {"Fn::ImportValue": "Lc"}},
])
def test_launch_configuration_not_reported_cf(tmp_path: Path, props: dict) -> None:
    assert "CF-ASG-005" not in _cf(tmp_path, {"C": _config(), "G": _group(**props)})


@pytest.mark.parametrize("extra", [
    'launch_configuration = "legacy"',
    "launch_configuration = aws_launch_configuration.c.name",
])
def test_launch_configuration_in_use_tf(tmp_path: Path, extra: str) -> None:
    text = _tf_config(_TF_IMDS_ON) + _tf_group(extra)
    assert _tf(tmp_path, text).get("CF-ASG-005") == {"aws_autoscaling_group.g"}


@pytest.mark.parametrize("extra", [
    "",
    "launch_template {\n    id = aws_launch_template.t.id\n  }",
    "launch_configuration = var.launch_configuration",
    "launch_configuration = data.aws_launch_configuration.c.name",
])
def test_launch_configuration_not_reported_tf(tmp_path: Path, extra: str) -> None:
    assert "CF-ASG-005" not in _tf(tmp_path, _tf_config(_TF_IMDS_ON) + _tf_group(extra))


# --- CF-ASG-006: fixed size with no scaling policy (COST-002, ASG part) ---


def _fixed(**props: Any) -> dict:
    return _group(MinSize="2", MaxSize="2", **props)


def _policy(group: Any) -> dict:
    return {"Type": "AWS::AutoScaling::ScalingPolicy", "Properties": {"AutoScalingGroupName": group}}


def test_fixed_size_cf(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"G": _fixed()}).get("CF-ASG-006") == {"G"}
    assert _cf(tmp_path, {"G": _group(MinSize=3, MaxSize="3")}).get("CF-ASG-006") == {"G"}


@pytest.mark.parametrize("sizes", [
    {"MinSize": "1", "MaxSize": "4"},
    {"MinSize": "0", "MaxSize": "0"},
    {"MinSize": _PARAM, "MaxSize": "2"},
    {"MinSize": "2", "MaxSize": _PARAM},
    {"MinSize": _PARAM, "MaxSize": _PARAM},
])
def test_fixed_size_not_reported_cf(tmp_path: Path, sizes: dict) -> None:
    assert "CF-ASG-006" not in _cf(tmp_path, {"G": _group(**sizes)})


def test_policy_or_schedule_of_the_group_clears_it_cf(tmp_path: Path) -> None:
    assert "CF-ASG-006" not in _cf(tmp_path, {"G": _fixed(), "P": _policy({"Ref": "G"})})
    schedule = {"Type": "AWS::AutoScaling::ScheduledAction", "Properties": {"AutoScalingGroupName": {"Ref": "G"}}}
    assert "CF-ASG-006" not in _cf(tmp_path, {"G": _fixed(), "S": schedule})
    named = _fixed(AutoScalingGroupName="web")
    assert "CF-ASG-006" not in _cf(tmp_path, {"G": named, "P": _policy("web")})


def test_policy_of_another_group_does_not_clear_it_cf(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"G": _fixed(), "H": _fixed(), "P": _policy({"Ref": "H"})})
    assert found.get("CF-ASG-006") == {"G"}


@pytest.mark.parametrize("target", [_PARAM, "some-other-name"])
def test_policy_that_cannot_be_tied_counts_for_all_cf(tmp_path: Path, target: Any) -> None:
    assert "CF-ASG-006" not in _cf(tmp_path, {"G": _fixed(), "P": _policy(target)})


def test_fixed_size_tf(tmp_path: Path) -> None:
    text = 'resource "aws_autoscaling_group" "g" {\n  min_size = 2\n  max_size = 2\n}\n'
    assert _tf(tmp_path, text).get("CF-ASG-006") == {"aws_autoscaling_group.g"}


@pytest.mark.parametrize("sizes", [
    ("1", "4"), ("0", "0"), ("var.size", "2"), ("2", "var.size"), ("var.size", "var.size"),
])
def test_fixed_size_not_reported_tf(tmp_path: Path, sizes: tuple[str, str]) -> None:
    text = f'resource "aws_autoscaling_group" "g" {{\n  min_size = {sizes[0]}\n  max_size = {sizes[1]}\n}}\n'
    assert "CF-ASG-006" not in _tf(tmp_path, text)


_TF_FIXED = 'resource "aws_autoscaling_group" "{0}" {{\n  min_size = 2\n  max_size = 2\n}}\n'


@pytest.mark.parametrize("resource", ["aws_autoscaling_policy", "aws_autoscaling_schedule"])
def test_policy_or_schedule_of_the_group_clears_it_tf(tmp_path: Path, resource: str) -> None:
    text = _TF_FIXED.format("g") + _TF_FIXED.format("h") + f'''
resource "{resource}" "p" {{
  autoscaling_group_name = aws_autoscaling_group.g.name
}}
'''
    assert _tf(tmp_path, text).get("CF-ASG-006") == {"aws_autoscaling_group.h"}


def test_policy_that_cannot_be_tied_counts_for_all_tf(tmp_path: Path) -> None:
    text = _TF_FIXED.format("g") + '''
resource "aws_autoscaling_policy" "p" {
  autoscaling_group_name = var.group
}
'''
    assert "CF-ASG-006" not in _tf(tmp_path, text)


def test_fixed_size_is_worded_as_advice(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"G": _fixed()}}), encoding="utf-8")
    found = [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[]) if f.id == "CF-ASG-006"]
    assert len(found) == 1
    assert "can be intended" in found[0].recommendation


def test_cost_002_stays_beside_the_fixed_size_check() -> None:
    assert "CF-ASG-006" not in CF_COVERS_STATIC
    assert CF_PARTLY_COVERS_STATIC["CF-ASG-006"][0] == ("COST-002",)


# --- Spot check still reads the group, and a healthy pair reports nothing ---


def test_compliant_group_and_configuration_report_nothing_cf(tmp_path: Path) -> None:
    group = _group(HealthCheckType="ELB", TargetGroupARNs=["arn"],
                   LaunchTemplate={"LaunchTemplateId": "lt-1", "Version": "1"})
    assert _cf(tmp_path, {"G": group, "C": _config(AssociatePublicIpAddress=False)}) == {}


def test_spot_check_is_unchanged_by_the_group_properties_tf(tmp_path: Path) -> None:
    text = _tf_group('name = var.name\n  health_check_type = var.health\n  target_group_arns = var.tgs')
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    found = run_resource_checks(resources_from_terraform(tmp_path, []), tmp_path / "main.tf")
    assert "CF-SUST-001" in {f.id for f in found}
