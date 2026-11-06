"""CF-EC2-002 (subnets that map public IPs) and CF-EC2-003 (instances that ask for one)."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = {"CF-EC2-002", "CF-EC2-003"}
CDK_TAGS = [{"Key": "aws-cdk:subnet-name", "Value": "Public"}, {"Key": "aws-cdk:subnet-type", "Value": "Public"}]


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings if f.id in IDS}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _subnet(**props) -> dict:
    return {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.0.0.0/24", **props}}


def _instance(**props) -> dict:
    return {"Type": "AWS::EC2::Instance", "Properties": {
        "ImageId": "ami-1", "MetadataOptions": {"HttpTokens": "required"}, **props}}


def _lt(**data) -> dict:
    return {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
        "MetadataOptions": {"HttpTokens": "required"}, **data}}}


def test_cloudformation_public_ips(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "PublicSubnet": _subnet(MapPublicIpOnLaunch=True),
        "PublicString": _subnet(MapPublicIpOnLaunch="true"),
        "PrivateSubnet": _subnet(MapPublicIpOnLaunch=False),
        "DefaultSubnet": _subnet(),
        "ParamSubnet": _subnet(MapPublicIpOnLaunch={"Ref": "Public"}),
        "CdkPublic": _subnet(MapPublicIpOnLaunch=True, Tags=CDK_TAGS),  # ec2.Vpc public subnet
        "PublicInstance": _instance(NetworkInterfaces=[
            {"DeviceIndex": "0", "AssociatePublicIpAddress": True, "SubnetId": {"Ref": "S"}}]),
        "PrivateInstance": _instance(NetworkInterfaces=[
            {"DeviceIndex": "0", "AssociatePublicIpAddress": False, "SubnetId": {"Ref": "S"}}]),
        "PlainInstance": _instance(SubnetId={"Ref": "S"}),
        "PublicLt": _lt(NetworkInterfaces=[{"DeviceIndex": 0, "AssociatePublicIpAddress": "true"}]),
        "PrivateLt": _lt(NetworkInterfaces=[{"DeviceIndex": 0}]),
    })
    assert _found(findings) == {
        ("PublicSubnet", "CF-EC2-002"),
        ("PublicString", "CF-EC2-002"),
        ("PublicInstance", "CF-EC2-003"),
        ("PublicLt", "CF-EC2-003"),
    }
    assert {f.severity for f in findings} == {"Medium"}
    instance = next(f for f in findings if f.evidence.startswith("PublicInstance"))
    assert instance.recommendation.startswith("AssociatePublicIpAddress is true on network interface 0.")
    attach_fixes(findings, "cloudformation")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert "MapPublicIpOnLaunch: false" in code["PublicSubnet"]
    assert "LaunchTemplateData:" in code["PublicLt"]


PUBLIC_IP_TF = """\
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.v.id
  cidr_block              = "10.0.0.0/24"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.v.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_subnet" "from_var" {
  vpc_id                  = aws_vpc.v.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = var.public
}

resource "aws_instance" "public" {
  ami                         = "ami-1"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_instance" "private" {
  ami                         = "ami-1"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_launch_template" "public" {
  metadata_options {
    http_tokens = "required"
  }
  network_interfaces {
    associate_public_ip_address = true
  }
}

resource "aws_launch_template" "spot_unknown" {
  metadata_options {
    http_tokens = "required"
  }
  dynamic "instance_market_options" {
    for_each = var.spot
    content {
      market_type = "spot"
    }
  }
  network_interfaces {
    associate_public_ip_address = true
  }
}
"""


def test_terraform_public_ips(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(PUBLIC_IP_TF, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    findings = [f for f in run_resource_checks(resources, tmp_path / "main.tf") if f.id in IDS]
    assert _found(findings) == {
        ("aws_subnet.public", "CF-EC2-002"),
        ("aws_instance.public", "CF-EC2-003"),
        ("aws_launch_template.public", "CF-EC2-003"),
        # An unknown Spot block does not hide the network interface check.
        ("aws_launch_template.spot_unknown", "CF-EC2-003"),
    }
    attach_fixes(findings, "terraform")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert "map_public_ip_on_launch = false" in code["aws_subnet.public"]
    assert "associate_public_ip_address = false" in code["aws_instance.public"]
    assert "network_interfaces {" in code["aws_launch_template.public"]
