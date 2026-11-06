"""CF-VPC-002 / CF-VPC-003: S3 and DynamoDB traffic through a NAT gateway."""
import json
from pathlib import Path

from aws_arch_agent import pricing
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-VPC-002", "CF-VPC-003")


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _vpc(name: str = "Vpc", nat: bool = True) -> dict:
    out = {
        name: {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
        f"{name}Public": {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": name}, "CidrBlock": "10.0.0.0/24"}},
    }
    if nat:
        out[f"{name}Eip"] = {"Type": "AWS::EC2::EIP", "Properties": {"Domain": "vpc"}}
        out[f"{name}Nat"] = {"Type": "AWS::EC2::NatGateway", "Properties": {
            "SubnetId": {"Ref": f"{name}Public"}, "AllocationId": {"Fn::GetAtt": [f"{name}Eip", "AllocationId"]}}}
    return out


def _endpoint(service, vpc: str = "Vpc", kind: str | None = None) -> dict:
    props = {"VpcId": {"Ref": vpc}, "ServiceName": service}
    if kind:
        props["VpcEndpointType"] = kind
    return {"Type": "AWS::EC2::VPCEndpoint", "Properties": props}


def _sub(svc: str) -> dict:
    return {"Fn::Sub": "com.amazonaws.${AWS::Region}." + svc}


def test_nat_and_no_gateway_endpoints_gives_two_findings(tmp_path: Path) -> None:
    """Done when: a VPC with NAT and no gateway endpoints gives two findings."""
    found = _cf(tmp_path, _vpc())
    assert sorted(f.id for f in found) == list(IDS)
    s3 = next(f for f in found if f.id == "CF-VPC-002")
    gb = pricing.price("nat:gb", "us-east-1")
    assert gb is not None
    assert f"${gb.usd:.6g}/GB" in s3.recommendation
    assert "no hourly or data charge" in s3.recommendation
    assert "only the Gateway type is free" in s3.recommendation
    assert s3.evidence == "Vpc (AWS::EC2::VPC)" and s3.category == "Cost Optimization"


def test_s3_gateway_endpoint_leaves_one(tmp_path: Path) -> None:
    """Done when: with an S3 gateway endpoint, one."""
    found = _cf(tmp_path, _vpc() | {"S3": _endpoint(_sub("s3"))})
    assert [f.id for f in found] == ["CF-VPC-003"]


def test_no_nat_gives_none(tmp_path: Path) -> None:
    """Done when: a VPC with no NAT gives none."""
    assert _cf(tmp_path, _vpc(nat=False)) == []


def test_interface_endpoint_for_s3_does_not_clear_it(tmp_path: Path) -> None:
    found = _cf(tmp_path, _vpc() | {"S3": _endpoint(_sub("s3"), kind="Interface")})
    assert sorted(f.id for f in found) == list(IDS)


def test_service_name_forms(tmp_path: Path) -> None:
    join = {"Fn::Join": ["", ["com.amazonaws.", {"Ref": "AWS::Region"}, ".dynamodb"]]}  # cdk synth
    found = _cf(tmp_path, _vpc() | {
        "S3": _endpoint("com.amazonaws.us-east-1.s3", kind="Gateway"), "Ddb": _endpoint(join)})
    assert found == []


def test_an_unreadable_endpoint_is_not_judged(tmp_path: Path) -> None:
    found = _cf(tmp_path, _vpc() | {"E": _endpoint({"Ref": "ServiceParam"})})
    assert found == []
    # Another service, read literally, clears nothing.
    found = _cf(tmp_path, _vpc() | {"E": _endpoint(_sub("ec2"), kind="Interface")})
    assert sorted(f.id for f in found) == list(IDS)
    # A readable S3 endpoint whose type comes from a parameter may be the gateway one.
    found = _cf(tmp_path, _vpc() | {"E": _endpoint(_sub("s3"), kind=None) | {"Properties": {
        "VpcId": {"Ref": "Vpc"}, "ServiceName": _sub("s3"), "VpcEndpointType": {"Ref": "Kind"}}}})
    assert [f.id for f in found] == ["CF-VPC-003"]


def test_each_vpc_is_judged_on_its_own_endpoints(tmp_path: Path) -> None:
    found = _cf(tmp_path, _vpc("A") | _vpc("B") | _vpc("C", nat=False) | {
        "AS3": _endpoint(_sub("s3"), vpc="A"), "ADdb": _endpoint(_sub("dynamodb"), vpc="A"),
        "CS3": _endpoint(_sub("s3"), vpc="C")})
    assert sorted((f.id, f.evidence) for f in found) == [
        ("CF-VPC-002", "B (AWS::EC2::VPC)"), ("CF-VPC-003", "B (AWS::EC2::VPC)")]


def test_private_nat_gateway_has_no_route_out(tmp_path: Path) -> None:
    resources = _vpc()
    resources["VpcNat"]["Properties"]["ConnectivityType"] = "private"
    assert _cf(tmp_path, resources) == []


def test_nat_gateway_with_no_vpc_in_the_template(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": {"Ref": "SubnetParam"}}},
        "S3": _endpoint(_sub("s3")) | {"Properties": {"VpcId": {"Ref": "VpcParam"}, "ServiceName": _sub("s3")}},
    })
    assert [(f.id, f.evidence) for f in found] == [("CF-VPC-003", "Nat (AWS::EC2::NatGateway)")]
    fix = attach_fixes(found, "cloudformation")[0].suggested_code or ""
    assert "VpcId: !Ref Vpc" in fix and ".dynamodb" in fix


TF = """\
data "aws_region" "current" {}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.0.0/24"
}

resource "aws_nat_gateway" "nat" {
  subnet_id = aws_subnet.public.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint" "ddb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Interface"
}
"""


def _tf(tmp_path: Path, text: str) -> list[Finding]:
    module = tmp_path / "infra"
    module.mkdir(exist_ok=True)
    (module / "main.tf").write_text(text, encoding="utf-8")
    return [f for f in run_resource_checks(resources_from_terraform(module), module) if f.id in IDS]


def test_terraform(tmp_path: Path) -> None:
    found = _tf(tmp_path, TF)
    assert [(f.id, f.evidence) for f in found] == [("CF-VPC-003", "aws_vpc.main (aws_vpc)")]
    fix = attach_fixes(found, "terraform")[0].suggested_code or ""
    assert "vpc_id            = aws_vpc.main.id" in fix and '.dynamodb"' in fix


def test_terraform_default_type_and_variables(tmp_path: Path) -> None:
    text = TF.replace('  vpc_endpoint_type = "Interface"\n', "")  # Gateway by default
    assert _tf(tmp_path, text) == []
    text = TF.replace('"com.amazonaws.${data.aws_region.current.name}.dynamodb"', "var.service")
    assert [f.id for f in _tf(tmp_path, text)] == ["CF-VPC-003"]  # an Interface endpoint is never free
    text = text.replace('  vpc_endpoint_type = "Interface"\n', "")
    assert _tf(tmp_path, text) == []  # a gateway endpoint whose variable may name DynamoDB
    text = TF.replace("subnet_id = aws_subnet.public.id", 'subnet_id = aws_subnet.public.id\n  connectivity_type = "private"')
    assert _tf(tmp_path, text) == []


def test_sub_list_form_and_data_source_service_names(tmp_path: Path) -> None:
    sub_list = {"Fn::Sub": ["com.amazonaws.${Region}.s3", {"Region": {"Ref": "AWS::Region"}}]}
    found = _cf(tmp_path, _vpc() | {"S3": _endpoint(sub_list)})
    assert [f.id for f in found] == ["CF-VPC-003"]
    # A service name from a data source cannot be read: it may be DynamoDB.
    text = TF.replace('"com.amazonaws.${data.aws_region.current.name}.dynamodb"',
                      "data.aws_vpc_endpoint_service.ddb.service_name")
    text = text.replace('  vpc_endpoint_type = "Interface"\n', "")
    assert _tf(tmp_path, text) == []
    # An endpoint type from a variable may be Gateway.
    text = TF.replace('vpc_endpoint_type = "Interface"', "vpc_endpoint_type = var.kind")
    assert _tf(tmp_path, text) == []
