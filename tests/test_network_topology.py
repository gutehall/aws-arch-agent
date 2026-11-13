"""REL 2: subnet tiers span Availability Zones and leave room in the VPC CIDR (CF-VPC-004,
CF-VPC-005, REL-032), VPCs connect through a hub rather than a peering mesh (CF-VPC-006),
and VPC CIDRs do not overlap across the repo (REPO-014)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _scan(root: Path, files: dict[str, str]) -> tuple[list, list[str]]:
    for rel, text in files.items():
        _write(root / rel, text)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings, ctx.rules_run


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def _az(index: int) -> dict:
    return {"Fn::Select": [index, {"Fn::GetAZs": ""}]}


def _subnet(cidr: str, az: object, public: bool | None = None) -> dict:
    props: dict = {"VpcId": {"Ref": "Vpc"}, "CidrBlock": cidr, "AvailabilityZone": az}
    if public is not None:
        props["MapPublicIpOnLaunch"] = public
    return {"Type": "AWS::EC2::Subnet", "Properties": props}


def _vpc(cidr: str = "10.0.0.0/16") -> dict:
    return {"Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": cidr}}}


def _public_route(*subnets: str) -> dict:
    """An internet gateway route table associated with these subnets."""
    out: dict = {
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
        "PublicRt": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
        "DefaultRoute": {"Type": "AWS::EC2::Route", "Properties": {
            "RouteTableId": {"Ref": "PublicRt"}, "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": {"Ref": "Igw"}}},
    }
    for name in subnets:
        out[f"{name}Rt"] = {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {
            "RouteTableId": {"Ref": "PublicRt"}, "SubnetId": {"Ref": name}}}
    return out


def _tf_subnet(name: str, cidr: str, az: str, public: bool = False) -> str:
    flag = "  map_public_ip_on_launch = true\n" if public else ""
    return (f'resource "aws_subnet" "{name}" {{\n  vpc_id = aws_vpc.main.id\n'
            f'  cidr_block = "{cidr}"\n  availability_zone = "{az}"\n{flag}}}\n')


_TF_VPC = 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
_TF_IGW = (
    'resource "aws_internet_gateway" "igw" {\n  vpc_id = aws_vpc.main.id\n}\n'
    'resource "aws_route_table" "public" {\n  vpc_id = aws_vpc.main.id\n'
    '  route {\n    cidr_block = "0.0.0.0/0"\n    gateway_id = aws_internet_gateway.igw.id\n  }\n}\n'
)


def _tf_link(subnet: str) -> str:
    return (f'resource "aws_route_table_association" "{subnet}" {{\n'
            f'  subnet_id = aws_subnet.{subnet}.id\n'
            '  route_table_id = aws_route_table.public.id\n}\n')


def test_rules_answer_rel2() -> None:
    assert RULE_BEST_PRACTICES["CF-VPC-004"] == ("REL02-BP03",)
    assert RULE_BEST_PRACTICES["CF-VPC-005"] == ("REL02-BP03",)
    assert RULE_BEST_PRACTICES["REL-032"] == ("REL02-BP03",)
    assert RULE_BEST_PRACTICES["CF-VPC-006"] == ("REL02-BP04",)
    assert RULE_BEST_PRACTICES["REPO-014"] == ("REL02-BP05",)
    assert {"REL02-BP03", "REL02-BP04", "REL02-BP05"}.isdisjoint(NOT_CHECKED)
    assert {"REL02-BP01", "REL02-BP02"}.isdisjoint(NOT_CHECKED)


# --- CF-VPC-004: a subnet tier in one Availability Zone (REL02-BP03) ---

@pytest.mark.parametrize(
    ("files", "tiers"),
    [
        # Public by route table, private by default: both in AZ index 0.
        ({"t.json": _cfn({**_vpc(), "Pub": _subnet("10.0.0.0/24", _az(0)),
                          "Priv": _subnet("10.0.1.0/24", _az(0)), **_public_route("Pub")})},
         {"public", "private"}),
        # Public tier spans two AZs, private tier is in one literal AZ.
        ({"t.json": _cfn({**_vpc(), "PubA": _subnet("10.0.0.0/24", "eu-west-1a", True),
                          "PubB": _subnet("10.0.1.0/24", "eu-west-1b", True),
                          "Priv": _subnet("10.0.2.0/24", "eu-west-1a", False)})},
         {"private"}),
        ({"main.tf": _TF_VPC + _TF_IGW + _tf_subnet("pub", "10.0.0.0/24", "eu-west-1a")
          + _tf_link("pub") + _tf_subnet("priv_a", "10.0.1.0/24", "eu-west-1a")
          + _tf_subnet("priv_b", "10.0.2.0/24", "eu-west-1b")}, {"public"}),
        ({"main.tf": _TF_VPC + _tf_subnet("pub", "10.0.0.0/24", "eu-west-1a", public=True)
          + _tf_subnet("priv", "10.0.1.0/24", "eu-west-1a")}, {"public", "private"}),
    ],
    ids=["cfn-both-tiers", "cfn-private-tier", "tf-igw-route", "tf-map-public-ip"],
)
def test_tier_in_one_az_fails(tmp_path: Path, files: dict, tiers: set) -> None:
    # Under prod/: the pytest directory name says "test", which reads as a dev stack.
    findings, ran = _scan(tmp_path, {f"prod/{rel}": text for rel, text in files.items()})
    hits = _found(findings, "CF-VPC-004")
    assert {f.evidence.split(": ", 1)[1].split()[0] for f in hits} == tiers
    for f in hits:
        assert f.question == "REL 2"
        assert f.severity == "Medium" and f.category == "Reliability"
    answer = {a.question.id: a for a in well_architected.answers(findings, ran)}["REL 2"]
    assert not answer.met


@pytest.mark.parametrize(
    "files",
    [
        {"t.json": _cfn({**_vpc(), "PubA": _subnet("10.0.0.0/24", _az(0)),
                         "PubB": _subnet("10.0.1.0/24", _az(1)),
                         "PrivA": _subnet("10.0.2.0/24", _az(0)),
                         "PrivB": _subnet("10.0.3.0/24", _az(1)),
                         **_public_route("PubA", "PubB")})},
        {"main.tf": _TF_VPC + _TF_IGW
         + _tf_subnet("pub_a", "10.0.0.0/24", "eu-west-1a") + _tf_link("pub_a")
         + _tf_subnet("pub_b", "10.0.1.0/24", "eu-west-1b") + _tf_link("pub_b")
         + _tf_subnet("priv_a", "10.0.2.0/24", "eu-west-1a")
         + _tf_subnet("priv_b", "10.0.3.0/24", "eu-west-1b")},
        # The AZ is not set, so AWS picks it: not judged.
        {"t.json": _cfn({**_vpc(), "Priv": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.0.0.0/24"}}})},
        # The AZ comes from a data source: not judged.
        {"main.tf": _TF_VPC + 'data "aws_availability_zones" "all" {}\n'
         'resource "aws_subnet" "priv" {\n  vpc_id = aws_vpc.main.id\n'
         '  cidr_block = "10.0.0.0/24"\n'
         '  availability_zone = data.aws_availability_zones.all.names[0]\n}\n'},
    ],
    ids=["cfn-two-azs", "tf-two-azs", "cfn-no-az", "tf-az-from-data"],
)
def test_tiers_across_azs_pass(tmp_path: Path, files: dict) -> None:
    findings, _ran = _scan(tmp_path, files)
    assert not _found(findings, "CF-VPC-004")


# --- CF-VPC-005: subnets take the whole VPC CIDR (REL02-BP03) ---

@pytest.mark.parametrize(
    ("files", "fires"),
    [
        ({"t.json": _cfn({**_vpc("10.0.0.0/23"), "A": _subnet("10.0.0.0/24", _az(0)),
                          "B": _subnet("10.0.1.0/24", _az(1))})}, True),
        ({"t.json": _cfn({**_vpc("10.0.0.0/22"), "A": _subnet("10.0.0.0/24", _az(0)),
                          "B": _subnet("10.0.1.0/24", _az(1))})}, False),
        # A secondary CIDR block leaves room.
        ({"t.json": _cfn({**_vpc("10.0.0.0/23"), "A": _subnet("10.0.0.0/24", _az(0)),
                          "B": _subnet("10.0.1.0/24", _az(1)),
                          "More": {"Type": "AWS::EC2::VPCCidrBlock", "Properties": {
                              "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.1.0.0/16"}}})}, False),
        # The VPC CIDR is a parameter: not judged.
        ({"t.json": _cfn({"Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
            "CidrBlock": {"Ref": "Cidr"}}}, "A": _subnet("10.0.0.0/24", _az(0))})}, False),
        ({"main.tf": 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/23"\n}\n'
          + _tf_subnet("a", "10.0.0.0/24", "eu-west-1a")
          + _tf_subnet("b", "10.0.1.0/24", "eu-west-1b")}, True),
        ({"main.tf": _TF_VPC + _tf_subnet("a", "10.0.0.0/24", "eu-west-1a")
          + _tf_subnet("b", "10.0.1.0/24", "eu-west-1b")}, False),
        ({"main.tf": 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/23"\n}\n'
          'resource "aws_vpc_ipv4_cidr_block_association" "more" {\n'
          '  vpc_id = aws_vpc.main.id\n  cidr_block = "10.1.0.0/16"\n}\n'
          + _tf_subnet("a", "10.0.0.0/24", "eu-west-1a")
          + _tf_subnet("b", "10.0.1.0/24", "eu-west-1b")}, False),
    ],
    ids=["cfn-full", "cfn-room", "cfn-secondary-block", "cfn-param-cidr",
         "tf-full", "tf-room", "tf-secondary-block"],
)
def test_exhausted_vpc_cidr(tmp_path: Path, files: dict, fires: bool) -> None:
    findings, _ran = _scan(tmp_path, files)
    hits = _found(findings, "CF-VPC-005")
    assert bool(hits) is fires
    for f in hits:
        assert f.question == "REL 2" and f.severity == "Low"


# --- CF-VPC-006: a peering mesh with no transit gateway (REL02-BP04) ---

def _peerings(count: int) -> dict:
    return {f"Peer{i}": {"Type": "AWS::EC2::VPCPeeringConnection", "Properties": {
        "VpcId": {"Ref": "Vpc"}, "PeerVpcId": f"vpc-0{i}"}} for i in range(count)}


def _tf_peerings(count: int) -> str:
    return "".join(
        f'resource "aws_vpc_peering_connection" "p{i}" {{\n  vpc_id = aws_vpc.main.id\n'
        f'  peer_vpc_id = "vpc-0{i}"\n}}\n' for i in range(count))


@pytest.mark.parametrize(
    ("files", "fires"),
    [
        ({"t.json": _cfn({**_vpc(), **_peerings(3)})}, True),
        ({"t.json": _cfn({**_vpc(), **_peerings(2)})}, False),
        ({"t.json": _cfn({**_vpc(), **_peerings(3), "Tgw": {
            "Type": "AWS::EC2::TransitGateway", "Properties": {}}})}, False),
        ({"t.json": _cfn({**_vpc(), **_peerings(3), "Wan": {
            "Type": "AWS::NetworkManager::CoreNetwork", "Properties": {
                "GlobalNetworkId": "global-network-1"}}})}, False),
        ({"main.tf": _TF_VPC + _tf_peerings(3)}, True),
        ({"main.tf": _TF_VPC + _tf_peerings(3)
          + 'resource "aws_ec2_transit_gateway" "hub" {}\n'}, False),
    ],
    ids=["cfn-mesh", "cfn-two-peerings", "cfn-tgw", "cfn-cloud-wan", "tf-mesh", "tf-tgw"],
)
def test_peering_mesh(tmp_path: Path, files: dict, fires: bool) -> None:
    findings, _ran = _scan(tmp_path, files)
    hits = _found(findings, "CF-VPC-006")
    assert bool(hits) is fires
    for f in hits:
        assert f.question == "REL 2" and "3 VPC peering connections" in f.evidence


# --- REPO-014: VPC CIDRs overlap across the repo (REL02-BP05) ---

_CDK_APP = (
    "new ec2.Vpc(this, 'Vpc', { ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16') });\n"
)


def test_overlap_across_templates_modules_and_cdk(tmp_path: Path) -> None:
    files = {
        "stacks/network.json": _cfn(_vpc("10.0.0.0/16")),
        "stacks/data.yaml": "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"
                            "  Vpc:\n    Type: AWS::EC2::VPC\n    Properties:\n"
                            "      CidrBlock: 10.0.80.0/20\n",
        "modules/shared/main.tf": 'resource "aws_vpc" "shared" {\n'
                                  '  cidr_block = "10.0.64.0/18"\n}\n',
        "package.json": "{}",
        "lib/app.ts": _CDK_APP,
    }
    findings, ran = _scan(tmp_path, files)
    hits = _found(findings, "REPO-014")
    # Every pair overlaps: four declarations, six pairs.
    assert len(hits) == 6
    joined = " ".join(f.evidence for f in hits)
    for rel in files:
        if rel != "package.json":
            assert rel in joined
    for f in hits:
        assert f.question == "REL 2" and f.severity == "Medium"
    assert "REPO-014" in ran


def test_no_overlap_passes(tmp_path: Path) -> None:
    findings, _ran = _scan(tmp_path, {
        "a.json": _cfn(_vpc("10.0.0.0/16")),
        "main.tf": 'resource "aws_vpc" "b" {\n  cidr_block = "10.1.0.0/16"\n}\n',
        "lib/app.py": "ec2.Vpc(self, 'C', ip_addresses=ec2.IpAddresses.cidr('10.2.0.0/16'))\n",
    })
    assert not _found(findings, "REPO-014")


def test_dev_and_prod_are_not_compared(tmp_path: Path) -> None:
    tf = 'resource "aws_vpc" "main" {\n  cidr_block = "10.9.0.0/16"\n}\n'
    findings, _ran = _scan(tmp_path, {"envs/dev/main.tf": tf, "envs/prod/main.tf": tf})
    assert not _found(findings, "REPO-014")
    # Two stacks of one environment do connect.
    findings, _ran = _scan(tmp_path, {"envs/prod/network/main.tf": tf})
    hits = _found(findings, "REPO-014")
    assert len(hits) == 1 and "envs/prod/main.tf" in hits[0].evidence


def test_compiled_js_and_cdk_out_count_once(tmp_path: Path) -> None:
    findings, _ran = _scan(tmp_path, {
        "package.json": "{}",
        "lib/app.ts": _CDK_APP,
        "lib/app.js": _CDK_APP,
        "cdk.out/App.template.json": _cfn(_vpc("10.0.0.0/16")),
    })
    assert not _found(findings, "REPO-014")


def test_module_cidr_counts(tmp_path: Path) -> None:
    findings, _ran = _scan(tmp_path, {
        "a/main.tf": 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n'
                     '  cidr   = "10.0.0.0/16"\n}\n',
        "b/main.tf": 'resource "aws_vpc" "b" {\n  cidr_block = "10.0.0.0/24"\n}\n',
    })
    assert len(_found(findings, "REPO-014")) == 1


def test_tier_in_one_az_is_skipped_in_dev(tmp_path: Path) -> None:
    tf = (_TF_VPC + _tf_subnet("pub", "10.0.0.0/24", "eu-west-1a", public=True)
          + _tf_subnet("priv", "10.0.1.0/24", "eu-west-1a"))
    findings, _ran = _scan(tmp_path, {"dev/main.tf": tf})
    assert _found(findings, "CF-VPC-004") == []
