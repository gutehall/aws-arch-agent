"""Security groups, network ACLs, NAT gateways and transit gateways in templates.

CF-SG-001 (sensitive or high-risk port), CF-SG-002 (every port), CF-SG-003 (all egress),
CF-NACL-001, CF-NAT-001, CF-TGW-001 and CF-TGW-002.
"""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-SG-001", "CF-SG-002", "CF-SG-003", "CF-NACL-001", "CF-NAT-001", "CF-TGW-001", "CF-TGW-002")


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    """Check id -> logical ids it reported. The scan must not warn."""
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _by_id(found)


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    found = run_resource_checks(resources, tmp_path / "main.tf", warnings)
    assert warnings == []
    return _by_id(found)


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _sg(ingress: list | None = None, egress: list | None = None) -> dict:
    props: dict = {"GroupDescription": "sg", "VpcId": "vpc-1"}
    if ingress is not None:
        props["SecurityGroupIngress"] = ingress
    if egress is not None:
        props["SecurityGroupEgress"] = egress
    return {"Type": "AWS::EC2::SecurityGroup", "Properties": props}


_CLOSED_EGRESS = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.0.0.0/16"}]
# What CDK writes for allowAllOutbound: true.
_CDK_ALL_OUT = [{"CidrIp": "0.0.0.0/0", "Description": "Allow all outbound traffic by default",
                 "IpProtocol": "-1"}]


def _rule(port: int | None, cidr: str = "0.0.0.0/0", protocol: str = "tcp") -> dict:
    rule: dict = {"IpProtocol": protocol, "CidrIp": cidr} if ":" not in cidr else {
        "IpProtocol": protocol, "CidrIpv6": cidr}
    if port is not None:
        rule |= {"FromPort": port, "ToPort": port}
    return rule


# --- Security groups -------------------------------------------------------------


def test_high_risk_and_sensitive_ports(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Ssh": _sg([_rule(22)], _CLOSED_EGRESS),
        "Http8080": _sg([_rule(8080, "::/0")], _CLOSED_EGRESS),  # Security Hub EC2.19
        "Smb": _sg([_rule(445)], _CLOSED_EGRESS),
        "Https": _sg([_rule(443)], _CLOSED_EGRESS),
        "Private": _sg([_rule(22, "10.0.0.0/8")], _CLOSED_EGRESS),
        "Icmp": _sg([{"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "CidrIp": "0.0.0.0/0"}],
                    _CLOSED_EGRESS),
    })
    assert found == {"CF-SG-001": {"Ssh", "Http8080", "Smb"}}


def test_all_ports_is_reported_once_as_cf_sg_002(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "AllProtocols": _sg([_rule(None, protocol="-1"), _rule(22)], _CLOSED_EGRESS),
        "FullRange": _sg([{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535,
                           "CidrIpv6": "::/0"}], _CLOSED_EGRESS),
        "Rule": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {
            "GroupId": "sg-1", "IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}},
        "Param": _sg([{"IpProtocol": "tcp", "FromPort": {"Ref": "Port"}, "ToPort": {"Ref": "Port"},
                       "CidrIp": "0.0.0.0/0"}], _CLOSED_EGRESS),
    })
    assert found["CF-SG-002"] == {"AllProtocols", "FullRange", "Rule"}
    assert found["CF-SG-001"] == {"Param"}  # an unknown port may be a sensitive one


def test_egress_open_to_the_internet(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "CdkDefault": _sg([], _CDK_ALL_OUT),
        "Closed": _sg([], _CLOSED_EGRESS),
        "Https": _sg([], [_rule(443)]),  # one port to anywhere is not all egress
        "AwsDefault": _sg([]),  # no SecurityGroupEgress: AWS allows all outbound
    })
    assert found == {"CF-SG-003": {"CdkDefault", "AwsDefault"}}


def test_a_standalone_egress_rule_does_not_remove_the_default(tmp_path: Path) -> None:
    """AWS adds the allow-all rule when the group is created with no egress rules; a
    standalone SecurityGroupEgress is added afterwards and leaves it in place."""
    found = _cf(tmp_path, {
        "Sg": _sg([]),
        "Out": {"Type": "AWS::EC2::SecurityGroupEgress", "Properties": {
            "GroupId": {"Fn::GetAtt": ["Sg", "GroupId"]}, "IpProtocol": "tcp",
            "FromPort": 443, "ToPort": 443, "CidrIp": "10.0.0.0/16"}},
        "OpenOut": {"Type": "AWS::EC2::SecurityGroupEgress", "Properties": {
            "GroupId": {"Fn::GetAtt": ["Sg", "GroupId"]}, "IpProtocol": "-1",
            "CidrIp": "0.0.0.0/0"}},
    })
    assert found == {"CF-SG-003": {"Sg", "OpenOut"}}


# --- Network ACLs ----------------------------------------------------------------


def _entry(**props: object) -> dict:
    base = {"NetworkAclId": {"Ref": "Acl"}, "RuleNumber": 100, "Protocol": 6,
            "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0",
            "PortRange": {"From": 22, "To": 22}}
    return {"Type": "AWS::EC2::NetworkAclEntry", "Properties": {**base, **props}}


def test_network_acl_entries(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Ssh": _entry(),
        "AllTraffic": _entry(Protocol=-1, PortRange=None),
        "RdpRange": _entry(Ipv6CidrBlock="::/0", CidrBlock=None, PortRange={"From": 3000, "To": 4000}),
        "Https": _entry(PortRange={"From": 443, "To": 443}),
        "Deny": _entry(RuleAction="deny"),
        "Outbound": _entry(Egress=True),
        "Private": _entry(CidrBlock="10.0.0.0/8"),
        "Param": _entry(PortRange={"Ref": "Ports"}),
    })
    assert found == {"CF-NACL-001": {"Ssh", "AllTraffic", "RdpRange"}}


# --- NAT gateways ----------------------------------------------------------------


def _az(index: int) -> dict:
    return {"Fn::Select": [index, {"Fn::GetAZs": ""}]}


def _vpc_with_nats(nat_azs: list[int]) -> dict:
    """Two AZs, the way CDK synthesises ec2.Vpc: one NAT gateway per entry in nat_azs, and
    each private subnet routed to the NAT gateway of its AZ, or the first one."""
    out: dict = {"Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}}}
    for i in (0, 1):
        out[f"Public{i}"] = {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": f"10.0.{i}.0/24", "AvailabilityZone": _az(i)}}
        out[f"Private{i}"] = {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": f"10.0.1{i}.0/24", "AvailabilityZone": _az(i)}}
    for i in nat_azs:
        out[f"Eip{i}"] = {"Type": "AWS::EC2::EIP", "Properties": {"Domain": "vpc"}}
        out[f"Nat{i}"] = {"Type": "AWS::EC2::NatGateway", "Properties": {
            "SubnetId": {"Ref": f"Public{i}"}, "AllocationId": {"Fn::GetAtt": [f"Eip{i}", "AllocationId"]}}}
    for i in (0, 1):
        nat = f"Nat{i}" if i in nat_azs else f"Nat{nat_azs[0]}"
        out[f"Table{i}"] = {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}}
        out[f"Assoc{i}"] = {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {
            "RouteTableId": {"Ref": f"Table{i}"}, "SubnetId": {"Ref": f"Private{i}"}}}
        out[f"Default{i}"] = {"Type": "AWS::EC2::Route", "Properties": {
            "RouteTableId": {"Ref": f"Table{i}"}, "DestinationCidrBlock": "0.0.0.0/0",
            "NatGatewayId": {"Ref": nat}}}
    return out


def test_one_nat_gateway_for_two_azs(tmp_path: Path) -> None:
    found = _cf(tmp_path, _vpc_with_nats([0]))
    assert found.get("CF-NAT-001") == {"Nat0"}


def test_a_nat_gateway_per_az_is_fine(tmp_path: Path) -> None:
    assert "CF-NAT-001" not in _cf(tmp_path, _vpc_with_nats([0, 1]))


def test_subnets_with_an_unknown_az_are_not_counted(tmp_path: Path) -> None:
    template = _vpc_with_nats([0])
    template["Private1"]["Properties"].pop("AvailabilityZone")
    assert "CF-NAT-001" not in _cf(tmp_path, template)


# --- Transit gateways ------------------------------------------------------------


def test_transit_gateway_auto_accept_and_flow_logs(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Open": {"Type": "AWS::EC2::TransitGateway", "Properties": {"AutoAcceptSharedAttachments": "enable"}},
        "Logged": {"Type": "AWS::EC2::TransitGateway", "Properties": {"AutoAcceptSharedAttachments": "disable"}},
        "Log": {"Type": "AWS::EC2::FlowLog", "Properties": {
            "ResourceType": "TransitGateway", "ResourceId": {"Ref": "Logged"},
            "LogDestinationType": "s3", "LogDestination": "arn:aws:s3:::logs"}},
    })
    assert found == {"CF-TGW-001": {"Open"}, "CF-TGW-002": {"Open"}}


def test_an_attachment_flow_log_does_not_hide_the_gateway(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Tgw": {"Type": "AWS::EC2::TransitGateway", "Properties": {}},
        "Log": {"Type": "AWS::EC2::FlowLog", "Properties": {
            "ResourceType": "TransitGatewayAttachment", "ResourceId": "tgw-attach-1"}},
        "Inbound": _entry(Egress="False"),  # a string false is still inbound
    })
    assert found == {"CF-TGW-002": {"Tgw"}, "CF-NACL-001": {"Inbound"}}


def test_a_flow_log_on_an_unknown_gateway_counts_for_all(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Tgw": {"Type": "AWS::EC2::TransitGateway", "Properties": {}},
        "Log": {"Type": "AWS::EC2::FlowLog", "Properties": {
            "ResourceType": "TransitGateway", "ResourceId": {"Ref": "TgwParam"}}},
    })
    assert found == {}


# --- Terraform -------------------------------------------------------------------

NETWORK_TF = """\
resource "aws_security_group" "web" {
  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "closed" {
  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_vpc_security_group_egress_rule" "out" {
  security_group_id = aws_security_group.closed.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
resource "aws_network_acl" "public" {
  vpc_id = "vpc-1"
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 3389
    to_port    = 3389
  }
}
resource "aws_network_acl_rule" "ssh" {
  network_acl_id = "acl-1"
  rule_number    = 110
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
resource "aws_network_acl_rule" "out" {
  network_acl_id = "acl-1"
  rule_number    = 120
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
resource "aws_ec2_transit_gateway" "hub" {
  auto_accept_shared_attachments = "enable"
}
resource "aws_ec2_transit_gateway" "logged" {}
resource "aws_flow_log" "tgw" {
  transit_gateway_id   = aws_ec2_transit_gateway.logged.id
  log_destination_type = "s3"
  log_destination      = "arn:aws:s3:::logs"
}
resource "aws_subnet" "public_a" {
  vpc_id            = "vpc-1"
  cidr_block        = "10.0.0.0/24"
  availability_zone = "eu-west-1a"
}
resource "aws_subnet" "private_a" {
  vpc_id            = "vpc-1"
  cidr_block        = "10.0.10.0/24"
  availability_zone = "eu-west-1a"
}
resource "aws_subnet" "private_b" {
  vpc_id            = "vpc-1"
  cidr_block        = "10.0.11.0/24"
  availability_zone = "eu-west-1b"
}
resource "aws_nat_gateway" "single" {
  subnet_id = aws_subnet.public_a.id
}
resource "aws_route_table" "private" {
  vpc_id = "vpc-1"
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.single.id
  }
}
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}
resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}
"""


def test_terraform_network_resources(tmp_path: Path) -> None:
    found = _tf(tmp_path, NETWORK_TF)
    assert found == {
        "CF-SG-002": {"aws_security_group.web"},
        # Terraform drops the AWS default egress: no egress block means none.
        "CF-SG-003": {"aws_security_group.web", "aws_vpc_security_group_egress_rule.out"},
        "CF-NACL-001": {"aws_network_acl.public", "aws_network_acl_rule.ssh"},
        "CF-NAT-001": {"aws_nat_gateway.single"},
        "CF-TGW-001": {"aws_ec2_transit_gateway.hub"},
        "CF-TGW-002": {"aws_ec2_transit_gateway.hub"},
    }


def test_terraform_unknown_values_are_not_judged(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "cidrs" { type = list(string) }
variable "accept" { type = string }
resource "aws_security_group" "dyn" {
  dynamic "egress" {
    for_each = var.cidrs
    content {
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      cidr_blocks = [egress.value]
    }
  }
}
resource "aws_ec2_transit_gateway" "hub" {
  auto_accept_shared_attachments = var.accept
}
resource "aws_flow_log" "tgw" {
  transit_gateway_id = var.tgw_id
}
""")
    assert found == {}


def test_fixes_match_the_resource_shape(tmp_path: Path) -> None:
    egress = attach_fixes([Finding(id="CF-SG-003", title="t", recommendation="r",
                                   evidence="Out (AWS::EC2::SecurityGroupEgress)")], "cloudformation")[0]
    assert "Type: AWS::EC2::SecurityGroupEgress" in (egress.suggested_code or "")
    acl = attach_fixes([Finding(id="CF-NACL-001", title="t", recommendation="r",
                                evidence="aws_network_acl.public (aws_network_acl)")], "terraform")[0]
    assert (acl.suggested_code or "").startswith('resource "aws_network_acl" "public" {')
    tgw = attach_fixes([Finding(id="CF-TGW-002", title="t", recommendation="r",
                                evidence="Hub (AWS::EC2::TransitGateway)")], "cloudformation")[0]
    assert "ResourceId: !Ref Hub" in (tgw.suggested_code or "")
