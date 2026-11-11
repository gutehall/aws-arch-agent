"""SEC 5: egress inspection (REPO-034), automated protection (REPO-035), and workloads in
public subnets (REPO-036)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    AutomatedNetworkProtectionMissing,
    EgressInspectionMissing,
    PublicSubnetWorkload,
    egress_paths,
    public_subnet_workloads,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }}, indent=2)


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = _cfn(merged)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / "prod" / _PATHS[source], body)


NAT = {
    "cdk": "const vpc = new ec2.Vpc(this, 'Vpc', { maxAzs: 2 });\n",
    "cloudformation": {"Nat": ("AWS::EC2::NatGateway", {"SubnetId": "subnet-1"})},
    "terraform": 'resource "aws_nat_gateway" "main" {\n  subnet_id = "subnet-1"\n}\n',
}
FIREWALL = {
    "cdk": "new networkfirewall.CfnFirewall(this, 'Fw', { firewallName, firewallPolicyArn, "
           "subnetMappings, vpcId });\n",
    "cloudformation": {"Fw": ("AWS::NetworkFirewall::Firewall", {"FirewallName": "fw"})},
    "terraform": 'resource "aws_networkfirewall_firewall" "fw" {\n  name = "fw"\n}\n',
}
DNS_FIREWALL = {
    "cdk": "new route53resolver.CfnFirewallRuleGroupAssociation(this, 'Dns', "
           "{ firewallRuleGroupId, priority: 101, vpcId });\n",
    "cloudformation": {"Dns": ("AWS::Route53Resolver::FirewallRuleGroupAssociation", {
        "Priority": 101})},
    "terraform": 'resource "aws_route53_resolver_firewall_rule_group_association" "dns" {\n'
                 "  priority = 101\n}\n",
}


# REPO-034: egress inspection


@pytest.mark.parametrize("source", SOURCES)
def test_egress_without_inspection_fails_repo_034(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, NAT[source])
    (finding,) = EgressInspectionMissing().run(tmp_path)
    assert finding.id == "REPO-034"
    assert "NAT gateway" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("control", [FIREWALL, DNS_FIREWALL], ids=["nfw", "dns"])
def test_egress_with_inspection_passes(tmp_path: Path, source: str, control: dict) -> None:
    _stack(tmp_path, source, NAT[source], control[source])
    assert EgressInspectionMissing().run(tmp_path) == []


def test_gateway_load_balancer_endpoint_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", NAT["cloudformation"], {"Gwlbe": (
        "AWS::EC2::VPCEndpoint", {"VpcEndpointType": "GatewayLoadBalancer"})})
    assert EgressInspectionMissing().run(tmp_path) == []


def test_cdk_vpc_without_nat_has_no_egress(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", "new ec2.Vpc(this, 'Vpc', { natGateways: 0 });\n")
    assert egress_paths(tmp_path) == {}
    assert EgressInspectionMissing().run(tmp_path) == []


def test_internet_gateway_is_egress(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_internet_gateway" "igw" {\n  vpc_id = "v"\n}\n')
    assert egress_paths(tmp_path) == {"internet gateway": "prod/main.tf"}


def test_no_vpc_gets_no_repo_034(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_s3_bucket" "d" {\n  bucket = "d"\n}\n')
    assert EgressInspectionMissing().run(tmp_path) == []


# REPO-035: automated network protection


ALB = {
    "cdk": "new elbv2.ApplicationLoadBalancer(this, 'Lb', { vpc, internetFacing: true });\n",
    "cloudformation": {"Lb": ("AWS::ElasticLoadBalancingV2::LoadBalancer", {})},
    "terraform": 'resource "aws_lb" "web" {\n  name = "web"\n}\n',
}
MANAGED_WAF = {
    "cdk": "new wafv2.CfnWebACL(this, 'Acl', { rules: [{ name: 'common', priority: 0, "
           "statement: { managedRuleGroupStatement: { vendorName: 'AWS', "
           "name: 'AWSManagedRulesCommonRuleSet' } } }] });\n",
    "cloudformation": {"Acl": ("AWS::WAFv2::WebACL", {"Rules": [{"Statement": {
        "ManagedRuleGroupStatement": {"VendorName": "AWS",
                                      "Name": "AWSManagedRulesCommonRuleSet"}}}]})},
    "terraform": 'resource "aws_wafv2_web_acl" "acl" {\n  rule {\n    statement {\n'
                 "      managed_rule_group_statement {\n        vendor_name = \"AWS\"\n"
                 '        name = "AWSManagedRulesCommonRuleSet"\n      }\n    }\n  }\n}\n',
}
SHIELD = {
    "cdk": "new shield.CfnProtection(this, 'Shield', { name, resourceArn });\n",
    "cloudformation": {"Shield": ("AWS::Shield::Protection", {"Name": "lb"})},
    "terraform": 'resource "aws_shield_protection" "lb" {\n  name = "lb"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_edge_without_automated_protection_fails_repo_035(
    tmp_path: Path, source: str
) -> None:
    _stack(tmp_path, source, ALB[source])
    (finding,) = AutomatedNetworkProtectionMissing().run(tmp_path)
    assert finding.id == "REPO-035"
    assert "load balancer" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("control", [MANAGED_WAF, SHIELD], ids=["waf", "shield"])
def test_edge_with_automated_protection_passes(
    tmp_path: Path, source: str, control: dict
) -> None:
    _stack(tmp_path, source, ALB[source], control[source])
    assert AutomatedNetworkProtectionMissing().run(tmp_path) == []


def test_waf_with_only_custom_rules_does_not_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", ALB["cloudformation"], {"Acl": (
        "AWS::WAFv2::WebACL", {"Rules": [{"Statement": {"RateBasedStatement": {
            "Limit": 1000}}}]})})
    assert AutomatedNetworkProtectionMissing().run(tmp_path)


def test_managed_threat_signatures_and_domain_lists_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", NAT["terraform"],
           'resource "aws_networkfirewall_firewall_policy" "p" {\n'
           '  resource_arn = "arn:aws:network-firewall:eu-west-1:aws-managed:'
           'stateful-rulegroup/ThreatSignaturesMalwareStrictOrder"\n}\n')
    assert AutomatedNetworkProtectionMissing().run(tmp_path) == []
    _stack(tmp_path, "cloudformation", NAT["cloudformation"], {"List": (
        "AWS::Route53Resolver::FirewallDomainList", {"ManagedOwnerName": "Route 53 Resolver DNS Firewall"})})
    assert AutomatedNetworkProtectionMissing().run(tmp_path) == []


def test_firewall_manager_policy_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", ALB["terraform"],
           'resource "aws_fms_policy" "waf" {\n  name = "waf"\n}\n')
    assert AutomatedNetworkProtectionMissing().run(tmp_path) == []


def test_nothing_exposed_gets_no_repo_035(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_s3_bucket" "d" {\n  bucket = "d"\n}\n')
    assert AutomatedNetworkProtectionMissing().run(tmp_path) == []


# REPO-036: workloads in public subnets


def test_cdk_function_in_public_subnet_fails_repo_036(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", NAT["cdk"],
           "new lambda.Function(this, 'Fn', { runtime, handler, code, vpc, "
           "vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC }, allowPublicSubnet: true });\n")
    (finding,) = PublicSubnetWorkload().run(tmp_path)
    assert "lambda.Function" in finding.evidence
    assert finding.file == "prod/lib/stack.ts"
    assert finding.line == 2


def test_cdk_load_balancer_in_public_subnet_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", NAT["cdk"],
           "new elbv2.ApplicationLoadBalancer(this, 'Lb', { vpc, internetFacing: true, "
           "vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC } });\n"
           "new ecs.FargateService(this, 'Svc', { cluster, taskDefinition, "
           "vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS } });\n")
    assert PublicSubnetWorkload().run(tmp_path) == []


def test_python_cdk_instance_in_public_subnet(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "ec2.Instance(self, 'Box', vpc=vpc, instance_type=t, machine_image=ami,\n"
           "    vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC))\n")
    (finding,) = PublicSubnetWorkload().run(tmp_path)
    assert "ec2.Instance" in finding.evidence


_TF_SUBNETS = (
    'resource "aws_subnet" "public" {\n  vpc_id = aws_vpc.main.id\n'
    "  map_public_ip_on_launch = true\n  tags = {\n    Name = \"public\"\n  }\n}\n"
    'resource "aws_subnet" "private" {\n  vpc_id = aws_vpc.main.id\n}\n'
)


def test_terraform_instance_in_public_subnet_fails(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", _TF_SUBNETS,
           'resource "aws_instance" "app" {\n  subnet_id = aws_subnet.public.id\n}\n'
           'resource "aws_nat_gateway" "nat" {\n  subnet_id = aws_subnet.public.id\n}\n'
           'resource "aws_lb" "web" {\n  subnets = [aws_subnet.public.id]\n}\n'
           'resource "aws_instance" "worker" {\n  subnet_id = aws_subnet.private.id\n}\n')
    found = public_subnet_workloads(tmp_path)
    assert [what for _rel, _line, what in found] == ["aws_instance.app"]


def test_cloudformation_database_in_public_subnets_fails(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {
        "PublicA": ("AWS::EC2::Subnet", {"MapPublicIpOnLaunch": True}),
        "PrivateA": ("AWS::EC2::Subnet", {}),
        "Nat": ("AWS::EC2::NatGateway", {"SubnetId": {"Ref": "PublicA"}}),
        "Lb": ("AWS::ElasticLoadBalancingV2::LoadBalancer", {"Subnets": [{"Ref": "PublicA"}]}),
        "Db": ("AWS::RDS::DBSubnetGroup", {"SubnetIds": [{"Ref": "PublicA"}]}),
        "Fn": ("AWS::Lambda::Function", {"VpcConfig": {"SubnetIds": [{"Ref": "PrivateA"}]}}),
    })
    (finding,) = PublicSubnetWorkload().run(tmp_path)
    assert "Db (AWS::RDS::DBSubnetGroup)" in finding.evidence
    assert "Lb" not in finding.evidence and "Nat" not in finding.evidence


def test_no_public_subnet_gets_no_repo_036(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", _TF_SUBNETS.replace(
        "  map_public_ip_on_launch = true\n", ""),
        'resource "aws_instance" "app" {\n  subnet_id = aws_subnet.public.id\n}\n')
    assert PublicSubnetWorkload().run(tmp_path) == []


# Reports and the answer


def test_saved_report_quoting_findings_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", NAT["terraform"], ALB["terraform"])
    rules = (EgressInspectionMissing(), AutomatedNetworkProtectionMissing())
    hits = [f for rule in rules for f in rule.run(tmp_path)]
    assert len(hits) == 2
    report = json.dumps({"findings": [f.model_dump() for f in hits]})
    _write(tmp_path / "reports" / "report.json", report)
    assert all(len(rule.run(tmp_path)) == 1 for rule in rules)
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    assert all(rule.run(empty) == [] for rule in (*rules, PublicSubnetWorkload()))


def test_sec5_rules_map_and_run_by_default() -> None:
    assert well_architected.best_practices_of("REPO-034") == ("SEC05-BP03",)
    assert well_architected.best_practices_of("REPO-035") == ("SEC05-BP04",)
    assert well_architected.best_practices_of("REPO-036") == ("SEC05-BP01",)
    assert not {"REPO-034", "REPO-035", "REPO-036"} & ORG_RULE_IDS


def test_sec5_is_fully_checked_and_reads_met_without_findings() -> None:
    (sec5,) = [a for a in well_architected.answers([]) if a.question.id == "SEC 5"]
    assert sec5.not_checked == ()
    assert sec5.met
