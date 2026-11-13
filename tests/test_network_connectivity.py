"""REL 2: a public endpoint is highly available (REPO-131) and the on-premises link is
redundant (REPO-132)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import PublicEndpointNotHighlyAvailable, SingleOnPremLink
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TF_INSTANCE = (
    'resource "aws_instance" "web" {\n  ami = "ami-1"\n  associate_public_ip_address = true\n}\n'
)
_CFN_INSTANCE = (
    '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Web": {"Type": '
    '"AWS::EC2::Instance", "Properties": {"ImageId": "ami-1", "NetworkInterfaces": '
    '[{"AssociatePublicIpAddress": true, "DeviceIndex": "0"}]}}}}'
)
_CDK_INSTANCE = "new ec2.Instance(this, 'Web', { vpc, instanceType, machineImage, associatePublicIpAddress: true });\n"
_TF_VPN = 'resource "aws_vpn_connection" "{n}" {{\n  customer_gateway_id = "cgw"\n}}\n'


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_rel2() -> None:
    assert RULE_BEST_PRACTICES["REPO-131"] == ("REL02-BP01",)
    assert RULE_BEST_PRACTICES["REPO-132"] == ("REL02-BP02",)
    assert {"REL02-BP01", "REL02-BP02"}.isdisjoint(NOT_CHECKED)


@pytest.mark.parametrize(
    "files",
    [{"main.tf": _TF_INSTANCE}, {"t.json": _CFN_INSTANCE}, {"lib/stack.ts": _CDK_INSTANCE}],
    ids=["terraform", "cloudformation", "cdk"],
)
def test_public_instance_without_a_load_balancer_fails(tmp_path: Path, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), "REPO-131")
    assert hit.question == "REL 2"
    assert hit.severity == "Medium" and hit.category == "Reliability"
    assert "public IP" in hit.evidence and hit.evidence.endswith("found none")


@pytest.mark.parametrize(
    "extra",
    [
        {"lb.tf": 'resource "aws_lb" "l" {\n  load_balancer_type = "application"\n}\n'},
        {"lb.json": '{"Resources": {"L": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer"}}}'},
        {"lib/lb.ts": "new elbv2.ApplicationLoadBalancer(this, 'Lb', { vpc });\n"},
        {"ga.tf": 'resource "aws_globalaccelerator_accelerator" "a" {\n  name = "a"\n}\n'},
    ],
    ids=["terraform-alb", "cloudformation-alb", "cdk-alb", "accelerator"],
)
def test_load_balancer_or_accelerator_passes(tmp_path: Path, extra: dict) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": _TF_INSTANCE, **extra}), "REPO-131")


def test_instance_without_a_public_ip_does_not_fire(tmp_path: Path) -> None:
    files = {"main.tf": 'resource "aws_instance" "w" {\n  ami = "ami-1"\n}\n'}
    assert not _found(_scan(tmp_path, files), "REPO-131")


def test_eip_on_a_nat_gateway_does_not_fire(tmp_path: Path) -> None:
    files = {"main.tf": 'resource "aws_eip" "nat" {}\nresource "aws_nat_gateway" "n" {}\n'}
    assert not _found(_scan(tmp_path, files), "REPO-131")


@pytest.mark.parametrize(
    "files",
    [
        {"vpn.tf": _TF_VPN.format(n="a")},
        {"vpn.json": '{"Resources": {"V": {"Type": "AWS::EC2::VPNConnection"}}}'},
        {"lib/vpn.ts": "new ec2.VpnConnection(this, 'Vpn', { vpc, ip: '1.2.3.4' });\n"},
        {"dx.tf": 'resource "aws_dx_private_virtual_interface" "v" {\n  name = "v"\n}\n'},
    ],
    ids=["terraform-vpn", "cloudformation-vpn", "cdk-vpn", "direct-connect"],
)
def test_single_link_fails(tmp_path: Path, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), "REPO-132")
    assert hit.question == "REL 2"
    assert hit.evidence.startswith("Declares one link") and hit.evidence.endswith("found none")


@pytest.mark.parametrize(
    "files",
    [
        {"vpn.tf": _TF_VPN.format(n="a") + _TF_VPN.format(n="b")},
        {"vpn.tf": _TF_VPN.format(n="a"), "vpn2.tf": _TF_VPN.format(n="b")},
        {"vpn.tf": _TF_VPN.format(n="a"),
         "dx.tf": 'resource "aws_dx_connection" "c" {\n  name = "c"\n}\n'},
        {"dx.tf": 'resource "aws_dx_private_virtual_interface" "a" {}\n'
                  'resource "aws_dx_private_virtual_interface" "b" {}\n'},
    ],
    ids=["two-vpn-one-file", "two-vpn-two-files", "vpn-and-direct-connect", "two-vifs"],
)
def test_redundant_links_pass(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-132")


def test_no_on_premises_link_passes(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}), "REPO-132")


def test_links_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "vpn.tf", _TF_VPN.format(n="a"))
    _write(tmp_path / "tests" / "i.tf", _TF_INSTANCE)
    assert not SingleOnPremLink().run(tmp_path)
    assert not PublicEndpointNotHighlyAvailable().run(tmp_path)
