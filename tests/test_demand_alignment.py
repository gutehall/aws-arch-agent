"""SUS 2: aligning resources to demand. SLAs (REPO-098), unused assets (REPO-099),
geographic placement (REPO-100), team resources (REPO-101), and a flattened demand curve
(REPO-102)."""
import json
from pathlib import Path

import pytest
from test_demand_management import API, FN, LIMITS, QUEUE, SNS_LAMBDA, SOURCES, _stack, _write

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    DemandUnbuffered,
    GeographicPlacementMismatch,
    SlaIgnoresSustainability,
    TeamResourcesUnsized,
    UnusedAssets,
    DemandCurveNotFlattened,
)

RULES = (SlaIgnoresSustainability(), UnusedAssets(), GeographicPlacementMismatch(),
         TeamResourcesUnsized(), DemandCurveNotFlattened())


# REPO-098: SLAs and sustainability.

@pytest.mark.parametrize("source", SOURCES)
def test_workload_with_no_sla_note_fires_repo_098(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FN[source])
    (hit,) = SlaIgnoresSustainability().run(tmp_path)
    assert "Lambda" in hit.evidence and "found none" in hit.evidence


@pytest.mark.parametrize("path,text", (
    ("docs/sla.md", "99.9% availability; idle capacity off-hours is scaled to zero."),
    ("docs/slo.md", "Target 99.5%. A lower target saves energy, so we right-size."),
    ("docs/notes.md", "## Service level\n\nWe accept 99.5% to cut carbon from idle fleets.\n"),
    ("docs/reliability-targets.md", "Availability target 99.9% with scale-to-zero at night."),
    ("docs/notes.md", "# Availability target\n\nThe target limits utilization waste.\n"),
))
def test_sla_note_with_a_sustainability_tradeoff_passes_repo_098(
    tmp_path: Path, path: str, text: str
) -> None:
    _stack(tmp_path, "terraform", FN["terraform"])
    _write(tmp_path / path, text)
    assert SlaIgnoresSustainability().run(tmp_path) == []


def test_sla_note_without_a_sustainability_word_fires_repo_098(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FN["terraform"])
    _write(tmp_path / "docs/sla.md", "Our SLA is 99.9% availability.")
    assert len(SlaIgnoresSustainability().run(tmp_path)) == 1
    _write(tmp_path / "docs/other.md", "# Setup\n\nWe care about carbon and energy.")
    assert len(SlaIgnoresSustainability().run(tmp_path)) == 1


def test_no_workload_is_silent_repo_098(tmp_path: Path) -> None:
    _write(tmp_path / "prod/main.tf", 'variable "x" {}\n')
    assert SlaIgnoresSustainability().run(tmp_path) == []


# REPO-099: unused assets.

VOLUME = {
    "cdk": "const vol = new ec2.Volume(this, 'Vol', { availabilityZone: 'a' });\n",
    "cloudformation": {"Vol": {"Type": "AWS::EC2::Volume", "Properties": {}}},
    "terraform": 'resource "aws_ebs_volume" "data" {\n  size = 10\n}\n',
}
VOLUME_ATTACHED = {
    "cdk": "const vol = new ec2.Volume(this, 'Vol', { availabilityZone: 'a' });\n"
           "vol.grantAttachVolume(role);\n",
    "cloudformation": {
        "Vol": VOLUME["cloudformation"]["Vol"],
        "Att": {"Type": "AWS::EC2::VolumeAttachment", "Properties": {
            "VolumeId": {"Ref": "Vol"}, "InstanceId": "i-1", "Device": "/dev/sdf"}}},
    "terraform": VOLUME["terraform"]
    + 'resource "aws_volume_attachment" "a" {\n  volume_id = aws_ebs_volume.data.id\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_unattached_volume_fires_repo_099(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, VOLUME[source])
    (hit,) = UnusedAssets().run(tmp_path)
    assert "EBS volume" in hit.evidence and "prod/" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_attached_volume_passes_repo_099(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, VOLUME_ATTACHED[source])
    assert UnusedAssets().run(tmp_path) == []


OTHERS = {
    "load balancer": {
        "cloudformation": {"Lb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                                  "Properties": {}}},
        "terraform": 'resource "aws_lb" "front" {}\n',
        "cdk": "const alb = new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });\n"},
    "target group": {
        "cloudformation": {"Tg": {"Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                                  "Properties": {}}},
        "terraform": 'resource "aws_lb_target_group" "tg" {}\n',
        "cdk": "const tg = new elbv2.ApplicationTargetGroup(this, 'Tg', { vpc });\n"},
    "NAT gateway": {
        "cloudformation": {"Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {}}},
        "terraform": 'resource "aws_nat_gateway" "nat" {}\n',
        "cdk": "const nat = new ec2.CfnNatGateway(this, 'Nat', { subnetId });\n"},
    "network interface": {
        "cloudformation": {"Eni": {"Type": "AWS::EC2::NetworkInterface", "Properties": {}}},
        "terraform": 'resource "aws_network_interface" "eni" {}\n',
        "cdk": "const eni = new ec2.CfnNetworkInterface(this, 'Eni', { subnetId });\n"},
}
REFERENCES = {
    "load balancer": {"cloudformation": ("Lb", "Listener"), "terraform": ("aws_lb.front", ""),
                      "cdk": ("alb", "alb.addListener('L', { port: 80 });\n")},
    "target group": {"cloudformation": ("Tg", "Listener"), "terraform": ("aws_lb_target_group.tg", ""),
                     "cdk": ("tg", "listener.addTargetGroups('T', { targetGroups: [tg] });\n")},
    "NAT gateway": {"cloudformation": ("Nat", "Route"), "terraform": ("aws_nat_gateway.nat", ""),
                    "cdk": ("nat", "route.addDependency(nat);\n")},
    "network interface": {"cloudformation": ("Eni", "Attach"),
                          "terraform": ("aws_network_interface.eni", ""),
                          "cdk": ("eni", "inst.addDependency(eni);\n")},
}


def _referenced(kind: str, source: str):
    target, extra = REFERENCES[kind][source]
    if source == "cloudformation":
        return {extra: {"Type": "AWS::EC2::Route", "Properties": {"X": {"Ref": target}}}}
    if source == "terraform":
        return f'resource "aws_x" "x" {{\n  ref = {target}.id\n}}\n'
    return extra


@pytest.mark.parametrize("kind", OTHERS)
@pytest.mark.parametrize("source", SOURCES)
def test_unreferenced_asset_fires_repo_099(tmp_path: Path, source: str, kind: str) -> None:
    _stack(tmp_path, source, OTHERS[kind][source])
    (hit,) = UnusedAssets().run(tmp_path)
    assert kind in hit.evidence


@pytest.mark.parametrize("kind", OTHERS)
@pytest.mark.parametrize("source", SOURCES)
def test_referenced_asset_passes_repo_099(tmp_path: Path, source: str, kind: str) -> None:
    refs = _referenced(kind, source)
    if source == "cloudformation":
        _stack(tmp_path, source, OTHERS[kind][source], refs)
    else:
        _stack(tmp_path, source, OTHERS[kind][source], refs)
    assert UnusedAssets().run(tmp_path) == []


def test_reference_in_another_file_counts_repo_099(tmp_path: Path) -> None:
    _write(tmp_path / "prod/a.tf", VOLUME["terraform"])
    assert len(UnusedAssets().run(tmp_path)) == 1
    _write(tmp_path / "prod/b.tf", VOLUME_ATTACHED["terraform"].split("}\n", 1)[1])
    assert UnusedAssets().run(tmp_path) == []


def test_elastic_ips_stay_with_cost_012_repo_099(tmp_path: Path) -> None:
    _write(tmp_path / "prod/main.tf", 'resource "aws_eip" "ip" {}\n')
    _write(tmp_path / "prod/t.json", json.dumps(
        {"Resources": {"Ip": {"Type": "AWS::EC2::EIP", "Properties": {}}}}))
    _write(tmp_path / "prod/stack.ts", "new ec2.CfnEIP(this, 'Ip');\n")
    assert UnusedAssets().run(tmp_path) == []


def test_bare_construct_fires_and_argument_passes_repo_099(tmp_path: Path) -> None:
    _write(tmp_path / "prod/a.ts", "new ec2.Volume(this, 'Vol', { availabilityZone: 'a' });\n")
    assert len(UnusedAssets().run(tmp_path)) == 1
    _write(tmp_path / "prod/a.ts", "attach(new ec2.Volume(this, 'Vol', {}));\n")
    assert UnusedAssets().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_099(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", VOLUME["terraform"], env=env)
    assert UnusedAssets().run(tmp_path) == []


def test_python_cdk_repo_099(tmp_path: Path) -> None:
    code = "vol = ec2.Volume(self, 'Vol', availability_zone='a')\n"
    _write(tmp_path / "app.py", code)
    assert len(UnusedAssets().run(tmp_path)) == 1
    _write(tmp_path / "app.py", code + "vol.grant_attach_volume(role)\n")
    assert UnusedAssets().run(tmp_path) == []
    _write(tmp_path / "app.py", 'SNIPPET = "vol = ec2.Volume(self, \'Vol\')"\n')
    assert UnusedAssets().run(tmp_path) == []


# REPO-100: geographic placement.

def _cdn(source: str, price_class: str, region: str) -> list:
    pc = price_class.upper()
    if source == "cdk":
        return [f"new cloudfront.Distribution(this, 'Cdn', {{ priceClass: "
                f"cloudfront.PriceClass.PRICE_CLASS_{pc}, defaultBehavior }});\n"
                f"new Stack(app, 'S', {{ env: {{ region: '{region}' }} }});\n"]
    if source == "cloudformation":
        return [{"Cdn": {"Type": "AWS::CloudFront::Distribution", "Properties": {
            "DistributionConfig": {"PriceClass": f"PriceClass_{price_class}", "Origins": [
                {"DomainName": f"bucket.s3.{region}.amazonaws.com"}]}}}}]
    return [f'resource "aws_cloudfront_distribution" "cdn" {{\n  price_class = '
            f'"PriceClass_{price_class}"\n}}\nprovider "aws" {{\n  region = "{region}"\n}}\n']


@pytest.mark.parametrize("price_class,region", (
    ("100", "ap-southeast-2"), ("100", "sa-east-1"), ("100", "ap-northeast-1"),
    ("100", "me-south-1"), ("100", "af-south-1"), ("200", "sa-east-1"),
    ("200", "ap-southeast-2"), ("200", "ap-southeast-4"),
))
@pytest.mark.parametrize("source", SOURCES)
def test_price_class_outside_region_fires_repo_100(
    tmp_path: Path, source: str, price_class: str, region: str
) -> None:
    _stack(tmp_path, source, *_cdn(source, price_class, region))
    (hit,) = GeographicPlacementMismatch().run(tmp_path)
    assert region in hit.evidence and f"PriceClass_{price_class}" in hit.evidence


@pytest.mark.parametrize("price_class,region", (
    ("100", "us-east-1"), ("100", "eu-west-1"), ("100", "ca-central-1"), ("100", "il-central-1"),
    ("200", "ap-northeast-1"), ("200", "me-south-1"), ("200", "af-south-1"),
    ("200", "eu-central-1"), ("All", "sa-east-1"), ("All", "ap-southeast-2"),
))
@pytest.mark.parametrize("source", SOURCES)
def test_price_class_covering_region_passes_repo_100(
    tmp_path: Path, source: str, price_class: str, region: str
) -> None:
    _stack(tmp_path, source, *_cdn(source, price_class, region))
    assert GeographicPlacementMismatch().run(tmp_path) == []


def test_alb_and_api_domains_are_regions_repo_100(tmp_path: Path) -> None:
    for domain in ("x.ap-southeast-2.elb.amazonaws.com",
                   "x.execute-api.sa-east-1.amazonaws.com"):
        cf = {"Cdn": {"Type": "AWS::CloudFront::Distribution", "Properties": {
            "DistributionConfig": {"PriceClass": "PriceClass_100",
                                   "Origins": [{"DomainName": domain}]}}}}
        _stack(tmp_path, "cloudformation", cf)
        assert len(GeographicPlacementMismatch().run(tmp_path)) == 1


def test_no_region_or_no_cloudfront_is_silent_repo_100(tmp_path: Path) -> None:
    _write(tmp_path / "prod/a.ts", "new cloudfront.Distribution(this, 'C', "
           "{ priceClass: cloudfront.PriceClass.PRICE_CLASS_100 });\n")
    assert GeographicPlacementMismatch().run(tmp_path) == []
    _write(tmp_path / "prod/a.ts", "new Stack(app, 'S', { env: { region: 'sa-east-1' } });\n")
    assert GeographicPlacementMismatch().run(tmp_path) == []


def test_aliased_provider_is_not_the_stack_region_repo_100(tmp_path: Path) -> None:
    _write(tmp_path / "prod/main.tf",
           'resource "aws_cloudfront_distribution" "c" {\n  price_class = "PriceClass_100"\n}\n'
           'provider "aws" {\n  alias  = "dr"\n  region = "ap-southeast-2"\n}\n')
    assert GeographicPlacementMismatch().run(tmp_path) == []


@pytest.mark.parametrize("comment", (
    "// users are in Sydney, so we pay for the wider edge",
    "// latency to our audience",
))
def test_comment_explains_placement_repo_100(tmp_path: Path, comment: str) -> None:
    code = _cdn("cdk", "100", "ap-southeast-2")[0]
    head, tail = code.split("new Stack", 1)
    _write(tmp_path / "prod/stack.ts", head + comment + "\nnew Stack" + tail)
    assert GeographicPlacementMismatch().run(tmp_path) == []
    _write(tmp_path / "prod/stack.ts", code)
    assert len(GeographicPlacementMismatch().run(tmp_path)) == 1


@pytest.mark.parametrize("path,text", (
    ("docs/placement.md", "Origin in Sydney because our users are in Australia."),
    ("docs/notes.md", "## Edge\n\nPriceClass_100 on purpose: latency is fine for our audience."),
    ("docs/region.md", "Sydney only: data residency."),
))
def test_placement_note_passes_repo_100(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "cdk", *_cdn("cdk", "100", "ap-southeast-2"))
    _write(tmp_path / path, text)
    assert GeographicPlacementMismatch().run(tmp_path) == []


def test_python_cdk_and_strings_repo_100(tmp_path: Path) -> None:
    code = ("cloudfront.Distribution(self, 'C', "
            "price_class=cloudfront.PriceClass.PRICE_CLASS_100, default_behavior=b)\n"
            "Stack(app, 'S', env=Environment(region='ap-southeast-2'))\n")
    _write(tmp_path / "app.py", code)
    assert len(GeographicPlacementMismatch().run(tmp_path)) == 1
    quoted = "\n".join(f'    "{line}"' for line in code.splitlines())
    _write(tmp_path / "app.py", f"SNIPPETS = (\n{quoted}\n)\n")
    assert GeographicPlacementMismatch().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_100(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "cdk", *_cdn("cdk", "100", "ap-southeast-2"), env=env)
    assert GeographicPlacementMismatch().run(tmp_path) == []


# REPO-101: team resources.

@pytest.mark.parametrize("source", SOURCES)
def test_workload_with_no_team_note_fires_repo_101(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FN[source])
    (hit,) = TeamResourcesUnsized().run(tmp_path)
    assert "Lambda" in hit.evidence and "found none" in hit.evidence


@pytest.mark.parametrize("path,text", (
    ("docs/dev-environments.md", "Dev boxes auto-stop after 30 minutes idle."),
    ("docs/ci-runners.md", "Runners are on-demand and scale down to zero."),
    ("docs/workstations.md", "Right-sized by role; hibernate overnight."),
    ("docs/notes.md", "## Build agents\n\nSpot instances, shut down after each job.\n"),
    ("docs/notes.md", "# Developer environment\n\nStopped on a schedule, nights and weekends.\n"),
    ("docs/team-resources.md", "Everyone uses a right-sizing guide."),
))
def test_team_note_passes_repo_101(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", FN["terraform"])
    _write(tmp_path / path, text)
    assert TeamResourcesUnsized().run(tmp_path) == []


def test_team_note_without_sizing_words_fires_repo_101(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FN["terraform"])
    _write(tmp_path / "docs/dev-environments.md", "Developers have laptops.")
    assert len(TeamResourcesUnsized().run(tmp_path)) == 1
    _write(tmp_path / "docs/other.md", "# Setup\n\nAuto-stop, idle, schedule.")
    assert len(TeamResourcesUnsized().run(tmp_path)) == 1


def test_no_workload_is_silent_repo_101(tmp_path: Path) -> None:
    _write(tmp_path / "prod/main.tf", 'variable "x" {}\n')
    assert TeamResourcesUnsized().run(tmp_path) == []


def test_python_cdk_strings_do_not_count_repo_098_and_101(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "_lambda.Function(self, 'Fn', runtime=r, handler='h', code=c)\n")
    assert len(TeamResourcesUnsized().run(tmp_path)) == 1
    assert len(SlaIgnoresSustainability().run(tmp_path)) == 1
    _write(tmp_path / "app.py", "TEXT = \"_lambda.Function(self, 'Fn', runtime=r)\"\n")
    assert TeamResourcesUnsized().run(tmp_path) == []
    assert SlaIgnoresSustainability().run(tmp_path) == []


# REPO-102: demand curve. Same cases as REPO-097.

@pytest.mark.parametrize("source", SOURCES)
def test_bare_api_fires_repo_102(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, API[source])
    (hit,) = DemandCurveNotFlattened().run(tmp_path)
    assert "API Gateway API in prod/" in hit.evidence and "idle capacity" in hit.evidence


@pytest.mark.parametrize("limit", LIMITS)
@pytest.mark.parametrize("source", SOURCES)
def test_throttled_api_passes_repo_102(tmp_path: Path, source: str, limit: str) -> None:
    _stack(tmp_path, source, LIMITS[limit][source])
    assert DemandCurveNotFlattened().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_sns_to_lambda_repo_102(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SNS_LAMBDA[source])
    (hit,) = DemandCurveNotFlattened().run(tmp_path)
    assert "SNS subscription to Lambda in prod/" in hit.evidence
    _stack(tmp_path, source, SNS_LAMBDA[source], QUEUE[source])
    assert DemandCurveNotFlattened().run(tmp_path) == []


def test_no_edge_and_no_worker_is_silent_repo_102(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FN["terraform"])
    assert DemandCurveNotFlattened().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_102(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", API["terraform"], env=env)
    assert DemandCurveNotFlattened().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_repo_097_is_unchanged_repo_102(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, API[source])
    assert len(DemandUnbuffered().run(tmp_path)) == 1
    assert len(DemandCurveNotFlattened().run(tmp_path)) == 1
    (hit,) = DemandUnbuffered().run(tmp_path)
    assert hit.category == "Cost" and "absorb or limit it" in hit.evidence


# All five.

def test_every_rule_is_silent_on_this_repo() -> None:
    root = Path(__file__).resolve().parent.parent
    for rule in RULES:
        assert rule.run(root) == [], rule.id


def _firing(rule_id: str, root: Path) -> None:
    if rule_id in ("REPO-098", "REPO-101"):
        _stack(root, "terraform", FN["terraform"])
    elif rule_id == "REPO-099":
        _stack(root, "terraform", VOLUME["terraform"])
    elif rule_id == "REPO-100":
        _stack(root, "cloudformation", *_cdn("cloudformation", "100", "sa-east-1"))
    else:
        _stack(root, "terraform", API["terraform"])


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _firing(rule.id, tmp_path)
    (hit,) = rule.run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", text)
    assert len(rule.run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", text)
    assert rule.run(empty) == []


@pytest.mark.parametrize("rule_id,practice", (
    ("REPO-098", "SUS02-BP02"), ("REPO-099", "SUS02-BP03"), ("REPO-100", "SUS02-BP04"),
    ("REPO-101", "SUS02-BP05"), ("REPO-102", "SUS02-BP06"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "SUS 2"


def test_rules_run_by_default() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == set()
    assert {r.category for r in RULES} == {"Sustainability"}
    assert {r.severity for r in RULES} == {"Low"}
    assert {t for r in RULES for t in r.themes} == {"sustainability", "finops"}


def test_sus2_is_fully_checked() -> None:
    (sus2,) = [a for a in well_architected.answers([]) if a.question.id == "SUS 2"]
    assert sus2.not_checked == ()


def test_sus2_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _firing("REPO-099", tmp_path)
    findings = UnusedAssets().run(tmp_path)
    (sus2,) = [a for a in well_architected.answers(findings) if a.question.id == "SUS 2"]
    assert not sus2.met
