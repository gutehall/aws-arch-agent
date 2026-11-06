"""Monthly cost estimates on cost findings."""
import json
from pathlib import Path

import pytest

from aws_arch_agent import pricing
from aws_arch_agent.models import Finding, RepoContext
from aws_arch_agent.report.html import render_html
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.report.sarif import render_sarif
from aws_arch_agent.report.schema import REPORT_SCHEMA
from aws_arch_agent.rules import estimates
from aws_arch_agent.rules.cf_template import CF_COVERS_STATIC, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

ROOT = Path(__file__).resolve().parents[1]
IDS = {"CF-EBS-002", "CF-EIP-001", "CF-COST-002", "CF-PERF-003", "CF-PERF-004"}


def _p(key: str, region: str = "us-east-1") -> float:
    found = pricing.price(key, region)
    assert found is not None, key
    return found.usd


def _cf(tmp_path: Path, resources: dict) -> dict[tuple[str, str], Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    found = run_cf_rules_from_paths([path], repo_path=tmp_path)
    return {(f.id, f.evidence.split(" ")[0]): f for f in found if f.id in IDS}


def _volume(**props) -> dict:
    return {"Type": "AWS::EC2::Volume", "Properties": {"AvailabilityZone": "us-east-1a", "Encrypted": True, **props}}


def test_gp2_volumes(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Gp2": _volume(VolumeType="gp2", Size=100),
        "Default": _volume(Size="500"),            # unset means gp2
        "Big": _volume(VolumeType="gp2", Size=2000),
        "FromSnapshot": _volume(SnapshotId="snap-1"),
        "Gp3": _volume(VolumeType="gp3", Size=100),
        "Param": _volume(VolumeType={"Ref": "Type"}, Size=100),
    })
    assert {name for fid, name in found if fid == "CF-EBS-002"} == {"Gp2", "Default", "Big", "FromSnapshot"}
    gp2, gp3 = _p("ebs:gp2"), _p("ebs:gp3")
    small = found[("CF-EBS-002", "Gp2")]
    assert small.monthly_cost_usd == round(100 * gp2, 2)
    assert small.monthly_savings_usd == round(100 * gp2 - 100 * gp3, 2)
    assert small.estimate_basis.startswith(f"100 GiB gp2 × ${gp2:.6g}/GB-month, us-east-1, AWS prices of ")
    assert found[("CF-EBS-002", "Default")].recommendation.startswith("VolumeType is not set, so it is gp2.")
    big = found[("CF-EBS-002", "Big")]
    assert big.monthly_cost_usd == round(2000 * gp2, 2) and big.monthly_savings_usd is None
    assert "No saving is estimated" in big.estimate_basis
    unsized = found[("CF-EBS-002", "FromSnapshot")]
    assert unsized.monthly_cost_usd is None and unsized.monthly_savings_usd is None and unsized.estimate_basis is None


def test_nat_gateway_estimate(tmp_path: Path) -> None:
    nat = {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": {"Ref": "S"}}}
    found = _cf(tmp_path, {"A": nat, "B": nat})
    finding = next(f for (fid, _), f in found.items() if fid == "CF-COST-002")
    assert finding.monthly_cost_usd == round(2 * 730 * _p("nat:hour"), 2)
    assert finding.monthly_savings_usd is None  # endpoints save traffic, which is not guessed
    assert finding.estimate_basis.startswith(f"2 NAT gateways × 730 h × ${_p('nat:hour'):.6g}/h, us-east-1")
    assert "Excludes data processing" in finding.estimate_basis


def _rds(**props) -> dict:
    return {"Type": "AWS::RDS::DBInstance", "Properties": {"StorageEncrypted": True, **props}}


def test_oversized_rds_estimate(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Pg": _rds(DBInstanceClass="db.r6g.4xlarge", Engine="postgres", MultiAZ=True),
        "Aurora": _rds(DBInstanceClass="db.r6g.2xlarge", Engine="aurora-postgresql",
                       DBClusterIdentifier={"Ref": "Cluster"}),
        "NoEngine": _rds(DBInstanceClass="db.r6g.4xlarge", Engine={"Ref": "Engine"}),
        "Oracle": _rds(DBInstanceClass="db.r6i.4xlarge", Engine="oracle-ee"),
    })
    pg = found[("CF-PERF-003", "Pg")]
    now = _p("rds:postgres:multi-az:db.r6g.4xlarge")
    smaller = _p("rds:postgres:multi-az:db.r6g.2xlarge")
    assert pg.monthly_cost_usd == round(730 * now, 2)
    assert pg.monthly_savings_usd == round(730 * now - 730 * smaller, 2)
    assert "PostgreSQL Multi-AZ" in pg.estimate_basis and "(db.r6g.2xlarge," in pg.estimate_basis
    aurora = found[("CF-PERF-003", "Aurora")]
    assert aurora.monthly_cost_usd == round(730 * _p("rds:aurora-postgresql:single-az:db.r6g.2xlarge"), 2)
    for name in ("NoEngine", "Oracle"):  # no price to read: the finding has no number
        assert found[("CF-PERF-003", name)].monthly_cost_usd is None


def test_large_ec2_estimate(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Big": {"Type": "AWS::EC2::Instance", "Properties": {
            "InstanceType": "m5.4xlarge", "MetadataOptions": {"HttpTokens": "required"}}},
    })
    big = found[("CF-PERF-004", "Big")]
    assert big.monthly_cost_usd == round(730 * _p("ec2:m5.4xlarge"), 2)
    assert big.monthly_savings_usd == round(730 * _p("ec2:m5.4xlarge") - 730 * _p("ec2:m5.2xlarge"), 2)


def _eip(**props) -> dict:
    return {"Type": "AWS::EC2::EIP", "Properties": {"Domain": "vpc", **props}}


def test_unused_elastic_ips(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Idle": _eip(),
        "ForNat": _eip(),
        "Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {
            "AllocationId": {"Fn::GetAtt": ["ForNat", "AllocationId"]}, "SubnetId": "subnet-1"}},
        "Associated": _eip(),
        "Assoc": {"Type": "AWS::EC2::EIPAssociation", "Properties": {
            "AllocationId": {"Fn::GetAtt": ["Associated", "AllocationId"]}, "InstanceId": "i-1"}},
        "OnInstance": _eip(InstanceId="i-2"),
        "ForNlb": _eip(),
        "Nlb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {
            "Type": "network", "SubnetMappings": [
                {"SubnetId": "subnet-1", "AllocationId": {"Fn::GetAtt": ["ForNlb", "AllocationId"]}}]}},
        "Byoip": _eip(PublicIpv4Pool="ipv4pool-ec2-123"),
    })
    assert {name for fid, name in found if fid == "CF-EIP-001"} == {"Idle"}
    idle = found[("CF-EIP-001", "Idle")]
    cost = round(730 * _p("eip:idle-hour"), 2)
    assert idle.monthly_cost_usd == cost and idle.monthly_savings_usd == cost


def test_template_checks_replace_the_cdk_rules() -> None:
    assert CF_COVERS_STATIC["CF-EBS-002"] == ("COST-008",)
    assert CF_COVERS_STATIC["CF-EIP-001"] == ("COST-012",)


TF = """\
resource "aws_ebs_volume" "gp2" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}

resource "aws_ebs_volume" "gp3" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
  encrypted         = true
}

resource "aws_ebs_volume" "from_var" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = var.type
  encrypted         = true
}

resource "aws_eip" "idle" {
  domain = "vpc"
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = "subnet-1"
}

resource "aws_eip" "nlb" {
  domain = "vpc"
}

resource "aws_lb" "nlb" {
  load_balancer_type = "network"
  subnet_mapping {
    subnet_id     = "subnet-1"
    allocation_id = aws_eip.nlb.id
  }
}

resource "aws_eip" "assoc" {
  domain = "vpc"
}

resource "aws_eip_association" "assoc" {
  allocation_id = aws_eip.assoc.id
  instance_id   = "i-1"
}

resource "aws_db_instance" "big" {
  engine            = "mysql"
  instance_class    = "db.m5.4xlarge"
  storage_encrypted = true
  multi_az          = false
}
"""


def test_terraform_estimates(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    found = {(f.id, f.evidence.split(" ")[0]): f
             for f in run_resource_checks(resources_from_terraform(tmp_path), tmp_path) if f.id in IDS}
    assert {k for k in found if k[0] in ("CF-EBS-002", "CF-EIP-001")} == {
        ("CF-EBS-002", "aws_ebs_volume.gp2"), ("CF-EIP-001", "aws_eip.idle")}
    assert found[("CF-EBS-002", "aws_ebs_volume.gp2")].monthly_cost_usd == round(100 * _p("ebs:gp2"), 2)
    rds = found[("CF-PERF-003", "aws_db_instance.big")]
    assert rds.monthly_cost_usd == round(730 * _p("rds:mysql:single-az:db.m5.4xlarge"), 2)
    nat = next(f for (fid, _), f in found.items() if fid == "CF-COST-002")
    assert nat.monthly_cost_usd == round(730 * _p("nat:hour"), 2)
    fixes = attach_fixes(list(found.values()), "terraform")
    gp2 = next(f for f in fixes if f.id == "CF-EBS-002")
    assert 'type = "gp3"' in (gp2.suggested_code or "")
    assert all("In CDK" not in f.recommendation for f in fixes)


def test_estimates_use_the_scan_region(tmp_path: Path) -> None:
    resources = {"Gp2": _volume(VolumeType="gp2", Size=100)}
    with pricing.use_region("eu-north-1"):
        north = _cf(tmp_path, resources)[("CF-EBS-002", "Gp2")]
    assert north.monthly_cost_usd == round(100 * _p("ebs:gp2", "eu-north-1"), 2)
    assert ", eu-north-1, AWS prices of" in north.estimate_basis
    assert pricing.current_region() == "us-east-1"  # restored
    with pricing.use_region("ap-south-2"):  # not in the snapshot: no number, finding stays
        unknown = _cf(tmp_path, resources)[("CF-EBS-002", "Gp2")]
    assert unknown.monthly_cost_usd is None and unknown.estimate_basis is None


def test_savings_are_never_subtracted_from_cost() -> None:
    est = estimates.gp2_volume(100)
    assert est is not None and est.monthly_savings_usd is not None
    assert est.monthly_cost_usd == round(100 * _p("ebs:gp2"), 2)  # the full current cost


def _finding(**estimate) -> Finding:
    return Finding(id="CF-EBS-002", title="EBS volume uses gp2", severity="Low", category="Cost Optimization",
                   file="t.yaml", evidence="Vol (AWS::EC2::Volume)", recommendation="Use gp3.", **estimate)


ESTIMATE = {"monthly_cost_usd": 10.0, "monthly_savings_usd": 2.0, "estimate_basis": "100 GiB gp2 × $0.1/GB-month"}


def test_reports_show_estimates() -> None:
    ctx = RepoContext(repo_path="/r")
    with_estimate, without = _finding(**ESTIMATE), _finding()
    md = render_markdown(ctx, [with_estimate])
    assert "- Estimated cost: **$10.00/month** (estimate)" in md
    assert "- Estimated saving: **$2.00/month** (estimate)" in md
    assert "- Estimate basis: 100 GiB gp2" in md
    assert "Estimated" not in render_markdown(ctx, [without])

    data = json.loads(render_json(ctx, [with_estimate]))["findings"][0]
    assert data["monthly_cost_usd"] == 10.0 and data["monthly_savings_usd"] == 2.0

    sarif = json.loads(render_sarif(ctx, [with_estimate, without]))["runs"][0]["results"]
    assert sarif[0]["properties"] == {"estimatedMonthlyCostUsd": 10.0, "estimatedMonthlySavingsUsd": 2.0,
                                      "estimateBasis": "100 GiB gp2 × $0.1/GB-month"}
    assert "properties" not in sarif[1]

    html = render_html(ctx, [with_estimate])
    assert "Estimated cost: $10.00/month (estimate)" in html and "**" not in html.split("<main>")[1]


def test_schema_documents_the_estimate_fields() -> None:
    props = REPORT_SCHEMA["properties"]["findings"]["items"]["properties"]
    for key in ("monthly_cost_usd", "monthly_savings_usd", "estimate_basis"):
        assert key in props
    doc = json.loads((ROOT / "docs" / "report-schema.json").read_text(encoding="utf-8"))
    assert doc == REPORT_SCHEMA


@pytest.mark.parametrize("size,expected", [("100", 100), (100, 100), (True, None), ({"Ref": "S"}, None), ("1e3", None)])
def test_literal_sizes(size, expected) -> None:
    assert estimates._literal_int(size) == expected


def test_terraform_eip_references_through_expressions(tmp_path: Path) -> None:
    """References inside count indexes, conditionals and templates still count as use."""
    (tmp_path / "main.tf").write_text("""\
resource "aws_eip" "counted" {
  count  = 2
  domain = "vpc"
}

resource "aws_nat_gateway" "counted" {
  count         = 2
  allocation_id = aws_eip.counted[count.index].id
  subnet_id     = var.subnets[count.index]
}

resource "aws_eip" "maybe" {
  domain = "vpc"
}

resource "aws_eip_association" "maybe" {
  allocation_id = var.attach ? aws_eip.maybe.id : null
  instance_id   = "i-1"
}

resource "aws_eip" "templated" {
  domain = "vpc"
}

resource "aws_ssm_parameter" "ip" {
  name  = "/app/ip"
  type  = "String"
  value = "${var.prefix}-${aws_eip.templated.public_ip}"
}

resource "aws_eip" "idle" {
  domain = "vpc"
}
""", encoding="utf-8")
    found = {f.evidence.split(" ")[0] for f in run_resource_checks(resources_from_terraform(tmp_path), tmp_path)
             if f.id == "CF-EIP-001"}
    assert found == {"aws_eip.idle"}


def test_gp2_throughput_caveat_above_170_gib() -> None:
    small, mid = estimates.gp2_volume(100), estimates.gp2_volume(500)
    assert small is not None and "250 MB/s" not in small.basis
    assert mid is not None and mid.monthly_savings_usd is not None
    assert "gp2 can reach 250 MB/s above 170 GiB" in mid.basis


def test_one_size_smaller_is_the_next_size_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the region lacks the next size down, no saving, rather than one from further down."""
    real = pricing.price

    def without_2xlarge(key: str, region: str = "us-east-1"):
        return None if key == "ec2:m5.2xlarge" and region == "us-east-1" else real(key, region)

    monkeypatch.setattr(estimates, "price", without_2xlarge)
    est = estimates.ec2_instance("m5.4xlarge")
    assert est is not None and est.monthly_cost_usd is not None and est.monthly_savings_usd is None
