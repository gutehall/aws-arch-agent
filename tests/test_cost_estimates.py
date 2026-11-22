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


def test_one_size_smaller_is_the_next_size_the_region_prices(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the scan's region is asked: a size it does not price is skipped (m5 has no 3xlarge)."""
    real = pricing.price
    asked: list[tuple[str, str]] = []

    def without_2xlarge(key: str, region: str = "us-east-1"):
        asked.append((key, region))
        return None if key == "ec2:m5.2xlarge" and region == "us-east-1" else real(key, region)

    monkeypatch.setattr(estimates, "price", without_2xlarge)
    est = estimates.ec2_instance("m5.4xlarge")
    assert est is not None and est.monthly_savings_usd is not None
    assert "one size smaller (m5.xlarge" in est.basis
    assert {region for _, region in asked} == {"us-east-1"}


# --- Live coverage: load balancers, containers, data stores, networking ---------

LIVE = {
    "elb:alb-hour": [0.0225, "Hrs"], "elb:nlb-hour": [0.0225, "Hrs"], "elb:gwlb-hour": [0.0125, "Hrs"],
    "elb:clb-hour": [0.025, "Hrs"], "eks:cluster-hour": [0.10, "Hrs"],
    "fargate:vcpu-hour": [0.04048, "Hrs"], "fargate:gb-hour": [0.004445, "Hrs"],
    "fargate:vcpu-hour-arm": [0.03238, "Hrs"], "fargate:gb-hour-arm": [0.00356, "Hrs"],
    "elasticache:redis:cache.r6g.large": [0.206, "Hrs"], "elasticache:valkey:cache.t4g.micro": [0.0128, "Hrs"],
    "opensearch:r6g.large.search": [0.167, "Hrs"], "opensearch:m6g.large.search": [0.128, "Hrs"],
    "opensearch:storage:gp3": [0.122, "GB-Mo"], "redshift:ra3.xlplus": [1.086, "Hrs"],
    "vpce:hour": [0.01, "Hrs"], "kms:key-month": [1.0, "Keys"], "secrets:secret-month": [0.40, "Secrets"],
    "kinesis:shard-hour": [0.015, "ShardHour"], "kinesis:on-demand-stream-hour": [0.04, "StreamHour"],
    "ec2:m5.large": [0.096, "Hrs"], "ebs:gp3": [0.08, "GB-Mo"], "ebs:io2": [0.125, "GB-Mo"],
    "ebs:gp3-iops": [0.005, "IOPS-Mo"], "ebs:gp3-throughput": [0.04, "MiBps-Mo"], "ebs:io2-iops": [0.065, "IOPS-Mo"],
    "rds:postgres:multi-az:db.m5.large": [0.356, "Hrs"], "rds:postgres:single-az:db.m5.large": [0.178, "Hrs"],
    "rds:storage:gp3": [0.115, "GB-Mo"],
}


@pytest.fixture
def live() -> object:
    with pricing.use_provider(pricing.InMemoryPriceProvider(
            {"us-east-1": LIVE}, {"us-east-1": "2026-11-05"})) as provider:
        yield provider


def _res(rtype: str, props: dict, name: str = "R", count: int = 1, references: frozenset = frozenset()):
    from aws_arch_agent.rules.resource_model import Resource

    return Resource(type=rtype, name=name, properties=props, count=count, references=references)


@pytest.mark.parametrize("rtype, props, usd, words", [
    ("lb", {}, 730 * 0.0225, "Application Load Balancer"),
    ("lb", {"Type": "network"}, 730 * 0.0225, "Network Load Balancer"),
    ("lb", {"Type": "gateway"}, 730 * 0.0125, "Gateway Load Balancer"),
    ("elb", {}, 730 * 0.025, "Classic Load Balancer"),
    ("eks_cluster", {}, 73.0, "EKS cluster control plane"),
    ("elasticache_cluster", {"CacheNodeType": "cache.r6g.large", "Engine": "redis", "NumCacheNodes": 2},
     2 * 730 * 0.206, "2 cache.r6g.large redis node(s)"),
    ("elasticache_replication_group", {"CacheNodeType": "cache.r6g.large", "NumNodeGroups": 2,
                                       "ReplicasPerNodeGroup": 1}, 4 * 730 * 0.206, "4 cache.r6g.large"),
    ("elasticache_replication_group", {"CacheNodeType": "cache.t4g.micro", "Engine": "valkey",
                                       "NumCacheClusters": 3}, 3 * 730 * 0.0128, "valkey"),
    ("redshift_cluster", {"NodeType": "ra3.xlplus", "NumberOfNodes": 2}, 2 * 730 * 1.086, "managed storage"),
    ("redshift_cluster", {"NodeType": "ra3.xlplus", "ClusterType": "single-node"}, 730 * 1.086, "1 ra3.xlplus"),
    ("vpc_endpoint", {"VpcEndpointType": "Interface", "SubnetIds": ["a", "b", "c"]}, 3 * 730 * 0.01, "3 interface"),
    ("vpc_endpoint", {"ServiceName": "com.amazonaws.us-east-1.s3"}, 0.0, "Gateway endpoint"),
    ("kms_key", {}, 1.0, "customer managed KMS key"),
    ("secretsmanager_secret", {}, 0.4, "1 secret"),
    ("kinesis_stream", {"ShardCount": 4}, 4 * 730 * 0.015, "4 shard(s)"),
    ("kinesis_stream", {"StreamModeDetails": {"StreamMode": "ON_DEMAND"}}, 730 * 0.04, "on-demand stream"),
    ("opensearch_domain", {"ClusterConfig": {"InstanceType": "r6g.large.search", "InstanceCount": 2,
                                             "DedicatedMasterEnabled": True, "DedicatedMasterType": "m6g.large.search"},
                           "EBSOptions": {"EBSEnabled": True, "VolumeSize": 100, "VolumeType": "gp3"}},
     2 * 730 * 0.167 + 3 * 730 * 0.128 + 2 * 100 * 0.122, "3 m6g.large.search dedicated master(s)"),
    ("db_instance", {"DBInstanceClass": "db.m5.large", "Engine": "postgres", "MultiAZ": True,
                     "AllocatedStorage": 100, "StorageType": "gp3"}, 730 * 0.356 + 2 * 100 * 0.115, "× 2 (Multi-AZ"),
    ("ebs_volume", {"VolumeType": "gp3", "Size": 100, "Iops": 6000, "Throughput": 250},
     100 * 0.08 + 3000 * 0.005 + 125 * 0.04, "3,000 IOPS above 3,000"),
    ("ebs_volume", {"VolumeType": "io2", "Size": 100, "Iops": 1000}, 100 * 0.125 + 1000 * 0.065, "1,000 provisioned IOPS"),
])
def test_new_service_estimates(live: object, rtype: str, props: dict, usd: float, words: str) -> None:
    est = estimates.resource_cost(_res(rtype, props))
    assert est is not None and est.monthly_cost_usd == round(usd, 2), est
    assert words in est.basis and "us-east-1, AWS prices of 2026-11-05" in est.basis or usd == 0.0


@pytest.mark.parametrize("rtype, props", [
    ("lb", {"Type": {"Ref": "Kind"}}),
    ("elasticache_cluster", {"CacheNodeType": "cache.r6g.large", "NumCacheNodes": {"Ref": "N"}}),
    ("elasticache_cluster", {"CacheNodeType": {"Ref": "T"}}),
    ("elasticache_replication_group", {"CacheNodeType": "cache.r6g.large"}),  # no node count given
    ("redshift_cluster", {"NodeType": "ra3.xlplus", "NumberOfNodes": "${var.n}"}),
    ("vpc_endpoint", {"VpcEndpointType": "Interface", "SubnetIds": {"Ref": "Subnets"}}),
    ("kinesis_stream", {}),  # provisioned with no shard count
    ("opensearch_domain", {"ClusterConfig": {"InstanceType": "r6g.large.search"},
                           "EBSOptions": {"EBSEnabled": True, "VolumeSize": {"Ref": "Size"}}}),
    ("ecs_service", {"LaunchType": "FARGATE", "DesiredCount": 2}),  # no task definition
    ("autoscaling_group", {"DesiredCapacity": 2}),  # no launch template
])
def test_unresolved_properties_are_not_guessed(live: object, rtype: str, props: dict) -> None:
    assert estimates.resource_cost(_res(rtype, props)) is None


def test_fargate_service_resolves_its_task_definition(live: object) -> None:
    task = _res("ecs_task_definition", {"Cpu": "512", "Memory": "1 GB", "RequiresCompatibilities": ["FARGATE"],
                                        "RuntimePlatform": {"CpuArchitecture": "ARM64"}}, name="Task")
    cf = _res("ecs_service", {"DesiredCount": 3, "TaskDefinition": {"Ref": "Task"}})
    est = estimates.resource_cost(cf, {"Task": task})
    assert est is not None and est.monthly_cost_usd == round(3 * 730 * (0.5 * 0.03238 + 1 * 0.00356), 2)
    assert "3 Fargate task(s) (ARM64, 0.5 vCPU" in est.basis
    tf_task = _res("ecs_task_definition", {"Cpu": "1024", "Memory": "2048", "RequiresCompatibilities": ["FARGATE"]},
                   name="aws_ecs_task_definition.app")
    tf = _res("ecs_service", {"LaunchType": "FARGATE", "DesiredCount": 2, "TaskDefinition": object()},
              references=frozenset({"aws_ecs_task_definition.app", "aws_ecs_cluster.main"}))
    est = estimates.resource_cost(tf, {"aws_ecs_task_definition.app": tf_task})
    assert est is not None and est.monthly_cost_usd == round(2 * 730 * (1 * 0.04048 + 2 * 0.004445), 2)
    for ref in ({"Fn::GetAtt": ["Task", "Arn"]}, {"Fn::GetAtt": "Task.Arn"}):
        svc = _res("ecs_service", {"DesiredCount": 1, "TaskDefinition": ref})
        assert estimates.resource_cost(svc, {"Task": task}) is not None
    # EC2 launch type and Fargate Spot are not priced as Fargate.
    assert estimates.resource_cost(_res("ecs_service", {"LaunchType": "EC2", "DesiredCount": 2,
                                                        "TaskDefinition": {"Ref": "Task"}}), {"Task": task}) is None
    spot = _res("ecs_service", {"DesiredCount": 2, "TaskDefinition": {"Ref": "Task"},
                                "CapacityProviderStrategy": [{"CapacityProvider": "FARGATE_SPOT"}]})
    assert estimates.resource_cost(spot, {"Task": task}) is None


def test_autoscaling_group_resolves_its_launch_template(live: object) -> None:
    lt = _res("launch_template", {"LaunchTemplateData": {"InstanceType": "m5.large"}}, name="Lt")
    asg = _res("autoscaling_group", {"MinSize": "2", "MaxSize": "6", "LaunchTemplate": {
        "LaunchTemplateId": {"Ref": "Lt"}, "Version": "1"}})
    est = estimates.resource_cost(asg, {"Lt": lt})
    assert est is not None and est.monthly_cost_usd == round(2 * 730 * 0.096, 2)
    assert est.basis.startswith("2 × (1 m5.large") and "Saving if" not in est.basis
    tf_lt = _res("launch_template", {"InstanceType": "m5.large"}, name="aws_launch_template.web")
    tf = _res("autoscaling_group", {"DesiredCapacity": 3, "LaunchTemplate": {"LaunchTemplateId": object()}},
              references=frozenset({"aws_launch_template.web"}))
    est = estimates.resource_cost(tf, {"aws_launch_template.web": tf_lt})
    assert est is not None and est.monthly_cost_usd == round(3 * 730 * 0.096, 2)
    lc = _res("launch_configuration", {"InstanceType": "m5.large"}, name="Lc")
    assert estimates.resource_cost(_res("autoscaling_group", {"DesiredCapacity": 1, "LaunchConfigurationName": {
        "Ref": "Lc"}}), {"Lc": lc}) is not None
    mixed = _res("autoscaling_group", {"DesiredCapacity": 1, "MixedInstancesPolicy": {"x": 1},
                                       "LaunchTemplate": {"LaunchTemplateId": {"Ref": "Lt"}}})
    assert estimates.resource_cost(mixed, {"Lt": lt}) is None


@pytest.mark.parametrize("count, usd", [(3, 3 * 73.0), (0, 0.0)])
def test_count_multiplies_the_cost(live: object, count: int, usd: float) -> None:
    est = estimates.resource_cost(_res("eks_cluster", {}, count=count))
    assert est is not None and est.monthly_cost_usd == round(usd, 2)
    assert est.basis.startswith(f"count = {count} × (1 EKS cluster")


def test_aurora_instances_have_no_storage_line(live: object) -> None:
    assert estimates.rds_storage({"Engine": "aurora-postgresql", "AllocatedStorage": 100}) is None
    assert estimates.rds_storage({"Engine": "postgres", "AllocatedStorage": {"Ref": "S"}}) is None


@pytest.mark.parametrize("props", [
    {"DesiredCount": 1, "TaskDefinition": {"Ref": "Task"}, "CapacityProviderStrategy": [{"CapacityProvider": {"Ref": "P"}}]},
    {"DesiredCount": 1, "TaskDefinition": {"Ref": "Task"}, "CapacityProviderStrategy": {"Ref": "S"}},
    {"DesiredCount": 1, "TaskDefinition": {"Ref": "Task"}, "LaunchType": {"Ref": "L"}},
])
def test_fargate_values_from_parameters_are_not_guessed(live: object, props: dict) -> None:
    task = _res("ecs_task_definition", {"Cpu": "256", "Memory": "512", "RequiresCompatibilities": ["FARGATE"]})
    assert estimates.resource_cost(_res("ecs_service", props), {"Task": task}) is None


def test_odd_shapes_are_not_priced(live: object) -> None:
    assert estimates.public_ipv4({"Ref": "Pool"}) is None
    lt = _res("launch_template", {"LaunchTemplateData": {"Ref": "Data"}}, name="Lt")
    asg = _res("autoscaling_group", {"DesiredCapacity": 1, "LaunchTemplate": {"LaunchTemplateId": {"Ref": "Lt"}}})
    assert estimates.resource_cost(asg, {"Lt": lt}) is None
    big = estimates.resource_cost(_res("ebs_volume", {"VolumeType": "io2", "Size": 100, "Iops": 40000}))
    assert big is not None and "io2 IOPS above 32,000 cost less" in big.basis
