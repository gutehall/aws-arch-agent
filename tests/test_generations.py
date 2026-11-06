"""CF-GEN-001: previous-generation instance families (DM3-547)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent import pricing
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import CF_COVERS_STATIC, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.generations import DATA_PATH, successors
from aws_arch_agent.rules.terraform_model import resources_from_terraform

H = 730
ID = "CF-GEN-001"


def _p(key: str) -> float:
    found = pricing.price(key, "us-east-1")
    assert found is not None, key
    return found.usd


def _cf(tmp_path: Path, resources: dict) -> dict[str, Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return {f.evidence.split(" ")[0]: f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == ID}


def _ec2(t: str) -> dict:
    return {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": t, "MetadataOptions": {"HttpTokens": "required"}}}


def _db(cls: str) -> dict:
    return {"Type": "AWS::RDS::DBInstance", "Properties": {
        "DBInstanceClass": cls, "Engine": "postgres", "StorageEncrypted": True}}


def test_t2_micro_and_db_m4_large_get_one_finding_each(tmp_path: Path) -> None:
    """Done when: each gives one finding with a suggested type; a current type gives none."""
    found = _cf(tmp_path, {
        "Old": _ec2("t2.micro"), "OldDb": _db("db.m4.large"),
        "New": _ec2("m7i.large"), "NewDb": _db("db.m6i.large"), "Graviton": _ec2("t4g.micro"),
    })
    assert set(found) == {"Old", "OldDb"}
    old = found["Old"]
    assert old.recommendation.startswith("t2.micro is a previous-generation type: move to t3.micro (x86) or "
                                         "t4g.micro (Graviton).")
    assert "needs an arm64 build of the workload" in old.recommendation
    assert old.monthly_cost_usd == round(H * _p("ec2:t2.micro"), 2)
    assert old.monthly_savings_usd == round(H * _p("ec2:t2.micro") - H * _p("ec2:t3.micro"), 2)
    assert "t4g.micro:" in (old.estimate_basis or "")
    db = found["OldDb"]
    assert "db.m6i.large (x86) or db.m7g.large (Graviton)" in db.recommendation
    assert db.monthly_savings_usd == round(
        H * _p("rds:postgres:single-az:db.m4.large") - H * _p("rds:postgres:single-az:db.m6i.large"), 2)


def test_every_resource_kind(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
            "InstanceType": "c4.xlarge", "MetadataOptions": {"HttpTokens": "required"}}}},
        "Lc": {"Type": "AWS::AutoScaling::LaunchConfiguration", "Properties": {
            "InstanceType": "m3.medium", "ImageId": "ami-1"}},
        "Asg": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
            "MaxSize": "2", "MinSize": "1", "MixedInstancesPolicy": {
                "LaunchTemplate": {"Overrides": [{"InstanceType": "r4.large"}, {"InstanceType": "r7g.large"}]},
                "InstancesDistribution": {"SpotAllocationStrategy": "price-capacity-optimized"}}}},
        "Cache": {"Type": "AWS::ElastiCache::ReplicationGroup", "Properties": {
            "ReplicationGroupDescription": "c", "CacheNodeType": "cache.t2.small",
            "AtRestEncryptionEnabled": True, "TransitEncryptionEnabled": True}},
        "Search": {"Type": "AWS::OpenSearchService::Domain", "Properties": {
            "ClusterConfig": {"InstanceType": "m4.large.search", "DedicatedMasterType": "r4.large.search"},
            "EncryptionAtRestOptions": {"Enabled": True}, "NodeToNodeEncryptionOptions": {"Enabled": True}}},
        "Param": _ec2("t2.micro") | {"Properties": {"InstanceType": {"Ref": "Type"}}},
    })
    assert set(found) == {"Lt", "Lc", "Asg", "Cache", "Search"}
    assert found["Asg"].recommendation.startswith("r4.large is a previous-generation type")
    assert "r7g.large is" not in found["Asg"].recommendation
    assert "m5.large.search (x86) or m7g.large.search (Graviton)" in found["Search"].recommendation
    assert "r5.large.search" in found["Search"].recommendation
    assert found["Search"].monthly_cost_usd is None  # two types, and OpenSearch is not priced
    assert found["Cache"].monthly_cost_usd is None   # ElastiCache is not in the price snapshot
    assert "If the size does not exist in the new family" in found["Lc"].recommendation


@pytest.mark.parametrize("kind,current,expected", [
    ("ec2", "m4.16xlarge", ("m7i.16xlarge", "m7g.16xlarge")),
    ("ec2", "d2.xlarge", ("d3.xlarge", None)),
    ("ec2", "m5.large", None),
    ("ec2", "m4", None),
    ("rds", "db.r4.2xlarge", ("db.r6i.2xlarge", "db.r7g.2xlarge")),
    ("rds", "db.r6g.large", None),
    ("elasticache", "cache.m4.large", ("cache.m5.large", "cache.m7g.large")),
    ("opensearch", "t2.small.search", ("t3.small.search", None)),
])
def test_successors(kind, current, expected) -> None:
    assert successors(kind, current) == expected


def test_mapping_lives_in_one_data_file() -> None:
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    assert set(data) - {"_comment"} == {"ec2", "rds", "elasticache", "opensearch"}


TF = """\
resource "aws_instance" "old" {
  instance_type = "t2.micro"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_db_instance" "old" {
  engine            = "mysql"
  instance_class    = "db.t2.micro"
  storage_encrypted = true
}

resource "aws_launch_template" "lt" {
  instance_type = "m4.large"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_launch_template" "from_var" {
  instance_type = var.type
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_elasticache_cluster" "c" {
  cluster_id = "c"
  node_type  = "cache.m4.large"
}

resource "aws_opensearch_domain" "s" {
  domain_name = "s"
  cluster_config {
    instance_type = "r4.large.search"
  }
}

resource "aws_autoscaling_group" "asg" {
  max_size = 2
  min_size = 1
  mixed_instances_policy {
    launch_template {
      override {
        instance_type = "c4.large"
      }
    }
  }
}

resource "aws_instance" "current" {
  instance_type = "m7g.large"
  metadata_options {
    http_tokens = "required"
  }
}
"""


def test_terraform(tmp_path: Path) -> None:
    module = tmp_path / "infra"
    module.mkdir()
    (module / "main.tf").write_text(TF, encoding="utf-8")
    findings = [f for f in run_resource_checks(resources_from_terraform(module), module) if f.id == ID]
    found = {f.evidence.split(" ")[0]: f for f in findings}
    assert set(found) == {"aws_instance.old", "aws_db_instance.old", "aws_launch_template.lt",
                          "aws_elasticache_cluster.c", "aws_opensearch_domain.s", "aws_autoscaling_group.asg"}
    db = found["aws_db_instance.old"]
    # db.t2.micro and db.t3.micro cost the same: a cost, and no saving rather than $0.
    assert _p("rds:mysql:single-az:db.t2.micro") == _p("rds:mysql:single-az:db.t3.micro")
    assert db.monthly_cost_usd == round(H * _p("rds:mysql:single-az:db.t2.micro"), 2)
    assert db.monthly_savings_usd is None
    # The launch template's other checks are unaffected by its instance type.
    fixes = attach_fixes(findings, "terraform")
    assert 'instance_class = "db.m6i.large"' in next(f.suggested_code for f in fixes if f.id == ID
                                                     and f.evidence.startswith("aws_db_instance"))


def test_replaces_the_cdk_source_rule() -> None:
    assert CF_COVERS_STATIC[ID] == ("SUST-007",)
