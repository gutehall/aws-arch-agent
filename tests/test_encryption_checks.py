"""CF-SNS-001, CF-EBS-001, CF-EFS-001, CF-KIN-001, CF-EC-001/002: encryption in templates."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import (
    drop_static_covered_by_cf,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import load_plan_values, resources_from_terraform

IDS = {"CF-SNS-001", "CF-EBS-001", "CF-EFS-001", "CF-KIN-001", "CF-EC-001", "CF-EC-002"}


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings if f.id in IDS}


# --- CloudFormation -----------------------------------------------------------------


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _r(rtype: str, **props) -> dict:
    return {"Type": rtype, "Properties": props}


CF_RESOURCES = {
    # SNS
    "TopicPlain": _r("AWS::SNS::Topic"),
    "TopicKms": _r("AWS::SNS::Topic", KmsMasterKeyId="alias/aws/sns"),
    "TopicRef": _r("AWS::SNS::Topic", KmsMasterKeyId={"Ref": "Key"}),
    # EBS volume
    "VolPlain": _r("AWS::EC2::Volume", Size=10),
    "VolFalse": _r("AWS::EC2::Volume", Encrypted="false"),
    "VolOk": _r("AWS::EC2::Volume", Encrypted=True),
    "VolSnapshot": _r("AWS::EC2::Volume", SnapshotId="snap-1"),  # takes the snapshot's setting
    "VolParam": _r("AWS::EC2::Volume", Encrypted={"Ref": "Enc"}),
    # Launch template block devices
    "LtPlain": _r("AWS::EC2::LaunchTemplate", LaunchTemplateData={"BlockDeviceMappings": [
        {"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 20}},
        {"DeviceName": "/dev/xvdb", "Ebs": {"Encrypted": True}},
    ]}),
    "LtOk": _r("AWS::EC2::LaunchTemplate", LaunchTemplateData={"BlockDeviceMappings": [
        {"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": "true"}},
        {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"},
    ]}),
    "LtNoDevices": _r("AWS::EC2::LaunchTemplate", LaunchTemplateData={"InstanceType": "t3.micro"}),
    # EFS
    "EfsPlain": _r("AWS::EFS::FileSystem"),
    "EfsOk": _r("AWS::EFS::FileSystem", Encrypted=True),
    # Kinesis
    "StreamPlain": _r("AWS::Kinesis::Stream", ShardCount=1),
    "StreamOk": _r("AWS::Kinesis::Stream", StreamEncryption={
        "EncryptionType": "KMS", "KeyId": "alias/aws/kinesis"}),
    # ElastiCache
    "RedisPlain": _r("AWS::ElastiCache::ReplicationGroup", Engine="redis"),
    "RedisOk": _r("AWS::ElastiCache::ReplicationGroup",
                  AtRestEncryptionEnabled=True, TransitEncryptionEnabled=True),
    "ValkeyDefault": _r("AWS::ElastiCache::ReplicationGroup",
                        Engine="valkey", TransitEncryptionEnabled=True),
    "ValkeyOff": _r("AWS::ElastiCache::ReplicationGroup", Engine="valkey",
                    AtRestEncryptionEnabled=False, TransitEncryptionEnabled=True),
    "EngineParam": _r("AWS::ElastiCache::ReplicationGroup", Engine={"Ref": "Engine"},
                      TransitEncryptionEnabled=True),
}


def test_cloudformation_encryption(tmp_path: Path) -> None:
    findings = _cf(tmp_path, CF_RESOURCES)
    assert _found(findings) == {
        ("TopicPlain", "CF-SNS-001"),
        ("VolPlain", "CF-EBS-001"),
        ("VolFalse", "CF-EBS-001"),
        ("LtPlain", "CF-EBS-001"),
        ("EfsPlain", "CF-EFS-001"),
        ("StreamPlain", "CF-KIN-001"),
        ("RedisPlain", "CF-EC-001"),
        ("RedisPlain", "CF-EC-002"),
        ("ValkeyOff", "CF-EC-001"),
    }
    severity = {f.id: f.severity for f in findings}
    assert severity["CF-SNS-001"] == "Low"  # SNS keeps its own disk encryption
    assert {severity[i] for i in IDS - {"CF-SNS-001"}} == {"Medium"}
    lt = next(f for f in findings if f.evidence.startswith("LtPlain"))
    assert lt.recommendation.startswith("Unencrypted: /dev/xvda.")


def test_cloudformation_fixes(tmp_path: Path) -> None:
    findings = attach_fixes(_cf(tmp_path, CF_RESOURCES), "cloudformation")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert "KmsMasterKeyId: alias/aws/sns" in code[("TopicPlain", "CF-SNS-001")]
    assert "BlockDeviceMappings:" in code[("LtPlain", "CF-EBS-001")]
    assert "Type: AWS::EC2::Volume" in code[("VolPlain", "CF-EBS-001")]
    assert "TransitEncryptionEnabled: true" in code[("RedisPlain", "CF-EC-002")]


def test_static_rules_are_dropped_when_cf_reports_them() -> None:
    static = [Finding(id=i, title="t", recommendation="r")
              for i in ("SEC-014", "SEC-025", "SEC-037", "SEC-038")]
    cf = [Finding(id=i, title="t", recommendation="r")
          for i in ("CF-SNS-001", "CF-EC-002", "CF-EFS-001", "CF-KIN-001")]
    assert [f.id for f in drop_static_covered_by_cf(static + cf)] == [f.id for f in cf]


# --- Terraform ------------------------------------------------------------------

ENCRYPTION_TF = """\
resource "aws_sns_topic" "plain" {}

resource "aws_sns_topic" "kms" {
  kms_master_key_id = aws_kms_key.k.id
}

resource "aws_ebs_volume" "plain" {
  availability_zone = "eu-north-1a"
  size              = 10
}

resource "aws_ebs_volume" "encrypted" {
  availability_zone = "eu-north-1a"
  encrypted         = true
}

resource "aws_ebs_volume" "from_var" {
  availability_zone = "eu-north-1a"
  encrypted         = var.encrypted
}

resource "aws_launch_template" "plain" {
  instance_market_options {
    market_type = "spot"
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
    }
  }
}

resource "aws_launch_template" "encrypted" {
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted = true
    }
  }
}

resource "aws_launch_template" "unknown_device" {
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted = var.encrypted
    }
  }
}

resource "aws_efs_file_system" "plain" {}

resource "aws_efs_file_system" "encrypted" {
  encrypted = true
}

resource "aws_kinesis_stream" "plain" {
  name        = "s"
  shard_count = 1
}

resource "aws_kinesis_stream" "kms" {
  name            = "s"
  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "r"
  description          = "r"
  engine               = "redis"
}

resource "aws_elasticache_replication_group" "encrypted" {
  replication_group_id       = "e"
  description                = "e"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}

resource "aws_elasticache_replication_group" "valkey" {
  replication_group_id       = "v"
  description                = "v"
  engine                     = "valkey"
  transit_encryption_enabled = true
}
"""


def _tf(module: Path, plan: dict | None = None) -> list[Finding]:
    resources = resources_from_terraform(module, plan_values=plan)
    return [f for f in run_resource_checks(resources, module / "main.tf") if f.id in IDS]


def test_terraform_encryption(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ENCRYPTION_TF, encoding="utf-8")
    assert _found(_tf(tmp_path)) == {
        ("aws_sns_topic.plain", "CF-SNS-001"),
        ("aws_ebs_volume.plain", "CF-EBS-001"),
        ("aws_launch_template.plain", "CF-EBS-001"),
        ("aws_efs_file_system.plain", "CF-EFS-001"),
        ("aws_kinesis_stream.plain", "CF-KIN-001"),
        ("aws_elasticache_replication_group.redis", "CF-EC-001"),
        ("aws_elasticache_replication_group.redis", "CF-EC-002"),
    }


def test_terraform_unknown_block_device_keeps_other_launch_template_checks(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ENCRYPTION_TF, encoding="utf-8")
    resources = {r.name: r for r in resources_from_terraform(tmp_path)}
    unknown = resources["aws_launch_template.unknown_device"]
    assert "BlockDeviceMappings" in unknown.unresolved
    assert "LaunchTemplateData" in unknown.properties


def test_terraform_plan_fills_encrypted_from_var(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ENCRYPTION_TF, encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"planned_values": {"root_module": {"resources": [{
        "address": "aws_ebs_volume.from_var", "mode": "managed",
        "values": {"availability_zone": "eu-north-1a", "encrypted": False},
    }]}}}), encoding="utf-8")
    found = _found(_tf(tmp_path, load_plan_values(plan_path)))
    assert ("aws_ebs_volume.from_var", "CF-EBS-001") in found


def test_terraform_fixes(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ENCRYPTION_TF, encoding="utf-8")
    findings = attach_fixes(_tf(tmp_path), "terraform")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert 'resource "aws_kinesis_stream" "plain"' in code[("aws_kinesis_stream.plain", "CF-KIN-001")]
    assert "block_device_mappings {" in code[("aws_launch_template.plain", "CF-EBS-001")]
    assert "at_rest_encryption_enabled = true" in code[
        ("aws_elasticache_replication_group.redis", "CF-EC-001")]
    assert all("In CDK" not in f.recommendation for f in findings)
