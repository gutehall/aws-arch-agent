"""Encryption checks in templates: SNS, EBS, EFS, Kinesis, ElastiCache (DM3-525) and
OpenSearch, Redshift, DocumentDB, Neptune, MSK (DM3-552)."""
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
  block_device_mappings {
    device_name = var.data_device
    ebs {
      volume_size = 100
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
        ("aws_launch_template.unknown_device", "CF-EBS-001"),
        ("aws_efs_file_system.plain", "CF-EFS-001"),
        ("aws_kinesis_stream.plain", "CF-KIN-001"),
        ("aws_elasticache_replication_group.redis", "CF-EC-001"),
        ("aws_elasticache_replication_group.redis", "CF-EC-002"),
    }


def test_terraform_unknown_block_device_does_not_hide_the_others(tmp_path: Path) -> None:
    """A device with unknown encryption is skipped; the plain one beside it is still reported."""
    (tmp_path / "main.tf").write_text(ENCRYPTION_TF, encoding="utf-8")
    resources = {r.name: r for r in resources_from_terraform(tmp_path)}
    unknown = resources["aws_launch_template.unknown_device"]
    assert "BlockDeviceMappings" not in unknown.unresolved
    assert "LaunchTemplateData" in unknown.properties
    finding = next(f for f in _tf(tmp_path) if f.evidence.startswith("aws_launch_template.unknown_device"))
    assert finding.recommendation.startswith("Unencrypted: a block device.")


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


# --- OpenSearch, Redshift, DocumentDB, Neptune, MSK (DM3-552) ----------------------

IDS2 = {"CF-OS-001", "CF-OS-002", "CF-RS-001", "CF-DOCDB-001", "CF-NEP-001", "CF-MSK-001"}


def _found2(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings if f.id in IDS2}


def _msk(**transit) -> dict:
    return _r("AWS::MSK::Cluster", EncryptionInfo={"EncryptionInTransit": transit})


CF_RESOURCES_2 = {
    "SearchPlain": _r("AWS::OpenSearchService::Domain"),
    "SearchOk": _r("AWS::OpenSearchService::Domain",
                   EncryptionAtRestOptions={"Enabled": True},
                   NodeToNodeEncryptionOptions={"Enabled": "true"}),
    "SearchIf": _r("AWS::OpenSearchService::Domain",
                   EncryptionAtRestOptions={"Fn::If": ["Prod", {"Enabled": True}, {"Enabled": False}]},
                   NodeToNodeEncryptionOptions={"Enabled": {"Ref": "N2N"}}),
    "RedshiftDefault": _r("AWS::Redshift::Cluster", NodeType="ra3.xlplus"),  # encrypted by default
    "RedshiftOff": _r("AWS::Redshift::Cluster", Encrypted=False),
    "RedshiftOn": _r("AWS::Redshift::Cluster", Encrypted=True),
    "DocPlain": _r("AWS::DocDB::DBCluster"),
    "DocOk": _r("AWS::DocDB::DBCluster", StorageEncrypted=True),
    "DocSnapshot": _r("AWS::DocDB::DBCluster", SnapshotIdentifier="snap"),  # inherits
    "NeptunePlain": _r("AWS::Neptune::DBCluster"),
    "NeptuneOk": _r("AWS::Neptune::DBCluster", StorageEncrypted="true"),
    "NeptuneClone": _r("AWS::Neptune::DBCluster", SourceDBClusterIdentifier="src"),
    "MskDefault": _r("AWS::MSK::Cluster", ClusterName="m"),  # TLS and InCluster by default
    "MskTlsOnly": _msk(ClientBroker="TLS", InCluster=True),
    "MskPlain": _msk(ClientBroker="PLAINTEXT"),
    "MskMixed": _msk(ClientBroker="TLS_PLAINTEXT", InCluster=False),
    "MskRef": _msk(ClientBroker={"Ref": "Broker"}),
}


def test_cloudformation_encryption_part_2(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": CF_RESOURCES_2}), encoding="utf-8")
    findings = [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS2]
    assert _found2(findings) == {
        ("SearchPlain", "CF-OS-001"),
        ("SearchPlain", "CF-OS-002"),
        ("RedshiftOff", "CF-RS-001"),
        ("DocPlain", "CF-DOCDB-001"),
        ("NeptunePlain", "CF-NEP-001"),
        ("MskPlain", "CF-MSK-001"),
        ("MskMixed", "CF-MSK-001"),
    }
    severity = {f.id: f.severity for f in findings}
    assert severity["CF-RS-001"] == "Low"  # Redshift encrypts by default; only false is asked
    assert {severity[i] for i in IDS2 - {"CF-RS-001"}} == {"Medium"}
    mixed = next(f for f in findings if f.evidence.startswith("MskMixed"))
    assert mixed.recommendation.startswith("ClientBroker is TLS_PLAINTEXT; InCluster is false.")
    attach_fixes(findings, "cloudformation")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert "ClientBroker: TLS" in code[("MskPlain", "CF-MSK-001")]
    assert "StorageEncrypted: true" in code[("NeptunePlain", "CF-NEP-001")]


def test_static_rules_are_dropped_for_part_2() -> None:
    static = [Finding(id=i, title="t", recommendation="r")
              for i in ("SEC-039", "SEC-044", "SEC-059", "SEC-060", "SEC-061")]
    cf = [Finding(id=i, title="t", recommendation="r")
          for i in ("CF-OS-001", "CF-MSK-001", "CF-RS-001", "CF-DOCDB-001", "CF-NEP-001")]
    assert [f.id for f in drop_static_covered_by_cf(static + cf)] == [f.id for f in cf]


ENCRYPTION_TF_2 = """\
resource "aws_opensearch_domain" "plain" {
  domain_name = "plain"
}

resource "aws_opensearch_domain" "encrypted" {
  domain_name = "enc"
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
}

resource "aws_redshift_cluster" "default" {
  cluster_identifier = "d"
  node_type          = "ra3.xlplus"
}

resource "aws_redshift_cluster" "off" {
  cluster_identifier = "o"
  encrypted          = false
}

resource "aws_docdb_cluster" "plain" {
  cluster_identifier = "p"
}

resource "aws_docdb_cluster" "encrypted" {
  cluster_identifier = "e"
  storage_encrypted  = true
}

resource "aws_docdb_cluster" "from_snapshot" {
  cluster_identifier  = "s"
  snapshot_identifier = "snap"
}

resource "aws_neptune_cluster" "plain" {
  cluster_identifier = "p"
}

resource "aws_neptune_cluster" "from_var" {
  cluster_identifier = "v"
  storage_encrypted  = var.encrypted
}

resource "aws_msk_cluster" "default" {
  cluster_name = "d"
}

resource "aws_msk_cluster" "plaintext" {
  cluster_name = "p"
  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT"
    }
  }
}

resource "aws_msk_cluster" "tls" {
  cluster_name = "t"
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}
"""


def test_terraform_encryption_part_2(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ENCRYPTION_TF_2, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    findings = [f for f in run_resource_checks(resources, tmp_path / "main.tf") if f.id in IDS2]
    assert _found2(findings) == {
        ("aws_opensearch_domain.plain", "CF-OS-001"),
        ("aws_opensearch_domain.plain", "CF-OS-002"),
        ("aws_redshift_cluster.off", "CF-RS-001"),
        ("aws_docdb_cluster.plain", "CF-DOCDB-001"),
        ("aws_neptune_cluster.plain", "CF-NEP-001"),
        ("aws_msk_cluster.plaintext", "CF-MSK-001"),
    }
    attach_fixes(findings, "terraform")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert 'resource "aws_msk_cluster" "plaintext"' in code[("aws_msk_cluster.plaintext", "CF-MSK-001")]
    assert "encrypt_at_rest {" in code[("aws_opensearch_domain.plain", "CF-OS-001")]
    assert all("In CDK" not in f.recommendation for f in findings)
