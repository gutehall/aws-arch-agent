"""DynamoDB, ElastiCache and EFS resilience and access: CF-DDB-004/005, CF-EC-003..007, CF-EFS-002..005."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.environments import RULE_POLICY
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = (
    "CF-DDB-004", "CF-DDB-005", "CF-EC-003", "CF-EC-004", "CF-EC-005", "CF-EC-006", "CF-EC-007",
    "CF-EFS-002", "CF-EFS-003", "CF-EFS-004", "CF-EFS-005",
)
_PARAM = {"Ref": "Param"}
_GROUP = "AWS::ElastiCache::ReplicationGroup"
_CLUSTER = "AWS::ElastiCache::CacheCluster"


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict, name: str = "t.json") -> dict[str, set[str]]:
    path = tmp_path / name
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _by_id(found)


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _table(**props: Any) -> dict:
    base = {"DeletionProtectionEnabled": True,
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}}
    return {"Type": "AWS::DynamoDB::Table", "Properties": {**base, **props}}


def _group(**props: Any) -> dict:
    base = {"AutomaticFailoverEnabled": True, "MultiAZEnabled": True, "SnapshotRetentionLimit": 7,
            "CacheSubnetGroupName": "private", "TransitEncryptionEnabled": True,
            "AtRestEncryptionEnabled": True}
    return {"Type": _GROUP, "Properties": {**base, **props}}


def _cluster(**props: Any) -> dict:
    base = {"Engine": "redis", "SnapshotRetentionLimit": 7, "CacheSubnetGroupName": "private"}
    return {"Type": _CLUSTER, "Properties": {**base, **props}}


def _efs(**props: Any) -> dict:
    base = {"BackupPolicy": {"Status": "ENABLED"}, "LifecyclePolicies": [{"TransitionToIA": "AFTER_30_DAYS"}],
            "Encrypted": True}
    return {"Type": "AWS::EFS::FileSystem", "Properties": {**base, **props}}


def _point(**props: Any) -> dict:
    base = {"FileSystemId": "fs", "RootDirectory": {"Path": "/app"}, "PosixUser": {"Uid": "1", "Gid": "1"}}
    return {"Type": "AWS::EFS::AccessPoint", "Properties": {**base, **props}}


def _without(resource: dict, key: str) -> dict:
    return {**resource, "Properties": {k: v for k, v in resource["Properties"].items() if k != key}}


def test_hardened_resources_have_no_findings(tmp_path: Path) -> None:
    resources = {"T": _table(), "G": _group(), "C": _cluster(), "F": _efs(), "A": _point()}
    assert _cf(tmp_path, resources) == {}


# --- DynamoDB --------------------------------------------------------------


@pytest.mark.parametrize(("value", "fires"), [
    (False, True), ("false", True), (None, True), (True, False), ("true", False), (_PARAM, False),
])
def test_table_deletion_protection(tmp_path: Path, value: Any, fires: bool) -> None:
    table = _table(DeletionProtectionEnabled=value) if value is not None else _without(
        _table(), "DeletionProtectionEnabled")
    assert _cf(tmp_path, {"T": table}) == ({"CF-DDB-004": {"T"}} if fires else {})


def test_deletion_protection_is_not_reported_in_dev() -> None:
    assert RULE_POLICY["CF-DDB-004"]["dev"] is None


@pytest.mark.parametrize(("pitr", "fires"), [
    (None, True),
    ({"PointInTimeRecoveryEnabled": False}, True),
    ({"PointInTimeRecoveryEnabled": True}, False),
    ({"PointInTimeRecoveryEnabled": _PARAM}, False),
    (_PARAM, False),
])
def test_table_with_no_backup(tmp_path: Path, pitr: Any, fires: bool) -> None:
    key = "PointInTimeRecoverySpecification"
    table = _without(_table(), key) if pitr is None else _table(**{key: pitr})
    assert _cf(tmp_path, {"T": table}) == ({"CF-DDB-005": {"T"}} if fires else {})


def _selection(**body: Any) -> dict:
    return {"Type": "AWS::Backup::BackupSelection", "Properties": {
        "BackupPlanId": "p", "BackupSelection": {"SelectionName": "s", "IamRoleArn": "r", **body}}}


@pytest.mark.parametrize(("selection", "fires"), [
    (_selection(Resources=[{"Fn::GetAtt": ["T", "Arn"]}]), False),
    (_selection(Resources=["*"]), False),
    (_selection(Resources=[{"Fn::GetAtt": ["Other", "Arn"]}]), True),
    (_selection(Resources=_PARAM), False),
])
def test_a_backup_selection_counts_as_backup(tmp_path: Path, selection: dict, fires: bool) -> None:
    table = _without(_table(), "PointInTimeRecoverySpecification")
    other = {"Type": "AWS::SQS::Queue", "Properties": {}}
    found = _cf(tmp_path, {"T": table, "S": selection, "Other": other})
    assert found == ({"CF-DDB-005": {"T"}} if fires else {})


# --- ElastiCache: replication groups ----------------------------------------


@pytest.mark.parametrize(("props", "fires"), [
    ({"AutomaticFailoverEnabled": False}, True),
    ({"MultiAZEnabled": False}, True),
    ({"AutomaticFailoverEnabled": "false", "MultiAZEnabled": "false"}, True),
    ({"AutomaticFailoverEnabled": _PARAM}, False),
    ({"MultiAZEnabled": _PARAM}, False),
])
def test_group_failover(tmp_path: Path, props: dict, fires: bool) -> None:
    assert _cf(tmp_path, {"G": _group(**props)}) == ({"CF-EC-003": {"G"}} if fires else {})


@pytest.mark.parametrize("key", ["AutomaticFailoverEnabled", "MultiAZEnabled"])
def test_group_failover_unset_fires(tmp_path: Path, key: str) -> None:
    assert _cf(tmp_path, {"G": _without(_group(), key)}) == {"CF-EC-003": {"G"}}


def test_failover_is_not_reported_outside_prod() -> None:
    assert RULE_POLICY["CF-EC-003"] == {"dev": None, "staging": None}


def test_a_cache_cluster_has_no_failover_check(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"C": _cluster()}) == {}


@pytest.mark.parametrize(("props", "fires"), [
    ({"EngineVersion": "5.0.6"}, True),
    ({"EngineVersion": "4.0.10"}, True),
    ({"EngineVersion": 5.0}, True),
    ({"EngineVersion": "5.0.6", "AuthToken": "{{resolve:secretsmanager:s}}"}, False),
    ({"EngineVersion": "5.0.6", "AuthToken": _PARAM}, False),
    ({"EngineVersion": "6.x"}, False),
    ({"EngineVersion": "7.1"}, False),
    ({"EngineVersion": _PARAM}, False),
    ({}, False),
    ({"EngineVersion": "5.0.6", "Engine": "valkey"}, False),
    ({"EngineVersion": "5.0.6", "Engine": _PARAM}, False),
])
def test_old_redis_auth(tmp_path: Path, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"G": _group(**props)})
    assert found == ({"CF-EC-006": {"G"}} if fires else {})


def test_a_group_from_a_primary_cluster_takes_settings_from_it(tmp_path: Path) -> None:
    group = {"Type": _GROUP, "Properties": {
        "AutomaticFailoverEnabled": True, "MultiAZEnabled": True, "PrimaryClusterId": "c",
        "EngineVersion": "5.0.6", "AutoMinorVersionUpgrade": False,
    }}
    assert _cf(tmp_path, {"G": group}) == {}


def test_a_group_from_a_primary_cluster_still_needs_failover(tmp_path: Path) -> None:
    group = {"Type": _GROUP, "Properties": {"PrimaryClusterId": "c"}}
    assert _cf(tmp_path, {"G": group}) == {"CF-EC-003": {"G"}}


# --- ElastiCache: both types -------------------------------------------------


@pytest.mark.parametrize("make", [_group, _cluster])
@pytest.mark.parametrize(("value", "fires"), [(0, True), ("0", True), (None, True), (1, False), (_PARAM, False)])
def test_snapshot_retention(tmp_path: Path, make: Any, value: Any, fires: bool) -> None:
    resource = make(SnapshotRetentionLimit=value) if value is not None else _without(make(), "SnapshotRetentionLimit")
    assert _cf(tmp_path, {"R": resource}) == ({"CF-EC-004": {"R"}} if fires else {})


def test_snapshot_retention_covers_valkey_not_memcached(tmp_path: Path) -> None:
    valkey = _cluster(Engine="valkey", SnapshotRetentionLimit=0)
    memcached = _cluster(Engine="memcached", SnapshotRetentionLimit=0)
    unknown = _cluster(Engine=_PARAM, SnapshotRetentionLimit=0)
    assert _cf(tmp_path, {"V": valkey, "M": memcached, "U": unknown}) == {"CF-EC-004": {"V"}}


@pytest.mark.parametrize("make", [_group, _cluster])
@pytest.mark.parametrize(("value", "fires"), [(False, True), ("false", True), (True, False), (_PARAM, False)])
def test_minor_version_upgrade(tmp_path: Path, make: Any, value: Any, fires: bool) -> None:
    assert _cf(tmp_path, {"R": make(AutoMinorVersionUpgrade=value)}) == ({"CF-EC-005": {"R"}} if fires else {})


def test_minor_version_upgrade_skips_memcached_and_unset(tmp_path: Path) -> None:
    memcached = _cluster(Engine="memcached", AutoMinorVersionUpgrade=False)
    assert _cf(tmp_path, {"M": memcached}) == {}


@pytest.mark.parametrize("make", [_group, _cluster])
@pytest.mark.parametrize(("value", "fires"), [("default", True), (None, True), ("private", False), (_PARAM, False)])
def test_subnet_group(tmp_path: Path, make: Any, value: Any, fires: bool) -> None:
    resource = make(CacheSubnetGroupName=value) if value is not None else _without(make(), "CacheSubnetGroupName")
    assert _cf(tmp_path, {"R": resource}) == ({"CF-EC-007": {"R"}} if fires else {})


def test_memcached_still_needs_a_subnet_group(tmp_path: Path) -> None:
    memcached = _without(_cluster(Engine="memcached"), "CacheSubnetGroupName")
    assert _cf(tmp_path, {"M": memcached}) == {"CF-EC-007": {"M"}}


# --- EFS ---------------------------------------------------------------------


@pytest.mark.parametrize(("value", "fires"), [
    ({"Status": "DISABLED"}, True),
    ({"Status": "ENABLED"}, False),
    ({"Status": _PARAM}, False),
    (_PARAM, False),
])
def test_efs_backup_policy(tmp_path: Path, value: Any, fires: bool) -> None:
    assert _cf(tmp_path, {"F": _efs(BackupPolicy=value)}) == ({"CF-EFS-002": {"F"}} if fires else {})


def test_efs_backup_policy_unset(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"F": _without(_efs(), "BackupPolicy")}) == {"CF-EFS-002": {"F"}}


def test_one_zone_defaults_to_backups_on(tmp_path: Path) -> None:
    one_zone = _without(_efs(AvailabilityZoneName="eu-west-1a"), "BackupPolicy")
    assert _cf(tmp_path, {"F": one_zone}) == {}
    assert _cf(tmp_path, {"F": _efs(AvailabilityZoneName="eu-west-1a", BackupPolicy={"Status": "DISABLED"})}) == {
        "CF-EFS-002": {"F"}}


@pytest.mark.parametrize(("value", "fires"), [
    (None, True), ([], True), ([{"TransitionToIA": "AFTER_30_DAYS"}], False), (_PARAM, False),
])
def test_efs_lifecycle(tmp_path: Path, value: Any, fires: bool) -> None:
    system = _efs(LifecyclePolicies=value) if value is not None else _without(_efs(), "LifecyclePolicies")
    assert _cf(tmp_path, {"F": system}) == ({"CF-EFS-003": {"F"}} if fires else {})


@pytest.mark.parametrize(("root", "fires"), [
    (None, True),
    ({"Path": "/"}, True),
    ({}, True),
    ({"Path": "/app"}, False),
    ({"Path": _PARAM}, False),
    (_PARAM, False),
])
def test_access_point_root(tmp_path: Path, root: Any, fires: bool) -> None:
    point = _point(RootDirectory=root) if root is not None else _without(_point(), "RootDirectory")
    assert _cf(tmp_path, {"A": point}) == ({"CF-EFS-004": {"A"}} if fires else {})


@pytest.mark.parametrize(("posix", "fires"), [
    (None, True), ({"Uid": "1", "Gid": "1"}, False), (_PARAM, False),
])
def test_access_point_posix_user(tmp_path: Path, posix: Any, fires: bool) -> None:
    point = _point(PosixUser=posix) if posix is not None else _without(_point(), "PosixUser")
    assert _cf(tmp_path, {"A": point}) == ({"CF-EFS-005": {"A"}} if fires else {})


# --- Terraform ---------------------------------------------------------------


_TF_HARDENED = """
resource "aws_dynamodb_table" "t" {
  name                        = "t"
  deletion_protection_enabled = true
  point_in_time_recovery {
    enabled = true
  }
}
resource "aws_elasticache_replication_group" "g" {
  replication_group_id       = "g"
  automatic_failover_enabled = true
  multi_az_enabled           = true
  snapshot_retention_limit   = 7
  subnet_group_name          = aws_elasticache_subnet_group.s.name
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  engine_version             = "7.1"
}
resource "aws_elasticache_cluster" "c" {
  cluster_id               = "c"
  engine                   = "redis"
  snapshot_retention_limit = 1
  subnet_group_name        = "private"
}
resource "aws_efs_file_system" "f" {
  encrypted = true
  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}
resource "aws_efs_backup_policy" "b" {
  file_system_id = aws_efs_file_system.f.id
  backup_policy {
    status = "ENABLED"
  }
}
resource "aws_efs_access_point" "a" {
  file_system_id = aws_efs_file_system.f.id
  root_directory {
    path = "/app"
  }
  posix_user {
    uid = 1
    gid = 1
  }
}
"""


def test_terraform_hardened_resources_have_no_findings(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_HARDENED) == {}


def test_terraform_findings(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_dynamodb_table" "t" {
  name = "t"
}
resource "aws_elasticache_replication_group" "g" {
  replication_group_id       = "g"
  engine_version             = "5.0.6"
  auto_minor_version_upgrade = false
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}
resource "aws_elasticache_cluster" "c" {
  cluster_id        = "c"
  engine            = "redis"
  subnet_group_name = "default"
}
resource "aws_efs_file_system" "f" {
  encrypted = true
}
resource "aws_efs_access_point" "a" {
  file_system_id = aws_efs_file_system.f.id
}
""") == {
        "CF-DDB-004": {"aws_dynamodb_table.t"},
        "CF-DDB-005": {"aws_dynamodb_table.t"},
        "CF-EC-003": {"aws_elasticache_replication_group.g"},
        "CF-EC-004": {"aws_elasticache_replication_group.g", "aws_elasticache_cluster.c"},
        "CF-EC-005": {"aws_elasticache_replication_group.g"},
        "CF-EC-006": {"aws_elasticache_replication_group.g"},
        "CF-EC-007": {"aws_elasticache_replication_group.g", "aws_elasticache_cluster.c"},
        "CF-EFS-002": {"aws_efs_file_system.f"},
        "CF-EFS-003": {"aws_efs_file_system.f"},
        "CF-EFS-004": {"aws_efs_access_point.a"},
        "CF-EFS-005": {"aws_efs_access_point.a"},
    }


def test_terraform_unknown_values_are_not_judged(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_dynamodb_table" "t" {
  name                        = "t"
  deletion_protection_enabled = var.protect
  point_in_time_recovery {
    enabled = var.pitr
  }
}
resource "aws_elasticache_replication_group" "g" {
  replication_group_id       = "g"
  automatic_failover_enabled = var.failover
  multi_az_enabled           = var.multi_az
  snapshot_retention_limit   = var.days
  auto_minor_version_upgrade = var.minor
  subnet_group_name          = var.subnets
  engine_version             = var.version
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}
resource "aws_efs_file_system" "f" {
  encrypted = true
  dynamic "lifecycle_policy" {
    for_each = var.policies
    content {
      transition_to_ia = lifecycle_policy.value
    }
  }
}
resource "aws_efs_backup_policy" "b" {
  file_system_id = aws_efs_file_system.f.id
  backup_policy {
    status = var.status
  }
}
resource "aws_efs_access_point" "a" {
  file_system_id = aws_efs_file_system.f.id
  dynamic "root_directory" {
    for_each = var.roots
    content {
      path = root_directory.value
    }
  }
  dynamic "posix_user" {
    for_each = var.users
    content {
      uid = 1
      gid = 1
    }
  }
}
""") == {}


def test_terraform_cluster_in_a_group_is_not_judged(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_elasticache_cluster" "member" {
  cluster_id           = "m"
  replication_group_id = var.group
}
""") == {}


def test_terraform_auth_token_counts_and_stays_out_of_the_model(tmp_path: Path) -> None:
    text = """
resource "aws_elasticache_replication_group" "g" {
  replication_group_id = "g"
  engine_version       = "5.0.6"
  auth_token           = "literal-token-value"
}
"""
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    resources = resources_from_terraform(tmp_path, [])
    assert "literal-token-value" not in json.dumps(resources[0].properties, default=str)
    found = _by_id(run_resource_checks(resources, tmp_path / "main.tf"))
    assert "CF-EC-006" not in found


@pytest.mark.parametrize(("policy", "fires"), [
    ('file_system_id = aws_efs_file_system.f.id\n backup_policy {\n status = "DISABLED"\n }', True),
    ('file_system_id = aws_efs_file_system.other.id\n backup_policy {\n status = "ENABLED"\n }', True),
    ('file_system_id = var.fs\n backup_policy {\n status = "DISABLED"\n }', False),
    ('file_system_id = aws_efs_file_system.f.id\n dynamic "backup_policy" {\n for_each = var.x\n content {\n '
     'status = "ENABLED"\n }\n }', False),
])
def test_terraform_backup_policy_links(tmp_path: Path, policy: str, fires: bool) -> None:
    found = _tf(tmp_path, f"""
resource "aws_efs_file_system" "f" {{
  encrypted = true
  lifecycle_policy {{
    transition_to_ia = "AFTER_30_DAYS"
  }}
}}
resource "aws_efs_file_system" "other" {{
  encrypted = true
  lifecycle_policy {{
    transition_to_ia = "AFTER_30_DAYS"
  }}
}}
resource "aws_efs_backup_policy" "keep" {{
  file_system_id = aws_efs_file_system.other.id
  backup_policy {{
    status = "ENABLED"
  }}
}}
resource "aws_efs_backup_policy" "b" {{
  {policy}
}}
""")
    assert found == ({"CF-EFS-002": {"aws_efs_file_system.f"}} if fires else {})


def test_terraform_one_zone_defaults_to_backups_on(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_efs_file_system" "f" {
  encrypted              = true
  availability_zone_name = "eu-west-1a"
  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}
""") == {}
