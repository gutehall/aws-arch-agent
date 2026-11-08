"""Redshift, DocumentDB and Neptune beyond encryption: CF-RS-002..007, CF-DOCDB-002..004, CF-NEP-002..005."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

RS_IDS = tuple(f"CF-RS-00{n}" for n in range(2, 8))
DOC_IDS = ("CF-DOCDB-002", "CF-DOCDB-003", "CF-DOCDB-004")
NEP_IDS = ("CF-NEP-002", "CF-NEP-003", "CF-NEP-004", "CF-NEP-005")
IDS = (*RS_IDS, *DOC_IDS, *NEP_IDS)
_PARAM = {"Ref": "Param"}


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


def _redshift(**props: Any) -> dict:
    base = {
        "MasterUsername": "warehouse_admin", "DBName": "analytics", "PubliclyAccessible": False,
        "AutomatedSnapshotRetentionPeriod": 7, "LoggingProperties": {"LogDestinationType": "cloudwatch"},
        "AllowVersionUpgrade": True, "EnhancedVpcRouting": True,
    }
    return {"Type": "AWS::Redshift::Cluster", "Properties": {**base, **props}}


def _docdb(**props: Any) -> dict:
    base = {"BackupRetentionPeriod": 7, "EnableCloudwatchLogsExports": ["audit"], "DeletionProtection": True}
    return {"Type": "AWS::DocDB::DBCluster", "Properties": {**base, **props}}


def _neptune(**props: Any) -> dict:
    base = {"BackupRetentionPeriod": 7, "EnableCloudwatchLogsExports": ["audit"], "DeletionProtection": True,
            "IamAuthEnabled": True}
    return {"Type": "AWS::Neptune::DBCluster", "Properties": {**base, **props}}


def test_hardened_clusters_have_no_findings(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"R": _redshift(), "D": _docdb(), "N": _neptune()}) == {}


@pytest.mark.parametrize(("check", "props", "fires"), [
    ("CF-RS-002", {"PubliclyAccessible": True}, True),
    ("CF-RS-002", {"PubliclyAccessible": "true"}, True),
    ("CF-RS-002", {"PubliclyAccessible": _PARAM}, False),
    ("CF-RS-003", {"AutomatedSnapshotRetentionPeriod": 0}, True),
    ("CF-RS-003", {"AutomatedSnapshotRetentionPeriod": "0"}, True),
    ("CF-RS-003", {"AutomatedSnapshotRetentionPeriod": 1}, False),
    ("CF-RS-003", {"AutomatedSnapshotRetentionPeriod": _PARAM}, False),
    ("CF-RS-004", {"LoggingProperties": _PARAM}, False),
    ("CF-RS-005", {"AllowVersionUpgrade": False}, True),
    ("CF-RS-005", {"AllowVersionUpgrade": "false"}, True),
    ("CF-RS-005", {"AllowVersionUpgrade": _PARAM}, False),
    ("CF-RS-006", {"EnhancedVpcRouting": False}, True),
    ("CF-RS-006", {"EnhancedVpcRouting": _PARAM}, False),
    ("CF-RS-007", {"MasterUsername": "awsuser"}, True),
    ("CF-RS-007", {"MasterUsername": "AWSUser"}, True),
    ("CF-RS-007", {"DBName": "dev"}, True),
    ("CF-RS-007", {"MasterUsername": _PARAM, "DBName": _PARAM}, False),
    ("CF-RS-007", {"MasterUsername": "awsuser", "SnapshotIdentifier": "s"}, False),
])
def test_redshift_settings(tmp_path: Path, check: str, props: dict, fires: bool) -> None:
    assert _cf(tmp_path, {"R": _redshift(**props)}) == ({check: {"R"}} if fires else {})


def test_redshift_unset_settings(tmp_path: Path) -> None:
    resource = {"Type": "AWS::Redshift::Cluster", "Properties": {"MasterUsername": "admin_user"}}
    assert _cf(tmp_path, {"R": resource}) == {"CF-RS-004": {"R"}, "CF-RS-006": {"R"}}


def test_a_default_name_finding_says_which(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"R": _redshift(MasterUsername="awsuser", DBName="dev")}}), encoding="utf-8")
    found = [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == "CF-RS-007"]
    assert len(found) == 1
    assert "admin user awsuser and database dev" in found[0].recommendation


@pytest.mark.parametrize(("factory", "retention", "audit", "deletion"), [
    (_docdb, "CF-DOCDB-002", "CF-DOCDB-003", "CF-DOCDB-004"),
    (_neptune, "CF-NEP-004", "CF-NEP-002", "CF-NEP-003"),
])
@pytest.mark.parametrize(("kind", "props", "fires"), [
    ("retention", {"BackupRetentionPeriod": 6}, True),
    ("retention", {"BackupRetentionPeriod": "1"}, True),
    ("retention", {"BackupRetentionPeriod": "7"}, False),
    ("retention", {"BackupRetentionPeriod": _PARAM}, False),
    ("audit", {"EnableCloudwatchLogsExports": []}, True),
    ("audit", {"EnableCloudwatchLogsExports": ["profiler"]}, True),
    ("audit", {"EnableCloudwatchLogsExports": ["Audit"]}, False),
    ("audit", {"EnableCloudwatchLogsExports": _PARAM}, False),
    ("audit", {"EnableCloudwatchLogsExports": [_PARAM]}, False),
    ("audit", {"EnableCloudwatchLogsExports": ["profiler", _PARAM]}, False),
    ("deletion", {"DeletionProtection": False}, True),
    ("deletion", {"DeletionProtection": _PARAM}, False),
])
def test_cluster_settings(tmp_path: Path, factory: Any, retention: str, audit: str, deletion: str,
                          kind: str, props: dict, fires: bool) -> None:
    check = {"retention": retention, "audit": audit, "deletion": deletion}[kind]
    assert _cf(tmp_path, {"C": factory(**props)}) == ({check: {"C"}} if fires else {})


def test_unset_clusters_report_every_setting(tmp_path: Path) -> None:
    assert set(_cf(tmp_path, {"D": {"Type": "AWS::DocDB::DBCluster", "Properties": {}}})) == set(DOC_IDS)
    assert set(_cf(tmp_path, {"N": {"Type": "AWS::Neptune::DBCluster", "Properties": {}}})) == set(NEP_IDS)


@pytest.mark.parametrize(("value", "fires"), [(False, True), ("false", True), (True, False), (_PARAM, False)])
def test_neptune_iam_auth(tmp_path: Path, value: Any, fires: bool) -> None:
    assert _cf(tmp_path, {"N": _neptune(IamAuthEnabled=value)}) == ({"CF-NEP-005": {"N"}} if fires else {})


def test_deletion_protection_is_prod_advice(tmp_path: Path) -> None:
    resources = {"D": _docdb(DeletionProtection=False), "N": _neptune(DeletionProtection=False)}
    assert _cf(tmp_path, resources, "dev-stack.json") == {}
    assert set(_cf(tmp_path, resources, "staging-stack.json")) == {"CF-DOCDB-004", "CF-NEP-003"}


def test_terraform(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "on" { type = bool }
variable "days" { type = number }
variable "name" { type = string }
variable "items" { type = list(string) }

resource "aws_redshift_cluster" "bare" {
  cluster_identifier = "bare"
  master_username    = "awsuser"
}
resource "aws_redshift_cluster" "bad" {
  cluster_identifier                  = "bad"
  master_username                     = "someone"
  database_name                       = "analytics"
  publicly_accessible                 = true
  automated_snapshot_retention_period = 0
  allow_version_upgrade               = false
  enhanced_vpc_routing                = false
}
resource "aws_redshift_cluster" "good" {
  cluster_identifier   = "good"
  master_username      = "someone"
  database_name        = "analytics"
  enhanced_vpc_routing = true
}
resource "aws_redshift_logging" "good" {
  cluster_identifier   = aws_redshift_cluster.good.id
  log_destination_type = "cloudwatch"
}
resource "aws_redshift_cluster" "legacy_logs" {
  cluster_identifier   = "legacy"
  master_username      = "someone"
  database_name        = "analytics"
  enhanced_vpc_routing = true
  logging {
    enable = true
  }
}
resource "aws_redshift_cluster" "from_vars" {
  cluster_identifier                  = "vars"
  master_username                     = var.name
  database_name                       = var.name
  publicly_accessible                 = var.on
  automated_snapshot_retention_period = var.days
  allow_version_upgrade               = var.on
  enhanced_vpc_routing                = var.on
  logging {
    enable = var.on
  }
}
resource "aws_redshift_cluster" "restored" {
  cluster_identifier   = "restored"
  snapshot_identifier  = "snap"
  enhanced_vpc_routing = true
  logging {
    enable = true
  }
}

resource "aws_docdb_cluster" "bare" {}
resource "aws_docdb_cluster" "good" {
  backup_retention_period         = 7
  enabled_cloudwatch_logs_exports = ["audit", "profiler"]
  deletion_protection             = true
}
resource "aws_docdb_cluster" "from_vars" {
  backup_retention_period         = var.days
  enabled_cloudwatch_logs_exports = var.items
  deletion_protection             = var.on
}

resource "aws_neptune_cluster" "bare" {}
resource "aws_neptune_cluster" "good" {
  backup_retention_period             = 7
  enable_cloudwatch_logs_exports      = ["audit"]
  deletion_protection                 = true
  iam_database_authentication_enabled = true
}
resource "aws_neptune_cluster" "from_vars" {
  backup_retention_period             = var.days
  enable_cloudwatch_logs_exports      = var.items
  deletion_protection                 = var.on
  iam_database_authentication_enabled = var.on
}
""")
    bare, bad = "aws_redshift_cluster.bare", "aws_redshift_cluster.bad"
    assert found["CF-RS-002"] == {bad}
    assert found["CF-RS-003"] == {bad}
    assert found["CF-RS-004"] == {bare, bad}
    assert found["CF-RS-005"] == {bad}
    assert found["CF-RS-006"] == {bare, bad}
    assert found["CF-RS-007"] == {bare}
    for check in DOC_IDS:
        assert found[check] == {"aws_docdb_cluster.bare"}
    for check in NEP_IDS:
        assert found[check] == {"aws_neptune_cluster.bare"}


def test_terraform_defaults_the_database_name_and_counts_an_untied_logging_resource(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "cluster" { type = string }

resource "aws_redshift_cluster" "a" {
  cluster_identifier   = "a"
  master_username      = "someone"
  enhanced_vpc_routing = true
}
resource "aws_redshift_logging" "untied" {
  cluster_identifier = var.cluster
}
""")
    assert found == {"CF-RS-007": {"aws_redshift_cluster.a"}}
