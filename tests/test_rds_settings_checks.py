"""RDS and Aurora settings in templates: CF-RDS-006..014."""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = tuple(f"CF-RDS-{n:03d}" for n in range(6, 15))


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _by_id(found)


# Every CF-RDS-006..014 setting good, for a MySQL instance.
_GOOD = {
    "Engine": "mysql", "EngineVersion": "8.0.40", "DBInstanceClass": "db.r7g.large",
    "StorageEncrypted": True, "MultiAZ": True, "DeletionProtection": True,
    "BackupRetentionPeriod": 7, "DBParameterGroupName": {"Ref": "TlsParams"},
    "MonitoringInterval": 60, "EnableIAMDatabaseAuthentication": True,
    "CopyTagsToSnapshot": True, "EnableCloudwatchLogsExports": ["error"],
    "Port": "3307", "MasterUsername": "app_owner",
}
_TLS_PARAMS = {"Type": "AWS::RDS::DBParameterGroup", "Properties": {
    "Family": "mysql8.0", "Description": "tls", "Parameters": {"require_secure_transport": "ON"}}}


def _db(**props: object) -> dict:
    return {"Type": "AWS::RDS::DBInstance", "Properties": {**_GOOD, **props}}


def test_a_hardened_instance_has_no_findings(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Db": _db(), "TlsParams": _TLS_PARAMS}) == {}


def test_each_setting(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "TlsParams": _TLS_PARAMS,
        "NoTls": _db(DBParameterGroupName="default.mysql8.0"),
        "NoMonitoring": _db(MonitoringInterval=0),
        "NoIam": _db(EnableIAMDatabaseAuthentication=False),
        "NoUpgrades": _db(AutoMinorVersionUpgrade=False),
        "NoTags": _db(CopyTagsToSnapshot=None),
        "NoLogs": _db(EnableCloudwatchLogsExports=[]),
        "DefaultPort": _db(Port=3306),
        "Admin": _db(MasterUsername="admin"),
        "X86": _db(DBInstanceClass="db.m5.large"),
    })
    assert found == {
        "CF-RDS-006": {"NoTls"}, "CF-RDS-007": {"NoMonitoring"}, "CF-RDS-008": {"NoIam"},
        "CF-RDS-009": {"NoUpgrades"}, "CF-RDS-010": {"NoTags"}, "CF-RDS-011": {"NoLogs"},
        "CF-RDS-012": {"DefaultPort"}, "CF-RDS-013": {"Admin"}, "CF-RDS-014": {"X86"},
    }


def test_tls_by_engine_and_version(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Pg16": _db(Engine="postgres", EngineVersion="16.4", DBParameterGroupName=None, Port="5433"),
        "Pg14": _db(Engine="postgres", EngineVersion="14.12", DBParameterGroupName=None, Port="5433"),
        "Pg16Off": _db(Engine="postgres", EngineVersion="16.4", Port="5433",
                       DBParameterGroupName={"Ref": "PgOff"}),
        "PgOff": {"Type": "AWS::RDS::DBParameterGroup", "Properties": {
            "Family": "postgres16", "Description": "x", "Parameters": {"rds.force_ssl": 0}}},
        "Unread": _db(DBParameterGroupName={"Ref": "GroupParam"}),
        # No version: AWS picks the current major (15+), whose default enforces TLS.
        "PgNoVersion": _db(Engine="postgres", EngineVersion=None, DBParameterGroupName=None, Port="5433"),
        "PgFamily14": _db(Engine="postgres", EngineVersion=None, Port="5433",
                          DBParameterGroupName={"Ref": "Pg14Params"}),
        "Pg14Params": {"Type": "AWS::RDS::DBParameterGroup", "Properties": {
            "Family": "postgres14", "Description": "x", "Parameters": {"work_mem": "64"}}},
        "Oracle": _db(Engine="oracle-se2", DBParameterGroupName=None, Port="1522",
                      DBInstanceClass="db.m5.large"),
    })
    # PostgreSQL 15+ defaults to rds.force_ssl=1; Oracle sets TLS in an option group.
    assert found["CF-RDS-006"] == {"Pg14", "Pg16Off", "PgFamily14"}
    # Oracle has no IAM database authentication or Graviton classes.
    assert "Oracle" not in found.get("CF-RDS-008", set()) | found.get("CF-RDS-014", set())


def test_aurora_cluster_and_members(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Cluster": {"Type": "AWS::RDS::DBCluster", "Properties": {
            "Engine": "aurora-postgresql", "StorageEncrypted": True, "DeletionProtection": True,
            "BackupRetentionPeriod": 7, "MasterUsername": "postgres"}},
        "Writer": {"Type": "AWS::RDS::DBInstance", "Properties": {
            "Engine": "aurora-postgresql", "DBClusterIdentifier": {"Ref": "Cluster"},
            "DBInstanceClass": "db.r6i.large"}},
    })
    assert found == {
        # The cluster owns TLS, IAM auth, tags, logs, port and username.
        "CF-RDS-006": {"Cluster"}, "CF-RDS-008": {"Cluster"}, "CF-RDS-010": {"Cluster"},
        "CF-RDS-011": {"Cluster"}, "CF-RDS-012": {"Cluster"}, "CF-RDS-013": {"Cluster"},
        # Each member sets its own monitoring and class.
        "CF-RDS-007": {"Writer"}, "CF-RDS-014": {"Writer"},
    }


def test_restored_and_generated_values_are_not_judged(tmp_path: Path) -> None:
    secret_user = {"Fn::Join": ["", ["{{resolve:secretsmanager:", {"Ref": "Secret"}, ":SecretString:username}}"]]}
    found = _cf(tmp_path, {
        "TlsParams": _TLS_PARAMS,
        "FromSnapshot": _db(DBSnapshotIdentifier="snap-1", Port=None, MasterUsername=None),
        "CdkSecret": _db(MasterUsername=secret_user),
        "Serverless": _db(DBInstanceClass="db.serverless"),
    })
    assert found == {}


def test_terraform_instances_clusters_and_parameter_groups(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("""\
resource "aws_db_parameter_group" "tls" {
  family = "mysql8.0"
  parameter {
    name  = "require_secure_transport"
    value = "ON"
  }
}
resource "aws_db_instance" "good" {
  engine                              = "mysql"
  instance_class                      = "db.t4g.micro"
  parameter_group_name                = aws_db_parameter_group.tls.name
  monitoring_interval                 = 60
  iam_database_authentication_enabled = true
  copy_tags_to_snapshot               = true
  enabled_cloudwatch_logs_exports     = ["error"]
  port                                = 3307
  username                            = "app_owner"
}
resource "aws_db_instance" "bare" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  username       = "admin"
}
resource "aws_rds_cluster" "aurora" {
  engine                              = "aurora-mysql"
  master_username                     = "app_owner"
  port                                = 3307
  iam_database_authentication_enabled = true
  copy_tags_to_snapshot               = true
  enabled_cloudwatch_logs_exports     = ["audit"]
  db_cluster_parameter_group_name     = "default.aurora-mysql8.0"
}
resource "aws_rds_cluster_instance" "writer" {
  cluster_identifier  = aws_rds_cluster.aurora.id
  engine              = "aurora-mysql"
  instance_class      = "db.r7g.large"
  monitoring_interval = 0
}
""", encoding="utf-8")
    warnings: list[str] = []
    found = _by_id(run_resource_checks(resources_from_terraform(tmp_path, warnings), tmp_path / "main.tf", warnings))
    assert warnings == []
    assert found == {
        "CF-RDS-006": {"aws_db_instance.bare", "aws_rds_cluster.aurora"},
        "CF-RDS-007": {"aws_db_instance.bare", "aws_rds_cluster_instance.writer"},
        "CF-RDS-008": {"aws_db_instance.bare"},
        "CF-RDS-010": {"aws_db_instance.bare"},
        "CF-RDS-011": {"aws_db_instance.bare"},
        "CF-RDS-012": {"aws_db_instance.bare"},
        "CF-RDS-013": {"aws_db_instance.bare"},
        "CF-RDS-014": {"aws_db_instance.bare"},
    }
