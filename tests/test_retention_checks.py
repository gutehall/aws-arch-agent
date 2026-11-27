"""Retention on the services that keep data forever: log groups a service creates (CF-CW-003),
backup rules that never delete (CF-BAK-006), MemoryDB snapshots (CF-MDB-001) and EventBridge
archives (CF-EB-003). Each runs on CloudFormation, synthesised CDK and Terraform."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.report.doc_topics import RULE_TOPICS, TOPICS
from aws_arch_agent.rules import wa_map
from aws_arch_agent.rules.cf_template import CF_THEMES, CF_TITLES, run_cf_rules_from_paths
from aws_arch_agent.rules.effort import LOW
from aws_arch_agent.rules.fix_snippets import _CLOUDFORMATION, _TERRAFORM

NEW = ("CF-CW-003", "CF-BAK-006", "CF-MDB-001", "CF-EB-003")


def _cf(tmp_path: Path, resources: dict) -> list:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "stack.template.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return run_cf_rules_from_paths([path], repo_path=tmp_path)


def _cf_ids(tmp_path: Path, resources: dict) -> set[str]:
    return {f.id for f in _cf(tmp_path, resources)}


def _tf_ids(tmp_path: Path, text: str) -> set[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False)
    return {f.id for f in findings}


def test_new_checks_are_registered() -> None:
    for cid in NEW:
        assert cid in CF_TITLES and cid in CF_THEMES and cid in wa_map.RULE_BEST_PRACTICES
        assert cid in LOW and cid in _CLOUDFORMATION and cid in _TERRAFORM
        assert RULE_TOPICS[cid] in TOPICS
    assert RULE_TOPICS["CF-CW-003"] == "log_retention"


# --- CF-CW-003: log groups a service creates at deploy time --------------------------------

_FN = {"Type": "AWS::Lambda::Function", "Properties": {
    "FunctionName": "orders", "Runtime": "python3.12", "Handler": "a.h", "Role": "r", "Code": {"ZipFile": "x"}}}


def _group(name, **props) -> dict:
    return {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": name, **props}}


def test_a_named_lambda_with_no_log_group_fires(tmp_path: Path) -> None:
    findings = [f for f in _cf(tmp_path, {"Fn": _FN}) if f.id == "CF-CW-003"]
    assert len(findings) == 1 and "/aws/lambda/orders" in findings[0].evidence


@pytest.mark.parametrize("cover", [
    {"G": _group("/aws/lambda/orders", RetentionInDays=30)},
    {"FnLogRetentionAB12": {"Type": "Custom::LogRetention", "Properties": {
        "ServiceToken": "t", "LogGroupName": "/aws/lambda/orders", "RetentionInDays": 14}}},
])
def test_a_retained_group_or_log_retention_covers_the_function(tmp_path: Path, cover: dict) -> None:
    assert "CF-CW-003" not in _cf_ids(tmp_path, {"Fn": _FN, **cover})


def test_a_declared_group_with_no_retention_is_cw_001_only(tmp_path: Path) -> None:
    ids = _cf_ids(tmp_path, {"Fn": _FN, "G": _group("/aws/lambda/orders")})
    assert "CF-CW-001" in ids and "CF-CW-003" not in ids


@pytest.mark.parametrize("resources", [
    # A generated function name cannot be known.
    {"Fn": {**_FN, "Properties": {**_FN["Properties"], "FunctionName": {"Ref": "Name"}}}},
    {"Fn": {**_FN, "Properties": {k: v for k, v in _FN["Properties"].items() if k != "FunctionName"}}},
    # A logging config the scan cannot read may name its own group.
    {"Fn": {**_FN, "Properties": {**_FN["Properties"], "LoggingConfig": {"Fn::If": ["C", {}, {}]}}}},
    # Logs go to the group the function names.
    {"Fn": {**_FN, "Properties": {**_FN["Properties"], "LoggingConfig": {"LogGroup": {"Ref": "G"}}}}},
    # A LogRetention whose name cannot be read may cover it.
    {"Fn": _FN, "R": {"Type": "Custom::LogRetention", "Properties": {
        "LogGroupName": {"Fn::Join": ["", ["/aws/lambda/", {"Ref": "Fn"}]]}, "RetentionInDays": 7}}},
    # A child stack may declare the group.
    {"Fn": _FN, "Child": {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "u"}}},
])
def test_what_the_scan_cannot_read_is_not_judged(tmp_path: Path, resources: dict) -> None:
    assert "CF-CW-003" not in _cf_ids(tmp_path, resources)


@pytest.mark.parametrize("resource,name", [
    ({"Type": "AWS::ECS::TaskDefinition", "Properties": {"ContainerDefinitions": [
        {"Name": "app", "Image": "i", "LogConfiguration": {
            "LogDriver": "awslogs", "Options": {"awslogs-group": "/ecs/app", "awslogs-region": "eu-west-1"}}}]}},
     "/ecs/app"),
    ({"Type": "AWS::EC2::FlowLog", "Properties": {
        "ResourceId": "vpc-1", "ResourceType": "VPC", "TrafficType": "ALL",
        "LogGroupName": "vpc-flow", "DeliverLogsPermissionArn": "r"}}, "vpc-flow"),
    ({"Type": "AWS::RDS::DBInstance", "Properties": {
        "DBInstanceIdentifier": "Orders", "Engine": "postgres", "DBInstanceClass": "db.t4g.micro",
        "EnableCloudwatchLogsExports": ["postgresql"]}}, "/aws/rds/instance/orders/postgresql"),
    ({"Type": "AWS::RDS::DBCluster", "Properties": {
        "DBClusterIdentifier": "core", "Engine": "aurora-mysql", "EnableCloudwatchLogsExports": ["audit"]}},
     "/aws/rds/cluster/core/audit"),
    ({"Type": "AWS::EKS::Cluster", "Properties": {
        "Name": "prod", "RoleArn": "r", "ResourcesVpcConfig": {"SubnetIds": ["s"]},
        "Logging": {"ClusterLogging": {"EnabledTypes": [{"Type": "api"}]}}}}, "/aws/eks/prod/cluster"),
    ({"Type": "AWS::CodeBuild::Project", "Properties": {
        "Source": {"Type": "NO_SOURCE"}, "Artifacts": {"Type": "NO_ARTIFACTS"},
        "Environment": {"Type": "LINUX_CONTAINER", "Image": "i", "ComputeType": "BUILD_GENERAL1_SMALL"},
        "ServiceRole": "r", "LogsConfig": {"CloudWatchLogs": {"Status": "ENABLED", "GroupName": "builds"}}}},
     "builds"),
])
def test_each_service_fires_and_a_retained_group_covers_it(tmp_path: Path, resource: dict, name: str) -> None:
    findings = [f for f in _cf(tmp_path / "bare", {"R": resource}) if f.id == "CF-CW-003"]
    assert len(findings) == 1 and name in findings[0].evidence
    covered = {"R": resource, "G": _group(name, RetentionInDays=90)}
    assert "CF-CW-003" not in _cf_ids(tmp_path / "covered", covered)


def test_services_that_write_no_logs_do_not_fire(tmp_path: Path) -> None:
    resources = {
        "Db": {"Type": "AWS::RDS::DBInstance", "Properties": {"DBInstanceIdentifier": "o", "Engine": "postgres"}},
        "Eks": {"Type": "AWS::EKS::Cluster", "Properties": {"Name": "e", "RoleArn": "r",
                                                             "ResourcesVpcConfig": {"SubnetIds": ["s"]}}},
        "Flow": {"Type": "AWS::EC2::FlowLog", "Properties": {
            "ResourceId": "v", "ResourceType": "VPC", "LogDestinationType": "s3", "LogDestination": "arn:b"}},
    }
    assert "CF-CW-003" not in _cf_ids(tmp_path, resources)


def test_cw_003_on_synthesised_cdk_and_terraform(tmp_path: Path) -> None:
    out = tmp_path / "cdk" / "cdk.out"
    out.mkdir(parents=True)
    (out / "Stack.template.json").write_text(json.dumps({"Resources": {"Fn": _FN}}), encoding="utf-8")
    assert "CF-CW-003" in {f.id for f in run_cf_rules_from_paths([out / "Stack.template.json"],
                                                                     repo_path=tmp_path / "cdk")}
    fn = 'resource "aws_lambda_function" "f" {\n  function_name = "orders"\n  role = "r"\n}\n'
    assert "CF-CW-003" in _tf_ids(tmp_path / "tf-bare", fn)
    group = 'resource "aws_cloudwatch_log_group" "g" {\n  name = "/aws/lambda/orders"\n  retention_in_days = 30\n}\n'
    assert "CF-CW-003" not in _tf_ids(tmp_path / "tf-covered", fn + group)
    forever = group.replace("30", "0")
    ids = _tf_ids(tmp_path / "tf-zero", fn + forever)
    assert "CF-CW-001" in ids and "CF-CW-003" not in ids
    interpolated = 'resource "aws_lambda_function" "f" {\n  function_name = "${var.prefix}-orders"\n  role = "r"\n}\n'
    assert "CF-CW-003" not in _tf_ids(tmp_path / "tf-var", interpolated)
    task = ('resource "aws_ecs_task_definition" "t" {\n  family = "t"\n  container_definitions = jsonencode([{\n'
            '    name = "app", image = "i",\n    logConfiguration = { logDriver = "awslogs", options = '
            '{ "awslogs-group" = "/ecs/app" } }\n  }])\n}\n')
    assert "CF-CW-003" in _tf_ids(tmp_path / "tf-ecs", task)
    flow = 'resource "aws_flow_log" "f" {\n  vpc_id = "v"\n  traffic_type = "ALL"\n  log_group_name = "vpc-flow"\n}\n'
    assert "CF-CW-003" in _tf_ids(tmp_path / "tf-flow", flow)
    s3_flow = ('resource "aws_flow_log" "f" {\n  vpc_id = "v"\n  traffic_type = "ALL"\n'
               '  log_destination_type = "s3"\n  log_destination = "arn:aws:s3:::b"\n}\n')
    assert "CF-CW-003" not in _tf_ids(tmp_path / "tf-flow-s3", s3_flow)


# --- CF-BAK-006: backup rules that never delete ---------------------------------------------

def _plan(*lifecycles) -> dict:
    rules = []
    for i, lifecycle in enumerate(lifecycles):
        rule = {"RuleName": f"r{i}", "TargetBackupVault": "v"}
        if lifecycle is not None:
            rule["Lifecycle"] = lifecycle
        rules.append(rule)
    return {"Type": "AWS::Backup::BackupPlan", "Properties": {"BackupPlan": {
        "BackupPlanName": "p", "BackupPlanRule": rules}}}


@pytest.mark.parametrize("lifecycle,expected", [
    (None, {"CF-BAK-006"}),
    ({"MoveToColdStorageAfterDays": 30}, {"CF-BAK-006"}),
    ({"DeleteAfterDays": 3}, {"CF-BAK-003"}),
    ({"DeleteAfterDays": 35}, set()),
    ({"DeleteAfterDays": {"Ref": "Days"}}, set()),
])
def test_backup_rule_retention(tmp_path: Path, lifecycle, expected: set) -> None:
    ids = _cf_ids(tmp_path, {"P": _plan(lifecycle)})
    assert ids & {"CF-BAK-003", "CF-BAK-006"} == expected


def test_one_never_delete_finding_per_plan_naming_its_rules(tmp_path: Path) -> None:
    findings = [f for f in _cf(tmp_path, {"P": _plan(None, {"DeleteAfterDays": 35}, None)}) if f.id == "CF-BAK-006"]
    assert len(findings) == 1
    assert "r0" in findings[0].recommendation and "r2" in findings[0].recommendation
    assert "r1" not in findings[0].recommendation
    assert "CF-BAK-006" not in _cf_ids(tmp_path / "ref", {"P": {"Type": "AWS::Backup::BackupPlan",
                                                                "Properties": {"BackupPlan": {"Ref": "X"}}}})


def test_bak_006_on_terraform(tmp_path: Path) -> None:
    plan = ('resource "aws_backup_plan" "p" {\n  name = "p"\n  rule {\n    rule_name = "daily"\n'
            '    target_vault_name = "v"\n    schedule = "cron(0 5 * * ? *)"\n%s  }\n}\n')
    assert "CF-BAK-006" in _tf_ids(tmp_path / "none", plan % "")
    keep = plan % "    lifecycle {\n      delete_after = 35\n    }\n"
    assert "CF-BAK-006" not in _tf_ids(tmp_path / "keep", keep)
    cold = plan % "    lifecycle {\n      cold_storage_after = 30\n    }\n"
    assert "CF-BAK-006" in _tf_ids(tmp_path / "cold", cold)


# --- CF-MDB-001 and CF-EB-003 ---------------------------------------------------------------

def _mdb(**props) -> dict:
    return {"Type": "AWS::MemoryDB::Cluster", "Properties": {
        "ClusterName": "c", "NodeType": "db.t4g.small", "ACLName": "open-access", **props}}


def _archive(**props) -> dict:
    return {"Type": "AWS::Events::Archive", "Properties": {"SourceArn": "arn:bus", **props}}


@pytest.mark.parametrize("cid,resource,fires", [
    ("CF-MDB-001", _mdb(), True),
    ("CF-MDB-001", _mdb(SnapshotRetentionLimit=0), True),
    ("CF-MDB-001", _mdb(SnapshotRetentionLimit=1), False),
    ("CF-MDB-001", _mdb(SnapshotRetentionLimit={"Ref": "Days"}), False),
    ("CF-EB-003", _archive(), True),
    ("CF-EB-003", _archive(RetentionDays=0), True),
    ("CF-EB-003", _archive(RetentionDays=1), False),
    ("CF-EB-003", _archive(RetentionDays={"Ref": "Days"}), False),
])
def test_snapshot_and_archive_retention(tmp_path: Path, cid: str, resource: dict, fires: bool) -> None:
    assert (cid in _cf_ids(tmp_path, {"R": resource})) is fires


def test_mdb_and_archive_on_cdk_and_terraform(tmp_path: Path) -> None:
    out = tmp_path / "cdk" / "cdk.out"
    out.mkdir(parents=True)
    (out / "S.template.json").write_text(json.dumps({"Resources": {"M": _mdb(), "A": _archive()}}), encoding="utf-8")
    ids = {f.id for f in run_cf_rules_from_paths([out / "S.template.json"], repo_path=tmp_path / "cdk")}
    assert {"CF-MDB-001", "CF-EB-003"} <= ids
    mdb = 'resource "aws_memorydb_cluster" "m" {\n  name = "m"\n  node_type = "db.t4g.small"\n  acl_name = "open-access"\n%s}\n'
    assert "CF-MDB-001" in _tf_ids(tmp_path / "mdb", mdb % "")
    assert "CF-MDB-001" not in _tf_ids(tmp_path / "mdb-ok", mdb % "  snapshot_retention_limit = 1\n")
    arch = 'resource "aws_cloudwatch_event_archive" "a" {\n  name = "a"\n  event_source_arn = "arn:bus"\n%s}\n'
    assert "CF-EB-003" in _tf_ids(tmp_path / "eb", arch % "")
    assert "CF-EB-003" in _tf_ids(tmp_path / "eb-zero", arch % "  retention_days = 0\n")
    assert "CF-EB-003" not in _tf_ids(tmp_path / "eb-ok", arch % "  retention_days = 7\n")


def test_elasticache_backups_are_unchanged(tmp_path: Path) -> None:
    cache = {"Type": "AWS::ElastiCache::ReplicationGroup", "Properties": {
        "ReplicationGroupDescription": "d", "Engine": "redis", "CacheNodeType": "cache.t4g.small"}}
    ids = _cf_ids(tmp_path, {"C": cache})
    assert "CF-EC-004" in ids and "CF-MDB-001" not in ids


def test_a_dynamic_terraform_logging_config_is_not_judged(tmp_path: Path) -> None:
    fn = ('resource "aws_lambda_function" "f" {\n  function_name = "orders"\n  role = "r"\n'
          '  dynamic "logging_config" {\n    for_each = var.cfg\n    content {\n'
          '      log_group = logging_config.value\n    }\n  }\n}\n')
    assert "CF-CW-003" not in _tf_ids(tmp_path, fn)
