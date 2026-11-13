"""REL 13: disaster recovery objectives, failover, drills and drift (REPO-052 to REPO-055)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    DisasterRecoveryDrift,
    DisasterRecoveryUntested,
    FailoverAutomationMissing,
    RecoveryObjectivesMissing,
    dr_replication,
    multi_region_deploys,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}
RULES = (RecoveryObjectivesMissing, FailoverAutomationMissing, DisasterRecoveryUntested,
         DisasterRecoveryDrift)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / "prod" / _PATHS[source], body)


BUCKET = {
    "cdk": "new s3.Bucket(this, 'Data');\n",
    "cloudformation": {"Data": {"Type": "AWS::S3::Bucket"}},
    "terraform": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n',
}
OBJECTIVE = {
    "cdk": "Tags.of(this).add('RTO', '4h');\nTags.of(this).add('RPO', '15m');\n",
    "cloudformation": {"Policy": {"Type": "AWS::ResilienceHub::ResiliencyPolicy", "Properties": {
        "Tier": "MissionCritical", "Policy": {"Region": {"RtoInSecs": 3600, "RpoInSecs": 900}}}}},
    "terraform": 'resource "aws_dynamodb_table" "orders" {\n  tags = {\n'
                 '    RecoveryPointObjective = "15m"\n  }\n}\n',
}
REPLICATION = {
    "cdk": "new s3.Bucket(this, 'Data', { replicationRules: [{ destination, priority: 1 }] });\n",
    "cloudformation": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {
        "ReplicationConfiguration": {"Role": "arn:aws:iam::1:role/r", "Rules": []}}}},
    "terraform": 'resource "aws_s3_bucket_replication_configuration" "data" {\n'
                 '  bucket = aws_s3_bucket.data.id\n}\n',
}
FAILOVER = {
    "cdk": "new route53.ARecord(this, 'Primary', { zone, target, failover: 'PRIMARY' });\n",
    "cloudformation": {"Health": {"Type": "AWS::Route53::HealthCheck", "Properties": {
        "HealthCheckConfig": {"Type": "HTTPS"}}}},
    "terraform": 'resource "aws_route53_record" "primary" {\n'
                 '  failover_routing_policy {\n    type = "PRIMARY"\n  }\n}\n',
}
DRILL = {
    "cdk": "new fis.CfnExperimentTemplate(this, 'RegionFailover', { description: 'drill' });\n",
    "cloudformation": {"Readiness": {"Type": "AWS::Route53RecoveryReadiness::ReadinessCheck",
                                     "Properties": {"ResourceSetName": "db"}}},
    "terraform": 'resource "aws_fis_experiment_template" "region_failover" {\n'
                 '  description = "drill"\n}\n',
}
SYNC = {
    "cdk": "new AppStack(app, 'Primary', { env: { region: 'us-east-1' } });\n"
           "new AppStack(app, 'Recovery', { env: { region: 'us-west-2' } });\n",
    "cloudformation": {"Sets": {"Type": "AWS::CloudFormation::StackSet", "Properties": {
        "StackSetName": "app", "PermissionModel": "SELF_MANAGED"}}},
    "terraform": 'module "primary" {\n  source = "./modules/app"\n'
                 '  providers = { aws = aws.east }\n}\n'
                 'module "recovery" {\n  source = "./modules/app"\n'
                 '  providers = { aws = aws.west }\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_data_store_without_objectives_fails_repo_052(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    (finding,) = RecoveryObjectivesMissing().run(tmp_path)
    assert finding.id == "REPO-052"
    assert "S3 bucket" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_recovery_objective_passes_repo_052(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source], OBJECTIVE[source])
    assert RecoveryObjectivesMissing().run(tmp_path) == []


def test_cdk_context_key_passes_repo_052(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", BUCKET["cdk"])
    _write(tmp_path / "prod" / "cdk.json", '{"context": {"rtoMinutes": 60}}\n')
    assert RecoveryObjectivesMissing().run(tmp_path) == []


def test_objective_in_prose_does_not_pass_repo_052(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", BUCKET["cdk"], "// our RTO is four hours and RPO: 15 minutes\n")
    _write(tmp_path / "README.md", "rto: 4h\nrpo: 15m\n")
    assert RecoveryObjectivesMissing().run(tmp_path)


def test_no_workload_gets_no_repo_052(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_sns_topic" "t" {\n  name = "t"\n}\n')
    assert RecoveryObjectivesMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_replication_without_failover_fails_repo_053(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, REPLICATION[source])
    (finding,) = FailoverAutomationMissing().run(tmp_path)
    assert finding.id == "REPO-053"
    assert finding.severity == "Medium"
    assert "S3 replication" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_failover_passes_repo_053(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, REPLICATION[source], FAILOVER[source])
    assert FailoverAutomationMissing().run(tmp_path) == []


@pytest.mark.parametrize("table", [
    "new dynamodb.TableV2(this, 'Orders', { partitionKey, replicas: [{ region: 'us-west-2' }] });\n",
    "new dynamodb.Table(this, 'Orders', { partitionKey, replicationRegions: ['us-west-2'] });\n",
])
def test_cdk_global_table_passes_repo_053(tmp_path: Path, table: str) -> None:
    _stack(tmp_path, "cdk", table)
    assert "DynamoDB global table" in dr_replication(tmp_path)
    assert FailoverAutomationMissing().run(tmp_path) == []


def test_terraform_global_table_passes_repo_053(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform",
           'resource "aws_dynamodb_table" "orders" {\n  name = "orders"\n'
           '  replica {\n    region_name = "us-west-2"\n  }\n}\n')
    assert FailoverAutomationMissing().run(tmp_path) == []


def test_cloudformation_global_table_passes_repo_053(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {"Orders": {"Type": "AWS::DynamoDB::GlobalTable"}})
    assert FailoverAutomationMissing().run(tmp_path) == []


@pytest.mark.parametrize("copy, kind", [
    ('resource "aws_rds_global_cluster" "g" {\n  global_cluster_identifier = "g"\n}\n',
     "Aurora global database"),
    ('resource "aws_db_instance" "replica" {\n'
     '  replicate_source_db = "arn:aws:rds:us-east-1:1:db:main"\n}\n',
     "RDS cross-Region read replica"),
    ('resource "aws_backup_plan" "p" {\n  rule {\n    copy_action {\n'
     '      destination_vault_arn = aws_backup_vault.dr.arn\n    }\n  }\n}\n',
     "AWS Backup copy action"),
])
def test_other_copies_fail_repo_053(tmp_path: Path, copy: str, kind: str) -> None:
    _stack(tmp_path, "terraform", copy)
    (finding,) = FailoverAutomationMissing().run(tmp_path)
    assert kind in finding.evidence


def test_same_region_read_replica_is_not_a_copy(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform",
           'resource "aws_db_instance" "replica" {\n'
           '  replicate_source_db = aws_db_instance.main.identifier\n}\n')
    assert dr_replication(tmp_path) == {}


def test_global_accelerator_in_two_regions_passes_repo_053(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", REPLICATION["terraform"],
           'resource "aws_globalaccelerator_endpoint_group" "east" {\n'
           '  endpoint_group_region = "us-east-1"\n}\n'
           'resource "aws_globalaccelerator_endpoint_group" "west" {\n'
           '  endpoint_group_region = "us-west-2"\n}\n')
    assert FailoverAutomationMissing().run(tmp_path) == []


def test_tested_restore_passes_repo_053(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", REPLICATION["terraform"],
           'resource "aws_backup_restore_testing_plan" "weekly" {\n'
           '  schedule_expression = "cron(0 3 ? * SUN *)"\n}\n')
    assert FailoverAutomationMissing().run(tmp_path) == []


@pytest.mark.parametrize("rule", [FailoverAutomationMissing, DisasterRecoveryUntested,
                                  DisasterRecoveryDrift])
def test_no_replication_gets_no_finding(tmp_path: Path, rule: type) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    assert rule().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_replication_without_drill_fails_repo_054(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, REPLICATION[source])
    (finding,) = DisasterRecoveryUntested().run(tmp_path)
    assert finding.id == "REPO-054"


@pytest.mark.parametrize("source", SOURCES)
def test_drill_passes_repo_054(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, REPLICATION[source], DRILL[source])
    assert DisasterRecoveryUntested().run(tmp_path) == []


@pytest.mark.parametrize("command", [
    "aws route53-recovery-cluster update-routing-control-state --routing-control-arn $ARN",
    "aws rds switchover-global-cluster --global-cluster-identifier g",
    "aws drs start-recovery --is-drill --source-servers id=s-1",
])
def test_drill_in_a_build_passes_repo_054(tmp_path: Path, command: str) -> None:
    _stack(tmp_path, "terraform", REPLICATION["terraform"])
    _write(tmp_path / ".github" / "workflows" / "dr.yml",
           f"on:\n  schedule:\n    - cron: '0 3 1 * *'\njobs:\n  drill:\n    steps:\n"
           f"      - run: {command}\n")
    assert DisasterRecoveryUntested().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_replication_without_drift_control_fails_repo_055(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, REPLICATION[source])
    (finding,) = DisasterRecoveryDrift().run(tmp_path)
    assert finding.id == "REPO-055"


@pytest.mark.parametrize("source", SOURCES)
def test_drift_control_passes_repo_055(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, REPLICATION[source], SYNC[source])
    assert DisasterRecoveryDrift().run(tmp_path) == []


def test_python_stack_in_two_regions_passes_repo_055(tmp_path: Path) -> None:
    _write(tmp_path / "app.py",
           "AppStack(app, 'Primary', env=cdk.Environment(region='us-east-1'))\n"
           "AppStack(app, 'Recovery', env=cdk.Environment(region='eu-west-1'))\n")
    assert multi_region_deploys(tmp_path) == {"stack AppStack in two Regions": "app.py"}


def test_stack_in_one_region_does_not_pass_repo_055(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", REPLICATION["cdk"],
           "new AppStack(app, 'Primary', { env: { region: 'us-east-1' } });\n"
           "new EdgeStack(app, 'Edge', { env: { region: 'us-west-2' } });\n")
    assert DisasterRecoveryDrift().run(tmp_path)


def test_module_with_one_provider_does_not_pass_repo_055(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", REPLICATION["terraform"],
           'module "a" {\n  source = "./modules/app"\n}\n'
           'module "b" {\n  source = "./modules/app"\n}\n')
    assert DisasterRecoveryDrift().run(tmp_path)


def test_drift_detection_in_a_build_passes_repo_055(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", REPLICATION["terraform"])
    _write(tmp_path / ".github" / "workflows" / "drift.yml",
           "on:\n  schedule:\n    - cron: '0 6 * * *'\njobs:\n  drift:\n    steps:\n"
           "      - run: terraform plan -detailed-exitcode -input=false\n")
    assert DisasterRecoveryDrift().run(tmp_path) == []


def test_saved_report_quoting_the_findings_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], REPLICATION["terraform"])
    hits = [f for rule in RULES for f in rule().run(tmp_path)]
    assert sorted(f.id for f in hits) == ["REPO-052", "REPO-053", "REPO-054", "REPO-055"]
    report = json.dumps({"findings": [hit.model_dump() for hit in hits]})
    prose = "".join(f"{h.title}\n{h.evidence}\n{h.recommendation}\n" for h in hits)
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", prose)
    assert sorted(f.id for rule in RULES for f in rule().run(tmp_path)) == [
        "REPO-052", "REPO-053", "REPO-054", "REPO-055"]
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", prose)
    assert [f for rule in RULES for f in rule().run(empty)] == []


def test_rules_map_to_rel13_and_run_by_default() -> None:
    assert well_architected.best_practices_of("REPO-052") == ("REL13-BP01",)
    assert well_architected.best_practices_of("REPO-053") == ("REL13-BP05",)
    assert well_architected.best_practices_of("REPO-054") == ("REL13-BP03",)
    assert well_architected.best_practices_of("REPO-055") == ("REL13-BP04",)
    for rule_id in ("REPO-052", "REPO-053", "REPO-054", "REPO-055"):
        assert rule_id not in ORG_RULE_IDS


def test_rel13_is_fully_checked_and_reads_met_without_findings() -> None:
    (rel13,) = [a for a in well_architected.answers([]) if a.question.id == "REL 13"]
    assert rel13.not_checked == ()
    assert rel13.met
