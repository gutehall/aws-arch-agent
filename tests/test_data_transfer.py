"""COST 8: data transfer. Data transfer modeling (REPO-094) and components chosen for
transfer cost (REPO-095)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import DataTransferNotOptimised, DataTransferUnmodelled

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}
RULES = (DataTransferUnmodelled(), DataTransferNotOptimised())


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object, env: str = "prod") -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / env / _PATHS[source], body)


# REPO-094: data transfer modeling.

MULTI_AZ_DB = {
    "cdk": "new rds.DatabaseInstance(this, 'Db', { engine, multiAz: true });\n",
    "cloudformation": {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
        "MultiAZ": True}}},
    "terraform": 'resource "aws_db_instance" "db" {\n  multi_az = true\n}\n',
}
SINGLE_AZ_DB = {
    "cdk": "new rds.DatabaseInstance(this, 'Db', { engine, multiAz: false });\n",
    "cloudformation": {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
        "MultiAZ": False}}},
    "terraform": 'resource "aws_db_instance" "db" {\n  multi_az = false\n}\n',
}
S3_CRR = {
    "cdk": "new s3.CfnBucket(this, 'B', { replicationConfiguration: { rules: [] } });\n",
    "cloudformation": {"B": {"Type": "AWS::S3::Bucket", "Properties": {
        "ReplicationConfiguration": {"Role": "arn", "Rules": []}}}},
    "terraform": 'resource "aws_s3_bucket_replication_configuration" "b" {\n'
                 '  bucket = "b"\n}\n',
}
DDB_REPLICA = {
    "cdk": "new dynamodb.TableV2(this, 'T', { replicas: [{ region: 'eu-west-1' }] });\n",
    "cloudformation": {"T": {"Type": "AWS::DynamoDB::GlobalTable", "Properties": {
        "Replicas": [{"Region": "eu-west-1"}]}}},
    "terraform": 'resource "aws_dynamodb_table" "t" {\n  replica {\n'
                 '    region_name = "eu-west-1"\n  }\n}\n',
}
BACKUP_COPY = {
    "cdk": "new backup.BackupPlanRule({ copyActions: [{ destinationBackupVault: v }] });\n",
    "cloudformation": {"P": {"Type": "AWS::Backup::BackupPlan", "Properties": {
        "BackupPlan": {"BackupPlanRule": [{"CopyActions": [{"DestinationBackupVaultArn": "a"}]}]}}}},
    "terraform": 'resource "aws_backup_plan" "p" {\n  rule {\n    copy_action {\n'
                 '      destination_vault_arn = "arn"\n    }\n  }\n}\n',
}
ASG_SUBNETS = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Web', { vpc });\n",
    "cloudformation": {"Web": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "VPCZoneIdentifier": ["subnet-a", "subnet-b"]}}},
    "terraform": 'resource "aws_autoscaling_group" "web" {\n'
                 '  vpc_zone_identifier = ["subnet-a", "subnet-b"]\n}\n',
}
ASG_ONE_SUBNET = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Web', { vpc });\n"
           "new ec2.Vpc(this, 'V', { maxAzs: 1 });\n",
    "cloudformation": {"Web": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "VPCZoneIdentifier": ["subnet-a"]}}},
    "terraform": 'resource "aws_autoscaling_group" "web" {\n'
                 '  vpc_zone_identifier = ["subnet-a"]\n}\n',
}
KINDS = {"multi_az": MULTI_AZ_DB, "crr": S3_CRR, "ddb": DDB_REPLICA, "backup": BACKUP_COPY,
         "asg": ASG_SUBNETS}
TRANSFER_TAG = {
    "cdk": "Tags.of(this).add('DataTransfer', '2 TB per month');\n",
    "cloudformation": {"Tagged": {"Type": "AWS::S3::Bucket", "Properties": {
        "Tags": [{"Key": "CrossAZTraffic", "Value": "low"}]}}},
    "terraform": 'provider "aws" {\n  default_tags {\n    tags = {\n'
                 '      TransferCost = "low"\n    }\n  }\n}\n',
}


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("source", SOURCES)
def test_cross_az_or_region_resource_fires_repo_094(tmp_path: Path, source: str,
                                                   kind: str) -> None:
    _stack(tmp_path, source, KINDS[kind][source])
    (hit,) = DataTransferUnmodelled().run(tmp_path)
    assert hit.id == "REPO-094"
    assert f"prod/{_PATHS[source]}" in hit.evidence and "searched" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_single_az_resource_is_silent_repo_094(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SINGLE_AZ_DB[source])
    assert DataTransferUnmodelled().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_one_subnet_fleet_is_silent_repo_094(tmp_path: Path, source: str) -> None:
    if source == "cdk":
        _stack(tmp_path, source, "new ec2.Vpc(this, 'V', { maxAzs: 1 });\n"
               "new autoscaling.AutoScalingGroup(this, 'Web', { vpc });\n")
    else:
        _stack(tmp_path, source, ASG_ONE_SUBNET[source])
    assert DataTransferUnmodelled().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_transfer_tag_passes_repo_094(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, MULTI_AZ_DB[source], TRANSFER_TAG[source])
    assert DataTransferUnmodelled().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/data-transfer.md", "Cross-AZ traffic is about 3 TB per month.\n"),
    ("README.md", "# App\n\n## Data transfer\n\nRDS replication to the standby, 500 GB.\n"),
    ("docs/egress.md", "Egress goes through CloudFront.\n"),
    ("docs/cost.md", "# Cost\n\n## Cross-AZ traffic\n\nAurora readers: $40 per month.\n"),
))
def test_transfer_note_passes_repo_094(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", MULTI_AZ_DB["terraform"])
    _write(tmp_path / path, text)
    assert DataTransferUnmodelled().run(tmp_path) == []


def test_note_without_size_or_service_does_not_pass_repo_094(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", MULTI_AZ_DB["terraform"])
    _write(tmp_path / "docs/data-transfer.md", "TODO.\n")
    assert DataTransferUnmodelled().run(tmp_path)


@pytest.mark.parametrize("comment", ("# data transfer: 2 TB a month between AZs",
                                     "# cross-AZ traffic is small"))
def test_comment_on_previous_line_passes_repo_094(tmp_path: Path, comment: str) -> None:
    _stack(tmp_path, "terraform", comment + "\n" + MULTI_AZ_DB["terraform"].replace(
        "multi_az = true", "multi_az = true"))
    # comment sits above the resource block, two lines before multi_az: not adjacent
    assert DataTransferUnmodelled().run(tmp_path)
    _stack(tmp_path, "terraform", 'resource "aws_db_instance" "db" {\n  ' + comment
           + "\n  multi_az = true\n}\n")
    assert DataTransferUnmodelled().run(tmp_path) == []


def test_comment_on_same_line_passes_repo_094(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", "new rds.DatabaseInstance(this, 'Db', { multiAz: true }); "
           "// cross-AZ replication, 100 GB a month\n")
    assert DataTransferUnmodelled().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_094(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", MULTI_AZ_DB["terraform"], env=env)
    assert DataTransferUnmodelled().run(tmp_path) == []


def test_no_cross_az_resources_is_silent_repo_094(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
    assert DataTransferUnmodelled().run(tmp_path) == []


def test_other_cross_az_kinds_repo_094(tmp_path: Path) -> None:
    for text in (
        'resource "aws_elasticache_replication_group" "c" {\n  num_cache_clusters = 2\n}\n',
        'resource "aws_opensearch_domain" "d" {\n  cluster_config {\n'
        '    zone_awareness_enabled = true\n  }\n}\n',
        'resource "aws_msk_cluster" "k" {\n  number_of_broker_nodes = 3\n}\n',
        'resource "aws_rds_cluster_instance" "a" {}\nresource "aws_rds_cluster_instance" "b" {}\n',
        'resource "aws_efs_replication_configuration" "e" {}\n',
        'resource "aws_ebs_snapshot_copy" "s" {}\n',
    ):
        _stack(tmp_path, "terraform", text)
        assert DataTransferUnmodelled().run(tmp_path), text


def test_python_cdk_repo_094(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "rds.DatabaseInstance(self, 'Db', engine=e, multi_az=True)\n")
    (hit,) = DataTransferUnmodelled().run(tmp_path)
    assert "app.py:1" in hit.evidence
    _write(tmp_path / "app.py", "# data transfer: 1 TB per month\n"
           "rds.DatabaseInstance(self, 'Db', engine=e, multi_az=True)\n")
    assert DataTransferUnmodelled().run(tmp_path) == []


def test_python_source_snippets_do_not_match_repo_094(tmp_path: Path) -> None:
    _write(tmp_path / "snippets.py", 'FIX = """MultiAZ: true\n"""\nx = {"MultiAZ": True}\n')
    assert DataTransferUnmodelled().run(tmp_path) == []


def test_silent_on_this_repo() -> None:
    root = Path(__file__).resolve().parent.parent
    assert DataTransferUnmodelled().run(root) == []
    assert DataTransferNotOptimised().run(root) == []


# REPO-095: components chosen for transfer cost.

NAT = {
    "cdk": "new ec2.Vpc(this, 'V', { natGateways: 1 });\n",
    "cloudformation": {"Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {}}},
    "terraform": 'resource "aws_nat_gateway" "n" {\n  subnet_id = "s"\n}\n',
}
BUCKET = {
    "cdk": "new s3.Bucket(this, 'Data');\n",
    "cloudformation": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}},
    "terraform": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n',
}
TABLE = {
    "cdk": "new dynamodb.Table(this, 'T', { partitionKey });\n",
    "cloudformation": {"T": {"Type": "AWS::DynamoDB::Table", "Properties": {}}},
    "terraform": 'resource "aws_dynamodb_table" "t" {\n  name = "t"\n}\n',
}
VPC_LAMBDA = {
    "cdk": "new lambda.Function(this, 'Fn', { runtime, handler, code, vpc });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {
        "VpcConfig": {"SubnetIds": ["subnet-a", "subnet-b"]}}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  vpc_config {\n'
                 '    subnet_ids = ["a", "b"]\n  }\n}\n',
}
PLAIN_LAMBDA = {
    "cdk": "new lambda.Function(this, 'Fn', { runtime, handler, code });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  runtime = "python3.12"\n}\n',
}
ECS_TASK = {
    "cdk": "new ecs.FargateService(this, 'Api', { cluster, taskDefinition });\n",
    "cloudformation": {"Api": {"Type": "AWS::ECS::Service", "Properties": {
        "NetworkConfiguration": {"AwsvpcConfiguration": {"Subnets": ["a"]}}}}},
    "terraform": 'resource "aws_ecs_service" "api" {\n  network_configuration {\n'
                 '    subnets = ["a"]\n  }\n}\n',
}
S3_ENDPOINT = {
    "cdk": "vpc.addGatewayEndpoint('S3', { service: ec2.GatewayVpcEndpointAwsService.S3 });\n",
    "cloudformation": {"E": {"Type": "AWS::EC2::VPCEndpoint", "Properties": {
        "ServiceName": "com.amazonaws.eu-west-1.s3", "VpcEndpointType": "Gateway"}}},
    "terraform": 'resource "aws_vpc_endpoint" "s3" {\n'
                 '  service_name = "com.amazonaws.eu-west-1.s3"\n}\n',
}
DDB_ENDPOINT = {
    "cdk": "vpc.addGatewayEndpoint('Ddb', { service: ec2.GatewayVpcEndpointAwsService."
           "DYNAMODB });\n",
    "cloudformation": {"E2": {"Type": "AWS::EC2::VPCEndpoint", "Properties": {
        "ServiceName": "com.amazonaws.eu-west-1.dynamodb"}}},
    "terraform": 'resource "aws_vpc_endpoint" "ddb" {\n'
                 '  service_name = "com.amazonaws.eu-west-1.dynamodb"\n}\n',
}


@pytest.mark.parametrize("mover", (VPC_LAMBDA, ECS_TASK), ids=("lambda", "ecs"))
@pytest.mark.parametrize("source", SOURCES)
def test_vpc_mover_behind_nat_without_endpoint_fires_repo_095(tmp_path: Path, source: str,
                                                              mover: dict) -> None:
    _stack(tmp_path, source, NAT[source], BUCKET[source], mover[source])
    (hit,) = DataTransferNotOptimised().run(tmp_path)
    assert hit.id == "REPO-095"
    assert "NAT gateway" in hit.evidence and "S3" in hit.evidence
    assert f"prod/{_PATHS[source]}" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_dynamodb_without_endpoint_fires_repo_095(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, NAT[source], TABLE[source], VPC_LAMBDA[source])
    (hit,) = DataTransferNotOptimised().run(tmp_path)
    assert "DynamoDB" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_gateway_endpoint_passes_repo_095(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, NAT[source], BUCKET[source], VPC_LAMBDA[source],
           S3_ENDPOINT[source])
    assert DataTransferNotOptimised().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_endpoint_for_one_service_still_fires_for_the_other_repo_095(tmp_path: Path,
                                                                    source: str) -> None:
    _stack(tmp_path, source, NAT[source], BUCKET[source], TABLE[source], VPC_LAMBDA[source],
           S3_ENDPOINT[source])
    (hit,) = DataTransferNotOptimised().run(tmp_path)
    assert "DynamoDB" in hit.evidence and "S3 and" not in hit.evidence
    _stack(tmp_path, source, NAT[source], BUCKET[source], TABLE[source], VPC_LAMBDA[source],
           S3_ENDPOINT[source], DDB_ENDPOINT[source])
    assert DataTransferNotOptimised().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_no_nat_is_silent_repo_095(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source], VPC_LAMBDA[source])
    assert DataTransferNotOptimised().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_lambda_outside_vpc_is_silent_repo_095(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, NAT[source], BUCKET[source], PLAIN_LAMBDA[source])
    assert DataTransferNotOptimised().run(tmp_path) == []


def test_single_az_vpc_passes_repo_095(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", NAT["cdk"], BUCKET["cdk"], VPC_LAMBDA["cdk"],
           "new ec2.Vpc(this, 'One', { maxAzs: 1 });\n")
    assert DataTransferNotOptimised().run(tmp_path) == []


def test_cdk_default_vpc_has_a_nat_gateway_repo_095(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", "const vpc = new ec2.Vpc(this, 'V');\n", BUCKET["cdk"],
           VPC_LAMBDA["cdk"])
    assert DataTransferNotOptimised().run(tmp_path)
    _stack(tmp_path, "cdk", "const vpc = new ec2.Vpc(this, 'V', { natGateways: 0 });\n",
           BUCKET["cdk"], VPC_LAMBDA["cdk"])
    assert DataTransferNotOptimised().run(tmp_path) == []


def test_transfer_note_does_not_excuse_nat_path_repo_095(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", NAT["terraform"], BUCKET["terraform"],
           VPC_LAMBDA["terraform"])
    _write(tmp_path / "docs/data-transfer.md", "Lambda to S3, 2 TB per month.\n")
    assert DataTransferNotOptimised().run(tmp_path)


@pytest.mark.parametrize("kind", ("crr", "ddb", "backup"))
@pytest.mark.parametrize("source", SOURCES)
def test_cross_region_copy_without_reason_fires_repo_095(tmp_path: Path, source: str,
                                                        kind: str) -> None:
    _stack(tmp_path, source, KINDS[kind][source])
    (hit,) = DataTransferNotOptimised().run(tmp_path)
    assert "another Region" in hit.evidence and f"prod/{_PATHS[source]}" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_cross_region_copy_with_tag_or_endpoint_passes_repo_095(tmp_path: Path,
                                                                source: str) -> None:
    _stack(tmp_path, source, S3_CRR[source], TRANSFER_TAG[source])
    assert DataTransferNotOptimised().run(tmp_path) == []
    _stack(tmp_path, source, S3_CRR[source], S3_ENDPOINT[source])
    assert DataTransferNotOptimised().run(tmp_path) == []


def test_cross_region_copy_with_note_or_comment_passes_repo_095(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", S3_CRR["terraform"])
    _write(tmp_path / "docs/data-transfer.md", "CRR to eu-west-1 for DR: 200 GB per month.\n")
    assert DataTransferNotOptimised().run(tmp_path) == []
    (tmp_path / "docs/data-transfer.md").unlink()
    _stack(tmp_path, "terraform", "# data transfer: 200 GB a month for DR\n"
           + S3_CRR["terraform"])
    assert DataTransferNotOptimised().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_095(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", S3_CRR["terraform"], NAT["terraform"],
           BUCKET["terraform"], VPC_LAMBDA["terraform"], env=env)
    assert DataTransferNotOptimised().run(tmp_path) == []


def test_python_cdk_repo_095(tmp_path: Path) -> None:
    code = ("vpc = ec2.Vpc(self, 'V')\ns3.Bucket(self, 'Data')\n"
            "_lambda.Function(self, 'Fn', runtime=r, handler='h', code=c, vpc=vpc)\n")
    _write(tmp_path / "app.py", code)
    (hit,) = DataTransferNotOptimised().run(tmp_path)
    assert "Lambda function Fn in app.py:3" in hit.evidence
    _write(tmp_path / "app.py", code + "vpc.add_gateway_endpoint('S3', "
           "service=ec2.GatewayVpcEndpointAwsService.S3)\n")
    assert DataTransferNotOptimised().run(tmp_path) == []


# Both rules.

def _firing(rule_id: str, root: Path) -> None:
    if rule_id == "REPO-094":
        _stack(root, "terraform", MULTI_AZ_DB["terraform"])
    else:
        _stack(root, "terraform", NAT["terraform"], BUCKET["terraform"],
               VPC_LAMBDA["terraform"])


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _firing(rule.id, tmp_path)
    (hit,) = rule.run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", text)
    assert len(rule.run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", text)
    assert rule.run(empty) == []


@pytest.mark.parametrize("rule_id,practice", (
    ("REPO-094", "COST08-BP01"), ("REPO-095", "COST08-BP02"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 8"


def test_rules_run_by_default() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == set()
    assert {r.category for r in RULES} == {"Cost"}
    assert {r.severity for r in RULES} == {"Low"}
    assert {t for r in RULES for t in r.themes} == {"finops"}


def test_cost8_is_fully_checked() -> None:
    (cost8,) = [a for a in well_architected.answers([]) if a.question.id == "COST 8"]
    assert cost8.not_checked == ()


def test_cost8_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _firing("REPO-094", tmp_path)
    findings = DataTransferUnmodelled().run(tmp_path)
    (cost8,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 8"]
    assert not cost8.met
