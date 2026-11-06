"""CF-DEL-001: stateful resources whose data is deleted with the stack (DM3-539)."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

ID = "CF-DEL-001"
STATEFUL = {
    "Db": "AWS::RDS::DBInstance",
    "Cluster": "AWS::RDS::DBCluster",
    "Table": "AWS::DynamoDB::Table",
    "Bucket": "AWS::S3::Bucket",
    "Fs": "AWS::EFS::FileSystem",
    "Logs": "AWS::Logs::LogGroup",
}


def _found(findings: list[Finding]) -> set[str]:
    return {f.evidence.split(" ")[0] for f in findings if f.id == ID}


def _cf(tmp_path: Path, resources: dict, name: str = "t.json") -> list[Finding]:
    path = tmp_path / name
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == ID]


def _r(rtype: str, **attrs) -> dict:
    return {"Type": rtype, "Properties": {}, **attrs}


def test_cloudformation_each_type_with_and_without_retention(tmp_path: Path) -> None:
    resources: dict = {}
    for name, rtype in STATEFUL.items():
        resources[f"{name}Plain"] = _r(rtype)
        resources[f"{name}Delete"] = _r(rtype, DeletionPolicy="Delete", UpdateReplacePolicy="Delete")
        resources[f"{name}Kept"] = _r(rtype, DeletionPolicy="Retain", UpdateReplacePolicy="Retain")
        resources[f"{name}OnlyDelete"] = _r(rtype, DeletionPolicy="Retain")  # replacement deletes
    resources["DbSnap"] = _r("AWS::RDS::DBInstance", DeletionPolicy="Snapshot", UpdateReplacePolicy="Snapshot")
    resources["ClusterSnap"] = _r("AWS::RDS::DBCluster", UpdateReplacePolicy="Snapshot")  # default Snapshot
    resources["TableOnCreate"] = _r(
        "AWS::DynamoDB::Table", DeletionPolicy="RetainExceptOnCreate", UpdateReplacePolicy="Retain")
    # Snapshot is not supported for buckets: CloudFormation deletes them.
    resources["BucketSnap"] = _r("AWS::S3::Bucket", DeletionPolicy="Snapshot", UpdateReplacePolicy="Snapshot")
    resources["BucketIf"] = _r(
        "AWS::S3::Bucket", DeletionPolicy={"Fn::If": ["Prod", "Retain", "Delete"]}, UpdateReplacePolicy="Retain")
    # Fn::If is not judged, but a missing UpdateReplacePolicy still deletes on replacement.
    resources["DbIfNoReplace"] = _r("AWS::RDS::DBInstance", DeletionPolicy={"Fn::If": ["Prod", "Snapshot", "Delete"]})
    # RetainExceptOnCreate is not an UpdateReplacePolicy value.
    resources["TableBadReplace"] = _r(
        "AWS::DynamoDB::Table", DeletionPolicy="Retain", UpdateReplacePolicy="RetainExceptOnCreate")
    for name in ("Table", "Fs", "Logs"):  # these cannot be snapshotted
        resources[f"{name}Snap"] = _r(STATEFUL[name], DeletionPolicy="Snapshot", UpdateReplacePolicy="Snapshot")
    resources["Member"] = {"Type": "AWS::RDS::DBInstance", "Properties": {"DBClusterIdentifier": {"Ref": "Cluster"}}}
    resources["Queue"] = _r("AWS::SQS::Queue")  # not stateful here
    findings = _cf(tmp_path, resources)
    expected = {f"{n}{s}" for n in STATEFUL for s in ("Plain", "Delete", "OnlyDelete")} | {
        "BucketSnap", "DbIfNoReplace", "TableBadReplace", "TableSnap", "FsSnap", "LogsSnap"}
    assert _found(findings) == expected
    assert {f.severity for f in findings} == {"Medium"}
    assert {f.category for f in findings} == {"Reliability"}

    by_name = {f.evidence.split(" ")[0]: f for f in findings}
    assert by_name["BucketPlain"].recommendation.startswith(
        "DeletionPolicy and UpdateReplacePolicy do not keep the data")
    assert "Set DeletionPolicy and UpdateReplacePolicy to Retain." in by_name["BucketPlain"].recommendation
    # A standalone RDS instance is snapshotted on delete by default; replacement still deletes it.
    assert by_name["DbPlain"].recommendation.startswith("UpdateReplacePolicy does not keep the data")
    assert "to Snapshot or Retain" in by_name["DbPlain"].recommendation
    assert by_name["DbIfNoReplace"].recommendation.startswith("UpdateReplacePolicy does not keep")


def test_cloudformation_fixes(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Bucket": _r("AWS::S3::Bucket"),
        "Db": _r("AWS::RDS::DBInstance"),
        "Cluster": _r("AWS::RDS::DBCluster"),
    })
    attach_fixes(findings, "cloudformation")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert "Type: AWS::S3::Bucket\n  DeletionPolicy: Retain\n  UpdateReplacePolicy: Retain" in code["Bucket"]
    assert "DeletionPolicy: Snapshot\n  UpdateReplacePolicy: Snapshot" in code["Db"]
    assert "Type: AWS::RDS::DBCluster\n  DeletionPolicy: Snapshot" in code["Cluster"]
    assert all("In CDK" not in f.recommendation for f in findings)


def _cdk(rtype: str, policy: str | None) -> dict:
    """A resource as cdk synth writes it; removalPolicy sets both policies."""
    body: dict = {"Type": rtype, "Properties": {}, "Metadata": {"aws:cdk:path": "App/Stack/Res/Resource"}}
    if policy:
        body["DeletionPolicy"] = body["UpdateReplacePolicy"] = policy
    return body


def test_cdk_synth_output_reports_removal_policy_destroy(tmp_path: Path) -> None:
    out = tmp_path / "cdk.out"
    out.mkdir()
    resources: dict = {}
    for name, rtype in STATEFUL.items():
        resources[f"{name}Destroy"] = _cdk(rtype, "Delete")  # removalPolicy: RemovalPolicy.DESTROY
        resources[f"{name}Retain"] = _cdk(rtype, "Retain")  # the L2 default, or RETAIN
    resources["DbSnapshot"] = _cdk("AWS::RDS::DBInstance", "Snapshot")  # SNAPSHOT
    findings = _cf(out, resources, "Stack.template.json")
    assert _found(findings) == {f"{n}Destroy" for n in STATEFUL}
    assert all(
        f.recommendation.endswith("In CDK: removalPolicy: RemovalPolicy.RETAIN (or SNAPSHOT for RDS), not DESTROY.")
        for f in findings
    )


DELETION_TF = """\
resource "aws_db_instance" "plain" {
  engine = "postgres"
}

resource "aws_db_instance" "kept" {
  engine = "postgres"
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_rds_cluster" "plain" {
  engine = "aurora-postgresql"
}

resource "aws_rds_cluster" "kept" {
  engine = "aurora-postgresql"
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_dynamodb_table" "plain" {
  name     = "t"
  hash_key = "id"
}

resource "aws_dynamodb_table" "kept" {
  name     = "t"
  hash_key = "id"
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "plain" {
  bucket = "plain"
}

resource "aws_s3_bucket" "off" {
  bucket = "off"
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket" "other_lifecycle" {
  bucket = "other"
  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_s3_bucket" "kept" {
  bucket = "kept"
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_efs_file_system" "plain" {
  encrypted = true
}

resource "aws_efs_file_system" "kept" {
  encrypted = true
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "plain" {
  name = "plain"
}

resource "aws_cloudwatch_log_group" "kept" {
  name = "kept"
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_rds_cluster" "named_from_var" {
  cluster_identifier = var.name
  engine             = "aurora-postgresql"
}

resource "aws_s3_bucket" "from_var" {
  bucket = "v"
  lifecycle {
    prevent_destroy = var.keep
  }
}

resource "aws_sqs_queue" "q" {
  name = "q"
}
"""


def _tf(tmp_path: Path) -> list[Finding]:
    # A neutral module directory: pytest's own ("test_...") would read as a dev stack (DM3-544).
    module = tmp_path / "infra"
    module.mkdir(exist_ok=True)
    (module / "main.tf").write_text(DELETION_TF, encoding="utf-8")
    resources = resources_from_terraform(module)
    return [f for f in run_resource_checks(resources, module) if f.id == ID]


def test_terraform_prevent_destroy_clears_the_finding(tmp_path: Path) -> None:
    findings = _tf(tmp_path)
    assert _found(findings) == {
        "aws_db_instance.plain", "aws_rds_cluster.plain", "aws_rds_cluster.named_from_var",
        "aws_dynamodb_table.plain",
        "aws_s3_bucket.plain", "aws_s3_bucket.off", "aws_s3_bucket.other_lifecycle",
        "aws_efs_file_system.plain", "aws_cloudwatch_log_group.plain",
    }
    assert all(f.line for f in findings)
    assert all(f.recommendation.startswith("lifecycle.prevent_destroy is not true") for f in findings)


def test_terraform_fixes(tmp_path: Path) -> None:
    findings = attach_fixes(_tf(tmp_path), "terraform")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert code["aws_dynamodb_table.plain"].startswith('resource "aws_dynamodb_table" "plain" {')
    assert "prevent_destroy = true" in code["aws_dynamodb_table.plain"]
    assert all("In CDK" not in f.recommendation for f in findings)
