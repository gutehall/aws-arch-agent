"""CF-S3-006/007 (S3 storage classes), CF-DDB-003 (DynamoDB autoscaling) and gp2 launch
template block devices (CF-EBS-002) (DM3-548)."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import CF_COVERS_STATIC, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.environments import use_environments
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = {"CF-S3-006", "CF-S3-007", "CF-DDB-003", "CF-EBS-002"}


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.id, f.evidence.split(" ")[0]) for f in findings if f.id in IDS}


def _cf(tmp_path: Path, resources: dict, name: str = "t.json") -> list[Finding]:
    path = tmp_path / name
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _bucket(**props) -> dict:
    return {"Type": "AWS::S3::Bucket", "Properties": props}


def _table(**props) -> dict:
    return {"Type": "AWS::DynamoDB::Table", "Properties": {
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        "SSESpecification": {"SSEEnabled": True}, **props}}


THROUGHPUT = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}


def _target(resource_id, namespace: str = "dynamodb") -> dict:
    return {"Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": {
        "ServiceNamespace": namespace, "ScalableDimension": "dynamodb:table:ReadCapacityUnits",
        "ResourceId": resource_id, "MinCapacity": 1, "MaxCapacity": 10}}


def _lt(*devices: dict) -> dict:
    return {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
        "MetadataOptions": {"HttpTokens": "required"}, "BlockDeviceMappings": list(devices)}}}


def test_cloudformation(tmp_path: Path) -> None:
    found = _found(_cf(tmp_path, {
        "Plain": _bucket(),
        "Tiered": _bucket(LifecycleConfiguration={"Rules": [{"Status": "Enabled", "Transitions": [
            {"StorageClass": "INTELLIGENT_TIERING", "TransitionInDays": 0}]}]}),
        "ExpireOnly": _bucket(LifecycleConfiguration={"Rules": [{"Status": "Enabled", "ExpirationInDays": 30}]}),
        "ExpireAndIt": _bucket(LifecycleConfiguration={"Rules": [{"Status": "Enabled", "ExpirationInDays": 30}]},
                               IntelligentTieringConfigurations=[{"Id": "a", "Status": "Enabled", "Tierings": []}]),
        "LifecycleIf": _bucket(LifecycleConfiguration={"Fn::If": ["X", {"Rules": []}, {"Ref": "AWS::NoValue"}]}),
        "NoScaling": _table(ProvisionedThroughput=THROUGHPUT),
        "ByRef": _table(ProvisionedThroughput=THROUGHPUT),
        "ByRefTarget": _target({"Fn::Join": ["", ["table/", {"Ref": "ByRef"}]]}),
        "ByName": _table(TableName="orders", ProvisionedThroughput=THROUGHPUT),
        "ByNameTarget": _target("table/orders"),
        "OnDemand": _table(BillingMode="PAY_PER_REQUEST"),
        "Other": _target("service/cluster/svc", namespace="ecs"),  # not DynamoDB: no effect
        "Gp2Lt": _lt({"DeviceName": "/dev/xvda", "Ebs": {"VolumeType": "gp2", "VolumeSize": 20, "Encrypted": True}}),
        "Gp3Lt": _lt({"DeviceName": "/dev/xvda", "Ebs": {"VolumeType": "gp3", "Encrypted": True}}),
        "UnsetLt": _lt({"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": True}}),  # the AMI decides
    }))
    assert found == {
        ("CF-S3-006", "Plain"), ("CF-S3-007", "ExpireOnly"),
        ("CF-DDB-003", "NoScaling"), ("CF-EBS-002", "Gp2Lt"),
    }


def test_details_and_estimates(tmp_path: Path) -> None:
    by = {(f.id, f.evidence.split(" ")[0]): f for f in _cf(tmp_path, {
        "NoScaling": _table(ProvisionedThroughput=THROUGHPUT),
        "Gp2Lt": _lt({"DeviceName": "/dev/xvdb", "Ebs": {"VolumeType": "gp2", "Encrypted": True}}),
    })}
    ddb = by[("CF-DDB-003", "NoScaling")]
    assert ddb.severity == "Medium" and ddb.monthly_cost_usd and ddb.monthly_cost_usd > 0
    lt = by[("CF-EBS-002", "Gp2Lt")]
    assert lt.recommendation.startswith("VolumeType is gp2 on /dev/xvdb.")
    assert lt.monthly_cost_usd is None  # a template launches some number of instances


def test_unlinked_scaling_target_covers_every_table(tmp_path: Path) -> None:
    found = _found(_cf(tmp_path, {
        "A": _table(ProvisionedThroughput=THROUGHPUT),
        "Shared": _target({"Fn::ImportValue": "TableId"}),
    }))
    assert found == set()


def test_dev_stack_skips_autoscaling_advice(tmp_path: Path) -> None:
    (tmp_path / "dev").mkdir()
    with use_environments(None, tmp_path):
        found = _found(_cf(tmp_path / "dev", {"T": _table(ProvisionedThroughput=THROUGHPUT)}, "stack.json"))
    assert ("CF-DDB-003", "T") not in found  # CF-ENV-006 says use on demand instead


def test_replaces_the_cdk_source_rules() -> None:
    assert CF_COVERS_STATIC["CF-S3-006"] == ("COST-013",)
    assert CF_COVERS_STATIC["CF-S3-007"] == ("COST-007",)
    assert CF_COVERS_STATIC["CF-DDB-003"] == ("COST-003",)


TF = """\
resource "aws_s3_bucket" "plain" {
  bucket = "plain"
}

resource "aws_s3_bucket" "tiered" {
  bucket = "tiered"
}

resource "aws_s3_bucket_lifecycle_configuration" "tiered" {
  bucket = aws_s3_bucket.tiered.id
  rule {
    id     = "t"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_s3_bucket" "expire" {
  bucket = "expire"
}

resource "aws_s3_bucket_lifecycle_configuration" "expire" {
  bucket = aws_s3_bucket.expire.id
  rule {
    id     = "e"
    status = "Enabled"
    expiration {
      days = 30
    }
  }
}

resource "aws_s3_bucket" "expire_it" {
  bucket = "expire-it"
}

resource "aws_s3_bucket_lifecycle_configuration" "expire_it" {
  bucket = aws_s3_bucket.expire_it.id
  rule {
    id     = "e"
    status = "Enabled"
    expiration {
      days = 30
    }
  }
}

resource "aws_s3_bucket_intelligent_tiering_configuration" "expire_it" {
  bucket = aws_s3_bucket.expire_it.id
  name   = "all"
  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
}

resource "aws_s3_bucket" "legacy" {
  bucket = "legacy"
  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
}

resource "aws_dynamodb_table" "orders" {
  name           = "orders"
  hash_key       = "id"
  read_capacity  = 5
  write_capacity = 5
}

resource "aws_appautoscaling_target" "orders" {
  service_namespace  = "dynamodb"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  resource_id        = "table/${aws_dynamodb_table.orders.name}"
  min_capacity       = 5
  max_capacity       = 50
}

resource "aws_dynamodb_table" "users" {
  name           = "users"
  hash_key       = "id"
  read_capacity  = 5
  write_capacity = 5
}

resource "aws_dynamodb_table" "events" {
  name         = "events"
  hash_key     = "id"
  billing_mode = "PAY_PER_REQUEST"
}

resource "aws_launch_template" "gp2" {
  metadata_options {
    http_tokens = "required"
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type = "gp2"
      encrypted   = true
    }
  }
}

resource "aws_launch_template" "from_var" {
  metadata_options {
    http_tokens = "required"
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type = var.type
      encrypted   = true
    }
  }
}
"""


def test_terraform(tmp_path: Path) -> None:
    module = tmp_path / "infra"
    module.mkdir()
    (module / "main.tf").write_text(TF, encoding="utf-8")
    findings = run_resource_checks(resources_from_terraform(module), module)
    assert _found(findings) == {
        ("CF-S3-006", "aws_s3_bucket.plain"), ("CF-S3-007", "aws_s3_bucket.expire"),
        ("CF-DDB-003", "aws_dynamodb_table.users"), ("CF-EBS-002", "aws_launch_template.gp2"),
    }
    # An unknown volume type hides only the gp2 check, not encryption.
    assert not any(f.id == "CF-EBS-001" for f in findings)
    fixes = {(f.id, f.evidence.split(" ")[0]): f.suggested_code or ""
             for f in attach_fixes([f for f in findings if f.id in IDS], "terraform")}
    assert 'resource "aws_s3_bucket_lifecycle_configuration" "plain"' in fixes[("CF-S3-006", "aws_s3_bucket.plain")]
    assert "aws_dynamodb_table.users.name" in fixes[("CF-DDB-003", "aws_dynamodb_table.users")]
    assert 'volume_type = "gp3"' in fixes[("CF-EBS-002", "aws_launch_template.gp2")]


def test_rule_shapes(tmp_path: Path) -> None:
    found = _found(_cf(tmp_path, {
        "Singular": _bucket(LifecycleConfiguration={"Rules": [
            {"Status": "Enabled", "Transition": {"StorageClass": "GLACIER", "TransitionInDays": 90}}]}),
        "Noncurrent": _bucket(LifecycleConfiguration={"Rules": [
            {"Status": "Enabled", "NoncurrentVersionTransitions": [{"StorageClass": "GLACIER", "TransitionInDays": 30}]}]}),
        "AllDisabled": _bucket(LifecycleConfiguration={"Rules": [
            {"Status": "Disabled", "Transitions": [{"StorageClass": "GLACIER", "TransitionInDays": 30}]}]}),
        "DisabledMove": _bucket(LifecycleConfiguration={"Rules": [
            {"Status": "Enabled", "ExpirationInDays": 30},
            {"Status": "Disabled", "Transitions": [{"StorageClass": "GLACIER", "TransitionInDays": 30}]}]}),
        "RuleIf": _bucket(LifecycleConfiguration={"Rules": [{"Fn::If": ["X", {"Status": "Enabled"}, {"Ref": "AWS::NoValue"}]}]}),
    }))
    assert found == {("CF-S3-006", "AllDisabled"), ("CF-S3-007", "DisabledMove")}


def test_index_targets_do_not_cover_the_table(tmp_path: Path) -> None:
    found = _found(_cf(tmp_path, {
        "Orders": _table(TableName="orders", ProvisionedThroughput=THROUGHPUT),
        "IndexOnly": _target({"Fn::Sub": "table/${Orders}/index/by-date"}),
        "LiteralIndex": _target("table/orders/index/by-date"),
        "Other": _table(TableName="orders-archive", ProvisionedThroughput=THROUGHPUT),
        "OtherByName": _target("table/orders-archive"),
    }))
    assert found == {("CF-DDB-003", "Orders")}  # the index targets neither cover nor hide it


def test_terraform_dynamic_lifecycle_blocks_are_not_judged(tmp_path: Path) -> None:
    module = tmp_path / "infra"
    module.mkdir()
    (module / "main.tf").write_text("""\
resource "aws_s3_bucket" "dyn_inline" {
  bucket = "a"
  dynamic "lifecycle_rule" {
    for_each = var.rules
    content {
      enabled = true
    }
  }
}

resource "aws_s3_bucket" "dyn_transition" {
  bucket = "b"
}

resource "aws_s3_bucket_lifecycle_configuration" "dyn_transition" {
  bucket = aws_s3_bucket.dyn_transition.id
  rule {
    id     = "r"
    status = "Enabled"
    dynamic "transition" {
      for_each = var.transitions
      content {
        days          = transition.value
        storage_class = "GLACIER"
      }
    }
  }
}

resource "aws_s3_bucket" "disabled" {
  bucket = "c"
}

resource "aws_s3_bucket_lifecycle_configuration" "disabled" {
  bucket = aws_s3_bucket.disabled.id
  rule {
    id     = "r"
    status = "Disabled"
    expiration {
      days = 30
    }
  }
}
""", encoding="utf-8")
    found = _found(run_resource_checks(resources_from_terraform(module), module))
    assert found == {("CF-S3-006", "aws_s3_bucket.disabled")}
