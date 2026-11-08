"""S3 ACLs and ownership, replication and Bucket Keys: CF-S3-008..012."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.report.doc_topics import RULE_TOPICS
from aws_arch_agent.rules.cf_template import (
    CF_COVERS_STATIC,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-S3-008", "CF-S3-009", "CF-S3-010", "CF-S3-011", "CF-S3-012")
_PARAM = {"Ref": "Param"}
_IF = {"Fn::If": ["C", "a", "b"]}
_VAR = 'variable "x" {}\n'
_ALL_ON = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
_METRICS_ON = {"Metrics": {"Status": "Enabled"}, "ReplicationTime": {"Status": "Enabled"}}


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


def _tf(tmp_path: Path, text: str, name: str = "main.tf") -> dict[str, set[str]]:
    (tmp_path / name).write_text(_VAR + text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / name))


def _bucket(**props: Any) -> dict:
    return {"Type": "AWS::S3::Bucket", "Properties": props}


def _owner(value: Any) -> dict:
    return {"Rules": [{"ObjectOwnership": value}]}


def _replication(*rules: Any) -> dict:
    return {"Role": "arn:aws:iam::111111111111:role/r", "Rules": list(rules)}


def _rule(status: Any = "Enabled", **destination: Any) -> dict:
    return {"Status": status, "Destination": {"Bucket": "arn:aws:s3:::dest", **destination}}


def _kms(algorithm: Any = "aws:kms", **rule: Any) -> dict:
    return {"ServerSideEncryptionConfiguration": [
        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm}, **rule}]}


# --- CF-S3-008 and CF-S3-009, CloudFormation ---


@pytest.mark.parametrize(("props", "expected"), [
    ({"OwnershipControls": _owner("ObjectWriter")}, {"CF-S3-008"}),
    ({"OwnershipControls": _owner("BucketOwnerPreferred")}, {"CF-S3-008"}),
    ({"OwnershipControls": _owner("BucketOwnerPreferred"), "AccessControl": "Private"}, {"CF-S3-008"}),
    ({"AccessControl": "AuthenticatedRead"}, {"CF-S3-008"}),
    ({"AccessControl": "BucketOwnerFullControl"}, {"CF-S3-008"}),
    # A public ACL reports once, as the public check.
    ({"AccessControl": "PublicRead"}, {"CF-S3-009"}),
    ({"AccessControl": "PublicReadWrite"}, {"CF-S3-009"}),
    ({"AccessControl": "PublicRead", "OwnershipControls": _owner("ObjectWriter")}, {"CF-S3-009"}),
    ({"AccessControl": "PublicRead", "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}, {"CF-S3-009"}),
    # S3 ignores or rejects a public ACL here, but the bucket still sets an ACL.
    ({"AccessControl": "PublicRead", "PublicAccessBlockConfiguration": _ALL_ON}, {"CF-S3-008"}),
    ({"AccessControl": "PublicRead", "PublicAccessBlockConfiguration": {"IgnorePublicAcls": True}}, {"CF-S3-008"}),
    ({"AccessControl": "PublicRead", "PublicAccessBlockConfiguration": {"BlockPublicAcls": "true"}}, {"CF-S3-008"}),
    ({"AccessControl": "PublicRead", "PublicAccessBlockConfiguration": {"IgnorePublicAcls": _PARAM}}, {"CF-S3-008"}),
    ({"AccessControl": "PublicRead", "PublicAccessBlockConfiguration": _IF}, {"CF-S3-008"}),
    # Unset ownership is BucketOwnerEnforced on a new bucket.
    ({}, set()),
    ({"AccessControl": "Private"}, set()),
    ({"OwnershipControls": _owner("BucketOwnerEnforced")}, set()),
    ({"OwnershipControls": _owner("BucketOwnerEnforced"), "AccessControl": "AuthenticatedRead"}, set()),
    ({"OwnershipControls": _owner("BucketOwnerEnforced"), "AccessControl": "PublicRead"}, set()),
    # Grants the log delivery group, not user access.
    ({"AccessControl": "LogDeliveryWrite"}, set()),
    ({"AccessControl": "LogDeliveryWrite", "OwnershipControls": _owner("ObjectWriter")}, set()),
    # Unknown values.
    ({"AccessControl": _PARAM}, set()),
    ({"AccessControl": _IF}, set()),
    ({"AccessControl": _PARAM, "OwnershipControls": _owner("ObjectWriter")}, set()),
    ({"OwnershipControls": _PARAM}, set()),
    ({"OwnershipControls": _owner(_PARAM)}, set()),
    ({"OwnershipControls": _owner(_PARAM), "AccessControl": "PublicRead"}, set()),
    ({"OwnershipControls": {"Rules": _IF}, "AccessControl": "AuthenticatedRead"}, set()),
])
def test_acls_cloudformation(tmp_path: Path, props: dict, expected: set[str]) -> None:
    found = _cf(tmp_path, {"B": _bucket(**props)})
    assert set(found) == expected


def _distribution(bucket: Any) -> dict:
    return {"Type": "AWS::CloudFront::Distribution", "Properties": {
        "DistributionConfig": {"Enabled": True, "Logging": {"Bucket": bucket}}}}


@pytest.mark.parametrize(("log_bucket", "reported"), [
    ({"Fn::GetAtt": ["Logs", "DomainName"]}, set()),  # the target itself
    ("logs-name.s3.amazonaws.com", set()),  # by literal name
    (_PARAM, set()),  # cannot be tied: counts for all
    ("other.s3.amazonaws.com", {"Logs"}),  # another bucket
    ({"Fn::GetAtt": ["Other", "DomainName"]}, {"Logs"}),
])
def test_cloudfront_log_target_needs_acls(tmp_path: Path, log_bucket: Any, reported: set[str]) -> None:
    found = _cf(tmp_path, {
        "Logs": _bucket(BucketName="logs-name", OwnershipControls=_owner("BucketOwnerPreferred")),
        "Other": _bucket(),
        "Dist": _distribution(log_bucket),
    })
    assert found.get("CF-S3-008", set()) == reported


# --- CF-S3-008 and CF-S3-009, Terraform ---

_TF_BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "bkt"\n}\n'


def _tf_acl(acl: str) -> str:
    return f'resource "aws_s3_bucket_acl" "a" {{\n  bucket = aws_s3_bucket.b.id\n  acl = {acl}\n}}\n'


def _tf_owner(value: str, bucket: str = "aws_s3_bucket.b.id") -> str:
    return (f'resource "aws_s3_bucket_ownership_controls" "o" {{\n  bucket = {bucket}\n'
            f'  rule {{\n    object_ownership = {value}\n  }}\n}}\n')


_TF_IGNORE = ('resource "aws_s3_bucket_public_access_block" "p" {\n  bucket = aws_s3_bucket.b.id\n'
              '  ignore_public_acls = true\n}\n')


@pytest.mark.parametrize(("text", "expected"), [
    (_tf_owner('"ObjectWriter"'), {"CF-S3-008"}),
    (_tf_owner('"BucketOwnerPreferred"') + _tf_acl('"private"'), {"CF-S3-008"}),
    (_tf_acl('"authenticated-read"'), {"CF-S3-008"}),
    (_tf_acl('"public-read"'), {"CF-S3-009"}),
    (_tf_acl('"public-read-write"'), {"CF-S3-009"}),
    (_tf_acl('"public-read"') + _tf_owner('"ObjectWriter"'), {"CF-S3-009"}),
    (_tf_acl('"public-read"') + _TF_IGNORE, {"CF-S3-008"}),
    ("", set()),
    (_tf_acl('"private"'), set()),
    (_tf_acl('"log-delivery-write"'), set()),
    (_tf_owner('"BucketOwnerEnforced"'), set()),
    (_tf_owner('"BucketOwnerEnforced"') + _tf_acl('"public-read"'), set()),
    (_tf_acl("var.x"), set()),
    (_tf_owner("var.x"), set()),
    (_tf_owner("var.x") + _tf_acl('"public-read"'), set()),
    (_tf_owner('"ObjectWriter"') + _tf_acl("var.x"), set()),
    # Grants are not read.
    ('resource "aws_s3_bucket_acl" "a" {\n  bucket = aws_s3_bucket.b.id\n'
     '  access_control_policy {\n    owner {\n      id = "1"\n    }\n  }\n}\n', set()),
    # A part the scan cannot tie to a bucket counts for all buckets.
    (_tf_acl('"public-read"') + _tf_owner('"BucketOwnerEnforced"', "var.x"), set()),
    ('resource "aws_s3_bucket_acl" "a" {\n  bucket = var.x\n  acl = "public-read"\n}\n', set()),
])
def test_acls_terraform(tmp_path: Path, text: str, expected: set[str]) -> None:
    assert set(_tf(tmp_path, _TF_BUCKET + text)) == expected


@pytest.mark.parametrize(("arguments", "expected"), [
    ('acl = "public-read"', {"CF-S3-009"}),
    ('acl = "public-read-write"', {"CF-S3-009"}),
    ('acl = "authenticated-read"', {"CF-S3-008"}),
    ('acl = "private"', set()),
    ('acl = var.x', set()),
    ('grant {\n    id = "1"\n    type = "CanonicalUser"\n    permissions = ["READ"]\n  }', set()),
    ('dynamic "grant" {\n    for_each = var.x\n    content {\n      type = "Group"\n    }\n  }', set()),
])
def test_inline_acl_terraform(tmp_path: Path, arguments: str, expected: set[str]) -> None:
    found = _tf(tmp_path, f'resource "aws_s3_bucket" "b" {{\n  {arguments}\n}}\n')
    assert set(found) == expected


def test_terraform_cloudfront_log_target(tmp_path: Path) -> None:
    text = (_tf_owner('"BucketOwnerPreferred"')
            + 'resource "aws_cloudfront_distribution" "d" {\n  logging_config {\n'
            '    bucket = aws_s3_bucket.b.bucket_domain_name\n  }\n}\n')
    assert "CF-S3-008" not in _tf(tmp_path, _TF_BUCKET + text)


# --- CF-S3-010, CloudFormation ---


@pytest.mark.parametrize(("logical_id", "props"), [
    ("CriticalData", {}),
    ("critical", {}),
    ("B", {"BucketName": "acme-critical-data"}),
    ("B", {"BucketName": "business_critical"}),
    ("B", {"Tags": [{"Key": "Tier", "Value": "critical"}]}),
    ("B", {"Tags": [{"Key": "Tier", "Value": "Mission-Critical"}]}),
    ("B", {"Tags": [{"Key": "Critical", "Value": "true"}]}),
    ("B", {"Tags": [{"Key": "critical", "Value": "yes"}]}),
])
def test_replication_critical_reports(tmp_path: Path, logical_id: str, props: dict) -> None:
    assert _cf(tmp_path, {logical_id: _bucket(**props)})["CF-S3-010"] == {logical_id}


@pytest.mark.parametrize(("logical_id", "props"), [
    ("Plain", {}),
    ("NonCritical", {}),
    ("noncritical", {}),
    ("B", {"BucketName": "acme-non-critical"}),
    ("B", {"BucketName": "not_critical"}),
    ("B", {"BucketName": {"Fn::Sub": "critical-${AWS::Region}"}}),
    ("B", {"Tags": [{"Key": "Critical", "Value": "false"}]}),
    ("B", {"Tags": [{"Key": "Critical", "Value": "no"}]}),
    ("B", {"Tags": [{"Key": "Criticality", "Value": "low"}]}),
    ("B", {"Tags": [{"Key": "Tier", "Value": "non-critical"}]}),
    ("B", {"Tags": [{"Key": "Tier", "Value": _PARAM}]}),
    ("B", {"Tags": [{"Key": "Description", "Value": "logs for critical alerts"}]}),
    # Already replicates, or may.
    ("Critical", {"ReplicationConfiguration": _replication(_rule(**_METRICS_ON))}),
    ("Critical", {"ReplicationConfiguration": _IF}),
])
def test_replication_critical_silent(tmp_path: Path, logical_id: str, props: dict) -> None:
    assert "CF-S3-010" not in _cf(tmp_path, {logical_id: _bucket(**props)})


def test_replication_prod_stack_reports_only_in_prod(tmp_path: Path) -> None:
    resources = {"Data": _bucket()}
    assert _cf(tmp_path, resources, "prod-stack.json")["CF-S3-010"] == {"Data"}
    assert "CF-S3-010" not in _cf(tmp_path, resources, "dev-stack.json")
    assert "CF-S3-010" not in _cf(tmp_path, resources, "stack.json")


@pytest.mark.parametrize("resources", [
    # Access log target, by reference, literal name, or ACL.
    {"Skipped": _bucket(), "Src": _bucket(ReplicationConfiguration=_replication(_rule(**_METRICS_ON)),
                                          LoggingConfiguration={"DestinationBucketName": {"Ref": "Skipped"}})},
    {"Skipped": _bucket(BucketName="the-target"),
     "Src": _bucket(ReplicationConfiguration=_replication(_rule(**_METRICS_ON)),
                    LoggingConfiguration={"DestinationBucketName": "the-target"})},
    {"Skipped": _bucket(AccessControl="LogDeliveryWrite")},
    # CloudFront and CloudTrail log targets.
    {"Skipped": _bucket(), "Dist": _distribution({"Fn::GetAtt": ["Skipped", "DomainName"]})},
    {"Skipped": _bucket(), "Trail": {"Type": "AWS::CloudTrail::Trail", "Properties": {
        "S3BucketName": {"Ref": "Skipped"}, "IsLogging": True}}},
    # Replication destination, by reference and by literal ARN.
    {"Skipped": _bucket(), "Src": _bucket(ReplicationConfiguration=_replication(
        {"Status": "Enabled", "Destination": {"Bucket": {"Fn::GetAtt": ["Skipped", "Arn"]}, **_METRICS_ON}}))},
    {"Skipped": _bucket(BucketName="dest"),
     "Src": _bucket(ReplicationConfiguration=_replication(_rule(**_METRICS_ON)))},
    # Named for logs or as a replica.
    {"AccessLogs": _bucket()},
    {"Skipped": _bucket(BucketName="acme-logging")},
    {"DataReplica": _bucket()},
])
def test_replication_skips_log_buckets_and_destinations(tmp_path: Path, resources: dict) -> None:
    assert "CF-S3-010" not in _cf(tmp_path, resources, "prod-stack.json")


def test_replication_critical_name_outweighs_a_log_word(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"CriticalLogs": _bucket()})
    assert found["CF-S3-010"] == {"CriticalLogs"}


def test_replication_logging_to_itself_is_not_a_log_bucket(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"Data": _bucket(LoggingConfiguration={"DestinationBucketName": {"Ref": "Data"}})},
                "prod-stack.json")
    assert found["CF-S3-010"] == {"Data"}


# --- CF-S3-010, Terraform ---

_TF_REPLICATION = """
resource "aws_s3_bucket_replication_configuration" "r" {
  bucket = aws_s3_bucket.b.id
  role   = "arn:aws:iam::111111111111:role/r"
  rule {
    status = "Enabled"
    destination {
      bucket = "arn:aws:s3:::dest"
    }
  }
}
"""


@pytest.mark.parametrize("text", [
    'resource "aws_s3_bucket" "critical_data" {}\n',
    'resource "aws_s3_bucket" "b" {\n  bucket = "acme-critical"\n}\n',
    'resource "aws_s3_bucket" "b" {\n  tags = {\n    Tier = "critical"\n  }\n}\n',
])
def test_replication_critical_terraform_reports(tmp_path: Path, text: str) -> None:
    assert "CF-S3-010" in _tf(tmp_path, text)


@pytest.mark.parametrize("text", [
    'resource "aws_s3_bucket" "b" {}\n',
    'resource "aws_s3_bucket" "b" {\n  bucket = var.x\n}\n',
    'resource "aws_s3_bucket" "b" {\n  tags = {\n    Tier = var.x\n  }\n}\n',
    'resource "aws_s3_bucket" "b" {\n  tags = {\n    Critical = false\n  }\n}\n',
    # The Terraform tag model keeps string values only, so a boolean value is unknown.
    'resource "aws_s3_bucket" "b" {\n  tags = {\n    Critical = true\n  }\n}\n',
    'resource "aws_s3_bucket" "non_critical" {}\n',
    # Replication on its own resource, inline, from a variable, dynamic, or not tied to a bucket.
    'resource "aws_s3_bucket" "critical" {}\n' + _TF_REPLICATION.replace("aws_s3_bucket.b.id", "aws_s3_bucket.critical.id"),
    'resource "aws_s3_bucket" "critical" {\n  replication_configuration {\n    role = "r"\n'
    '    rules {\n      status = "Enabled"\n      destination {\n        bucket = "d"\n      }\n    }\n  }\n}\n',
    'resource "aws_s3_bucket" "critical" {\n  dynamic "replication_configuration" {\n    for_each = var.x\n'
    '    content {\n      role = "r"\n    }\n  }\n}\n',
    'resource "aws_s3_bucket" "critical" {}\n' + _TF_REPLICATION.replace("aws_s3_bucket.b.id", "var.x"),
    'resource "aws_s3_bucket" "critical" {}\n' + _TF_REPLICATION.replace('status = "Enabled"', "status = var.x"),
])
def test_replication_terraform_silent(tmp_path: Path, text: str) -> None:
    assert "CF-S3-010" not in _tf(tmp_path, text)


def test_replication_prod_terraform_skips_targets(tmp_path: Path) -> None:
    text = """
resource "aws_s3_bucket" "data" {}
resource "aws_s3_bucket" "target" {}
resource "aws_s3_bucket" "replica_dest" {}
resource "aws_s3_bucket_logging" "l" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.target.id
}
resource "aws_s3_bucket" "src" {}
resource "aws_s3_bucket_replication_configuration" "r" {
  bucket = aws_s3_bucket.src.id
  role   = "r"
  rule {
    status = "Enabled"
    destination {
      bucket = aws_s3_bucket.replica_dest.arn
    }
  }
}
"""
    assert _tf(tmp_path, text, "prod.tf")["CF-S3-010"] == {"aws_s3_bucket.data"}


# --- CF-S3-011 ---


@pytest.mark.parametrize("rule", [
    _rule(),
    _rule(Metrics={"Status": "Enabled"}),
    _rule(ReplicationTime={"Status": "Enabled"}),
    _rule(Metrics={"Status": "Disabled"}, ReplicationTime={"Status": "Enabled"}),
    _rule(Metrics={"Status": "Enabled"}, ReplicationTime={"Status": "Disabled"}),
    # The destination bucket being a parameter does not hide settings the template spells out.
    {"Status": "Enabled", "Destination": {"Bucket": _PARAM}},
])
def test_metrics_reports(tmp_path: Path, rule: dict) -> None:
    found = _cf(tmp_path, {"B": _bucket(ReplicationConfiguration=_replication(rule))})
    assert found["CF-S3-011"] == {"B"}


@pytest.mark.parametrize("config", [
    _replication(_rule(**_METRICS_ON)),
    _replication(_rule(status="Disabled")),
    _replication(_rule(status=_PARAM)),
    _replication(_IF),
    _replication({"Status": "Enabled", "Destination": _IF}),
    _replication({"Status": "Enabled", "Destination": _PARAM}),
    _replication(_rule(Metrics=_IF, ReplicationTime={"Status": "Enabled"})),
    _replication(_rule(Metrics={"Status": _PARAM}, ReplicationTime={"Status": "Enabled"})),
    {"Role": "r", "Rules": _IF},
    _IF,
])
def test_metrics_silent(tmp_path: Path, config: Any) -> None:
    assert "CF-S3-011" not in _cf(tmp_path, {"B": _bucket(ReplicationConfiguration=config)})


def test_metrics_no_replication_is_silent(tmp_path: Path) -> None:
    assert "CF-S3-011" not in _cf(tmp_path, {"B": _bucket()})


_TF_ON = """
      metrics {
        status = "Enabled"
      }
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
"""


def _tf_rule(destination: str = "", status: str = '"Enabled"', bucket: str = '"arn:aws:s3:::dest"') -> str:
    return f"""
resource "aws_s3_bucket" "b" {{}}
resource "aws_s3_bucket_replication_configuration" "r" {{
  bucket = aws_s3_bucket.b.id
  role   = "r"
  rule {{
    status = {status}
    destination {{
      bucket = {bucket}
      {destination}
    }}
  }}
}}
"""


@pytest.mark.parametrize("text", [
    _tf_rule(),
    _tf_rule(bucket="var.x"),
    _tf_rule('metrics {\n  status = "Enabled"\n}'),
    _tf_rule(_TF_ON.replace('metrics {\n        status = "Enabled"', 'metrics {\n        status = "Disabled"')),
    'resource "aws_s3_bucket" "b" {\n  replication_configuration {\n    role = "r"\n    rules {\n'
    '      status = "Enabled"\n      destination {\n        bucket = "d"\n      }\n    }\n  }\n}\n',
])
def test_metrics_terraform_reports(tmp_path: Path, text: str) -> None:
    assert "CF-S3-011" in _tf(tmp_path, text)


@pytest.mark.parametrize("text", [
    _tf_rule(_TF_ON),
    _tf_rule(status='"Disabled"'),
    _tf_rule(status="var.x"),
    _tf_rule(_TF_ON.replace('metrics {\n        status = "Enabled"', "metrics {\n        status = var.x")),
    _tf_rule('dynamic "metrics" {\n  for_each = var.x\n  content {\n    status = "Enabled"\n  }\n}\n'
             'replication_time {\n  status = "Enabled"\n}'),
    'resource "aws_s3_bucket" "b" {\n  replication_configuration {\n    role = "r"\n    rules {\n'
    f'      status = "Enabled"\n      destination {{\n        bucket = "d"\n{_TF_ON}      }}\n    }}\n  }}\n}}\n',
    'resource "aws_s3_bucket" "b" {}\n',
    # A configuration the scan cannot tie to a bucket.
    _tf_rule().replace("aws_s3_bucket.b.id", "var.x"),
])
def test_metrics_terraform_silent(tmp_path: Path, text: str) -> None:
    assert "CF-S3-011" not in _tf(tmp_path, text)


# --- CF-S3-012 ---


@pytest.mark.parametrize("encryption", [_kms(), _kms(BucketKeyEnabled=False), _kms(BucketKeyEnabled="false")])
def test_bucket_key_reports(tmp_path: Path, encryption: dict) -> None:
    assert _cf(tmp_path, {"B": _bucket(BucketEncryption=encryption)})["CF-S3-012"] == {"B"}


@pytest.mark.parametrize("encryption", [
    _kms(BucketKeyEnabled=True),
    _kms(BucketKeyEnabled="true"),
    _kms(BucketKeyEnabled=_PARAM),
    _kms("aws:kms:dsse"),  # DSSE-KMS does not support Bucket Keys
    _kms("AES256"),
    _kms(_PARAM),
    _IF,
    {"ServerSideEncryptionConfiguration": _IF},
    {"ServerSideEncryptionConfiguration": [_IF]},
])
def test_bucket_key_silent(tmp_path: Path, encryption: Any) -> None:
    assert "CF-S3-012" not in _cf(tmp_path, {"B": _bucket(BucketEncryption=encryption)})


def _tf_sse(algorithm: str = '"aws:kms"', extra: str = "", bucket: str = "aws_s3_bucket.b.id") -> str:
    return f"""
resource "aws_s3_bucket" "b" {{}}
resource "aws_s3_bucket_server_side_encryption_configuration" "s" {{
  bucket = {bucket}
  rule {{
    {extra}
    apply_server_side_encryption_by_default {{
      sse_algorithm = {algorithm}
    }}
  }}
}}
"""


_TF_INLINE_SSE = """
resource "aws_s3_bucket" "b" {
  server_side_encryption_configuration {
    rule {
      %s
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}
"""


@pytest.mark.parametrize("text", [
    _tf_sse(), _tf_sse(extra="bucket_key_enabled = false"), _TF_INLINE_SSE % "",
])
def test_bucket_key_terraform_reports(tmp_path: Path, text: str) -> None:
    assert "CF-S3-012" in _tf(tmp_path, text)


@pytest.mark.parametrize("text", [
    _tf_sse(extra="bucket_key_enabled = true"),
    _tf_sse(extra="bucket_key_enabled = var.x"),
    _tf_sse('"aws:kms:dsse"'),
    _tf_sse('"AES256"'),
    _tf_sse("var.x"),
    _tf_sse(bucket="var.x"),
    _TF_INLINE_SSE % "bucket_key_enabled = true",
    'resource "aws_s3_bucket" "b" {}\n',
])
def test_bucket_key_terraform_silent(tmp_path: Path, text: str) -> None:
    assert "CF-S3-012" not in _tf(tmp_path, text)


def test_unknown_bucket_key_does_not_hide_disabled_encryption(tmp_path: Path) -> None:
    text = _tf_sse('"NONE"', "bucket_key_enabled = var.x")
    (tmp_path / "main.tf").write_text(_VAR + text, encoding="utf-8")
    found = run_resource_checks(resources_from_terraform(tmp_path, []), tmp_path / "main.tf")
    assert "CF-S3-002" in {f.id for f in found}


# --- wiring ---


def test_each_check_is_wired() -> None:
    assert CF_COVERS_STATIC["CF-S3-010"] == ("REL-026",)
    assert CF_COVERS_STATIC["CF-S3-011"] == ("OPS-025",)
    for check_id in IDS:
        assert check_id in RULE_TOPICS
        assert check_id in SNIPPETS["cloudformation"]
        assert check_id in SNIPPETS["terraform"]
