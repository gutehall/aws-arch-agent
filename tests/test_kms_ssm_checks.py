"""KMS rotation and deletion window, SSM parameters: CF-KMS-002/003, CF-SSM-001/002, OPS-023."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.operational_excellence import SsmParameterAdvancedTier
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-KMS-002", "CF-KMS-003", "CF-SSM-001", "CF-SSM-002")
_PARAM = {"Ref": "Param"}


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf_findings(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return found


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    return _by_id(_cf_findings(tmp_path, resources))


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _key(**props: Any) -> dict:
    return {"Type": "AWS::KMS::Key", "Properties": {"EnableKeyRotation": True, **props}}


def _parameter(**props: Any) -> dict:
    return {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "abc", **props}}


def _bucket(key: str) -> dict:
    return {"Type": "AWS::S3::Bucket", "Properties": {"BucketEncryption": {
        "ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {
            "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": {"Fn::GetAtt": [key, "Arn"]}}}]}}}


def test_rotation(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Default": {"Type": "AWS::KMS::Key", "Properties": {}},
        "Off": _key(EnableKeyRotation=False),
        "Text": _key(EnableKeyRotation="false"),
        "Named": {"Type": "AWS::KMS::Key", "Properties": {"KeySpec": "SYMMETRIC_DEFAULT"}},
        "On": _key(),
        "OnText": _key(EnableKeyRotation="true"),
        "Unread": _key(EnableKeyRotation=_PARAM),
        "Rsa": {"Type": "AWS::KMS::Key", "Properties": {"KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"}},
        "Hmac": {"Type": "AWS::KMS::Key", "Properties": {"KeySpec": "HMAC_256"}},
        "External": {"Type": "AWS::KMS::Key", "Properties": {"Origin": "EXTERNAL"}},
        "UnreadSpec": {"Type": "AWS::KMS::Key", "Properties": {"KeySpec": _PARAM}},
        "UnreadOrigin": {"Type": "AWS::KMS::Key", "Properties": {"Origin": _PARAM}},
    }) == {"CF-KMS-002": {"Default", "Off", "Text", "Named"}}


def test_deletion_window_needs_a_data_store_that_uses_the_key(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Short": _key(PendingWindowInDays=7),
        "ShortText": _key(PendingWindowInDays="7"),
        "Full": _key(PendingWindowInDays=30),
        "Default": _key(),
        "Unused": _key(PendingWindowInDays=7),
        "Unread": _key(PendingWindowInDays=_PARAM),
        "Queue": _key(PendingWindowInDays=7),
        "A": _bucket("Short"),
        "B": _bucket("ShortText"),
        "C": _bucket("Full"),
        "D": _bucket("Default"),
        "E": _bucket("Unread"),
        "Topic": {"Type": "AWS::Lambda::Function", "Properties": {"KmsKeyArn": {"Fn::GetAtt": ["Queue", "Arn"]}}},
    }) == {"CF-KMS-003": {"Short", "ShortText"}}


def test_a_tag_named_key_is_not_a_reference_to_a_key_named_key(tmp_path: Path) -> None:
    tagged = {"Type": "AWS::S3::Bucket", "Properties": {"Tags": [{"Key": "team", "Value": "a"}]}}
    assert _cf(tmp_path, {"Key": _key(PendingWindowInDays=7), "B": tagged}) == {}
    assert _cf(tmp_path, {"Key": _key(PendingWindowInDays=7), "B": _bucket("Key")}) == {"CF-KMS-003": {"Key"}}


@pytest.mark.parametrize("name", [
    "/app/db/password", "db_password", "/app/api-key", "/app/API_KEY", "/app/github-token",
    "/app/client-secret", {"Fn::Sub": "/${Env}/db/password"},
])
def test_parameter_names_that_look_like_secrets(tmp_path: Path, name: Any) -> None:
    assert _cf(tmp_path, {"P": _parameter(Name=name)}) == {"CF-SSM-001": {"P"}}


@pytest.mark.parametrize("name", [
    "/app/db/host", "/app/secret-arn", "/app/password-min-length", "/app/max-tokens",
    "/secrets/region", {"Fn::Sub": "/app/${Which}"}, _PARAM,
])
def test_parameter_names_that_do_not(tmp_path: Path, name: Any) -> None:
    assert _cf(tmp_path, {"P": _parameter(Name=name)}) == {}


def test_logical_id_is_used_when_the_name_cannot_be_read(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "NoName": _parameter(),
        "DbPasswordParam1234ABCD": _parameter(),
        "DbPasswordFromRef": _parameter(Name=_PARAM),
        "DbPasswordNamed": _parameter(Name="/app/host"),
    }) == {"CF-SSM-001": {"DbPasswordParam1234ABCD", "DbPasswordFromRef"}}


@pytest.mark.parametrize(("props", "fires"), [
    ({"Value": "hunter2"}, True),
    ({"Value": _PARAM}, True),
    ({"Value": "{{resolve:secretsmanager:s:SecretString:p}}"}, True),
    ({"Value": "arn:aws:secretsmanager:eu-west-1:1:secret:s"}, False),
    ({"Value": "true"}, False),
    ({"Value": "12"}, False),
    ({"Value": 3306}, False),
    ({"Value": True}, False),
    ({"Value": {"Fn::GetAtt": ["Thing", "Arn"]}}, False),
    ({"Value": {"Fn::GetAtt": "Thing.Arn"}}, False),
    ({"Value": {"Fn::Sub": "arn:${AWS::Partition}:kms:r:1:key/k"}}, False),
    ({"Value": {"Ref": "Thing"}}, False),
    ({"Value": {"Fn::GetAtt": ["Thing", "Secret"]}}, True),
    ({"Type": "StringList"}, False),
    ({"Type": _PARAM}, False),
])
def test_parameter_type_and_value(tmp_path: Path, props: dict, fires: bool) -> None:
    thing = {"Type": "AWS::SNS::Topic", "Properties": {"KmsMasterKeyId": "alias/aws/sns"}}
    found = _cf(tmp_path, {"P": _parameter(Name="/app/password", **props), "Thing": thing})
    assert found == ({"CF-SSM-001": {"P"}} if fires else {})


def test_findings_never_quote_a_parameter_value(tmp_path: Path) -> None:
    found = _cf_findings(tmp_path, {"P": _parameter(Name="/app/password", Value="hunter2-value")})
    ours = [f for f in found if f.id == "CF-SSM-001"]
    assert ours and all("hunter2-value" not in str(f) for f in ours)


@pytest.mark.parametrize(("props", "fires"), [
    ({"Tier": "Advanced"}, True),
    ({"Tier": "Advanced", "Value": "x" * 4095}, True),
    ({"Tier": "Advanced", "Value": "x" * 4096}, False),
    ({"Tier": "Advanced", "Value": "å" * 2048}, False),
    ({"Tier": "Standard"}, False),
    ({"Tier": "Intelligent-Tiering"}, False),
    ({}, False),
    ({"Tier": "Advanced", "Value": _PARAM}, False),
    ({"Tier": _PARAM}, False),
    ({"Tier": "Advanced", "Policies": '[{"Type":"Expiration"}]'}, False),
    ({"Tier": "Advanced", "DataType": "json"}, False),
    ({"Tier": "Advanced", "DataType": "text"}, True),
])
def test_advanced_tier(tmp_path: Path, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"P": _parameter(Name="/app/host", **props)})
    assert found == ({"CF-SSM-002": {"P"}} if fires else {})


def test_terraform(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "on" { type = bool }
variable "days" { type = number }
variable "value" { type = string }
variable "kind" { type = string }

resource "aws_kms_key" "plain" {}
resource "aws_kms_key" "rotated" {
  enable_key_rotation = true
}
resource "aws_kms_key" "from_var" {
  enable_key_rotation = var.on
}
resource "aws_kms_key" "signing" {
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}
resource "aws_kms_key" "custom_store" {
  custom_key_store_id = "cks-1"
}
resource "aws_kms_key" "short" {
  enable_key_rotation     = true
  deletion_window_in_days = 7
}
resource "aws_kms_key" "short_sse" {
  enable_key_rotation     = true
  deletion_window_in_days = 7
}
resource "aws_kms_key" "short_unused" {
  enable_key_rotation     = true
  deletion_window_in_days = 7
}
resource "aws_kms_key" "window_from_var" {
  enable_key_rotation     = true
  deletion_window_in_days = var.days
}
resource "aws_dynamodb_table" "t" {
  name     = "t"
  hash_key = "id"
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.short.arn
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
  bucket = aws_s3_bucket.b.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.short_sse.arn
    }
  }
}
resource "aws_cloudwatch_log_group" "l" {
  name       = "l"
  kms_key_id = aws_kms_key.window_from_var.arn
}

resource "aws_ssm_parameter" "plain" {
  name  = "/app/db/password"
  type  = "String"
  value = "hunter2"
}
resource "aws_ssm_parameter" "db_token" {
  name  = "/${var.kind}/x"
  type  = "String"
  value = var.value
}
resource "aws_ssm_parameter" "insecure" {
  name           = "/app/api-key"
  type           = "String"
  insecure_value = var.value
}
resource "aws_ssm_parameter" "secure" {
  name  = "/app/password"
  type  = "SecureString"
  value = var.value
}
resource "aws_ssm_parameter" "from_var" {
  name  = "/app/secret"
  type  = var.kind
  value = "x"
}
resource "aws_ssm_parameter" "signing_key" {
  name  = "/app/signing-key"
  type  = "String"
  value = aws_kms_key.rotated.arn
}
resource "aws_kms_key" "secure_param" {
  enable_key_rotation     = true
  deletion_window_in_days = 7
}
resource "aws_ssm_parameter" "encrypted" {
  name   = "/app/encrypted"
  type   = "SecureString"
  key_id = aws_kms_key.secure_param.arn
  value  = var.value
}
resource "aws_ssm_parameter" "host" {
  name  = "/app/host"
  type  = "String"
  value = "h"
}
resource "aws_ssm_parameter" "advanced" {
  name  = "/app/big"
  type  = "String"
  tier  = "Advanced"
  value = "small"
}
resource "aws_ssm_parameter" "advanced_var" {
  name  = "/app/big2"
  type  = "String"
  tier  = "Advanced"
  value = var.value
}
""")
    assert found["CF-KMS-002"] == {"aws_kms_key.plain"}
    assert found["CF-KMS-003"] == {"aws_kms_key.short", "aws_kms_key.short_sse", "aws_kms_key.secure_param"}
    assert found["CF-SSM-001"] == {
        "aws_ssm_parameter.plain", "aws_ssm_parameter.db_token", "aws_ssm_parameter.insecure"}
    assert found["CF-SSM-002"] == {"aws_ssm_parameter.advanced"}


def test_restated_throughput_rule_does_not_recommend_the_advanced_tier(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    lib = tmp_path / "lib"
    lib.mkdir()
    stack = lib / "stack.ts"
    stack.write_text("new ssm.StringParameter(this, 'P', { tier: ssm.ParameterTier.ADVANCED });\n", encoding="utf-8")
    found = SsmParameterAdvancedTier().run(tmp_path, "typescript")
    assert [f.id for f in found] == ["OPS-023"]
    assert "does not raise this limit" in found[0].recommendation
    stack.write_text(
        "new ssm.StringParameter(this, 'P', {});\n// ssm/parameter-store/high-throughput-enabled\n",
        encoding="utf-8",
    )
    assert SsmParameterAdvancedTier().run(tmp_path, "typescript") == []
