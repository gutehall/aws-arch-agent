"""OpenSearch, MSK and Kinesis access and resilience: CF-OS-003..007, CF-MSK-002/003, CF-KIN-002."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

OS_IDS = tuple(f"CF-OS-00{n}" for n in range(3, 8))
IDS = (*OS_IDS, "CF-MSK-002", "CF-MSK-003", "CF-KIN-002")
_PARAM = {"Ref": "Param"}


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf_findings(tmp_path: Path, resources: dict, name: str = "t.json") -> list[Finding]:
    path = tmp_path / name
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


_GOOD_LOGS = {"ES_APPLICATION_LOGS": {"Enabled": True, "CloudWatchLogsLogGroupArn": "a"},
              "AUDIT_LOGS": {"Enabled": True, "CloudWatchLogsLogGroupArn": "b"}}


def _domain(**props: Any) -> dict:
    base = {
        "VPCOptions": {"SubnetIds": ["s"]},
        "AdvancedSecurityOptions": {"Enabled": True},
        "DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-PFS-2023-10"},
        "LogPublishingOptions": _GOOD_LOGS,
        "ClusterConfig": {"InstanceCount": 3, "ZoneAwarenessEnabled": True},
        "EncryptionAtRestOptions": {"Enabled": True},
        "NodeToNodeEncryptionOptions": {"Enabled": True},
    }
    return {"Type": "AWS::OpenSearchService::Domain", "Properties": {**base, **props}}


def _cluster(**props: Any) -> dict:
    base = {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}}
    return {"Type": "AWS::MSK::Cluster", "Properties": {**base, **props}}


def test_hardened_resources_have_no_findings(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"D": _domain(), "C": _cluster()}) == {}


def test_unset_opensearch_domain_reports_every_setting(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"D": {"Type": "AWS::OpenSearchService::Domain", "Properties": {}}})
    assert set(found) == set(OS_IDS)


@pytest.mark.parametrize(("check", "props", "fires"), [
    ("CF-OS-003", {"VPCOptions": _PARAM}, False),
    ("CF-OS-004", {"AdvancedSecurityOptions": {"Enabled": False}}, True),
    ("CF-OS-004", {"AdvancedSecurityOptions": {"Enabled": _PARAM}}, False),
    ("CF-OS-004", {"AdvancedSecurityOptions": _PARAM}, False),
    ("CF-OS-005", {"DomainEndpointOptions": {"EnforceHTTPS": False}}, True),
    ("CF-OS-005", {"DomainEndpointOptions": {}}, True),
    ("CF-OS-005", {"DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07"}}, True),
    ("CF-OS-005", {"DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"}}, False),
    ("CF-OS-005", {"DomainEndpointOptions": {"EnforceHTTPS": True}}, False),
    ("CF-OS-005", {"DomainEndpointOptions": {"EnforceHTTPS": _PARAM}}, False),
    ("CF-OS-005", {"DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": _PARAM}}, False),
    ("CF-OS-005", {"DomainEndpointOptions": _PARAM}, False),
    ("CF-OS-006", {"LogPublishingOptions": {"ES_APPLICATION_LOGS": {"Enabled": True}}}, True),
    ("CF-OS-006", {"LogPublishingOptions": {"AUDIT_LOGS": {"Enabled": True}}}, True),
    ("CF-OS-006", {"LogPublishingOptions": {**_GOOD_LOGS, "AUDIT_LOGS": {"Enabled": False}}}, True),
    ("CF-OS-006", {"LogPublishingOptions": {"ES_APPLICATION_LOGS": {}, "AUDIT_LOGS": {}}}, False),
    ("CF-OS-006", {"LogPublishingOptions": {**_GOOD_LOGS, "AUDIT_LOGS": {"Enabled": _PARAM}}}, False),
    ("CF-OS-006", {"LogPublishingOptions": _PARAM}, False),
    ("CF-OS-007", {"ClusterConfig": {"InstanceCount": 2, "ZoneAwarenessEnabled": True}}, True),
    ("CF-OS-007", {"ClusterConfig": {"InstanceCount": "3", "ZoneAwarenessEnabled": "true"}}, False),
    ("CF-OS-007", {"ClusterConfig": {"InstanceCount": 3}}, True),
    ("CF-OS-007", {"ClusterConfig": {"InstanceCount": 3, "ZoneAwarenessEnabled": False}}, True),
    ("CF-OS-007", {"ClusterConfig": {"InstanceCount": _PARAM, "ZoneAwarenessEnabled": True}}, False),
    ("CF-OS-007", {"ClusterConfig": {"InstanceCount": 3, "ZoneAwarenessEnabled": _PARAM}}, False),
    ("CF-OS-007", {"ClusterConfig": {"InstanceCount": 1, "ZoneAwarenessEnabled": _PARAM}}, True),
    ("CF-OS-007", {"ClusterConfig": _PARAM}, False),
])
def test_opensearch_settings(tmp_path: Path, check: str, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"D": _domain(**props)})
    assert found == ({check: {"D"}} if fires else {})


@pytest.mark.parametrize("name", ["dev-stack.json", "staging-stack.json"])
def test_node_count_is_prod_advice(tmp_path: Path, name: str) -> None:
    resources = {"D": _domain(ClusterConfig={"InstanceCount": 1})}
    assert "CF-OS-007" not in _by_id(_cf_findings(tmp_path, resources, name))


@pytest.mark.parametrize(("authentication", "fires"), [
    ({"Sasl": {"Iam": {"Enabled": True}}}, False),
    ({"Sasl": {"Scram": {"Enabled": "true"}}}, False),
    ({"Tls": {"Enabled": True}}, False),
    ({"Tls": {"CertificateAuthorityArnList": ["arn"]}}, False),
    ({}, True),
    ({"Unauthenticated": {"Enabled": True}}, True),
    ({"Sasl": {"Iam": {"Enabled": False}}}, True),
    # Security Hub MSK.6 fails on unauthenticated access even beside another method.
    ({"Sasl": {"Iam": {"Enabled": True}}, "Unauthenticated": {"Enabled": True}}, True),
    ({"Unauthenticated": {"Enabled": True}, "Sasl": {"Iam": _PARAM}}, True),
    ({"Unauthenticated": {"Enabled": _PARAM}}, False),
    ({"Sasl": _PARAM}, False),
    ({"Sasl": {"Iam": {"Enabled": _PARAM}}}, False),
    ({"Tls": _PARAM}, False),
    (_PARAM, False),
])
def test_msk_authentication(tmp_path: Path, authentication: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"C": _cluster(ClientAuthentication=authentication)})
    assert found == ({"CF-MSK-002": {"C"}} if fires else {})


def test_msk_with_no_authentication_setting_is_open(tmp_path: Path) -> None:
    resource = {"Type": "AWS::MSK::Cluster", "Properties": {}}
    assert _cf(tmp_path, {"C": resource}) == {"CF-MSK-002": {"C"}}


@pytest.mark.parametrize(("public", "fires"), [
    ({"Type": "SERVICE_PROVIDED_EIPS"}, True),
    ({"Type": "DISABLED"}, False),
    ({"Type": _PARAM}, False),
    (_PARAM, False),
])
def test_msk_public_access(tmp_path: Path, public: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"C": _cluster(BrokerNodeGroupInfo={"ConnectivityInfo": {"PublicAccess": public}})})
    assert found == ({"CF-MSK-003": {"C"}} if fires else {})


def _stream(**props: Any) -> dict:
    return {"Type": "AWS::Kinesis::Stream", "Properties": {"StreamEncryption": {"EncryptionType": "KMS"}, **props}}


def _mapping(stream: str) -> dict:
    return {"Type": "AWS::Lambda::EventSourceMapping",
            "Properties": {"FunctionName": "f", "EventSourceArn": {"Fn::GetAtt": [stream, "Arn"]}}}


def test_kinesis_retention_needs_a_consumer_in_the_template(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Default": _stream(), "MapDefault": _mapping("Default"),
        "Explicit": _stream(RetentionPeriodHours=24), "MapExplicit": _mapping("Explicit"),
        "Text": _stream(RetentionPeriodHours="24"), "MapText": _mapping("Text"),
        "Long": _stream(RetentionPeriodHours=168), "MapLong": _mapping("Long"),
        "Unread": _stream(RetentionPeriodHours=_PARAM), "MapUnread": _mapping("Unread"),
        "Unused": _stream(),
    }) == {"CF-KIN-002": {"Default", "Explicit", "Text"}}


@pytest.mark.parametrize(("kind", "props"), [
    ("AWS::Kinesis::StreamConsumer", {"ConsumerName": "c", "StreamARN": {"Fn::GetAtt": ["S", "Arn"]}}),
    ("AWS::KinesisFirehose::DeliveryStream", {"KinesisStreamSourceConfiguration": {
        "KinesisStreamARN": {"Fn::GetAtt": ["S", "Arn"]}, "RoleARN": "r"}}),
    ("AWS::KinesisAnalyticsV2::Application", {"ApplicationConfiguration": {"Input": {"Fn::Sub": "${S.Arn}"}}}),
])
def test_other_stream_consumers(tmp_path: Path, kind: str, props: dict) -> None:
    assert _cf(tmp_path, {"S": _stream(), "R": {"Type": kind, "Properties": props}}) == {"CF-KIN-002": {"S"}}


def test_a_function_that_only_writes_is_not_a_consumer(tmp_path: Path) -> None:
    writer = {"Type": "AWS::Lambda::Function", "Properties": {
        "Environment": {"Variables": {"STREAM": {"Ref": "S"}}}}}
    assert _cf(tmp_path, {"S": _stream(), "Fn": writer}) == {}


def test_terraform(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "on" { type = bool }
variable "count_of" { type = number }
variable "items" { type = list(any) }

resource "aws_opensearch_domain" "bare" {
  domain_name = "bare"
}
resource "aws_opensearch_domain" "good" {
  domain_name = "good"
  vpc_options {
    subnet_ids = [aws_subnet.a.id]
  }
  advanced_security_options {
    enabled = true
  }
  domain_endpoint_options {
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }
  log_publishing_options {
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.a.arn
  }
  log_publishing_options {
    log_type                 = "AUDIT_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.b.arn
  }
  cluster_config {
    instance_count         = 3
    zone_awareness_enabled = true
  }
}
resource "aws_opensearch_domain" "weak" {
  domain_name = "weak"
  vpc_options {
    subnet_ids = var.items
  }
  advanced_security_options {
    enabled = false
  }
  domain_endpoint_options {
    enforce_https = false
  }
  log_publishing_options {
    log_type = "ES_APPLICATION_LOGS"
    enabled  = false
  }
  log_publishing_options {
    log_type                 = "AUDIT_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.b.arn
  }
  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
  }
}
resource "aws_opensearch_domain" "from_vars" {
  domain_name = "vars"
  vpc_options {
    subnet_ids = var.items
  }
  advanced_security_options {
    enabled = var.on
  }
  domain_endpoint_options {
    enforce_https = var.on
  }
  dynamic "log_publishing_options" {
    for_each = var.items
    content {}
  }
  cluster_config {
    instance_count         = var.count_of
    zone_awareness_enabled = var.on
  }
}
resource "aws_opensearch_domain" "all_dynamic" {
  domain_name = "dyn"
  dynamic "vpc_options" {
    for_each = var.items
    content {}
  }
  dynamic "advanced_security_options" {
    for_each = var.items
    content {}
  }
  dynamic "domain_endpoint_options" {
    for_each = var.items
    content {}
  }
  dynamic "log_publishing_options" {
    for_each = var.items
    content {}
  }
  dynamic "cluster_config" {
    for_each = var.items
    content {}
  }
}

resource "aws_msk_cluster" "open" {
  cluster_name = "open"
}
resource "aws_msk_cluster" "public" {
  cluster_name = "public"
  client_authentication {
    sasl {
      iam = true
    }
  }
  broker_node_group_info {
    connectivity_info {
      public_access {
        type = "SERVICE_PROVIDED_EIPS"
      }
    }
  }
}
resource "aws_msk_cluster" "mixed" {
  cluster_name = "mixed"
  client_authentication {
    unauthenticated = true
    tls {
      certificate_authority_arns = ["arn"]
    }
  }
}
resource "aws_msk_cluster" "tls" {
  cluster_name = "tls"
  client_authentication {
    tls {
      certificate_authority_arns = ["arn"]
    }
  }
}
resource "aws_msk_cluster" "empty_tls" {
  cluster_name = "empty"
  client_authentication {
    tls {}
  }
}
resource "aws_msk_cluster" "from_var" {
  cluster_name = "var"
  client_authentication {
    sasl {
      iam = var.on
    }
  }
}
resource "aws_msk_cluster" "dynamic_auth" {
  cluster_name = "dyn"
  dynamic "client_authentication" {
    for_each = var.items
    content {}
  }
}

resource "aws_kinesis_stream" "read" {
  name             = "read"
  encryption_type  = "KMS"
}
resource "aws_lambda_event_source_mapping" "m" {
  function_name    = "f"
  event_source_arn = aws_kinesis_stream.read.arn
}
resource "aws_kinesis_stream" "kept" {
  name             = "kept"
  retention_period = 72
}
resource "aws_kinesis_stream_consumer" "c" {
  name       = "c"
  stream_arn = aws_kinesis_stream.kept.arn
}
resource "aws_kinesis_stream" "by_firehose" {
  name = "by_firehose"
}
resource "aws_kinesis_firehose_delivery_stream" "f" {
  name        = "f"
  destination = "extended_s3"
  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.by_firehose.arn
    role_arn           = "r"
  }
}
resource "aws_kinesis_stream" "var_hours" {
  name             = "var"
  retention_period = var.count_of
}
resource "aws_kinesis_stream_consumer" "d" {
  name       = "d"
  stream_arn = aws_kinesis_stream.var_hours.arn
}
resource "aws_kinesis_stream" "nobody" {
  name = "nobody"
}
""")
    bare, good, weak = "aws_opensearch_domain.bare", "aws_opensearch_domain.good", "aws_opensearch_domain.weak"
    assert found["CF-OS-003"] == {bare}
    assert found["CF-OS-004"] == {bare, weak}
    assert found["CF-OS-005"] == {bare, weak}
    assert found["CF-OS-006"] == {bare, weak}
    assert found["CF-OS-007"] == {bare, weak}
    assert not any(good in names for names in found.values())
    assert found["CF-MSK-002"] == {"aws_msk_cluster.open", "aws_msk_cluster.mixed"}
    assert found["CF-MSK-003"] == {"aws_msk_cluster.public"}
    assert found["CF-KIN-002"] == {"aws_kinesis_stream.read", "aws_kinesis_stream.by_firehose"}
