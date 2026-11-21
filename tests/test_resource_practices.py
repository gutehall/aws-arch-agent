"""Best practices that only a repo rule answered, now read from resources:
CF-SYN-001, CF-LOGS-001, CF-CE-001, CF-EBS-003, CF-RDS-015, CF-S3-013."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform
from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

IDS = ("CF-SYN-001", "CF-LOGS-001", "CF-CE-001", "CF-EBS-003", "CF-RDS-015", "CF-S3-013")
PRACTICES = {
    "CF-SYN-001": "OPS04-BP03", "CF-LOGS-001": "OPS08-BP02", "CF-CE-001": "COST01-BP06",
    "CF-EBS-003": "SUS02-BP03", "CF-RDS-015": "SUS04-BP04", "CF-S3-013": "SUS04-BP05",
}


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            assert f.severity == "Low"
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    path = tmp_path / "t.json"
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


def _r(rtype: str, **props: Any) -> dict:
    return {"Type": rtype, "Properties": props}


@pytest.mark.parametrize("check_id", IDS)
def test_each_check_answers_a_practice_that_was_repo_only(check_id: str) -> None:
    practice = PRACTICES[check_id]
    assert RULE_BEST_PRACTICES[check_id] == (practice,)
    others = [r for r, bps in RULE_BEST_PRACTICES.items() if practice in bps and r != check_id]
    assert others and all(r.startswith("REPO-") for r in others)  # the repo rule still answers too


# --- CF-SYN-001: user experience telemetry ---------------------------------------------------


@pytest.mark.parametrize("entry", [
    _r("AWS::CloudFront::Distribution", DistributionConfig={}),
    _r("AWS::ApiGatewayV2::Api", ProtocolType="HTTP"),
    _r("AWS::ApiGateway::RestApi", Name="api"),
    _r("AWS::ElasticLoadBalancingV2::LoadBalancer", Type="application"),
])
def test_public_entry_point_without_canary_or_rum(tmp_path: Path, entry: dict) -> None:
    assert _cf(tmp_path, {"Entry": entry}).get("CF-SYN-001") == {"Entry"}


@pytest.mark.parametrize("watcher", [
    _r("AWS::Synthetics::Canary", Name="home"),
    _r("AWS::RUM::AppMonitor", Name="web"),
])
def test_canary_or_rum_answers_user_telemetry(tmp_path: Path, watcher: dict) -> None:
    found = _cf(tmp_path, {"Entry": _r("AWS::CloudFront::Distribution", DistributionConfig={}), "W": watcher})
    assert "CF-SYN-001" not in found


@pytest.mark.parametrize("entry", [
    _r("AWS::ApiGateway::RestApi", EndpointConfiguration={"Types": ["PRIVATE"]}),
    _r("AWS::ElasticLoadBalancingV2::LoadBalancer", Scheme="internal"),
    _r("AWS::ApiGateway::RestApi", EndpointConfiguration={"Ref": "Param"}),
])
def test_private_or_unreadable_entry_points_are_not_judged(tmp_path: Path, entry: dict) -> None:
    assert "CF-SYN-001" not in _cf(tmp_path, {"Entry": entry})


def test_terraform_user_telemetry(tmp_path: Path) -> None:
    lb = 'resource "aws_lb" "web" {\n  internal = false\n}\n'
    assert _tf(tmp_path, lb).get("CF-SYN-001") == {"aws_lb.web"}
    canary = 'resource "aws_synthetics_canary" "home" {\n  name = "home"\n}\n'
    assert "CF-SYN-001" not in _tf(tmp_path, lb + canary)
    internal = 'resource "aws_lb" "web" {\n  internal = true\n}\n'
    assert "CF-SYN-001" not in _tf(tmp_path, internal)
    private = ('resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n'
               '  endpoint_configuration {\n    types = ["PRIVATE"]\n  }\n}\n')
    assert "CF-SYN-001" not in _tf(tmp_path, private)


# --- CF-LOGS-001: log analysis -----------------------------------------------------------------


def test_log_groups_with_nothing_reading_them(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"Logs": _r("AWS::Logs::LogGroup", RetentionInDays=30)})
    assert found.get("CF-LOGS-001") == {"Logs"}


@pytest.mark.parametrize("reader", [
    "AWS::Logs::MetricFilter", "AWS::Logs::SubscriptionFilter", "AWS::Logs::LogAnomalyDetector",
    "AWS::Logs::QueryDefinition",
])
def test_a_log_reader_answers_log_analysis(tmp_path: Path, reader: str) -> None:
    found = _cf(tmp_path, {"Logs": _r("AWS::Logs::LogGroup", RetentionInDays=30),
                           "Reader": _r(reader, LogGroupName={"Ref": "Logs"})})
    assert "CF-LOGS-001" not in found


def test_terraform_log_analysis(tmp_path: Path) -> None:
    group = 'resource "aws_cloudwatch_log_group" "app" {\n  retention_in_days = 30\n}\n'
    assert _tf(tmp_path, group).get("CF-LOGS-001") == {"aws_cloudwatch_log_group.app"}
    metric = ('resource "aws_cloudwatch_log_metric_filter" "errors" {\n'
              '  log_group_name = aws_cloudwatch_log_group.app.name\n  pattern = "ERROR"\n}\n')
    assert "CF-LOGS-001" not in _tf(tmp_path, group + metric)


def test_a_remote_module_may_hold_the_log_reader(tmp_path: Path) -> None:
    group = 'resource "aws_cloudwatch_log_group" "app" {\n  retention_in_days = 30\n}\n'
    module = 'module "obs" {\n  source = "git::https://example.com/obs.git"\n}\n'
    assert "CF-LOGS-001" not in _tf(tmp_path, group + module)


# --- CF-CE-001: cost anomaly alerts -----------------------------------------------------------


def test_anomaly_monitor_without_subscription(tmp_path: Path) -> None:
    monitor = _r("AWS::CE::AnomalyMonitor", MonitorName="svc", MonitorType="DIMENSIONAL",
                 MonitorDimension="SERVICE")
    assert _cf(tmp_path, {"Monitor": monitor}).get("CF-CE-001") == {"Monitor"}
    sub = _r("AWS::CE::AnomalySubscription", MonitorArnList=[{"Fn::GetAtt": ["Monitor", "MonitorArn"]}])
    assert "CF-CE-001" not in _cf(tmp_path, {"Monitor": monitor, "Sub": sub})


def test_no_monitor_is_not_reported(tmp_path: Path) -> None:
    assert "CF-CE-001" not in _cf(tmp_path, {"Q": _r("AWS::SQS::Queue")})


def test_terraform_anomaly_subscription(tmp_path: Path) -> None:
    monitor = 'resource "aws_ce_anomaly_monitor" "svc" {\n  name = "svc"\n}\n'
    assert _tf(tmp_path, monitor).get("CF-CE-001") == {"aws_ce_anomaly_monitor.svc"}
    sub = ('resource "aws_ce_anomaly_subscription" "alerts" {\n'
           '  monitor_arn_list = [aws_ce_anomaly_monitor.svc.arn]\n}\n')
    assert "CF-CE-001" not in _tf(tmp_path, monitor + sub)


# --- CF-EBS-003: unattached volumes ------------------------------------------------------------


def test_volume_nothing_attaches(tmp_path: Path) -> None:
    vol = _r("AWS::EC2::Volume", Size=100, VolumeType="gp3", AvailabilityZone="eu-west-1a")
    assert _cf(tmp_path, {"Data": vol}).get("CF-EBS-003") == {"Data"}


@pytest.mark.parametrize("attacher", [
    _r("AWS::EC2::VolumeAttachment", VolumeId={"Ref": "Data"}, InstanceId={"Ref": "Host"}, Device="/dev/sdf"),
    _r("AWS::EC2::Instance", Volumes=[{"VolumeId": {"Ref": "Data"}, "Device": "/dev/sdf"}]),
])
def test_attached_volume_is_not_reported(tmp_path: Path, attacher: dict) -> None:
    vol = _r("AWS::EC2::Volume", Size=100, VolumeType="gp3", AvailabilityZone="eu-west-1a")
    assert "CF-EBS-003" not in _cf(tmp_path, {"Data": vol, "Attach": attacher})


def test_terraform_volume_attachment(tmp_path: Path) -> None:
    vol = 'resource "aws_ebs_volume" "data" {\n  size = 100\n  type = "gp3"\n}\n'
    assert _tf(tmp_path, vol).get("CF-EBS-003") == {"aws_ebs_volume.data"}
    attach = ('resource "aws_volume_attachment" "data" {\n  device_name = "/dev/sdf"\n'
              '  volume_id = aws_ebs_volume.data.id\n  instance_id = "i-1"\n}\n')
    assert "CF-EBS-003" not in _tf(tmp_path, vol + attach)


# --- CF-RDS-015: RDS storage autoscaling -------------------------------------------------------


def test_rds_instance_without_max_allocated_storage(tmp_path: Path) -> None:
    db = _r("AWS::RDS::DBInstance", Engine="postgres", AllocatedStorage="100", DBInstanceClass="db.m7g.large")
    assert _cf(tmp_path, {"Db": db}).get("CF-RDS-015") == {"Db"}


@pytest.mark.parametrize("props", [
    {"Engine": "postgres", "AllocatedStorage": "100", "MaxAllocatedStorage": 500},
    {"Engine": "aurora-postgresql", "DBClusterIdentifier": {"Ref": "Cluster"}},
    {"Engine": "postgres", "SourceDBInstanceIdentifier": "primary"},
    {"Engine": {"Ref": "Engine"}, "AllocatedStorage": "100"},
    {"Engine": "postgres", "MaxAllocatedStorage": {"Fn::If": ["Big", 500, {"Ref": "AWS::NoValue"}]}},
])
def test_rds_storage_autoscaling_on_or_not_judged(tmp_path: Path, props: dict) -> None:
    assert "CF-RDS-015" not in _cf(tmp_path, {"Db": _r("AWS::RDS::DBInstance", **props)})


def test_terraform_rds_storage_autoscaling(tmp_path: Path) -> None:
    db = 'resource "aws_db_instance" "main" {\n  engine = "mysql"\n  allocated_storage = 50\n}\n'
    assert _tf(tmp_path, db).get("CF-RDS-015") == {"aws_db_instance.main"}
    grows = ('resource "aws_db_instance" "main" {\n  engine = "mysql"\n  allocated_storage = 50\n'
             '  max_allocated_storage = 200\n}\n')
    assert "CF-RDS-015" not in _tf(tmp_path, grows)
    member = ('resource "aws_rds_cluster_instance" "m" {\n  engine = "aurora-mysql"\n'
              '  cluster_identifier = aws_rds_cluster.c.id\n}\n')
    assert "CF-RDS-015" not in _tf(tmp_path, member)


# --- CF-S3-013: noncurrent versions ------------------------------------------------------------

_VERSIONED = {"VersioningConfiguration": {"Status": "Enabled"}}


def test_versioned_bucket_keeps_noncurrent_versions(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"B": _r("AWS::S3::Bucket", **_VERSIONED)}).get("CF-S3-013") == {"B"}
    expire_only_current = {"Rules": [{"Status": "Enabled", "ExpirationInDays": 365}]}
    found = _cf(tmp_path, {"B": _r("AWS::S3::Bucket", **_VERSIONED, LifecycleConfiguration=expire_only_current)})
    assert found.get("CF-S3-013") == {"B"}
    disabled = {"Rules": [{"Status": "Disabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]}
    found = _cf(tmp_path, {"B": _r("AWS::S3::Bucket", **_VERSIONED, LifecycleConfiguration=disabled)})
    assert found.get("CF-S3-013") == {"B"}


@pytest.mark.parametrize("props", [
    {**_VERSIONED, "LifecycleConfiguration": {"Rules": [
        {"Status": "Enabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]}},
    {**_VERSIONED, "LifecycleConfiguration": {"Rules": [
        {"Status": "Enabled", "NoncurrentVersionExpirationInDays": 30}]}},
    {"VersioningConfiguration": {"Status": "Suspended"}},
    {},
    {"VersioningConfiguration": {"Ref": "Versioning"}},
    {**_VERSIONED, "LifecycleConfiguration": {"Fn::If": ["Prod", {"Rules": []}, {"Ref": "AWS::NoValue"}]}},
])
def test_noncurrent_versions_expire_or_not_judged(tmp_path: Path, props: dict) -> None:
    assert "CF-S3-013" not in _cf(tmp_path, {"B": _r("AWS::S3::Bucket", **props)})


def test_terraform_noncurrent_versions(tmp_path: Path) -> None:
    bucket = ('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
              'resource "aws_s3_bucket_versioning" "b" {\n  bucket = aws_s3_bucket.b.id\n'
              '  versioning_configuration {\n    status = "Enabled"\n  }\n}\n')
    assert _tf(tmp_path, bucket).get("CF-S3-013") == {"aws_s3_bucket.b"}
    lifecycle = ('resource "aws_s3_bucket_lifecycle_configuration" "b" {\n  bucket = aws_s3_bucket.b.id\n'
                 '  rule {\n    id = "old"\n    status = "Enabled"\n'
                 '    noncurrent_version_expiration {\n      noncurrent_days = 30\n    }\n  }\n}\n')
    assert "CF-S3-013" not in _tf(tmp_path, bucket + lifecycle)
    inline = ('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  versioning {\n    enabled = true\n  }\n'
              '  lifecycle_rule {\n    enabled = true\n'
              '    noncurrent_version_expiration {\n      days = 30\n    }\n  }\n}\n')
    assert "CF-S3-013" not in _tf(tmp_path, inline)


def test_review_fixes_unreadable_status_and_dynamic_endpoint(tmp_path: Path) -> None:
    status = {"Rules": [{"Status": {"Ref": "On"}, "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]}
    found = _cf(tmp_path, {"B": _r("AWS::S3::Bucket", **_VERSIONED, LifecycleConfiguration=status)})
    assert "CF-S3-013" not in found
    dynamic = ('resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n'
               '  dynamic "endpoint_configuration" {\n    for_each = var.ec\n'
               '    content {\n      types = endpoint_configuration.value\n    }\n  }\n}\n')
    assert "CF-SYN-001" not in _tf(tmp_path, dynamic)
