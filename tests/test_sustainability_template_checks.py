"""Accelerators, instance store, EBS copies and backups of recreatable data: CF-SUST-004..007."""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform
from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

IDS = ("CF-SUST-004", "CF-SUST-005", "CF-SUST-006", "CF-SUST-007")


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            assert f.severity == "Low" and f.category == "Sustainability"
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


def test_each_check_answers_one_practice() -> None:
    assert RULE_BEST_PRACTICES["CF-SUST-004"] == ("SUS05-BP04",)
    assert RULE_BEST_PRACTICES["CF-SUST-005"] == ("SUS04-BP02",)
    assert RULE_BEST_PRACTICES["CF-SUST-006"] == ("SUS04-BP06",)
    assert RULE_BEST_PRACTICES["CF-SUST-007"] == ("SUS04-BP08",)


# --- CF-SUST-004: accelerators ---

_GPU = {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "g5.xlarge", "ImageId": "ami-1"}}
_GPU_LT = {"Type": "AWS::EC2::LaunchTemplate",
           "Properties": {"LaunchTemplateData": {"InstanceType": "p4d.24xlarge"}}}
_GPU_ALARM = {"Type": "AWS::CloudWatch::Alarm", "Properties": {
    "MetricName": "nvidia_smi_utilization_gpu", "Namespace": "CWAgent", "Statistic": "Average",
    "Period": 300, "EvaluationPeriods": 3, "Threshold": 10, "ComparisonOperator": "LessThanThreshold",
    "AlarmActions": ["arn:aws:sns:eu-west-1:1:t"]}}


def test_cf_accelerator_without_alarm_or_schedule(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Gpu": _GPU}).get("CF-SUST-004") == {"Gpu"}
    assert _cf(tmp_path, {"Lt": _GPU_LT}).get("CF-SUST-004") == {"Lt"}


def test_cf_accelerator_with_alarm_or_schedule_passes(tmp_path: Path) -> None:
    assert "CF-SUST-004" not in _cf(tmp_path, {"Gpu": _GPU, "Alarm": _GPU_ALARM})
    schedule = {"Type": "AWS::AutoScaling::ScheduledAction",
                "Properties": {"AutoScalingGroupName": "g", "Recurrence": "0 2 * * *", "DesiredCapacity": 2}}
    assert "CF-SUST-004" not in _cf(tmp_path, {"Gpu": _GPU, "Night": schedule})


def test_cf_general_purpose_instance_is_not_judged(tmp_path: Path) -> None:
    plain = {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "m7g.large", "ImageId": "ami-1"}}
    unknown = {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": {"Ref": "Type"}, "ImageId": "ami-1"}}
    assert "CF-SUST-004" not in _cf(tmp_path, {"Plain": plain, "Unknown": unknown})


_TF_GPU = 'resource "aws_instance" "gpu" {\n  ami = "ami-1"\n  instance_type = "inf2.xlarge"\n}\n'


def test_tf_accelerator_without_alarm(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_GPU).get("CF-SUST-004") == {"aws_instance.gpu"}


def test_tf_accelerator_with_alarm_or_schedule_passes(tmp_path: Path) -> None:
    alarm = ('resource "aws_cloudwatch_metric_alarm" "gpu" {\n  alarm_name = "gpu"\n'
             '  metric_name = "neuroncore_utilization"\n  namespace = "CWAgent"\n'
             '  comparison_operator = "LessThanThreshold"\n  evaluation_periods = 3\n  threshold = 10\n'
             '  period = 300\n  statistic = "Average"\n}\n')
    assert "CF-SUST-004" not in _tf(tmp_path, _TF_GPU + alarm)
    schedule = ('resource "aws_autoscaling_schedule" "night" {\n  scheduled_action_name = "n"\n'
                '  autoscaling_group_name = "g"\n  recurrence = "0 2 * * *"\n  desired_capacity = 2\n}\n')
    assert "CF-SUST-004" not in _tf(tmp_path, _TF_GPU + schedule)


def test_tf_alarm_from_a_remote_module_may_exist(tmp_path: Path) -> None:
    module = 'module "alarms" {\n  source = "app.terraform.io/acme/alarms/aws"\n}\n'
    assert "CF-SUST-004" not in _tf(tmp_path, _TF_GPU + module)


# --- CF-SUST-005: instance store ---

_EPHEMERAL = {"Type": "AWS::EC2::Instance", "Properties": {
    "InstanceType": "m5.large", "ImageId": "ami-1",
    "BlockDeviceMappings": [{"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"}]}}
_NVME = {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "i4i.xlarge", "ImageId": "ami-1"}}


def test_cf_instance_store_without_durable_store(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Eph": _EPHEMERAL}).get("CF-SUST-005") == {"Eph"}
    assert _cf(tmp_path, {"Nvme": _NVME}).get("CF-SUST-005") == {"Nvme"}


def test_cf_instance_store_with_durable_store_passes(tmp_path: Path) -> None:
    bucket = {"Type": "AWS::S3::Bucket", "Properties": {}}
    table = {"Type": "AWS::DynamoDB::Table", "Properties": {}}
    assert "CF-SUST-005" not in _cf(tmp_path, {"Nvme": _NVME, "Data": bucket})
    assert "CF-SUST-005" not in _cf(tmp_path, {"Eph": _EPHEMERAL, "Table": table})
    plain = {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "m5.large", "ImageId": "ami-1"}}
    assert "CF-SUST-005" not in _cf(tmp_path, {"Plain": plain})


def test_tf_instance_store_without_durable_store(tmp_path: Path) -> None:
    nvme = 'resource "aws_instance" "nvme" {\n  ami = "ami-1"\n  instance_type = "d3.xlarge"\n}\n'
    assert _tf(tmp_path, nvme).get("CF-SUST-005") == {"aws_instance.nvme"}
    eph = ('resource "aws_launch_template" "eph" {\n  instance_type = "m5.large"\n'
           '  block_device_mappings {\n    device_name = "/dev/sdb"\n    virtual_name = "ephemeral0"\n  }\n}\n')
    assert _tf(tmp_path, eph).get("CF-SUST-005") == {"aws_launch_template.eph"}


def test_tf_instance_store_with_durable_store_passes(tmp_path: Path) -> None:
    eph = ('resource "aws_instance" "eph" {\n  ami = "ami-1"\n  instance_type = "m5.large"\n'
           '  ephemeral_block_device {\n    device_name = "/dev/sdb"\n    virtual_name = "ephemeral0"\n  }\n}\n')
    assert _tf(tmp_path, eph).get("CF-SUST-005") == {"aws_instance.eph"}
    efs = 'resource "aws_efs_file_system" "data" {\n  encrypted = true\n}\n'
    assert "CF-SUST-005" not in _tf(tmp_path, eph + efs)


# --- CF-SUST-006: EBS volumes and no shared store ---

_VOL = {"Type": "AWS::EC2::Volume", "Properties": {"AvailabilityZone": "eu-west-1a", "Size": 100, "Encrypted": True}}


def test_cf_several_volumes_without_shared_store(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"A": _VOL, "B": _VOL}).get("CF-SUST-006") == {"A"}


def test_cf_one_volume_or_a_shared_store_passes(tmp_path: Path) -> None:
    assert "CF-SUST-006" not in _cf(tmp_path, {"A": _VOL})
    efs = {"Type": "AWS::EFS::FileSystem", "Properties": {"Encrypted": True}}
    assert "CF-SUST-006" not in _cf(tmp_path, {"A": _VOL, "B": _VOL, "Shared": efs})


_TF_VOLS = ('resource "aws_ebs_volume" "data" {\n  count = 2\n  availability_zone = "eu-west-1a"\n'
            '  size = 100\n  encrypted = true\n}\n')


def test_tf_several_volumes_without_shared_store(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_VOLS).get("CF-SUST-006") == {"aws_ebs_volume.data"}


def test_tf_volumes_with_a_shared_store_passes(tmp_path: Path) -> None:
    bucket = 'resource "aws_s3_bucket" "shared" {\n  bucket = "shared-data"\n}\n'
    assert "CF-SUST-006" not in _tf(tmp_path, _TF_VOLS + bucket)
    module = 'module "storage" {\n  source = "git::https://example.com/storage.git"\n}\n'
    assert "CF-SUST-006" not in _tf(tmp_path, _TF_VOLS + module)


# --- CF-SUST-007: backups of recreatable data ---

def _selection(*entries: object) -> dict:
    return {"Type": "AWS::Backup::BackupSelection", "Properties": {
        "BackupPlanId": "plan-1",
        "BackupSelection": {"SelectionName": "s", "IamRoleArn": "arn:aws:iam::1:role/b", "Resources": list(entries)}}}


def test_cf_selection_of_a_cache_or_temp_bucket(tmp_path: Path) -> None:
    cache = {"Type": "AWS::ElastiCache::ReplicationGroup", "Properties": {"ReplicationGroupDescription": "c"}}
    temp = {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "app-scratch-data"}}
    assert _cf(tmp_path, {"Cache": cache, "Sel": _selection({"Fn::GetAtt": ["Cache", "ARN"]})}
               ).get("CF-SUST-007") == {"Sel"}
    assert _cf(tmp_path, {"Temp": temp, "Sel": _selection({"Fn::GetAtt": ["Temp", "Arn"]})}
               ).get("CF-SUST-007") == {"Sel"}
    assert _cf(tmp_path, {"Sel": _selection("arn:aws:s3:::tmp-uploads")}).get("CF-SUST-007") == {"Sel"}


def test_cf_selection_of_durable_data_passes(tmp_path: Path) -> None:
    data = {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "customer-records"}}
    temp = {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "app-temp"}}
    assert "CF-SUST-007" not in _cf(tmp_path, {"Data": data, "Temp": temp,
                                              "Sel": _selection({"Fn::GetAtt": ["Data", "Arn"]})})
    # "template" holds the letters of "temp" but is not the word.
    assert "CF-SUST-007" not in _cf(tmp_path, {"Sel": _selection("arn:aws:s3:::templates")})
    assert "CF-SUST-007" not in _cf(tmp_path, {"Sel": _selection({"Ref": "Arns"})})


def test_tf_selection_of_a_cache(tmp_path: Path) -> None:
    text = ('resource "aws_elasticache_replication_group" "cache" {\n  replication_group_id = "c"\n'
            '  description = "c"\n}\n'
            'resource "aws_backup_selection" "all" {\n  name = "s"\n  plan_id = "p"\n  iam_role_arn = "r"\n'
            '  resources = [aws_elasticache_replication_group.cache.arn]\n}\n')
    assert _tf(tmp_path, text).get("CF-SUST-007") == {"aws_backup_selection.all"}


def test_tf_selection_of_durable_data_passes(tmp_path: Path) -> None:
    text = ('resource "aws_s3_bucket" "tmp" {\n  bucket = "build-tmp"\n}\n'
            'resource "aws_s3_bucket" "records" {\n  bucket = "records"\n}\n'
            'resource "aws_backup_selection" "s" {\n  name = "s"\n  plan_id = "p"\n  iam_role_arn = "r"\n'
            '  resources = [aws_s3_bucket.records.arn]\n}\n')
    assert "CF-SUST-007" not in _tf(tmp_path, text)
    hit = text.replace("aws_s3_bucket.records.arn", "aws_s3_bucket.tmp.arn")
    assert _tf(tmp_path, hit).get("CF-SUST-007") == {"aws_backup_selection.s"}
