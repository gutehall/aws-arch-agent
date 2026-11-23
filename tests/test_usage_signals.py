"""The former advice rules that read the usage file: REL-011, OPS-023, SUST-002, SUST-003, PERF-011, PERF-014."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.pricing import usage
from aws_arch_agent.rules import stack_cost, usage_signals
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.well_architected import answers

RULES = {r.id: r for r in ALL_RULES if r.id in usage_signals.USAGE_RULE_IDS}


def _cf(root: Path, resources: dict[str, Any], profile: dict[str, Any] | None) -> Path:
    (root / "template.json").write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    if profile is not None:
        (root / usage.DEFAULT_FILE).write_text(yaml.safe_dump(profile), encoding="utf-8")
    return root


def _tf(root: Path, body: str, profile: dict[str, Any] | None) -> Path:
    (root / "main.tf").write_text(body, encoding="utf-8")
    if profile is not None:
        (root / usage.DEFAULT_FILE).write_text(yaml.safe_dump(profile), encoding="utf-8")
    return root


def _ids(root: Path, **kw: Any) -> set[str]:
    _r, _c, findings, _w = analyze_v1(root, use_llm=False, **kw)
    return {f.id for f in findings}


_DB = {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "postgres", "DBInstanceClass": "db.t3.small"}}}
_REPLICA = {"Replica": {"Type": "AWS::RDS::DBInstance", "Properties": {"SourceDBInstanceIdentifier": {"Ref": "Db"}}}}
_SSM = {"P": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "v"}}}
_EC2 = {"Web": {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "t3.small", "ImageId": "ami-1"}}}
_BIG_EC2 = {"Web": {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "m5.8xlarge", "ImageId": "ami-1"}}}
_ASG = {"Asg": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {"MinSize": "1", "MaxSize": "4"}}}
_SCHEDULE = {"Night": {"Type": "AWS::AutoScaling::ScheduledAction",
                       "Properties": {"AutoScalingGroupName": {"Ref": "Asg"}, "Recurrence": "0 20 * * *"}}}
_ALB = {"Alb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {}}}
_GA = {"Ga": {"Type": "AWS::GlobalAccelerator::Accelerator", "Properties": {"Name": "a"}}}
_BUCKET = {"B": {"Type": "AWS::S3::Bucket", "Properties": {}}}
_ACCEL_BUCKET = {"B": {"Type": "AWS::S3::Bucket",
                       "Properties": {"AccelerateConfiguration": {"AccelerationStatus": "Enabled"}}}}

# (rule, resources, signal that reports, resources that answer it)
CASES = [
    ("REL-011", _DB, {"defaults": {"db_instance": {"read_write_ratio": 6}}}, {**_DB, **_REPLICA}),
    ("OPS-023", _SSM, {"defaults": {"ssm_parameter": {"get_parameter_tps": 120}}}, None),
    ("SUST-002", _EC2, {"resources": {"Web": {"avg_cpu_percent": 7}}}, None),
    ("SUST-003", _ASG, {"workload": {"traffic_pattern": "business-hours"}}, {**_ASG, **_SCHEDULE}),
    ("PERF-011", _ALB, {"workload": {"user_regions": 3}}, {**_ALB, **_GA}),
    ("PERF-014", _BUCKET, {"workload": {"upload_regions": 2}}, _ACCEL_BUCKET),
]


@pytest.mark.parametrize(("rule_id", "resources", "signal", "_answered"), CASES)
def test_the_signal_reports(tmp_path: Path, rule_id: str, resources: dict, signal: dict, _answered: Any) -> None:
    repo = _cf(tmp_path, resources, signal)
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False)
    got = [f for f in findings if f.id == rule_id]
    assert len(got) == 1, rule_id
    assert got[0].title == RULES[rule_id].title and got[0].severity == "Low"
    assert "usage file" in (got[0].evidence or "").lower()
    assert rule_id in ctx.rules_run


@pytest.mark.parametrize(("rule_id", "resources", "_signal", "_answered"), CASES)
def test_no_signal_no_finding(tmp_path: Path, rule_id: str, resources: dict, _signal: dict, _answered: Any) -> None:
    repo = _cf(tmp_path, resources, None)
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False)
    assert rule_id not in {f.id for f in findings}
    assert rule_id not in ctx.rules_run  # unanswered, not met


@pytest.mark.parametrize(("rule_id", "_resources", "signal", "answered"),
                         [c for c in CASES if c[3] is not None])
def test_the_iac_answers_the_signal(tmp_path: Path, rule_id: str, _resources: dict, signal: dict,
                                    answered: dict) -> None:
    repo = _cf(tmp_path, answered, signal)
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False)
    assert rule_id not in {f.id for f in findings}
    assert rule_id in ctx.rules_run


@pytest.mark.parametrize(("rule_id", "resources", "quiet"), [
    ("REL-011", _DB, {"defaults": {"db_instance": {"read_write_ratio": 2}}}),
    ("OPS-023", _SSM, {"defaults": {"ssm_parameter": {"get_parameter_tps": 40}}}),
    ("SUST-002", _EC2, {"resources": {"Web": {"avg_cpu_percent": 55}}}),
    ("SUST-003", _ASG, {"workload": {"traffic_pattern": "steady"}}),
    ("PERF-011", _ALB, {"workload": {"user_regions": 1}}),
    ("PERF-014", _BUCKET, {"workload": {"upload_regions": 1}}),
])
def test_a_signal_under_the_threshold_is_met(tmp_path: Path, rule_id: str, resources: dict, quiet: dict) -> None:
    repo = _cf(tmp_path, resources, quiet)
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False)
    assert rule_id not in {f.id for f in findings}
    assert rule_id in ctx.rules_run


def test_ssm_higher_throughput_answers_ops_023(tmp_path: Path) -> None:
    setting = {"S": {"Type": "Custom::Setting", "Properties": {"SettingId": "/ssm/parameter-store/high-throughput-enabled"}}}
    repo = _cf(tmp_path, {**_SSM, **setting}, {"defaults": {"ssm_parameter": {"get_parameter_tps": 120}}})
    assert "OPS-023" not in _ids(repo)


def test_sust_002_does_not_repeat_cf_perf_004(tmp_path: Path) -> None:
    repo = _cf(tmp_path, _BIG_EC2, {"resources": {"Web": {"avg_cpu_percent": 7}}})
    ids = _ids(repo)
    assert "CF-PERF-004" in ids and "SUST-002" not in ids


def test_sust_002_type_default_needs_that_type(tmp_path: Path) -> None:
    repo = _cf(tmp_path, _BUCKET, {"defaults": {"instance": {"avg_cpu_percent": 5}}})
    assert "SUST-002" not in _ids(repo)


def test_terraform_signals(tmp_path: Path) -> None:
    body = (
        'resource "aws_db_instance" "db" {\n  engine = "postgres"\n  instance_class = "db.t3.small"\n}\n'
        'resource "aws_lb" "web" {\n  name = "web"\n}\n'
    )
    repo = _tf(tmp_path, body, {"defaults": {"db_instance": {"read_write_ratio": 9}},
                                "workload": {"user_regions": 2}})
    ids = _ids(repo)
    assert {"REL-011", "PERF-011"} <= ids


def test_cdk_source_signal(tmp_path: Path) -> None:
    (tmp_path / "cdk.json").write_text('{"app": "npx ts-node bin/app.ts"}\n', encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");\n', encoding="utf-8")
    assert "PERF-014" not in _ids(tmp_path)  # no usage file: quiet, as the advice rule never knew
    (tmp_path / usage.DEFAULT_FILE).write_text("workload:\n  upload_regions: 4\n", encoding="utf-8")
    assert "PERF-014" in _ids(tmp_path)


def test_the_scans_profile_wins_over_the_repo_file(tmp_path: Path) -> None:
    repo = _cf(tmp_path, _ALB, {"workload": {"user_regions": 1}})
    profile = usage.parse({"workload": {"user_regions": 5}})
    _r, _c, findings, _w = analyze_v1(repo, use_llm=False, finops=stack_cost.FinOps(usage=profile))
    assert "PERF-011" in {f.id for f in findings}


def test_a_stated_signal_answers_its_practice(tmp_path: Path) -> None:
    repo = _cf(tmp_path, {**_ALB, **_GA}, {"workload": {"user_regions": 3}})
    _r, ctx, findings, _w = analyze_v1(repo, use_llm=False)
    from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

    bp = RULE_BEST_PRACTICES["PERF-011"][0]
    question = next(a for a in answers(findings, ctx.rules_run) if bp in [p.id for p in a.question.best_practices])
    assert bp not in question.not_checked


@pytest.mark.parametrize(("data", "message"), [
    ({"workload": {"traffic_pattern": "weekly"}}, "traffic_pattern must be one of"),
    ({"workload": {"user_regions": 0}}, "user_regions must be a whole number"),
    ({"workload": {"upload_regions": 1.5}}, "upload_regions must be a whole number"),
    ({"workload": {"peak": 1}}, "unknown key(s) peak"),
    ({"defaults": {"instance": {"avg_cpu_percent": 120}}}, "avg_cpu_percent must be 100 or less"),
    ({"defaults": {"instance": {"monthly_requests": 1}}}, "unknown key(s) monthly_requests"),
    ({"defaults": {"ssm_parameter": {"get_parameter_tps": -1}}}, "must not be negative"),
])
def test_the_new_keys_are_validated(data: dict, message: str) -> None:
    with pytest.raises(usage.UsageError, match=message.replace("(", r"\(").replace(")", r"\)")):
        usage.parse(data)


def test_signals_are_not_priced() -> None:
    profile = usage.parse({"defaults": {"db_instance": {"read_write_ratio": 5}, "instance": {"avg_cpu_percent": 9}}})
    assert profile.for_resource("db_instance", "Db") is None
    assert profile.for_resource("instance", "Web") is None
