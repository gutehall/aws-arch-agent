"""Dependency alarms, workload alarms and trace analysis: CF-OBS-001..003."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform
from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

IDS = ("CF-OBS-001", "CF-OBS-002", "CF-OBS-003")
_FN = {"Type": "AWS::Lambda::Function", "Properties": {}}
_TABLE = {"Type": "AWS::DynamoDB::Table", "Properties": {}}
_XRAY = {"Type": "AWS::XRay::Group", "Properties": {"GroupName": "slow", "FilterExpression": "responsetime > 5"}}


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


def _alarm(namespace: Any, metric: str = "Errors", **props: Any) -> dict:
    return {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": namespace, "MetricName": metric, "AlarmActions": ["arn:aws:sns:eu-west-1:1:t"], **props}}


def _tf_alarm(label: str, namespace: str, metric: str = "Errors") -> str:
    return (f'resource "aws_cloudwatch_metric_alarm" "{label}" {{\n  alarm_name = "{label}"\n'
            f'  namespace = "{namespace}"\n  metric_name = "{metric}"\n  comparison_operator = "GreaterThanThreshold"\n'
            '  evaluation_periods = 1\n  threshold = 1\n  period = 60\n  statistic = "Sum"\n'
            '  alarm_actions = ["arn:aws:sns:eu-west-1:1:t"]\n}\n')


_TF_FN = 'resource "aws_lambda_function" "f" {\n  function_name = "f"\n  role = "r"\n}\n'
_TF_TABLE = 'resource "aws_dynamodb_table" "t" {\n  name = "t"\n  hash_key = "id"\n}\n'
_TF_XRAY = 'resource "aws_xray_group" "g" {\n  group_name = "g"\n  filter_expression = "responsetime > 5"\n}\n'


def test_each_check_answers_one_practice() -> None:
    assert RULE_BEST_PRACTICES["CF-OBS-001"] == ("OPS04-BP04",)
    assert RULE_BEST_PRACTICES["CF-OBS-002"] == ("OPS08-BP01",)
    assert RULE_BEST_PRACTICES["CF-OBS-003"] == ("OPS08-BP03",)


# --- CF-OBS-001 ---

def test_cf_dependency_without_alarm(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"T": _TABLE, "A": _alarm("AWS/Lambda")}).get("CF-OBS-001") == {"T"}


def test_cf_dependency_alarm_or_unreadable_alarm_passes(tmp_path: Path) -> None:
    assert "CF-OBS-001" not in _cf(tmp_path, {"T": _TABLE, "A": _alarm("AWS/DynamoDB", "ThrottledRequests")})
    assert "CF-OBS-001" not in _cf(tmp_path, {"T": _TABLE, "A": _alarm({"Ref": "Namespace"})})
    assert "CF-OBS-001" not in _cf(tmp_path, {"F": _FN})


def test_tf_dependency_without_and_with_alarm(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_TABLE).get("CF-OBS-001") == {"aws_dynamodb_table.t"}
    assert "CF-OBS-001" not in _tf(tmp_path, _TF_TABLE + _tf_alarm("t", "AWS/DynamoDB", "ThrottledRequests"))
    module = 'module "alarms" {\n  source = "app.terraform.io/acme/alarms/aws"\n}\n'
    assert "CF-OBS-001" not in _tf(tmp_path, _TF_TABLE + module)


# --- CF-OBS-002 ---

def test_cf_only_infrastructure_alarms(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"F": _FN, "A": _alarm("AWS/Lambda"), "X": _XRAY}).get("CF-OBS-002") == {"A"}
    edge = _alarm("AWS/ApplicationELB", "RequestCount")
    assert _cf(tmp_path, {"F": _FN, "A": edge, "X": _XRAY}).get("CF-OBS-002") == {"A"}


def test_cf_workload_alarm_passes(tmp_path: Path) -> None:
    assert "CF-OBS-002" not in _cf(tmp_path, {"F": _FN, "A": _alarm("AWS/Lambda"), "K": _alarm("MyApp", "OrdersFailed")})
    assert "CF-OBS-002" not in _cf(tmp_path, {"F": _FN, "A": _alarm("AWS/ApplicationELB", "TargetResponseTime")})
    band = {"Type": "AWS::CloudWatch::Alarm", "Properties": {"ThresholdMetricId": "ad", "Metrics": [
        {"Id": "m", "MetricStat": {"Metric": {"Namespace": "AWS/Lambda", "MetricName": "Duration"},
                                   "Period": 60, "Stat": "p99"}},
        {"Id": "ad", "Expression": "ANOMALY_DETECTION_BAND(m, 2)"}]}}
    assert "CF-OBS-002" not in _cf(tmp_path, {"F": _FN, "B": band})


def test_cf_no_alarm_is_left_to_cf_alarm_001(tmp_path: Path) -> None:
    assert "CF-OBS-002" not in _cf(tmp_path, {"F": _FN})


def test_tf_only_infrastructure_alarms(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_FN + _tf_alarm("cpu", "AWS/Lambda")).get("CF-OBS-002") == {
        "aws_cloudwatch_metric_alarm.cpu"}


def test_tf_workload_alarm_in_metric_query_passes(tmp_path: Path) -> None:
    query = ('resource "aws_cloudwatch_metric_alarm" "kpi" {\n  alarm_name = "kpi"\n'
             '  comparison_operator = "GreaterThanThreshold"\n  evaluation_periods = 1\n  threshold = 1\n'
             '  metric_query {\n    id = "m"\n    metric {\n      namespace = "MyApp"\n'
             '      metric_name = "OrdersFailed"\n      period = 60\n      stat = "Sum"\n    }\n  }\n}\n')
    assert "CF-OBS-002" not in _tf(tmp_path, _TF_FN + _tf_alarm("cpu", "AWS/Lambda") + query)


# --- CF-OBS-003 ---

def test_cf_compute_without_trace_analysis(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"F": _FN}).get("CF-OBS-003") == {"F"}


def test_cf_trace_analysis_passes(tmp_path: Path) -> None:
    assert "CF-OBS-003" not in _cf(tmp_path, {"F": _FN, "X": _XRAY})
    rule = {"Type": "AWS::XRay::SamplingRule", "Properties": {}}
    assert "CF-OBS-003" not in _cf(tmp_path, {"F": _FN, "S": rule})
    assert "CF-OBS-003" not in _cf(tmp_path, {"F": _FN, "A": _alarm("ApplicationSignals", "Fault")})
    assert "CF-OBS-003" not in _cf(tmp_path, {"T": _TABLE})


def test_tf_compute_with_and_without_trace_analysis(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_FN).get("CF-OBS-003") == {"aws_lambda_function.f"}
    assert "CF-OBS-003" not in _tf(tmp_path, _TF_FN + _TF_XRAY)
    assert "CF-OBS-003" not in _tf(tmp_path, _TF_FN + _tf_alarm("trace", "AWS/X-Ray", "ApproximateTraceCount"))
