"""PERF 5: KPIs with a threshold (REPO-184), automated remediation (REPO-185), a load test
(REPO-186) and a review note (REPO-187)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-184", ("PERF05-BP01", "PERF05-BP02")), ("REPO-185", ("PERF05-BP05",)),
          ("REPO-186", ("PERF05-BP04",)), ("REPO-187", ("PERF05-BP03", "PERF05-BP07")))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_ALARM = ('resource "aws_cloudwatch_metric_alarm" "a" {{\n  metric_name = "{metric}"\n'
          '  threshold = {limit}\n}}\n')
_HOST = {"i.tf": 'resource "aws_instance" "web" {\n  instance_type = "m5.large"\n}\n'}


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / (rel[1:] if rel.startswith("/") else f"prod/{rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_perf5() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_the_review_note_rule(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, _TF), "REPO-187")
    assert hit.question == "PERF 5" and hit.category == "Performance Efficiency"
    assert hit.evidence.startswith("Holds IaC (")


def test_compute_without_a_kpi_alarm_fails(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, _HOST), "REPO-184")
    assert hit.question == "PERF 5" and hit.file == "prod/i.tf"
    assert hit.evidence.startswith("Runs ")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    # REPO-185 and REPO-186 read the build and the compute, like REPO-047 and REPO-017.
    assert not any(_found(findings, r) for r in ("REPO-184", "REPO-187"))


@pytest.mark.parametrize(
    "files",
    [
        {"a.tf": _ALARM.format(metric="TargetResponseTime", limit="0.5")},
        {"a.tf": _ALARM.format(metric="CPUUtilization", limit=80)},
        {"a.json": '{"Resources": {"A": {"Type": "AWS::CloudWatch::Alarm", "Properties": '
                   '{"MetricName": "Duration", "Threshold": 3000}}}}'},
    ],
    ids=["latency", "cpu", "cfn"],
)
def test_kpi_alarm_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_HOST, **files}), "REPO-184")


@pytest.mark.parametrize(
    "files",
    [
        {"a.tf": _ALARM.format(metric="Errors", limit=1)},
        {"a.tf": _ALARM.format(metric="Latency", limit="var.limit")},
    ],
    ids=["not-performance", "threshold-from-variable"],
)
def test_alarm_without_a_kpi_fails(tmp_path: Path, files: dict) -> None:
    assert _found(_scan(tmp_path, {**_HOST, **files}), "REPO-184")


def test_metric_and_threshold_must_share_an_alarm(tmp_path: Path) -> None:
    text = ("# latency matters\n" + _ALARM.format(metric="Errors", limit=1))
    assert _found(_scan(tmp_path, {**_HOST, "a.tf": text}), "REPO-184")


def test_compute_without_automation_fails_the_remediation_rule(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, _HOST), "REPO-185")
    assert hit.question == "PERF 5"


def test_scaling_policy_passes_the_remediation_rule(tmp_path: Path) -> None:
    files = {**_HOST, "p.tf": 'resource "aws_autoscaling_policy" "p" {\n'
                              '  policy_type = "TargetTrackingScaling"\n}\n'}
    assert not _found(_scan(tmp_path, files), "REPO-185")


def test_load_test_rule_reads_the_build(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, _TF), "REPO-186")
    assert hit.question == "PERF 5"
    ci = {"/.github/workflows/ci.yml": "jobs:\n  load:\n    steps:\n      - run: k6 run load.js\n"}
    assert not _found(_scan(tmp_path, {**_TF, **ci}), "REPO-186")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/performance-review.md": "Monthly.\n"},
        {"docs/ops.md": "## Performance KPIs\n\np99 under 300 ms.\n"},
    ],
    ids=["named", "heading"],
)
def test_review_note_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-187")
