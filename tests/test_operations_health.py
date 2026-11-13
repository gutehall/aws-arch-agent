"""OPS 9: operations metrics (REPO-157), operator status (REPO-158) and a dated review of the
operations metrics (REPO-159)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-157", "OPS09-BP01"), ("REPO-158", "OPS09-BP02"), ("REPO-159", "OPS09-BP03"))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_ALARM = ('resource "aws_cloudwatch_metric_alarm" "a" {\n  alarm_name = "errors"\n'
          '  metric_name = "Errors"\n}\n')


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _hits(findings: list, rule_id: str) -> list:
    return [f for f in findings if f.id == rule_id]


def test_rules_answer_ops9() -> None:
    for rule_id, bp in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


@pytest.mark.parametrize("rule_id", ["REPO-157", "REPO-159"])
def test_iac_with_nothing_fails(tmp_path: Path, rule_id: str) -> None:
    (hit,) = _hits(_scan(tmp_path, _TF), rule_id)
    assert hit.question == "OPS 9" and hit.category == "Operational Excellence"
    assert hit.severity == "Low" and hit.evidence.endswith("found none")


@pytest.mark.parametrize("rule_id", ["REPO-157", "REPO-158", "REPO-159"])
def test_repo_without_iac_does_not_fire(tmp_path: Path, rule_id: str) -> None:
    assert not _hits(_scan(tmp_path, {"README.md": "# app\n"}), rule_id)


@pytest.mark.parametrize(
    "files",
    [
        {"m.tf": 'resource "aws_cloudwatch_metric_alarm" "d" {\n  metric_name = "DeploymentCount"\n}\n'},
        {"s.json": '{"Resources": {"S": {"Type": "AWS::ApplicationSignals::ServiceLevelObjective"}}}'},
        {"lib/s.ts": "const errorBudget = 0.001;\n"},
        {".github/workflows/ci.yml": "name: ci\non: [push]\njobs:\n  d:\n    runs-on: ubuntu-latest\n"
                                     "    steps:\n      - run: aws cloudwatch put-metric-data "
                                     "--metric-name DeploymentFrequency --value 1\n"},
    ],
    ids=["tf-deploy-count", "cfn-slo", "cdk-error-budget", "ci-put-metric-data"],
)
def test_operations_metric_passes(tmp_path: Path, files: dict) -> None:
    assert not _hits(_scan(tmp_path, {**_TF, **files}), "REPO-157")


def test_alarms_without_a_dashboard_or_status_topic_fire(tmp_path: Path) -> None:
    (hit,) = _hits(_scan(tmp_path, {"a.tf": _ALARM}), "REPO-158")
    assert hit.question == "OPS 9" and hit.severity == "Low" and "alarms" in hit.evidence


@pytest.mark.parametrize(
    "extra",
    [
        {"d.tf": 'resource "aws_cloudwatch_dashboard" "d" {\n  dashboard_name = "ops"\n}\n'},
        {"d.json": '{"Resources": {"D": {"Type": "AWS::CloudWatch::Dashboard"}}}'},
        {"lib/d.ts": "new cloudwatch.Dashboard(this, 'Ops');\n"},
    ],
    ids=["tf", "cfn", "cdk"],
)
def test_dashboard_passes(tmp_path: Path, extra: dict) -> None:
    assert not _hits(_scan(tmp_path, {"a.tf": _ALARM, **extra}), "REPO-158")


def test_no_alarms_means_no_status_finding(tmp_path: Path) -> None:
    assert not _hits(_scan(tmp_path, _TF), "REPO-158")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("docs/ops-review-2026-03.md", "Alarm count fell.\nDate: 2026-03-02\n"),
        ("docs/operations-metrics.md", "Reviewed in March 2026.\n"),
        ("docs/team.md", "## Operations review\n\nHeld on 2026-04-01.\n"),
        ("docs/retro-2026-02.md", "Date: 2026-02-10\n"),
    ],
    ids=["named", "metrics", "heading", "retro"],
)
def test_dated_review_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _hits(_scan(tmp_path, {**_TF, name: text}), "REPO-159")


def test_undated_review_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/ops-review.md": "We should review operations.\n"}
    assert _hits(_scan(tmp_path, files), "REPO-159")
