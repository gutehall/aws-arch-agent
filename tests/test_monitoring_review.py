"""REL 6: a dated review record of the monitoring scope (REPO-147)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TABLE = 'resource "aws_dynamodb_table" "t" {\n  name = "t"\n}\n'


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _hits(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-147"]


def test_rule_answers_rel6() -> None:
    assert RULE_BEST_PRACTICES["REPO-147"] == ("REL06-BP06",)
    assert "REL06-BP06" not in NOT_CHECKED


def test_stateful_resource_without_review_fires(tmp_path: Path) -> None:
    (hit,) = _hits(_scan(tmp_path, {"t.tf": _TABLE}))
    assert hit.question == "REL 6" and hit.category == "Reliability" and hit.severity == "Low"
    assert hit.file == "prod/t.tf" and "DynamoDB table" in hit.evidence


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("docs/monitoring-review-2026-03.md", "Alarms for the table.\nDate: 2026-03-02\n"),
        ("docs/alarm-coverage.md", "Reviewed in March 2026.\n"),
        ("docs/ops.md", "## Monitoring review\n\nDone on 2026-04-01.\n"),
    ],
    ids=["named", "named-month", "heading"],
)
def test_dated_review_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _hits(_scan(tmp_path, {"t.tf": _TABLE, name: text}))


def test_undated_review_fails(tmp_path: Path) -> None:
    files = {"t.tf": _TABLE, "docs/monitoring-review.md": "We should review alarms.\n"}
    assert _hits(_scan(tmp_path, files))


def test_no_stateful_resource_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"f.tf": 'resource "aws_lambda_function" "f" {}\n'})
    assert not _hits(findings)
