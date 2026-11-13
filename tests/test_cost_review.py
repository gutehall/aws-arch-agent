"""COST 10: a recurring cost review (REPO-182)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-182"]


def test_rule_answers_cost10() -> None:
    assert RULE_BEST_PRACTICES["REPO-182"] == ("COST10-BP01", "COST10-BP02")
    assert not {"COST10-BP01", "COST10-BP02"} & NOT_CHECKED


def test_bare_iac_fails(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, _TF))
    assert hit.question == "COST 10" and hit.category == "Cost"
    assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, {"README.md": "# app\n"}))


@pytest.mark.parametrize(
    "files",
    [
        {"docs/cost-review-2026-03.md": "Re-checked Graviton prices on 2026-03-02.\n"},
        {"docs/finops.md": "## Cost review\n\nReviewed in March 2026.\n"},
        {"e.tf": 'resource "aws_bcmdataexports_export" "e" {}\n'},
        {"e.json": '{"Resources": {"A": {"Type": "AWS::CE::AnomalySubscription"}}}'},
    ],
    ids=["named", "heading", "tf-export", "cfn-anomaly"],
)
def test_review_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}))


def test_undated_cost_review_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/cost-review.md": "We look at the bill sometimes.\n"}
    assert _found(_scan(tmp_path, files))
