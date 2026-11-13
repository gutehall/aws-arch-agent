"""REL 7: a load test shows the workload adapts to demand (REPO-148, the REPO-017 search)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_WORKFLOW = ".github/workflows/ci.yml"


def _scan(root: Path, files: dict[str, str]) -> list:
    files = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n', **files}
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _ids(findings: list, *ids: str) -> dict[str, list]:
    return {i: [f for f in findings if f.id == i] for i in ids}


def test_rule_answers_rel7() -> None:
    assert RULE_BEST_PRACTICES["REPO-148"] == ("REL07-BP04",)
    assert "REL07-BP04" not in NOT_CHECKED


def test_no_load_test_fires_both_rules(tmp_path: Path) -> None:
    hits = _ids(_scan(tmp_path, {}), "REPO-017", "REPO-148")
    assert len(hits["REPO-017"]) == 1 and len(hits["REPO-148"]) == 1
    assert hits["REPO-148"][0].question == "REL 7"
    assert hits["REPO-017"][0].question == "REL 12"
    assert hits["REPO-148"][0].evidence == hits["REPO-017"][0].evidence


@pytest.mark.parametrize(
    "run",
    ["k6 run load/checkout.js", "artillery run load.yml", "locust --headless -f l.py"],
)
def test_load_test_in_ci_passes_both_rules(tmp_path: Path, run: str) -> None:
    workflow = f"name: ci\non: [push]\njobs:\n  load:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {run}\n"
    hits = _ids(_scan(tmp_path, {_WORKFLOW: workflow}), "REPO-017", "REPO-148")
    assert not hits["REPO-017"] and not hits["REPO-148"]


def test_ci_without_a_load_test_names_the_build(tmp_path: Path) -> None:
    workflow = "name: ci\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n"
    (hit,) = _ids(_scan(tmp_path, {_WORKFLOW: workflow}), "REPO-148")["REPO-148"]
    assert ".github/workflows/ci.yml" in hit.evidence
