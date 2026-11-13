"""PERF 1: an architecture decision record that shows how the choice was made (REPO-183)."""
from pathlib import Path

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_FULL = (
    "# Compute choice\n\nWe considered Lambda and Fargate. The Well-Architected guidance and the "
    "reference architecture for serverless APIs favour Lambda. Cost: Lambda is $40 a month "
    "against $120. Tradeoff: cold starts for the first request. We ran a benchmark and the "
    "measured p99 was 180 ms, which is the data we used.\n"
)


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-183"]


def test_rule_answers_perf1() -> None:
    bps = tuple(f"PERF01-BP0{i}" for i in range(1, 8))
    assert RULE_BEST_PRACTICES["REPO-183"] == bps
    assert not set(bps) & NOT_CHECKED


def test_no_record_fails(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, _TF))
    assert hit.question == "PERF 1" and hit.category == "Performance Efficiency"
    assert "found none" in hit.evidence


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, {"README.md": "# app\n"}))


def test_complete_record_passes(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, {**_TF, "docs/adr/0001-compute.md": _FULL}))


def test_incomplete_record_names_what_is_missing(tmp_path: Path) -> None:
    files = {**_TF, "docs/adr/0001-compute.md": "# Compute\n\nWe chose Lambda.\n"}
    (hit,) = _found(_scan(tmp_path, files))
    assert "the cost comparison" in hit.evidence and "the benchmark" in hit.evidence


def test_sections_can_come_from_several_records(tmp_path: Path) -> None:
    half = _FULL.split("Cost:")[0]
    rest = "# Pricing\n\nCost: $40. Tradeoff: cold starts. A benchmark gave measured results.\n"
    files = {**_TF, "docs/adr/0001-a.md": half, "docs/adr/0002-b.md": rest}
    assert not _found(_scan(tmp_path, files))
