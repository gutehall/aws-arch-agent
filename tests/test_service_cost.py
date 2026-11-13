"""COST 5: cost requirements (REPO-179), the cost of each component (REPO-180) and licensing
(REPO-181)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-179", ("COST05-BP01", "COST05-BP06")),
          ("REPO-180", ("COST05-BP02", "COST05-BP03")), ("REPO-181", ("COST05-BP04",)))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_HOST = 'resource "aws_ec2_host" "h" {\n  instance_type = "m5.large"\n}\n'
_MARKET = 'data "aws_ami" "m" {\n  owners = ["aws-marketplace"]\n}\n'


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_cost5() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_the_cost_rules(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    (hit,) = _found(findings, "REPO-179")
    assert hit.question == "COST 5" and hit.category == "Cost"
    assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")
    assert not _found(findings, "REPO-181")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r, _ in _RULES)


@pytest.mark.parametrize(
    "files",
    [
        {"b.tf": 'resource "aws_budgets_budget" "b" {\n  name = "b"\n}\n'},
        {"b.json": '{"Resources": {"B": {"Type": "AWS::Budgets::Budget"}}}'},
        {"lib/b.ts": "new budgets.CfnBudget(this, 'B', { budget });\n"},
        {"docs/cost.md": "Steady usage is $400 a month; peak is $900.\n"},
    ],
    ids=["tf", "cfn", "cdk", "note"],
)
def test_cost_requirements_pass(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-179")


def test_cost_note_without_peak_and_steady_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/cost.md": "We try to spend less.\n"}
    assert _found(_scan(tmp_path, files), "REPO-179")


def test_component_cost_rule_fires_with_a_workload_and_no_estimate(tmp_path: Path) -> None:
    files = {"i.tf": 'resource "aws_instance" "web" {\n  instance_type = "m5.large"\n}\n'}
    (hit,) = _found(_scan(tmp_path, files), "REPO-180")
    assert hit.question == "COST 5"


def test_component_cost_rule_passes_with_an_estimate(tmp_path: Path) -> None:
    files = {"i.tf": 'resource "aws_instance" "web" {\n  instance_type = "m5.large"\n}\n',
             "docs/cost-estimate.md": "Estimated cost: $120 a month.\n"}
    assert not _found(_scan(tmp_path, files), "REPO-180")


def test_marketplace_image_on_a_dedicated_host_needs_a_licence_note(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, {"m.tf": _MARKET + _HOST}), "REPO-181")
    assert hit.question == "COST 5" and hit.file == "prod/m.tf"


@pytest.mark.parametrize(
    "files",
    [
        {"m.tf": _MARKET + _HOST, "docs/licensing.md": "BYOL.\n"},
        {"m.tf": _MARKET + _HOST, "docs/ops.md": "## Licences\n\nBring your own.\n"},
        {"m.tf": _MARKET},
        {"h.tf": _HOST},
    ],
    ids=["named", "heading", "no-host", "no-marketplace"],
)
def test_licence_rule_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-181")
