"""OPS 7: runbooks (REPO-172), playbooks (REPO-173), a support plan (REPO-174) and the
operational readiness checklist (REPO-175)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-172", ("OPS07-BP03",)), ("REPO-173", ("OPS07-BP04",)),
          ("REPO-174", ("OPS07-BP06",)), ("REPO-175", ("OPS07-BP01", "OPS07-BP02")))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops7() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_every_rule(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    for rule_id, _ in _RULES:
        (hit,) = _found(findings, rule_id)
        assert hit.question == "OPS 7" and hit.category == "Operational Excellence"
        assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r, _ in _RULES)


@pytest.mark.parametrize(
    "files",
    [
        {"docs/runbooks/deploy.md": "Steps.\n"},
        {"docs/ops.md": "## Runbook\n\nRestore the table.\n"},
        {"d.tf": 'resource "aws_ssm_document" "d" {\n  name = "restore"\n}\n'},
        {"d.json": '{"Resources": {"D": {"Type": "AWS::SSM::Document"}}}'},
    ],
    ids=["folder", "heading", "tf-document", "cfn-document"],
)
def test_runbook_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-172")


def test_playbook_passes(tmp_path: Path) -> None:
    files = {**_TF, "docs/playbooks/latency.md": "Open the dashboard.\n"}
    findings = _scan(tmp_path, files)
    assert not _found(findings, "REPO-173") and not _found(findings, "REPO-122")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/support-plan.md": "Enterprise Support.\n"},
        {"docs/ops.md": "## AWS Support\n\nBusiness plan.\n"},
        {"s.tf": 'resource "aws_support_case" "c" {}\n'},
    ],
    ids=["named", "heading", "tf"],
)
def test_support_plan_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-174")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/readiness.md": "- [ ] alarms\n"},
        {"docs/launch.md": "## Operational readiness\n\nChecked.\n"},
    ],
    ids=["named", "heading"],
)
def test_readiness_checklist_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-175")
