"""OPS 2: owners of procedures (REPO-165), operations activities (REPO-166), the ownership
mechanism (REPO-167) and requests for a change (REPO-168)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-165", ("OPS02-BP02",)), ("REPO-166", ("OPS02-BP03",)),
          ("REPO-167", ("OPS02-BP04", "OPS02-BP06")), ("REPO-168", ("OPS02-BP05",)))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / (rel[1:] if rel.startswith("/") else f"prod/{rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops2() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_every_rule(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    for rule_id, _ in _RULES:
        (hit,) = _found(findings, rule_id)
        assert hit.question == "OPS 2" and hit.category == "Operational Excellence"
        assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r, _ in _RULES)


@pytest.mark.parametrize(
    "files",
    [
        {"docs/runbooks/restore.md": "# Restore\n\nOwner: platform-team\n"},
        {"docs/procedures.md": "# Procedures\n\n**Owner** - @alice\n"},
    ],
    ids=["runbook", "procedure"],
)
def test_owned_procedure_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-165")


@pytest.mark.parametrize(
    "note", ["# Restore\n\nOwner: TBD\n", "# Restore\n\nRun the script.\n"],
    ids=["tbd", "no-owner"],
)
def test_procedure_without_an_owner_fails(tmp_path: Path, note: str) -> None:
    files = {**_TF, "docs/runbooks/restore.md": note}
    assert _found(_scan(tmp_path, files), "REPO-165")


@pytest.mark.parametrize(
    "files",
    [
        {"c.tf": 'resource "aws_ssmcontacts_contact" "c" {\n  alias = "c"\n}\n'},
        {"docs/on-call.md": "Platform is on call.\n"},
    ],
    ids=["iac", "note"],
)
def test_activity_owner_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-166")


@pytest.mark.parametrize(
    "files",
    [
        {"/CODEOWNERS": "* @org/platform\n"},
        {"docs/ownership.md": "Platform owns the network stack.\n"},
        {"c.tf": 'resource "aws_ssmcontacts_plan" "p" {}\n'},
    ],
    ids=["codeowners", "note", "plan"],
)
def test_ownership_mechanism_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-167")


def test_comment_only_codeowners_fails(tmp_path: Path) -> None:
    files = {**_TF, "/CODEOWNERS": "# add owners\n"}
    assert _found(_scan(tmp_path, files), "REPO-167")


@pytest.mark.parametrize(
    "files",
    [
        {"/.github/workflows/ci.yml": "on:\n  pull_request:\njobs: {}\n"},
        {"/.github/pull_request_template.md": "What changed?\n"},
        {"/.github/ISSUE_TEMPLATE/change.md": "Request\n"},
        {"p.tf": 'resource "aws_codepipeline" "p" {\n  stage {\n    action {\n'
                 '      category = "Approval"\n    }\n  }\n}\n'},
        {"lib/p.ts": "new actions.ManualApprovalAction({ actionName: 'Approve' });\n"},
    ],
    ids=["ci-trigger", "pr-template", "issue-template", "tf-approval", "cdk-approval"],
)
def test_change_request_path_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-168")
