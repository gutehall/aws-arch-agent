"""SEC 11: security training (REPO-117), a penetration test record (REPO-118), required code
review (REPO-119), programmatic deploys (REPO-120) and security ownership (REPO-121)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import (
    CodeReviewNotEnforced,
    PenetrationTestMissing,
    ProgrammaticDeployMissing,
    SecurityOwnershipMissing,
    SecurityTrainingMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_IDS_BP = (("REPO-117", "SEC11-BP01"), ("REPO-118", "SEC11-BP03"), ("REPO-119", "SEC11-BP04"),
           ("REPO-120", "SEC11-BP06"), ("REPO-121", "SEC11-BP08"))
_SOURCES = [
    {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'},
    {"t.json": '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"B": '
               '{"Type": "AWS::S3::Bucket"}}}'},
    {"cdk.json": "{}", "lib/stack.ts": "new s3.Bucket(this, 'B');\n"},
]
_SRC_IDS = ["terraform", "cloudformation", "cdk"]
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str]) -> list:
    # Under prod/: the pytest directory name says "test", which reads as a dev stack.
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_sec11() -> None:
    for rule_id, bp in _IDS_BP:
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


@pytest.mark.parametrize("rule_id", [r for r, _ in _IDS_BP])
@pytest.mark.parametrize("files", _SOURCES, ids=_SRC_IDS)
def test_iac_with_no_practice_fails(tmp_path: Path, rule_id: str, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), rule_id)
    assert hit.question == "SEC 11"
    assert hit.category == "Security"
    assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


@pytest.mark.parametrize("rule_id", [r for r, _ in _IDS_BP])
def test_repo_without_iac_does_not_fire(tmp_path: Path, rule_id: str) -> None:
    assert not _found(_scan(tmp_path, {"README.md": "# app\n"}), rule_id)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("SECURITY_TRAINING.md", "# Notes\nWe run courses.\n"),
        ("docs/security-awareness.md", "Yearly.\n"),
        ("README.md", "# App\n\n## Secure coding\n\nOWASP course each year.\n"),
        ("docs/team.md", "## Security training\nEveryone takes the AWS course.\n"),
    ],
    ids=["named", "awareness-name", "heading", "heading-docs"],
)
def test_training_note_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _found(_scan(tmp_path, {**_TF, name: text}), "REPO-117")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("docs/pentest-2026-03.md", "Scope: API. Findings: 2 medium.\nDate: 2026-03-14\n"),
        ("docs/security.md", "## Penetration test\n\nLast run 2026-02-10 by a vendor.\n"),
        ("security/penetration-testing.md", "Tested in March 2026.\n"),
    ],
    ids=["named", "heading", "month-year"],
)
def test_dated_pentest_record_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _found(_scan(tmp_path, {**_TF, name: text}), "REPO-118")


def test_undated_pentest_note_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/pentest.md": "We should run a pen test sometime.\n"}
    assert _found(_scan(tmp_path, files), "REPO-118")


@pytest.mark.parametrize(
    "files",
    [
        {"gh.tf": 'resource "github_branch_protection" "main" {\n  pattern = "main"\n'
                  '  required_pull_request_reviews {\n    required_approving_review_count = 1\n'
                  '  }\n}\n'},
        {"gh2.tf": 'resource "github_repository_ruleset" "r" {\n  name = "main"\n}\n'},
        {"cc.tf": 'resource "aws_codecommit_approval_rule_template" "t" {\n  name = "t"\n}\n'},
        {"lib/repo.ts": "new codecommit.CfnApprovalRuleTemplate(this, 'T', {});\n"},
    ],
    ids=["branch-protection", "ruleset", "approval-tf", "approval-cdk"],
)
def test_review_enforced_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-119")


@pytest.mark.parametrize("path", ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"])
def test_codeowners_passes(tmp_path: Path, path: str) -> None:
    _write(tmp_path / path, "* @org/platform\n")
    _write(tmp_path / "main.tf", _TF["main.tf"])
    assert not CodeReviewNotEnforced().run(tmp_path)


def test_branch_protection_in_repo_settings_passes(tmp_path: Path) -> None:
    _write(tmp_path / ".github" / "settings.yml",
           "branches:\n  - name: main\n    protection:\n      required_pull_request_reviews:\n"
           "        required_approving_review_count: 1\n")
    _write(tmp_path / "main.tf", _TF["main.tf"])
    assert not CodeReviewNotEnforced().run(tmp_path)


@pytest.mark.parametrize(
    "files",
    [
        {"cd/pipeline.tf": 'resource "aws_codepipeline" "p" {\n  name = "p"\n}\n'},
        {"lib/pipe.ts": "new pipelines.CodePipeline(this, 'Pipe', { synth });\n"},
    ],
    ids=["terraform-pipeline", "cdk-pipeline"],
)
def test_pipeline_deploy_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-120")


def test_ci_workflow_that_deploys_passes(tmp_path: Path) -> None:
    _write(tmp_path / ".github/workflows/deploy.yml",
           "name: deploy\non: [push]\njobs:\n  d:\n    steps:\n      - run: terraform apply "
           "-auto-approve\n")
    _write(tmp_path / "main.tf", _TF["main.tf"])
    assert not ProgrammaticDeployMissing().run(tmp_path)


def test_ci_that_only_tests_still_fails_deploy(tmp_path: Path) -> None:
    _write(tmp_path / ".github/workflows/ci.yml",
           "name: ci\non: [push]\njobs:\n  t:\n    steps:\n      - run: pytest\n")
    _write(tmp_path / "main.tf", _TF["main.tf"])
    assert ProgrammaticDeployMissing().run(tmp_path)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("SECURITY.md", "# Security policy\nReport issues to security@example.com\n"),
        ("docs/security-owners.md", "Owner: @alice\n"),
        ("docs/team.md", "## Security champions\n\n- @alice\n"),
    ],
    ids=["security-md", "owners-note", "champions-heading"],
)
def test_security_ownership_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _found(_scan(tmp_path, {**_TF, name: text}), "REPO-121")


def test_codeowners_line_for_security_passes(tmp_path: Path) -> None:
    _write(tmp_path / "CODEOWNERS", "/iam/ @org/security-team\n")
    _write(tmp_path / "main.tf", _TF["main.tf"])
    assert not SecurityOwnershipMissing().run(tmp_path)


def test_codeowners_without_security_still_fails_ownership(tmp_path: Path) -> None:
    _write(tmp_path / "CODEOWNERS", "* @org/platform\n")
    _write(tmp_path / "main.tf", _TF["main.tf"])
    assert SecurityOwnershipMissing().run(tmp_path)


def test_notes_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", _TF["main.tf"])
    _write(tmp_path / "tests" / "SECURITY_TRAINING.md", "# x\n")
    _write(tmp_path / "tests" / "pentest-2026-03.md", "2026-03-14\n")
    assert SecurityTrainingMissing().run(tmp_path)
    assert PenetrationTestMissing().run(tmp_path)
    assert SecurityOwnershipMissing().run(tmp_path)
