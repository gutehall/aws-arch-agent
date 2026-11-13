"""SEC 3: access requirements (REPO-140), permission reduction (REPO-141), access lifecycle
(REPO-142) and sharing within the organization (REPO-143)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-140", "SEC03-BP01"), ("REPO-141", "SEC03-BP04"), ("REPO-142", "SEC03-BP06"),
          ("REPO-143", "SEC03-BP08"))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_ROLE = 'resource "aws_iam_role" "{n}" {{\n  name = "{n}"\n}}\n'


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str], org: bool = True) -> list:
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False, rules_org=org)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_sec3() -> None:
    for rule_id, bp in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


def test_iac_with_nothing_fails_the_note_rules(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    for rule_id in ("REPO-140", "REPO-141"):
        (hit,) = _found(findings, rule_id)
        assert hit.question == "SEC 3" and hit.category == "Security"
        assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")
    assert not _found(findings, "REPO-142") and not _found(findings, "REPO-143")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r, _ in _RULES)


def test_permission_reduction_is_org_level(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, _TF, org=False), "REPO-141")


@pytest.mark.parametrize(
    "files",
    [
        {"r.tf": 'resource "aws_iam_role" "r" {\n  permissions_boundary = "arn"\n}\n'},
        {"r.json": '{"Resources": {"R": {"Type": "AWS::IAM::Role", '
                   '"Properties": {"PermissionsBoundary": "arn"}}}}'},
        {"r.tf": _ROLE.format(n="a") + _ROLE.format(n="b")},
        {"lib/s.ts": "new iam.Role(this, 'A', {});\nnew iam.Role(this, 'B', {});\n"},
        {"docs/access-model.md": "# Access\n\nThe api role reads the table.\n"},
        {"docs/design.md": "## Access requirements\n\nWho reaches what.\n"},
    ],
    ids=["tf-boundary", "cfn-boundary", "tf-roles", "cdk-roles", "named-note", "heading"],
)
def test_access_requirements_pass(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-140")


def test_one_role_alone_does_not_pass(tmp_path: Path) -> None:
    files = {**_TF, "r.tf": _ROLE.format(n="a")}
    assert _found(_scan(tmp_path, files), "REPO-140")


@pytest.mark.parametrize(
    "files",
    [
        {"a.tf": 'resource "aws_accessanalyzer_analyzer" "a" {\n  analyzer_name = "a"\n}\n'},
        {"a.json": '{"Resources": {"A": {"Type": "AWS::AccessAnalyzer::Analyzer"}}}'},
        {"lib/a.ts": "new accessanalyzer.CfnAnalyzer(this, 'A', { type: 'ACCOUNT' });\n"},
        {"docs/access-review-2026-03.md": "Removed s3:* from the api role.\nDate: 2026-03-02\n"},
        {"docs/iam.md": "## Permission review\n\nReviewed in March 2026.\n"},
    ],
    ids=["tf", "cfn", "cdk", "dated-note", "dated-heading"],
)
def test_permission_reduction_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-141")


def test_undated_access_review_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/access-review.md": "We should review access.\n"}
    assert _found(_scan(tmp_path, files), "REPO-141")


@pytest.mark.parametrize(
    ("files", "line"),
    [
        ({"u.tf": 'resource "aws_iam_user" "ci" {\n  name = "ci"\n}\n'}, 1),
        ({"u.tf": '# keys\nresource "aws_iam_access_key" "k" {\n  user = "ci"\n}\n'}, 2),
        ({"u.json": '{"Resources": {"U": {"Type": "AWS::IAM::User"}}}'}, 1),
        ({"lib/u.ts": "const x = 1;\nnew iam.User(this, 'CI');\n"}, 2),
    ],
    ids=["tf-user", "tf-key", "cfn-user", "cdk-user"],
)
def test_long_lived_identity_fires(tmp_path: Path, files: dict, line: int) -> None:
    (hit,) = _found(_scan(tmp_path, {**_TF, **files}), "REPO-142")
    assert hit.severity == "Medium" and hit.question == "SEC 3"
    assert hit.line == line


def test_roles_and_sso_pass_the_lifecycle_rule(tmp_path: Path) -> None:
    files = {**_TF, "r.tf": _ROLE.format(n="a"),
             "s.tf": 'resource "aws_ssoadmin_permission_set" "p" {\n  name = "p"\n}\n'}
    assert not _found(_scan(tmp_path, files), "REPO-142")


@pytest.mark.parametrize(
    "files",
    [
        {"r.tf": 'resource "aws_ram_resource_share" "s" {\n  name = "s"\n}\n'},
        {"r.json": '{"Resources": {"S": {"Type": "AWS::RAM::ResourceShare"}}}'},
        {"lib/r.ts": "new ram.CfnResourceShare(this, 'S', { name: 's' });\n"},
        {"r.tf": 'resource "aws_ram_resource_share" "s" {\n  allow_external_principals = true\n}\n'},
    ],
    ids=["tf-default", "cfn-default", "cdk-default", "tf-explicit-true"],
)
def test_open_ram_share_fires(tmp_path: Path, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, {**_TF, **files}), "REPO-143")
    assert hit.severity == "Medium" and hit.question == "SEC 3" and hit.line


@pytest.mark.parametrize(
    "files",
    [
        {"r.tf": 'resource "aws_ram_resource_share" "s" {\n  allow_external_principals = false\n}\n'},
        {"r.json": '{"Resources": {"S": {"Type": "AWS::RAM::ResourceShare", '
                   '"Properties": {"AllowExternalPrincipals": false}}}}'},
        {"lib/r.ts": "new ram.CfnResourceShare(this, 'S', { allowExternalPrincipals: false });\n"},
        {"main2.tf": 'resource "aws_s3_bucket" "c" {}\n'},
    ],
    ids=["tf", "cfn", "cdk", "no-share"],
)
def test_org_only_ram_share_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-143")
