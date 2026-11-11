"""SEC 3: permission boundaries (REPO-031) and a break-glass role (REPO-032)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    BreakGlassRoleMissing,
    PermissionBoundaryMissing,
    break_glass_roles,
)

SOURCES = ("cdk", "cloudformation", "terraform")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict[str, tuple[str, dict]]) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }}, indent=2)


def _stack(root: Path, source: str, body: str) -> None:
    path = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
            "terraform": "main.tf"}[source]
    _write(root / "prod" / path, body)


ROLE = {
    "cdk": "const worker = new iam.Role(this, 'Worker', { assumedBy });\n",
    "cloudformation": _cfn({"Worker": ("AWS::IAM::Role", {"AssumeRolePolicyDocument": {}})}),
    "terraform": 'resource "aws_iam_role" "worker" {\n  name = "worker"\n}\n',
}
BOUNDED = {
    "cdk": "const worker = new iam.Role(this, 'Worker', { assumedBy, "
           "permissionsBoundary: boundary });\n",
    "cloudformation": _cfn({"Worker": ("AWS::IAM::Role", {
        "AssumeRolePolicyDocument": {}, "PermissionsBoundary": "arn:aws:iam::1:policy/cap"})}),
    "terraform": 'resource "aws_iam_role" "worker" {\n  name = "worker"\n'
                 '  permissions_boundary = "arn:aws:iam::1:policy/cap"\n}\n',
}


# REPO-031: permissions boundary


@pytest.mark.parametrize("source", SOURCES)
def test_role_without_boundary_fails_repo_031(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ROLE[source])
    (finding,) = PermissionBoundaryMissing().run(tmp_path)
    assert finding.id == "REPO-031"
    assert "IAM role or user" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_role_with_boundary_passes_repo_031(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BOUNDED[source])
    assert PermissionBoundaryMissing().run(tmp_path) == []


def test_iam_user_counts_as_a_principal(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_iam_user" "ci" {\n  name = "ci"\n}\n')
    assert PermissionBoundaryMissing().run(tmp_path)


def test_cdk_boundary_aspect_and_context_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", ROLE["cdk"] + "iam.PermissionsBoundary.of(this).apply(cap);\n")
    assert PermissionBoundaryMissing().run(tmp_path) == []
    _stack(tmp_path, "cdk", ROLE["cdk"])
    _write(tmp_path / "cdk.json", json.dumps(
        {"app": "npx ts-node bin/app.ts",
         "context": {"@aws-cdk/core:permissionsBoundary": {"name": "cap"}}}))
    assert PermissionBoundaryMissing().run(tmp_path) == []


def test_python_cdk_boundary(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py", "iam.Role(self, 'Worker', assumed_by=principal)\n")
    assert PermissionBoundaryMissing().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py",
           "iam.Role(self, 'Worker', assumed_by=principal, permissions_boundary=cap)\n")
    assert PermissionBoundaryMissing().run(tmp_path) == []


def test_scp_passes_repo_031(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", ROLE["terraform"]
           + 'resource "aws_organizations_policy" "deny" {\n  name = "deny"\n}\n')
    assert PermissionBoundaryMissing().run(tmp_path) == []


def test_no_iam_principal_gets_no_repo_031(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_s3_bucket" "data" {\n  bucket = "d"\n}\n')
    assert PermissionBoundaryMissing().run(tmp_path) == []


def test_a_boundary_only_in_tests_does_not_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", ROLE["cdk"])
    _write(tmp_path / "test" / "stack.test.ts", "permissionsBoundary: boundary,\n")
    assert PermissionBoundaryMissing().run(tmp_path)


# REPO-032: break-glass role


BREAK_GLASS = {
    "cdk": "new iam.Role(this, 'BreakGlass', { assumedBy: new iam.AccountRootPrincipal(), "
           "maxSessionDuration });\n",
    "cloudformation": _cfn({"BreakGlassRole": ("AWS::IAM::Role", {
        "AssumeRolePolicyDocument": {}})}),
    "terraform": 'resource "aws_iam_role" "emergency_access" {\n  name = "emergency-access"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_no_break_glass_role_fails_repo_032(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ROLE[source])
    (finding,) = BreakGlassRoleMissing().run(tmp_path)
    assert finding.id == "REPO-032"
    assert "found none" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_break_glass_role_passes_repo_032(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ROLE[source] + "\n" + BREAK_GLASS[source]
           if source != "cloudformation" else BREAK_GLASS[source])
    assert BreakGlassRoleMissing().run(tmp_path) == []


def test_identity_center_permission_set_counts(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform",
           'resource "aws_ssoadmin_permission_set" "break_glass" {\n  name = "BreakGlass"\n}\n')
    found, _daily = break_glass_roles(tmp_path)
    assert found == {"break-glass permission set": "prod/main.tf"}
    assert BreakGlassRoleMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_workload_using_break_glass_role_fails_repo_032(tmp_path: Path, source: str) -> None:
    body = {
        "cdk": "const breakGlass = new iam.Role(this, 'BreakGlass', { assumedBy });\n"
               "new lambda.Function(this, 'Fn', { runtime, handler, code, role: breakGlass });\n",
        "cloudformation": json.dumps({"Resources": {
            "BreakGlassRole": {"Type": "AWS::IAM::Role", "Properties": {}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "Role": {"Fn::GetAtt": ["BreakGlassRole", "Arn"]}}},
        }}, indent=2),
        "terraform": 'resource "aws_iam_role" "break_glass" {\n  name = "break-glass"\n}\n'
                     'resource "aws_lambda_function" "fn" {\n'
                     "  role = aws_iam_role.break_glass.arn\n}\n",
    }[source]
    _stack(tmp_path, source, body)
    (finding,) = BreakGlassRoleMissing().run(tmp_path)
    assert "uses it as its role" in finding.evidence
    assert finding.file and finding.file.startswith("prod/")
    assert finding.line


def test_policies_attached_to_the_break_glass_role_are_not_use(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform",
           'resource "aws_iam_role" "break_glass" {\n  name = "break-glass"\n}\n'
           'resource "aws_iam_role_policy_attachment" "admin" {\n'
           "  role = aws_iam_role.break_glass.name\n  policy_arn = var.admin\n}\n")
    assert BreakGlassRoleMissing().run(tmp_path) == []
    _stack(tmp_path, "cloudformation", json.dumps({"Resources": {
        "BreakGlassRole": {"Type": "AWS::IAM::Role", "Properties": {}},
        "Admin": {"Type": "AWS::IAM::Policy", "Properties": {
            "Roles": [{"Ref": "BreakGlassRole"}]}},
    }}, indent=2))
    assert BreakGlassRoleMissing().run(tmp_path) == []


def test_repo_032_is_an_org_rule_and_031_is_not() -> None:
    assert "REPO-032" in ORG_RULE_IDS
    assert "REPO-031" not in ORG_RULE_IDS


def test_saved_report_quoting_findings_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", ROLE["cdk"])
    hits = PermissionBoundaryMissing().run(tmp_path) + BreakGlassRoleMissing().run(tmp_path)
    report = "\n".join(f"{f.id} {f.title}\n{f.evidence}\n{f.recommendation}" for f in hits)
    _write(tmp_path / "reports" / "report.md", report)
    assert len(PermissionBoundaryMissing().run(tmp_path)) == 1
    assert len(BreakGlassRoleMissing().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.md", report)
    assert PermissionBoundaryMissing().run(empty) == []
    (missing,) = BreakGlassRoleMissing().run(empty)
    assert "found none" in missing.evidence


# The answer


def test_sec3_rules_map_to_their_best_practices() -> None:
    assert well_architected.best_practices_of("REPO-031") == ("SEC03-BP05",)
    assert well_architected.best_practices_of("REPO-032") == ("SEC03-BP03",)
    assert well_architected.question_of("REPO-032") == "SEC 3"


def test_sec3_reads_not_met_while_practices_remain_unchecked() -> None:
    (sec3,) = [a for a in well_architected.answers([]) if a.question.id == "SEC 3"]
    assert sec3.not_checked == ("SEC03-BP01", "SEC03-BP04", "SEC03-BP06", "SEC03-BP08")
    assert not sec3.met
