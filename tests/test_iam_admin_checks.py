"""CF-IAM-008 (templates) and SEC-067 (CDK source): full admin access."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import iam_policy
from aws_arch_agent.rules.cf_template import (
    drop_static_covered_by_cf,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.security_iam import IamAdministratorAccess
from aws_arch_agent.rules.terraform_model import load_plan_values, resources_from_terraform

IAM_IDS = {"CF-IAM-001", "CF-IAM-002", "CF-IAM-003", "CF-IAM-008"}
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
# What CDK synth writes for ManagedPolicy.fromAwsManagedPolicyName("AdministratorAccess").
CDK_ADMIN = {"Fn::Join": ["", [
    "arn:", {"Ref": "AWS::Partition"}, ":iam::aws:policy/AdministratorAccess",
]]}


def _doc(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(action, resource="*") -> dict:
    return {"Effect": "Allow", "Action": action, "Resource": resource}


# --- policy analysis --------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "admin"),
    [
        (ADMIN, True),
        ("arn:aws-us-gov:iam::aws:policy/AdministratorAccess", True),
        ("arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess", True),
        (CDK_ADMIN, True),
        ({"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess"}, True),
        ("arn:aws:iam::aws:policy/AdministratorAccess-Amplify", False),
        ("arn:aws:iam::aws:policy/ReadOnlyAccess", False),
        ("arn:aws:iam::111122223333:policy/AdministratorAccess", False),  # customer managed
        ({"Fn::Join": ["", ["arn:", {"Ref": "AWS::Partition"},
                            ":iam::aws:policy/AdministratorAccess-AWSElasticBeanstalk"]]}, False),
        ({"Ref": "PolicyArn"}, False),
        ({"Fn::If": ["IsDev", CDK_ADMIN, {"Ref": "AWS::NoValue"}]}, False),  # not guessed
        (None, False),
    ],
)
def test_is_admin_policy_arn(value, admin: bool) -> None:
    assert iam_policy.is_admin_policy_arn(value) is admin


@pytest.mark.parametrize(
    ("doc", "kinds"),
    [
        (_doc(_allow("*")), ["admin"]),
        (_doc(_allow(["*"], ["*"])), ["admin"]),
        (_doc(_allow("*", "arn:aws:s3:::b")), ["all_actions"]),
        # Reported once, as admin, even with another Action "*" statement.
        (_doc(_allow("*"), _allow("*", "arn:aws:s3:::b")), ["admin"]),
        (_doc(_allow("*"), _allow("s3:*")), ["admin", "service_actions"]),
        (_doc(_allow("*", {"Ref": "R"})), ["all_actions"]),  # unknown resource: not admin
        (_doc({"Effect": "Deny", "Action": "*", "Resource": "*"}), []),
    ],
)
def test_broadest_admin(doc: dict, kinds: list[str]) -> None:
    assert [b.kind for b in iam_policy.broadest(doc)] == kinds


# --- CloudFormation -----------------------------------------------------------------


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IAM_IDS]


def _found(findings: list[Finding]) -> dict[str, str]:
    return {f.evidence.split(" ")[0]: f.id for f in findings}


def test_cloudformation_managed_and_inline_admin(tmp_path: Path) -> None:
    trust = _doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                  "Action": "sts:AssumeRole"})
    findings = _cf(tmp_path, {
        "Literal": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": trust, "ManagedPolicyArns": [ADMIN]}},
        "Cdk": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": trust, "ManagedPolicyArns": [CDK_ADMIN]}},
        "User": {"Type": "AWS::IAM::User", "Properties": {"ManagedPolicyArns": [ADMIN]}},
        "Group": {"Type": "AWS::IAM::Group", "Properties": {"Policies": [
            {"PolicyName": "everything", "PolicyDocument": _doc(_allow("*"))},
        ]}},
        "Managed": {"Type": "AWS::IAM::ManagedPolicy",
                    "Properties": {"PolicyDocument": _doc(_allow("*"))}},
        "Scoped": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": trust,
            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/ReadOnlyAccess", {"Ref": "Other"}]}},
        "Amplify": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": trust,
            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess-Amplify"]}},
    })
    assert _found(findings) == {
        "Literal": "CF-IAM-008",
        "Cdk": "CF-IAM-008",
        "User": "CF-IAM-008",
        "Group": "CF-IAM-008",
        "Managed": "CF-IAM-008",
    }
    assert {f.severity for f in findings} == {"High"}
    literal = next(f for f in findings if f.evidence.startswith("Literal"))
    assert "managed policy AdministratorAccess" in literal.recommendation
    group = next(f for f in findings if f.evidence.startswith("Group"))
    assert "policy everything" in group.recommendation


def test_admin_is_reported_once_not_also_as_all_actions(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Role": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": _doc(),
            "ManagedPolicyArns": [ADMIN],
            "Policies": [
                {"PolicyName": "bucket", "PolicyDocument": _doc(_allow("*", "arn:aws:s3:::b"))},
                {"PolicyName": "all", "PolicyDocument": _doc(_allow("*"))},
            ],
        }},
        "Scoped": {"Type": "AWS::IAM::ManagedPolicy",
                   "Properties": {"PolicyDocument": _doc(_allow("*", "arn:aws:s3:::b"))}},
    })
    assert sorted((f.evidence.split(" ")[0], f.id) for f in findings) == [
        ("Role", "CF-IAM-008"),
        ("Scoped", "CF-IAM-001"),
    ]


def test_cloudformation_fix_removes_the_managed_policy(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Role": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": _doc(), "ManagedPolicyArns": [ADMIN]}},
    })
    attach_fixes(findings, "cloudformation")
    code = findings[0].suggested_code or ""
    assert "remove arn:aws:iam::aws:policy/AdministratorAccess" in code
    assert "Policies:" in code and code.startswith("Role:")


def test_static_rules_are_dropped_when_cf_reports_admin() -> None:
    static = [Finding(id=i, title="t", recommendation="r") for i in ("SEC-001", "SEC-002", "SEC-067")]
    cf = [Finding(id="CF-IAM-008", title="t", recommendation="r")]
    assert [f.id for f in drop_static_covered_by_cf(static + cf)] == ["CF-IAM-008"]


# --- Terraform ------------------------------------------------------------------

ADMIN_TF = """\
data "aws_partition" "current" {}

data "aws_iam_policy" "admin" {
  name = "AdministratorAccess"
}

data "aws_iam_policy" "readonly" {
  arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "managed" {
  assume_role_policy  = "{}"
  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

resource "aws_iam_role" "inline" {
  assume_role_policy = "{}"
  inline_policy {
    name   = "everything"
    policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
  }
}

resource "aws_iam_role_policy_attachment" "role" {
  role       = aws_iam_role.inline.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_policy_attachment" "user" {
  user       = "ci"
  policy_arn = data.aws_iam_policy.admin.arn
}

resource "aws_iam_group_policy_attachment" "group" {
  group      = "admins"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_policy_attachment" "shared" {
  name       = "shared"
  roles      = [aws_iam_role.managed.name]
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachments_exclusive" "exclusive" {
  role_name   = "app"
  policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

resource "aws_iam_user_policy_attachments_exclusive" "user_exclusive" {
  user_name   = "ci"
  policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

resource "aws_iam_group_policy_attachments_exclusive" "group_exclusive" {
  group_name  = "admins"
  policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = "app"
  policy_arn = data.aws_iam_policy.readonly.arn
}

resource "aws_iam_role_policy_attachment" "from_var" {
  role       = "app"
  policy_arn = var.policy_arn
}

resource "aws_iam_role_policy_attachment" "amplify" {
  role       = "app"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess-Amplify"
}
"""


def _tf(module: Path, plan: dict | None = None) -> list[Finding]:
    resources = resources_from_terraform(module, plan_values=plan)
    return [f for f in run_resource_checks(resources, module / "main.tf") if f.id in IAM_IDS]


def test_terraform_admin_forms(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ADMIN_TF, encoding="utf-8")
    assert _found(_tf(tmp_path)) == {
        "aws_iam_role.managed": "CF-IAM-008",
        "aws_iam_role.inline": "CF-IAM-008",
        "aws_iam_role_policy_attachment.role": "CF-IAM-008",
        "aws_iam_user_policy_attachment.user": "CF-IAM-008",
        "aws_iam_group_policy_attachment.group": "CF-IAM-008",
        "aws_iam_policy_attachment.shared": "CF-IAM-008",
        "aws_iam_role_policy_attachments_exclusive.exclusive": "CF-IAM-008",
        "aws_iam_user_policy_attachments_exclusive.user_exclusive": "CF-IAM-008",
        "aws_iam_group_policy_attachments_exclusive.group_exclusive": "CF-IAM-008",
    }


def test_terraform_finding_points_at_the_attachment(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ADMIN_TF, encoding="utf-8")
    group = next(f for f in _tf(tmp_path) if f.evidence.startswith("aws_iam_group_policy_attachment"))
    lines = ADMIN_TF.splitlines()
    assert group.line is not None
    assert lines[group.line - 1].startswith('resource "aws_iam_group_policy_attachment"')


def test_terraform_plan_fills_an_attachment_from_var(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ADMIN_TF, encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"planned_values": {"root_module": {"resources": [{
        "address": "aws_iam_role_policy_attachment.from_var",
        "mode": "managed",
        "values": {"role": "app", "policy_arn": ADMIN},
    }]}}}), encoding="utf-8")
    found = _found(_tf(tmp_path, load_plan_values(plan_path)))
    assert found["aws_iam_role_policy_attachment.from_var"] == "CF-IAM-008"


def test_terraform_fix_matches_the_resource_shape(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ADMIN_TF, encoding="utf-8")
    findings = attach_fixes(_tf(tmp_path), "terraform")
    by_name = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert 'resource "aws_iam_role_policy_attachment" "role"' in by_name[
        "aws_iam_role_policy_attachment.role"]
    assert "policy_arn = aws_iam_policy.role.arn" in by_name["aws_iam_role_policy_attachment.role"]
    assert "drop AdministratorAccess from managed_policy_arns" in by_name["aws_iam_role.managed"]
    assert "policy_arns = [aws_iam_policy.exclusive.arn]" in by_name[
        "aws_iam_role_policy_attachments_exclusive.exclusive"]
    assert 'resource "aws_iam_group_policy_attachments_exclusive" "group_exclusive"' in by_name[
        "aws_iam_group_policy_attachments_exclusive.group_exclusive"]
    assert all("In CDK" not in f.recommendation for f in findings)


# --- CDK source (SEC-067) -------------------------------------------------------


def _cdk(tmp_path: Path, lang: str, code: str) -> list[Finding]:
    if lang == "typescript":
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "stack.ts").write_text(code, encoding="utf-8")
    else:
        (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return IamAdministratorAccess().run(tmp_path, lang)


@pytest.mark.parametrize(
    ("lang", "code", "hits"),
    [
        ("typescript", "role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess'));", 1),
        ("typescript", 'iam.ManagedPolicy.fromAwsManagedPolicyName( "AdministratorAccess" )', 1),
        ("typescript", "iam.ManagedPolicy.fromManagedPolicyArn(this, 'A', 'arn:aws:iam::aws:policy/AdministratorAccess')", 1),
        ("typescript", "iam.ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess-Amplify')", 0),
        ("typescript", "iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess')", 0),
        ("python", "iam.ManagedPolicy.from_aws_managed_policy_name(\"AdministratorAccess\")", 1),
        ("python", "iam.ManagedPolicy.from_aws_managed_policy_name('PowerUserAccess')", 0),
    ],
)
def test_cdk_source_admin(tmp_path: Path, lang: str, code: str, hits: int) -> None:
    findings = _cdk(tmp_path, lang, code)
    assert len(findings) == hits
    assert all(f.severity == "High" and f.suggested_code for f in findings)
