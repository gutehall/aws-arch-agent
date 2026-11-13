"""SEC 2: people sign in through a central identity provider, workloads use temporary
credentials, and permissions come from groups (CF-IAM-009 to CF-IAM-011, SEC-069 to
SEC-071). SEC 1: the account root user is checked (REPO-006)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.registry import ALL_RULES

RULE_BY_ID = {r.id: r for r in ALL_RULES}
SOURCES = ("cdk", "cloudformation", "terraform")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _scan(root: Path, files: dict[str, str]) -> tuple[list, list[str]]:
    for rel, text in files.items():
        _write(root / rel, text)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings, ctx.rules_run


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def _answer(findings: list, ran: list[str], question: str):
    return {a.question.id: a for a in well_architected.answers(findings, ran)}[question]


USER = {"Type": "AWS::IAM::User", "Properties": {"UserName": "alice"}}
POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


# --- CF-IAM-009: a console password on an IAM user (SEC02-BP04) ---

@pytest.mark.parametrize(
    ("files", "fires"),
    [
        ({"t.json": _cfn({"Alice": {"Type": "AWS::IAM::User", "Properties": {
            "LoginProfile": {"Password": "Initial-1", "PasswordResetRequired": True}}}})}, True),
        ({"t.json": _cfn({"Alice": USER})}, False),
        ({"main.tf": 'resource "aws_iam_user" "alice" {\n  name = "alice"\n}\n'
                     'resource "aws_iam_user_login_profile" "alice" {\n'
                     '  user = aws_iam_user.alice.name\n}\n'}, True),
        ({"main.tf": 'resource "aws_iam_user" "deploy" {\n  name = "deploy"\n}\n'}, False),
    ],
    ids=["cfn-login-profile", "cfn-no-login-profile", "tf-login-profile", "tf-user-only"],
)
def test_console_password_on_an_iam_user(tmp_path: Path, files: dict, fires: bool) -> None:
    findings, ran = _scan(tmp_path, files)
    found = _found(findings, "CF-IAM-009")
    assert bool(found) is fires
    if fires:
        (f,) = found
        assert f.question == "SEC 2"
        assert f.best_practices == ["SEC02-BP04"]
        assert f.severity == "Medium"
        assert "Identity Center" in f.recommendation
        assert not _answer(findings, ran, "SEC 2").met


@pytest.mark.parametrize(
    "files",
    [
        # Identity Center: a permission set and an assignment, no IAM users.
        {"t.json": _cfn({
            "ReadOnly": {"Type": "AWS::SSO::PermissionSet", "Properties": {
                "InstanceArn": "arn:aws:sso:::instance/ssoins-1", "Name": "ReadOnly",
                "ManagedPolicies": [POLICY_ARN]}},
            "Assign": {"Type": "AWS::SSO::Assignment", "Properties": {
                "InstanceArn": "arn:aws:sso:::instance/ssoins-1",
                "PermissionSetArn": {"Fn::GetAtt": ["ReadOnly", "PermissionSetArn"]},
                "PrincipalId": "g-1", "PrincipalType": "GROUP",
                "TargetId": "111122223333", "TargetType": "AWS_ACCOUNT"}},
        })},
        # A SAML provider and a role people federate into.
        {"main.tf": 'resource "aws_iam_saml_provider" "corp" {\n  name = "corp"\n'
                    '  saml_metadata_document = file("saml.xml")\n}\n'},
        # No people defined at all.
        {"main.tf": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n'},
    ],
    ids=["identity-center", "saml", "no-identities"],
)
def test_central_identity_or_no_users_passes_sec02_bp04(tmp_path: Path, files: dict) -> None:
    findings, ran = _scan(tmp_path, files)
    assert not _found(findings, "CF-IAM-009")
    sec2 = _answer(findings, ran, "SEC 2")
    assert "SEC02-BP04" not in sec2.not_checked
    assert not any("SEC02-BP04" in f.best_practices for f in sec2.findings)


# --- CF-IAM-010: an access key created in the template (SEC02-BP02) ---

@pytest.mark.parametrize(
    ("files", "fires"),
    [
        ({"t.json": _cfn({"Alice": USER, "Key": {"Type": "AWS::IAM::AccessKey",
                                                 "Properties": {"UserName": {"Ref": "Alice"}}}})},
         True),
        ({"t.json": _cfn({"Alice": USER, "Key": {"Type": "AWS::IAM::AccessKey", "Properties": {
            "UserName": {"Ref": "Alice"}, "Status": "Inactive"}}})}, False),
        ({"t.json": _cfn({"Role": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"}]}}}})}, False),
        ({"main.tf": 'resource "aws_iam_access_key" "ci" {\n  user = "ci"\n}\n'}, True),
        ({"main.tf": 'resource "aws_iam_access_key" "ci" {\n  user = "ci"\n'
                     '  status = "Inactive"\n}\n'}, False),
        ({"main.tf": 'variable "status" {}\nresource "aws_iam_access_key" "ci" {\n'
                     '  user = "ci"\n  status = var.status\n}\n'}, False),
    ],
    ids=["cfn-key", "cfn-inactive", "cfn-role", "tf-key", "tf-inactive", "tf-status-unknown"],
)
def test_access_key_in_the_template(tmp_path: Path, files: dict, fires: bool) -> None:
    findings, _ran = _scan(tmp_path, files)
    found = _found(findings, "CF-IAM-010")
    assert bool(found) is fires
    if fires:
        (f,) = found
        assert f.question == "SEC 2"
        assert f.best_practices == ["SEC02-BP02"]
        assert f.severity == "Medium"


# --- CF-IAM-011: policies attached to a user, not a group (SEC02-BP06) ---

_TF_USER = 'resource "aws_iam_user" "bob" {\n  name = "bob"\n}\n'


@pytest.mark.parametrize(
    ("files", "fires"),
    [
        ({"t.json": _cfn({"Bob": {"Type": "AWS::IAM::User", "Properties": {
            "ManagedPolicyArns": [POLICY_ARN]}}})}, True),
        ({"t.json": _cfn({"Bob": {"Type": "AWS::IAM::User", "Properties": {"Policies": [{
            "PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}]}}})}, True),
        ({"t.json": _cfn({"Bob": USER, "P": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "Users": [{"Ref": "Bob"}], "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}}})}, True),
        ({"t.json": _cfn({"Bob": USER, "P": {"Type": "AWS::IAM::UserPolicy", "Properties": {
            "UserName": {"Ref": "Bob"}, "PolicyName": "p", "PolicyDocument": {}}}})}, True),
        # Permissions through a group: Groups on the user, or UserToGroupAddition.
        ({"t.json": _cfn({
            "Readers": {"Type": "AWS::IAM::Group", "Properties": {"ManagedPolicyArns": [POLICY_ARN]}},
            "Bob": {"Type": "AWS::IAM::User", "Properties": {"Groups": [{"Ref": "Readers"}]}},
            "Carol": USER,
            "Add": {"Type": "AWS::IAM::UserToGroupAddition", "Properties": {
                "GroupName": {"Ref": "Readers"}, "Users": [{"Ref": "Carol"}]}},
        })}, False),
        ({"main.tf": _TF_USER + 'resource "aws_iam_user_policy_attachment" "bob" {\n'
                                '  user = aws_iam_user.bob.name\n'
                                f'  policy_arn = "{POLICY_ARN}"\n}}\n'}, True),
        ({"main.tf": _TF_USER + 'resource "aws_iam_user_policy" "bob" {\n'
                                '  user = aws_iam_user.bob.name\n  policy = "{}"\n}\n'}, True),
        ({"main.tf": _TF_USER + 'resource "aws_iam_policy_attachment" "read" {\n'
                                '  name = "read"\n  users = [aws_iam_user.bob.name]\n'
                                f'  policy_arn = "{POLICY_ARN}"\n}}\n'}, True),
        ({"main.tf": _TF_USER + 'resource "aws_iam_policy_attachment" "read" {\n'
                                '  name = "read"\n  groups = ["readers"]\n'
                                f'  policy_arn = "{POLICY_ARN}"\n}}\n'}, False),
        ({"main.tf": _TF_USER + 'resource "aws_iam_group" "readers" {\n  name = "readers"\n}\n'
                                'resource "aws_iam_group_policy_attachment" "readers" {\n'
                                '  group = aws_iam_group.readers.name\n'
                                f'  policy_arn = "{POLICY_ARN}"\n}}\n'
                                'resource "aws_iam_user_group_membership" "bob" {\n'
                                '  user = aws_iam_user.bob.name\n'
                                '  groups = [aws_iam_group.readers.name]\n}\n'}, False),
    ],
    ids=["cfn-managed", "cfn-inline", "cfn-policy-users", "cfn-user-policy", "cfn-groups",
         "tf-user-attachment", "tf-user-policy", "tf-policy-attachment-users",
         "tf-policy-attachment-groups", "tf-group-membership"],
)
def test_policies_attached_to_a_user(tmp_path: Path, files: dict, fires: bool) -> None:
    findings, _ran = _scan(tmp_path, files)
    found = _found(findings, "CF-IAM-011")
    assert bool(found) is fires
    for f in found:
        assert f.question == "SEC 2"
        assert f.best_practices == ["SEC02-BP06"]
        assert f.severity == "Low"


def test_clean_identity_template_meets_sec2_template_checks(tmp_path: Path) -> None:
    """Groups, a role and no console password or key: none of the three fire."""
    findings, _ran = _scan(tmp_path, {"t.json": _cfn({
        "Readers": {"Type": "AWS::IAM::Group", "Properties": {"ManagedPolicyArns": [POLICY_ARN]}},
        "Deploy": {"Type": "AWS::IAM::User", "Properties": {"Groups": [{"Ref": "Readers"}]}},
    })})
    assert not {"CF-IAM-009", "CF-IAM-010", "CF-IAM-011"} & {f.id for f in findings}


# --- CDK: SEC-069 to SEC-071 ---

@pytest.mark.parametrize(
    ("rule_id", "language", "code", "fires"),
    [
        ("SEC-069", "typescript",
         "const u = new iam.CfnUser(this, 'U', {\n  loginProfile: { password },\n});", True),
        ("SEC-069", "typescript",
         "new iam.User(this, 'U');\nnew rds.DatabaseInstance(this, 'Db', { password });", False),
        ("SEC-069", "python",
         "iam.CfnUser(self, 'U', login_profile=iam.CfnUser.LoginProfileProperty(password=p))",
         True),
        ("SEC-070", "python", "iam.CfnAccessKey(self, 'K', user_name='ci')", True),
        ("SEC-071", "typescript",
         "const bob = new iam.User(this, 'Bob');\nbob.addToPolicy(statement);", True),
        ("SEC-071", "typescript",
         "const bob = new iam.User(this, 'Bob');\nnew iam.Policy(this, 'P', {\n"
         "  users: [bob],\n  statements,\n});", True),
        ("SEC-071", "typescript",
         "const bob = new iam.User(this, 'Bob');\npolicy.attachToUser(bob);", True),
        ("SEC-071", "python",
         "iam.CfnUser(self, 'Bob', managed_policy_arns=[arn])", True),
        ("SEC-071", "typescript",
         "const bob = new iam.User(this, 'Bob');\nreaders.addUser(bob);\n"
         "role.addManagedPolicy(readOnly);", False),
    ],
    ids=["cfn-login-profile", "rds-password", "py-cfn-login-profile", "py-cfn-access-key",
         "add-to-policy", "policy-users", "attach-to-user", "py-cfn-managed", "group"],
)
def test_cdk_identity_rules(
    tmp_path: Path, rule_id: str, language: str, code: str, fires: bool
) -> None:
    name = "lib/stack.ts" if language == "typescript" else "app.py"
    _write(tmp_path / name, code + "\n")
    findings = RULE_BY_ID[rule_id].run(tmp_path, language)
    assert bool([f for f in findings if f.id == rule_id]) is fires
    for f in findings:
        assert f.line is not None and f.file


@pytest.mark.parametrize(
    ("rule_id", "best_practice"),
    [("SEC-069", "SEC02-BP04"), ("SEC-070", "SEC02-BP02"), ("SEC-071", "SEC02-BP06")],
)
def test_cdk_findings_answer_sec2(tmp_path: Path, rule_id: str, best_practice: str) -> None:
    code = {
        "SEC-069": "new iam.User(this, 'U', { password: SecretValue.unsafePlainText('x') });",
        "SEC-070": "new iam.AccessKey(this, 'K', { user });",
        "SEC-071": "new iam.User(this, 'U', { managedPolicies: [readOnly] });",
    }[rule_id]
    findings, _ran = _scan(tmp_path, {"package.json": "{}", "lib/stack.ts": code + "\n"})
    (f,) = _found(findings, rule_id)
    assert f.question == "SEC 2"
    assert f.best_practices == [best_practice]


# --- REPO-006: the root user of an account the repo defines (SEC01-BP02) ---

ACCOUNT = {
    "cdk": ("lib/accounts.ts",
            "new organizations.CfnAccount(this, 'Workload', { accountName: 'w', email });\n"),
    "cloudformation": ("accounts.template.json", _cfn({"Workload": {
        "Type": "AWS::Organizations::Account",
        "Properties": {"AccountName": "w", "Email": "w@example.com"}}})),
    "terraform": ("accounts.tf",
                  'resource "aws_organizations_account" "workload" {\n  name = "w"\n}\n'),
}
_ROOT_SCP = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Deny", "Action": "*", "Resource": "*",
    "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}}}]})
ROOT_CONTROLS: dict[str, dict[str, str]] = {
    "config_rules": {
        "cdk": "new config.ManagedRule(this, 'Mfa', "
               "{ identifier: config.ManagedRuleIdentifiers.ROOT_ACCOUNT_MFA_ENABLED });\n"
               "new config.ManagedRule(this, 'Key', "
               "{ identifier: config.ManagedRuleIdentifiers.IAM_ROOT_ACCESS_KEY_CHECK });\n",
        "cloudformation": _cfn({
            "Mfa": {"Type": "AWS::Config::ConfigRule", "Properties": {"Source": {
                "Owner": "AWS", "SourceIdentifier": "ROOT_ACCOUNT_MFA_ENABLED"}}},
            "Key": {"Type": "AWS::Config::ConfigRule", "Properties": {"Source": {
                "Owner": "AWS", "SourceIdentifier": "IAM_ROOT_ACCESS_KEY_CHECK"}}},
        }),
        "terraform": 'resource "aws_config_config_rule" "mfa" {\n  name = "root-mfa"\n'
                     '  source {\n    owner = "AWS"\n'
                     '    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"\n  }\n}\n'
                     'resource "aws_config_config_rule" "key" {\n  name = "root-key"\n'
                     '  source {\n    owner = "AWS"\n'
                     '    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"\n  }\n}\n',
    },
    "conformance_pack": {
        "cdk": "new config.CfnConformancePack(this, 'Pack', { conformancePackName: 'p' });\n",
        "cloudformation": _cfn({"Pack": {"Type": "AWS::Config::ConformancePack", "Properties": {
            "ConformancePackName": "p", "TemplateS3Uri": "s3://b/pack.yaml"}}}),
        "terraform": 'resource "aws_config_conformance_pack" "p" {\n  name = "p"\n}\n',
    },
    "security_hub_standard": {
        "cdk": "new securityhub.CfnHub(this, 'Hub', { enableDefaultStandards: false });\n"
               "new securityhub.CfnStandard(this, 'Cis', { standardsArn: "
               "'arn:aws:securityhub:eu-west-1::standards/cis-aws-foundations-benchmark/v/3.0.0' });\n",
        "cloudformation": _cfn({
            "Hub": {"Type": "AWS::SecurityHub::Hub", "Properties": {"EnableDefaultStandards": False}},
            "Fsbp": {"Type": "AWS::SecurityHub::Standard", "Properties": {"StandardsArn":
                "arn:aws:securityhub:eu-west-1::standards/"
                "aws-foundational-security-best-practices/v/1.0.0"}},
        }),
        # Default standards (FSBP and CIS) are on unless turned off.
        "terraform": 'resource "aws_securityhub_account" "h" {\n}\n',
    },
    "scp": {
        "cdk": "new organizations.CfnPolicy(this, 'DenyRoot', { name: 'deny-root', "
               f"type: 'SERVICE_CONTROL_POLICY', content: {_ROOT_SCP} }});\n",
        "cloudformation": _cfn({"DenyRoot": {"Type": "AWS::Organizations::Policy", "Properties": {
            "Name": "deny-root", "Type": "SERVICE_CONTROL_POLICY",
            "Content": json.loads(_ROOT_SCP)}}}),
        "terraform": 'resource "aws_organizations_policy" "deny_root" {\n  name = "deny-root"\n'
                     f"  content = <<EOT\n{_ROOT_SCP}\nEOT\n}}\n",
    },
}
_CONTROL_FILE = {"cdk": "lib/baseline.ts", "cloudformation": "baseline.template.json",
                 "terraform": "baseline.tf"}


def _account_repo(root: Path, source: str) -> dict[str, str]:
    files = {ACCOUNT[source][0]: ACCOUNT[source][1]}
    if source == "cdk":
        files["package.json"] = "{}"
    return files


@pytest.mark.parametrize("source", SOURCES)
def test_account_without_root_controls_fails_repo_006(tmp_path: Path, source: str) -> None:
    findings, ran = _scan(tmp_path, _account_repo(tmp_path, source))
    (f,) = _found(findings, "REPO-006")
    assert f.question == "SEC 1"
    assert f.best_practices == ["SEC01-BP02"]
    assert f.severity == "Medium"
    assert f.file == ACCOUNT[source][0]
    assert "ROOT_ACCOUNT_MFA_ENABLED or IAM_ROOT_ACCESS_KEY_CHECK" in f.evidence
    sec1 = _answer(findings, ran, "SEC 1")
    assert "SEC01-BP02" not in sec1.not_checked
    assert not sec1.met


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("kind", sorted(ROOT_CONTROLS))
def test_any_root_control_passes_repo_006(tmp_path: Path, source: str, kind: str) -> None:
    files = _account_repo(tmp_path, source)
    files[_CONTROL_FILE[source]] = ROOT_CONTROLS[kind][source]
    findings, _ran = _scan(tmp_path, files)
    assert not _found(findings, "REPO-006")


def test_one_config_rule_is_not_enough(tmp_path: Path) -> None:
    files = _account_repo(tmp_path, "cloudformation")
    files["rules.template.json"] = _cfn({"Mfa": {"Type": "AWS::Config::ConfigRule", "Properties": {
        "Source": {"Owner": "AWS", "SourceIdentifier": "ROOT_ACCOUNT_MFA_ENABLED"}}}})
    findings, _ran = _scan(tmp_path, files)
    (f,) = _found(findings, "REPO-006")
    assert "no Config rule IAM_ROOT_ACCESS_KEY_CHECK," in f.evidence


def test_hub_without_default_standards_is_not_enough(tmp_path: Path) -> None:
    files = _account_repo(tmp_path, "terraform")
    files["hub.tf"] = 'resource "aws_securityhub_account" "h" {\n  enable_default_standards = false\n}\n'
    findings, _ran = _scan(tmp_path, files)
    assert _found(findings, "REPO-006")


def test_scp_without_a_root_condition_is_not_enough(tmp_path: Path) -> None:
    files = _account_repo(tmp_path, "terraform")
    files["scp.tf"] = 'resource "aws_organizations_policy" "deny_leave" {\n  name = "deny"\n}\n'
    findings, _ran = _scan(tmp_path, files)
    assert _found(findings, "REPO-006")


@pytest.mark.parametrize("source", SOURCES)
def test_workload_repo_gets_no_repo_006(tmp_path: Path, source: str) -> None:
    files = {
        "cdk": {"package.json": "{}", "lib/stack.ts": "new s3.Bucket(this, 'Data');\n"},
        "cloudformation": {"stack.template.json": _cfn({"Data": {
            "Type": "AWS::S3::Bucket", "Properties": {}}})},
        "terraform": {"main.tf": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n'},
    }[source]
    findings, ran = _scan(tmp_path, files)
    assert not _found(findings, "REPO-006")
    assert "REPO-006" in ran
