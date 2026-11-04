"""CF-IAM-004..007: IAM role trust policies that are open to too many callers."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes, strip_cdk_hint
from aws_arch_agent.rules.terraform_model import resources_from_terraform

TRUST_IDS = {"CF-IAM-004", "CF-IAM-005", "CF-IAM-006", "CF-IAM-007"}
GITHUB = {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:oidc-provider/token.actions.githubusercontent.com"}


def _role(principal, action="sts:AssumeRole", condition=None) -> dict:
    statement = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition is not None:
        statement["Condition"] = condition
    return {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [statement]},
    }}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in TRUST_IDS]


def _found(findings: list[Finding]) -> dict[str, tuple[str, str]]:
    return {f.evidence.split(" ")[0]: (f.id, f.severity) for f in findings}


def test_cloudformation_trust_policies(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Anyone": _role("*"),
        "AnyoneAws": _role({"AWS": "*"}, action=["sts:AssumeRole", "sts:TagSession"]),
        "AnyoneInOrg": _role({"AWS": "*"}, condition={"StringEquals": {"aws:PrincipalOrgID": "o-123"}}),
        "CrossAccount": _role({"AWS": "arn:aws:iam::111122223333:root"}),
        "CrossAccountBareId": _role({"AWS": ["111122223333"]}),
        "CrossAccountExternalId": _role({"AWS": "arn:aws:iam::111122223333:role/x"},
                                        condition={"StringEquals": {"sts:ExternalId": "abc"}}),
        "SameAccountCdk": _role({"AWS": {"Fn::Join": ["", ["arn:", {"Ref": "AWS::Partition"}, ":iam::",
                                                            {"Ref": "AWS::AccountId"}, ":root"]]}}),
        "LambdaRole": _role({"Service": "lambda.amazonaws.com"}),
        "ConfigRole": _role({"Service": ["config.amazonaws.com", "ec2.amazonaws.com"]}),
        "ConfigRoleScoped": _role({"Service": "config.amazonaws.com"},
                                  condition={"StringEquals": {"AWS:SourceAccount": "111122223333"}}),
        "GitHubOpen": _role({"Federated": GITHUB}, action="sts:AssumeRoleWithWebIdentity",
                            condition={"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}),
        "GitHubScoped": _role({"Federated": GITHUB}, action="sts:AssumeRoleWithWebIdentity", condition={
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:org/repo:*"},
        }),
        "OtherAction": _role("*", action="s3:GetObject"),
        "ConditionFromIf": _role("*", condition={"Fn::If": ["Prod", {}, {}]}),
        "Deny": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}]}}},
        "TrustFromParam": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"Ref": "P"}}},
    })
    assert _found(findings) == {
        "Anyone": ("CF-IAM-004", "High"),
        "AnyoneAws": ("CF-IAM-004", "High"),
        "CrossAccount": ("CF-IAM-005", "Medium"),
        "CrossAccountBareId": ("CF-IAM-005", "Medium"),
        "ConfigRole": ("CF-IAM-006", "Low"),
        "GitHubOpen": ("CF-IAM-007", "High"),
    }
    by_name = {f.evidence.split(" ")[0]: f for f in findings}
    assert "Trusted: 111122223333." in by_name["CrossAccount"].recommendation
    assert "Trusted: config.amazonaws.com." in by_name["ConfigRole"].recommendation


def test_review_cases(tmp_path: Path) -> None:
    oidc_aud = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
    findings = _cf(tmp_path, {
        # Conditions that do not limit the caller leave "*" open.
        "AnyoneOverTls": _role("*", condition={"Bool": {"aws:SecureTransport": "true"}}),
        "AnyoneFromIp": _role({"AWS": "*"}, condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),
        "AnyoneByArn": _role("*", condition={"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/ci"}}),
        # CDK AccountPrincipal and a regional service principal.
        "CdkAccountPrincipal": _role({"AWS": {"Fn::Join": ["", ["arn:", {"Ref": "AWS::Partition"},
                                                                 ":iam::111122223333:root"]]}}),
        "RegionalLogs": _role({"Service": "logs.eu-north-1.amazonaws.com"}),
        # GitHub: a provider Ref is known by its condition keys; a wildcard sub is open.
        "GitHubRefNoSub": _role({"Federated": {"Ref": "GitHubProvider"}},
                                action="sts:AssumeRoleWithWebIdentity", condition=oidc_aud),
        "GitHubAnyRepo": _role({"Federated": GITHUB}, action="sts:AssumeRoleWithWebIdentity",
                               condition={"StringLike": {"token.actions.githubusercontent.com:sub": "repo:*"}}),
        "GitHubSubFromParam": _role({"Federated": GITHUB}, action="sts:AssumeRoleWithWebIdentity",
                                    condition={"StringLike": {"token.actions.githubusercontent.com:sub":
                                                              {"Ref": "Sub"}}}),
        "OtherOidcRef": _role({"Federated": {"Ref": "Provider"}}, action="sts:AssumeRoleWithWebIdentity"),
    })
    assert _found(findings) == {
        "AnyoneOverTls": ("CF-IAM-004", "High"),
        "AnyoneFromIp": ("CF-IAM-004", "High"),
        "CdkAccountPrincipal": ("CF-IAM-005", "Medium"),
        "RegionalLogs": ("CF-IAM-006", "Low"),
        "GitHubRefNoSub": ("CF-IAM-007", "High"),
        "GitHubAnyRepo": ("CF-IAM-007", "High"),
    }


def test_one_role_can_have_several_kinds(tmp_path: Path) -> None:
    role = {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "sts:AssumeRole"},
    ]}}}
    assert sorted(f.id for f in _cf(tmp_path, {"R": role})) == ["CF-IAM-004", "CF-IAM-005"]


TF = """\
resource "aws_iam_role" "anyone" {
  name = "anyone"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "sts:AssumeRole" }]
  })
}

data "aws_iam_policy_document" "config" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "config"
  assume_role_policy = data.aws_iam_policy_document.config.json
}

data "aws_iam_policy_document" "partner" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["abc"]
    }
  }
}

resource "aws_iam_role" "partner" {
  name               = "partner"
  assume_role_policy = data.aws_iam_policy_document.partner.json
}

data "aws_iam_policy_document" "github" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"]
    }
  }
}

resource "aws_iam_role" "github" {
  name               = "github"
  assume_role_policy = data.aws_iam_policy_document.github.json
}

data "aws_iam_policy_document" "star_type" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "star_type" {
  name               = "star_type"
  assume_role_policy = data.aws_iam_policy_document.star_type.json
}

resource "aws_iam_role" "from_var" {
  name               = "from_var"
  assume_role_policy = var.trust
}

resource "aws_iam_role" "heredoc_with_var" {
  name               = "heredoc_with_var"
  assume_role_policy = <<EOF
{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Sid": "${var.sid}"}]}
EOF
}

resource "aws_iam_role" "var_principal" {
  name = "var_principal"
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = { AWS = var.caller }, Action = "sts:AssumeRole" }]
  })
}
"""


def _tf(tmp_path: Path) -> list[Finding]:
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    return [f for f in run_resource_checks(resources, tmp_path / "main.tf") if f.id in TRUST_IDS]


def test_terraform_trust_policies(tmp_path: Path) -> None:
    assert _found(_tf(tmp_path)) == {
        "aws_iam_role.anyone": ("CF-IAM-004", "High"),
        "aws_iam_role.config": ("CF-IAM-006", "Low"),
        "aws_iam_role.github": ("CF-IAM-007", "High"),
        "aws_iam_role.star_type": ("CF-IAM-004", "High"),
    }


def test_fixes_in_both_languages(tmp_path: Path) -> None:
    tf = {f.id: f for f in attach_fixes(_tf(tmp_path), "terraform")}
    assert 'assume_role_policy = data.aws_iam_policy_document.github_trust.json' in tf["CF-IAM-007"].suggested_code
    assert '"token.actions.githubusercontent.com:sub"' in tf["CF-IAM-007"].suggested_code
    cf = attach_fixes(_cf(tmp_path, {
        "A": _role("*"),
        "B": _role({"AWS": "arn:aws:iam::111122223333:root"}),
        "C": _role({"Service": "sns.amazonaws.com"}),
        "D": _role({"Federated": GITHUB}, action="sts:AssumeRoleWithWebIdentity"),
    }), "cloudformation")
    assert {f.id for f in cf if f.suggested_code} == TRUST_IDS
    by_id = {f.id: f.suggested_code for f in cf}
    assert "sts:ExternalId" in by_id["CF-IAM-005"]
    assert "${AWS::AccountId}" in by_id["CF-IAM-007"]
    assert all("In CDK" not in f.recommendation for f in cf)


def test_cdk_hints_are_stripped_for_raw_templates(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "A": _role("*"),
        "B": _role({"AWS": "arn:aws:iam::111122223333:root"}),
        "C": _role({"Service": "sns.amazonaws.com"}),
        "D": _role({"Federated": GITHUB}, action="sts:AssumeRoleWithWebIdentity"),
    })
    assert {f.id for f in findings} == TRUST_IDS
    for finding in findings:
        stripped = strip_cdk_hint(finding.recommendation)
        assert "In CDK" not in stripped and stripped.endswith(".")
