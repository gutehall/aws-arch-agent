"""CF-RP-001 (resource policies open to any principal) and CF-KMS-001 (key policies)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import iam_policy
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = {"CF-RP-001", "CF-KMS-001"}


def _doc(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _open(action="sqs:SendMessage", principal="*", condition=None) -> dict:
    stmt = {"Effect": "Allow", "Principal": principal, "Action": action, "Resource": "*"}
    if condition is not None:
        stmt["Condition"] = condition
    return stmt


SOURCE_ARN = {"ArnEquals": {"aws:SourceArn": "arn:aws:events:eu-north-1:111122223333:rule/r"}}


# --- policy analysis --------------------------------------------------------------


@pytest.mark.parametrize(
    ("doc", "actions"),
    [
        (_doc(_open()), ["sqs:SendMessage"]),
        (_doc(_open(principal={"AWS": "*"})), ["sqs:SendMessage"]),
        (_doc(_open(principal={"AWS": ["*"]})), ["sqs:SendMessage"]),
        (_doc(_open(principal={"*": ["*"]})), ["sqs:SendMessage"]),  # aws_iam_policy_document
        (_doc(_open(action={"Ref": "A"})), []),  # open, actions unknown
        (_doc(_open(condition=SOURCE_ARN)), None),
        (_doc(_open(condition={"StringEquals": {"aws:SourceAccount": "111122223333"}})), None),
        (_doc(_open(condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc"}})), None),
        (_doc(_open(condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}})), None),
        (_doc(_open(condition={"StringEquals": {"AWS:SOURCEARN": "x"}})), None),  # keys ignore case
        # aws:SecureTransport and aws:SourceIp do not limit who the caller is.
        (_doc(_open(condition={"Bool": {"aws:SecureTransport": "true"}})), ["sqs:SendMessage"]),
        (_doc(_open(condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})), ["sqs:SendMessage"]),
        (_doc(_open(condition={"Fn::If": ["C", {}, {}]})), None),  # unknown condition
        # Negated, IfExists, Null and "*" conditions leave the statement open.
        (_doc(_open(condition={"StringNotEquals": {"aws:SourceAccount": "1"}})), ["sqs:SendMessage"]),
        (_doc(_open(condition={"ArnNotLike": {"aws:SourceArn": "arn:x"}})), ["sqs:SendMessage"]),
        (_doc(_open(condition={"ArnEqualsIfExists": {"aws:SourceArn": "arn:x"}})), ["sqs:SendMessage"]),
        (_doc(_open(condition={"Null": {"aws:SourceArn": "false"}})), ["sqs:SendMessage"]),
        (_doc(_open(condition={"StringLike": {"aws:SourceArn": "*"}})), ["sqs:SendMessage"]),
        (_doc(_open(condition={"ForAnyValue:StringEquals": {"aws:PrincipalOrgID": ["o-1"]}})), None),
        (_doc(_open(principal={"AWS": "arn:aws:iam::111122223333:root"})), None),
        (_doc(_open(principal={"Service": "events.amazonaws.com"})), None),
        (_doc(_open(principal={"Ref": "P"})), None),
        (_doc({"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}), None),
        (_doc({"Effect": "Allow", "NotPrincipal": {"AWS": "x"}, "Action": "s3:*"}), None),
    ],
)
def test_public_actions(doc: dict, actions: list[str] | None) -> None:
    assert iam_policy.public_actions(doc) == actions


# --- CloudFormation -----------------------------------------------------------------


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _found(findings: list[Finding]) -> dict[str, str]:
    return {f.evidence.split(" ")[0]: f.id for f in findings}


def _policy(rtype: str, doc: dict) -> dict:
    return {"Type": rtype, "Properties": {"PolicyDocument": doc}}


def test_cloudformation_resource_policies(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Queue": _policy("AWS::SQS::QueuePolicy", _doc(_open())),
        "QueueOk": _policy("AWS::SQS::QueuePolicy", _doc(_open(condition=SOURCE_ARN))),
        "Topic": _policy("AWS::SNS::TopicPolicy", _doc(_open("sns:Publish", {"AWS": "*"}))),
        "TopicOk": _policy("AWS::SNS::TopicPolicy", _doc(_open(
            "sns:Publish", condition={"StringEquals": {"aws:SourceAccount": "111122223333"}}))),
        "Bucket": {"Type": "AWS::S3::BucketPolicy", "Properties": {
            "Bucket": {"Ref": "B"}, "PolicyDocument": _doc(_open("s3:GetObject"))}},
        "BucketOk": {"Type": "AWS::S3::BucketPolicy", "Properties": {
            "Bucket": {"Ref": "B"}, "PolicyDocument": _doc(_open(
                "s3:GetObject", condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}}))}},
        "Repo": {"Type": "AWS::ECR::Repository", "Properties": {
            "RepositoryPolicyText": _doc(_open("ecr:BatchGetImage"))}},
        "RepoText": {"Type": "AWS::ECR::Repository", "Properties": {  # JSON text is read too
            "RepositoryPolicyText": json.dumps(_doc(_open("ecr:*")))}},
        "RepoOk": {"Type": "AWS::ECR::Repository", "Properties": {
            "RepositoryPolicyText": _doc(_open("ecr:BatchGetImage", condition={
                "StringEquals": {"aws:PrincipalOrgID": "o-abc"}}))}},
        "RepoNone": {"Type": "AWS::ECR::Repository", "Properties": {}},
        "Unknown": _policy("AWS::SQS::QueuePolicy", {"Fn::If": ["C", {}, {}]}),
    })
    assert _found(findings) == {
        "Queue": "CF-RP-001",
        "Topic": "CF-RP-001",
        "Bucket": "CF-RP-001",
        "Repo": "CF-RP-001",
        "RepoText": "CF-RP-001",
    }
    assert {f.severity for f in findings} == {"High"}
    queue = next(f for f in findings if f.evidence.startswith("Queue"))
    assert queue.recommendation.startswith("Allowed to anyone: sqs:SendMessage.")


def test_cloudformation_lambda_permissions(tmp_path: Path) -> None:
    def perm(**props) -> dict:
        return {"Type": "AWS::Lambda::Permission", "Properties": {
            "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "Fn"}, **props}}

    findings = _cf(tmp_path, {
        "Open": perm(Principal="*"),
        "Arn": perm(Principal="*", SourceArn={"Fn::GetAtt": ["Api", "Arn"]}),
        "Account": perm(Principal="*", SourceAccount="111122223333"),
        "Org": perm(Principal="*", PrincipalOrgID="o-abc"),
        "Service": perm(Principal="s3.amazonaws.com"),
        "UrlNone": perm(Principal="*", Action="lambda:InvokeFunctionUrl", FunctionUrlAuthType="NONE"),
        "UrlIam": perm(Principal="*", Action="lambda:InvokeFunctionUrl", FunctionUrlAuthType="AWS_IAM"),
        "Ref": perm(Principal={"Ref": "P"}),
    })
    assert _found(findings) == {"Open": "CF-RP-001", "UrlNone": "CF-RP-001"}


def test_kms_root_key_policy_is_not_flagged(tmp_path: Path) -> None:
    """The standard key policy has Resource "*" but a named principal (CDK default)."""
    root = {"Effect": "Allow", "Action": "kms:*", "Resource": "*", "Principal": {"AWS": {
        "Fn::Join": ["", ["arn:", {"Ref": "AWS::Partition"}, ":iam::", {"Ref": "AWS::AccountId"}, ":root"]],
    }}}
    via_service = _open("kms:Decrypt", condition={"StringEquals": {
        "kms:CallerAccount": "111122223333", "kms:ViaService": "s3.eu-north-1.amazonaws.com"}})
    findings = _cf(tmp_path, {
        "Root": {"Type": "AWS::KMS::Key", "Properties": {"KeyPolicy": _doc(root)}},
        "ViaService": {"Type": "AWS::KMS::Key", "Properties": {"KeyPolicy": _doc(root, via_service)}},
        "Open": {"Type": "AWS::KMS::Key", "Properties": {"KeyPolicy": _doc(root, _open("kms:Decrypt"))}},
    })
    assert _found(findings) == {"Open": "CF-KMS-001"}


def test_cloudformation_fixes_match_the_resource(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Queue": _policy("AWS::SQS::QueuePolicy", _doc(_open())),
        "Repo": {"Type": "AWS::ECR::Repository", "Properties": {
            "RepositoryPolicyText": _doc(_open("ecr:BatchGetImage"))}},
        "Open": {"Type": "AWS::Lambda::Permission", "Properties": {"Principal": "*"}},
    })
    attach_fixes(findings, "cloudformation")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert "Type: AWS::SQS::QueuePolicy" in code["Queue"] and "aws:SourceArn" in code["Queue"]
    assert "RepositoryPolicyText:" in code["Repo"]
    assert "SourceArn:" in code["Open"]


def test_snippets_fit_each_policy_type(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Topic": _policy("AWS::SNS::TopicPolicy", _doc(_open("sns:Publish"))),
        "Bucket": {"Type": "AWS::S3::BucketPolicy", "Properties": {
            "Bucket": {"Ref": "B"}, "PolicyDocument": _doc(_open("s3:GetObject"))}},
    })
    attach_fixes(findings, "cloudformation")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert "sns:Publish" in code["Topic"] and "sqs:" not in code["Topic"]
    assert '!Sub "${MyBucket.Arn}/*"' in code["Bucket"]


# --- Terraform ------------------------------------------------------------------

POLICIES_TF = """\
data "aws_iam_policy_document" "public" {
  statement {
    actions   = ["sns:Publish"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "limited" {
  statement {
    actions   = ["sns:Publish"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["111122223333"]
    }
  }
}

resource "aws_sqs_queue_policy" "open" {
  queue_url = aws_sqs_queue.q.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "sqs:SendMessage", Resource = aws_sqs_queue.q.arn }]
  })
}

resource "aws_sqs_queue_policy" "limited" {
  queue_url = aws_sqs_queue.q.id
  policy = jsonencode({
    Statement = [{
      Effect = "Allow", Principal = { AWS = "*" }, Action = "sqs:SendMessage", Resource = aws_sqs_queue.q.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.t.arn } }
    }]
  })
}

resource "aws_sns_topic_policy" "open" {
  arn    = aws_sns_topic.t.arn
  policy = data.aws_iam_policy_document.public.json
}

resource "aws_sns_topic_policy" "limited" {
  arn    = aws_sns_topic.t.arn
  policy = data.aws_iam_policy_document.limited.json
}

resource "aws_s3_bucket" "b" {}

resource "aws_s3_bucket_policy" "open" {
  bucket = aws_s3_bucket.b.id
  policy = <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
EOF
}

resource "aws_ecr_repository_policy" "open" {
  repository = "app"
  policy     = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "ecr:BatchGetImage" }] })
}

resource "aws_ecr_repository_policy" "from_var" {
  repository = "app"
  policy     = var.policy
}

resource "aws_lambda_permission" "open" {
  action        = "lambda:InvokeFunction"
  function_name = "fn"
  principal     = "*"
}

resource "aws_lambda_permission" "limited" {
  action        = "lambda:InvokeFunction"
  function_name = "fn"
  principal     = "*"
  source_arn    = aws_api_gateway_rest_api.api.execution_arn
}

resource "aws_lambda_permission" "from_var" {
  action        = "lambda:InvokeFunction"
  function_name = "fn"
  principal     = "*"
  source_arn    = var.source_arn
}

resource "aws_kms_key" "root" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow", Action = "kms:*", Resource = "*"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })
}

resource "aws_kms_key" "open" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "kms:Decrypt", Resource = var.arn }]
  })
}
"""


def _tf(module: Path) -> list[Finding]:
    resources = resources_from_terraform(module)
    return [f for f in run_resource_checks(resources, module / "main.tf") if f.id in IDS]


def test_terraform_resource_policies(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(POLICIES_TF, encoding="utf-8")
    assert _found(_tf(tmp_path)) == {
        "aws_sqs_queue_policy.open": "CF-RP-001",
        "aws_sns_topic_policy.open": "CF-RP-001",
        "aws_s3_bucket_policy.open": "CF-RP-001",
        "aws_ecr_repository_policy.open": "CF-RP-001",
        "aws_lambda_permission.open": "CF-RP-001",
        "aws_kms_key.open": "CF-KMS-001",
    }


def test_terraform_fixes_match_the_resource(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(POLICIES_TF, encoding="utf-8")
    findings = attach_fixes(_tf(tmp_path), "terraform")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert 'resource "aws_sqs_queue_policy" "open"' in code["aws_sqs_queue_policy.open"]
    assert "data.aws_iam_policy_document.open.json" in code["aws_sqs_queue_policy.open"]
    assert "source_arn" in code["aws_lambda_permission.open"]
    assert all("In CDK" not in f.recommendation for f in findings)
