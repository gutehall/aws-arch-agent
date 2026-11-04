"""CF-S3-005: S3 buckets with no bucket policy that denies requests without TLS."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import _tls_enforced, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes, strip_cdk_hint
from aws_arch_agent.rules.terraform_model import load_plan_values, resources_from_terraform

# What CDK synthesizes for `enforceSSL: true`.
CDK_TLS_STATEMENT = {
    "Action": "s3:*",
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    "Effect": "Deny",
    "Principal": {"AWS": "*"},
    "Resource": [
        {"Fn::GetAtt": ["Bucket", "Arn"]},
        {"Fn::Join": ["", [{"Fn::GetAtt": ["Bucket", "Arn"]}, "/*"]]},
    ],
}
READ_STATEMENT = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "s3:GetObject",
                  "Resource": "*"}


def _bucket(**props) -> dict:
    return {"Type": "AWS::S3::Bucket", "Properties": props}


def _policy(bucket, *statements) -> dict:
    return {"Type": "AWS::S3::BucketPolicy", "Properties": {
        "Bucket": bucket, "PolicyDocument": {"Version": "2012-10-17", "Statement": list(statements)},
    }}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == "CF-S3-005"]


def _names(findings: list[Finding]) -> set[str]:
    return {f.evidence.split(" ")[0] for f in findings}


def test_cloudformation_buckets(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "NoPolicy": _bucket(),
        "CdkEnforceSsl": _bucket(),
        "CdkEnforceSslPolicy": _policy({"Ref": "CdkEnforceSsl"}, CDK_TLS_STATEMENT),
        "ReadOnly": _bucket(),
        "ReadOnlyPolicy": _policy({"Ref": "ReadOnly"}, READ_STATEMENT),
        "ByName": _bucket(BucketName="by-name"),
        "ByNamePolicy": _policy("by-name", READ_STATEMENT, {**CDK_TLS_STATEMENT, "Principal": "*",
                                                            "Condition": {"Bool": {"aws:SecureTransport": False}}}),
        "OnlyGetObject": _bucket(),
        "OnlyGetObjectPolicy": _policy({"Ref": "OnlyGetObject"}, {**CDK_TLS_STATEMENT, "Action": "s3:GetObject"}),
        "OneAccount": _bucket(),
        "OneAccountPolicy": _policy({"Ref": "OneAccount"},
                                    {**CDK_TLS_STATEMENT, "Principal": {"AWS": "arn:aws:iam::1:root"}}),
        "ConditionalStatement": _bucket(),
        "ConditionalStatementPolicy": _policy({"Ref": "ConditionalStatement"},
                                              {"Fn::If": ["Prod", CDK_TLS_STATEMENT, {"Ref": "AWS::NoValue"}]}),
        "OtherBucketPolicy": _policy("bucket-in-another-stack", READ_STATEMENT),
    })
    assert _names(findings) == {"NoPolicy", "ReadOnly", "OnlyGetObject", "OneAccount"}
    assert {f.severity for f in findings} == {"Medium"}
    assert all("in this template" in f.recommendation for f in findings)


def test_malformed_or_incomplete_policies_are_unknown(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Data": _bucket(),
        "Broken": {"Type": "AWS::S3::BucketPolicy", "Properties": ["not", "an", "object"]},
    }) == []
    assert _cf(tmp_path, {
        "Data": _bucket(),
        "NoDocument": {"Type": "AWS::S3::BucketPolicy", "Properties": {"Bucket": {"Ref": "Data"}}},
    }) == []


def test_policy_on_an_unknown_bucket_could_be_any_bucket(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Data": _bucket(),
        "Imported": _policy({"Fn::ImportValue": "BucketName"}, CDK_TLS_STATEMENT),
    })
    assert findings == []


def test_tls_enforced_shapes() -> None:
    assert _tls_enforced(None) is False
    assert _tls_enforced({"Statement": CDK_TLS_STATEMENT}) is True
    assert _tls_enforced(json.dumps({"Statement": [READ_STATEMENT]})) is False
    assert _tls_enforced("not json") is None
    assert _tls_enforced({"Fn::If": ["C", {}, {}]}) is None
    assert _tls_enforced({"Statement": {"Ref": "S"}}) is None
    tls = {**CDK_TLS_STATEMENT, "Action": ["s3:GetObject", "*"],
           "Condition": {"Bool": {"AWS:SecureTransport": ["false"]}}}
    assert _tls_enforced({"Statement": [tls]}) is True


TF = """\
resource "aws_s3_bucket" "none" {
  bucket = "none"
}

resource "aws_s3_bucket" "jsonencoded" {
  bucket = "jsonencoded"
}

resource "aws_s3_bucket_policy" "jsonencoded" {
  bucket = aws_s3_bucket.jsonencoded.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.jsonencoded.arn, "${aws_s3_bucket.jsonencoded.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket" "read_only" {
  bucket = "read-only"
}

resource "aws_s3_bucket_policy" "read_only" {
  bucket = aws_s3_bucket.read_only.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "*" }]
  })
}

resource "aws_s3_bucket" "heredoc" {
  bucket = "heredoc"
}

resource "aws_s3_bucket_policy" "heredoc" {
  bucket = "heredoc"
  policy = <<EOF
{"Statement": [{"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "s3:*", "Resource": "*",
  "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
EOF
}

resource "aws_s3_bucket" "heredoc_read_only" {
  bucket = "heredoc-read-only"
}

resource "aws_s3_bucket_policy" "heredoc_read_only" {
  bucket = aws_s3_bucket.heredoc_read_only.id
  policy = <<-EOF
    {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}
    EOF
}

resource "aws_s3_bucket" "allows_tls_only" {
  bucket = "allows-tls-only"
}

resource "aws_s3_bucket_policy" "allows_tls_only" {
  bucket = aws_s3_bucket.allows_tls_only.id
  policy = jsonencode({
    Statement = [
      { Effect = "Deny", Principal = "*", Action = "s3:DeleteBucket", Resource = "*" },
      { Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "*",
        Condition = { Bool = { "aws:SecureTransport" = "true" } } },
    ]
  })
}

resource "aws_s3_bucket" "lowercase_key" {
  bucket = "lowercase-key"
}

resource "aws_s3_bucket_policy" "lowercase_key" {
  bucket = aws_s3_bucket.lowercase_key.id
  policy = jsonencode({
    Statement = [{ Effect = "Deny", Principal = "*", Action = "s3:*", Resource = "*",
                   Condition = { Bool = { "aws:securetransport" = false } } }]
  })
}

resource "aws_s3_bucket" "merged_with_data" {
  bucket = "merged-with-data"
}

resource "aws_s3_bucket_policy" "merged_with_data" {
  bucket = aws_s3_bucket.merged_with_data.id
  policy = jsonencode(merge(jsondecode(data.aws_iam_policy_document.base.json), { Version = "2012-10-17" }))
}

resource "aws_s3_bucket" "from_data" {
  bucket = "from-data"
}

resource "aws_s3_bucket_policy" "from_data" {
  bucket = aws_s3_bucket.from_data.id
  policy = data.aws_iam_policy_document.from_data.json
}

resource "aws_s3_bucket" "from_var" {
  bucket = "from-var"
}

resource "aws_s3_bucket_policy" "from_var" {
  bucket = aws_s3_bucket.from_var.id
  policy = var.policy
}
"""


def _tf(tmp_path: Path, text: str = TF, plan: dict | None = None) -> list[Finding]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    plan_values = None
    if plan is not None:
        (tmp_path / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        plan_values = load_plan_values(tmp_path / "plan.json")
    resources = resources_from_terraform(tmp_path, plan_values=plan_values)
    return [f for f in run_resource_checks(resources, tmp_path / "main.tf") if f.id == "CF-S3-005"]


def test_terraform_buckets(tmp_path: Path) -> None:
    assert _names(_tf(tmp_path)) == {
        "aws_s3_bucket.none", "aws_s3_bucket.read_only",
        "aws_s3_bucket.heredoc_read_only", "aws_s3_bucket.allows_tls_only",
    }


def test_terraform_policy_on_a_bucket_outside_the_module(tmp_path: Path) -> None:
    text = TF + """
resource "aws_s3_bucket_policy" "elsewhere" {
  bucket = "a-bucket-in-another-module"
  policy = "{}"
}
"""
    # It may be the policy of "none". read_only has its own, and a bucket has only one.
    assert _names(_tf(tmp_path, text)) == {
        "aws_s3_bucket.read_only", "aws_s3_bucket.heredoc_read_only", "aws_s3_bucket.allows_tls_only",
    }


DATA_DOCS = """\
data "aws_iam_policy_document" "tls_only" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

data "aws_iam_policy_document" "read_only" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "var_effect" {
  statement {
    effect    = var.effect
    actions   = ["s3:*"]
    resources = ["*"]
  }
}

resource "aws_s3_bucket" "doc_tls" {
  bucket = "doc-tls"
}

resource "aws_s3_bucket_policy" "doc_tls" {
  bucket = aws_s3_bucket.doc_tls.id
  policy = data.aws_iam_policy_document.tls_only.json
}

resource "aws_s3_bucket" "doc_read" {
  bucket = "doc-read"
}

resource "aws_s3_bucket_policy" "doc_read" {
  bucket = aws_s3_bucket.doc_read.id
  policy = data.aws_iam_policy_document.read_only.json
}

resource "aws_s3_bucket" "doc_var" {
  bucket = "doc-var"
}

resource "aws_s3_bucket_policy" "doc_var" {
  bucket = aws_s3_bucket.doc_var.id
  policy = data.aws_iam_policy_document.var_effect.json
}
"""


def test_terraform_reads_policy_document_data_sources(tmp_path: Path) -> None:
    assert _names(_tf(tmp_path, DATA_DOCS)) == {"aws_s3_bucket.doc_read"}


def test_terraform_jsonencode_with_a_var_is_unknown(tmp_path: Path) -> None:
    text = """\
resource "aws_s3_bucket" "b" {
  bucket = "b"
}

resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({
    Statement = [{ Effect = var.effect, Principal = "*", Action = "s3:*", Resource = "*",
                   Condition = { Bool = { "aws:SecureTransport" = "false" } } }]
  })
}
"""
    assert _tf(tmp_path, text) == []


def test_terraform_plan_fills_the_policy(tmp_path: Path) -> None:
    deny = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
                           "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
    plan = {"planned_values": {"root_module": {"resources": [
        {"address": "aws_s3_bucket_policy.from_var", "mode": "managed",
         "values": {"bucket": "from-var", "policy": json.dumps(deny)}},
        {"address": "aws_s3_bucket_policy.from_data", "mode": "managed",
         "values": {"bucket": "from-data", "policy": json.dumps({"Statement": [READ_STATEMENT]})}},
    ]}}}
    assert _names(_tf(tmp_path, plan=plan)) == {
        "aws_s3_bucket.none", "aws_s3_bucket.read_only", "aws_s3_bucket.from_data",
        "aws_s3_bucket.heredoc_read_only", "aws_s3_bucket.allows_tls_only",
    }


def test_fixes_in_both_languages(tmp_path: Path) -> None:
    [tf] = [f for f in attach_fixes(_tf(tmp_path), "terraform") if f.evidence.startswith("aws_s3_bucket.none ")]
    assert '"aws:SecureTransport" = "false"' in tf.suggested_code
    assert "aws_s3_bucket.none.id" in tf.suggested_code
    [cf] = attach_fixes(_cf(tmp_path, {"Data": _bucket()}), "cloudformation")
    assert "Bucket: !Ref Data" in cf.suggested_code
    assert '!Sub "${Data.Arn}/*"' in cf.suggested_code
    assert "In CDK" not in cf.recommendation


def test_cdk_hint_is_stripped_for_raw_templates(tmp_path: Path) -> None:
    [finding] = _cf(tmp_path, {"Data": _bucket()})
    stripped = strip_cdk_hint(finding.recommendation)
    assert "In CDK" not in stripped and stripped.endswith(".")
