"""CF-IAM-001..003: over-broad IAM policies in CloudFormation and Terraform.

Action "*" on Resource "*" is CF-IAM-008 (full admin access, tests/test_iam_admin_checks.py).
"""
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
from aws_arch_agent.rules.terraform_model import load_plan_values, resources_from_terraform

IAM_IDS = {"CF-IAM-001", "CF-IAM-002", "CF-IAM-003", "CF-IAM-008"}


def _doc(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(action, resource="*") -> dict:
    return {"Effect": "Allow", "Action": action, "Resource": resource}


# --- policy document analysis ---------------------------------------------------


@pytest.mark.parametrize(
    ("doc", "kinds"),
    [
        (_doc(_allow("*")), ["admin"]),
        (_doc(_allow("*", "arn:aws:s3:::b")), ["all_actions"]),
        (_doc(_allow(["s3:*", "sqs:SendMessage"])), ["service_actions"]),
        (_doc(_allow(["sqs:SendMessage"])), ["write_on_all_resources"]),
        (_doc(_allow(["sqs:SendMessage"], "arn:aws:sqs:eu-north-1:1:q")), []),
        (_doc(_allow(["s3:GetObject", "s3:List*", "ec2:Describe*"])), []),
        (_doc(_allow(["xray:PutTraceSegments", "cloudwatch:PutMetricData"])), []),
        (_doc({"Effect": "Deny", "Action": "*", "Resource": "*"}), []),
        (_doc(_allow({"Ref": "Actions"})), []),
        (_doc(_allow("*"), _allow("s3:*"), _allow("sns:Publish")),
         ["admin", "service_actions", "write_on_all_resources"]),
        ({"Statement": _allow("*")}, ["admin"]),  # single statement, not a list
        (_doc(_allow(["s3:getobject", "S3:LIST*"])), []),  # action names ignore case
        (_doc(_allow(["sqs:sendmessage"])), ["write_on_all_resources"]),
        (_doc({"Effect": {"Ref": "E"}, "Action": "*", "Resource": "*"}), []),  # unknown Effect
    ],
)
def test_broadest_kinds(doc: dict, kinds: list[str]) -> None:
    assert [b.kind for b in iam_policy.broadest(doc)] == kinds


def test_as_document_reads_json_text_and_rejects_non_policies() -> None:
    assert iam_policy.as_document(json.dumps(_doc(_allow("*")))) is not None
    assert iam_policy.as_document("not json") is None
    assert iam_policy.as_document({"Fn::Sub": "x"}) is None


# --- CloudFormation -----------------------------------------------------------------


def _cf_findings(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IAM_IDS]


def test_cloudformation_policy_types(tmp_path: Path) -> None:
    findings = _cf_findings(tmp_path, {
        "Managed": {"Type": "AWS::IAM::ManagedPolicy",
                    "Properties": {"PolicyDocument": _doc(_allow("*", "arn:aws:s3:::b"))}},
        "Inline": {"Type": "AWS::IAM::Policy",
                   "Properties": {"PolicyName": "p", "PolicyDocument": _doc(_allow("dynamodb:*"))}},
        "Role": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": _doc(),
            "Policies": [
                {"PolicyName": "ok", "PolicyDocument": _doc(_allow("s3:GetObject"))},
                {"PolicyName": "writes", "PolicyDocument": _doc(_allow("sqs:SendMessage"))},
            ],
        }},
        "User": {"Type": "AWS::IAM::User", "Properties": {
            "Policies": [{"PolicyName": "u", "PolicyDocument": _doc(_allow("*"))}]}},
        "Scoped": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "PolicyDocument": _doc(_allow("s3:PutObject", "arn:aws:s3:::b/*"))}},
    })
    got = {(f.id, f.evidence.split(" ")[0]) for f in findings}
    assert got == {
        ("CF-IAM-001", "Managed"),
        ("CF-IAM-002", "Inline"),
        ("CF-IAM-003", "Role"),
        ("CF-IAM-008", "User"),
    }
    role = next(f for f in findings if f.evidence.startswith("Role"))
    assert role.evidence == "Role (AWS::IAM::Role)"
    assert role.recommendation.startswith("Flagged: sqs:SendMessage (in policy writes).")
    # A raw template gets a CloudFormation fix shaped for the resource, without the CDK hint.
    attach_fixes(findings, "cloudformation")
    assert "Policies:" in (role.suggested_code or "") and "In CDK" not in role.recommendation
    managed = next(f for f in findings if f.evidence.startswith("Managed"))
    assert "PolicyDocument:" in (managed.suggested_code or "")
    assert all(f.category == "Security" and f.file == "t.json" for f in findings)
    assert {f.severity for f in findings if f.id in ("CF-IAM-001", "CF-IAM-008")} == {"High"}


def test_cloudformation_intrinsic_values_are_not_guessed(tmp_path: Path) -> None:
    findings = _cf_findings(tmp_path, {
        "P": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {"PolicyDocument": _doc(
            _allow({"Ref": "Action"}),
            _allow("sqs:SendMessage", {"Fn::GetAtt": ["Q", "Arn"]}),
        )}},
        "Q": {"Type": "AWS::IAM::ManagedPolicy",
              "Properties": {"PolicyDocument": {"Fn::If": ["C", {}, {}]}}},
    })
    assert findings == []


def test_static_wildcard_rules_are_dropped_when_cf_reports_them() -> None:
    static = [Finding(id=i, title="t", recommendation="r") for i in ("SEC-001", "SEC-002")]
    cf = [Finding(id="CF-IAM-001", title="t", recommendation="r")]
    assert [f.id for f in drop_static_covered_by_cf(static + cf)] == ["SEC-002", "CF-IAM-001"]


# --- Terraform ------------------------------------------------------------------

POLICIES_TF = """\
resource "aws_iam_policy" "all" {
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_role_policy" "heredoc" {
  role   = aws_iam_role.app.id
  policy = <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
EOF
}

data "aws_iam_policy_document" "writes" {
  statement {
    actions   = ["sqs:SendMessage", "s3:GetObject"]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "from_data" {
  user   = "ci"
  policy = data.aws_iam_policy_document.writes.json
}

resource "aws_iam_role" "app" {
  assume_role_policy = "{}"
  inline_policy {
    name   = "partly_known"
    policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = var.arn }] })
  }
  inline_policy {
    name   = "unknown"
    policy = var.policy
  }
}

resource "aws_iam_policy" "scoped" {
  policy = jsonencode({
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.b.arn}/*" },
      { Effect = "Allow", Action = ["xray:PutTraceSegments"], Resource = "*" },
    ]
  })
}

resource "aws_iam_policy" "unknown_actions" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = var.actions, Resource = "*" }] })
}

resource "aws_iam_policy" "from_var" {
  policy = var.policy
}
"""


def _tf_findings(module: Path, plan: dict | None = None) -> dict[str, str]:
    resources = resources_from_terraform(module, plan_values=plan)
    findings = run_resource_checks(resources, module / "main.tf")
    return {f.evidence.split(" ")[0]: f.id for f in findings if f.id in IAM_IDS}


def test_terraform_policy_forms(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(POLICIES_TF, encoding="utf-8")
    assert _tf_findings(tmp_path) == {
        "aws_iam_policy.all": "CF-IAM-008",
        "aws_iam_role_policy.heredoc": "CF-IAM-002",
        "aws_iam_user_policy.from_data": "CF-IAM-003",
        "aws_iam_role.app": "CF-IAM-001",
    }


def test_terraform_finding_points_at_the_policy_line(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(POLICIES_TF, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    finding = next(
        f for f in run_resource_checks(resources, tmp_path / "main.tf")
        if f.evidence.startswith("aws_iam_role_policy.heredoc")
    )
    assert finding.file == str(tmp_path / "main.tf") and finding.line == 8


def test_terraform_data_sources_are_not_resources(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(POLICIES_TF, encoding="utf-8")
    names = {r.name for r in resources_from_terraform(tmp_path)}
    assert not any(name.startswith("data.") for name in names)


def test_terraform_json_policy_string(tmp_path: Path) -> None:
    body = {"resource": {"aws_iam_policy": {
        "literal": {"policy": json.dumps(_doc(_allow("*")))},
        "encoded": {"policy": "${jsonencode({Statement = [{Effect = \"Allow\", Action = \"iam:*\", Resource = \"*\"}]})}"},
    }}}
    (tmp_path / "main.tf.json").write_text(json.dumps(body), encoding="utf-8")
    assert _tf_findings(tmp_path) == {
        "aws_iam_policy.literal": "CF-IAM-008",
        "aws_iam_policy.encoded": "CF-IAM-002",
    }


def test_terraform_plan_fills_a_policy_from_var(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(POLICIES_TF, encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"planned_values": {"root_module": {"resources": [{
        "address": "aws_iam_policy.from_var", "mode": "managed", "type": "aws_iam_policy",
        "name": "from_var", "values": {"policy": json.dumps(_doc(_allow("*")))},
    }]}}}), encoding="utf-8")
    found = _tf_findings(tmp_path, load_plan_values(plan_path))
    assert found["aws_iam_policy.from_var"] == "CF-IAM-008"


def test_terraform_fix_matches_the_resource_shape(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(POLICIES_TF, encoding="utf-8")
    findings = run_resource_checks(resources_from_terraform(tmp_path), tmp_path / "main.tf")
    attach_fixes(findings, "terraform")
    by_name = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings if f.id in IAM_IDS}
    assert 'resource "aws_iam_role_policy" "heredoc"' in by_name["aws_iam_role_policy.heredoc"]
    assert "inline_policy {" in by_name["aws_iam_role.app"]
    assert "data.aws_iam_policy_document.app.json" in by_name["aws_iam_role.app"]


def test_synth_output_keeps_the_cdk_hint_and_raw_templates_drop_it() -> None:
    from aws_arch_agent.rules.fix_snippets import strip_cdk_hint
    from aws_arch_agent.rules.cf_template import _IAM_CDK_HINT

    assert strip_cdk_hint("Scope it." + _IAM_CDK_HINT) == "Scope it."


def test_terraform_heredoc_with_interpolation_and_minified_json(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("""\
resource "aws_iam_role_policy" "interp" {
  role   = "r"
  policy = <<-EOT
    {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "${aws_s3_bucket.b.arn}"}]}
  EOT
}

data "aws_iam_policy_document" "mixed" {
  statement {
    actions   = ["kms:*"]
    resources = ["*"]
  }
  dynamic "statement" {
    for_each = var.extra
    content {
      actions = statement.value
    }
  }
}

resource "aws_iam_policy" "minified" {
  policy = data.aws_iam_policy_document.mixed.minified_json
}
""", encoding="utf-8")
    assert _tf_findings(tmp_path) == {
        "aws_iam_role_policy.interp": "CF-IAM-001",
        "aws_iam_policy.minified": "CF-IAM-002",
    }
