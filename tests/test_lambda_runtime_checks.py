"""CF-LAM-003 (templates) and SEC-068 (CDK source): deprecated Lambda runtimes."""
import json
from datetime import date
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import lambda_runtimes
from aws_arch_agent.rules.cf_template import (
    drop_static_covered_by_cf,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.security_compute import LambdaDeprecatedRuntime
from aws_arch_agent.rules.terraform_model import resources_from_terraform

# Fixed day for the checks: python3.10 deprecated, dotnet8 within 6 months, python3.14 current.
TODAY = date(2026, 11, 5)


@pytest.fixture(autouse=True)
def _fixed_today(monkeypatch: pytest.MonkeyPatch) -> None:
    real = lambda_runtimes.status
    monkeypatch.setattr(lambda_runtimes, "status", lambda r, today=None: real(r, today or TODAY))


def test_runtime_list_was_checked_in_the_last_6_months() -> None:
    """Re-check https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html and
    update rules/lambda_runtimes.py (dates and LAST_CHECKED) when this fails."""
    assert (date.today() - lambda_runtimes.LAST_CHECKED).days <= 183


@pytest.mark.parametrize(
    ("runtime", "expected"),
    [
        ("python3.10", ("deprecated", date(2026, 10, 31))),
        ("nodejs16.x", ("deprecated", date(2024, 6, 12))),
        ("dotnet8", ("soon", date(2026, 11, 10))),
        ("python3.14", None),
        ("nodejs26.x", None),  # preview: no date
        ("python9.9", None),  # unknown: maybe newer than the list
    ],
)
def test_status(runtime: str, expected) -> None:
    assert lambda_runtimes.status(runtime, TODAY) == expected


def test_soon_window_is_6_months() -> None:
    assert lambda_runtimes.status("nodejs22.x", date(2026, 10, 31)) == ("soon", date(2027, 4, 30))
    assert lambda_runtimes.status("nodejs22.x", date(2026, 10, 1)) is None


@pytest.mark.parametrize(
    ("runtime", "current"),
    [("python3.10", "python3.14"), ("nodejs18.x", "nodejs24.x"), ("java8.al2", "java25"),
     ("dotnetcore3.1", "dotnet10"), ("go1.x", "provided.al2023"), ("ruby3.2", "ruby4.0")],
)
def test_replacement_is_the_current_version_of_the_language(runtime: str, current: str) -> None:
    assert lambda_runtimes.replacement(runtime) == current
    assert lambda_runtimes.status(current, TODAY) is None


@pytest.mark.parametrize(
    ("constant", "runtime"),
    [("NODEJS_18_X", "nodejs18.x"), ("PYTHON_3_9", "python3.9"), ("JAVA_8_CORRETTO", "java8.al2"),
     ("JAVA_11", "java11"), ("DOTNET_CORE_3_1", "dotnetcore3.1"), ("DOTNET_8", "dotnet8"),
     ("RUBY_3_2", "ruby3.2"), ("GO_1_X", "go1.x"), ("PROVIDED_AL2", "provided.al2"),
     ("PROVIDED_AL2023", "provided.al2023"), ("PROVIDED", "provided"), ("NODEJS_LATEST", None),
     ("NODEJS_4_3_EDGE", "nodejs4.3-edge"), ("NODEJS_8_10", "nodejs8.10"),
     ("FROM_IMAGE", None)],
)
def test_cdk_runtime_id(constant: str, runtime: str | None) -> None:
    assert lambda_runtimes.cdk_runtime_id(constant) == runtime


# --- CloudFormation -----------------------------------------------------------------


def _fn(**props) -> dict:
    return {"Type": "AWS::Lambda::Function", "Properties": {"Handler": "h", **props}}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == "CF-LAM-003"]


def test_cloudformation_runtimes(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Old": _fn(Runtime="python3.10"),
        "OldNode": _fn(Runtime="nodejs16.x"),
        "Soon": _fn(Runtime="dotnet8"),
        "Current": _fn(Runtime="python3.14"),
        "Image": _fn(PackageType="Image", Runtime="python3.10"),
        "Param": _fn(Runtime={"Ref": "Runtime"}),
        "NoRuntime": _fn(),
    })
    got = {f.evidence.split(" ")[0]: f.severity for f in findings}
    assert got == {"Old": "High", "OldNode": "High", "Soon": "Low"}
    old = next(f for f in findings if f.evidence.startswith("Old"))
    assert "python3.10 was deprecated on 2026-10-31" in old.recommendation
    assert "Move to python3.14." in old.recommendation
    attach_fixes(findings, "cloudformation")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert "Runtime: python3.14" in code["Old"]
    assert "Runtime: nodejs24.x" in code["OldNode"]  # the fix follows the language
    assert "Runtime: dotnet10" in code["Soon"]


def test_static_rule_is_dropped_when_cf_reports_it() -> None:
    static = [Finding(id="SEC-068", title="t", recommendation="r")]
    cf = [Finding(id="CF-LAM-003", title="t", recommendation="r")]
    assert [f.id for f in drop_static_covered_by_cf(static + cf)] == ["CF-LAM-003"]


# --- Terraform ------------------------------------------------------------------

RUNTIMES_TF = """\
resource "aws_lambda_function" "old" {
  function_name = "old"
  role          = aws_iam_role.r.arn
  runtime       = "nodejs18.x"
  handler       = "index.handler"
}

resource "aws_lambda_function" "soon" {
  function_name = "soon"
  role          = aws_iam_role.r.arn
  runtime       = "dotnet8"
  handler       = "h"
}

resource "aws_lambda_function" "current" {
  function_name = "current"
  role          = aws_iam_role.r.arn
  runtime       = "nodejs24.x"
  handler       = "index.handler"
}

resource "aws_lambda_function" "image" {
  function_name = "image"
  role          = aws_iam_role.r.arn
  package_type  = "Image"
  image_uri     = "111122223333.dkr.ecr.eu-north-1.amazonaws.com/app:1"
}

resource "aws_lambda_function" "from_var" {
  function_name = "from_var"
  role          = aws_iam_role.r.arn
  runtime       = var.runtime
  handler       = "index.handler"
}
"""


def test_terraform_runtimes(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(RUNTIMES_TF, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    findings = [f for f in run_resource_checks(resources, tmp_path / "main.tf") if f.id == "CF-LAM-003"]
    assert {f.evidence.split(" ")[0]: f.severity for f in findings} == {
        "aws_lambda_function.old": "High",
        "aws_lambda_function.soon": "Low",
    }
    attach_fixes(findings, "terraform")
    old = next(f for f in findings if f.evidence.startswith("aws_lambda_function.old"))
    assert 'resource "aws_lambda_function" "old"' in (old.suggested_code or "")
    assert 'runtime = "nodejs24.x"' in (old.suggested_code or "")
    assert "Move to nodejs24.x." in old.recommendation and "In CDK" not in old.recommendation


# --- CDK source (SEC-068) -------------------------------------------------------


def _cdk(tmp_path: Path, lang: str, code: str) -> list[Finding]:
    if lang == "typescript":
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "stack.ts").write_text(code, encoding="utf-8")
    else:
        (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
        (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return LambdaDeprecatedRuntime().run(tmp_path, lang)


@pytest.mark.parametrize(
    ("lang", "code", "severities"),
    [
        ("typescript", "new lambda.Function(this, 'F', { runtime: lambda.Runtime.NODEJS_18_X });", ["High"]),
        ("typescript", "runtime: lambda.Runtime.DOTNET_8,", ["Low"]),
        ("typescript", "runtime: lambda.Runtime.NODEJS_24_X,", []),
        ("typescript", "runtime: lambda.Runtime.NODEJS_LATEST,", []),
        ("python", "_lambda.Function(self, 'F', runtime=_lambda.Runtime.PYTHON_3_9)", ["High"]),
        ("python", "runtime=_lambda.Runtime.PYTHON_3_14", []),
    ],
)
def test_cdk_source(tmp_path: Path, lang: str, code: str, severities: list[str]) -> None:
    assert [f.severity for f in _cdk(tmp_path, lang, code)] == severities
