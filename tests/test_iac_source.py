"""IaC source detection: CDK, CloudFormation, Terraform, or mixed."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent.agent.v1 import (
    IacError,
    analyze_v1,
    detect_source,
    is_cf_template,
    resolve_source,
)
from aws_arch_agent.cli import app

runner = CliRunner()

CF_YAML = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-data"
"""

CF_YAML_NO_VERSION = """Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref QueueName
"""

GH_WORKFLOW = """name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
"""

TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "data"\n}\n'


def _cdk_ts(root: Path) -> None:
    (root / "cdk.json").write_text(json.dumps({"app": "npx ts-node bin/app.ts"}), encoding="utf-8")
    (root / "bin").mkdir()
    (root / "bin" / "app.ts").write_text('new s3.Bucket(this, "B");\n', encoding="utf-8")


def test_cdk_repo_with_workflow_yaml_stays_cdk(tmp_path: Path) -> None:
    _cdk_ts(tmp_path)
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(GH_WORKFLOW, encoding="utf-8")
    (tmp_path / "deploy.yml").write_text(GH_WORKFLOW, encoding="utf-8")
    assert detect_source(tmp_path) == "cdk"


def test_cdk_wins_over_templates_and_terraform(tmp_path: Path) -> None:
    _cdk_ts(tmp_path)
    (tmp_path / "extra.yaml").write_text(CF_YAML, encoding="utf-8")
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    assert detect_source(tmp_path) == "cdk"


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("package.json", json.dumps({"dependencies": {"aws-cdk-lib": "2.170.0"}})),
        ("requirements.txt", "aws-cdk-lib==2.170.0\nconstructs\n"),
        ("pyproject.toml", '[project]\ndependencies = ["aws-cdk-lib>=2"]\n'),
    ],
)
def test_cdk_package_marks_cdk(tmp_path: Path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")
    (tmp_path / "template.yaml").write_text(CF_YAML, encoding="utf-8")
    assert detect_source(tmp_path) == "cdk"


def test_cloudformation_dir_is_cloudformation(tmp_path: Path) -> None:
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "stack.yaml").write_text(CF_YAML, encoding="utf-8")
    (tmp_path / "ci.yml").write_text(GH_WORKFLOW, encoding="utf-8")
    assert detect_source(tmp_path) == "cloudformation"


def test_template_without_version_needs_aws_resource(tmp_path: Path) -> None:
    ok = tmp_path / "queue.yml"
    ok.write_text(CF_YAML_NO_VERSION, encoding="utf-8")
    other = tmp_path / "other.yml"
    other.write_text("Resources:\n  Thing:\n    Type: Custom::Thing\n", encoding="utf-8")
    assert is_cf_template(ok)
    assert not is_cf_template(other)


def test_json_template_detected(tmp_path: Path) -> None:
    path = tmp_path / "stack.template.json"
    path.write_text(
        json.dumps({"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}), encoding="utf-8"
    )
    assert is_cf_template(path)
    assert detect_source(tmp_path) == "cloudformation"


def test_workflow_yaml_is_not_template(tmp_path: Path) -> None:
    path = tmp_path / "ci.yml"
    path.write_text(GH_WORKFLOW + "env:\n  NOTE: AWS::S3::Bucket\n", encoding="utf-8")
    assert not is_cf_template(path)
    assert detect_source(tmp_path) == "cdk"


@pytest.mark.parametrize("name", ["main.tf", "main.tf.json"])
def test_terraform_files(tmp_path: Path, name: str) -> None:
    content = TF if name.endswith(".tf") else json.dumps({"resource": {}})
    (tmp_path / name).write_text(content, encoding="utf-8")
    assert detect_source(tmp_path) == "terraform"


def test_cloudformation_and_terraform_is_mixed(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text(CF_YAML, encoding="utf-8")
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    assert detect_source(tmp_path) == "mixed"


def test_explicit_iac_without_files_fails(tmp_path: Path) -> None:
    _cdk_ts(tmp_path)
    with pytest.raises(IacError, match="--iac terraform"):
        resolve_source(tmp_path, "terraform")
    with pytest.raises(IacError, match="--iac cloudformation"):
        resolve_source(tmp_path, "cloudformation")
    assert resolve_source(tmp_path, "cdk") == "cdk"


def test_explicit_iac_overrides_detection(tmp_path: Path) -> None:
    _cdk_ts(tmp_path)
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    assert resolve_source(tmp_path, "auto") == "cdk"
    assert resolve_source(tmp_path, "terraform") == "terraform"


def test_v1_context_reports_source(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text(CF_YAML, encoding="utf-8")
    report, ctx, _findings, _warnings = analyze_v1(tmp_path, use_llm=False)
    assert ctx.source == "cloudformation"
    assert "- Source: **cloudformation**" in report


def test_cli_explicit_iac_with_no_files_exits_nonzero(tmp_path: Path) -> None:
    _cdk_ts(tmp_path)
    out = tmp_path / "r.md"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--no-llm", "--iac", "terraform", "--out", str(out)]
    )
    assert result.exit_code == 1
    assert "no Terraform" in result.output
    assert not out.exists()


def test_cli_rejects_unknown_iac(tmp_path: Path) -> None:
    _cdk_ts(tmp_path)
    result = runner.invoke(app, ["--repo", str(tmp_path), "--no-llm", "--iac", "pulumi"])
    assert result.exit_code != 0


def test_cli_json_includes_source(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    out = tmp_path / "r.json"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["context"]["source"] == "terraform"


def test_minified_json_template_with_version_only(tmp_path: Path) -> None:
    path = tmp_path / "min.json"
    path.write_text('{"AWSTemplateFormatVersion":"2010-09-09","Resources":{}}', encoding="utf-8")
    assert is_cf_template(path)


def test_version_key_in_comment_is_not_template(tmp_path: Path) -> None:
    path = tmp_path / "notes.yml"
    path.write_text("# AWSTemplateFormatVersion: not here\nname: x\n", encoding="utf-8")
    assert not is_cf_template(path)


def test_explicit_cdk_needs_cdk_app_not_stray_script(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text(CF_YAML, encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "helper.py").write_text("print('hi')\n", encoding="utf-8")
    with pytest.raises(IacError, match="--iac cdk"):
        resolve_source(tmp_path, "cdk")
    (tmp_path / "app.py").write_text("app = App()\n", encoding="utf-8")
    assert resolve_source(tmp_path, "cdk") == "cdk"
