"""V1 scans raw CloudFormation with the template checks: no synth, no CDK regex pass."""
import json
from pathlib import Path

from typer.testing import CliRunner

from aws_arch_agent.agent.v1 import analyze_v1, discover_templates
from aws_arch_agent.cli import app
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths
from aws_arch_agent.tools.cdk_synth import list_templates_from_path, load_template
from aws_arch_agent.tools.cfn_yaml import load_cfn_yaml
from aws_arch_agent.tools.files import iter_files

runner = CliRunner()

BUCKET_YAML = """AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Env:
    Type: String
Resources:
  Data:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-${Env}"
      Tags:
        - Key: env
          Value: !Ref Env
"""

WORKFLOW = """name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""


def _cf_repo(root: Path) -> None:
    (root / "templates").mkdir()
    (root / "templates" / "data.yaml").write_text(BUCKET_YAML, encoding="utf-8")
    (root / "deploy.yml").write_text(WORKFLOW, encoding="utf-8")
    # Python helper that the CDK regex pass would flag (SEC-005 pattern).
    (root / "scripts").mkdir()
    (root / "scripts" / "seed.py").write_text('s3.Bucket(self, "B")\n', encoding="utf-8")


def test_short_tags_become_long_form_intrinsics() -> None:
    doc = load_cfn_yaml(
        "A: !Ref X\n"
        "B: !GetAtt Res.Arn\n"
        "C: !Sub 'x-${AWS::Region}'\n"
        "D: !Join [',', [a, !Ref Y]]\n"
        "E: !GetAtt [Res, Arn]\n"
    )
    assert doc["A"] == {"Ref": "X"}
    assert doc["B"] == {"Fn::GetAtt": ["Res", "Arn"]}
    assert doc["C"] == {"Fn::Sub": "x-${AWS::Region}"}
    assert doc["D"] == {"Fn::Join": [",", ["a", {"Ref": "Y"}]]}
    assert doc["E"] == {"Fn::GetAtt": ["Res", "Arn"]}


def test_yaml_template_with_short_tags_parses_for_checks(tmp_path: Path) -> None:
    path = tmp_path / "data.yaml"
    path.write_text(BUCKET_YAML, encoding="utf-8")
    warnings: list[str] = []
    findings = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    assert any(f.id == "CF-S3-001" for f in findings)
    assert load_template(path)["Resources"]["Data"]["Type"] == "AWS::S3::Bucket"


def test_v1_cloudformation_repo_runs_template_checks(tmp_path: Path) -> None:
    _cf_repo(tmp_path)
    report, ctx, findings, warnings = analyze_v1(tmp_path, use_llm=False)
    assert ctx.source == "cloudformation"
    assert ctx.notes["templates_scanned"] == 1
    assert warnings == []
    ids = {f.id for f in findings}
    assert "CF-S3-001" in ids
    assert all(f.id.startswith(("CF-", "REPO-")) for f in findings), ids
    assert {f.file for f in findings if f.file} == {"templates/data.yaml"}
    assert "CF-S3-001" in report


def test_only_real_templates_are_discovered(tmp_path: Path) -> None:
    _cf_repo(tmp_path)
    (tmp_path / "config.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
    (tmp_path / "stack.json").write_text(
        json.dumps({"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}), encoding="utf-8"
    )
    (tmp_path / "legacy.template").write_text(BUCKET_YAML, encoding="utf-8")
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "vendored.yaml").write_text(BUCKET_YAML, encoding="utf-8")
    found = list_templates_from_path(tmp_path, real_only=True)
    names = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert names == ["legacy.template", "stack.json", "templates/data.yaml"]


def test_discovery_respects_max_files(tmp_path: Path) -> None:
    _cf_repo(tmp_path)
    assert discover_templates(tmp_path, []) == []
    assert len(discover_templates(tmp_path, iter_files(tmp_path))) == 1


def test_include_and_exclude_apply_to_template_checks(tmp_path: Path) -> None:
    _cf_repo(tmp_path)
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False, rules_exclude=["CF-S3-001"])
    assert "CF-S3-001" not in {f.id for f in findings}
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False, rules_include=["CF-S3-001"])
    assert {f.id for f in findings} == {"CF-S3-001"}


def test_mixed_repo_runs_template_checks(tmp_path: Path) -> None:
    _cf_repo(tmp_path)
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    _r, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    assert ctx.source == "mixed"
    assert any(f.id == "CF-S3-001" for f in findings)
    assert all(f.id.startswith(("CF-", "REPO-")) for f in findings)


def test_cdk_repo_still_runs_regex_pass(tmp_path: Path) -> None:
    (tmp_path / "cdk.json").write_text(json.dumps({"app": "python3 app.py"}), encoding="utf-8")
    (tmp_path / "app.py").write_text('s3.Bucket(self, "B")\n', encoding="utf-8")
    (tmp_path / "extra.yaml").write_text(BUCKET_YAML, encoding="utf-8")
    _r, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False, rules_include=["SEC-005"])
    assert ctx.source == "cdk"
    assert any(f.id == "SEC-005" for f in findings)


def test_cli_default_v1_reports_template_findings(tmp_path: Path) -> None:
    _cf_repo(tmp_path)
    out = tmp_path / "r.json"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["context"]["source"] == "cloudformation"
    assert any(f["id"] == "CF-S3-001" for f in data["findings"])


def test_discovery_skips_symlinked_dirs(tmp_path: Path) -> None:
    _cf_repo(tmp_path)
    (tmp_path / "templates" / "loop").symlink_to(tmp_path, target_is_directory=True)
    found = list_templates_from_path(tmp_path, real_only=True)
    assert [p.relative_to(tmp_path).as_posix() for p in found] == ["templates/data.yaml"]


def test_json_template_with_tabs_in_template_suffix(tmp_path: Path) -> None:
    path = tmp_path / "stack.template"
    path.write_text(
        '{\n\t"Resources": {\n\t\t"B": {"Type": "AWS::S3::Bucket"}\n\t}\n}\n', encoding="utf-8"
    )
    warnings: list[str] = []
    findings = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    assert any(f.id == "CF-S3-001" for f in findings)


def test_intrinsic_lambda_architectures_do_not_break_checks(tmp_path: Path) -> None:
    path = tmp_path / "fn.yaml"
    path.write_text(
        """Conditions:
  UseArm: !Equals [!Ref Arch, arm64]
Resources:
  FnIf:
    Type: AWS::Lambda::Function
    Properties:
      Architectures: !If [UseArm, [arm64], [x86_64]]
  FnRef:
    Type: AWS::Lambda::Function
    Properties:
      Architectures: [!Ref Arch]
""",
        encoding="utf-8",
    )
    warnings: list[str] = []
    findings = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    assert not any(f.id == "CF-PERF-001" for f in findings)
    assert any(f.id == "CF-LAM-002" for f in findings)
