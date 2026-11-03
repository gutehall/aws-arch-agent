"""V1 reports Terraform findings with the CF-* controls, at the HCL file and line."""
import json
from pathlib import Path

from typer.testing import CliRunner

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.cli import app

runner = CliRunner()

MAIN_TF = """\
variable "encrypt" {
  type = bool
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}

resource "aws_db_instance" "db" {
  storage_encrypted   = var.encrypt
  multi_az            = false
  deletion_protection = true
  backup_retention_period = 7
}
"""

NETWORK_TF = """\
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
"""


def _tf_repo(root: Path) -> Path:
    infra = root / "infra"
    infra.mkdir()
    (infra / "main.tf").write_text(MAIN_TF, encoding="utf-8")
    (infra / "network.tf").write_text(NETWORK_TF, encoding="utf-8")
    (infra / "main.tf").with_name("module.tf").write_text(
        'module "child" {\n  source = "../modules/child"\n}\n', encoding="utf-8"
    )
    child = root / "modules" / "child"
    child.mkdir(parents=True)
    (child / "main.tf").write_text('resource "aws_sqs_queue" "q" {}\n', encoding="utf-8")
    # A script the CDK regex pass would flag (SEC-005 pattern).
    (root / "scripts").mkdir()
    (root / "scripts" / "seed.py").write_text('s3.Bucket(self, "B")\n', encoding="utf-8")
    return infra


def test_terraform_repo_reports_cf_findings_at_hcl_lines(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    report, ctx, findings, warnings = analyze_v1(tmp_path, use_llm=False)
    assert ctx.source == "terraform"
    assert ctx.notes["terraform_modules"] == ["infra"]
    assert warnings == []
    assert all(f.id.startswith("CF-") for f in findings), {f.id for f in findings}
    by_id = {f.id: f for f in findings}
    s3 = by_id["CF-S3-001"]
    assert (s3.file, s3.line) == ("infra/main.tf", 5)
    assert s3.evidence == "aws_s3_bucket.data (aws_s3_bucket)"
    assert (by_id["CF-RDS-003"].file, by_id["CF-RDS-003"].line) == ("infra/main.tf", 9)
    assert "CF-RDS-001" not in by_id  # storage_encrypted = var.encrypt
    # Template-level control points at the resource that triggered it.
    assert (by_id["CF-FL-001"].file, by_id["CF-FL-001"].line) == ("infra/network.tf", 1)
    # The local child module is not a root module.
    assert not any("modules/child" in (f.file or "") for f in findings)
    assert "CF-S3-001" in report


def test_include_and_exclude_apply(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False, rules_include=["CF-S3-001"])
    assert {f.id for f in findings} == {"CF-S3-001"}
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False, rules_exclude=["CF-S3-001"])
    assert "CF-S3-001" not in {f.id for f in findings}


def test_severity_threshold_applies(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False, severity_threshold="high")
    assert findings and all(f.severity == "High" for f in findings)


def test_mixed_repo_runs_cloudformation_and_terraform(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    (tmp_path / "stack.yaml").write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  Q:\n    Type: AWS::SQS::Queue\n',
        encoding="utf-8",
    )
    _r, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False)
    assert ctx.source == "mixed"
    files = {f.file for f in findings}
    assert "stack.yaml" in files
    assert "infra/main.tf" in files


def test_explicit_iac_terraform_on_mixed_repo(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    (tmp_path / "stack.yaml").write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  Q:\n    Type: AWS::SQS::Queue\n',
        encoding="utf-8",
    )
    _r, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False, iac="terraform")
    assert ctx.source == "terraform"
    assert "stack.yaml" not in {f.file for f in findings}


def test_bad_terraform_file_is_a_warning(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_vpc" "v" {\n', encoding="utf-8")
    (tmp_path / "ok.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    _r, _c, findings, warnings = analyze_v1(tmp_path, use_llm=False)
    assert any("main.tf" in w for w in warnings)
    assert any(f.id == "CF-S3-001" and f.file == "ok.tf" for f in findings)


def test_cli_sarif_has_hcl_location(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    out = tmp_path / "r.sarif"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--no-llm", "--format", "sarif", "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    results = json.loads(out.read_text())["runs"][0]["results"]
    s3 = next(r for r in results if r["ruleId"] == "CF-S3-001")
    loc = s3["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "infra/main.tf"
    assert loc["region"]["startLine"] == 5
