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
    assert all(f.id.startswith(("CF-", "REPO-")) for f in findings), {f.id for f in findings}
    by_id = {f.id: f for f in findings}
    s3 = by_id["CF-S3-001"]
    assert (s3.file, s3.line) == ("infra/main.tf", 5)
    assert s3.evidence == "aws_s3_bucket.data (aws_s3_bucket)"
    assert (by_id["CF-RDS-003"].file, by_id["CF-RDS-003"].line) == ("infra/main.tf", 9)
    assert "CF-RDS-001" not in by_id  # storage_encrypted = var.encrypt
    # Template-level control points at the resource that triggered it.
    assert (by_id["CF-FL-001"].file, by_id["CF-FL-001"].line) == ("infra/network.tf", 1)
    assert by_id["CF-FL-001"].evidence == "Template has 1 VPC(s) and 0 FlowLog(s) (aws_vpc.main)"
    # The local child module is not a root module, and the report says it was skipped.
    assert not any("modules/child" in (f.file or "") for f in findings)
    assert ctx.notes["terraform_child_modules_skipped"] == ["modules/child"]
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
    results = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]
    s3 = next(r for r in results if r["ruleId"] == "CF-S3-001")
    loc = s3["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "infra/main.tf"
    assert loc["region"]["startLine"] == 5


def test_launch_template_finding_points_at_one_without_spot(tmp_path: Path) -> None:
    (tmp_path / "lt.tf").write_text(
        """resource "aws_launch_template" "spot" {
  instance_market_options {
    market_type = "spot"
  }
}

resource "aws_launch_template" "ondemand" {
  instance_type = "t3.micro"
}
""",
        encoding="utf-8",
    )
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False)
    sust = next(f for f in findings if f.id == "CF-SUST-003")
    assert (sust.file, sust.line) == ("lt.tf", 7)
    assert sust.evidence.endswith("(aws_launch_template.ondemand)")


def _write_plan(path: Path, resources: list[dict]) -> Path:
    path.write_text(
        json.dumps({"planned_values": {"root_module": {"resources": resources}}}), encoding="utf-8"
    )
    return path


DB_PLAN = [{
    "address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance", "name": "db",
    "values": {"storage_encrypted": False},
}]


def test_tf_plan_fills_values_in_its_root_module(tmp_path: Path) -> None:
    infra = _tf_repo(tmp_path)
    plan = _write_plan(tmp_path / "plan.json", DB_PLAN)
    _r, ctx, findings, warnings = analyze_v1(tmp_path, use_llm=False, tf_plan=plan)
    assert warnings == []
    assert ctx.notes["terraform_plan_module"] == "infra"
    rds = next(f for f in findings if f.id == "CF-RDS-001")
    assert (rds.file, rds.line) == ("infra/main.tf", 9)
    assert infra.is_dir()


def test_without_tf_plan_scan_is_unchanged(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    _r, ctx, findings, warnings = analyze_v1(tmp_path, use_llm=False)
    assert "terraform_plan_module" not in ctx.notes
    assert "CF-RDS-001" not in {f.id for f in findings}
    assert warnings == []


def test_tf_plan_with_several_root_modules_uses_the_plan_dir(tmp_path: Path) -> None:
    infra = _tf_repo(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "main.tf").write_text('resource "aws_vpc" "v" {}\n', encoding="utf-8")
    _r, ctx, findings, warnings = analyze_v1(
        tmp_path, use_llm=False, tf_plan=_write_plan(infra / "plan.json", DB_PLAN)
    )
    assert warnings == []
    assert ctx.notes["terraform_plan_module"] == "infra"
    assert "CF-RDS-001" in {f.id for f in findings}
    # A plan outside every root module is not applied.
    _r, ctx, findings, warnings = analyze_v1(
        tmp_path, use_llm=False, tf_plan=_write_plan(tmp_path / "plan.json", DB_PLAN)
    )
    assert any("plan not applied" in w for w in warnings)
    assert "CF-RDS-001" not in {f.id for f in findings}


def test_missing_tf_plan_is_a_warning_and_the_scan_runs(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    out = tmp_path / "r.json"
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(out),
        "--tf-plan", str(tmp_path / "missing.json"),
    ])
    assert result.exit_code == 2, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert any("missing.json" in w for w in report["warnings"])
    assert any(f["id"] == "CF-S3-001" for f in report["findings"])


def test_cli_tf_plan(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    plan = _write_plan(tmp_path / "plan.json", DB_PLAN)
    out = tmp_path / "r.json"
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(out),
        "--tf-plan", str(plan),
    ])
    assert result.exit_code == 0, result.output
    assert any(f["id"] == "CF-RDS-001" for f in json.loads(out.read_text(encoding="utf-8"))["findings"])


def test_cli_tf_plan_is_v1_only(tmp_path: Path) -> None:
    _tf_repo(tmp_path)
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--no-llm", "--mode", "v2", "--tf-plan", "plan.json",
    ])
    assert result.exit_code == 1
    assert "V1 only" in result.output


def test_tf_plan_on_non_terraform_source_is_a_warning(tmp_path: Path) -> None:
    (tmp_path / "cdk.json").write_text('{"app": "npx ts-node bin/app.ts"}', encoding="utf-8")
    plan = _write_plan(tmp_path / "plan.json", DB_PLAN)
    _r, ctx, _f, warnings = analyze_v1(tmp_path, use_llm=False, tf_plan=plan)
    assert ctx.source == "cdk"
    assert any("--tf-plan applies only" in w for w in warnings)
