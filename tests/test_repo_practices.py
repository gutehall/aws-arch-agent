"""OPS 5: tests, a pipeline, environments (repo-level rules) and EC2 patching."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import environments_found

REPO_IDS = ("REPO-001", "REPO-002", "REPO-003")
SOURCES = ("cdk", "cloudformation", "terraform")

CDK_STACK = "import * as cdk from 'aws-cdk-lib';\nnew s3.Bucket(this, 'Data');\n"
CFN_BUCKET = {"Resources": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}}}
TF_BUCKET = 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n'


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _bare_repo(root: Path, source: str) -> None:
    """One stack, no tests, no CI, one environment."""
    if source == "cdk":
        _write(root / "package.json", "{}")
        _write(root / "lib" / "stack.ts", CDK_STACK)
    elif source == "cloudformation":
        _write(root / "stack.template.json", json.dumps(CFN_BUCKET))
    else:
        _write(root / "main.tf", TF_BUCKET)


def _add_controls(root: Path, source: str) -> None:
    """Tests, a CI workflow, and a dev and a prod environment, in the source's own idiom."""
    _write(root / ".github" / "workflows" / "ci.yml", "on: push\njobs: {}\n")
    if source == "cdk":
        _write(root / "test" / "stack.test.ts", "test('bucket', () => {});\n")
        _write(
            root / "bin" / "app.ts",
            "import * as cdk from 'aws-cdk-lib';\n"
            "new AppStack(app, 'AppDev');\nnew AppStack(app, 'AppProd');\n",
        )
    elif source == "cloudformation":
        _write(root / ".taskcat.yml", "project:\n  name: app\n")
        _write(root / "parameters" / "dev-params.json", "[]")
        _write(root / "parameters" / "prod-params.json", "[]")
    else:
        _write(root / "tests" / "main.tftest.hcl", 'run "plan" {\n  command = plan\n}\n')
        _write(root / "envs" / "dev.tfvars", 'name = "dev"\n')
        _write(root / "envs" / "prod.tfvars", 'name = "prod"\n')


def _scan(root: Path):
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return _report, ctx, findings


@pytest.mark.parametrize("source", SOURCES)
def test_repo_without_the_controls_fails_ops5(tmp_path: Path, source: str) -> None:
    _bare_repo(tmp_path, source)
    report, ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    repo = [f for f in findings if f.id.startswith("REPO-")]
    assert sorted(f.id for f in repo) == list(REPO_IDS)  # once each, whatever the passes
    for f in repo:
        assert f.question == "OPS 5"
        assert f.best_practices == list(well_architected.best_practices_of(f.id))
    assert set(REPO_IDS) <= set(ctx.rules_run)
    assert "- **OPS 5** How do you reduce defects, ease remediation, and improve flow into" in report
    assert "  - [REPO-001] Repo has no automated tests" in report


@pytest.mark.parametrize("source", SOURCES)
def test_repo_with_the_controls_passes(tmp_path: Path, source: str) -> None:
    _bare_repo(tmp_path, source)
    _add_controls(tmp_path, source)
    _report, ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    assert not [f.id for f in findings if f.id.startswith("REPO-")]


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (".gitlab-ci.yml", "stages: [build]\n"),
        ("buildspec.yml", "version: 0.2\n"),
        ("Jenkinsfile", "pipeline {}\n"),
        (".circleci/config.yml", "version: 2.1\n"),
        ("lib/pipeline.ts", "new pipelines.CodePipeline(this, 'Pipeline', { synth });\n"),
        ("pipeline.tf", 'resource "aws_codepipeline" "app" {\n}\n'),
    ],
)
def test_any_ci_config_or_pipeline_in_the_iac_satisfies_repo_002(
    tmp_path: Path, rel: str, text: str
) -> None:
    _bare_repo(tmp_path, "terraform")
    _write(tmp_path / rel, text)
    _r, _ctx, findings = _scan(tmp_path)
    assert "REPO-002" not in {f.id for f in findings}


def test_environments_come_from_paths_stack_ids_and_cdk_context(tmp_path: Path) -> None:
    _write(tmp_path / "infra" / "staging" / "main.tf", TF_BUCKET)
    _write(tmp_path / "app.py", "AppStack(app, 'app-prod')\n")
    _write(tmp_path / "cdk.json", json.dumps({"context": {
        "dev": {"account": "1"}, "@aws-cdk/pipelines:reduceStageRoleTrustScope": True}}))
    assert set(environments_found(tmp_path)) == {"staging", "prod", "dev"}


def test_test_fixtures_and_feature_flags_name_no_environment(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "fixtures" / "prod.tfvars", "x = 1\n")
    _write(tmp_path / "cdk.json", json.dumps({"context": {
        "@aws-cdk/pipelines:reduceStageRoleTrustScope": True}}))
    _write(tmp_path / "envs" / "test" / "main.tf", TF_BUCKET)  # envs/test is an environment
    assert set(environments_found(tmp_path)) == {"dev"}


def test_build_output_is_not_searched(tmp_path: Path) -> None:
    _bare_repo(tmp_path, "terraform")
    _write(tmp_path / "node_modules" / "pkg" / "test" / "index.test.js", "test()\n")
    _write(tmp_path / ".terraform" / "modules" / "m" / "buildspec.yml", "version: 0.2\n")
    _r, _ctx, findings = _scan(tmp_path)
    assert {"REPO-001", "REPO-002"} <= {f.id for f in findings}


def test_rules_exclude_turns_off_a_repo_rule_on_a_template_scan(tmp_path: Path) -> None:
    _bare_repo(tmp_path, "cloudformation")
    _report, ctx, findings, _w = analyze_v1(tmp_path, use_llm=False, rules_exclude=["REPO-002"])
    ids = {f.id for f in findings}
    assert "REPO-002" not in ids and "REPO-001" in ids
    assert "REPO-002" not in ctx.rules_run


def test_repo_rules_count_as_run_for_every_source() -> None:
    active = ["REPO-001", "CF-S3-001", "SEC-001"]
    assert well_architected.rules_run(active, cdk=False, templates=True) == ["REPO-001", "CF-S3-001"]
    assert well_architected.rules_run(active, cdk=True, templates=False) == ["REPO-001", "SEC-001"]


def test_v2_reports_the_repo_rules(tmp_path: Path) -> None:
    _bare_repo(tmp_path, "cdk")
    _report, ctx, findings, _w = analyze_v2(tmp_path, use_llm=False, skip_synth=True)
    repo = sorted(f.id for f in findings if f.id.startswith("REPO-"))
    assert repo == list(REPO_IDS)
    assert set(REPO_IDS) <= set(ctx.rules_run)


# --- CF-PATCH-001: EC2 compute with no patch baseline or patch run ---

def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


CFN_INSTANCE = {"Web": {"Type": "AWS::EC2::Instance", "Properties": {"ImageId": "ami-1"}}}
CFN_ASSOCIATION = {"Type": "AWS::SSM::Association", "Properties": {"Name": "AWS-RunPatchBaseline"}}
CFN_WINDOW_TASK = {
    "Type": "AWS::SSM::MaintenanceWindowTask",
    "Properties": {"TaskArn": "AWS-RunPatchBaseline", "TaskType": "RUN_COMMAND"},
}
TF_INSTANCE = 'resource "aws_instance" "web" {\n  ami = "ami-1"\n}\n'


@pytest.mark.parametrize(
    ("extra", "fires"),
    [
        ({}, True),
        ({"Agent": {"Type": "AWS::SSM::Association", "Properties": {"Name": "AWS-UpdateSSMAgent"}}},
         True),
        ({"Patch": CFN_ASSOCIATION}, False),
        ({"Task": CFN_WINDOW_TASK}, False),
        ({"Baseline": {"Type": "AWS::SSM::PatchBaseline", "Properties": {"Name": "b"}}}, False),
    ],
)
def test_cf_patch_001_on_cloudformation(tmp_path: Path, extra: dict, fires: bool) -> None:
    _write(tmp_path / "stack.template.json", _cfn({**CFN_INSTANCE, **extra}))
    _r, _ctx, findings = _scan(tmp_path)
    patch = [f for f in findings if f.id == "CF-PATCH-001"]
    assert bool(patch) is fires
    if fires:
        assert patch[0].question == "OPS 5"
        assert patch[0].best_practices == ["OPS05-BP05"]
        assert "AWS-RunPatchBaseline" in (patch[0].suggested_code or "")


def test_cf_patch_001_needs_ec2_compute(tmp_path: Path) -> None:
    _write(tmp_path / "stack.template.json", json.dumps(CFN_BUCKET))
    _r, _ctx, findings = _scan(tmp_path)
    assert "CF-PATCH-001" not in {f.id for f in findings}


@pytest.mark.parametrize(
    ("extra", "fires"),
    [
        ("", True),
        ('resource "aws_ssm_patch_baseline" "b" {\n  name = "b"\n}\n', False),
        ('resource "aws_ssm_association" "p" {\n  name = "AWS-RunPatchBaseline"\n}\n', False),
        ('resource "aws_ssm_association" "p" {\n  name = var.document\n}\n', False),
        ('resource "aws_ssm_maintenance_window_task" "t" {\n'
         '  task_type = "RUN_COMMAND"\n  task_arn = "AWS-RunPatchBaseline"\n}\n', False),
        ('resource "aws_ssm_association" "a" {\n  name = "AWS-UpdateSSMAgent"\n}\n', True),
    ],
)
def test_cf_patch_001_on_terraform(tmp_path: Path, extra: str, fires: bool) -> None:
    _write(tmp_path / "main.tf", TF_INSTANCE + extra)
    _r, ctx, findings = _scan(tmp_path)
    assert ctx.source == "terraform"
    patch = [f for f in findings if f.id == "CF-PATCH-001"]
    assert bool(patch) is fires
    if fires:
        assert patch[0].file == "main.tf"
        assert patch[0].question == "OPS 5"
