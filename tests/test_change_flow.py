"""OPS 5: version control (REPO-113), a configuration store (REPO-114), a quality gate in CI
(REPO-115) and small, reversible changes (REPO-116)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import (
    ConfigurationStoreMissing,
    QualityGateMissing,
    SmallReversibleChangesMissing,
    VersionControlMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TF_FN = 'resource "aws_lambda_function" "f" {\n  function_name = "f"\n}\n'
_CFN_FN = (
    '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"F": {"Type": '
    '"AWS::Lambda::Function", "Properties": {}}}}'
)
_CDK_FN = "new lambda.Function(this, 'F', { runtime, handler, code });\n"
_COMPUTE = [{"main.tf": _TF_FN}, {"t.json": _CFN_FN}, {"lib/stack.ts": _CDK_FN}]
_IDS = ["terraform", "cloudformation", "cdk"]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str], *, git: bool = False) -> list:
    # Under prod/: the pytest directory name says "test", which reads as a dev stack.
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    if git:
        (root / ".git").mkdir()
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops5() -> None:
    for rule_id, bp in (("REPO-113", "OPS05-BP01"), ("REPO-114", "OPS05-BP03"),
                        ("REPO-115", "OPS05-BP07"), ("REPO-116", "OPS05-BP09")):
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


# REPO-113 version control

def test_no_git_no_hosted_repo_fails(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, {"main.tf": _TF_FN}), "REPO-113")
    assert hit.question == "OPS 5"
    assert hit.severity == "Low" and hit.category == "Operational Excellence"
    assert hit.evidence.endswith("found none")


def test_git_checkout_passes(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": _TF_FN}, git=True), "REPO-113")


def test_git_file_in_a_worktree_passes(tmp_path: Path) -> None:
    _write(tmp_path / ".git", "gitdir: /elsewhere/.git/worktrees/x\n")
    assert not _found(_scan(tmp_path, {"main.tf": _TF_FN}), "REPO-113")


def test_git_in_a_parent_folder_passes(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "infra"
    _write(sub / "main.tf", _TF_FN)
    assert not VersionControlMissing().run(sub)


@pytest.mark.parametrize(
    "files",
    [
        {"main.tf": 'resource "aws_codecommit_repository" "r" {\n  repository_name = "r"\n}\n'},
        {"lib/stack.ts": "new codecommit.Repository(this, 'Repo', { repositoryName: 'r' });\n"},
        {"lib/pipe.ts": "CodePipelineSource.connection('org/repo', 'main', { connectionArn });\n"},
        {"main.tf": 'resource "aws_codestarconnections_connection" "c" {\n  name = "c"\n}\n'},
    ],
    ids=["terraform-codecommit", "cdk-codecommit", "cdk-connection", "terraform-connection"],
)
def test_hosted_repository_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-113")


# REPO-114 configuration store

@pytest.mark.parametrize("files", _COMPUTE, ids=_IDS)
def test_hardcoded_config_fails(tmp_path: Path, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), "REPO-114")
    assert hit.question == "OPS 5"
    assert hit.evidence.endswith("found none")


@pytest.mark.parametrize(
    "extra",
    [
        {"ssm.tf": 'resource "aws_ssm_parameter" "p" {\n  name = "/app/x"\n}\n'},
        {"lib/cfg.ts": "const v = ssm.StringParameter.valueForStringParameter(this, '/app/x');\n"},
        {"secret.tf": 'resource "aws_secretsmanager_secret" "s" {\n  name = "s"\n}\n'},
        {"t2.json": '{"Resources": {"P": {"Type": "AWS::SSM::Parameter", "Properties": {}}}}'},
        {"dev.tfvars": 'instance_count = 1\n'},
        {"config/prod.json": '{"retention": 30}'},
        {"cdk.context.json": '{"env": "prod"}'},
        {"appconfig.tf": 'resource "aws_appconfig_application" "a" {\n  name = "a"\n}\n'},
    ],
    ids=["tf-ssm", "cdk-ssm", "tf-secret", "cfn-ssm", "tfvars", "config-dir", "cdk-context",
         "appconfig"],
)
def test_config_store_passes(tmp_path: Path, extra: dict) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": _TF_FN, **extra}), "REPO-114")


def test_no_compute_does_not_fire_config(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}),
                      "REPO-114")


# REPO-115 quality gate

_WORKFLOW = "name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: {cmd}\n"


def test_ci_without_a_gate_fails(tmp_path: Path) -> None:
    files = {".github/workflows/ci.yml": _WORKFLOW.format(cmd="npm run build"), "main.tf": _TF_FN}
    # The workflow must sit at the repo root, not under prod/.
    _write(tmp_path / ".github/workflows/ci.yml", files.pop(".github/workflows/ci.yml"))
    (hit,) = _found(_scan(tmp_path, files), "REPO-115")
    assert hit.question == "OPS 5"
    assert hit.severity == "Medium"
    assert "ci.yml" in hit.evidence and hit.evidence.endswith("found none")


def test_no_ci_at_all_fails(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, {"main.tf": _TF_FN}), "REPO-115")
    assert "no CI config or pipeline" in hit.evidence


@pytest.mark.parametrize(
    "cmd",
    ["npx eslint .", "ruff check .", "mypy src", "npx tsc --noEmit", "golangci-lint run",
     "pytest --cov=src --cov-fail-under=80", "tflint", "cfn-lint template.yaml",
     "npm run lint"],
    ids=["eslint", "ruff", "mypy", "tsc", "golangci", "coverage", "tflint", "cfn-lint",
         "npm-lint"],
)
def test_quality_gate_in_ci_passes(tmp_path: Path, cmd: str) -> None:
    _write(tmp_path / ".github/workflows/ci.yml", _WORKFLOW.format(cmd=cmd))
    assert not QualityGateMissing().run(tmp_path)


def test_gate_in_a_package_script_the_ci_runs_passes(tmp_path: Path) -> None:
    _write(tmp_path / ".github/workflows/ci.yml", _WORKFLOW.format(cmd="npm run verify"))
    _write(tmp_path / "package.json", '{"scripts": {"verify": "eslint . && jest"}}')
    assert not QualityGateMissing().run(tmp_path)


def test_gate_in_a_codebuild_buildspec_passes(tmp_path: Path) -> None:
    _write(tmp_path / "buildspec.yml",
           "version: 0.2\nphases:\n  build:\n    commands:\n      - ruff check .\n")
    assert not QualityGateMissing().run(tmp_path)


# REPO-116 small, reversible changes

@pytest.mark.parametrize("files", _COMPUTE, ids=_IDS)
def test_no_rollback_or_staged_deploy_fails(tmp_path: Path, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), "REPO-116")
    assert hit.question == "OPS 5"
    assert hit.evidence.endswith("found none")


@pytest.mark.parametrize(
    "extra",
    [
        {"cd.tf": 'resource "aws_codedeploy_deployment_group" "g" {\n  app_name = "a"\n}\n'},
        {"lib/alias.ts": "new lambda.Alias(this, 'A', { version, additionalVersions: "
                         "[{ version: v2, weight: 0.1 }] }); // canary\n"},
        {"sam.json": '{"DeploymentPreference": {"Type": "Canary10Percent5Minutes"}}'},
        {"ecs.tf": 'resource "aws_ecs_service" "s" {\n  deployment_circuit_breaker {\n'
                   '    enable   = true\n    rollback = true\n  }\n}\n'},
        {"lib/bg.ts": "// blue/green deploy through the ALB\n"},
    ],
    ids=["codedeploy", "alias-canary", "sam-canary", "ecs-circuit-breaker", "blue-green"],
)
def test_staged_or_reversible_deploy_passes(tmp_path: Path, extra: dict) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": _TF_FN, **extra}), "REPO-116")


def test_synthetics_canary_is_not_a_canary_deploy(tmp_path: Path) -> None:
    files = {"main.tf": _TF_FN, "lib/canary.ts": "new synthetics.Canary(this, 'Probe', { test });\n"}
    assert _found(_scan(tmp_path, files), "REPO-116")


def test_config_directory_without_an_environment_does_not_pass(tmp_path: Path) -> None:
    files = {"main.tf": _TF_FN, "config/index.ts": "export const x = 1;\n"}
    assert _found(_scan(tmp_path, files), "REPO-114")


def test_no_compute_does_not_fire_small_changes(tmp_path: Path) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}),
                      "REPO-116")


def test_rules_ignore_tests_dir(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "fn.tf", _TF_FN)
    assert not ConfigurationStoreMissing().run(tmp_path)
    assert not SmallReversibleChangesMissing().run(tmp_path)
