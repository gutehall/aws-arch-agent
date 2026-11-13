"""OPS 6: a test gates each deploy (REPO-021), and deployments of the workload's compute roll
back on their own (REPO-022)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    AutomatedRollbackMissing,
    DeployTestGateMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

RULES = ("REPO-021", "REPO-022")
OPS6 = ("OPS06-BP01", "OPS06-BP02", "OPS06-BP03", "OPS06-BP04")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources},
                      indent=2)


_CF_FUNCTION = {"Type": "AWS::Lambda::Function", "Properties": {
    "Runtime": "python3.12", "Handler": "app.handler", "Role": "arn:aws:iam::1:role/r",
    "Code": {"ZipFile": "def handler(e, c): pass"}}}


def _cf_pipeline(*stages: tuple[str, str]) -> dict:
    return {"Pipeline": {"Type": "AWS::CodePipeline::Pipeline", "Properties": {
        "RoleArn": "arn:aws:iam::1:role/p", "PipelineType": "V2",
        "Stages": [
            {"Name": name, "Actions": [{"Name": name, "ActionTypeId": {
                "Category": category, "Owner": "AWS", "Provider": "CodeBuild",
                "Version": "1"}}]}
            for name, category in stages
        ]}}}


# Each source: the compute, and a build that deploys it. The gate is a test run before the
# deploy; the rollback control is in the IaC.
_CF_BUILDSPEC = (
    "version: 0.2\nphases:\n  build:\n    commands:\n{test}"
    "      - aws cloudformation deploy --template-file t.json --stack-name app\n"
)
_TF_WORKFLOW = (
    "name: deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n{test}"
    "      - run: terraform apply -auto-approve\n"
)
_TF_FUNCTION = (
    'resource "aws_lambda_function" "fn" {\n  function_name = "shop"\n'
    '  runtime = "python3.12"\n  handler = "app.handler"\n  role = aws_iam_role.fn.arn\n}\n'
)
_CDK_STACK = (
    "const fn = new lambda.Function(this, 'Fn', { runtime, handler: 'app.handler', code });\n"
    "const pipeline = new pipelines.CodePipeline(this, 'Pipeline', {\n"
    "  synth: new pipelines.ShellStep('Synth', { input, commands: [\n"
    "    'npm ci',\n{test}    'npx cdk synth',\n  ] }),\n});\n"
    "pipeline.addStage(new AppStage(this, 'Prod'));\n"
)

_CF_ROLLBACK = {
    "circuit breaker": {"Svc": {"Type": "AWS::ECS::Service", "Properties": {
        "Cluster": "c", "TaskDefinition": "t", "DeploymentConfiguration": {
            "DeploymentCircuitBreaker": {"Enable": True, "Rollback": True}}}}},
    "deployment alarms": {"Svc": {"Type": "AWS::ECS::Service", "Properties": {
        "Cluster": "c", "TaskDefinition": "t", "DeploymentConfiguration": {
            "Alarms": {"AlarmNames": ["errors"], "Enable": True, "Rollback": True}}}}},
    "codedeploy": {"Group": {"Type": "AWS::CodeDeploy::DeploymentGroup", "Properties": {
        "ApplicationName": "app", "ServiceRoleArn": "arn:aws:iam::1:role/cd",
        "AutoRollbackConfiguration": {"Enabled": True,
                                      "Events": ["DEPLOYMENT_FAILURE"]}}}},
    "sam": {"Api": {"Type": "AWS::Serverless::Function", "Properties": {
        "Runtime": "python3.12", "Handler": "app.handler", "AutoPublishAlias": "live",
        "DeploymentPreference": {"Type": "Canary10Percent5Minutes"}}}},
    "pipeline rollback": {"Pipeline": {"Type": "AWS::CodePipeline::Pipeline", "Properties": {
        "RoleArn": "arn:aws:iam::1:role/p", "PipelineType": "V2", "Stages": [
            {"Name": "Prod", "OnFailure": {"Result": "ROLLBACK"}, "Actions": []}]}}},
    "rolling update": {"Asg": {
        "Type": "AWS::AutoScaling::AutoScalingGroup",
        "UpdatePolicy": {"AutoScalingRollingUpdate": {
            "MinInstancesInService": 1, "WaitOnResourceSignals": True,
            "PauseTime": "PT10M"}},
        "Properties": {"MinSize": "1", "MaxSize": "2"}}},
}
_TF_ROLLBACK = {
    "circuit breaker": (
        'resource "aws_ecs_service" "svc" {\n  name = "svc"\n'
        '  deployment_circuit_breaker {\n    enable   = true\n    rollback = true\n  }\n}\n'),
    "deployment alarms": (
        'resource "aws_ecs_service" "svc" {\n  name = "svc"\n'
        '  alarms {\n    alarm_names = ["errors"]\n    enable = true\n'
        '    rollback = true\n  }\n}\n'),
    "codedeploy": (
        'resource "aws_codedeploy_deployment_group" "g" {\n  app_name = "app"\n'
        '  auto_rollback_configuration {\n    enabled = true\n'
        '    events  = ["DEPLOYMENT_FAILURE"]\n  }\n}\n'),
    "pipeline rollback": (
        'resource "aws_codepipeline" "p" {\n  name = "p"\n  pipeline_type = "V2"\n'
        '  stage {\n    name = "Prod"\n    on_failure {\n      result = "ROLLBACK"\n'
        '    }\n  }\n}\n'),
    "instance refresh": (
        'resource "aws_autoscaling_group" "asg" {\n  instance_refresh {\n'
        '    strategy = "Rolling"\n    preferences {\n      auto_rollback = true\n'
        '    }\n  }\n}\n'),
}
_CDK_ROLLBACK = {
    "circuit breaker": (
        "new ecs.FargateService(this, 'Svc', { cluster, taskDefinition,\n"
        "  circuitBreaker: { enable: true, rollback: true } });\n"),
    "deployment alarms": (
        "new ecs.FargateService(this, 'Svc', { cluster, taskDefinition,\n"
        "  deploymentAlarms: { alarmNames: [errors.alarmName] } });\n"),
    "codedeploy": (
        "new codedeploy.LambdaDeploymentGroup(this, 'Deploy', { alias,\n"
        "  deploymentConfig: codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES });\n"),
    "pipeline rollback": (
        "new codepipeline.Pipeline(this, 'Release', { pipelineType: "
        "codepipeline.PipelineType.V2,\n  stages: [{ stageName: 'Prod', actions,\n"
        "    onFailure: { result: codepipeline.Result.ROLLBACK } }] });\n"),
}


def _cf_iac(test: str = "", rollback: dict | None = None) -> dict[str, str]:
    return {
        "prod/t.json": _cfn({"Fn": _CF_FUNCTION, **(rollback or {})}),
        "buildspec.yml": _CF_BUILDSPEC.format(test=test and f"      - {test}\n"),
    }


def _tf_iac(test: str = "", rollback: str = "") -> dict[str, str]:
    return {
        "prod/main.tf": _TF_FUNCTION + rollback,
        ".github/workflows/deploy.yml": _TF_WORKFLOW.format(
            test=test and f"      - run: {test}\n"),
    }


def _cdk_iac(test: str = "", rollback: str = "") -> dict[str, str]:
    return {
        "prod/lib/stack.ts": _CDK_STACK.replace("{test}", test and f"    '{test}',\n")
        + rollback,
        "prod/package.json": "{}",
    }


_BUILDERS = {"cdk": _cdk_iac, "cloudformation": _cf_iac, "terraform": _tf_iac}
_TESTS = {"cdk": "npm test", "cloudformation": "pytest -q", "terraform": "go test ./..."}
_ROLLBACKS = {"cdk": _CDK_ROLLBACK, "cloudformation": _CF_ROLLBACK, "terraform": _TF_ROLLBACK}
_SOURCE_IDS = list(_BUILDERS)
_ROLLBACK_CASES = [(source, kind) for source in _SOURCE_IDS for kind in _ROLLBACKS[source]]


def _put(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        _write(root / rel, text)


def _scan(root: Path, files: dict[str, str]) -> tuple:
    # IaC under prod/: the pytest directory name says "test", which reads as a dev stack.
    _put(root, files)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return ctx, findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def _gate(root: Path, files: dict[str, str]) -> list:
    _put(root, files)
    return DeployTestGateMissing().run(root)


def test_rules_answer_ops6() -> None:
    assert RULE_BEST_PRACTICES["REPO-021"] == ("OPS06-BP02",)
    assert RULE_BEST_PRACTICES["REPO-022"] == ("OPS06-BP04",)
    assert set(OPS6).isdisjoint(NOT_CHECKED)
    covered = {bp for bps in RULE_BEST_PRACTICES.values() for bp in bps}
    assert set(OPS6) <= covered


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_no_controls_fail_ops6(tmp_path: Path, source: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source]())
    assert ctx.source == source
    (gate,) = _found(findings, "REPO-021")
    (rollback,) = _found(findings, "REPO-022")
    for hit in (gate, rollback):
        assert hit.question == "OPS 6"
        assert hit.category == "Operational Excellence"
        assert hit.severity == "Medium"
        assert hit.evidence.endswith("found none")
    assert rollback.evidence.startswith("Runs Lambda (prod/")
    assert rollback.file is None
    assert gate.file in ("prod/lib/stack.ts", "buildspec.yml", ".github/workflows/deploy.yml")
    assert gate.line
    assert f"Deploys from {gate.file} (line {gate.line})" in gate.evidence
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    assert not answer["OPS 6"].met


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_test_gate_passes(tmp_path: Path, source: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source](test=_TESTS[source]))
    assert ctx.source == source
    assert not _found(findings, "REPO-021")
    assert _found(findings, "REPO-022")


@pytest.mark.parametrize(("source", "kind"), _ROLLBACK_CASES)
def test_rollback_control_passes(tmp_path: Path, source: str, kind: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source](rollback=_ROLLBACKS[source][kind]))
    assert ctx.source == source
    assert not _found(findings, "REPO-022")
    assert _found(findings, "REPO-021")


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_all_controls_answer_ops6_met(tmp_path: Path, source: str) -> None:
    rollback = next(iter(_ROLLBACKS[source].values()))
    if source == "cdk":
        # REL-023 (OPS06-BP03) asks an ECS service for blue/green; use the Lambda control.
        rollback = _CDK_ROLLBACK["codedeploy"]
    ctx, findings = _scan(tmp_path, _BUILDERS[source](test=_TESTS[source], rollback=rollback))
    assert not [f for f in findings if f.id in RULES]
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    ops6 = answer["OPS 6"]
    assert set(OPS6).isdisjoint(ops6.not_checked)
    assert not ops6.findings
    assert ops6.met


# REPO-021: what counts as a gate.

_WORKFLOW = "jobs:\n  ci:\n    steps:\n{steps}"


def _steps(*lines: str) -> str:
    return _WORKFLOW.format(steps="".join(f"      - {line}\n" for line in lines))


@pytest.mark.parametrize("steps", [
    ("run: npm test || true", "run: npx cdk deploy --all"),
    ("run: pytest || exit 0", "run: sam deploy"),
    ("name: tests\n        continue-on-error: true\n        run: npm test",
     "run: npx cdk deploy"),
    ("run: npx cdk deploy", "run: npm test"),  # the test runs after the deploy
    ("run: pip install pytest tox", "run: terraform apply -auto-approve"),
])
def test_test_that_cannot_gate_fires(tmp_path: Path, steps: tuple[str, ...]) -> None:
    (hit,) = _gate(tmp_path, {".github/workflows/ci.yml": _steps(*steps)})
    assert hit.file == ".github/workflows/ci.yml"


def test_gitlab_allow_failure_is_not_a_gate(tmp_path: Path) -> None:
    ci = (
        "test:\n  stage: test\n  allow_failure: true\n  script:\n    - pytest\n"
        "deploy:\n  stage: deploy\n  script:\n    - sam deploy --no-confirm-changeset\n"
    )
    assert _gate(tmp_path, {".gitlab-ci.yml": ci})
    assert not _gate(tmp_path / "strict", {".gitlab-ci.yml": ci.replace(
        "  allow_failure: true\n", "")})


@pytest.mark.parametrize(("script", "gated"), [
    ("npm test && cdk deploy --all", True),
    ("jest --ci && cdk deploy --all", True),
    ("cdk deploy --all", False),
    ("npm test || true && cdk deploy --all", False),
    ("npm run unit && cdk deploy", True),  # two levels deep
])
def test_package_json_script_indirection(tmp_path: Path, script: str, gated: bool) -> None:
    package = {"scripts": {"deploy": script, "unit": "vitest run"}}
    files = {
        "package.json": json.dumps(package),
        ".github/workflows/ci.yml": _steps("run: npm ci", "run: npm run deploy"),
    }
    assert bool(_gate(tmp_path, files)) is not gated


def test_swallowed_script_is_not_a_gate(tmp_path: Path) -> None:
    files = {
        "package.json": json.dumps({"scripts": {"check": "npm test"}}),
        ".github/workflows/ci.yml": _steps("run: npm run check || true", "run: sam deploy"),
    }
    assert _gate(tmp_path, files)


def test_staging_then_test_then_prod_passes(tmp_path: Path) -> None:
    staged = _steps(
        "run: npx cdk deploy Staging", "run: npm run test:integration",
        "run: npx cdk deploy Prod",
    )
    assert not _gate(tmp_path, {".github/workflows/release.yml": staged})
    # Tests after the last deploy gate nothing.
    late = _steps(
        "run: npx cdk deploy Staging", "run: npx cdk deploy Prod",
        "run: npm run test:integration",
    )
    (hit,) = _gate(tmp_path / "late", {".github/workflows/release.yml": late})
    assert hit.line == 4


@pytest.mark.parametrize(("stages", "gated"), [
    ((("Source", "Source"), ("Test", "Test"), ("Deploy", "Deploy")), True),
    ((("Source", "Source"), ("Deploy", "Deploy"), ("Test", "Test")), False),
    ((("Source", "Source"), ("Build", "Build"), ("Deploy", "Deploy")), False),
])
def test_codepipeline_test_action(tmp_path: Path, stages: tuple, gated: bool) -> None:
    files = {"prod/pipeline.json": _cfn(_cf_pipeline(*stages))}
    assert bool(_gate(tmp_path, files)) is not gated


def test_terraform_codepipeline_test_action(tmp_path: Path) -> None:
    def pipeline(*categories: str) -> str:
        actions = "".join(
            f'  stage {{\n    name = "{c}"\n    action {{\n      category = "{c}"\n'
            '      owner = "AWS"\n    }\n  }\n' for c in categories
        )
        return f'resource "aws_codepipeline" "p" {{\n  name = "p"\n{actions}}}\n'
    assert not _gate(tmp_path, {"prod/main.tf": pipeline("Source", "Test", "Deploy")})
    assert _gate(tmp_path / "b", {"prod/main.tf": pipeline("Source", "Build", "Deploy")})


def test_cdk_pipelines_pre_step_gates_and_post_step_does_not(tmp_path: Path) -> None:
    base = (
        "const pipeline = new pipelines.CodePipeline(this, 'Pipeline', { synth });\n"
        "pipeline.addStage(new AppStage(this, 'Prod'), {\n"
        "  {key}: [new pipelines.ShellStep('Test', { commands: ['npm test'] })],\n});\n"
    )
    assert not _gate(tmp_path, {"prod/lib/pipeline.ts": base.replace("{key}", "pre")})
    assert _gate(tmp_path / "post", {"prod/lib/pipeline.ts": base.replace("{key}", "post")})


def test_codepipeline_stage_literal_is_not_a_deploy(tmp_path: Path) -> None:
    text = (
        "const pipeline = new codepipeline.Pipeline(this, 'Release');\n"
        "pipeline.addStage({ stageName: 'Source', actions: [source] });\n"
    )
    assert not _gate(tmp_path, {"prod/lib/pipeline.ts": text})
    deploy = text + (
        "pipeline.addStage({ stageName: 'Deploy', actions: [\n"
        "  new codepipeline_actions.EcsDeployAction({ actionName: 'Ecs', service, input })] });\n"
    )
    assert _gate(tmp_path / "deploy", {"prod/lib/pipeline.ts": deploy})


def test_no_deploy_no_finding(tmp_path: Path) -> None:
    assert not _gate(tmp_path, {".github/workflows/ci.yml": _steps("run: npm ci",
                                                                    "run: npx cdk synth")})
    assert not _gate(tmp_path / "empty", {"prod/main.tf": _TF_FUNCTION})


def test_each_ungated_build_is_named(tmp_path: Path) -> None:
    files = {
        ".github/workflows/a.yml": _steps("run: npm test", "run: npx cdk deploy"),
        ".github/workflows/b.yml": _steps("run: terraform apply"),
        ".gitlab-ci.yml": "deploy:\n  script:\n    - sam deploy\n",
    }
    (hit,) = _gate(tmp_path, files)
    assert hit.file == ".github/workflows/b.yml"
    assert ".github/workflows/b.yml (line 4), .gitlab-ci.yml (line 3)" in hit.evidence
    assert "a.yml" not in hit.evidence


# REPO-022: what counts as a rollback.

def _rollback(root: Path, files: dict[str, str]) -> list:
    _put(root, files)
    return AutomatedRollbackMissing().run(root)


@pytest.mark.parametrize("text", [
    "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: web\n",
    "apiVersion: flagger.app/v1beta1\nkind: Canary\nmetadata:\n  name: web\n",
])
def test_kubernetes_progressive_delivery_passes(tmp_path: Path, text: str) -> None:
    assert not _rollback(tmp_path, {"prod/main.tf": _TF_FUNCTION, "k8s/web.yaml": text})


def test_rollback_configuration_in_a_build_passes(tmp_path: Path) -> None:
    files = _cf_iac()
    files["buildspec.yml"] += (
        "      - aws cloudformation update-stack --stack-name app "
        "--rollback-configuration file://rollback.json\n")
    assert not _rollback(tmp_path, files)


@pytest.mark.parametrize("text", [
    # Rollback off.
    "new ecs.FargateService(this, 'Svc', { circuitBreaker: { enable: true, rollback: false } });\n",
    "new codedeploy.LambdaDeploymentGroup(this, 'Deploy', { alias,\n"
    "  autoRollback: { failedDeployment: false } });\n",
    # Not a rollback: termination protection, an Argo Rollout kind with no Argo apiVersion.
    "new AppStack(app, 'Prod', { terminationProtection: true });\n",
])
def test_not_a_rollback(tmp_path: Path, text: str) -> None:
    files = {"prod/lib/stack.ts": "new lambda.Function(this, 'Fn', { runtime, code });\n" + text}
    assert _rollback(tmp_path, files)


def test_no_compute_no_rollback_finding(tmp_path: Path) -> None:
    assert not _rollback(tmp_path, {"prod/lib/stack.ts": "new sqs.Queue(this, 'Jobs');\n"})


def test_rollback_in_tests_does_not_count(tmp_path: Path) -> None:
    files = {
        "prod/main.tf": _TF_FUNCTION,
        "tests/fixture.tf": _TF_ROLLBACK["circuit breaker"],
    }
    assert _rollback(tmp_path, files)


def test_report_quoting_the_findings_does_not_pass(tmp_path: Path) -> None:
    # A JSON report saved in the repo quotes both findings and their recommendations, and it
    # names a CodeBuild project, so the gate check reads it as a build config.
    files = _cf_iac()
    _put(tmp_path, files)
    rules = (DeployTestGateMissing(), AutomatedRollbackMissing())
    hits = [hit for rule in rules for hit in rule.run(tmp_path)]
    assert len(hits) == 2
    report = {"note": "AWS::CodeBuild::Project", "findings": [
        {"evidence": hit.evidence, "recommendation": hit.recommendation} for hit in hits
    ]}
    _write(tmp_path / "report.json", json.dumps(report, indent=2))
    for rule in rules:
        assert rule.run(tmp_path)
