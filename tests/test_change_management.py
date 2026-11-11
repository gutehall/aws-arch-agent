"""REL 8: live instances are replaced, not changed in place (REPO-023); a functional test runs
against the deployed change (REPO-024); the infrastructure is deployed by automation
(REPO-025); and the deploy runs a resiliency test (REPO-026)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    AutomatedDeployMissing,
    FunctionalTestMissing,
    InPlaceChange,
    ResiliencyTestMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

RULES = ("REPO-023", "REPO-024", "REPO-025", "REPO-026")
REL8 = ("REL08-BP01", "REL08-BP02", "REL08-BP03", "REL08-BP04", "REL08-BP05")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _put(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        _write(root / rel, text)


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources},
                      indent=2)


_CF_FUNCTION = {"Type": "AWS::Lambda::Function", "Properties": {
    "Runtime": "python3.12", "Handler": "app.handler", "Role": "arn:aws:iam::1:role/r",
    "Code": {"ZipFile": "def handler(e, c): pass"}}}
_TF_FUNCTION = (
    'resource "aws_lambda_function" "fn" {\n  function_name = "shop"\n'
    '  runtime = "python3.12"\n  handler = "app.handler"\n  role = aws_iam_role.fn.arn\n}\n'
)
_CDK_FUNCTION = (
    "const fn = new lambda.Function(this, 'Fn', { runtime, handler: 'app.handler', code });\n"
)

_SMOKE = "curl -fsS https://staging.example.com/health"
_CHAOS = "aws fis start-experiment --experiment-template-id EXT1"

# Each source: the IaC, and (with deploy) a build that deploys it. after: the commands run
# after the deploy.


def _cf_iac(deploy: bool = True, after: tuple[str, ...] = (), extra: dict | None = None
            ) -> dict[str, str]:
    files = {"prod/t.json": _cfn({"Fn": _CF_FUNCTION, **(extra or {})})}
    if deploy:
        files["buildspec.yml"] = (
            "version: 0.2\nphases:\n  build:\n    commands:\n"
            "      - aws cloudformation deploy --template-file prod/t.json --stack-name app\n"
            + "".join(f"      - {line}\n" for line in after)
        )
    return files


def _tf_iac(deploy: bool = True, after: tuple[str, ...] = (), extra: str = ""
            ) -> dict[str, str]:
    files = {"prod/main.tf": _TF_FUNCTION + extra}
    if deploy:
        files[".github/workflows/deploy.yml"] = (
            "name: deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n"
            "      - run: terraform apply -auto-approve\n"
            + "".join(f"      - run: {line}\n" for line in after)
        )
    return files


def _cdk_iac(deploy: bool = True, after: tuple[str, ...] = (), extra: str = ""
             ) -> dict[str, str]:
    text = _CDK_FUNCTION + extra
    if deploy:
        post = ", ".join(f"'{line}'" for line in after)
        text += (
            "const pipeline = new pipelines.CodePipeline(this, 'Pipeline', {\n"
            "  synth: new pipelines.ShellStep('Synth', { input, commands: ['npm ci', "
            "'npx cdk synth'] }),\n});\n"
            "pipeline.addStage(new AppStage(this, 'Prod')"
            + (f", {{\n  post: [new pipelines.ShellStep('Check', {{ commands: [{post}] }})],\n}}"
               if after else "")
            + ");\n"
        )
    return {"prod/lib/stack.ts": text, "prod/package.json": "{}"}


_BUILDERS = {"cdk": _cdk_iac, "cloudformation": _cf_iac, "terraform": _tf_iac}
_SOURCE_IDS = list(_BUILDERS)
_IN_PLACE = {
    "cdk": "new codedeploy.ServerDeploymentGroup(this, 'Fleet', { autoScalingGroups: [asg] });\n",
    "cloudformation": {"Group": {"Type": "AWS::CodeDeploy::DeploymentGroup", "Properties": {
        "ApplicationName": "app", "ServiceRoleArn": "arn:aws:iam::1:role/cd",
        "DeploymentStyle": {"DeploymentType": "IN_PLACE",
                            "DeploymentOption": "WITHOUT_TRAFFIC_CONTROL"}}}},
    "terraform": (
        'resource "aws_codedeploy_deployment_group" "g" {\n  app_name = "app"\n'
        '  deployment_style {\n    deployment_type = "IN_PLACE"\n  }\n}\n'),
}


def _scan(root: Path, files: dict[str, str]) -> tuple:
    # IaC under prod/: the pytest directory name says "test", which reads as a dev stack.
    _put(root, files)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return ctx, findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def _run(rule: object, root: Path, files: dict[str, str]) -> list:
    _put(root, files)
    return rule.run(root)  # type: ignore[attr-defined]


def test_rules_answer_rel8() -> None:
    assert RULE_BEST_PRACTICES["REPO-023"] == ("REL08-BP04",)
    assert RULE_BEST_PRACTICES["REPO-024"] == ("REL08-BP02",)
    assert RULE_BEST_PRACTICES["REPO-025"] == ("REL08-BP01", "REL08-BP05")
    assert RULE_BEST_PRACTICES["REPO-026"] == ("REL08-BP03",)
    assert set(REL8).isdisjoint(NOT_CHECKED)
    covered = {bp for bps in RULE_BEST_PRACTICES.values() for bp in bps}
    assert set(REL8) <= covered


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_no_controls_fail_rel8(tmp_path: Path, source: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source](extra=_IN_PLACE[source]))
    assert ctx.source == source
    hits = [_found(findings, rule_id) for rule_id in ("REPO-023", "REPO-024", "REPO-026")]
    assert all(len(hit) == 1 for hit in hits)
    in_place, functional, resiliency = (hit[0] for hit in hits)
    assert not _found(findings, "REPO-025")
    for hit in (in_place, functional, resiliency):
        assert hit.question == "REL 8"
        assert hit.category == "Reliability"
    assert in_place.severity == "Medium"
    assert functional.severity == resiliency.severity == "Low"
    assert functional.evidence.endswith("found none")
    assert resiliency.evidence.endswith("found none")
    assert in_place.evidence.startswith("Changes running instances in place")
    assert in_place.file and in_place.file.startswith("prod/")
    assert in_place.line
    assert functional.line
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    assert not answer["REL 8"].met


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_no_automated_deploy_fails(tmp_path: Path, source: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source](deploy=False))
    assert ctx.source == source
    (hit,) = _found(findings, "REPO-025")
    assert hit.question == "REL 8"
    assert hit.category == "Reliability"
    assert hit.severity == "Medium"
    kind = {"cdk": "CDK", "cloudformation": "CloudFormation", "terraform": "Terraform"}[source]
    assert hit.evidence.startswith(f"Holds IaC ({kind}: 1 file)")
    assert hit.evidence.endswith("found none")
    # Nothing deploys, so there is no deploy to test.
    assert not [f for f in findings if f.id in ("REPO-023", "REPO-024", "REPO-026")]


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_all_controls_answer_rel8_met(tmp_path: Path, source: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source](after=(_SMOKE, _CHAOS)))
    assert ctx.source == source
    assert not [f for f in findings if f.id in RULES]
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    rel8 = answer["REL 8"]
    assert set(REL8).isdisjoint(rel8.not_checked)
    assert not rel8.not_checked
    assert not rel8.findings
    assert rel8.met


# REPO-023: what changes instances in place.

_WORKFLOW = "jobs:\n  ci:\n    steps:\n{steps}"


def _steps(*lines: str) -> str:
    return _WORKFLOW.format(steps="".join(f"      - {line}\n" for line in lines))


@pytest.mark.parametrize(("command", "what"), [
    ("run: rsync -az dist/ deploy@web1.example.com:/srv/app", "ssh, scp or rsync"),
    ("run: ssh -i key.pem ec2-user@10.0.0.5 'sudo systemctl restart app'", "ssh, scp or rsync"),
    ("uses: appleboy/ssh-action@v1", "ssh, scp or rsync"),
    ("run: ansible-playbook -i hosts site.yml", "ansible-playbook"),
    ("run: aws ssm send-command --document-name AWS-RunShellScript --targets Key=tag:app,"
     "Values=web", "SSM Run Command"),
    ("run: aws deploy create-deployment --application-name app --deployment-group-name web",
     "in-place CodeDeploy deployment"),
])
def test_build_that_changes_hosts_fires(tmp_path: Path, command: str, what: str) -> None:
    (hit,) = _run(InPlaceChange(), tmp_path, {".github/workflows/ci.yml": _steps(command)})
    assert what in hit.evidence
    assert hit.file == ".github/workflows/ci.yml"
    assert hit.line == 4


def test_package_json_script_that_changes_hosts_fires(tmp_path: Path) -> None:
    files = {
        "package.json": json.dumps({"scripts": {"ship": "ansible-playbook site.yml"}}),
        ".github/workflows/ci.yml": _steps("run: npm run ship"),
    }
    (hit,) = _run(InPlaceChange(), tmp_path, files)
    assert "ansible-playbook in package.json script ship" in hit.evidence


@pytest.mark.parametrize("command", [
    "run: ssh -T git@github.com",
    "run: pip install ansible",
    "run: ssh-keyscan github.com >> ~/.ssh/known_hosts",
    "run: aws ssm get-parameter --name /app/url",
    "run: aws deploy create-deployment --application-name app "
    "--deployment-config-name CodeDeployDefault.LambdaCanary10Percent5Minutes",
])
def test_build_that_does_not_change_hosts_is_quiet(tmp_path: Path, command: str) -> None:
    assert not _run(InPlaceChange(), tmp_path, {".github/workflows/ci.yml": _steps(command)})


def test_create_deployment_to_a_blue_green_group_is_quiet(tmp_path: Path) -> None:
    files = {
        ".github/workflows/ci.yml": _steps("run: aws deploy create-deployment --application-"
                                           "name app --deployment-group-name web"),
        "prod/main.tf": (
            'resource "aws_codedeploy_deployment_group" "g" {\n  app_name = "app"\n'
            '  deployment_style {\n    deployment_type = "BLUE_GREEN"\n  }\n}\n'),
    }
    assert not _run(InPlaceChange(), tmp_path, files)


_CF_IN_PLACE = {
    "default style": {"Group": {"Type": "AWS::CodeDeploy::DeploymentGroup", "Properties": {
        "ApplicationName": "app", "ServiceRoleArn": "arn:aws:iam::1:role/cd",
        "Ec2TagFilters": [{"Key": "app", "Value": "web", "Type": "KEY_AND_VALUE"}]}}},
    "run command association": {"Assoc": {"Type": "AWS::SSM::Association", "Properties": {
        "Name": "AWS-RunShellScript", "Targets": [{"Key": "tag:app", "Values": ["web"]}],
        "Parameters": {"commands": ["yum update -y"]}}}},
    "ansible association": {"Assoc": {"Type": "AWS::SSM::Association", "Properties": {
        "Name": "AWS-ApplyAnsiblePlaybooks"}}},
    "cfn-hup": {"Host": {"Type": "AWS::EC2::Instance", "Metadata": {
        "AWS::CloudFormation::Init": {"config": {
            "files": {"/etc/cfn/cfn-hup.conf": {"content": "[main]\nstack=app\n"}},
            "services": {"sysvinit": {"cfn-hup": {"enabled": True}}}}}},
        "Properties": {"ImageId": "ami-1", "InstanceType": "t3.micro"}}},
}
_TF_IN_PLACE = {
    "default style": (
        'resource "aws_codedeploy_deployment_group" "g" {\n  app_name = "app"\n'
        '  ec2_tag_set {\n    ec2_tag_filter {\n      key = "app"\n    }\n  }\n}\n'),
    "run command association": (
        'resource "aws_ssm_association" "patch" {\n  name = "AWS-RunPowerShellScript"\n'
        '  targets {\n    key = "tag:app"\n    values = ["web"]\n  }\n}\n'),
}
_CDK_IN_PLACE = {
    "cfn group": "new codedeploy.CfnDeploymentGroup(this, 'G', { applicationName: 'app',\n"
                 "  serviceRoleArn: role.roleArn, deploymentStyle: { deploymentType: "
                 "'IN_PLACE' } });\n",
    "run command association": "new ssm.CfnAssociation(this, 'Patch', {\n"
                               "  name: 'AWS-RunShellScript', targets });\n",
    "cfn-hup": "ec2.InitService.enable('cfn-hup', { serviceRestartHandle: handle });\n",
}
_IN_PLACE_CASES = (
    [("cloudformation", kind) for kind in _CF_IN_PLACE]
    + [("terraform", kind) for kind in _TF_IN_PLACE]
    + [("cdk", kind) for kind in _CDK_IN_PLACE]
)


@pytest.mark.parametrize(("source", "kind"), _IN_PLACE_CASES)
def test_iac_that_changes_instances_fires(tmp_path: Path, source: str, kind: str) -> None:
    extra = {"cloudformation": _CF_IN_PLACE, "terraform": _TF_IN_PLACE,
             "cdk": _CDK_IN_PLACE}[source][kind]
    (hit,) = _run(InPlaceChange(), tmp_path, _BUILDERS[source](deploy=False, extra=extra))
    assert hit.file and hit.file.startswith("prod/")
    assert hit.line


@pytest.mark.parametrize(("source", "extra"), [
    # Lambda versions, ECS task definitions, AMI launch templates and blue/green replace.
    ("cloudformation", {
        "App": {"Type": "AWS::CodeDeploy::Application", "Properties": {
            "ComputePlatform": "ECS"}},
        "Group": {"Type": "AWS::CodeDeploy::DeploymentGroup", "Properties": {
            "ApplicationName": "app", "ServiceRoleArn": "arn:aws:iam::1:role/cd",
            "DeploymentStyle": {"DeploymentType": "BLUE_GREEN",
                                "DeploymentOption": "WITH_TRAFFIC_CONTROL"}}},
        "Version": {"Type": "AWS::Lambda::Version", "Properties": {"FunctionName": "fn"}},
        "Task": {"Type": "AWS::ECS::TaskDefinition", "Properties": {"Family": "web"}},
        "Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
            "LaunchTemplateData": {"ImageId": "ami-123"}}},
        "Agent": {"Type": "AWS::SSM::Association", "Properties": {
            "Name": "AWS-UpdateSSMAgent"}},
    }),
    ("terraform", (
        'resource "aws_codedeploy_app" "a" {\n  name = "a"\n  compute_platform = "ECS"\n}\n'
        'resource "aws_codedeploy_deployment_group" "g" {\n  app_name = "a"\n'
        '  deployment_style {\n    deployment_type = "BLUE_GREEN"\n'
        '    deployment_option = "WITH_TRAFFIC_CONTROL"\n  }\n}\n'
        'resource "aws_launch_template" "lt" {\n  image_id = "ami-123"\n}\n'
        'resource "aws_ecs_task_definition" "t" {\n  family = "web"\n}\n')),
    ("cdk", (
        "const alias = new lambda.Alias(this, 'Live', { aliasName: 'live', "
        "version: fn.currentVersion });\n"
        "new codedeploy.LambdaDeploymentGroup(this, 'Deploy', { alias });\n"
        "new ec2.LaunchTemplate(this, 'Lt', { machineImage });\n")),
])
def test_replacement_is_quiet(tmp_path: Path, source: str, extra: object) -> None:
    assert not _run(InPlaceChange(), tmp_path, _BUILDERS[source](extra=extra))


def test_each_mutation_is_named(tmp_path: Path) -> None:
    files = _cf_iac(extra=_CF_IN_PLACE["run command association"])
    files["buildspec.yml"] += "      - ansible-playbook site.yml\n"
    (hit,) = _run(InPlaceChange(), tmp_path, files)
    assert "ansible-playbook in buildspec.yml (line 6)" in hit.evidence
    assert "SSM association Assoc running AWS-RunShellScript in prod/t.json" in hit.evidence
    assert hit.file == "buildspec.yml"
    assert hit.line == 6


def test_in_place_in_tests_does_not_count(tmp_path: Path) -> None:
    files = {"prod/main.tf": _TF_FUNCTION, "tests/fixture.tf": _TF_IN_PLACE["default style"]}
    assert not _run(InPlaceChange(), tmp_path, files)


# REPO-024: what counts as a functional test of the deployed change.

@pytest.mark.parametrize("command", [
    "curl --fail https://staging.example.com/health",
    "curl -sSf ${{ env.URL }}/health",
    "npx playwright test",
    "npx cypress run",
    "newman run api.postman_collection.json",
    "npm run e2e",
    "npm run test:integration",
    "pytest tests/integ",
    "npx integ-runner",
])
def test_functional_test_after_deploy_passes(tmp_path: Path, command: str) -> None:
    files = {".github/workflows/ci.yml": _steps("run: npx cdk deploy --all", f"run: {command}")}
    assert not _run(FunctionalTestMissing(), tmp_path, files)


@pytest.mark.parametrize("steps", [
    ("run: npx cdk deploy --all", "run: npx playwright test || true"),
    ("run: npx cdk deploy --all", "name: smoke\n        continue-on-error: true\n"
     "        run: npm run smoke"),
    ("run: npx cdk deploy --all", "run: curl https://staging.example.com/health"),
    ("run: npm test", "run: npx cdk deploy --all"),  # before the deploy, not after it
    ("run: npx cdk deploy --all", "run: pip install playwright"),
])
def test_test_that_cannot_check_the_deploy_fires(tmp_path: Path, steps: tuple) -> None:
    (hit,) = _run(FunctionalTestMissing(), tmp_path, {".github/workflows/ci.yml": _steps(*steps)})
    assert hit.file == ".github/workflows/ci.yml"


def test_staging_then_smoke_then_prod_passes(tmp_path: Path) -> None:
    staged = _steps("run: npx cdk deploy Staging", f"run: {_SMOKE}", "run: npx cdk deploy Prod")
    assert not _run(FunctionalTestMissing(), tmp_path, {".github/workflows/release.yml": staged})
    # With two deploys, a smoke test after production promotes nothing.
    late = _steps("run: npx cdk deploy Staging", "run: npx cdk deploy Prod", f"run: {_SMOKE}")
    (hit,) = _run(FunctionalTestMissing(), tmp_path / "late",
                  {".github/workflows/release.yml": late})
    assert hit.line == 4


def test_package_json_smoke_script_counts(tmp_path: Path) -> None:
    files = {
        "package.json": json.dumps({"scripts": {"release": "cdk deploy && npm run check",
                                                "check": "newman run api.json"}}),
        ".github/workflows/ci.yml": _steps("run: npm run release"),
    }
    assert not _run(FunctionalTestMissing(), tmp_path, files)
    files["package.json"] = json.dumps({"scripts": {"release": "npm run check && cdk deploy",
                                                    "check": "newman run api.json"}})
    assert _run(FunctionalTestMissing(), tmp_path / "before", files)


@pytest.mark.parametrize(("stages", "tested"), [
    (("Source", "Deploy", "Test"), True),
    (("Source", "Test", "Deploy"), False),
])
def test_codepipeline_test_after_deploy(tmp_path: Path, stages: tuple, tested: bool) -> None:
    pipeline = {"Pipeline": {"Type": "AWS::CodePipeline::Pipeline", "Properties": {
        "RoleArn": "arn:aws:iam::1:role/p", "Stages": [
            {"Name": name, "Actions": [{"Name": name, "ActionTypeId": {
                "Category": name, "Owner": "AWS", "Provider": "CodeBuild", "Version": "1"}}]}
            for name in stages]}}}
    hits = _run(FunctionalTestMissing(), tmp_path, {"prod/pipeline.json": _cfn(pipeline)})
    assert bool(hits) is not tested


def test_cdk_post_step_counts_and_pre_step_does_not(tmp_path: Path) -> None:
    base = (
        "const pipeline = new pipelines.CodePipeline(this, 'Pipeline', { synth });\n"
        "pipeline.addStage(new AppStage(this, 'Prod'), {\n"
        "  {key}: [new pipelines.ShellStep('Check', { commands: ['./check.sh'] })],\n});\n"
    )
    assert not _run(FunctionalTestMissing(), tmp_path,
                    {"prod/lib/pipeline.ts": base.replace("{key}", "post")})
    assert _run(FunctionalTestMissing(), tmp_path / "pre",
                {"prod/lib/pipeline.ts": base.replace("{key}", "pre")})


def test_no_deploy_no_functional_finding(tmp_path: Path) -> None:
    files = {".github/workflows/ci.yml": _steps("run: npm ci", "run: npx cdk synth")}
    assert not _run(FunctionalTestMissing(), tmp_path, files)


# REPO-025: automated deploys.

def test_iac_without_any_build_names_none_found(tmp_path: Path) -> None:
    (hit,) = _run(AutomatedDeployMissing(), tmp_path, _tf_iac(deploy=False))
    assert "searched the repo for a build config that deploys, and the IaC" in hit.evidence


def test_build_that_does_not_deploy_fires(tmp_path: Path) -> None:
    files = _tf_iac(deploy=False)
    files[".github/workflows/ci.yml"] = _steps("run: terraform plan", "run: npm test")
    (hit,) = _run(AutomatedDeployMissing(), tmp_path, files)
    assert "build configs (.github/workflows/ci.yml)" in hit.evidence


def test_deploy_through_a_package_script_passes(tmp_path: Path) -> None:
    files = _cdk_iac(deploy=False)
    files["package.json"] = json.dumps({"scripts": {"ship": "cdk deploy --all"}})
    files[".github/workflows/ci.yml"] = _steps("run: npm run ship")
    assert not _run(AutomatedDeployMissing(), tmp_path, files)


def test_codepipeline_in_the_iac_passes(tmp_path: Path) -> None:
    files = _tf_iac(deploy=False, extra='resource "aws_codepipeline" "p" {\n  name = "p"\n}\n')
    assert not _run(AutomatedDeployMissing(), tmp_path, files)


def test_no_iac_no_automation_finding(tmp_path: Path) -> None:
    files = {"package.json": json.dumps({"name": "app"}), "src/app.js": "console.log(1);\n"}
    assert not _run(AutomatedDeployMissing(), tmp_path, files)


# REPO-026: resiliency tests in the deploy.

@pytest.mark.parametrize("command", [
    _CHAOS, "chaos run experiment.json", "litmusctl run chaos-experiment",
])
def test_chaos_after_deploy_passes(tmp_path: Path, command: str) -> None:
    files = {".github/workflows/ci.yml": _steps("run: sam deploy", f"run: {command}")}
    assert not _run(ResiliencyTestMissing(), tmp_path, files)


def test_fis_template_alone_does_not_count(tmp_path: Path) -> None:
    files = {
        ".github/workflows/ci.yml": _steps("run: sam deploy"),
        "prod/fis.tf": 'resource "aws_fis_experiment_template" "az" {\n  description = "az"\n}\n',
    }
    (hit,) = _run(ResiliencyTestMissing(), tmp_path, files)
    assert hit.file == ".github/workflows/ci.yml"


def test_chaos_in_a_build_that_does_not_deploy_does_not_count(tmp_path: Path) -> None:
    files = {
        ".github/workflows/ci.yml": _steps("run: sam deploy"),
        ".github/workflows/chaos.yml": _steps(f"run: {_CHAOS}"),
    }
    assert _run(ResiliencyTestMissing(), tmp_path, files)


def test_step_functions_fis_task_passes(tmp_path: Path) -> None:
    files = {
        ".github/workflows/ci.yml": _steps("run: sam deploy"),
        "prod/lib/release.ts": (
            "new tasks.CallAwsService(this, 'Chaos', { service: 'fis', "
            "action: 'startExperiment', iamResources: ['*'] });\n"),
    }
    assert not _run(ResiliencyTestMissing(), tmp_path, files)


def test_no_deploy_no_resiliency_finding(tmp_path: Path) -> None:
    files = {".github/workflows/ci.yml": _steps("run: npm ci", "run: npm test")}
    assert not _run(ResiliencyTestMissing(), tmp_path, files)


# A saved report quotes the findings; that must not pass a check or fire one.

def _report(root: Path, hits: list) -> None:
    # It names a CodeBuild project, so the builds read it as a build config.
    report = {"note": "AWS::CodeBuild::Project", "findings": [
        {"evidence": hit.evidence, "recommendation": hit.recommendation} for hit in hits
    ]}
    _write(root / "report.json", json.dumps(report, indent=2))


def test_report_quoting_the_findings_does_not_pass(tmp_path: Path) -> None:
    deployed = tmp_path / "deployed"
    _put(deployed, _cf_iac(extra=_CF_IN_PLACE["run command association"]))
    bare = tmp_path / "bare"
    _put(bare, _cf_iac(deploy=False))
    cases = [
        (deployed, (InPlaceChange(), FunctionalTestMissing(), ResiliencyTestMissing())),
        (bare, (AutomatedDeployMissing(),)),
    ]
    hits = [hit for root, rules in cases for rule in rules for hit in rule.run(root)]
    assert len(hits) == 4
    for root, rules in cases:
        _report(root, hits)
        for rule in rules:
            assert rule.run(root), rule.id


def test_report_quoting_an_in_place_finding_does_not_fire(tmp_path: Path) -> None:
    source = tmp_path / "source"
    files = _cf_iac(after=("ansible-playbook site.yml", "ssh deploy@web1 restart"),
                    extra={**_CF_IN_PLACE["cfn-hup"], **_CF_IN_PLACE["default style"]})
    _put(source, files)
    (hit,) = InPlaceChange().run(source)
    clean = tmp_path / "clean"
    _put(clean, _cf_iac())
    _report(clean, [hit])
    assert not InPlaceChange().run(clean)
