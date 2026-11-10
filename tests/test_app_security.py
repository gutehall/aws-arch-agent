"""SEC 11: dependency scans (REPO-009), artifact scans (REPO-010), central packages (REPO-011)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import artifact_controls, package_sources, pipeline_scans

SOURCES = ("cdk", "cloudformation", "terraform")
SEC11 = {"REPO-009", "REPO-010", "REPO-011"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict[str, tuple[str, dict]]) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }})


def _scan(root: Path, **kwargs):
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False, **kwargs)
    return ctx, findings


def _ids(findings) -> set[str]:
    return {f.id for f in findings} & SEC11


def _sec11(findings, ran):
    return {a.question.id: a for a in well_architected.answers(findings, ran)}["SEC 11"]


# A bucket-only stack per source, and where an extra control file goes.
_STACK = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json", "terraform": "main.tf"}
_EXTRA = {"cdk": "lib/build.ts", "cloudformation": "build.template.json", "terraform": "build.tf"}
BUCKET = {
    "cdk": "new s3.Bucket(this, 'Data');\n",
    "cloudformation": _cfn({"Data": ("AWS::S3::Bucket", {})}),
    "terraform": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n',
}
LAMBDA = {
    "cdk": "new lambda.Function(this, 'Fn', { runtime, handler: 'index.handler', code });\n",
    "cloudformation": _cfn({"Fn": ("AWS::Lambda::Function", {"Handler": "index.handler"})}),
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}
ECR = {
    "cdk": "new ecr.Repository(this, 'Repo');\n",
    "cloudformation": _cfn({"Repo": ("AWS::ECR::Repository", {})}),
    "terraform": 'resource "aws_ecr_repository" "repo" {\n  name = "app"\n}\n',
}
SCAN_ON_PUSH = {
    "cdk": "new ecr.Repository(this, 'Repo', { imageScanOnPush: true });\n",
    "cloudformation": _cfn({"Repo": ("AWS::ECR::Repository", {
        "ImageScanningConfiguration": {"ScanOnPush": True}})}),
    "terraform": (
        'resource "aws_ecr_repository" "repo" {\n  name = "app"\n'
        "  image_scanning_configuration {\n    scan_on_push = true\n  }\n}\n"
    ),
}
REGISTRY_SCANNING = {
    "cdk": "new ecr.CfnRegistryScanningConfiguration(this, 'Scan', { scanType: 'ENHANCED', "
           "rules: [] });\n",
    "cloudformation": _cfn({"Scan": ("AWS::ECR::RegistryScanningConfiguration", {
        "ScanType": "ENHANCED", "Rules": []})}),
    "terraform": (
        'resource "aws_ecr_registry_scanning_configuration" "scan" {\n'
        '  scan_type = "ENHANCED"\n}\n'
    ),
}


def _inspector(types: list[str]) -> dict[str, str]:
    quoted = ", ".join(f"'{t}'" for t in types)
    return {
        "cdk": "new cr.AwsCustomResource(this, 'Inspector', { onCreate: { service: 'Inspector2', "
               f"action: 'enable', parameters: {{ resourceTypes: [{quoted}] }} }} }});\n",
        # CloudFormation has no enabler resource: a custom resource calls inspector2:Enable.
        "cloudformation": _cfn({"Enable": ("Custom::InspectorEnable", {
            "ServiceToken": "arn", "ResourceTypes": types,
            "Policy": {"Action": "inspector2:Enable"}})}),
        "terraform": (
            'resource "aws_inspector2_enabler" "on" {\n'
            f"  resource_types = {json.dumps(types)}\n}}\n"
        ),
    }


CODEARTIFACT = {
    "cdk": "new codeartifact.CfnRepository(this, 'Npm', { domainName: 'corp', "
           "repositoryName: 'npm' });\n",
    "cloudformation": _cfn({"Npm": ("AWS::CodeArtifact::Repository", {
        "DomainName": "corp", "RepositoryName": "npm"})}),
    "terraform": (
        'resource "aws_codeartifact_repository" "npm" {\n'
        '  repository = "npm"\n  domain     = "corp"\n}\n'
    ),
}


# A CodeBuild project per source whose inline buildspec runs the given command.
def _codebuild(command: str) -> dict[str, str]:
    return {
        "cdk": "new codebuild.PipelineProject(this, 'Build', { buildSpec: "
               "codebuild.BuildSpec.fromObject({ phases: { build: { commands: "
               f"['npm ci', '{command}'] }} }} }}) }});\n",
        "cloudformation": _cfn({"Build": ("AWS::CodeBuild::Project", {"Source": {
            "Type": "CODEPIPELINE",
            "BuildSpec": f"version: 0.2\nphases:\n  build:\n    commands:\n      - {command}\n",
        }})}),
        "terraform": (
            'resource "aws_codebuild_project" "build" {\n  source {\n'
            '    type      = "CODEPIPELINE"\n    buildspec = <<-EOT\n'
            "      phases:\n        build:\n          commands:\n"
            f"            - {command}\n    EOT\n  }}\n}}\n"
        ),
    }


def _repo(
    root: Path, source: str, extra: str | None = None, stack: dict[str, str] = BUCKET
) -> None:
    """A one-stack repo of the source; extra goes in a second IaC file."""
    _write(root / _STACK[source], stack[source])
    if source == "cdk":
        _write(root / "package.json", "{}")
    if extra is not None:
        _write(root / _EXTRA[source], extra)


def _gh_workflow(root: Path, steps: str) -> None:
    _write(root / ".github" / "workflows" / "ci.yml", (
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n" + steps
    ))


# REPO-009: dependency scans


@pytest.mark.parametrize("source", SOURCES)
def test_no_build_fails_repo_009_and_sec11_is_not_met(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source)
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    assert SEC11 & set(ctx.rules_run) == SEC11  # on by default, not org-level
    (f,) = [f for f in findings if f.id == "REPO-009"]
    assert f.question == "SEC 11"
    assert f.best_practices == ["SEC11-BP02"]
    assert (f.severity, f.category) == ("Medium", "Security")
    assert f.evidence.endswith("found none")
    assert "a build to run a dependency scan" in f.evidence
    sec11 = _sec11(findings, ctx.rules_run)
    assert not sec11.met
    assert not {"SEC11-BP02", "SEC11-BP05"} & set(sec11.not_checked)


@pytest.mark.parametrize("source", SOURCES)
def test_pipeline_without_a_scan_fails_repo_009(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source, _codebuild("npm run build")[source])
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-009"]
    assert f.evidence.startswith(f"Searched the build configs ({_EXTRA[source]})")
    assert f.evidence.endswith("found none")


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize(
    "command", ["npm audit --audit-level=high", "pip-audit -r requirements.txt",
                "osv-scanner -r .", "trivy fs --exit-code 1 ."],
)
def test_inline_buildspec_scan_passes_repo_009(tmp_path: Path, source: str, command: str) -> None:
    _repo(tmp_path, source, _codebuild(command)[source])
    _ctx, findings = _scan(tmp_path)
    assert "REPO-009" not in _ids(findings)


@pytest.mark.parametrize("source", SOURCES)
def test_swallowed_scan_does_not_pass_repo_009(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source, _codebuild("npm audit || true")[source])
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-009"]
    assert f.evidence.endswith(f"found npm audit in {_EXTRA[source]}, but it cannot fail the build")


@pytest.mark.parametrize("source", SOURCES)
def test_github_workflow_scan_passes_repo_009(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source)
    _gh_workflow(tmp_path, "      - name: Audit\n        run: pip-audit\n")
    _ctx, findings = _scan(tmp_path)
    assert "REPO-009" not in _ids(findings)


def test_continue_on_error_does_not_count(tmp_path: Path) -> None:
    _gh_workflow(tmp_path, (
        "      - name: Audit\n        run: |\n          npm ci\n          npm audit\n"
        "        continue-on-error: true\n      - run: npm test\n"
    ))
    _builds, scans = pipeline_scans(tmp_path)
    assert scans == [("npm audit", "dependency", ".github/workflows/ci.yml", False)]


def test_continue_on_error_on_another_step_does_not_matter(tmp_path: Path) -> None:
    _gh_workflow(tmp_path, (
        "      - name: Audit\n        run: npm audit\n"
        "      - name: Lint\n        run: npm run lint\n        continue-on-error: true\n"
    ))
    _builds, scans = pipeline_scans(tmp_path)
    assert scans == [("npm audit", "dependency", ".github/workflows/ci.yml", True)]


@pytest.mark.parametrize(
    "rel, text",
    [
        (".gitlab-ci.yml", "audit:\n  script:\n    - pip-audit\n  allow_failure: true\n"),
        ("buildspec.yml", "phases:\n  build:\n    on-failure: CONTINUE\n    commands:\n"
                          "      - pip-audit\n"),
        ("buildspec.yml", "phases:\n  build:\n    commands:\n      - pip-audit || exit 0\n"),
        # Trivy and grype pass on findings unless told to fail.
        ("buildspec.yml", "phases:\n  build:\n    commands:\n      - trivy fs .\n"),
        ("buildspec.yml", "phases:\n  build:\n    commands:\n      - grype dir:.\n"),
        # The Inspector action only sets an output; nothing here fails on it.
        (".github/workflows/ci.yml", "jobs:\n  scan:\n    steps:\n      - uses: aws-actions/"
                                     "vulnerability-scan-github-action-for-amazon-inspector@v1\n"),
    ],
)
def test_scans_that_cannot_fail_do_not_pass_repo_009(tmp_path: Path, rel: str, text: str) -> None:
    _write(tmp_path / rel, text)
    _builds, scans = pipeline_scans(tmp_path)
    assert scans and not any(fails for *_rest, fails in scans)
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-009"]
    assert "but it cannot fail the build" in f.evidence


def test_inspector_action_with_a_gate_passes_repo_009(tmp_path: Path) -> None:
    _gh_workflow(tmp_path, (
        "      - id: inspector\n"
        "        uses: aws-actions/vulnerability-scan-github-action-for-amazon-inspector@v1\n"
        "        with:\n          critical_threshold: 1\n"
        "      - if: steps.inspector.outputs.vulnerability_threshold_exceeded == 1\n"
        "        run: exit 1\n"
    ))
    _ctx, findings = _scan(tmp_path)
    assert "REPO-009" not in _ids(findings)


def test_package_script_the_pipeline_runs_passes_repo_009(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", json.dumps({"scripts": {
        "ci": "npm run lint && npm run audit", "audit": "npm audit --audit-level=high"}}))
    _write(tmp_path / "lib" / "pipeline.ts", (
        "new pipelines.CodePipeline(this, 'Pipeline', { synth: new pipelines.ShellStep("
        "'Synth', { input, commands: ['npm ci', 'npm run ci', 'npx cdk synth'] }) });\n"
    ))
    _builds, scans = pipeline_scans(tmp_path)
    assert scans == [("npm audit", "dependency", "package.json script audit", True)]
    _ctx, findings = _scan(tmp_path)
    assert "REPO-009" not in _ids(findings)


def test_package_script_nobody_runs_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", json.dumps({"scripts": {"audit": "npm audit"}}))
    _gh_workflow(tmp_path, "      - run: npm test\n")
    _builds, scans = pipeline_scans(tmp_path)
    assert scans == []


# REPO-010: container and function artifacts


@pytest.mark.parametrize("source", SOURCES)
def test_no_containers_or_functions_no_repo_010(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source)
    _ctx, findings = _scan(tmp_path)
    assert "REPO-010" not in _ids(findings)
    assert artifact_controls(tmp_path)[0] == {}


@pytest.mark.parametrize("source", SOURCES)
def test_unscanned_ecr_repository_fails_repo_010(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source, stack=ECR)
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-010"]
    assert f.question == "SEC 11"
    assert f.best_practices == ["SEC11-BP02"]
    assert (f.severity, f.category) == ("Medium", "Security")
    assert f.evidence.startswith(f"Builds container images ({_STACK[source]})")
    assert "Lambda" not in f.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_unscanned_function_fails_repo_010(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source, stack=LAMBDA)
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-010"]
    assert f.evidence.startswith(f"Deploys Lambda functions ({_STACK[source]})")
    assert "container" not in f.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("control", ["scan_on_push", "registry", "inspector"])
def test_container_scanning_passes_repo_010(tmp_path: Path, source: str, control: str) -> None:
    texts = {
        "scan_on_push": SCAN_ON_PUSH, "registry": REGISTRY_SCANNING,
        "inspector": _inspector(["ECR"]),
    }[control]
    _repo(tmp_path, source, texts[source], stack=ECR)
    _ctx, findings = _scan(tmp_path)
    assert "REPO-010" not in _ids(findings)


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("types", [["LAMBDA"], ["LAMBDA_CODE"]])
def test_inspector_lambda_passes_repo_010(tmp_path: Path, source: str, types: list[str]) -> None:
    _repo(tmp_path, source, _inspector(types)[source], stack=LAMBDA)
    _ctx, findings = _scan(tmp_path)
    assert "REPO-010" not in _ids(findings)


@pytest.mark.parametrize("source", SOURCES)
def test_inspector_for_ecr_only_leaves_functions_unscanned(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source, _inspector(["ECR"])[source], stack=LAMBDA)
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-010"]
    assert f.evidence.startswith("Deploys Lambda functions")


@pytest.mark.parametrize("source", SOURCES)
def test_dependency_scan_covers_functions(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source, _codebuild("npm audit --audit-level=high")[source], stack=LAMBDA)
    _ctx, findings = _scan(tmp_path)
    assert not {"REPO-009", "REPO-010"} & _ids(findings)


def test_dockerfile_with_ci_image_scan_passes_repo_010(tmp_path: Path) -> None:
    _write(tmp_path / "Dockerfile", "FROM public.ecr.aws/lambda/python:3.13\n")
    _gh_workflow(tmp_path, (
        "      - run: docker build -t app .\n"
        "      - run: trivy image --exit-code 1 --severity HIGH,CRITICAL app\n"
    ))
    _ctx, findings = _scan(tmp_path)
    assert "REPO-010" not in _ids(findings)


def test_dockerfile_with_swallowed_image_scan_fails_repo_010(tmp_path: Path) -> None:
    _write(tmp_path / "Dockerfile", "FROM public.ecr.aws/lambda/python:3.13\n")
    _gh_workflow(tmp_path, (
        "      - run: docker build -t app .\n"
        "      - run: snyk container test app\n        continue-on-error: true\n"
    ))
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-010"]
    assert f.evidence == (
        "Builds container images (Dockerfile); searched for ECR scan on push, "
        "ECR registry scanning, Amazon Inspector for ECR, and a CI image scan that fails the "
        "build; found snyk container in .github/workflows/ci.yml, but it cannot fail the build"
    )


def test_cdk_image_asset_counts_as_a_container(tmp_path: Path) -> None:
    _write(tmp_path / "lib" / "stack.ts", (
        "new lambda.DockerImageFunction(this, 'Fn', { code: "
        "lambda.DockerImageCode.fromImageAsset('app') });\n"
    ))
    assert artifact_controls(tmp_path)[0] == {"container images": "lib/stack.ts"}


# REPO-011: central package repository


@pytest.mark.parametrize("source", SOURCES)
def test_manifest_without_central_repo_fails_repo_011(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source)
    _write(tmp_path / "requirements.txt", "boto3\n")
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-011"]
    assert f.question == "SEC 11"
    assert f.best_practices == ["SEC11-BP05"]
    assert (f.severity, f.category) == ("Low", "Security")
    manifest = "package.json" if source == "cdk" else "requirements.txt"
    assert f.evidence.startswith(f"Has a package manifest ({manifest})")


@pytest.mark.parametrize("source", ("cloudformation", "terraform"))
def test_no_manifest_no_repo_011(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source)
    _ctx, findings = _scan(tmp_path)
    assert "REPO-011" not in _ids(findings)


@pytest.mark.parametrize("source", SOURCES)
def test_codeartifact_passes_repo_011(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source, CODEARTIFACT[source])
    _write(tmp_path / "requirements.txt", "boto3\n")
    _ctx, findings = _scan(tmp_path)
    assert "REPO-011" not in _ids(findings)


@pytest.mark.parametrize("source", SOURCES)
def test_codeartifact_login_in_ci_passes_repo_011(tmp_path: Path, source: str) -> None:
    _repo(tmp_path, source)
    _write(tmp_path / "requirements.txt", "boto3\n")
    _gh_workflow(tmp_path, "      - run: aws codeartifact login --tool pip --domain corp "
                           "--repository pypi\n")
    _ctx, findings = _scan(tmp_path)
    assert "REPO-011" not in _ids(findings)


PRIVATE = "https://corp-111122223333.d.codeartifact.eu-west-1.amazonaws.com"


@pytest.mark.parametrize(
    "rel, text",
    [
        (".npmrc", f"registry={PRIVATE}/npm/npm-store/\n"),
        (".yarnrc.yml", f"npmRegistryServer: \"{PRIVATE}/npm/npm-store/\"\n"),
        ("pip.conf", f"[global]\nindex-url = {PRIVATE}/pypi/pypi-store/simple/\n"),
        ("requirements.txt", "--index-url https://nexus.corp.example/simple\nboto3\n"),
        ("pyproject.toml", '[project]\nname = "x"\n\n[[tool.poetry.source]]\nname = "corp"\n'
                           'url = "https://pypi.corp.example/simple"\npriority = "primary"\n'),
        ("pom.xml", "<project><repositories>\n  <repository>\n    <id>corp</id>\n"
                    "    <url>https://nexus.corp.example/maven</url>\n  </repository>\n"
                    "</repositories></project>\n"),
        ("build.gradle", "repositories {\n  maven {\n    url 'https://nexus.corp.example/m2'\n"
                         "  }\n}\n"),
    ],
)
def test_private_registry_passes_repo_011(tmp_path: Path, rel: str, text: str) -> None:
    _write(tmp_path / "package.json", "{}")
    _write(tmp_path / rel, text)
    manifest, found = package_sources(tmp_path)
    assert manifest is not None
    assert found == {"private registry": rel}


@pytest.mark.parametrize(
    "rel, text",
    [
        (".npmrc", "registry=https://registry.npmjs.org/\n"),
        # A scoped registry serves only that scope.
        (".npmrc", f"@corp:registry={PRIVATE}/npm/npm-store/\n"),
        ("pip.conf", "[global]\nindex-url = https://pypi.org/simple\n"),
        ("build.gradle", "repositories {\n  mavenCentral()\n  maven { url "
                         "'https://plugins.gradle.org/m2/' }\n}\n"),
    ],
)
def test_public_registries_do_not_pass_repo_011(tmp_path: Path, rel: str, text: str) -> None:
    _write(tmp_path / "package.json", "{}")
    _write(tmp_path / rel, text)
    assert package_sources(tmp_path)[1] == {}
    _ctx, findings = _scan(tmp_path)
    assert "REPO-011" in _ids(findings)


def test_controls_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "requirements.txt", "boto3\n")
    _write(tmp_path / "tests" / "test_stack.py", (
        "codeartifact.CfnRepository(self, 'R', domain_name='d', repository_name='r')\n"
        "_lambda.Function(self, 'Fn', runtime=r, handler=h, code=c)\n"
    ))
    assert package_sources(tmp_path)[1] == {}
    assert artifact_controls(tmp_path)[0] == {}


def test_sec11_met_with_all_three_controls(tmp_path: Path) -> None:
    _repo(tmp_path, "terraform", CODEARTIFACT["terraform"], stack=LAMBDA)
    _write(tmp_path / "requirements.txt", "boto3\n")
    _gh_workflow(tmp_path, "      - run: pip-audit -r requirements.txt\n")
    ctx, findings = _scan(tmp_path)
    assert not _ids(findings)
    sec11 = _sec11(findings, ctx.rules_run)
    assert not {"SEC11-BP02", "SEC11-BP05"} & set(sec11.not_checked)
    assert not {f.id for f in sec11.findings} & SEC11
