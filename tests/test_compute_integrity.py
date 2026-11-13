"""SEC 6: signed code and images (REPO-037) and pinned images (REPO-038)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    CodeSigningMissing,
    MutableImageTag,
    mutable_images,
    signing_gaps,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }}, indent=2)


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = _cfn(merged)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / "prod" / _PATHS[source], body)


LAMBDA = {
    "cdk": "new lambda.Function(this, 'Fn', { runtime, handler: 'index.handler', code });\n",
    "cloudformation": {"Fn": ("AWS::Lambda::Function", {"Handler": "index.handler"})},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  handler = "index.handler"\n}\n',
}
SIGNED = {
    "cdk": "const signing = new lambda.CodeSigningConfig(this, 'Signing', "
           "{ signingProfiles: [profile] });\n",
    "cloudformation": {"Signing": ("AWS::Lambda::CodeSigningConfig", {
        "AllowedPublishers": {"SigningProfileVersionArns": ["arn"]}})},
    "terraform": 'resource "aws_lambda_code_signing_config" "signing" {\n'
                 "  allowed_publishers {\n    signing_profile_version_arns = [var.p]\n  }\n}\n",
}


def _task(image: str) -> dict:
    return {
        "cdk": f"taskDef.addContainer('App', {{ image: ecs.ContainerImage.fromRegistry('{image}') }});\n",
        "cloudformation": {"Task": ("AWS::ECS::TaskDefinition", {
            "ContainerDefinitions": [{"Name": "app", "Image": image}]})},
        "terraform": 'resource "aws_ecs_task_definition" "app" {\n'
                     "  container_definitions = jsonencode([{\n"
                     f'    name = "app"\n    image = "{image}"\n  }}])\n}}\n',
    }


# REPO-037: signing


@pytest.mark.parametrize("source", SOURCES)
def test_unsigned_lambda_fails_repo_037(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source])
    (finding,) = CodeSigningMissing().run(tmp_path)
    assert finding.id == "REPO-037"
    assert "Lambda functions" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_lambda_with_code_signing_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], SIGNED[source])
    assert CodeSigningMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_unsigned_container_images_fail(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _task("nginx:1.27")[source])
    assert signing_gaps(tmp_path) == {"container images": f"prod/{_PATHS[source]}"}


def test_notation_signer_profile_or_build_signing_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", _task("nginx:1.27")["terraform"],
           'resource "aws_signer_signing_profile" "img" {\n'
           '  platform_id = "Notation-OCI-SHA384-ECDSA"\n}\n')
    assert CodeSigningMissing().run(tmp_path) == []
    _stack(tmp_path, "terraform", _task("nginx:1.27")["terraform"])
    _write(tmp_path / ".github" / "workflows" / "build.yml",
           "jobs:\n  build:\n    steps:\n      - run: cosign sign --yes $IMAGE\n")
    assert CodeSigningMissing().run(tmp_path) == []


def test_lambda_signing_does_not_cover_containers(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", LAMBDA["cloudformation"], SIGNED["cloudformation"],
           _task("nginx:1.27")["cloudformation"])
    (finding,) = CodeSigningMissing().run(tmp_path)
    assert "container images" in finding.evidence
    assert "Lambda functions" not in finding.evidence


def test_no_compute_gets_no_repo_037(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_s3_bucket" "d" {\n  bucket = "d"\n}\n')
    assert CodeSigningMissing().run(tmp_path) == []


# REPO-038: pinned images


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("image", ["nginx", "nginx:latest", "public.ecr.aws/docker/nginx"])
def test_mutable_image_fails_repo_038(tmp_path: Path, source: str, image: str) -> None:
    _stack(tmp_path, source, _task(image)[source])
    (finding,) = MutableImageTag().run(tmp_path)
    assert finding.id == "REPO-038"
    assert image in finding.evidence
    assert finding.file == f"prod/{_PATHS[source]}"


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("image", [
    "nginx:1.27.2", "1.dkr.ecr.eu-west-1.amazonaws.com/app:v42",
    "nginx@sha256:" + "a" * 64,
])
def test_pinned_image_passes_repo_038(tmp_path: Path, source: str, image: str) -> None:
    _stack(tmp_path, source, _task(image)[source])
    assert MutableImageTag().run(tmp_path) == []


def test_cloudformation_yaml_unquoted_image(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "template.yaml",
           "Resources:\n  Task:\n    Type: AWS::ECS::TaskDefinition\n    Properties:\n"
           "      ContainerDefinitions:\n        - Name: app\n          Image: nginx:latest\n"
           "        - Name: side\n          Image: !Sub '${AWS::AccountId}.dkr.ecr/x:latest'\n")
    assert [image for _rel, _line, image in mutable_images(tmp_path)] == ["nginx:latest"]


def test_cdk_ecr_repository_without_tag_is_latest(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk",
           "taskDef.addContainer('App', { image: ecs.ContainerImage.fromEcrRepository(repo) });\n")
    (finding,) = MutableImageTag().run(tmp_path)
    assert "latest tag" in finding.evidence
    _stack(tmp_path, "cdk",
           "taskDef.addContainer('App', { image: ecs.ContainerImage.fromEcrRepository(repo, "
           "'v42') });\nnew lambda.DockerImageFunction(this, 'Fn', "
           "{ code: lambda.DockerImageCode.fromImageAsset('./app') });\n")
    assert MutableImageTag().run(tmp_path) == []


def test_python_cdk_registry_image(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "task.add_container('App', image=ecs.ContainerImage.from_registry('redis'))\n")
    (finding,) = MutableImageTag().run(tmp_path)
    assert "redis" in finding.evidence


def test_lambda_image_uri_is_checked(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform",
           'resource "aws_lambda_function" "fn" {\n  package_type = "Image"\n'
           '  image_uri = "1.dkr.ecr.eu-west-1.amazonaws.com/fn:latest"\n}\n')
    assert MutableImageTag().run(tmp_path)


def test_variable_image_is_not_judged(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_ecs_task_definition" "app" {\n'
           "  container_definitions = jsonencode([{ image = var.image }])\n}\n")
    assert MutableImageTag().run(tmp_path) == []


# Reports and the answer


def test_saved_report_quoting_findings_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", LAMBDA["cdk"])
    hits = CodeSigningMissing().run(tmp_path)
    report = json.dumps({"findings": [f.model_dump() for f in hits]})
    _write(tmp_path / "reports" / "report.json", report)
    assert len(CodeSigningMissing().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    assert CodeSigningMissing().run(empty) == []
    assert MutableImageTag().run(empty) == []


def test_sec6_rules_map_and_run_by_default() -> None:
    assert well_architected.best_practices_of("REPO-037") == ("SEC06-BP04",)
    assert well_architected.best_practices_of("REPO-038") == ("SEC06-BP02",)
    assert not {"REPO-037", "REPO-038"} & ORG_RULE_IDS


def test_cloudformation_yaml_unquoted_image_with_crlf_line_endings(tmp_path: Path) -> None:
    path = tmp_path / "prod" / "template.yaml"
    path.parent.mkdir(parents=True)
    path.write_bytes(
        b"Resources:\r\n  Task:\r\n    Type: AWS::ECS::TaskDefinition\r\n    Properties:\r\n"
        b"      ContainerDefinitions:\r\n        - Name: app\r\n          Image: nginx:latest\r\n"
    )
    assert [image for _rel, _line, image in mutable_images(tmp_path)] == ["nginx:latest"]
