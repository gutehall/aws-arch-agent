"""CF-ECR-* (ECR repositories) and CF-ECS-* (ECS task definitions) (DM3-527)."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import CF_COVERS_STATIC, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import load_plan_values, resources_from_terraform

ECR = {"CF-ECR-001", "CF-ECR-002", "CF-ECR-003"}
ECS = {"CF-ECS-001", "CF-ECS-002", "CF-ECS-003"}
IDS = ECR | ECS


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings if f.id in IDS}


def _by(findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    return {(f.evidence.split(" ")[0], f.id): f for f in findings if f.id in IDS}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


LIFECYCLE = {"LifecyclePolicyText": '{"rules": []}'}


def _repo(**props) -> dict:
    return {"Type": "AWS::ECR::Repository", "Properties": props}


def _task(*containers: dict, **props) -> dict:
    return {"Type": "AWS::ECS::TaskDefinition", "Properties": {
        "ContainerDefinitions": list(containers), **props}}


SAFE = {"Name": "app", "Image": "x", "ReadonlyRootFilesystem": True, "User": "1000"}


def test_cloudformation_ecr(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Plain": _repo(),
        "Hardened": _repo(
            ImageScanningConfiguration={"ScanOnPush": True}, ImageTagMutability="IMMUTABLE",
            LifecyclePolicy=LIFECYCLE),
        "ScanOff": _repo(
            ImageScanningConfiguration={"ScanOnPush": "false"}, ImageTagMutability="IMMUTABLE_WITH_EXCLUSION",
            LifecyclePolicy=LIFECYCLE),
        "Mutable": _repo(
            ImageScanningConfiguration={"ScanOnPush": True}, ImageTagMutability="MUTABLE",
            LifecyclePolicy=LIFECYCLE),
        "FromParams": _repo(
            ImageScanningConfiguration={"ScanOnPush": {"Ref": "Scan"}},
            ImageTagMutability={"Ref": "Mutability"}, LifecyclePolicy=LIFECYCLE),
    })
    assert _found(findings) == {
        ("Plain", "CF-ECR-001"), ("Plain", "CF-ECR-002"), ("Plain", "CF-ECR-003"),
        ("ScanOff", "CF-ECR-001"),
        ("Mutable", "CF-ECR-002"),
    }
    assert {f.severity for f in findings} == {"Low"}
    scan = _by(findings)[("Plain", "CF-ECR-001")]
    assert "enhanced scanning" in scan.recommendation


def test_cloudformation_ecs(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Safe": _task(SAFE, {**SAFE, "Name": "sidecar", "User": "app:app"}),
        "Privileged": _task({**SAFE, "Privileged": True}, {**SAFE, "Name": "ok", "Privileged": "false"}),
        "Writable": _task({**SAFE, "ReadonlyRootFilesystem": False}, {**SAFE, "Name": "web",
                          "ReadonlyRootFilesystem": None}),
        "Root": _task({**SAFE, "User": "root"}, {**SAFE, "Name": "zero", "User": "0:0"},
                      {**SAFE, "Name": "unset", "User": None}),
        "NoUser": _task({k: v for k, v in SAFE.items() if k != "User"}),
        "Unknown": _task({"Name": "app", "Privileged": {"Ref": "P"},
                          "ReadonlyRootFilesystem": {"Ref": "R"}, "User": {"Ref": "U"}}),
        "Windows": _task({"Name": "win", "Image": "x"},
                         RuntimePlatform={"OperatingSystemFamily": "WINDOWS_SERVER_2022_CORE"}),
        # A family from a parameter may be Windows: User and ReadonlyRootFilesystem are not judged.
        "FamilyParam": _task({"Name": "win", "Image": "x", "Privileged": True},
                             RuntimePlatform={"OperatingSystemFamily": {"Ref": "Family"}}),
        "PlatformIf": _task({"Name": "win", "Image": "x"},
                            RuntimePlatform={"Fn::If": ["Win", {"OperatingSystemFamily": "WINDOWS_SERVER_2022_CORE"},
                                                        {"Ref": "AWS::NoValue"}]}),
        "Linux": _task({"Name": "lin", "Image": "x"}, RuntimePlatform={"OperatingSystemFamily": "LINUX"}),
        "Intrinsic": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
            "ContainerDefinitions": {"Fn::If": ["A", [], []]}}},
    })
    assert _found(findings) == {
        ("Privileged", "CF-ECS-001"),
        ("Writable", "CF-ECS-002"),
        ("Root", "CF-ECS-003"),
        ("NoUser", "CF-ECS-003"),
        ("FamilyParam", "CF-ECS-001"),
        ("Linux", "CF-ECS-002"),
        ("Linux", "CF-ECS-003"),
    }
    by = _by(findings)
    assert by[("Privileged", "CF-ECS-001")].severity == "High"
    assert "Privileged is true on app:" in by[("Privileged", "CF-ECS-001")].recommendation
    assert by[("Writable", "CF-ECS-002")].recommendation.startswith(
        "ReadonlyRootFilesystem is not true on app, web.")
    root = by[("Root", "CF-ECS-003")]
    assert root.severity == "Medium"
    assert root.recommendation.startswith("User is root or 0 on app, zero. User is not set on unset.")
    assert by[("NoUser", "CF-ECS-003")].severity == "Low"


def test_cloudformation_fixes(tmp_path: Path) -> None:
    findings = attach_fixes(_cf(tmp_path, {
        "Plain": _repo(),
        "Root": _task({**SAFE, "User": "root", "Privileged": True, "ReadonlyRootFilesystem": False}),
    }), "cloudformation")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert "ScanOnPush: true" in code[("Plain", "CF-ECR-001")]
    assert "ImageTagMutability: IMMUTABLE" in code[("Plain", "CF-ECR-002")]
    assert "LifecyclePolicyText" in code[("Plain", "CF-ECR-003")]
    assert "Privileged: false" in code[("Root", "CF-ECS-001")]
    assert "ReadonlyRootFilesystem: true" in code[("Root", "CF-ECS-002")]
    assert "User: '1000'" in code[("Root", "CF-ECS-003")]
    assert all("In CDK" not in f.recommendation for f in findings)


def test_template_checks_replace_the_cdk_rules() -> None:
    assert CF_COVERS_STATIC["CF-ECR-001"] == ("SEC-028",)
    assert CF_COVERS_STATIC["CF-ECR-002"] == ("SEC-029",)
    assert CF_COVERS_STATIC["CF-ECR-003"] == ("SEC-030",)
    assert CF_COVERS_STATIC["CF-ECS-002"] == ("SEC-020",)
    assert CF_COVERS_STATIC["CF-ECS-003"] == ("SEC-058",)


ECR_ECS_TF = """\
resource "aws_ecr_repository" "plain" {
  name = "plain"
}

resource "aws_ecr_repository" "hardened" {
  name                 = "hardened"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "hardened" {
  repository = aws_ecr_repository.hardened.name
  policy     = jsonencode({ rules = [] })
}

resource "aws_ecr_repository" "by_name" {
  name                 = "by-name"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_ecr_lifecycle_policy" "by_name" {
  repository = "by-name"
  policy     = "{\\"rules\\": []}"
}

resource "aws_ecr_repository" "from_var" {
  name                 = "v"
  image_tag_mutability = var.mutability
  image_scanning_configuration {
    scan_on_push = var.scan
  }
}

resource "aws_ecs_task_definition" "safe" {
  family = "safe"
  container_definitions = jsonencode([{
    name                   = "app"
    image                  = "x"
    readonlyRootFilesystem = true
    user                   = "1000"
  }])
}

resource "aws_ecs_task_definition" "risky" {
  family = "risky"
  container_definitions = jsonencode([
    {
      name       = "app"
      image      = var.image
      privileged = true
      user       = "root"
    },
    {
      name                   = "sidecar"
      image                  = "y"
      readonlyRootFilesystem = true
    }
  ])
}

resource "aws_ecs_task_definition" "json_string" {
  family                = "json"
  container_definitions = "[{\\"name\\": \\"app\\", \\"image\\": \\"x\\", \\"user\\": \\"0\\", \\"readonlyRootFilesystem\\": true}]"
}

resource "aws_ecs_task_definition" "unknown_user" {
  family = "unknown"
  container_definitions = jsonencode([{
    name                   = "app"
    image                  = "x"
    readonlyRootFilesystem = var.readonly
    user                   = var.user
  }])
}

resource "aws_ecs_task_definition" "from_file" {
  family                = "file"
  container_definitions = file("containers.json")
}

resource "aws_ecs_task_definition" "int_root" {
  family = "int"
  container_definitions = jsonencode([{ name = "app", image = "x", readonlyRootFilesystem = true, user = 0 }])
}

resource "aws_ecr_repository" "dynamic_scan" {
  name                 = "dyn"
  image_tag_mutability = "IMMUTABLE"
  dynamic "image_scanning_configuration" {
    for_each = var.scan ? [1] : []
    content {
      scan_on_push = true
    }
  }
}

resource "aws_ecs_task_definition" "dynamic_platform" {
  family = "dyn"
  container_definitions = jsonencode([{ name = "app", image = "x" }])
  dynamic "runtime_platform" {
    for_each = var.platforms
    content {
      operating_system_family = runtime_platform.value
    }
  }
}

resource "aws_ecs_task_definition" "windows" {
  family = "windows"
  container_definitions = jsonencode([{ name = "win", image = "x" }])
  runtime_platform {
    operating_system_family = "WINDOWS_SERVER_2022_CORE"
  }
}
"""


def _tf(tmp_path: Path, text: str = ECR_ECS_TF) -> list[Finding]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    return [f for f in run_resource_checks(resources, tmp_path) if f.id in IDS]


def test_terraform_ecr_and_ecs(tmp_path: Path) -> None:
    findings = _tf(tmp_path)
    assert _found(findings) == {
        ("aws_ecr_repository.plain", "CF-ECR-001"),
        ("aws_ecr_repository.plain", "CF-ECR-002"),
        ("aws_ecr_repository.plain", "CF-ECR-003"),
        ("aws_ecr_repository.by_name", "CF-ECR-001"),
        ("aws_ecr_repository.from_var", "CF-ECR-003"),
        ("aws_ecs_task_definition.risky", "CF-ECS-001"),
        ("aws_ecs_task_definition.risky", "CF-ECS-002"),
        ("aws_ecs_task_definition.risky", "CF-ECS-003"),
        ("aws_ecs_task_definition.json_string", "CF-ECS-003"),
        ("aws_ecs_task_definition.int_root", "CF-ECS-003"),
        ("aws_ecr_repository.dynamic_scan", "CF-ECR-003"),
    }
    assert all(f.line for f in findings)
    assert _by(findings)[("aws_ecs_task_definition.int_root", "CF-ECS-003")].severity == "Medium"
    by = _by(findings)
    assert by[("aws_ecs_task_definition.risky", "CF-ECS-002")].recommendation.startswith(
        "ReadonlyRootFilesystem is not true on app.")
    risky_user = by[("aws_ecs_task_definition.risky", "CF-ECS-003")]
    assert risky_user.recommendation.startswith("User is root or 0 on app. User is not set on sidecar.")


def test_terraform_unlinked_lifecycle_policy_counts_for_every_repository(tmp_path: Path) -> None:
    findings = _tf(tmp_path, """\
resource "aws_ecr_repository" "a" {
  name = "a"
}

resource "aws_ecr_lifecycle_policy" "some" {
  repository = var.repository
  policy     = jsonencode({ rules = [] })
}
""")
    assert ("aws_ecr_repository.a", "CF-ECR-003") not in _found(findings)
    assert ("aws_ecr_repository.a", "CF-ECR-001") in _found(findings)


def test_terraform_fixes(tmp_path: Path) -> None:
    findings = attach_fixes(_tf(tmp_path), "terraform")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert "scan_on_push = true" in code[("aws_ecr_repository.plain", "CF-ECR-001")]
    assert "repository = aws_ecr_repository.plain.name" in code[("aws_ecr_repository.plain", "CF-ECR-003")]
    assert 'user = "1000"' in code[("aws_ecs_task_definition.risky", "CF-ECS-003")]
    assert all("In CDK" not in f.recommendation for f in findings)


def test_terraform_plan_fills_container_definitions(tmp_path: Path) -> None:
    """The plan writes container_definitions as a JSON string; a var.* image is filled in."""
    (tmp_path / "main.tf").write_text("""\
resource "aws_ecs_task_definition" "planned" {
  family = "planned"
  container_definitions = jsonencode([{ name = "app", image = var.image, user = var.user }])
}
""", encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"planned_values": {"root_module": {"resources": [{
        "address": "aws_ecs_task_definition.planned", "mode": "managed",
        "values": {"family": "planned", "container_definitions": json.dumps(
            [{"name": "app", "image": "nginx", "user": "root", "readonlyRootFilesystem": True}])},
    }]}}}), encoding="utf-8")
    resources = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan_path))
    findings = [f for f in run_resource_checks(resources, tmp_path) if f.id in IDS]
    assert _found(findings) == {("aws_ecs_task_definition.planned", "CF-ECS-003")}
