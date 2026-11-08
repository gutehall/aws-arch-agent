"""CodeBuild and CodePipeline in templates: CF-CB-001..005, CF-CP-001..003."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = tuple(f"CF-CB-00{n}" for n in range(1, 6)) + tuple(f"CF-CP-00{n}" for n in range(1, 4))
_PARAM = {"Ref": "Param"}


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf_findings(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return found


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    return _by_id(_cf_findings(tmp_path, resources))


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _project(**props: Any) -> dict:
    return {"Type": "AWS::CodeBuild::Project", "Properties": props}


def _env(*variables: dict) -> dict:
    return {"EnvironmentVariables": list(variables)}


def _action(category: Any, order: Any = None) -> dict:
    action: dict = {"Name": "a", "ActionTypeId": {"Category": category}}
    if order is not None:
        action["RunOrder"] = order
    return action


def _stage(name: Any, *actions: dict) -> dict:
    return {"Name": name, "Actions": list(actions)}


_KEY = {"Type": "KMS", "Id": "k"}
_NOTIFY = {"Type": "AWS::CodeStarNotifications::NotificationRule",
           "Properties": {"Resource": {"Fn::Sub": "arn:aws:codepipeline:eu-west-1:1:${Pipe}"}}}


def _pipeline(**props: Any) -> dict:
    return {"Type": "AWS::CodePipeline::Pipeline", "Properties": {
        "ArtifactStore": {"Type": "S3", "Location": "b", "EncryptionKey": _KEY}, **props}}


def test_a_hardened_project_and_pipeline_have_no_findings(tmp_path: Path) -> None:
    project = _project(
        Environment={"PrivilegedMode": False, "EnvironmentVariables": [
            {"Name": "DB_PASSWORD", "Type": "SECRETS_MANAGER", "Value": "s:p"},
            {"Name": "AWS_SECRET_ACCESS_KEY", "Type": "PARAMETER_STORE", "Value": "/p"},
            {"Name": "STAGE", "Value": "prod"},
        ]},
        Source={"Type": "BITBUCKET", "Location": "https://bitbucket.org/w/r.git"},
        LogsConfig={"CloudWatchLogs": {"Status": "ENABLED"},
                    "S3Logs": {"Status": "ENABLED", "Location": "b/p", "EncryptionDisabled": False}},
    )
    pipeline = _pipeline(Name="prod-release", Stages=[
        _stage("Approve", _action("Approval")), _stage("Deploy", _action("Deploy"))])
    assert _cf(tmp_path, {"Build": project, "Pipe": pipeline, "Rule": _NOTIFY}) == {}


def test_plaintext_secrets(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Named": _project(Environment=_env({"Name": "DB_PASSWORD", "Value": "hunter2"})),
        "Typed": _project(Environment=_env({"Name": "API_KEY", "Type": "PLAINTEXT", "Value": "abc"})),
        "AwsValue": _project(Environment=_env({"Name": "KEY", "Value": "AKIAIOSFODNN7EXAMPLE"})),
        "AwsName": _project(Environment=_env({"Name": "AWS_ACCESS_KEY_ID", "Value": _PARAM})),
        "Reference": _project(Environment=_env({"Name": "DB_PASSWORD", "Value": _PARAM})),
        "Arn": _project(Environment=_env({"Name": "DB_SECRET_ARN", "Value": "arn:aws:secretsmanager:x"})),
        "Stored": _project(Environment=_env({"Name": "DB_PASSWORD", "Type": "SECRETS_MANAGER", "Value": "x"})),
        "UnreadType": _project(Environment=_env({"Name": "DB_PASSWORD", "Type": _PARAM, "Value": "x"})),
        "UnreadEnv": _project(Environment=_PARAM),
    }) == {"CF-CB-001": {"Named", "Typed", "AwsValue", "AwsName"}}


def test_findings_never_quote_a_secret(tmp_path: Path) -> None:
    found = _cf_findings(tmp_path, {
        "Build": _project(
            Environment=_env({"Name": "DB_PASSWORD", "Value": "hunter2-value"}),
            Source={"Location": "https://user:token-value@bitbucket.org/w/r.git"},
        )})
    ours = [f for f in found if f.id in ("CF-CB-001", "CF-CB-002")]
    assert {f.id for f in ours} == {"CF-CB-001", "CF-CB-002"}
    for finding in ours:
        text = str(finding)
        assert "hunter2-value" not in text and "token-value" not in text
    assert "DB_PASSWORD" in next(f for f in ours if f.id == "CF-CB-001").recommendation


@pytest.mark.parametrize(("location", "fires"), [
    ("https://user:token@bitbucket.org/w/r.git", True),
    ("https://x-token-auth:abc@github.com/o/r", True),
    ("https://ghp_abcdefghijklmnopqrstuvwxyz@github.com/o/r", True),
    ("https://bitbucket.org/w/r.git", False),
    ("https://user@bitbucket.org/w/r.git", False),
    ("https://git.example.com:8443/o/r@v1", False),
    ("https://user:{{resolve:secretsmanager:s}}@github.com/o/r", False),
    ("bucket/key.zip", False),
    (_PARAM, False),
])
def test_source_urls(tmp_path: Path, location: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"Build": _project(Source={"Location": location})})
    assert found == ({"CF-CB-002": {"Build"}} if fires else {})


def test_secondary_sources_are_read(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Build": _project(
        Source={"Location": "https://github.com/o/r"},
        SecondarySources=[{"Location": "https://u:p@github.com/o/r2"}],
    )}) == {"CF-CB-002": {"Build"}}


def test_privileged_mode(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "On": _project(Environment={"PrivilegedMode": True}),
        "Text": _project(Environment={"PrivilegedMode": "true"}),
        "Off": _project(Environment={"PrivilegedMode": False}),
        "Unread": _project(Environment={"PrivilegedMode": _PARAM}),
        "Unset": _project(Environment={}),
    }) == {"CF-CB-003": {"On", "Text"}}


def test_logs(tmp_path: Path) -> None:
    off = {"Status": "DISABLED"}
    assert _cf(tmp_path, {
        "Default": _project(),
        "NoConfig": _project(LogsConfig={}),
        "CloudWatchOff": _project(LogsConfig={"CloudWatchLogs": off}),
        "BothOff": _project(LogsConfig={"CloudWatchLogs": off, "S3Logs": off}),
        "S3On": _project(LogsConfig={"CloudWatchLogs": off, "S3Logs": {"Status": "ENABLED"}}),
        "Unread": _project(LogsConfig={"CloudWatchLogs": {"Status": _PARAM}}),
        "UnreadS3": _project(LogsConfig={"CloudWatchLogs": off, "S3Logs": {"Status": _PARAM}}),
        "UnreadS3Block": _project(LogsConfig={"CloudWatchLogs": off, "S3Logs": _PARAM}),
    }) == {"CF-CB-004": {"CloudWatchOff", "BothOff"}}


def test_s3_log_encryption(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Plain": _project(LogsConfig={"S3Logs": {"Status": "ENABLED", "EncryptionDisabled": True}}),
        "Encrypted": _project(LogsConfig={"S3Logs": {"Status": "ENABLED", "EncryptionDisabled": False}}),
        "Default": _project(LogsConfig={"S3Logs": {"Status": "ENABLED"}}),
        "S3Off": _project(LogsConfig={"S3Logs": {"Status": "DISABLED", "EncryptionDisabled": True}}),
        "Unread": _project(LogsConfig={"S3Logs": {"Status": "ENABLED", "EncryptionDisabled": _PARAM}}),
    }) == {"CF-CB-005": {"Plain"}}


def _cp(tmp_path: Path, resources: dict, check: str) -> set[str]:
    return _cf(tmp_path, resources).get(check, set())


def test_artifact_store_key(tmp_path: Path) -> None:
    def pipe(**props: Any) -> dict:
        return {"Type": "AWS::CodePipeline::Pipeline", "Properties": props}

    assert _cp(tmp_path, {
        "NoKey": pipe(ArtifactStore={"Type": "S3", "Location": "b"}),
        "Key": pipe(ArtifactStore={"Type": "S3", "Location": "b", "EncryptionKey": _KEY}),
        "KeyParam": pipe(ArtifactStore={"Type": "S3", "Location": "b", "EncryptionKey": _PARAM}),
        "Unread": pipe(ArtifactStore=_PARAM),
        "OneRegion": pipe(ArtifactStores=[
            {"Region": "a", "ArtifactStore": {"EncryptionKey": _KEY}},
            {"Region": "b", "ArtifactStore": {"Location": "b"}},
        ]),
        "AllRegions": pipe(ArtifactStores=[{"Region": "a", "ArtifactStore": {"EncryptionKey": _KEY}}]),
    }, "CF-CP-001") == {"NoKey", "OneRegion"}


@pytest.mark.parametrize(("name", "stages", "fires"), [
    # A stage named for production is what counts when there is one.
    (None, [_stage("DeployProd", _action("Deploy"))], True),
    (None, [_stage("Staging", _action("Deploy")), _stage("Prod", _action("Deploy"))], True),
    (None, [_stage("Staging", _action("Deploy")), _stage("Approve", _action("Approval")),
            _stage("Prod", _action("Deploy"))], False),
    (None, [_stage("Prod", _action("Approval", 1), _action("Deploy", 2))], False),
    # The same RunOrder runs at once, so that approval gates nothing.
    (None, [_stage("Prod", _action("Approval", 1), _action("Deploy", 1))], True),
    (None, [_stage("Prod", _action("Deploy", 1), _action("Approval", 2))], True),
    (None, [_stage("Prod", _action("Approval", "1"), _action("Deploy", "2"))], False),
    # A pipeline named for production: the last deploy needs the approval.
    ("prod-release", [_stage("Deploy", _action("Deploy"))], True),
    ("prod-release", [_stage("Stage", _action("Deploy")), _stage("Ok", _action("Approval")),
                      _stage("Live2", _action("Deploy"))], False),
    ("prod-release", [_stage("Source", _action("Source")), _stage("Build", _action("Build"))], False),
    # Whole words only.
    ("product-api", [_stage("Deploy", _action("Deploy"))], False),
    ("preprod", [_stage("Deploy", _action("Deploy"))], False),
    (None, [_stage("Deploy", _action("Deploy"))], False),
    # Values the scan cannot read.
    ("prod", [_stage("Deploy", _action(_PARAM))], False),
    ("prod", [_stage("Deploy", _action("Deploy", _PARAM))], False),
    ("prod", [{"Fn::If": ["c", {}, {}]}], False),
    ("prod", _PARAM, False),
])
def test_approval(tmp_path: Path, name: Any, stages: Any, fires: bool) -> None:
    props: dict = {"Stages": stages}
    if name:
        props["Name"] = name
    found = _cp(tmp_path, {"Pipe": _pipeline(**props)}, "CF-CP-002")
    assert found == ({"Pipe"} if fires else set())


def test_logical_id_names_a_pipeline_with_no_name(tmp_path: Path) -> None:
    deploy = [_stage("Deploy", _action("Deploy"))]
    assert _cp(tmp_path, {"ProdPipeline": _pipeline(Stages=deploy)}, "CF-CP-002") == {"ProdPipeline"}
    assert _cp(tmp_path, {"ProdPipeline": _pipeline(Name="app", Stages=deploy)}, "CF-CP-002") == set()


def _rule(resource: Any) -> dict:
    return {"Type": "AWS::CodeStarNotifications::NotificationRule", "Properties": {"Resource": resource}}


def _events(pattern: Any) -> dict:
    return {"Type": "AWS::Events::Rule", "Properties": {"EventPattern": pattern}}


@pytest.mark.parametrize(("extra", "fires"), [
    ({}, True),
    ({"Rule": _rule({"Fn::Sub": "arn:aws:codepipeline:r:1:${Pipe}"})}, False),
    ({"Rule": _rule({"Ref": "Param"})}, False),
    ({"Rule": _rule("arn:aws:codepipeline:r:1:named")}, False),
    ({"Rule": _rule({"Fn::Sub": "arn:aws:codepipeline:r:1:${Other}"}),
      "Other": _pipeline()}, True),
    ({"Rule": _rule("arn:aws:codebuild:r:1:project/p")}, True),
    ({"Rule": _rule({"Fn::GetAtt": ["Build", "Arn"]}), "Build": _project()}, True),
    ({"Rule": _events({"source": ["aws.codepipeline"]})}, False),
    ({"Rule": _events({"source": ["aws.codepipeline"], "resources": [{"Fn::Join": ["", [{"Ref": "Pipe"}]]}]})}, False),
    ({"Rule": _events({"source": ["aws.s3"]})}, True),
])
def test_notifications(tmp_path: Path, extra: dict, fires: bool) -> None:
    found = _cp(tmp_path, {"Pipe": _pipeline(), **extra}, "CF-CP-003")
    assert ("Pipe" in found) is fires


def test_terraform(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "token" { type = string }
variable "mode" { type = bool }

resource "aws_codebuild_project" "bad" {
  name = "bad"
  source {
    type     = "BITBUCKET"
    location = "https://user:secret@bitbucket.org/w/r.git"
  }
  secondary_sources {
    source_identifier = "two"
    type              = "GITHUB"
    location          = "https://github.com/o/r"
  }
  environment {
    privileged_mode = true
    environment_variable {
      name  = "DB_PASSWORD"
      value = "hunter2"
    }
    environment_variable {
      name  = "FROM_VAR"
      value = var.token
    }
  }
  logs_config {
    cloudwatch_logs {
      status = "DISABLED"
    }
    s3_logs {
      status = "DISABLED"
    }
  }
}

resource "aws_codebuild_project" "plain_logs" {
  name = "plain"
  source {
    type = "CODEPIPELINE"
  }
  environment {
    privileged_mode = var.mode
    environment_variable {
      name  = "API_KEY"
      value = var.token
    }
    environment_variable {
      name  = "AWS_SECRET_ACCESS_KEY"
      value = var.token
    }
  }
  logs_config {
    s3_logs {
      status              = "ENABLED"
      location            = "b/p"
      encryption_disabled = true
    }
  }
}

resource "aws_codebuild_project" "good" {
  name = "good"
  source {
    type     = "GITHUB"
    location = "https://github.com/o/r"
  }
  environment {
    environment_variable {
      name  = "DB_PASSWORD"
      type  = "SECRETS_MANAGER"
      value = "s:p"
    }
  }
}

resource "aws_codepipeline" "prod" {
  name = "prod"
  artifact_store {
    type     = "S3"
    location = "b"
  }
  stage {
    name = "Deploy"
    action {
      name     = "d"
      category = "Deploy"
      owner    = "AWS"
      provider = "S3"
      version  = "1"
    }
  }
}

resource "aws_codepipeline" "approved" {
  name = "prod-approved"
  artifact_store {
    type     = "S3"
    location = "b"
    encryption_key {
      type = "KMS"
      id   = aws_kms_key.a.arn
    }
  }
  stage {
    name = "Approve"
    action {
      name      = "a"
      category  = "Approval"
      owner     = "AWS"
      provider  = "Manual"
      version   = "1"
      run_order = 1
    }
  }
  stage {
    name = "Deploy"
    action {
      name      = "d"
      category  = "Deploy"
      owner     = "AWS"
      provider  = "S3"
      version   = "1"
      run_order = 2
    }
  }
}

resource "aws_codestarnotifications_notification_rule" "n" {
  name           = "n"
  detail_type    = "FULL"
  resource       = aws_codepipeline.approved.arn
  event_type_ids = ["codepipeline-pipeline-pipeline-execution-failed"]
}
""")
    assert found == {
        "CF-CB-001": {"aws_codebuild_project.bad", "aws_codebuild_project.plain_logs"},
        "CF-CB-002": {"aws_codebuild_project.bad"},
        "CF-CB-003": {"aws_codebuild_project.bad"},
        "CF-CB-004": {"aws_codebuild_project.bad"},
        "CF-CB-005": {"aws_codebuild_project.plain_logs"},
        "CF-CP-001": {"aws_codepipeline.prod"},
        "CF-CP-002": {"aws_codepipeline.prod"},
        "CF-CP-003": {"aws_codepipeline.prod"},
    }


def test_terraform_dynamic_blocks_are_not_judged(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "items" { type = list(any) }

resource "aws_codebuild_project" "dyn" {
  name = "dyn"
  environment {
    dynamic "environment_variable" {
      for_each = var.items
      content {
        name  = environment_variable.value.name
        value = environment_variable.value.value
      }
    }
  }
  dynamic "logs_config" {
    for_each = var.items
    content {}
  }
}

resource "aws_codebuild_project" "env" {
  name = "env"
  dynamic "environment" {
    for_each = var.items
    content {}
  }
}

resource "aws_codepipeline" "prod" {
  name = "prod"
  dynamic "artifact_store" {
    for_each = var.items
    content {}
  }
  dynamic "stage" {
    for_each = var.items
    content {}
  }
}

resource "aws_codepipeline" "prod_actions" {
  name = "prod-actions"
  artifact_store {
    type     = "S3"
    location = "b"
    dynamic "encryption_key" {
      for_each = var.items
      content {}
    }
  }
  stage {
    name = "Deploy"
    dynamic "action" {
      for_each = var.items
      content {}
    }
  }
}

resource "aws_cloudwatch_event_rule" "state" {
  event_pattern = jsonencode({ source = ["aws.codepipeline"] })
}
""")
    assert found == {}


def test_terraform_event_rule_tied_to_another_pipeline(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
resource "aws_codepipeline" "a" {
  name = "a"
}
resource "aws_codepipeline" "b" {
  name = "b"
}
resource "aws_cloudwatch_event_rule" "state" {
  event_pattern = jsonencode({ source = ["aws.codepipeline"], resources = [aws_codepipeline.a.arn] })
}
""")
    assert found == {"CF-CP-003": {"aws_codepipeline.b"}}
