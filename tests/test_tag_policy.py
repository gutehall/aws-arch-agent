"""CF-TAG-001: resources checked against a required tag policy."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import drop_static_covered_by_cf, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.tag_policy import TagPolicy, use_tag_policy
from aws_arch_agent.rules.terraform_model import resources_from_terraform

POLICY = TagPolicy(required=("CostCenter", "Owner", "Environment"), allowed={"Environment": ("prod", "dev")})
GOOD = [{"Key": "CostCenter", "Value": "42"}, {"Key": "Owner", "Value": "team-a"}, {"Key": "Environment", "Value": "prod"}]


def _tagged(findings: list[Finding]) -> dict[str, Finding]:
    return {f.evidence.split(" ")[0]: f for f in findings if f.id == "CF-TAG-001"}


def _cf(tmp_path: Path, resources: dict, policy: TagPolicy | None = POLICY) -> dict[str, Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    with use_tag_policy(policy):
        return _tagged(run_cf_rules_from_paths([path], repo_path=tmp_path))


def _bucket(tags=None, prop: str = "Tags", rtype: str = "AWS::S3::Bucket") -> dict:
    return {"Type": rtype, "Properties": {} if tags is None else {prop: tags}}


def test_cloudformation_one_finding_per_untagged_resource(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Tagged": _bucket(GOOD),
        "Untagged": _bucket(),
        "UntaggedQueue": {"Type": "AWS::SQS::Queue", "Properties": {}},
        "Partial": _bucket([{"Key": "CostCenter", "Value": "42"}]),
        "BadEnv": _bucket([*GOOD[:2], {"Key": "Environment", "Value": "Prod"}]),
        "EnvFromParam": _bucket([*GOOD[:2], {"Key": "Environment", "Value": {"Ref": "Env"}}]),
        "TagsIf": _bucket({"Fn::If": ["X", GOOD, []]}),
        "MapTags": _bucket({"CostCenter": "1", "Owner": "o", "Environment": "dev"}, rtype="AWS::ApiGatewayV2::Api"),
        "Efs": _bucket([{"Key": "Owner", "Value": "o"}], prop="FileSystemTags", rtype="AWS::EFS::FileSystem"),
        "Pool": _bucket({"Owner": "o"}, prop="UserPoolTags", rtype="AWS::Cognito::UserPool"),
        # Not taggable: never reported.
        "Policy": {"Type": "AWS::S3::BucketPolicy", "Properties": {"Bucket": "b", "PolicyDocument": {}}},
    })
    assert set(found) == {"Untagged", "UntaggedQueue", "Partial", "BadEnv", "Efs", "Pool"}
    assert found["Untagged"].recommendation.startswith("Missing required tags: CostCenter, Owner, Environment.")
    assert found["Partial"].recommendation.startswith("Missing required tags: Owner, Environment.")
    assert found["BadEnv"].recommendation.startswith("Value not allowed: Environment=Prod (allowed Environment: prod, dev).")
    assert {f.severity for f in found.values()} == {"Medium"}


def test_no_policy_means_no_check(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Untagged": _bucket()}, policy=None) == {}


def test_cdk_stack_tags_are_on_each_resource_in_synth_output(tmp_path: Path) -> None:
    """Tags.of(app).add(...) is written into each taggable resource by cdk synth."""
    out = tmp_path / "cdk.out"
    out.mkdir()
    bucket = {"Type": "AWS::S3::Bucket", "Properties": {"Tags": GOOD},
              "Metadata": {"aws:cdk:path": "App/Stack/B/Resource"}}
    (out / "Stack.template.json").write_text(json.dumps({"Resources": {"B": bucket}}), encoding="utf-8")
    with use_tag_policy(POLICY):
        assert _tagged(run_cf_rules_from_paths([out / "Stack.template.json"], repo_path=tmp_path)) == {}


DEFAULT_TAGS_TF = """\
provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      CostCenter  = "42"
      Environment = "prod"
    }
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  tags = {
    Owner = "team-a"
  }
}

resource "aws_sqs_queue" "jobs" {
  name = "jobs"
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = "{}"
}
"""


def _tf(tmp_path: Path, text: str, policy: TagPolicy | None = POLICY) -> dict[str, Finding]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    with use_tag_policy(policy):
        return _tagged(run_resource_checks(resources_from_terraform(tmp_path), tmp_path))


def test_terraform_default_tags_and_one_resource_missing_owner(tmp_path: Path) -> None:
    """Done when: default_tags plus one resource missing Owner gives exactly one finding."""
    found = _tf(tmp_path, DEFAULT_TAGS_TF)
    assert list(found) == ["aws_sqs_queue.jobs"]
    assert found["aws_sqs_queue.jobs"].recommendation.startswith("Missing required tag: Owner.")
    assert found["aws_sqs_queue.jobs"].line == 18


def test_terraform_tag_sources(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
provider "aws" {
  default_tags {
    tags = { CostCenter = "42", Environment = "dev" }
  }
}

provider "aws" {
  alias = "west"
}

provider "aws" {
  alias = "shared"
  default_tags {
    tags = var.common_tags
  }
}

resource "aws_s3_bucket" "west" {
  provider = aws.west
  tags     = { Owner = "o" }
}

resource "aws_s3_bucket" "shared" {
  provider = aws.shared
}

resource "aws_s3_bucket" "from_var" {
  tags = var.tags
}

resource "aws_s3_bucket" "owner_var" {
  tags = { Owner = var.owner }
}

resource "aws_s3_bucket" "bad_env" {
  tags = { Owner = "o", Environment = "staging" }
}

resource "aws_autoscaling_group" "asg" {
  max_size = 1
  min_size = 1
  tag {
    key                 = "Owner"
    value               = "o"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "asg_missing" {
  max_size = 1
  min_size = 1
}
""")
    # aws_autoscaling_group does not take provider default_tags, so asg lacks CostCenter.
    assert set(found) == {"aws_s3_bucket.west", "aws_s3_bucket.bad_env", "aws_autoscaling_group.asg",
                          "aws_autoscaling_group.asg_missing"}
    assert found["aws_autoscaling_group.asg"].recommendation.startswith(
        "Missing required tags: CostCenter, Environment.")
    # The west provider has no default_tags.
    assert found["aws_s3_bucket.west"].recommendation.startswith("Missing required tags: CostCenter, Environment.")
    assert "Environment=staging" in found["aws_s3_bucket.bad_env"].recommendation


def test_policy_replaces_the_repo_wide_tag_guesses(tmp_path: Path) -> None:
    guesses = [Finding(id=i, title="t", recommendation="r") for i in ("BP-001", "COST-015", "SEC-005")]
    assert [f.id for f in drop_static_covered_by_cf(list(guesses))] == ["BP-001", "COST-015", "SEC-005"]
    with use_tag_policy(POLICY):
        # No template read yet: the guesses stay.
        assert [f.id for f in drop_static_covered_by_cf(list(guesses))] == ["BP-001", "COST-015", "SEC-005"]
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        run_cf_rules_from_paths([bad], repo_path=tmp_path)
        assert [f.id for f in drop_static_covered_by_cf(list(guesses))] == ["BP-001", "COST-015", "SEC-005"]
        good = tmp_path / "good.json"
        good.write_text(json.dumps({"Resources": {"B": _bucket(GOOD)}}), encoding="utf-8")
        run_cf_rules_from_paths([good], repo_path=tmp_path)
        assert [f.id for f in drop_static_covered_by_cf(list(guesses))] == ["SEC-005"]
    # The scope resets afterwards.
    assert [f.id for f in drop_static_covered_by_cf(list(guesses))] == ["BP-001", "COST-015", "SEC-005"]


def test_numeric_tag_values_are_their_text(tmp_path: Path) -> None:
    path = tmp_path / "t.yaml"
    path.write_text(
        "Resources:\n"
        "  Ok:\n    Type: AWS::S3::Bucket\n    Properties:\n      Tags:\n"
        "        - {Key: CostCenter, Value: 1234}\n        - {Key: Owner, Value: o}\n"
        "        - {Key: Environment, Value: dev}\n"
        "  BadEnv:\n    Type: AWS::S3::Bucket\n    Properties:\n      Tags:\n"
        "        - {Key: CostCenter, Value: 1}\n        - {Key: Owner, Value: o}\n"
        "        - {Key: Environment, Value: 2024}\n",
        encoding="utf-8")
    with use_tag_policy(POLICY):
        found = _tagged(run_cf_rules_from_paths([path], repo_path=tmp_path))
    assert set(found) == {"BadEnv"}
    assert "Environment=2024" in found["BadEnv"].recommendation


def test_terraform_plan_tags_all_fills_unknown_tags(tmp_path: Path) -> None:
    from aws_arch_agent.rules.terraform_model import load_plan_values

    (tmp_path / "main.tf").write_text("""\
provider "aws" {
  default_tags {
    tags = var.common_tags
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

resource "aws_s3_bucket" "data" {
  bucket = "data"
}
""", encoding="utf-8")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"planned_values": {"root_module": {"resources": [
        {"address": "aws_s3_bucket.logs", "mode": "managed",
         "values": {"bucket": "logs", "tags_all": {"CostCenter": "1", "Owner": "o", "Environment": "dev"}}},
        {"address": "aws_s3_bucket.data", "mode": "managed",
         "values": {"bucket": "data", "tags_all": {"CostCenter": "1"}}},
    ]}}}), encoding="utf-8")
    resources = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan))
    with use_tag_policy(POLICY):
        found = _tagged(run_resource_checks(resources, tmp_path))
    assert set(found) == {"aws_s3_bucket.data"}  # without the plan neither is judged


def test_config(tmp_path: Path) -> None:
    assert load_config(tmp_path).tag_policy is None
    (tmp_path / ".aws-arch-agent.yaml").write_text(
        "tags:\n  required: [CostCenter, Owner, CostCenter]\n  allowed:\n    Environment: [prod, dev]\n",
        encoding="utf-8")
    policy = load_config(tmp_path).tag_policy
    assert policy == TagPolicy(required=("CostCenter", "Owner"), allowed={"Environment": ("prod", "dev")})
    (tmp_path / ".aws-arch-agent.yaml").write_text("tags:\n  required: []\n", encoding="utf-8")
    assert load_config(tmp_path).tag_policy is None  # no required keys: off
    for bad in ("tags: [a]\n", "tags:\n  require: [a]\n", "tags:\n  required: [a]\n  allowed: {Env: []}\n",
                "tags:\n  required: [a]\n  allowed: []\n"):
        (tmp_path / ".aws-arch-agent.yaml").write_text(bad, encoding="utf-8")
        with pytest.raises(ConfigError, match="tags"):
            load_config(tmp_path)


def test_fixes(tmp_path: Path) -> None:
    found = _tf(tmp_path, DEFAULT_TAGS_TF)
    fix = attach_fixes(list(found.values()), "terraform")[0].suggested_code or ""
    assert fix.startswith('resource "aws_sqs_queue" "jobs" {') and "default_tags" in fix


def test_cli_scan_and_cdk_source_note(tmp_path: Path) -> None:
    tf = tmp_path / "infra"
    tf.mkdir()
    (tf / "main.tf").write_text(DEFAULT_TAGS_TF, encoding="utf-8")
    (tmp_path / ".aws-arch-agent.yaml").write_text("tags:\n  required: [CostCenter, Owner, Environment]\n",
                                                   encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    ids = [f["id"] for f in json.loads(out.read_text())["findings"]]
    assert ids.count("CF-TAG-001") == 1

    cdk = tmp_path / "cdk"
    cdk.mkdir()
    (cdk / "package.json").write_text("{}", encoding="utf-8")
    (cdk / "lib").mkdir()
    (cdk / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    (cdk / ".aws-arch-agent.yaml").write_text("tags:\n  required: [Owner]\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["--repo", str(cdk), "--no-llm", "--out", str(tmp_path / "c.md")])
    assert result.exit_code == 0, result.output
    assert "tags.required is checked on templates, and this scan read none" in result.output
