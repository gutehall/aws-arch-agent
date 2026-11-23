"""CF-TAG-002: compute, data stores and edges carry a created-by and an owner tag (COST04-BP01)."""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform
from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

TAGS = [{"Key": "managed-by", "Value": "cdk"}, {"Key": "TEAM", "Value": "payments"}]


def _found(found: list[Finding]) -> list[Finding]:
    out = [f for f in found if f.id == "CF-TAG-002"]
    assert all(f.severity == "Low" for f in out)
    return out


def _cf(tmp_path: Path, resources: dict, folder: str = ".") -> list[Finding]:
    out = tmp_path / folder
    out.mkdir(exist_ok=True)
    path = out / "Stack.template.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return _found(run_cf_rules_from_paths([path], repo_path=tmp_path))


def _tf(tmp_path: Path, text: str) -> list[Finding]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    return _found(run_resource_checks(resources_from_terraform(tmp_path), tmp_path / "main.tf"))


def _bucket(tags: list | None = None) -> dict:
    return {"Type": "AWS::S3::Bucket", "Properties": {"Tags": tags} if tags is not None else {}}


def test_answers_cost04_bp01_only() -> None:
    assert RULE_BEST_PRACTICES["CF-TAG-002"] == ("COST04-BP01",)


def test_cf_resource_tags_pass_in_any_case(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"B": _bucket(TAGS)}) == []


def test_cf_missing_owner_or_created_by(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"B": _bucket([{"Key": "Owner", "Value": "o"}]), "C": _bucket([])})
    assert len(found) == 1
    assert found[0].evidence.startswith("B (AWS::S3::Bucket): no created-by tag")
    assert "1 more" in found[0].evidence


def test_cf_stack_with_no_workload_or_unreadable_tags_is_not_judged(tmp_path: Path) -> None:
    queue = {"Type": "AWS::SQS::Queue", "Properties": {}}
    assert _cf(tmp_path, {"Q": queue}) == []
    assert _cf(tmp_path, {"B": _bucket({"Ref": "Tags"})}) == []  # type: ignore[arg-type]


def _cdk(tags: list) -> dict:
    """What cdk synth writes for Tags.of(app).add(...): the tags on each taggable resource."""
    return {"Type": "AWS::Lambda::Function", "Metadata": {"aws:cdk:path": "App/Stack/Fn/Resource"},
            "Properties": {"Role": "arn:aws:iam::1:role/r", "Code": {"ZipFile": "x"}, "Handler": "i.h",
                           "Runtime": "python3.13", "Tags": tags}}


def test_cdk_app_tags_on_each_resource(tmp_path: Path) -> None:
    app = [{"Key": "CreatedBy", "Value": "cdk"}, {"Key": "Owner", "Value": "o"}]
    assert _cf(tmp_path, {"Fn": _cdk(app)}, "cdk.out") == []
    found = _cf(tmp_path, {"Fn": _cdk([{"Key": "Owner", "Value": "o"}])}, "cdk.out")
    assert [f.evidence.split(" ")[0] for f in found] == ["Fn"]


_TF_BUCKET = 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n'


def test_tf_default_tags_count(tmp_path: Path) -> None:
    provider = ('provider "aws" {\n  default_tags {\n    tags = {\n      Repository = "org/app"\n'
                '      CostOwner = "finance"\n    }\n  }\n}\n')
    assert _tf(tmp_path, provider + _TF_BUCKET) == []


def test_tf_missing_tags(tmp_path: Path) -> None:
    provider = 'provider "aws" {\n  default_tags {\n    tags = {\n      Team = "a"\n    }\n  }\n}\n'
    found = _tf(tmp_path, provider + _TF_BUCKET)
    assert len(found) == 1 and "no created-by tag" in found[0].evidence
    assert len(_tf(tmp_path, _TF_BUCKET)) == 1


def test_tf_resource_tags_and_unreadable_tags(tmp_path: Path) -> None:
    tagged = 'resource "aws_s3_bucket" "data" {\n  tags = {\n    iac = "terraform"\n    owner = "a"\n  }\n}\n'
    assert _tf(tmp_path, tagged) == []
    from_var = 'resource "aws_s3_bucket" "data" {\n  tags = var.tags\n}\n'
    assert _tf(tmp_path, from_var) == []
