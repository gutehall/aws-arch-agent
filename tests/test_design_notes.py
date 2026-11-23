"""SUST-004 and SUST-005: design judgments a repo note answers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.sustainability import AsyncProcessingHint, ManagedServicesPreference


def _cf(root: Path, resources: dict[str, Any], note: str | None = None, name: str = "docs/adr/0003-batch.md") -> Path:
    (root / "template.json").write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    if note is not None:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(note, encoding="utf-8")
    return root


def _ids(root: Path) -> set[str]:
    _r, ctx, findings, _w = analyze_v1(root, use_llm=False)
    assert {"SUST-004", "SUST-005"} <= set(ctx.rules_run)  # repo-note rules run for every source
    return {f.id for f in findings}


_BATCH_JOB = {"Job": {"Type": "AWS::Batch::JobDefinition", "Properties": {"Type": "container"}}}
_GLUE = {"Etl": {"Type": "AWS::Glue::Job", "Properties": {"Command": {"Name": "glueetl"}}}}
_SCHEDULED_FN = {
    "Fn": {"Type": "AWS::Lambda::Function", "Properties": {}},
    "Nightly": {"Type": "AWS::Events::Rule", "Properties": {"ScheduleExpression": "cron(0 2 * * ? *)"}},
}
_SFN_MAP = {"Sm": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {"Definition": {
    "StartAt": "Each", "States": {"Each": {"Type": "Map", "End": True}}}}}}
_DB_TASK = {"Td": {"Type": "AWS::ECS::TaskDefinition", "Properties": {"ContainerDefinitions": [
    {"Name": "db", "Image": "postgres:16"}, {"Name": "cache", "Image": "public.ecr.aws/docker/library/redis:7"}]}}}
_HOST_DB = {"Vm": {"Type": "AWS::EC2::Instance", "Properties": {"ImageId": "ami-1", "UserData": {
    "Fn::Base64": "#!/bin/bash\nyum install -y mysql-server\nsystemctl enable --now mysqld\n"}}}}
_FN_ONLY = {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}}
_RDS = {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "postgres"}}}

_BATCH_NOTE = (
    "# Batch processing\n\nThe nightly batch job runs asynchronously from a queue, because the "
    "import can take an hour and no caller waits for it.\n"
)
_MANAGED_NOTE = (
    "# Self-managed components\n\nWe run postgres and redis in ECS ourselves because the "
    "extensions we need are not available in RDS or ElastiCache.\n"
)


@pytest.mark.parametrize("resources", [_BATCH_JOB, _GLUE, _SCHEDULED_FN, _SFN_MAP])
def test_batch_without_a_note_reports_once(tmp_path: Path, resources: dict) -> None:
    _r, _c, findings, _w = analyze_v1(_cf(tmp_path, resources), use_llm=False)
    got = [f for f in findings if f.id == "SUST-004"]
    assert len(got) == 1 and got[0].severity == "Low"
    assert got[0].title == AsyncProcessingHint.title and got[0].category == "Sustainability"
    assert "Batch work:" in (got[0].evidence or "")


def test_a_batch_note_answers_sust_004(tmp_path: Path) -> None:
    assert "SUST-004" not in _ids(_cf(tmp_path, _BATCH_JOB, _BATCH_NOTE))


def test_a_note_without_the_reason_does_not_answer(tmp_path: Path) -> None:
    note = "# Batch processing\n\nThe nightly batch job runs asynchronously.\n"
    assert "SUST-004" in _ids(_cf(tmp_path, _BATCH_JOB, note))


def test_no_batch_no_sust_004(tmp_path: Path) -> None:
    assert "SUST-004" not in _ids(_cf(tmp_path, _FN_ONLY))


@pytest.mark.parametrize("resources", [_DB_TASK, _HOST_DB])
def test_self_managed_without_a_note_reports_once(tmp_path: Path, resources: dict) -> None:
    _r, _c, findings, _w = analyze_v1(_cf(tmp_path, resources), use_llm=False)
    got = [f for f in findings if f.id == "SUST-005"]
    assert len(got) == 1 and got[0].severity == "Low"
    assert got[0].title == ManagedServicesPreference.title
    assert "Self-managed:" in (got[0].evidence or "")


def test_a_note_naming_each_component_answers_sust_005(tmp_path: Path) -> None:
    assert "SUST-005" not in _ids(_cf(tmp_path, _DB_TASK, _MANAGED_NOTE, "docs/architecture.md"))


def test_a_note_missing_one_component_does_not_answer(tmp_path: Path) -> None:
    note = "# Self-managed components\n\nWe run postgres ourselves because we need an extension.\n"
    assert "SUST-005" in _ids(_cf(tmp_path, _DB_TASK, note, "docs/architecture.md"))


def test_managed_stores_are_not_self_managed(tmp_path: Path) -> None:
    assert "SUST-005" not in _ids(_cf(tmp_path, {**_RDS, **_FN_ONLY}))


def test_terraform_sources(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_glue_job" "etl" {\n  name = "etl"\n}\n'
        'resource "aws_ecs_task_definition" "t" {\n  container_definitions = jsonencode([{ name = "q", image = "rabbitmq:3" }])\n}\n',
        encoding="utf-8",
    )
    _r, _c, findings, _w = analyze_v1(tmp_path, use_llm=False)
    got = {f.id: f for f in findings}
    assert {"SUST-004", "SUST-005"} <= set(got)
    assert "rabbitmq" in (got["SUST-005"].evidence or "")


def test_dev_paths_do_not_count(tmp_path: Path) -> None:
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev" / "template.json").write_text(json.dumps({"Resources": _DB_TASK}), encoding="utf-8")
    assert "SUST-005" not in _ids(tmp_path)
