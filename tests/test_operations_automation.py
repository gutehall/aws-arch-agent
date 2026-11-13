"""COST 11: EC2 operations are automated (REPO-160)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_INSTANCE = 'resource "aws_instance" "web" {\n  ami = "x"\n}\n'
_WORKFLOW = "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _hits(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-160"]


def test_rule_answers_cost11() -> None:
    assert RULE_BEST_PRACTICES["REPO-160"] == ("COST11-BP01",)
    assert "COST11-BP01" not in NOT_CHECKED


@pytest.mark.parametrize(
    "files",
    [
        {"i.tf": _INSTANCE},
        {"i.json": '{"Resources": {"I": {"Type": "AWS::EC2::Instance"}}}'},
        {"lib/s.ts": "new ec2.Instance(this, 'W', { instanceType, machineImage, vpc });\n"},
    ],
    ids=["terraform", "cloudformation", "cdk"],
)
def test_manual_instances_fire(tmp_path: Path, files: dict) -> None:
    (hit,) = _hits(_scan(tmp_path, files))
    assert hit.question == "COST 11" and hit.category == "Cost"
    assert hit.severity == "Low" and hit.file == next(iter(files))


@pytest.mark.parametrize(
    "extra",
    [
        {"a.tf": 'resource "aws_ssm_association" "a" {\n  name = "AWS-RunPatchBaseline"\n}\n'},
        {"m.tf": 'resource "aws_ssm_maintenance_window" "m" {\n  name = "m"\n}\n'},
        {"a.json": '{"Resources": {"A": {"Type": "AWS::SSM::Association"}}}'},
        {"lib/d.ts": "new ssm.CfnDocument(this, 'D', { content: {}, documentType: 'Automation' });\n"},
        {".github/workflows/ci.yml": _WORKFLOW},
        {"buildspec.yml": "version: 0.2\n"},
    ],
    ids=["tf-association", "tf-window", "cfn-association", "cdk-document", "workflow", "buildspec"],
)
def test_ssm_or_pipeline_passes(tmp_path: Path, extra: dict) -> None:
    assert not _hits(_scan(tmp_path, {"i.tf": _INSTANCE, **extra}))


def test_no_instances_does_not_fire(tmp_path: Path) -> None:
    files = {"f.tf": 'resource "aws_lambda_function" "f" {}\n'}
    assert not _hits(_scan(tmp_path, files))
