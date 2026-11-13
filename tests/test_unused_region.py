"""SUS 1: a Region no resource uses (REPO-189)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
_ALIAS = 'provider "aws" {\n  alias  = "east"\n  region = "us-east-1"\n}\n'


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / (rel[1:] if rel.startswith("/") else f"prod/{rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rule_answers_sus1() -> None:
    assert RULE_BEST_PRACTICES["REPO-189"] == ("SUS01-BP01",)
    assert "SUS01-BP01" not in NOT_CHECKED


def test_unused_provider_alias_fires(tmp_path: Path) -> None:
    (hit,) = _found(_scan(tmp_path, {**_TF, "p.tf": _ALIAS}), "REPO-189")
    assert hit.question == "SUS 1" and hit.category == "Sustainability"
    assert hit.file == "prod/p.tf" and hit.line == 1


@pytest.mark.parametrize(
    "files",
    [
        {"p.tf": _ALIAS + 'resource "aws_s3_bucket" "r" {\n  provider = aws.east\n}\n'},
        {"p.tf": _ALIAS + 'module "m" {\n  source = "./m"\n  providers = { aws = aws.east }\n}\n'},
        {"p.tf": 'provider "aws" {\n  region = "eu-west-1"\n}\n'},
    ],
    ids=["resource", "module", "no-alias"],
)
def test_used_or_absent_alias_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-189")
