"""REL 12: failure playbooks (REPO-122), post-incident analysis (REPO-123) and game days
(REPO-124)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import (
    FailurePlaybookMissing,
    GameDayMissing,
    PostIncidentAnalysisMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-122", "REL12-BP01"), ("REPO-123", "REL12-BP02"), ("REPO-124", "REL12-BP05"))
_SOURCES = [
    {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'},
    {"t.json": '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"B": '
               '{"Type": "AWS::S3::Bucket"}}}'},
    {"cdk.json": "{}", "lib/stack.ts": "new s3.Bucket(this, 'B');\n"},
]
_IDS = ["terraform", "cloudformation", "cdk"]
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_rel12() -> None:
    for rule_id, bp in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


@pytest.mark.parametrize("rule_id", [r for r, _ in _RULES])
@pytest.mark.parametrize("files", _SOURCES, ids=_IDS)
def test_iac_with_no_note_fails(tmp_path: Path, rule_id: str, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), rule_id)
    assert hit.question == "REL 12"
    assert hit.severity == "Low" and hit.category == "Reliability"
    assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


@pytest.mark.parametrize("rule_id", [r for r, _ in _RULES])
def test_repo_without_iac_does_not_fire(tmp_path: Path, rule_id: str) -> None:
    assert not _found(_scan(tmp_path, {"README.md": "# app\n"}), rule_id)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("docs/playbooks/database-failover.md", "Symptoms: errors.\n"),
        ("PLAYBOOK.md", "# How to investigate\n"),
        ("docs/ops.md", "## Failure playbooks\n\nOpen the dashboard.\n"),
        ("docs/troubleshooting-guide.md", "Check the logs.\n"),
    ],
    ids=["dir", "named", "heading", "troubleshooting"],
)
def test_playbook_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _found(_scan(tmp_path, {**_TF, name: text}), "REPO-122")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("docs/postmortem-template.md", "# Timeline\n"),
        (".github/ISSUE_TEMPLATE/post-incident-review.md", "## Root cause\n"),
        ("docs/incidents.md", "## Post-incident analysis\n\nWhat happened.\n"),
        ("docs/rca-2026-03.md", "Root cause: a full disk.\n"),
    ],
    ids=["postmortem", "issue-template", "heading", "rca"],
)
def test_post_incident_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _found(_scan(tmp_path, {**_TF, name: text}), "REPO-123")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("docs/game-days.md", "Quarterly.\n"),
        ("GAMEDAY.md", "Plan.\n"),
        ("docs/reliability.md", "## Game day schedule\n\nQ1: AZ loss.\n"),
    ],
    ids=["named", "gameday", "heading"],
)
def test_game_day_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _found(_scan(tmp_path, {**_TF, name: text}), "REPO-124")


def test_notes_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", _TF["main.tf"])
    for name in ("playbook.md", "postmortem.md", "game-day.md"):
        _write(tmp_path / "tests" / name, "x\n")
    assert FailurePlaybookMissing().run(tmp_path)
    assert PostIncidentAnalysisMissing().run(tmp_path)
    assert GameDayMissing().run(tmp_path)
