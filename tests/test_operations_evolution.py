"""OPS 11: lessons from incidents (REPO-176), feedback on changes (REPO-177) and the
improvement note (REPO-178)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-176", ("OPS11-BP02", "OPS11-BP08")), ("REPO-177", ("OPS11-BP03",)),
          ("REPO-178", ("OPS11-BP01", "OPS11-BP04", "OPS11-BP05", "OPS11-BP06", "OPS11-BP07",
                        "OPS11-BP09")))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / (rel[1:] if rel.startswith("/") else f"prod/{rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops11() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_every_rule(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    for rule_id, _ in _RULES:
        (hit,) = _found(findings, rule_id)
        assert hit.question == "OPS 11" and hit.category == "Operational Excellence"
        assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r, _ in _RULES)


@pytest.mark.parametrize(
    "files",
    [
        {"docs/post-incident-template.md": "## Timeline\n\n## Lessons learned\n"},
        {"docs/postmortems/2026-03-01.md": "Action items: add an alarm.\n"},
    ],
    ids=["template", "review"],
)
def test_post_incident_with_lessons_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-176")


def test_post_incident_without_lessons_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/postmortem.md": "## Timeline\n\nWhat broke.\n"}
    assert _found(_scan(tmp_path, files), "REPO-176")


@pytest.mark.parametrize(
    "files",
    [
        {"/.github/ISSUE_TEMPLATE/change.md": "What did it do?\n"},
        {"n.tf": 'resource "aws_codestarnotifications_notification_rule" "n" {}\n'},
        {"lib/n.ts": "rule.notifyOnExecutionStateChange('Chat', target);\n"},
        {"docs/retrospectives.md": "Weekly.\n"},
    ],
    ids=["issue-template", "tf", "cdk", "note"],
)
def test_feedback_loop_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-177")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/continuous-improvement.md": "We pick one fix a sprint.\n"},
        {"docs/team.md": "## Knowledge sharing\n\nWiki.\n"},
    ],
    ids=["named", "heading"],
)
def test_improvement_note_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-178")
