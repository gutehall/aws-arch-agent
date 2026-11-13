"""OPS 3: escalation (REPO-169), the operator channel (REPO-170) and the operations
ownership note (REPO-171)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-169", ("OPS03-BP03",)), ("REPO-170", ("OPS03-BP04",)),
          ("REPO-171", ("OPS03-BP01", "OPS03-BP02", "OPS03-BP05", "OPS03-BP06", "OPS03-BP07")))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops3() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_every_rule(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    for rule_id, _ in _RULES:
        (hit,) = _found(findings, rule_id)
        assert hit.question == "OPS 3" and hit.category == "Operational Excellence"
        assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r, _ in _RULES)


@pytest.mark.parametrize(
    "files",
    [
        {"p.tf": 'resource "aws_ssmcontacts_plan" "p" {}\n'},
        {"p.json": '{"Resources": {"P": {"Type": "AWS::SSMContacts::Plan"}}}'},
        {"lib/p.ts": "new ssmcontacts.CfnPlan(this, 'P', { contactId });\n"},
        {"docs/escalation.md": "After 15 minutes page the lead.\n"},
    ],
    ids=["tf", "cfn", "cdk", "note"],
)
def test_escalation_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-169")


@pytest.mark.parametrize(
    "files",
    [
        {"c.tf": 'resource "aws_sns_topic_subscription" "s" {\n  protocol = "email"\n}\n'},
        {"c.json": '{"Resources": {"C": {"Type": "AWS::Chatbot::SlackChannelConfiguration"}}}'},
        {"lib/c.ts": "topic.addSubscription(new subs.EmailSubscription('ops@example.com'));\n"},
        {"docs/on-call.md": "Page the platform rota.\n"},
    ],
    ids=["tf", "cfn", "cdk", "note"],
)
def test_operator_channel_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-170")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/ops-ownership.md": "Sponsor: the CTO.\n"},
        {"docs/team.md": "## Team charter\n\nWe own what we run.\n"},
    ],
    ids=["named", "heading"],
)
def test_operations_note_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-171")
