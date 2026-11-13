"""SEC 10: contacts (REPO-125), an incident plan (REPO-126), security playbooks (REPO-127),
pre-provisioned response access (REPO-128), simulations (REPO-129) and learning from
incidents (REPO-130)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import (
    IncidentLearningMissing,
    KeyContactsMissing,
    ResponseAccessMissing,
    SecurityPlaybookMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-125", "SEC10-BP01"), ("REPO-126", "SEC10-BP02"), ("REPO-127", "SEC10-BP04"),
          ("REPO-128", "SEC10-BP05"), ("REPO-129", "SEC10-BP07"), ("REPO-130", "SEC10-BP08"))
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


def test_rules_answer_sec10() -> None:
    for rule_id, bp in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


@pytest.mark.parametrize("rule_id", [r for r, _ in _RULES])
@pytest.mark.parametrize("files", _SOURCES, ids=_IDS)
def test_iac_with_nothing_fails(tmp_path: Path, rule_id: str, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), rule_id)
    assert hit.question == "SEC 10"
    assert hit.severity == "Low" and hit.category == "Security"
    assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


@pytest.mark.parametrize("rule_id", [r for r, _ in _RULES])
def test_repo_without_iac_does_not_fire(tmp_path: Path, rule_id: str) -> None:
    assert not _found(_scan(tmp_path, {"README.md": "# app\n"}), rule_id)


@pytest.mark.parametrize(
    "files",
    [
        {"c.tf": 'resource "aws_ssmcontacts_contact" "c" {\n  alias = "sec"\n}\n'},
        {"c.json": '{"Resources": {"C": {"Type": "AWS::SSMContacts::Contact"}}}'},
        {"lib/c.ts": "new ssmcontacts.CfnContact(this, 'C', { alias: 'sec', type: 'PERSONAL' });\n"},
        {"docs/security-contacts.md": "Alice: 555-0100\n"},
        {"docs/ops.md": "## On-call\n\nRota in PagerDuty.\n"},
    ],
    ids=["terraform", "cloudformation", "cdk", "note", "heading"],
)
def test_contacts_pass(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-125")


@pytest.mark.parametrize(
    "files",
    [
        {"p.tf": 'resource "aws_ssmincidents_response_plan" "p" {\n  name = "p"\n}\n'},
        {"docs/incident-response-plan.md": "Scope.\n"},
        {"docs/security.md": "## Incident response\n\nWho leads.\n"},
    ],
    ids=["plan-resource", "plan-note", "heading"],
)
def test_incident_plan_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-126")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/security-playbooks/leaked-keys.md": "Steps.\n"},
        {"docs/ir-playbook.md": "Steps.\n"},
        {"docs/security.md": "## Security incident playbooks\n\nSee below.\n"},
    ],
    ids=["dir", "named", "heading"],
)
def test_security_playbook_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-127")


def test_generic_playbook_is_not_a_security_playbook(tmp_path: Path) -> None:
    assert _found(_scan(tmp_path, {**_TF, "docs/playbook.md": "How to restart.\n"}), "REPO-127")


@pytest.mark.parametrize(
    "files",
    [
        {"iam.tf": 'resource "aws_iam_role" "ir" {\n  name = "IncidentResponder"\n}\n'},
        {"iam.json": '{"Resources": {"R": {"Type": "AWS::IAM::Role", "Properties": '
                     '{"RoleName": "security-investigator"}}}}'},
        {"lib/iam.ts": "new iam.Role(this, 'ForensicsRole', { roleName: 'forensic-analyst', "
                       "assumedBy });\n"},
        {"sso.tf": 'resource "aws_ssoadmin_permission_set" "p" {\n  name = "SecurityIR"\n}\n'},
    ],
    ids=["terraform", "cloudformation", "cdk", "permission-set"],
)
def test_response_access_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-128")


def test_ordinary_role_is_not_response_access(tmp_path: Path) -> None:
    files = {**_TF, "iam.tf": 'resource "aws_iam_role" "app" {\n  name = "app-role"\n}\n'}
    assert _found(_scan(tmp_path, files), "REPO-128")


@pytest.mark.parametrize(
    "files",
    [
        {"fis.tf": 'resource "aws_fis_experiment_template" "t" {\n  description = "d"\n}\n'},
        {"fis.json": '{"Resources": {"T": {"Type": "AWS::FIS::ExperimentTemplate"}}}'},
        {"lib/fis.ts": "new fis.CfnExperimentTemplate(this, 'T', {});\n"},
    ],
    ids=["terraform", "cloudformation", "cdk"],
)
def test_simulation_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-129")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/security-postmortem-template.md": "# Timeline\n"},
        {"docs/security.md": "## Security post-incident review\n\nFollow-ups.\n"},
    ],
    ids=["named", "heading"],
)
def test_security_learning_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-130")


def test_general_postmortem_is_not_a_security_one(tmp_path: Path) -> None:
    files = {**_TF, "docs/postmortem-template.md": "# Timeline\n"}
    assert _found(_scan(tmp_path, files), "REPO-130")


def test_notes_and_roles_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", _TF["main.tf"])
    _write(tmp_path / "tests" / "security-playbook.md", "x\n")
    _write(tmp_path / "tests" / "security-postmortem.md", "x\n")
    _write(tmp_path / "tests" / "iam.tf", 'resource "aws_iam_role" "ir" {\n  name = "IncidentResponder"\n}\n')
    _write(tmp_path / "tests" / "contacts.md", "x\n")
    assert SecurityPlaybookMissing().run(tmp_path)
    assert IncidentLearningMissing().run(tmp_path)
    assert ResponseAccessMissing().run(tmp_path)
    assert KeyContactsMissing().run(tmp_path)
