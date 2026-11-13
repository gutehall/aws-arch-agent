"""SEC 1: control objectives (REPO-136), a smaller management scope (REPO-137), a threat model
(REPO-138) and new security services (REPO-139)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import ThreatModelMissing
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-136", "SEC01-BP03"), ("REPO-137", "SEC01-BP05"), ("REPO-138", "SEC01-BP07"),
          ("REPO-139", "SEC01-BP08"))
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
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False, rules_org=True)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_sec1() -> None:
    for rule_id, bp in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


@pytest.mark.parametrize("rule_id", [r for r, _ in _RULES])
@pytest.mark.parametrize("files", _SOURCES, ids=_IDS)
def test_iac_with_nothing_fails(tmp_path: Path, rule_id: str, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), rule_id)
    assert hit.question == "SEC 1"
    assert hit.severity == "Low" and hit.category == "Security"
    assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


@pytest.mark.parametrize("rule_id", [r for r, _ in _RULES])
def test_repo_without_iac_does_not_fire(tmp_path: Path, rule_id: str) -> None:
    assert not _found(_scan(tmp_path, {"README.md": "# app\n"}), rule_id)


@pytest.mark.parametrize(
    "files",
    [
        {"sh.tf": 'resource "aws_securityhub_standards_subscription" "s" {\n  standards_arn = "a"\n}\n'},
        {"sh.json": '{"Resources": {"S": {"Type": "AWS::SecurityHub::StandardsSubscription"}}}'},
        {"cfg.tf": 'resource "aws_config_conformance_pack" "c" {\n  name = "c"\n}\n'},
        {"cfg.json": '{"Resources": {"C": {"Type": "AWS::Config::OrganizationConformancePack"}}}'},
        {"lib/c.ts": "new config.CfnConformancePack(this, 'C', { conformancePackName: 'c' });\n"},
    ],
    ids=["tf-standard", "cfn-standard", "tf-pack", "cfn-org-pack", "cdk-pack"],
)
def test_control_objectives_pass(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-136")


@pytest.mark.parametrize(
    "files",
    [
        {"o.tf": 'resource "aws_organizations_delegated_administrator" "d" {\n  account_id = "1"\n}\n'},
        {"o.tf": 'resource "aws_guardduty_organization_admin_account" "g" {\n  admin_account_id = "1"\n}\n'},
        {"o.tf": 'resource "aws_controltower_control" "c" {\n  control_identifier = "x"\n}\n'},
        {"ct.json": '{"Resources": {"C": {"Type": "AWS::ControlTower::EnabledControl"}}}'},
    ],
    ids=["delegated", "guardduty-admin", "tf-control", "cfn-control"],
)
def test_security_scope_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-137")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("docs/threat-model.md", "# Assets\n"),
        ("security/threatmodel.json", "{}"),
        ("docs/design.md", "## Threat modeling\n\nSTRIDE per component.\n"),
        ("docs/model.threat-dragon.json", "{}"),
    ],
    ids=["named", "json", "heading", "threat-dragon"],
)
def test_threat_model_passes(tmp_path: Path, name: str, text: str) -> None:
    assert not _found(_scan(tmp_path, {**_TF, name: text}), "REPO-138")


@pytest.mark.parametrize(
    "files",
    [
        {"aa.tf": 'resource "aws_accessanalyzer_analyzer" "a" {\n  analyzer_name = "a"\n}\n'},
        {"aa.json": '{"Resources": {"A": {"Type": "AWS::AccessAnalyzer::Analyzer"}}}'},
        {"lib/i.ts": "new inspectorv2.CfnFilter(this, 'F', {});\n"},
        {"i.tf": 'resource "aws_inspector2_enabler" "e" {\n  account_ids = ["1"]\n}\n'},
        {"docs/security-review-2026-03.md": "Evaluated GuardDuty Malware Protection.\nDate: 2026-03-02\n"},
        {"docs/sec.md": "## Security service review\n\nReviewed in March 2026.\n"},
    ],
    ids=["tf-analyzer", "cfn-analyzer", "cdk-inspector", "tf-inspector", "dated-note",
         "dated-heading"],
)
def test_security_services_pass(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-139")


def test_undated_security_review_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/security-review.md": "We should review new services.\n"}
    assert _found(_scan(tmp_path, files), "REPO-139")


def test_threat_model_in_tests_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", _TF["main.tf"])
    _write(tmp_path / "tests" / "threat-model.md", "# x\n")
    assert ThreatModelMissing().run(tmp_path)
