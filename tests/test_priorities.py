"""OPS 1: customers (REPO-161), governance and compliance (REPO-162), threats (REPO-163) and
tradeoffs (REPO-164)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-161", ("OPS01-BP01", "OPS01-BP02")), ("REPO-162", ("OPS01-BP03", "OPS01-BP04")),
          ("REPO-163", ("OPS01-BP05",)), ("REPO-164", ("OPS01-BP06",)))
_TF = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}


def _scan(root: Path, files: dict[str, str], org: bool = True) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False, rules_org=org)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops1() -> None:
    for rule_id, bps in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == bps
        assert not set(bps) & NOT_CHECKED


def test_bare_iac_fails_every_rule(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF)
    for rule_id, _ in _RULES:
        (hit,) = _found(findings, rule_id)
        assert hit.question == "OPS 1"
        assert hit.evidence.startswith("Holds IaC (") and hit.evidence.endswith("found none")


def test_repo_without_iac_does_not_fire(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"README.md": "# app\n"})
    assert not any(_found(findings, r) for r, _ in _RULES)


def test_account_level_rules_need_rules_org(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _TF, org=False)
    assert not _found(findings, "REPO-162") and not _found(findings, "REPO-163")
    assert _found(findings, "REPO-161") and _found(findings, "REPO-164")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/customers.md": "Paying shops and the support team.\n"},
        {"README.md": "# App\n\n## Stakeholders\n\nShops, support.\n"},
        {"docs/design.md": "## Business priorities\n\nSpeed first.\n"},
    ],
    ids=["named", "heading", "priorities"],
)
def test_customer_note_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-161")


@pytest.mark.parametrize(
    "files",
    [
        {"c.tf": 'resource "aws_config_conformance_pack" "c" {\n  name = "c"\n}\n'},
        {"c.json": '{"Resources": {"S": {"Type": "AWS::SecurityHub::Standard"}}}'},
        {"lib/p.ts": "new organizations.CfnPolicy(this, 'Scp', { type: 'SERVICE_CONTROL_POLICY' });\n"},
        {"docs/compliance.md": "We follow PCI DSS 4.0.\n"},
        {"docs/security.md": "## SOC 2\n\nControls map to CC6.\n"},
    ],
    ids=["tf-pack", "cfn-standard", "cdk-scp", "note", "heading"],
)
def test_governance_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-162")


@pytest.mark.parametrize(
    "files",
    [
        {"g.tf": 'resource "aws_guardduty_detector" "d" {\n  enable = true\n}\n'},
        {"g.json": '{"Resources": {"H": {"Type": "AWS::SecurityHub::Hub"}}}'},
        {"lib/g.ts": "new guardduty.CfnDetector(this, 'D', { enable: true });\n"},
        {"docs/threat-model.md": "Assets and threats.\n"},
    ],
    ids=["tf", "cfn", "cdk", "note"],
)
def test_threat_landscape_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-163")


@pytest.mark.parametrize(
    "files",
    [
        {"docs/adr/0001-queue.md": "# Queue or stream\n\nTradeoff: cost against ordering.\n"},
        {"docs/decisions.md": "# Decisions\n\nConsequences: we run a consumer.\n"},
    ],
    ids=["adr-folder", "decisions"],
)
def test_adr_with_tradeoff_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, {**_TF, **files}), "REPO-164")


def test_adr_without_a_tradeoff_fails(tmp_path: Path) -> None:
    files = {**_TF, "docs/adr/0001-queue.md": "# Queue\n\nWe use SQS.\n"}
    assert _found(_scan(tmp_path, files), "REPO-164")
