"""SEC 4: security findings meet in one place (REPO-033)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    SecurityFindingsUncorrelated,
    finding_destinations,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict[str, tuple[str, dict]]) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }}, indent=2)


DETECTOR = {
    "cdk": "new guardduty.CfnDetector(this, 'Detector', { enable: true });\n",
    "cloudformation": {"Detector": ("AWS::GuardDuty::Detector", {"Enable": True})},
    "terraform": 'resource "aws_guardduty_detector" "main" {\n  enable = true\n}\n',
}
HUB = {
    "cdk": "new securityhub.CfnHub(this, 'Hub');\n",
    "cloudformation": {"Hub": ("AWS::SecurityHub::Hub", {})},
    "terraform": 'resource "aws_securityhub_account" "main" {}\n',
}
LAKE = {
    "cdk": "new securitylake.CfnDataLake(this, 'Lake', {});\n",
    "cloudformation": {"Lake": ("AWS::SecurityLake::DataLake", {})},
    "terraform": 'resource "aws_securitylake_data_lake" "main" {\n  meta_store_manager_role_arn = "x"\n}\n',
}
ROUTE = {
    "cdk": "new events.Rule(this, 'Findings', { eventPattern: { source: ['aws.guardduty'] }, "
           "targets: [new targets.SnsTopic(topic)] });\n",
    "cloudformation": {"Findings": ("AWS::Events::Rule", {
        "EventPattern": {"source": ["aws.guardduty"]},
        "Targets": [{"Arn": "arn:aws:sns:eu-west-1:1:sec", "Id": "sns"}]})},
    "terraform": 'resource "aws_cloudwatch_event_rule" "findings" {\n'
                 '  event_pattern = jsonencode({ source = ["aws.guardduty"] })\n}\n'
                 'resource "aws_cloudwatch_event_target" "sns" {\n'
                 "  rule = aws_cloudwatch_event_rule.findings.name\n  arn = var.topic\n}\n",
}


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        resources: dict = {}
        for part in parts:
            resources.update(part)  # type: ignore[call-overload]
        body = _cfn(resources)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / "prod" / _PATHS[source], body)


@pytest.mark.parametrize("source", SOURCES)
def test_detector_with_no_destination_fails_repo_033(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, DETECTOR[source])
    (finding,) = SecurityFindingsUncorrelated().run(tmp_path)
    assert finding.id == "REPO-033"
    assert "GuardDuty detector" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("destination", [HUB, LAKE, ROUTE], ids=["hub", "lake", "route"])
def test_detector_with_a_destination_passes(
    tmp_path: Path, source: str, destination: dict
) -> None:
    _stack(tmp_path, source, DETECTOR[source], destination[source])
    assert SecurityFindingsUncorrelated().run(tmp_path) == []


def test_no_detector_gets_no_finding(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_s3_bucket" "d" {\n  bucket = "d"\n}\n')
    assert SecurityFindingsUncorrelated().run(tmp_path) == []


def test_a_rule_without_a_target_is_not_a_destination(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", DETECTOR["cloudformation"], {"Findings": (
        "AWS::Events::Rule", {"EventPattern": {"source": ["aws.guardduty"]}})})
    assert SecurityFindingsUncorrelated().run(tmp_path)


def test_a_route_covers_only_the_source_it_names(tmp_path: Path) -> None:
    config = 'resource "aws_config_config_rule" "s3" {\n  name = "s3"\n}\n'
    _stack(tmp_path, "terraform", DETECTOR["terraform"], ROUTE["terraform"], config)
    (finding,) = SecurityFindingsUncorrelated().run(tmp_path)
    assert "AWS Config" in finding.evidence
    assert "GuardDuty" not in finding.evidence
    detectors, routed, hub = finding_destinations(tmp_path)
    assert set(detectors) == {"GuardDuty detector", "AWS Config"}
    assert routed == {"guardduty"}
    assert not hub


@pytest.mark.parametrize("detector", [
    "new config.ManagedRule(this, 'Encrypted', { identifier });\n",
    "new inspectorv2.CfnFilter(this, 'Suppress', { name, filterAction, filterCriteria });\n",
    "new macie.CfnSession(this, 'Macie', {});\n",
    "new accessanalyzer.CfnAnalyzer(this, 'Analyzer', { type: 'ACCOUNT' });\n",
])
def test_each_detector_kind_is_seen(tmp_path: Path, detector: str) -> None:
    _stack(tmp_path, "cdk", detector)
    assert SecurityFindingsUncorrelated().run(tmp_path)
    _stack(tmp_path, "cdk", detector, HUB["cdk"])
    assert SecurityFindingsUncorrelated().run(tmp_path) == []


def test_python_cdk(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py", "guardduty.CfnDetector(self, 'D', enable=True)\n")
    assert SecurityFindingsUncorrelated().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py",
           "guardduty.CfnDetector(self, 'D', enable=True)\nsecurityhub.CfnHub(self, 'Hub')\n")
    assert SecurityFindingsUncorrelated().run(tmp_path) == []


def test_a_hub_only_in_tests_does_not_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", DETECTOR["cdk"])
    _write(tmp_path / "test" / "stack.test.ts", HUB["cdk"])
    assert SecurityFindingsUncorrelated().run(tmp_path)


def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", DETECTOR["cdk"])
    (hit,) = SecurityFindingsUncorrelated().run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    _write(tmp_path / "reports" / "report.json", report)
    assert len(SecurityFindingsUncorrelated().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    assert SecurityFindingsUncorrelated().run(empty) == []


def test_repo_033_runs_by_default_and_answers_sec04_bp03() -> None:
    assert "REPO-033" not in ORG_RULE_IDS
    assert well_architected.best_practices_of("REPO-033") == ("SEC04-BP03",)
    assert well_architected.question_of("REPO-033") == "SEC 4"


def test_sec4_is_fully_checked_and_reads_met_without_findings() -> None:
    (sec4,) = [a for a in well_architected.answers([]) if a.question.id == "SEC 4"]
    assert sec4.not_checked == ()
    assert sec4.met
