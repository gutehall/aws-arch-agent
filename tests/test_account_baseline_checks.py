"""Account baseline resources a repo defines: CF-GD-001, CF-SH-001, CF-CFG-001, CF-MACIE-001, CF-BUDGET-001."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import (
    CF_COVERS_STATIC,
    CF_PARTLY_COVERS_STATIC,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.resource_model import Resource
from aws_arch_agent.rules.terraform_model import resources_from_terraform

SEVERITY = {"CF-GD-001": "Medium", "CF-SH-001": "Low", "CF-CFG-001": "Medium", "CF-MACIE-001": "Low",
            "CF-BUDGET-001": "Low"}
_PARAM = {"Ref": "Param"}
_FSBP = "arn:aws:securityhub:eu-west-1::standards/aws-foundational-security-best-practices/v/1.0.0"
_CIS = "arn:aws:securityhub:eu-west-1::standards/cis-aws-foundations-benchmark/v/1.4.0"


def _keep(found: list[Finding]) -> list[Finding]:
    kept = [f for f in found if f.id in SEVERITY]
    for f in kept:
        assert f.severity == SEVERITY[f.id]
    return kept


def _cf_findings(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _keep(found)


def _cf(tmp_path: Path, **resources: dict) -> set[str]:
    return {f"{f.id}:{(f.evidence or '').split(' ')[0]}" for f in _cf_findings(tmp_path, resources)}


def _tf_findings(tmp_path: Path, text: str) -> list[Finding]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _keep(run_resource_checks(resources, tmp_path / "main.tf"))


def _tf(tmp_path: Path, text: str) -> set[str]:
    return {f"{f.id}:{(f.evidence or '').split(' ')[0]}" for f in _tf_findings(tmp_path, text)}


def _detector(**props: Any) -> dict:
    return {"Type": "AWS::GuardDuty::Detector", "Properties": {"Enable": True, **props}}


def _hub(**props: Any) -> dict:
    return {"Type": "AWS::SecurityHub::Hub", "Properties": props}


def _standard(arn: Any) -> dict:
    return {"Type": "AWS::SecurityHub::Standard", "Properties": {"StandardsArn": arn}}


def _recorder(group: Any = None) -> dict:
    props = {"RoleARN": "arn:aws:iam::1:role/r"}
    return {"Type": "AWS::Config::ConfigurationRecorder",
            "Properties": props if group is None else {**props, "RecordingGroup": group}}


def _budget(**props: Any) -> dict:
    return {"Type": "AWS::Budgets::Budget", "Properties": {"Budget": {"BudgetType": "COST", "TimeUnit": "MONTHLY"}, **props}}


_NO_HUB_STANDARDS = _hub(EnableDefaultStandards=False)
_S3_OFF_TF = 'datasources {\n s3_logs {\n enable = false\n }\n }\n'


# --- GuardDuty ---

@pytest.mark.parametrize("value", [False, "false"])
def test_gd_detector_turned_off(tmp_path: Path, value: Any) -> None:
    assert _cf(tmp_path, D=_detector(Enable=value)) == {"CF-GD-001:D"}


@pytest.mark.parametrize("sources", [
    {"S3Logs": {"Enable": False}},
    {"Kubernetes": {"AuditLogs": {"Enable": False}}},
    {"MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": False}}},
])
def test_gd_legacy_data_source_off(tmp_path: Path, sources: dict) -> None:
    assert _cf(tmp_path, D=_detector(DataSources=sources)) == {"CF-GD-001:D"}


@pytest.mark.parametrize("name", ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION"])
def test_gd_feature_disabled(tmp_path: Path, name: str) -> None:
    assert _cf(tmp_path, D=_detector(Features=[{"Name": name, "Status": "DISABLED"}])) == {"CF-GD-001:D"}


def test_gd_names_each_control_and_reports_a_detector_once(tmp_path: Path) -> None:
    found = _cf_findings(tmp_path, {"D": _detector(Features=[
        {"Name": "S3_DATA_EVENTS", "Status": "DISABLED"},
        {"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"},
        {"Name": "EBS_MALWARE_PROTECTION", "Status": "DISABLED"},
    ])})
    assert len(found) == 1
    for control in ("GuardDuty.10", "GuardDuty.5", "GuardDuty.8"):
        assert f"Security Hub {control})" in found[0].recommendation


@pytest.mark.parametrize("props", [
    {},  # unset: features may be on by default
    {"Enable": _PARAM},
    {"DataSources": {"S3Logs": {"Enable": True}}},
    {"DataSources": {"S3Logs": {"Enable": _PARAM}}},
    {"DataSources": _PARAM},
    {"DataSources": {"Fn::If": ["C", {"S3Logs": {"Enable": False}}, {}]}},
    {"Features": _PARAM},
    {"Features": [{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}]},
    {"Features": [{"Name": "S3_DATA_EVENTS", "Status": _PARAM}]},
    {"Features": [{"Name": _PARAM, "Status": "DISABLED"}]},
    {"Features": [{"Name": "RDS_LOGIN_EVENTS", "Status": "DISABLED"}]},
    # What may turn the feature on wins over what sets it off.
    {"DataSources": {"S3Logs": {"Enable": False}}, "Features": [{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}]},
    {"DataSources": {"S3Logs": {"Enable": False}}, "Features": [{"Fn::If": ["C", {}, {}]}]},
])
def test_gd_cloudformation_not_judged(tmp_path: Path, props: dict) -> None:
    assert _cf(tmp_path, D=_detector(**props)) == set()


def test_gd_terraform_turned_off(tmp_path: Path) -> None:
    assert _tf(tmp_path, 'resource "aws_guardduty_detector" "d" {\n enable = false\n}\n') == {
        "CF-GD-001:aws_guardduty_detector.d"}


@pytest.mark.parametrize("block", [
    _S3_OFF_TF,
    'datasources {\n kubernetes {\n audit_logs {\n enable = false\n }\n }\n }\n',
    'datasources {\n malware_protection {\n scan_ec2_instance_with_findings {\n ebs_volumes {\n'
    ' enable = false\n }\n }\n }\n }\n',
])
def test_gd_terraform_data_source_off(tmp_path: Path, block: str) -> None:
    assert _tf(tmp_path, f'resource "aws_guardduty_detector" "d" {{\n{block}}}\n') == {
        "CF-GD-001:aws_guardduty_detector.d"}


@pytest.mark.parametrize("body", [
    "",
    "enable = true\n",
    "enable = var.x\n",
    'datasources {\n s3_logs {\n enable = true\n }\n }\n',
    'datasources {\n s3_logs {\n enable = var.x\n }\n }\n',
    'dynamic "datasources" {\n for_each = var.x\n content {\n s3_logs {\n enable = false\n }\n }\n }\n',
    'datasources {\n dynamic "s3_logs" {\n for_each = var.x\n content {\n enable = false\n }\n }\n }\n',
])
def test_gd_terraform_not_judged(tmp_path: Path, body: str) -> None:
    text = f'variable "x" {{}}\nresource "aws_guardduty_detector" "d" {{\n{body}}}\n'
    assert _tf(tmp_path, text) == set()


def _feature(label: str, detector: str, name: str, status: str) -> str:
    return (f'resource "aws_guardduty_detector_feature" "{label}" {{\n detector_id = {detector}\n'
            f' name = {name}\n status = {status}\n}}\n')


_TF_D = 'variable "x" {}\nresource "aws_guardduty_detector" "d" {}\n'
_TF_E = 'resource "aws_guardduty_detector" "e" {}\n'
_D_ID = "aws_guardduty_detector.d.id"


def test_gd_terraform_tied_feature_off_fires_only_on_its_detector(tmp_path: Path) -> None:
    text = _TF_D + _TF_E + _feature("f", _D_ID, '"S3_DATA_EVENTS"', '"DISABLED"')
    assert _tf(tmp_path, text) == {"CF-GD-001:aws_guardduty_detector.d"}


@pytest.mark.parametrize(("detector", "name", "status"), [
    (_D_ID, '"S3_DATA_EVENTS"', '"ENABLED"'),
    (_D_ID, '"S3_DATA_EVENTS"', "var.x"),
    (_D_ID, "var.x", '"DISABLED"'),
    (_D_ID, '"RDS_LOGIN_EVENTS"', '"DISABLED"'),
    ("var.x", '"S3_DATA_EVENTS"', '"DISABLED"'),  # cannot be tied, so not known to be this detector
    ("var.x", '"S3_DATA_EVENTS"', '"ENABLED"'),
])
def test_gd_terraform_feature_not_judged(tmp_path: Path, detector: str, name: str, status: str) -> None:
    assert _tf(tmp_path, _TF_D + _feature("f", detector, name, status)) == set()


@pytest.mark.parametrize(("detector", "status"), [
    (_D_ID, '"ENABLED"'),  # tied and on
    ("var.x", '"ENABLED"'),  # cannot be tied: counts for all detectors
    (_D_ID, "var.x"),
])
def test_gd_terraform_feature_resource_may_turn_on_what_a_block_sets_off(
    tmp_path: Path, detector: str, status: str
) -> None:
    text = (f'variable "x" {{}}\nresource "aws_guardduty_detector" "d" {{\n{_S3_OFF_TF}}}\n'
            + _feature("f", detector, '"S3_DATA_EVENTS"', status))
    assert _tf(tmp_path, text) == set()


def test_gd_feature_resource_alone_reports_nothing(tmp_path: Path) -> None:
    text = 'variable "x" {}\n' + _feature("f", "var.x", '"S3_DATA_EVENTS"', '"DISABLED"')
    assert _tf(tmp_path, text) == set()


def test_gd_malformed_feature_resource_may_turn_a_feature_on(tmp_path: Path) -> None:
    detector = Resource(type="guardduty_detector", name="d", source_type="aws_guardduty_detector",
                        properties={"DataSources": {"S3Logs": {"Enable": False}}})
    broken = Resource(type="guardduty_detector_feature", name="f", malformed="unreadable",
                      source_type="aws_guardduty_detector_feature")
    assert _keep(run_resource_checks([detector], tmp_path / "main.tf"))
    assert _keep(run_resource_checks([detector, broken], tmp_path / "main.tf")) == []


def test_gd_remote_module_may_define_features(tmp_path: Path) -> None:
    text = (f'resource "aws_guardduty_detector" "d" {{\n{_S3_OFF_TF}}}\n'
            'module "m" {\n source = "terraform-aws-modules/x/aws"\n}\n')
    assert _tf(tmp_path, text) == set()


def test_gd_module_does_not_hide_a_detector_turned_off(tmp_path: Path) -> None:
    text = ('resource "aws_guardduty_detector" "d" {\n enable = false\n}\n'
            'module "m" {\n source = "terraform-aws-modules/x/aws"\n}\n')
    assert _tf(tmp_path, text) == {"CF-GD-001:aws_guardduty_detector.d"}


# --- Security Hub ---

def test_sh_default_standards_off_and_no_fsbp(tmp_path: Path) -> None:
    assert _cf(tmp_path, H=_NO_HUB_STANDARDS) == {"CF-SH-001:H"}
    assert _cf(tmp_path, H=_NO_HUB_STANDARDS, C=_standard(_CIS)) == {"CF-SH-001:H"}


@pytest.mark.parametrize("resources", [
    {"H": _hub()},  # unset turns the default standards on
    {"H": _hub(EnableDefaultStandards=True)},
    {"H": _hub(EnableDefaultStandards=_PARAM)},
    {"H": _NO_HUB_STANDARDS, "S": _standard(_FSBP)},
    {"H": _NO_HUB_STANDARDS, "S": _standard(_PARAM)},
    {"H": _NO_HUB_STANDARDS, "S": _standard({"Fn::Sub": "arn:${AWS::Partition}:securityhub:::standards/x"})},
    {"H": _NO_HUB_STANDARDS, "S": {"Type": "AWS::SecurityHub::Standard", "Properties": {}}},
    {"H": _NO_HUB_STANDARDS, "S": {"Type": "AWS::SecurityHub::Standard", "Properties": "broken"}},
    {"H": _NO_HUB_STANDARDS, "P": {"Type": "AWS::SecurityHub::ConfigurationPolicy", "Properties": {}}},
    {"H": _NO_HUB_STANDARDS, "N": {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "u"}}},
    {"S": _standard(_CIS)},
    {"H": {"Type": "AWS::SecurityHub::HubV2", "Properties": {}}},
])
def test_sh_cloudformation_not_judged(tmp_path: Path, resources: dict) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    found = _keep(run_cf_rules_from_paths([path], repo_path=tmp_path))  # a broken resource warns
    assert found == []


_TF_HUB_OFF = 'variable "x" {}\nresource "aws_securityhub_account" "h" {\n enable_default_standards = false\n}\n'


def _tf_standard(arn: str) -> str:
    return f'resource "aws_securityhub_standards_subscription" "s" {{\n standards_arn = {arn}\n}}\n'


def test_sh_terraform_fires(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_HUB_OFF) == {"CF-SH-001:aws_securityhub_account.h"}
    assert _tf(tmp_path, _TF_HUB_OFF + _tf_standard(f'"{_CIS}"')) == {"CF-SH-001:aws_securityhub_account.h"}


@pytest.mark.parametrize("text", [
    'resource "aws_securityhub_account" "h" {}\n',
    'variable "x" {}\nresource "aws_securityhub_account" "h" {\n enable_default_standards = var.x\n}\n',
    _TF_HUB_OFF + _tf_standard(f'"{_FSBP}"'),
    _TF_HUB_OFF + _tf_standard("var.x"),
    _TF_HUB_OFF + _tf_standard('"arn:aws:securityhub:${var.x}::standards/cis"'),
    _TF_HUB_OFF + 'resource "aws_securityhub_configuration_policy" "p" {}\n',
    _TF_HUB_OFF + 'module "m" {\n source = "terraform-aws-modules/x/aws"\n}\n',
])
def test_sh_terraform_not_judged(tmp_path: Path, text: str) -> None:
    assert _tf(tmp_path, text) == set()


# --- AWS Config ---

@pytest.mark.parametrize("group", [
    {"AllSupported": False},
    {"AllSupported": "false"},
    {"AllSupported": False, "ResourceTypes": []},
])
def test_cfg_fires(tmp_path: Path, group: dict) -> None:
    assert _cf(tmp_path, R=_recorder(group)) == {"CF-CFG-001:R"}


@pytest.mark.parametrize("group", [
    None,
    {},
    _PARAM,
    {"AllSupported": True},
    {"AllSupported": _PARAM},
    {"ResourceTypes": ["AWS::S3::Bucket"]},
    {"AllSupported": False, "ResourceTypes": ["AWS::S3::Bucket"]},
    {"AllSupported": False, "ResourceTypes": _PARAM},
    {"AllSupported": False, "RecordingStrategy": {"UseOnly": "EXCLUSION_BY_RESOURCE_TYPES"}},
    {"AllSupported": False, "ExclusionByResourceTypes": {"ResourceTypes": ["AWS::S3::Bucket"]}},
])
def test_cfg_cloudformation_not_judged(tmp_path: Path, group: Any) -> None:
    assert _cf(tmp_path, R=_recorder(group)) == set()


def _tf_recorder(group: str) -> str:
    return f'variable "x" {{}}\nresource "aws_config_configuration_recorder" "r" {{\n role_arn = "a"\n{group}}}\n'


def test_cfg_terraform_fires(tmp_path: Path) -> None:
    text = _tf_recorder('recording_group {\n all_supported = false\n}\n')
    assert _tf(tmp_path, text) == {"CF-CFG-001:aws_config_configuration_recorder.r"}


@pytest.mark.parametrize("group", [
    "",
    'recording_group {\n all_supported = true\n}\n',
    'recording_group {\n all_supported = var.x\n}\n',
    'recording_group {\n all_supported = false\n resource_types = ["AWS::S3::Bucket"]\n}\n',
    'recording_group {\n all_supported = false\n resource_types = var.x\n}\n',
    'recording_group {\n all_supported = false\n recording_strategy {\n use_only = "X"\n }\n}\n',
    'recording_group {\n all_supported = false\n exclusion_by_resource_types {\n resource_types = var.x\n }\n}\n',
    'recording_group {\n all_supported = false\n dynamic "recording_strategy" {\n for_each = var.x\n'
    ' content {\n use_only = "X"\n }\n }\n}\n',
    'dynamic "recording_group" {\n for_each = var.x\n content {\n all_supported = false\n }\n}\n',
])
def test_cfg_terraform_not_judged(tmp_path: Path, group: str) -> None:
    assert _tf(tmp_path, _tf_recorder(group)) == set()


# --- Macie ---

def test_macie_fires(tmp_path: Path) -> None:
    session = {"Type": "AWS::Macie::Session", "Properties": {"Status": "PAUSED"}}
    assert _cf(tmp_path, M=session) == {"CF-MACIE-001:M"}
    assert _tf(tmp_path, 'resource "aws_macie2_account" "m" {\n status = "PAUSED"\n}\n') == {
        "CF-MACIE-001:aws_macie2_account.m"}


@pytest.mark.parametrize("props", [{}, {"Status": "ENABLED"}, {"Status": _PARAM}])
def test_macie_cloudformation_not_judged(tmp_path: Path, props: dict) -> None:
    assert _cf(tmp_path, M={"Type": "AWS::Macie::Session", "Properties": props}) == set()


@pytest.mark.parametrize("body", ["", 'status = "ENABLED"\n', "status = var.x\n"])
def test_macie_terraform_not_judged(tmp_path: Path, body: str) -> None:
    assert _tf(tmp_path, f'variable "x" {{}}\nresource "aws_macie2_account" "m" {{\n{body}}}\n') == set()


# --- Budgets ---

def test_budget_fires(tmp_path: Path) -> None:
    assert _cf(tmp_path, B=_budget()) == {"CF-BUDGET-001:B"}
    assert _cf(tmp_path, B=_budget(NotificationsWithSubscribers=[])) == {"CF-BUDGET-001:B"}
    assert _tf(tmp_path, 'resource "aws_budgets_budget" "b" {\n budget_type = "COST"\n}\n') == {
        "CF-BUDGET-001:aws_budgets_budget.b"}


@pytest.mark.parametrize("resources", [
    {"B": _budget(NotificationsWithSubscribers=[{"Notification": {}, "Subscribers": []}])},
    {"B": _budget(NotificationsWithSubscribers=_PARAM)},
    {"B": _budget(), "A": {"Type": "AWS::Budgets::BudgetsAction", "Properties": {}}},
    {"B": _budget(), "N": {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "u"}}},
])
def test_budget_cloudformation_not_judged(tmp_path: Path, resources: dict) -> None:
    assert _cf(tmp_path, **resources) == set()


@pytest.mark.parametrize("text", [
    'resource "aws_budgets_budget" "b" {\n notification {\n threshold = 80\n }\n}\n',
    'resource "aws_budgets_budget" "b" {\n notification {\n threshold = var.x\n }\n}\n',
    'resource "aws_budgets_budget" "b" {\n dynamic "notification" {\n for_each = var.x\n content {\n'
    ' threshold = 80\n }\n }\n}\n',
    'resource "aws_budgets_budget" "b" {}\nresource "aws_budgets_budget_action" "a" {}\n',
    'resource "aws_budgets_budget" "b" {}\nmodule "m" {\n source = "terraform-aws-modules/x/aws"\n}\n',
])
def test_budget_terraform_not_judged(tmp_path: Path, text: str) -> None:
    assert _tf(tmp_path, 'variable "x" {}\n' + text) == set()


# --- Shared ---

def test_nothing_reports_a_missing_service(tmp_path: Path) -> None:
    assert _cf(tmp_path, Q={"Type": "AWS::SQS::Queue", "Properties": {}}) == set()
    assert _tf(tmp_path, 'resource "aws_sqs_queue" "q" {}\n') == set()


@pytest.mark.parametrize("check_id", sorted(SEVERITY))
def test_checks_do_not_replace_the_cdk_rules(check_id: str) -> None:
    assert check_id not in CF_COVERS_STATIC
    assert check_id not in CF_PARTLY_COVERS_STATIC


@pytest.mark.parametrize("check_id", sorted(SEVERITY))
def test_each_check_has_snippets(check_id: str) -> None:
    assert "Type: AWS::" in SNIPPETS["cloudformation"][check_id]
    assert "resource " in SNIPPETS["terraform"][check_id]
