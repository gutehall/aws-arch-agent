"""Athena, Glue and Firehose: CF-ATH-001/002, CF-GLUE-001..003, CF-FH-001."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-ATH-001", "CF-ATH-002", "CF-GLUE-001", "CF-GLUE-002", "CF-GLUE-003", "CF-FH-001")
_PARAM = {"Ref": "Param"}
_IF = {"Fn::If": ["C", "a", {"Ref": "AWS::NoValue"}]}
_ENCRYPTED = {"ResultConfiguration": {"EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}}}
_METRICS = {"--enable-metrics": "true"}
_BOOKMARKS = "--job-bookmark-option"
_VAR = 'variable "x" {}\n'


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _by_id(found)


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(_VAR + text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _workgroup(config: Any = None, **props: Any) -> dict:
    if config is not None:
        props["WorkGroupConfiguration"] = config
    return {"Type": "AWS::Athena::WorkGroup", "Properties": {"Name": "wg", **props}}


def _job(kind: Any = "glueetl", security: Any = "sc", **props: Any) -> dict:
    body = {"Command": {"Name": kind} if kind is not None else {}, "Role": "r", **props}
    if security is not None:
        body["SecurityConfiguration"] = security
    return {"Type": "AWS::Glue::Job", "Properties": body}


def _security(**encryption: Any) -> dict:
    return {"Type": "AWS::Glue::SecurityConfiguration",
            "Properties": {"Name": "sc", "EncryptionConfiguration": encryption}}


_ALL_ON = {
    "S3Encryptions": [{"S3EncryptionMode": "SSE-S3"}],
    "CloudWatchEncryption": {"CloudWatchEncryptionMode": "SSE-KMS"},
    "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "CSE-KMS"},
}


def _stream(**props: Any) -> dict:
    return {"Type": "AWS::KinesisFirehose::DeliveryStream", "Properties": props}


@pytest.mark.parametrize(("config", "fires"), [
    (None, True),
    ({}, True),
    ({"ResultConfiguration": {"OutputLocation": "s3://b/"}}, True),
    ({"ResultConfiguration": {"EncryptionConfiguration": {}}}, True),
    ({"ManagedQueryResultsConfiguration": {"Enabled": False}}, True),
    ({"EngineVersion": {"SelectedEngineVersion": "Athena engine version 3"}}, True),
    (_ENCRYPTED, False),
    (_PARAM, False),
    (_IF, False),
    ({"ResultConfiguration": _PARAM}, False),
    ({"ResultConfiguration": {"EncryptionConfiguration": _IF}}, False),
    ({"ManagedQueryResultsConfiguration": {"Enabled": True}}, False),
    ({"ManagedQueryResultsConfiguration": {"Enabled": _PARAM}}, False),
    ({"ManagedQueryResultsConfiguration": _PARAM}, False),
    ({"EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"}}, False),
    ({"EngineVersion": {"SelectedEngineVersion": _PARAM}}, False),
    ({"EngineVersion": _PARAM}, False),
])
def test_athena_results_encryption(tmp_path: Path, config: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"W": _workgroup(config)})
    assert found.get("CF-ATH-001", set()) == ({"W"} if fires else set())


@pytest.mark.parametrize(("enforce", "fires"), [
    (False, True), ("false", True), (True, False), ("true", False), (_PARAM, False),
])
def test_athena_enforce(tmp_path: Path, enforce: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"W": _workgroup({**_ENCRYPTED, "EnforceWorkGroupConfiguration": enforce})})
    assert found == ({"CF-ATH-002": {"W"}} if fires else {})


def test_athena_enforce_unset_is_not_reported(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"W": _workgroup(_ENCRYPTED)}) == {}


def test_athena_older_updates_property_is_not_judged(tmp_path: Path) -> None:
    updates = {"EnforceWorkGroupConfiguration": False}
    assert _cf(tmp_path, {"W": _workgroup(WorkGroupConfigurationUpdates=updates)}) == {}


@pytest.mark.parametrize(("security", "fires"), [
    (None, True), ("", True), ("sc", False), (_PARAM, False), (_IF, False),
])
def test_glue_job_security_configuration(tmp_path: Path, security: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"J": _job(security=security, DefaultArguments=_METRICS)})
    assert found == ({"CF-GLUE-001": {"J"}} if fires else {})


@pytest.mark.parametrize(("encryption", "fires"), [
    ({}, True),
    ({**_ALL_ON, "S3Encryptions": [{"S3EncryptionMode": "DISABLED"}]}, True),
    ({**_ALL_ON, "S3Encryptions": []}, True),
    ({k: v for k, v in _ALL_ON.items() if k != "S3Encryptions"}, True),
    ({**_ALL_ON, "CloudWatchEncryption": {"CloudWatchEncryptionMode": "DISABLED"}}, True),
    ({**_ALL_ON, "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "DISABLED"}}, True),
    ({k: v for k, v in _ALL_ON.items() if k != "JobBookmarksEncryption"}, True),
    (_ALL_ON, False),
    ({**_ALL_ON, "S3Encryptions": _PARAM}, False),
    ({**_ALL_ON, "S3Encryptions": [{"S3EncryptionMode": _PARAM}]}, False),
    ({**_ALL_ON, "CloudWatchEncryption": _IF}, False),
    ({**_ALL_ON, "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": _PARAM}}, False),
])
def test_glue_security_configuration(tmp_path: Path, encryption: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"S": _security(**encryption)})
    assert found == ({"CF-GLUE-001": {"S"}} if fires else {})


def test_glue_security_configuration_from_a_parameter_is_not_judged(tmp_path: Path) -> None:
    res = {"Type": "AWS::Glue::SecurityConfiguration",
           "Properties": {"Name": "sc", "EncryptionConfiguration": _PARAM}}
    assert _cf(tmp_path, {"S": res}) == {}


@pytest.mark.parametrize("reference", [{"Ref": "S"}, "sc", "not-in-this-template"])
def test_a_weak_security_configuration_is_reported_once_on_itself(tmp_path: Path, reference: Any) -> None:
    found = _cf(tmp_path, {"S": _security(), "J": _job(security=reference, DefaultArguments=_METRICS)})
    assert found == {"CF-GLUE-001": {"S"}}


@pytest.mark.parametrize(("kind", "args", "fires"), [
    ("glueetl", None, True),
    ("gluestreaming", None, True),
    ("glueetl", {"--other": "x"}, True),
    ("glueetl", _METRICS, False),
    ("glueetl", {"--enable-metrics": _PARAM}, False),
    ("glueetl", _PARAM, False),
    ("glueetl", _IF, False),
    ("pythonshell", None, False),
    (_PARAM, None, False),
    (None, None, False),
])
def test_glue_metrics(tmp_path: Path, kind: Any, args: Any, fires: bool) -> None:
    props = {} if args is None else {"DefaultArguments": args}
    found = _cf(tmp_path, {"J": _job(kind, **props)})
    assert found.get("CF-GLUE-002", set()) == ({"J"} if fires else set())


def test_glue_metrics_in_non_overridable_arguments(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"J": _job(NonOverridableArguments=_METRICS)}) == {}


def test_glue_non_overridable_arguments_from_a_parameter_are_not_judged(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"J": _job(DefaultArguments={"--other": "x"}, NonOverridableArguments=_PARAM)}) == {}


@pytest.mark.parametrize(("kind", "value", "fires"), [
    ("glueetl", "job-bookmark-disable", True),
    ("glueetl", "job-bookmark-enable", False),
    ("glueetl", "job-bookmark-pause", False),
    ("glueetl", None, False),
    ("glueetl", _PARAM, False),
    ("gluestreaming", "job-bookmark-disable", False),
    ("pythonshell", "job-bookmark-disable", False),
    (_PARAM, "job-bookmark-disable", False),
    (None, "job-bookmark-disable", False),
])
def test_glue_bookmarks(tmp_path: Path, kind: Any, value: Any, fires: bool) -> None:
    args: dict = dict(_METRICS)
    if value is not None:
        args[_BOOKMARKS] = value
    found = _cf(tmp_path, {"J": _job(kind, DefaultArguments=args)})
    assert found.get("CF-GLUE-003", set()) == ({"J"} if fires else set())


def test_glue_bookmarks_in_non_overridable_arguments(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"J": _job(DefaultArguments=_METRICS,
                                     NonOverridableArguments={_BOOKMARKS: "job-bookmark-disable"})})
    assert found == {"CF-GLUE-003": {"J"}}


@pytest.mark.parametrize(("props", "fires"), [
    ({}, True),
    ({"DeliveryStreamType": "DirectPut"}, True),
    ({"DeliveryStreamEncryptionConfigurationInput": {"KeyType": "AWS_OWNED_CMK"}}, False),
    ({"DeliveryStreamEncryptionConfigurationInput": _PARAM}, False),
    ({"DeliveryStreamEncryptionConfigurationInput": _IF}, False),
    ({"DeliveryStreamType": "KinesisStreamAsSource"}, False),
    ({"DeliveryStreamType": "MSKAsSource"}, False),
    ({"DeliveryStreamType": _PARAM}, False),
    ({"KinesisStreamSourceConfiguration": {"KinesisStreamARN": "a", "RoleARN": "r"}}, False),
])
def test_firehose(tmp_path: Path, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"F": _stream(**props)})
    assert found == ({"CF-FH-001": {"F"}} if fires else {})


@pytest.mark.parametrize(("body", "expected"), [
    ("", {"CF-ATH-001"}),
    ("configuration {}", {"CF-ATH-001"}),
    ('configuration {\n result_configuration {\n output_location = "s3://b/"\n }\n}', {"CF-ATH-001"}),
    ('configuration {\n result_configuration {\n encryption_configuration {\n encryption_option = "SSE_S3"\n }\n }\n}',
     set()),
    ('configuration {\n result_configuration {\n encryption_configuration {\n encryption_option = var.x\n }\n }\n}',
     set()),
    ('configuration {\n result_configuration {\n dynamic "encryption_configuration" {\n for_each = var.x\n content {}\n }\n }\n}',
     set()),
    ('configuration {\n dynamic "result_configuration" {\n for_each = var.x\n content {}\n }\n}', set()),
    ('dynamic "configuration" {\n for_each = var.x\n content {}\n}', set()),
    ('configuration {\n managed_query_results_configuration {\n enabled = true\n }\n}', set()),
    ('configuration {\n managed_query_results_configuration {\n enabled = var.x\n }\n}', set()),
    ('configuration {\n managed_query_results_configuration {\n enabled = false\n }\n}', {"CF-ATH-001"}),
    ('configuration {\n engine_version {\n selected_engine_version = "PySpark engine version 3"\n }\n}', set()),
    ('configuration {\n engine_version {\n selected_engine_version = var.x\n }\n}', set()),
    ('configuration {\n enforce_workgroup_configuration = false\n}', {"CF-ATH-001", "CF-ATH-002"}),
    ('configuration {\n enforce_workgroup_configuration = true\n}', {"CF-ATH-001"}),
    ('configuration {\n enforce_workgroup_configuration = var.x\n}', {"CF-ATH-001"}),
])
def test_terraform_athena(tmp_path: Path, body: str, expected: set[str]) -> None:
    found = _tf(tmp_path, f'resource "aws_athena_workgroup" "w" {{\n name = "w"\n {body}\n}}\n')
    assert found == {i: {"aws_athena_workgroup.w"} for i in expected}


_TF_ON = 'security_configuration = "sc"\n default_arguments = { "--enable-metrics" = "true" }\n'


@pytest.mark.parametrize(("body", "expected"), [
    ("", {"CF-GLUE-001", "CF-GLUE-002"}),
    (_TF_ON, set()),
    ('security_configuration = var.x\n default_arguments = { "--enable-metrics" = "true" }', set()),
    ('security_configuration = aws_glue_security_configuration.s.name\n'
     ' default_arguments = { "--enable-metrics" = "true" }', set()),
    ('security_configuration = "sc"\n default_arguments = var.x', set()),
    ('security_configuration = "sc"\n default_arguments = merge(var.x, { "--a" = "b" })', set()),
    ('security_configuration = "sc"\n default_arguments = { (var.x) = "b" }', set()),
    ('security_configuration = "sc"\n default_arguments = { "--enable-metrics" = var.x }', set()),
    ('security_configuration = "sc"\n default_arguments = { "--a" = "b" }', {"CF-GLUE-002"}),
    ('security_configuration = "sc"\n non_overridable_arguments = { "--enable-metrics" = "true" }', set()),
    ('security_configuration = "sc"\n default_arguments = { "--a" = "b" }\n non_overridable_arguments = var.x', set()),
    (_TF_ON.replace('"true" }', '"true", "--job-bookmark-option" = "job-bookmark-disable" }'), {"CF-GLUE-003"}),
    (_TF_ON.replace('"true" }', '"true", "--job-bookmark-option" = "job-bookmark-enable" }'), set()),
    (_TF_ON.replace('"true" }', '"true", "--job-bookmark-option" = var.x }'), set()),
])
def test_terraform_glue_job(tmp_path: Path, body: str, expected: set[str]) -> None:
    found = _tf(tmp_path, f'resource "aws_glue_job" "j" {{\n name = "j"\n role_arn = "r"\n'
                          f' command {{\n script_location = "s3://b/k"\n }}\n {body}\n}}\n')
    assert found == {i: {"aws_glue_job.j"} for i in expected}


@pytest.mark.parametrize(("command", "expected"), [
    ('command {\n name = "gluestreaming"\n script_location = "s"\n}', {"CF-GLUE-002"}),
    ('command {\n name = "pythonshell"\n script_location = "s"\n}', set()),
    ('command {\n name = var.x\n script_location = "s"\n}', set()),
    ('dynamic "command" {\n for_each = var.x\n content {}\n}', set()),
])
def test_terraform_glue_job_type(tmp_path: Path, command: str, expected: set[str]) -> None:
    found = _tf(tmp_path, f'''resource "aws_glue_job" "j" {{
  name = "j"
  role_arn = "r"
  security_configuration = "sc"
  default_arguments = {{ "--job-bookmark-option" = "job-bookmark-disable" }}
  {command}
}}
''')
    assert found == {i: {"aws_glue_job.j"} for i in expected}


def test_terraform_glue_arguments_keep_no_other_values(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('''resource "aws_glue_job" "j" {
  command {
    script_location = "s"
  }
  default_arguments = { "--password" = "hunter2", "--enable-metrics" = "true" }
}
''', encoding="utf-8")
    job = resources_from_terraform(tmp_path, [])[0]
    assert set(job.properties["DefaultArguments"]) == {"--enable-metrics"}
    assert "hunter2" not in str(job.properties)


def _tf_security(s3: str, cloudwatch: str, bookmarks: str) -> str:
    return f'''resource "aws_glue_security_configuration" "s" {{
  name = "s"
  encryption_configuration {{
    {s3}
    {cloudwatch}
    {bookmarks}
  }}
}}
'''


_S3_ON = 's3_encryption {\n s3_encryption_mode = "SSE-S3"\n}'
_CW_ON = 'cloudwatch_encryption {\n cloudwatch_encryption_mode = "SSE-KMS"\n}'
_BM_ON = 'job_bookmarks_encryption {\n job_bookmarks_encryption_mode = "CSE-KMS"\n}'


@pytest.mark.parametrize(("blocks", "fires"), [
    ((_S3_ON, _CW_ON, _BM_ON), False),
    (('s3_encryption {\n s3_encryption_mode = "DISABLED"\n}', _CW_ON, _BM_ON), True),
    (("s3_encryption {}", _CW_ON, _BM_ON), True),
    ((_S3_ON, 'cloudwatch_encryption {\n cloudwatch_encryption_mode = "DISABLED"\n}', _BM_ON), True),
    ((_S3_ON, _CW_ON, 'job_bookmarks_encryption {\n job_bookmarks_encryption_mode = "DISABLED"\n}'), True),
    (('s3_encryption {\n s3_encryption_mode = var.x\n}', _CW_ON, _BM_ON), False),
    (('dynamic "s3_encryption" {\n for_each = var.x\n content {}\n}', _CW_ON, _BM_ON), False),
    ((_S3_ON, 'cloudwatch_encryption {\n cloudwatch_encryption_mode = var.x\n}', _BM_ON), False),
    ((_S3_ON, _CW_ON, 'job_bookmarks_encryption {\n job_bookmarks_encryption_mode = var.x\n}'), False),
])
def test_terraform_glue_security_configuration(tmp_path: Path, blocks: tuple[str, str, str], fires: bool) -> None:
    found = _tf(tmp_path, _tf_security(*blocks))
    assert found == ({"CF-GLUE-001": {"aws_glue_security_configuration.s"}} if fires else {})


def test_terraform_an_unknown_mode_does_not_hide_a_disabled_one(tmp_path: Path) -> None:
    found = _tf(tmp_path, _tf_security('s3_encryption {\n s3_encryption_mode = var.x\n}', "cloudwatch_encryption {}", _BM_ON))
    assert found == {"CF-GLUE-001": {"aws_glue_security_configuration.s"}}


def test_terraform_dynamic_encryption_configuration_is_not_judged(tmp_path: Path) -> None:
    assert _tf(tmp_path, '''resource "aws_glue_security_configuration" "s" {
  name = "s"
  dynamic "encryption_configuration" {
    for_each = var.x
    content {}
  }
}
''') == {}


@pytest.mark.parametrize(("body", "fires"), [
    ("", True),
    ("server_side_encryption {}", True),
    ("server_side_encryption {\n enabled = false\n}", True),
    ("server_side_encryption {\n enabled = true\n}", False),
    ("server_side_encryption {\n enabled = var.x\n}", False),
    ('dynamic "server_side_encryption" {\n for_each = var.x\n content {}\n}', False),
    ('kinesis_source_configuration {\n kinesis_stream_arn = "a"\n role_arn = "r"\n}', False),
    ('msk_source_configuration {\n msk_cluster_arn = "a"\n}', False),
    ('dynamic "kinesis_source_configuration" {\n for_each = var.x\n content {}\n}', False),
])
def test_terraform_firehose(tmp_path: Path, body: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_kinesis_firehose_delivery_stream" "f" {{\n name = "f"\n'
                          f' destination = "extended_s3"\n {body}\n}}\n')
    assert found == ({"CF-FH-001": {"aws_kinesis_firehose_delivery_stream.f"}} if fires else {})


@pytest.mark.parametrize(("language", "keys"), [
    ("cloudformation", [*IDS, "CF-GLUE-001:AWS::Glue::SecurityConfiguration"]),
    ("terraform", [*IDS, "CF-GLUE-001:aws_glue_security_configuration"]),
])
def test_every_check_has_a_snippet(language: str, keys: list[str]) -> None:
    assert set(keys) <= set(SNIPPETS[language])
