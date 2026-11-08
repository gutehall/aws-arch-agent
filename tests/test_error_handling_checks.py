"""Step Functions, EventBridge and SQS error handling: CF-SFN-001..003, CF-EB-001/002, CF-SQS-003,
and event bus policies under CF-RP-001."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

SFN_IDS = ("CF-SFN-001", "CF-SFN-002", "CF-SFN-003")
IDS = (*SFN_IDS, "CF-EB-001", "CF-EB-002", "CF-SQS-003", "CF-RP-001")
_PARAM = {"Ref": "Param"}
_RETRY = [{"ErrorEquals": ["States.ALL"]}]
_CATCH = [{"ErrorEquals": ["States.ALL"], "Next": "Failed"}]
_GOOD_DEFINITION = {
    "StartAt": "Work",
    "States": {"Work": {"Type": "Task", "Retry": _RETRY, "Catch": _CATCH, "End": True}, "Failed": {"Type": "Fail"}},
}


def _findings(found: list[Finding]) -> list[Finding]:
    return [f for f in found if f.id in IDS]


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in _findings(found):
        out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _run_cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return found


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    return _by_id(_run_cf(tmp_path, resources))


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _machine(**props: Any) -> dict:
    base = {
        "Definition": _GOOD_DEFINITION,
        "TracingConfiguration": {"Enabled": True},
        "LoggingConfiguration": {"Level": "ERROR"},
    }
    return {"Type": "AWS::StepFunctions::StateMachine", "Properties": {**base, **props}}


def _without(resource: dict, key: str) -> dict:
    return {**resource, "Properties": {k: v for k, v in resource["Properties"].items() if k != key}}


def _rule(**target: Any) -> dict:
    base = {"Id": "t1", "Arn": "arn", "DeadLetterConfig": {"Arn": "dlq"}, "RetryPolicy": {"MaximumRetryAttempts": 3}}
    merged = {k: v for k, v in {**base, **target}.items() if v is not None}
    return {"Type": "AWS::Events::Rule", "Properties": {"Targets": [merged]}}


def test_a_good_state_machine_and_rule_are_not_reported(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Machine": _machine(), "Rule": _rule()}) == {}


# --- CF-SFN-001 ---

@pytest.mark.parametrize("definition, shown", [
    ({"StartAt": "A", "States": {"A": {"Type": "Task", "Catch": _CATCH, "End": True}}}, "no Retry: A"),
    ({"StartAt": "A", "States": {"A": {"Type": "Task", "Retry": [], "Catch": _CATCH, "End": True}}}, "no Retry: A"),
    ({"StartAt": "A", "States": {"A": {"Type": "Task", "Retry": _RETRY, "End": True}}}, "no Catch: A"),
    ({"StartAt": "A", "States": {"A": {"Type": "Task", "Retry": _RETRY, "Next": "Done"},
                                 "Done": {"Type": "Succeed"}}}, "no Catch: A"),
    ({"StartAt": "P", "States": {"P": {"Type": "Parallel", "End": True, "Branches": [
        {"StartAt": "B", "States": {"B": {"Type": "Task", "End": True}}}]}}}, "no Retry: B"),
    ({"StartAt": "M", "States": {"M": {"Type": "Map", "End": True, "ItemProcessor": {
        "StartAt": "I", "States": {"I": {"Type": "Task", "End": True}}}}}}, "no Retry: I"),
    ({"StartAt": "M", "States": {"M": {"Type": "Map", "End": True, "Iterator": {
        "StartAt": "I", "States": {"I": {"Type": "Task", "End": True}}}}}}, "no Retry: I"),
])
def test_tasks_with_no_retry_or_catch_are_reported(tmp_path: Path, definition: dict, shown: str) -> None:
    found = _findings(_run_cf(tmp_path, {"Machine": _machine(Definition=definition)}))
    assert [f.id for f in found] == ["CF-SFN-001"]
    assert shown in found[0].recommendation


def test_only_the_last_task_needs_a_catch(tmp_path: Path) -> None:
    definition = {"StartAt": "A", "States": {
        "A": {"Type": "Task", "Retry": _RETRY, "Next": "B"},
        "B": {"Type": "Task", "Retry": _RETRY, "Catch": _CATCH, "End": True},
    }}
    assert _cf(tmp_path, {"Machine": _machine(Definition=definition)}) == {}


def test_a_nested_task_needs_a_retry_but_no_catch(tmp_path: Path) -> None:
    definition = {"StartAt": "P", "States": {"P": {"Type": "Parallel", "End": True, "Branches": [
        {"StartAt": "B", "States": {"B": {"Type": "Task", "Retry": _RETRY, "End": True}}}]}}}
    assert _cf(tmp_path, {"Machine": _machine(Definition=definition)}) == {}


def test_a_definition_with_no_tasks_is_not_reported(tmp_path: Path) -> None:
    definition = {"StartAt": "A", "States": {"A": {"Type": "Pass", "End": True}}}
    assert _cf(tmp_path, {"Machine": _machine(Definition=definition)}) == {}


def _string_machine(value: Any) -> dict:
    return _without(_machine(DefinitionString=value), "Definition")


BAD_JSON = json.dumps({"StartAt": "A", "States": {"A": {"Type": "Task", "End": True}}})


@pytest.mark.parametrize("value", [
    BAD_JSON,
    {"Fn::Sub": BAD_JSON},
    {"Fn::Sub": [BAD_JSON, {"X": "y"}]},
    # The way CDK synth writes it, with a reference inside a JSON string.
    {"Fn::Join": ["", ['{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:', {"Ref": "AWS::Partition"},
                       ':states:::lambda:invoke","End":true}}}']]},
])
def test_definition_string_is_read(tmp_path: Path, value: Any) -> None:
    assert _cf(tmp_path, {"Machine": _string_machine(value)}) == {"CF-SFN-001": {"Machine"}}


@pytest.mark.parametrize("value", [
    "not json",
    _PARAM,
    {"Fn::If": ["C", BAD_JSON, BAD_JSON]},
    # A value outside a JSON string may be a whole Retry block.
    {"Fn::Join": ["", ['{"States":{"A":{"Type":"Task","End":true,"Retry":', {"Ref": "R"}, "}}}"]]},
])
def test_a_definition_string_the_scan_cannot_read_is_not_judged(tmp_path: Path, value: Any) -> None:
    assert _cf(tmp_path, {"Machine": _string_machine(value)}) == {}


def _s3_machine(location: Any) -> dict:
    return _without(_machine(DefinitionS3Location=location), "Definition")


@pytest.mark.parametrize("name, text", [
    ("flow.asl.json", BAD_JSON),
    ("flow.asl.yaml", "States:\n  A:\n    Type: Task\n    End: true\n"),
])
def test_local_definition_file_is_read(tmp_path: Path, name: str, text: str) -> None:
    (tmp_path / "flows").mkdir()
    (tmp_path / "flows" / name).write_text(text, encoding="utf-8")
    assert _cf(tmp_path, {"Machine": _s3_machine(f"flows/{name}")}) == {"CF-SFN-001": {"Machine"}}


def test_definition_outside_the_template_folder_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "outside.json").write_text(BAD_JSON, encoding="utf-8")
    (tmp_path / "stack").mkdir()
    assert _cf(tmp_path / "stack", {"Machine": _s3_machine("../outside.json")}) == {}
    assert _cf(tmp_path / "stack", {"Machine": _s3_machine(str(tmp_path / "outside.json"))}) == {}


@pytest.mark.parametrize("location", [{"Bucket": "b", "Key": "k"}, "missing.json", "s3://b/k"])
def test_a_definition_in_s3_is_not_judged(tmp_path: Path, location: Any) -> None:
    assert _cf(tmp_path, {"Machine": _s3_machine(location)}) == {}


# --- CF-SFN-002 / CF-SFN-003 ---

@pytest.mark.parametrize("props", [{"TracingConfiguration": {"Enabled": False}}, {"TracingConfiguration": {}}])
def test_tracing_off_is_reported(tmp_path: Path, props: dict) -> None:
    assert _cf(tmp_path, {"Machine": _machine(**props)}) == {"CF-SFN-002": {"Machine"}}


def test_tracing_and_logging_unset_are_reported(tmp_path: Path) -> None:
    machine = _without(_without(_machine(), "TracingConfiguration"), "LoggingConfiguration")
    assert _cf(tmp_path, {"Machine": machine}) == {"CF-SFN-002": {"Machine"}, "CF-SFN-003": {"Machine"}}


@pytest.mark.parametrize("config", [{"Level": "OFF"}, {"Level": "off"}, {"Destinations": []}, {}])
def test_logging_off_is_reported(tmp_path: Path, config: dict) -> None:
    assert _cf(tmp_path, {"Machine": _machine(LoggingConfiguration=config)}) == {"CF-SFN-003": {"Machine"}}


def test_logging_finding_is_medium_and_names_the_control(tmp_path: Path) -> None:
    found = _findings(_run_cf(tmp_path, {"Machine": _machine(LoggingConfiguration={"Level": "OFF"})}))
    assert found[0].severity == "Medium"
    assert "StepFunctions.1" in found[0].recommendation


@pytest.mark.parametrize("props", [
    {"TracingConfiguration": _PARAM},
    {"TracingConfiguration": {"Enabled": _PARAM}},
    {"LoggingConfiguration": _PARAM},
    {"LoggingConfiguration": {"Level": _PARAM}},
    {"LoggingConfiguration": {"Fn::If": ["C", {"Level": "ALL"}, {"Level": "OFF"}]}},
])
def test_deploy_time_values_are_not_judged(tmp_path: Path, props: dict) -> None:
    assert _cf(tmp_path, {"Machine": _machine(**props)}) == {}


# --- CF-EB-001 / CF-EB-002 ---

@pytest.mark.parametrize("target, expected", [
    ({"DeadLetterConfig": None}, "CF-EB-001"),
    ({"DeadLetterConfig": {}}, "CF-EB-001"),
    ({"RetryPolicy": None}, "CF-EB-002"),
    ({"RetryPolicy": {"MaximumRetryAttempts": 0}}, "CF-EB-002"),
    ({"RetryPolicy": {"MaximumRetryAttempts": "0"}}, "CF-EB-002"),
])
def test_rule_target_gaps_are_reported(tmp_path: Path, target: dict, expected: str) -> None:
    assert _cf(tmp_path, {"Rule": _rule(**target)}) == {expected: {"Rule"}}


@pytest.mark.parametrize("target", [
    {"DeadLetterConfig": _PARAM},
    {"RetryPolicy": _PARAM},
    {"RetryPolicy": {"MaximumRetryAttempts": _PARAM}},
    {"RetryPolicy": {"MaximumEventAgeInSeconds": 60}},  # attempts stay at the default
])
def test_rule_values_the_scan_cannot_read_are_not_judged(tmp_path: Path, target: dict) -> None:
    assert _cf(tmp_path, {"Rule": _rule(**target)}) == {}


def test_rule_finding_names_only_the_bad_targets(tmp_path: Path) -> None:
    good = _rule()["Properties"]["Targets"][0]
    bad = {"Id": "bad", "Arn": "arn", "RetryPolicy": {"MaximumRetryAttempts": 2}}
    rule = {"Type": "AWS::Events::Rule", "Properties": {"Targets": [good, bad]}}
    found = _findings(_run_cf(tmp_path, {"Rule": rule}))
    assert [f.id for f in found] == ["CF-EB-001"]
    assert "Targets: bad." in found[0].recommendation


@pytest.mark.parametrize("targets", [None, _PARAM, [_PARAM], [{"Fn::If": ["C", {"Id": "a"}, {"Id": "b"}]}]])
def test_rule_with_targets_the_scan_cannot_read_is_not_judged(tmp_path: Path, targets: Any) -> None:
    props = {"Targets": targets} if targets is not None else {}
    assert _cf(tmp_path, {"Rule": {"Type": "AWS::Events::Rule", "Properties": props}}) == {}


# --- CF-RP-001 on event buses ---

_OPEN = {"Effect": "Allow", "Principal": "*", "Action": "events:PutEvents", "Resource": "*"}
_ORG = {**_OPEN, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}
_ACCOUNT = {**_OPEN, "Principal": {"AWS": "arn:aws:iam::111122223333:root"}}


@pytest.mark.parametrize("resource_type, props, reported", [
    ("AWS::Events::EventBus", {"Name": "b", "Policy": {"Statement": [_OPEN]}}, True),
    ("AWS::Events::EventBus", {"Name": "b", "Policy": {"Statement": [_ORG]}}, False),
    ("AWS::Events::EventBus", {"Name": "b"}, False),
    ("AWS::Events::EventBusPolicy", {"StatementId": "s", "Statement": _OPEN}, True),
    ("AWS::Events::EventBusPolicy", {"StatementId": "s", "Statement": json.dumps(_OPEN)}, True),
    ("AWS::Events::EventBusPolicy", {"StatementId": "s", "Statement": _ACCOUNT}, False),
    ("AWS::Events::EventBusPolicy", {"StatementId": "s", "Statement": "not json"}, False),
    ("AWS::Events::EventBusPolicy", {"StatementId": "s", "Principal": "*", "Action": "events:PutEvents"}, True),
    ("AWS::Events::EventBusPolicy", {"StatementId": "s", "Principal": "*", "Action": "events:PutEvents",
                                     "Condition": {"Type": "StringEquals", "Key": "aws:PrincipalOrgID",
                                                   "Value": "o-1"}}, False),
    ("AWS::Events::EventBusPolicy", {"StatementId": "s", "Principal": "111122223333",
                                     "Action": "events:PutEvents"}, False),
])
def test_event_bus_policies(tmp_path: Path, resource_type: str, props: dict, reported: bool) -> None:
    found = _cf(tmp_path, {"Bus": {"Type": resource_type, "Properties": props}})
    assert found == ({"CF-RP-001": {"Bus"}} if reported else {})


# --- CF-SQS-003 ---

def _consumer(queue_props: dict, fn_props: dict) -> dict:
    return {
        "Queue": {"Type": "AWS::SQS::Queue", "Properties": queue_props},
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": fn_props},
        "Map": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
            "EventSourceArn": {"Fn::GetAtt": ["Queue", "Arn"]}, "FunctionName": {"Ref": "Fn"}}},
    }


@pytest.mark.parametrize("queue, fn, reported", [
    ({"VisibilityTimeout": 30}, {"Timeout": 60}, True),
    ({}, {"Timeout": 31}, True),  # the queue default is 30
    ({"VisibilityTimeout": "30"}, {"Timeout": "60"}, True),
    ({"VisibilityTimeout": 60}, {"Timeout": 60}, False),
    ({}, {}, False),  # 30 against the function default of 3
    ({"VisibilityTimeout": _PARAM}, {"Timeout": 60}, False),
    ({"VisibilityTimeout": 30}, {"Timeout": _PARAM}, False),
])
def test_visibility_against_the_consumer(tmp_path: Path, queue: dict, fn: dict, reported: bool) -> None:
    assert _cf(tmp_path, _consumer(queue, fn)) == ({"CF-SQS-003": {"Queue"}} if reported else {})


def test_visibility_finding_is_medium_and_names_the_slowest_function(tmp_path: Path) -> None:
    resources = _consumer({"VisibilityTimeout": 30}, {"Timeout": 60})
    resources["Slow"] = {"Type": "AWS::Lambda::Function", "Properties": {"Timeout": 300}}
    resources["SlowMap"] = {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
        "EventSourceArn": {"Fn::GetAtt": ["Queue", "Arn"]}, "FunctionName": {"Ref": "Slow"}}}
    found = _findings(_run_cf(tmp_path, resources))
    assert [f.id for f in found] == ["CF-SQS-003"]
    assert found[0].severity == "Medium"
    assert "Slow can run for 300" in found[0].recommendation


def test_a_function_that_does_not_consume_the_queue_is_ignored(tmp_path: Path) -> None:
    resources = _consumer({"VisibilityTimeout": 30}, {"Timeout": 10})
    resources["Other"] = {"Type": "AWS::Lambda::Function", "Properties": {"Timeout": 900}}
    assert _cf(tmp_path, resources) == {}


# --- Terraform ---

_TF_GOOD_MACHINE = """
resource "aws_sfn_state_machine" "ok" {
  definition = jsonencode({
    StartAt = "A"
    States = { A = {
      Type = "Task", Resource = aws_lambda_function.f.arn, Parameters = { X = var.x }
      Retry = [{ ErrorEquals = ["States.ALL"] }], Catch = [{ ErrorEquals = ["States.ALL"], Next = "F" }], End = true
    }, F = { Type = "Fail" } }
  })
  tracing_configuration { enabled = true }
  logging_configuration { level = "ERROR" }
}
"""


def test_terraform_good_state_machine(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_GOOD_MACHINE) == {}


def test_terraform_state_machine_with_nothing_set(tmp_path: Path) -> None:
    text = '''
resource "aws_sfn_state_machine" "bad" {
  definition = jsonencode({ StartAt = "A", States = { A = { Type = "Task", Resource = "r", End = true } } })
}
'''
    assert _tf(tmp_path, text) == {
        "CF-SFN-001": {"aws_sfn_state_machine.bad"},
        "CF-SFN-002": {"aws_sfn_state_machine.bad"},
        "CF-SFN-003": {"aws_sfn_state_machine.bad"},
    }


@pytest.mark.parametrize("definition", [
    '<<EOF\n{"States": {"A": {"Type": "Task", "Resource": "${aws_lambda_function.f.arn}", "End": true}}}\nEOF',
    '"{\\"States\\": {\\"A\\": {\\"Type\\": \\"Task\\", \\"End\\": true}}}"',
])
def test_terraform_definition_as_text(tmp_path: Path, definition: str) -> None:
    text = f'''
resource "aws_sfn_state_machine" "m" {{
  definition = {definition}
  tracing_configuration {{ enabled = true }}
  logging_configuration {{ level = "ALL" }}
}}
'''
    assert _tf(tmp_path, text) == {"CF-SFN-001": {"aws_sfn_state_machine.m"}}


@pytest.mark.parametrize("definition", ['file("flow.json")', 'templatefile("flow.json", {})', "var.definition"])
def test_terraform_definition_the_scan_cannot_read_is_not_judged(tmp_path: Path, definition: str) -> None:
    text = f'''
resource "aws_sfn_state_machine" "m" {{
  definition = {definition}
  tracing_configuration {{ enabled = true }}
  logging_configuration {{ level = "ALL" }}
}}
'''
    assert _tf(tmp_path, text) == {}


def test_terraform_state_machine_values_from_variables_are_not_judged(tmp_path: Path) -> None:
    text = '''
resource "aws_sfn_state_machine" "m" {
  definition = file("flow.json")
  tracing_configuration { enabled = var.tracing }
  logging_configuration { level = var.level }
}
resource "aws_sfn_state_machine" "d" {
  definition = file("flow.json")
  dynamic "tracing_configuration" {
    for_each = var.t
    content { enabled = true }
  }
  dynamic "logging_configuration" {
    for_each = var.l
    content { level = "ALL" }
  }
}
'''
    assert _tf(tmp_path, text) == {}


def test_terraform_logging_off(tmp_path: Path) -> None:
    text = '''
resource "aws_sfn_state_machine" "m" {
  definition = file("flow.json")
  tracing_configuration { enabled = true }
  logging_configuration { level = "OFF" }
}
'''
    assert _tf(tmp_path, text) == {"CF-SFN-003": {"aws_sfn_state_machine.m"}}


def test_terraform_event_targets(tmp_path: Path) -> None:
    text = '''
resource "aws_cloudwatch_event_target" "ok" {
  rule = "r"
  arn  = "a"
  dead_letter_config { arn = aws_sqs_queue.d.arn }
  retry_policy { maximum_retry_attempts = 3 }
}
resource "aws_cloudwatch_event_target" "bare" {
  rule = "r"
  arn  = "a"
}
resource "aws_cloudwatch_event_target" "zero" {
  rule = "r"
  arn  = "a"
  dead_letter_config { arn = aws_sqs_queue.d.arn }
  retry_policy { maximum_retry_attempts = 0 }
}
resource "aws_cloudwatch_event_target" "vars" {
  rule = "r"
  arn  = "a"
  dead_letter_config { arn = var.dlq }
  retry_policy { maximum_retry_attempts = var.attempts }
}
resource "aws_cloudwatch_event_target" "dyn" {
  rule = "r"
  arn  = "a"
  dynamic "dead_letter_config" {
    for_each = var.d
    content { arn = "x" }
  }
  dynamic "retry_policy" {
    for_each = var.r
    content { maximum_retry_attempts = 1 }
  }
}
'''
    assert _tf(tmp_path, text) == {
        "CF-EB-001": {"aws_cloudwatch_event_target.bare"},
        "CF-EB-002": {"aws_cloudwatch_event_target.bare", "aws_cloudwatch_event_target.zero"},
    }


def test_terraform_event_bus_policies(tmp_path: Path) -> None:
    text = '''
resource "aws_cloudwatch_event_bus_policy" "open" {
  event_bus_name = "b"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "events:PutEvents", Resource = "*" }] })
}
resource "aws_cloudwatch_event_bus_policy" "account" {
  event_bus_name = "b"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "111122223333" }, Action = "events:PutEvents", Resource = "*" }] })
}
resource "aws_cloudwatch_event_permission" "open" {
  principal    = "*"
  statement_id = "s"
}
resource "aws_cloudwatch_event_permission" "org" {
  principal    = "*"
  statement_id = "s"
  condition {
    key   = "aws:PrincipalOrgID"
    type  = "StringEquals"
    value = "o-1"
  }
}
resource "aws_cloudwatch_event_permission" "dyn" {
  principal    = "*"
  statement_id = "s"
  dynamic "condition" {
    for_each = var.c
    content {
      key   = "aws:PrincipalOrgID"
      type  = "StringEquals"
      value = "o-1"
    }
  }
}
resource "aws_cloudwatch_event_permission" "var" {
  principal    = var.principal
  statement_id = "s"
}
resource "aws_cloudwatch_event_permission" "account" {
  principal    = "111122223333"
  statement_id = "s"
}
'''
    assert _tf(tmp_path, text) == {"CF-RP-001": {
        "aws_cloudwatch_event_bus_policy.open", "aws_cloudwatch_event_permission.open"}}


def test_terraform_visibility_against_the_consumer(tmp_path: Path) -> None:
    text = '''
resource "aws_sqs_queue" "short" {
  sqs_managed_sse_enabled = true
}
resource "aws_sqs_queue" "enough" {
  visibility_timeout_seconds = 360
}
resource "aws_sqs_queue" "unknown" {
  visibility_timeout_seconds = var.visibility
}
resource "aws_lambda_function" "f" {
  function_name = "f"
  timeout       = 60
}
resource "aws_lambda_event_source_mapping" "short" {
  event_source_arn = aws_sqs_queue.short.arn
  function_name    = aws_lambda_function.f.arn
}
resource "aws_lambda_event_source_mapping" "enough" {
  event_source_arn = aws_sqs_queue.enough.arn
  function_name    = aws_lambda_function.f.arn
}
resource "aws_lambda_event_source_mapping" "unknown" {
  event_source_arn = aws_sqs_queue.unknown.arn
  function_name    = aws_lambda_function.f.arn
}
'''
    assert _tf(tmp_path, text) == {"CF-SQS-003": {"aws_sqs_queue.short"}}
