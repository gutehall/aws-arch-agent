"""CF-DEMAND-001/002: a throttle or a buffer in front of demand (COST09-BP02, SUS02-BP06)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform
from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

IDS = ("CF-DEMAND-001", "CF-DEMAND-002")


def _found(found: list[Finding]) -> set[str]:
    by_id: dict[str, set[str]] = {i: set() for i in IDS}
    for f in found:
        if f.id in IDS:
            assert f.severity == "Low"
            other = IDS[1] if f.id == IDS[0] else IDS[0]
            assert other in f.recommendation
            by_id[f.id].add((f.evidence or "").split(" ")[0])
    assert by_id[IDS[0]] == by_id[IDS[1]], "one detection, two ids"
    return by_id[IDS[0]]


def _cf(tmp_path: Path, resources: dict) -> set[str]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _found(found)


def _tf(tmp_path: Path, text: str) -> set[str]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _found(run_resource_checks(resources, tmp_path / "main.tf"))


def test_two_ids_two_questions() -> None:
    assert RULE_BEST_PRACTICES["CF-DEMAND-001"] == ("COST09-BP02",)
    assert RULE_BEST_PRACTICES["CF-DEMAND-002"] == ("SUS02-BP06",)


# --- APIs, CloudFormation ---

def _fn(**props: Any) -> dict:
    return {"Type": "AWS::Lambda::Function", "Properties": {"Handler": "i.h", "Runtime": "python3.13", **props}}


def _api(stage_props: dict | None = None, fn_props: dict | None = None) -> dict:
    return {
        "Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": "a"}},
        "Fn": _fn(**(fn_props or {})),
        "Get": {"Type": "AWS::ApiGateway::Method", "Properties": {
            "RestApiId": {"Ref": "Api"}, "ResourceId": "r", "HttpMethod": "GET", "AuthorizationType": "NONE",
            "Integration": {"Type": "AWS_PROXY", "Uri": {"Fn::Sub": "arn:aws:apigateway:${AWS::Region}:lambda:path/"
                                                                    "2015-03-31/functions/${Fn.Arn}/invocations"}}}},
        "Prod": {"Type": "AWS::ApiGateway::Stage", "Properties": {
            "RestApiId": {"Ref": "Api"}, "StageName": "prod", "DeploymentId": "d", **(stage_props or {})}},
    }


def test_cf_api_without_throttle(tmp_path: Path) -> None:
    assert _cf(tmp_path, _api()) == {"Api"}


def test_cf_api_stage_throttle_passes(tmp_path: Path) -> None:
    settings = {"MethodSettings": [{"HttpMethod": "*", "ResourcePath": "/*", "ThrottlingRateLimit": 100}]}
    assert _cf(tmp_path, _api(settings)) == set()


def test_cf_usage_plan_throttle_passes(tmp_path: Path) -> None:
    plan = {"Type": "AWS::ApiGateway::UsagePlan", "Properties": {
        "ApiStages": [{"ApiId": {"Ref": "Api"}, "Stage": "prod"}], "Throttle": {"RateLimit": 50, "BurstLimit": 100}}}
    assert _cf(tmp_path, {**_api(), "Plan": plan}) == set()


def test_cf_waf_rate_rule_passes(tmp_path: Path) -> None:
    acl = {"Type": "AWS::WAFv2::WebACL", "Properties": {"Scope": "REGIONAL", "DefaultAction": {"Allow": {}}, "Rules": [
        {"Name": "rate", "Priority": 0, "Action": {"Block": {}},
         "Statement": {"RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP"}}}]}}
    assoc = {"Type": "AWS::WAFv2::WebACLAssociation", "Properties": {
        "WebACLArn": {"Fn::GetAtt": ["Acl", "Arn"]},
        "ResourceArn": {"Fn::Sub": "arn:aws:apigateway:${AWS::Region}::/restapis/${Api}/stages/${Prod}"}}}
    assert _cf(tmp_path, {**_api(), "Acl": acl, "Assoc": assoc}) == set()
    no_rate = json.loads(json.dumps(acl))
    no_rate["Properties"]["Rules"][0]["Statement"] = {"ByteMatchStatement": {}}
    assert _cf(tmp_path, {**_api(), "Acl": no_rate, "Assoc": assoc}) == {"Api"}


def test_cf_reserved_concurrency_passes(tmp_path: Path) -> None:
    assert _cf(tmp_path, _api(fn_props={"ReservedConcurrentExecutions": 20})) == set()


def test_cf_unreadable_stage_is_not_judged(tmp_path: Path) -> None:
    assert _cf(tmp_path, _api({"MethodSettings": {"Ref": "Settings"}})) == set()


# --- Direct invocation, CloudFormation ---

def _sns_to(endpoint_ref: str, protocol: str) -> dict:
    return {"Type": "AWS::SNS::Subscription", "Properties": {
        "TopicArn": {"Ref": "Topic"}, "Protocol": protocol, "Endpoint": {"Fn::GetAtt": [endpoint_ref, "Arn"]}}}


_TOPIC = {"Type": "AWS::SNS::Topic", "Properties": {}}


def test_cf_sns_invokes_lambda_directly(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Topic": _TOPIC, "Fn": _fn(), "Sub": _sns_to("Fn", "lambda")}) == {"Fn"}
    inline = {"Type": "AWS::SNS::Topic", "Properties": {
        "Subscription": [{"Protocol": "lambda", "Endpoint": {"Fn::GetAtt": ["Fn", "Arn"]}}]}}
    assert _cf(tmp_path, {"Topic": inline, "Fn": _fn()}) == {"Fn"}


def test_cf_sns_to_sqs_to_lambda_or_capped_passes(tmp_path: Path) -> None:
    queue = {"Type": "AWS::SQS::Queue", "Properties": {}}
    mapping = {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
        "EventSourceArn": {"Fn::GetAtt": ["Queue", "Arn"]}, "FunctionName": {"Ref": "Fn"}}}
    assert _cf(tmp_path, {"Topic": _TOPIC, "Fn": _fn(), "Queue": queue, "Map": mapping,
                          "Sub": _sns_to("Queue", "sqs")}) == set()
    assert _cf(tmp_path, {"Topic": _TOPIC, "Fn": _fn(ReservedConcurrentExecutions=5),
                          "Sub": _sns_to("Fn", "lambda")}) == set()


def test_cf_s3_notification_invokes_lambda(tmp_path: Path) -> None:
    bucket = {"Type": "AWS::S3::Bucket", "Properties": {"NotificationConfiguration": {"LambdaConfigurations": [
        {"Event": "s3:ObjectCreated:*", "Function": {"Fn::GetAtt": ["Fn", "Arn"]}}]}}}
    assert _cf(tmp_path, {"Bucket": bucket, "Fn": _fn()}) == {"Fn"}
    alias = {"Type": "AWS::Lambda::Alias", "Properties": {
        "FunctionName": {"Ref": "Fn"}, "FunctionVersion": "1", "Name": "live",
        "ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": 2}}}
    assert _cf(tmp_path, {"Bucket": bucket, "Fn": _fn(), "Live": alias}) == set()


# --- Terraform ---

_TF_FN = 'resource "aws_lambda_function" "f" {\n  function_name = "f"\n  role = "r"\n}\n'
_TF_API = (
    'resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n}\n'
    'resource "aws_api_gateway_integration" "get" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
    '  resource_id = "r"\n  http_method = "GET"\n  type = "AWS_PROXY"\n'
    '  integration_http_method = "POST"\n  uri = aws_lambda_function.f.invoke_arn\n}\n'
    'resource "aws_api_gateway_stage" "prod" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
    '  stage_name = "prod"\n  deployment_id = "d"\n}\n'
)


def test_tf_api_without_throttle(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_FN + _TF_API) == {"aws_api_gateway_rest_api.api"}


def test_tf_api_throttles_pass(tmp_path: Path) -> None:
    plan = ('resource "aws_api_gateway_usage_plan" "p" {\n  name = "p"\n'
            '  throttle_settings {\n    rate_limit = 50\n    burst_limit = 100\n  }\n}\n')
    assert _tf(tmp_path, _TF_FN + _TF_API + plan) == set()
    capped = _TF_FN.replace('role = "r"', 'role = "r"\n  reserved_concurrent_executions = 10')
    assert _tf(tmp_path, capped + _TF_API) == set()
    waf = ('resource "aws_wafv2_web_acl" "acl" {\n  name = "acl"\n  scope = "REGIONAL"\n'
           '  default_action {\n    allow {}\n  }\n  rule {\n    name = "rate"\n    priority = 0\n'
           '    action {\n      block {}\n    }\n    statement {\n      rate_based_statement {\n'
           '        limit = 1000\n        aggregate_key_type = "IP"\n      }\n    }\n  }\n}\n'
           'resource "aws_wafv2_web_acl_association" "a" {\n  resource_arn = aws_api_gateway_stage.prod.arn\n'
           '  web_acl_arn = aws_wafv2_web_acl.acl.arn\n}\n')
    assert _tf(tmp_path, _TF_FN + _TF_API + waf) == set()


def test_tf_sns_and_s3_invoke_lambda_directly(tmp_path: Path) -> None:
    sns = ('resource "aws_sns_topic" "t" {\n  name = "t"\n}\n'
           'resource "aws_sns_topic_subscription" "s" {\n  topic_arn = aws_sns_topic.t.arn\n'
           '  protocol = "lambda"\n  endpoint = aws_lambda_function.f.arn\n}\n')
    assert _tf(tmp_path, _TF_FN + sns) == {"aws_lambda_function.f"}
    s3 = ('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
          'resource "aws_s3_bucket_notification" "n" {\n  bucket = aws_s3_bucket.b.id\n'
          '  lambda_function {\n    lambda_function_arn = aws_lambda_function.f.arn\n'
          '    events = ["s3:ObjectCreated:*"]\n  }\n}\n')
    assert _tf(tmp_path, _TF_FN + s3) == {"aws_lambda_function.f"}
    provisioned = ('resource "aws_lambda_provisioned_concurrency_config" "p" {\n'
                   '  function_name = aws_lambda_function.f.function_name\n'
                   '  provisioned_concurrent_executions = 2\n  qualifier = "live"\n}\n')
    assert _tf(tmp_path, _TF_FN + s3 + provisioned) == set()


def test_tf_sns_to_sqs_passes(tmp_path: Path) -> None:
    text = ('resource "aws_sns_topic" "t" {\n  name = "t"\n}\n'
            'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n'
            'resource "aws_sns_topic_subscription" "s" {\n  topic_arn = aws_sns_topic.t.arn\n'
            '  protocol = "sqs"\n  endpoint = aws_sqs_queue.q.arn\n}\n'
            'resource "aws_lambda_event_source_mapping" "m" {\n  event_source_arn = aws_sqs_queue.q.arn\n'
            '  function_name = aws_lambda_function.f.arn\n}\n')
    assert _tf(tmp_path, _TF_FN + text) == set()
