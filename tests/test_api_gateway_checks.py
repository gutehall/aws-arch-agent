"""API Gateway auth, TLS, throttling, validation and caching: CF-APIGW-003..009, V2-003/004."""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = tuple(f"CF-APIGW-00{n}" for n in range(3, 10)) + ("CF-APIGW-V2-003", "CF-APIGW-V2-004")


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


def _method(verb: str, **props: object) -> dict:
    return {"Type": "AWS::ApiGateway::Method", "Properties": {
        "RestApiId": {"Ref": "Api"}, "ResourceId": "r", "HttpMethod": verb,
        "AuthorizationType": "AWS_IAM", "RequestValidatorId": {"Ref": "Validator"}, **props}}


_SECURE_API = {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": "a", "SecurityPolicy": "TLS_1_2"}}
_GOOD_SETTINGS = [{"ResourcePath": "/*", "HttpMethod": "*", "ThrottlingRateLimit": 100,
                   "ThrottlingBurstLimit": 200, "CachingEnabled": True, "CacheDataEncrypted": True}]


def _stage(**props: object) -> dict:
    base = {"RestApiId": {"Ref": "Api"}, "StageName": "prod", "CacheClusterEnabled": True,
            "ClientCertificateId": {"Ref": "Cert"}, "MethodSettings": _GOOD_SETTINGS}
    return {"Type": "AWS::ApiGateway::Stage", "Properties": {**base, **props}}


def test_a_hardened_rest_api_has_no_findings(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Api": _SECURE_API, "Get": _method("GET"), "Post": _method("POST"),
                          "Stage": _stage()}) == {}


_PARAM = {"Ref": "Param"}


def _settings(**props: object) -> list[dict]:
    return [{"ResourcePath": "/*", "HttpMethod": "*", "ThrottlingRateLimit": 1, **props}]


def test_values_known_only_at_deploy_time_are_not_judged(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Api": _SECURE_API,
        "KeyParam": _method("GET", AuthorizationType="NONE", ApiKeyRequired=_PARAM),
        "CacheParam": _stage(MethodSettings=_settings(CachingEnabled=True, CacheDataEncrypted=_PARAM)),
        "DisabledParam": {"Type": "AWS::ApiGateway::RestApi", "Properties": {
            "Name": "a", "DisableExecuteApiEndpoint": _PARAM}},
        "EndpointParam": {"Type": "AWS::ApiGateway::RestApi", "Properties": {
            "Name": "a", "EndpointConfiguration": _PARAM}},
        "TypesParam": {"Type": "AWS::ApiGateway::RestApi", "Properties": {
            "Name": "a", "EndpointConfiguration": {"Types": _PARAM}}},
        "TypeParam": {"Type": "AWS::ApiGateway::RestApi", "Properties": {
            "Name": "a", "EndpointConfiguration": {"Types": [_PARAM]}}},
    })
    assert found == {}


def test_cache_encryption_set_to_false_is_still_reported(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Api": _SECURE_API,
        "Stage": _stage(MethodSettings=_settings(CachingEnabled=True, CacheDataEncrypted=False)),
    })
    assert found == {"CF-APIGW-007": {"Stage"}}


def test_default_route_needs_a_known_http_api(tmp_path: Path) -> None:
    def route(api: object) -> dict:
        return {"Type": "AWS::ApiGatewayV2::Route", "Properties": {"ApiId": api, "RouteKey": "$default"}}

    found = _cf(tmp_path, {
        "Http": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"Name": "h", "ProtocolType": "HTTP"}},
        "OnHttp": route({"Ref": "Http"}),
        "OnUnknown": route("imported-api-id"),
    })
    assert found == {"CF-APIGW-V2-003": {"OnHttp"}}


def _terraform(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


_TF_STAGE = """
resource "aws_api_gateway_rest_api" "a" {
  name = "a"
}
resource "aws_api_gateway_stage" "s" {
  rest_api_id           = aws_api_gateway_rest_api.a.id
  stage_name            = "p"
  deployment_id         = "d"
  cache_cluster_enabled = true
  client_certificate_id = "c"
}
"""


def test_terraform_cache_encryption_from_a_variable_is_not_judged(tmp_path: Path) -> None:
    assert _terraform(tmp_path, _TF_STAGE + """
resource "aws_api_gateway_method_settings" "m" {
  rest_api_id = aws_api_gateway_rest_api.a.id
  stage_name  = aws_api_gateway_stage.s.stage_name
  method_path = "*/*"
  settings {
    throttling_rate_limit = 1
    caching_enabled       = true
    cache_data_encrypted  = var.encrypted
  }
}
""") == {}


def test_terraform_dynamic_usage_plan_throttle_counts(tmp_path: Path) -> None:
    assert _terraform(tmp_path, _TF_STAGE + """
resource "aws_api_gateway_usage_plan" "u" {
  name = "u"
  api_stages {
    api_id = aws_api_gateway_rest_api.a.id
    stage  = aws_api_gateway_stage.s.stage_name
  }
  dynamic "throttle_settings" {
    for_each = var.throttle
    content {
      rate_limit = 1
    }
  }
}
""") == {}


def test_methods(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Api": _SECURE_API,
        "Open": _method("GET", AuthorizationType="NONE"),
        "Unset": _method("DELETE", AuthorizationType=None),
        "Keyed": _method("GET", AuthorizationType="NONE", ApiKeyRequired=True),
        "Preflight": _method("OPTIONS", AuthorizationType="NONE"),
        "Unchecked": _method("POST", RequestValidatorId=None),
        "Proxy": _method("ANY", RequestValidatorId=None),
        "Read": _method("GET", RequestValidatorId=None),  # no body to validate
        "Stage": _stage(),
    })
    assert found == {"CF-APIGW-003": {"Open", "Unset"}, "CF-APIGW-006": {"Unchecked", "Proxy"}}


def test_tls_on_the_endpoint_and_domains(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Default": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": "d"}},
        "Old": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": "o", "SecurityPolicy": "TLS_1_0"}},
        "Private": {"Type": "AWS::ApiGateway::RestApi", "Properties": {
            "Name": "p", "EndpointConfiguration": {"Types": ["PRIVATE"]}}},
        "NoEndpoint": {"Type": "AWS::ApiGateway::RestApi", "Properties": {
            "Name": "n", "DisableExecuteApiEndpoint": True}},
        "Tls13": {"Type": "AWS::ApiGateway::RestApi", "Properties": {
            "Name": "t", "SecurityPolicy": "SecurityPolicy_TLS13_1_3_2025_09"}},
        "DomainDefault": {"Type": "AWS::ApiGateway::DomainName", "Properties": {"DomainName": "a.example.com"}},
        "DomainOld": {"Type": "AWS::ApiGateway::DomainName", "Properties": {
            "DomainName": "b.example.com", "SecurityPolicy": "TLS_1_0"}},
        "HttpDomainOld": {"Type": "AWS::ApiGatewayV2::DomainName", "Properties": {
            "DomainName": "c.example.com", "DomainNameConfigurations": [{"SecurityPolicy": "TLS_1_0"}]}},
    })
    # Regional and edge APIs default to TLS_1_0; custom domains default to TLS_1_2.
    assert found == {"CF-APIGW-004": {"Default", "Old", "DomainOld", "HttpDomainOld"}}


def test_stages(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Api": _SECURE_API, "Get": _method("GET"),
        "Bare": _stage(MethodSettings=None, CacheClusterEnabled=None, ClientCertificateId=None),
        "PlainCache": _stage(MethodSettings=[{"ResourcePath": "/*", "HttpMethod": "*",
                                              "ThrottlingRateLimit": 10, "CachingEnabled": True}]),
    })
    assert found == {
        "CF-APIGW-005": {"Bare"}, "CF-APIGW-007": {"PlainCache"},
        "CF-APIGW-008": {"Bare"}, "CF-APIGW-009": {"Bare"},
    }


def test_a_usage_plan_throttles_the_stage(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Api": _SECURE_API,
        "Stage": _stage(MethodSettings=[]),
        "Plan": {"Type": "AWS::ApiGateway::UsagePlan", "Properties": {
            "ApiStages": [{"ApiId": {"Ref": "Api"}, "Stage": {"Ref": "Stage"}}],
            "Throttle": {"RateLimit": 50, "BurstLimit": 100}}},
    })
    assert "CF-APIGW-005" not in found


def test_http_and_websocket_apis(tmp_path: Path) -> None:
    def route(api: str, key: str, auth: str | None = None) -> dict:
        props: dict = {"ApiId": {"Ref": api}, "RouteKey": key}
        if auth:
            props["AuthorizationType"] = auth
        return {"Type": "AWS::ApiGatewayV2::Route", "Properties": props}

    found = _cf(tmp_path, {
        "Http": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"Name": "h", "ProtocolType": "HTTP"}},
        "Ws": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"Name": "w", "ProtocolType": "WEBSOCKET"}},
        "OpenRoute": route("Http", "GET /items"),
        "JwtRoute": route("Http", "POST /items", "JWT"),
        "Cors": route("Http", "OPTIONS /items"),
        "Connect": route("Ws", "$connect"),
        "Message": route("Ws", "sendMessage"),  # WebSocket authorizes on $connect only
        "Throttled": {"Type": "AWS::ApiGatewayV2::Stage", "Properties": {
            "ApiId": {"Ref": "Http"}, "StageName": "$default",
            "DefaultRouteSettings": {"ThrottlingRateLimit": 100, "ThrottlingBurstLimit": 200}}},
        "Open": {"Type": "AWS::ApiGatewayV2::Stage", "Properties": {"ApiId": {"Ref": "Ws"}, "StageName": "prod"}},
    })
    assert found == {"CF-APIGW-V2-003": {"OpenRoute", "Connect"}, "CF-APIGW-V2-004": {"Open"}}


def test_terraform_api_gateway(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("""\
resource "aws_api_gateway_rest_api" "api" {
  name = "api"
}
resource "aws_api_gateway_method" "get" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = "r"
  http_method   = "GET"
  authorization = "NONE"
}
resource "aws_api_gateway_method" "post" {
  rest_api_id          = aws_api_gateway_rest_api.api.id
  resource_id          = "r"
  http_method          = "POST"
  authorization        = "AWS_IAM"
  request_validator_id = aws_api_gateway_request_validator.body.id
}
resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = "d"
  stage_name    = "prod"
}
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"
  settings {
    throttling_rate_limit = 100
    caching_enabled       = true
  }
}
resource "aws_api_gateway_domain_name" "old" {
  domain_name     = "api.example.com"
  security_policy = "TLS_1_0"
}
resource "aws_apigatewayv2_route" "open" {
  api_id    = "a"
  route_key = "GET /items"
}
resource "aws_apigatewayv2_stage" "default" {
  api_id = "a"
  name   = "$default"
}
""", encoding="utf-8")
    warnings: list[str] = []
    found = _by_id(run_resource_checks(resources_from_terraform(tmp_path, warnings), tmp_path / "main.tf", warnings))
    assert warnings == []
    assert found == {
        "CF-APIGW-003": {"aws_api_gateway_method.get"},
        "CF-APIGW-004": {"aws_api_gateway_domain_name.old"},  # the API default is not judged
        "CF-APIGW-007": {"aws_api_gateway_stage.prod"},  # merged method settings
        "CF-APIGW-008": {"aws_api_gateway_stage.prod"},
        "CF-APIGW-009": {"aws_api_gateway_stage.prod"},
        "CF-APIGW-V2-003": {"aws_apigatewayv2_route.open"},
        "CF-APIGW-V2-004": {"aws_apigatewayv2_stage.default"},
    }


def test_terraform_method_settings_on_an_unknown_stage_are_not_judged(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("""\
variable "stage" { type = string }
resource "aws_api_gateway_stage" "prod" {
  rest_api_id           = "a"
  deployment_id         = "d"
  stage_name            = "prod"
  cache_cluster_enabled = true
  client_certificate_id = "c"
}
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = "a"
  stage_name  = var.stage
  method_path = "*/*"
  settings {
    caching_enabled = true
  }
}
""", encoding="utf-8")
    found = _by_id(run_resource_checks(resources_from_terraform(tmp_path), tmp_path / "main.tf"))
    assert found == {}
