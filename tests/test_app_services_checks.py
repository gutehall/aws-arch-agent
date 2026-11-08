"""AppSync, Transfer Family, App Runner and Elastic Beanstalk: CF-APPSYNC-*, CF-TRANSFER-*,
CF-APPRUNNER-001 and CF-BEANSTALK-*."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = (
    *(f"CF-APPSYNC-00{n}" for n in range(1, 5)),
    *(f"CF-TRANSFER-00{n}" for n in range(1, 4)),
    "CF-APPRUNNER-001",
    *(f"CF-BEANSTALK-00{n}" for n in range(1, 4)),
)
_PARAM = {"Ref": "Param"}
_HEALTH = "aws:elasticbeanstalk:healthreporting:system"
_UPDATES = "aws:elasticbeanstalk:managedactions"
_LOGS = "aws:elasticbeanstalk:cloudwatch:logs"
_ALL_BEANSTALK = {f"CF-BEANSTALK-00{n}" for n in range(1, 4)}


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
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _api(**props: Any) -> dict:
    base = {"Name": "a", "AuthenticationType": "AWS_IAM", "LogConfig": {"FieldLogLevel": "ERROR"}}
    return {"Type": "AWS::AppSync::GraphQLApi", "Properties": {**base, **props}}


def _waf(arn: Any) -> dict:
    return {"Type": "AWS::WAFv2::WebACLAssociation", "Properties": {"ResourceArn": arn, "WebACLArn": "arn:acl"}}


def _cache(api_id: Any) -> dict:
    return {"Type": "AWS::AppSync::ApiCache", "Properties": {"ApiId": api_id}}


def _server(**props: Any) -> dict:
    return {"Type": "AWS::Transfer::Server", "Properties": props}


def _service(**props: Any) -> dict:
    return {"Type": "AWS::AppRunner::Service", "Properties": props}


def _opt(namespace: str, name: str, value: Any) -> dict:
    return {"Namespace": namespace, "OptionName": name, "Value": value}


_GOOD_OPTIONS = [_opt(_HEALTH, "SystemType", "enhanced"), _opt(_UPDATES, "ManagedActionsEnabled", "true"),
                 _opt(_LOGS, "StreamLogs", "true")]


def _env(*options: dict, **props: Any) -> dict:
    return {"Type": "AWS::ElasticBeanstalk::Environment", "Properties": {
        "ApplicationName": "app", "OptionSettings": list(options), **props}}


def _template(*options: dict, **props: Any) -> dict:
    return {"Type": "AWS::ElasticBeanstalk::ConfigurationTemplate", "Properties": {
        "ApplicationName": "app", "OptionSettings": list(options), **props}}


_TF_API = 'name = "a"\n authentication_type = "AWS_IAM"\n'
_TF_LOG = 'log_config {\n cloudwatch_logs_role_arn = "arn:r"\n field_log_level = "ERROR"\n}\n'
_TF_WAF = '''resource "aws_wafv2_web_acl_association" "w" {
  resource_arn = %s
  web_acl_arn = "arn:acl"
}
'''
_TF_CACHE = '''resource "aws_appsync_api_cache" "c" {
  api_id = %s
  api_caching_behavior = "FULL_REQUEST_CACHING"
  ttl = 300
  type = "SMALL"
}
'''


def _tf_setting(namespace: str, name: str, value: str) -> str:
    return f'setting {{\n namespace = "{namespace}"\n name = "{name}"\n value = {value}\n}}\n'


_TF_GOOD = (_tf_setting(_HEALTH, "SystemType", '"enhanced"') + _tf_setting(_UPDATES, "ManagedActionsEnabled", '"true"')
            + _tf_setting(_LOGS, "StreamLogs", '"true"'))


def _tf_env(body: str) -> str:
    return f'resource "aws_elastic_beanstalk_environment" "e" {{\n name = "e"\n application = "a"\n{body}}}\n'


def test_a_hardened_stack_has_no_findings(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Api": _api(),
        "Waf": _waf({"Fn::GetAtt": ["Api", "Arn"]}),
        "Cache": _cache({"Fn::GetAtt": ["Api", "ApiId"]}),
        "Server": _server(Protocols=["SFTP"], LoggingRole="arn:role", EndpointType="VPC"),
        "Service": _service(ObservabilityConfiguration={"ObservabilityEnabled": True,
                                                        "ObservabilityConfigurationArn": "arn:o"}),
        "Env": _env(*_GOOD_OPTIONS),
    }) == {}


def test_a_hardened_terraform_stack_has_no_findings(tmp_path: Path) -> None:
    assert _tf(tmp_path, f'''
resource "aws_appsync_graphql_api" "api" {{
  {_TF_API}{_TF_LOG}}}
{_TF_WAF % "aws_appsync_graphql_api.api.arn"}
{_TF_CACHE % "aws_appsync_graphql_api.api.id"}
resource "aws_transfer_server" "s" {{
  endpoint_type = "VPC"
  protocols = ["SFTP"]
  logging_role = aws_iam_role.r.arn
  endpoint_details {{
    vpc_id = "vpc-1"
  }}
}}
resource "aws_apprunner_service" "r" {{
  service_name = "s"
  observability_configuration {{
    observability_enabled = true
    observability_configuration_arn = aws_apprunner_observability_configuration.o.arn
  }}
}}
{_tf_env(_TF_GOOD)}''') == {}


# --- AppSync logging ---


@pytest.mark.parametrize("log", [None, {"FieldLogLevel": "NONE"}, {"FieldLogLevel": "none"}])
def test_appsync_with_no_field_logging_is_reported(tmp_path: Path, log: Any) -> None:
    found = _cf(tmp_path, {"Api": _api(LogConfig=log)})
    assert found["CF-APPSYNC-001"] == {"Api"}


@pytest.mark.parametrize("log", [
    {"FieldLogLevel": "ERROR"}, {"FieldLogLevel": "ALL"}, {"FieldLogLevel": "INFO"}, {"FieldLogLevel": "DEBUG"},
    {"FieldLogLevel": _PARAM}, _PARAM, {},
])
def test_appsync_field_logging_that_is_not_judged(tmp_path: Path, log: Any) -> None:
    assert "CF-APPSYNC-001" not in _cf(tmp_path, {"Api": _api(LogConfig=log)})


@pytest.mark.parametrize(("body", "fires"), [
    ("", True),
    ('log_config {\n cloudwatch_logs_role_arn = "arn:r"\n field_log_level = "NONE"\n}\n', True),
    (_TF_LOG, False),
    ('log_config {\n cloudwatch_logs_role_arn = "arn:r"\n field_log_level = var.level\n}\n', False),
    ('dynamic "log_config" {\n for_each = var.logs\n content {\n cloudwatch_logs_role_arn = "arn:r"\n'
     ' field_log_level = "NONE"\n}\n}\n', False),
])
def test_appsync_field_logging_in_terraform(tmp_path: Path, body: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_appsync_graphql_api" "api" {{\n {_TF_API}{body}}}\n')
    assert ("CF-APPSYNC-001" in found) is fires


# --- AppSync authentication ---


@pytest.mark.parametrize(("props", "fires"), [
    ({"AuthenticationType": "API_KEY"}, True),
    ({"AuthenticationType": "API_KEY", "AdditionalAuthenticationProviders": []}, True),
    ({"AuthenticationType": "API_KEY", "AdditionalAuthenticationProviders": [{"AuthenticationType": "AWS_IAM"}]}, False),
    ({"AuthenticationType": "AWS_IAM", "AdditionalAuthenticationProviders": [{"AuthenticationType": "API_KEY"}]}, False),
    ({"AuthenticationType": "AWS_IAM"}, False),
    ({"AuthenticationType": _PARAM}, False),
    ({"AuthenticationType": "API_KEY", "AdditionalAuthenticationProviders": _PARAM}, False),
    ({"AuthenticationType": "API_KEY", "AdditionalAuthenticationProviders": [{"AuthenticationType": _PARAM}]}, False),
    ({"AuthenticationType": "API_KEY", "AdditionalAuthenticationProviders": [{"Fn::If": ["C", {}, {}]}]}, False),
])
def test_appsync_api_key_as_the_only_provider(tmp_path: Path, props: dict, fires: bool) -> None:
    assert ("CF-APPSYNC-002" in _cf(tmp_path, {"Api": _api(**props)})) is fires


@pytest.mark.parametrize(("body", "fires"), [
    ('authentication_type = "API_KEY"\n', True),
    ('authentication_type = "API_KEY"\n additional_authentication_provider {\n authentication_type = "AWS_IAM"\n}\n', False),
    ('authentication_type = "AWS_IAM"\n additional_authentication_provider {\n authentication_type = "API_KEY"\n}\n', False),
    ("authentication_type = var.auth\n", False),
    ('authentication_type = "API_KEY"\n additional_authentication_provider {\n authentication_type = var.auth\n}\n', False),
    ('authentication_type = "API_KEY"\n dynamic "additional_authentication_provider" {\n for_each = var.p\n content {\n'
     ' authentication_type = "AWS_IAM"\n}\n}\n', False),
])
def test_appsync_api_key_in_terraform(tmp_path: Path, body: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_appsync_graphql_api" "api" {{\n name = "a"\n {body}{_TF_LOG}}}\n')
    assert ("CF-APPSYNC-002" in found) is fires


# --- AppSync WAF ---


def test_appsync_with_no_association_is_reported(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Api": _api()})["CF-APPSYNC-003"] == {"Api"}


def test_appsync_association_covers_only_its_api(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"Api": _api(), "Other": _api(), "Waf": _waf({"Fn::GetAtt": ["Api", "Arn"]})})
    assert found["CF-APPSYNC-003"] == {"Other"}


def test_an_association_on_an_alb_does_not_cover_an_api(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Api": _api(),
        "Alb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {}},
        "Waf": _waf({"Ref": "Alb"}),
    })
    assert found["CF-APPSYNC-003"] == {"Api"}


@pytest.mark.parametrize("arn", ["arn:aws:appsync:eu-west-1:111122223333:apis/abc", _PARAM])
def test_an_association_the_scan_cannot_tie_counts_for_all_apis(tmp_path: Path, arn: Any) -> None:
    assert "CF-APPSYNC-003" not in _cf(tmp_path, {"Api": _api(), "Other": _api(), "Waf": _waf(arn)})


def test_a_malformed_association_counts_for_all_apis(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {
        "Api": _api(), "Waf": {"Type": "AWS::WAFv2::WebACLAssociation", "Properties": "broken"},
    }}), encoding="utf-8")
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[])
    assert "CF-APPSYNC-003" not in _by_id(found)


@pytest.mark.parametrize("props", [
    {"Visibility": "PRIVATE"}, {"Visibility": _PARAM}, {"ApiType": "MERGED"}, {"ApiType": _PARAM},
])
def test_a_private_or_merged_api_is_not_asked_for_waf(tmp_path: Path, props: dict) -> None:
    assert "CF-APPSYNC-003" not in _cf(tmp_path, {"Api": _api(**props)})


def test_literal_global_graphql_api_is_asked_for_waf(tmp_path: Path) -> None:
    assert "CF-APPSYNC-003" in _cf(tmp_path, {"Api": _api(Visibility="GLOBAL", ApiType="GRAPHQL")})


def test_an_appsync_association_does_not_change_what_cf_waf_001_covers(tmp_path: Path) -> None:
    """Before and after these checks, CF-WAF-001 treats an association it cannot tie to an ALB or
    stage as unlinked."""
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {
        "Api": _api(),
        "Alb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {}},
        "Waf": _waf({"Fn::GetAtt": ["Api", "Arn"]}),
    }}), encoding="utf-8")
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[])
    assert "CF-WAF-001" not in {f.id for f in found}


@pytest.mark.parametrize(("extra", "attrs", "fires"), [
    ("", "", True),
    (_TF_WAF % "aws_appsync_graphql_api.api.arn", "", False),
    (_TF_WAF % "aws_lb.alb.arn" + 'resource "aws_lb" "alb" {\n name = "a"\n}\n', "", True),
    (_TF_WAF % "var.arn", "", False),
    ("", 'visibility = "PRIVATE"\n', False),
    ("", "visibility = var.v\n", False),
    ("", 'api_type = "MERGED"\n', False),
])
def test_appsync_waf_in_terraform(tmp_path: Path, extra: str, attrs: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_appsync_graphql_api" "api" {{\n {_TF_API}{attrs}{_TF_LOG}}}\n{extra}')
    assert ("CF-APPSYNC-003" in found) is fires


# --- AppSync caching ---


def test_appsync_with_no_cache_is_reported(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Api": _api()})["CF-APPSYNC-004"] == {"Api"}


def test_appsync_cache_covers_only_its_api(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"Api": _api(), "Other": _api(), "C": _cache({"Fn::GetAtt": ["Api", "ApiId"]})})
    assert found["CF-APPSYNC-004"] == {"Other"}


@pytest.mark.parametrize("api_id", ["abc123", _PARAM])
def test_a_cache_the_scan_cannot_tie_counts_for_all_apis(tmp_path: Path, api_id: Any) -> None:
    assert "CF-APPSYNC-004" not in _cf(tmp_path, {"Api": _api(), "Other": _api(), "C": _cache(api_id)})


def test_a_merged_api_is_not_asked_for_a_cache(tmp_path: Path) -> None:
    assert "CF-APPSYNC-004" not in _cf(tmp_path, {"Api": _api(ApiType="MERGED")})


@pytest.mark.parametrize(("extra", "fires"), [
    ("", True),
    (_TF_CACHE % "aws_appsync_graphql_api.api.id", False),
    (_TF_CACHE % "var.api_id", False),
    (_TF_CACHE % '"abc123"', False),
])
def test_appsync_cache_in_terraform(tmp_path: Path, extra: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_appsync_graphql_api" "api" {{\n {_TF_API}{_TF_LOG}}}\n{extra}')
    assert ("CF-APPSYNC-004" in found) is fires


def test_appsync_cache_for_another_api_in_terraform(tmp_path: Path) -> None:
    found = _tf(tmp_path, f'''
resource "aws_appsync_graphql_api" "api" {{
  {_TF_API}{_TF_LOG}}}
resource "aws_appsync_graphql_api" "other" {{
  {_TF_API}{_TF_LOG}}}
{_TF_CACHE % "aws_appsync_graphql_api.api.id"}''')
    assert found["CF-APPSYNC-004"] == {"aws_appsync_graphql_api.other"}


# --- Transfer Family ---


@pytest.mark.parametrize(("protocols", "fires"), [
    (["FTP"], True),
    (["SFTP", "FTP"], True),
    ([_PARAM, "FTP"], True),
    (["SFTP"], False),
    (["FTPS"], False),
    (["SFTP", "FTPS", "AS2"], False),
    ([_PARAM], False),
    (_PARAM, False),
    (None, False),
])
def test_transfer_ftp(tmp_path: Path, protocols: Any, fires: bool) -> None:
    props = {"Protocols": protocols} if protocols is not None else {}
    assert ("CF-TRANSFER-001" in _cf(tmp_path, {"S": _server(LoggingRole="arn:r", **props)})) is fires


@pytest.mark.parametrize(("props", "fires"), [
    ({}, True),
    ({"LoggingRole": ""}, True),
    ({"StructuredLogDestinations": []}, True),
    ({"LoggingRole": "", "StructuredLogDestinations": []}, True),
    ({"LoggingRole": "arn:r"}, False),
    ({"StructuredLogDestinations": ["arn:l"]}, False),
    ({"LoggingRole": _PARAM}, False),
    ({"StructuredLogDestinations": _PARAM}, False),
])
def test_transfer_logging(tmp_path: Path, props: dict, fires: bool) -> None:
    assert ("CF-TRANSFER-002" in _cf(tmp_path, {"S": _server(**props)})) is fires


@pytest.mark.parametrize(("endpoint", "fires"), [
    ("PUBLIC", True),
    ("public", True),
    ("VPC", False),
    ("VPC_ENDPOINT", False),
    (_PARAM, False),
    (None, False),  # CloudFormation documents no default
])
def test_transfer_public_endpoint(tmp_path: Path, endpoint: Any, fires: bool) -> None:
    props = {"EndpointType": endpoint} if endpoint is not None else {}
    assert ("CF-TRANSFER-003" in _cf(tmp_path, {"S": _server(**props)})) is fires


@pytest.mark.parametrize(("body", "ids"), [
    ("", {"CF-TRANSFER-002", "CF-TRANSFER-003"}),  # the provider defaults to PUBLIC, and to SFTP
    ('protocols = ["SFTP", "FTP"]\n', {"CF-TRANSFER-001", "CF-TRANSFER-002", "CF-TRANSFER-003"}),
    ('protocols = ["FTP", var.p]\n', {"CF-TRANSFER-002", "CF-TRANSFER-003"}),  # the list is one unknown expression
    ('protocols = ["FTPS"]\n', {"CF-TRANSFER-002", "CF-TRANSFER-003"}),
    ("protocols = var.p\n", {"CF-TRANSFER-002", "CF-TRANSFER-003"}),
    ('endpoint_type = "PUBLIC"\n', {"CF-TRANSFER-002", "CF-TRANSFER-003"}),
    ('endpoint_type = "VPC"\n', {"CF-TRANSFER-002"}),
    ("endpoint_type = var.t\n", {"CF-TRANSFER-002"}),
    ('endpoint_details {\n vpc_id = "v"\n}\n', {"CF-TRANSFER-002"}),
    ('endpoint_type = "VPC"\n logging_role = var.r\n', set()),
    ('endpoint_type = "VPC"\n logging_role = aws_iam_role.r.arn\n', set()),
    ('endpoint_type = "VPC"\n structured_log_destinations = ["arn:l"]\n', set()),
    ('endpoint_type = "VPC"\n structured_log_destinations = var.d\n', set()),
    ('endpoint_type = "VPC"\n structured_log_destinations = []\n', {"CF-TRANSFER-002"}),
])
def test_transfer_in_terraform(tmp_path: Path, body: str, ids: set[str]) -> None:
    assert set(_tf(tmp_path, f'resource "aws_transfer_server" "s" {{\n {body}}}\n')) == ids


# --- App Runner ---


@pytest.mark.parametrize(("config", "fires"), [
    (None, True),
    ({"ObservabilityEnabled": False}, True),
    ({"ObservabilityEnabled": "false"}, True),
    ({"ObservabilityEnabled": True}, False),
    ({"ObservabilityEnabled": "true", "ObservabilityConfigurationArn": "arn:o"}, False),
    ({"ObservabilityEnabled": _PARAM}, False),
    (_PARAM, False),
])
def test_app_runner_observability(tmp_path: Path, config: Any, fires: bool) -> None:
    props = {"ObservabilityConfiguration": config} if config is not None else {}
    assert ("CF-APPRUNNER-001" in _cf(tmp_path, {"S": _service(**props)})) is fires


@pytest.mark.parametrize(("body", "fires"), [
    ("", True),
    ("observability_configuration {\n observability_enabled = false\n}\n", True),
    ('observability_configuration {\n observability_enabled = true\n observability_configuration_arn = "arn:o"\n}\n', False),
    ("observability_configuration {\n observability_enabled = var.o\n}\n", False),
    ('dynamic "observability_configuration" {\n for_each = var.o\n content {\n observability_enabled = false\n}\n}\n', False),
])
def test_app_runner_observability_in_terraform(tmp_path: Path, body: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_apprunner_service" "s" {{\n service_name = "s"\n {body}}}\n')
    assert ("CF-APPRUNNER-001" in found) is fires


# --- Elastic Beanstalk ---


def test_beanstalk_with_nothing_set_gets_all_three(tmp_path: Path) -> None:
    assert set(_cf(tmp_path, {"E": _env()})) == _ALL_BEANSTALK


def test_beanstalk_with_no_option_settings_at_all_gets_all_three(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"E": {"Type": "AWS::ElasticBeanstalk::Environment", "Properties": {"ApplicationName": "a"}}})
    assert set(found) == _ALL_BEANSTALK


@pytest.mark.parametrize(("option", "check"), [
    (_opt(_HEALTH, "SystemType", "basic"), "CF-BEANSTALK-001"),
    (_opt(_UPDATES, "ManagedActionsEnabled", "false"), "CF-BEANSTALK-002"),
    (_opt(_UPDATES, "ManagedActionsEnabled", False), "CF-BEANSTALK-002"),
    (_opt(_LOGS, "StreamLogs", "false"), "CF-BEANSTALK-003"),
    (_opt(_LOGS, "StreamLogs", "FALSE"), "CF-BEANSTALK-003"),
])
def test_beanstalk_a_bad_value_is_reported(tmp_path: Path, option: dict, check: str) -> None:
    others = [o for o in _GOOD_OPTIONS if o["OptionName"] != option["OptionName"]]
    assert set(_cf(tmp_path, {"E": _env(*others, option)})) == {check}


@pytest.mark.parametrize("option", [
    _opt(_HEALTH, "SystemType", "Enhanced"),
    _opt(_UPDATES, "ManagedActionsEnabled", "True"),
    _opt(_UPDATES.upper(), "ManagedActionsEnabled", True),
    _opt(_LOGS, "StreamLogs", True),
])
def test_beanstalk_a_good_value_in_another_case_passes(tmp_path: Path, option: dict) -> None:
    others = [o for o in _GOOD_OPTIONS if o["OptionName"] != option["OptionName"]]
    assert _cf(tmp_path, {"E": _env(*others, option)}) == {}


def test_beanstalk_one_unknown_value_leaves_the_others_judged(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"E": _env(_opt(_HEALTH, "SystemType", _PARAM))})
    assert set(found) == {"CF-BEANSTALK-002", "CF-BEANSTALK-003"}


@pytest.mark.parametrize("settings", [
    _PARAM,
    [{"Fn::If": ["C", _opt(_LOGS, "StreamLogs", "true"), {"Ref": "AWS::NoValue"}]}],
    [{"Namespace": _PARAM, "OptionName": "SystemType", "Value": "enhanced"}],
    [{"Namespace": _HEALTH, "OptionName": _PARAM, "Value": "enhanced"}],
])
def test_beanstalk_settings_the_scan_cannot_read_are_not_judged(tmp_path: Path, settings: Any) -> None:
    env = {"Type": "AWS::ElasticBeanstalk::Environment", "Properties": {"ApplicationName": "a", "OptionSettings": settings}}
    assert _cf(tmp_path, {"E": env}) == {}


def test_beanstalk_merges_a_template_in_this_file(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "T": _template(_opt(_HEALTH, "SystemType", "enhanced"), _opt(_LOGS, "StreamLogs", "true")),
        "E": _env(TemplateName={"Ref": "T"}),
    })
    assert set(found) == {"CF-BEANSTALK-002"}


def test_beanstalk_environment_settings_win_over_the_template(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "T": _template(*_GOOD_OPTIONS),
        "E": _env(_opt(_LOGS, "StreamLogs", "false"), TemplateName={"Ref": "T"}),
    })
    assert set(found) == {"CF-BEANSTALK-003"}


def test_beanstalk_a_template_alone_is_not_judged(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"T": _template()}) == {}


@pytest.mark.parametrize("name", ["external", "T", _PARAM, {"Fn::ImportValue": "x"}])
def test_beanstalk_template_outside_the_scan_is_not_judged(tmp_path: Path, name: Any) -> None:
    """A literal that equals a logical id is not that template: CloudFormation generates its name."""
    assert _cf(tmp_path, {"T": _template(), "E": _env(TemplateName=name)}) == {}


@pytest.mark.parametrize("template", [
    _template(OptionSettings=_PARAM),
    _template(SourceConfiguration={"ApplicationName": "a", "TemplateName": "b"}),
    _template(EnvironmentId="e-123"),
    _template(EnvironmentId=_PARAM),
])
def test_beanstalk_template_the_scan_cannot_read_is_not_judged(tmp_path: Path, template: dict) -> None:
    assert _cf(tmp_path, {"T": template, "E": _env(TemplateName={"Ref": "T"})}) == {}


def test_beanstalk_malformed_template_is_not_judged(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {
        "T": {"Type": "AWS::ElasticBeanstalk::ConfigurationTemplate", "Properties": "broken"},
        "E": _env(TemplateName={"Ref": "T"}),
    }}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert _by_id(found) == {}
    assert any("T" in w for w in warnings)


@pytest.mark.parametrize(("body", "ids"), [
    ("", _ALL_BEANSTALK),
    (_TF_GOOD, set()),
    (_tf_setting(_HEALTH, "SystemType", '"basic"'), _ALL_BEANSTALK),
    (_tf_setting(_LOGS, "StreamLogs", "true"), {"CF-BEANSTALK-001", "CF-BEANSTALK-002"}),
    (_tf_setting(_HEALTH, "SystemType", "var.h"), {"CF-BEANSTALK-002", "CF-BEANSTALK-003"}),
    (_tf_setting(_UPDATES, "ManagedActionsEnabled", "var.u"), {"CF-BEANSTALK-001", "CF-BEANSTALK-003"}),
    ('setting {\n namespace = var.n\n name = "SystemType"\n value = "enhanced"\n}\n', set()),
    (f'dynamic "setting" {{\n for_each = var.s\n content {{\n namespace = "{_HEALTH}"\n name = "SystemType"\n'
     ' value = "basic"\n}\n}\n', set()),
    ("template_name = var.t\n", set()),
    ('template_name = "external"\n', set()),
])
def test_beanstalk_in_terraform(tmp_path: Path, body: str, ids: set[str]) -> None:
    assert set(_tf(tmp_path, _tf_env(body))) == ids


_TF_TEMPLATE = '''resource "aws_elastic_beanstalk_configuration_template" "t" {
  name = "tpl"
  application = "a"
%s}
'''


@pytest.mark.parametrize("reference", ["aws_elastic_beanstalk_configuration_template.t.name", '"tpl"'])
def test_beanstalk_merges_a_template_in_terraform(tmp_path: Path, reference: str) -> None:
    template = _TF_TEMPLATE % (_tf_setting(_HEALTH, "SystemType", '"enhanced"') + _tf_setting(_LOGS, "StreamLogs", '"true"'))
    found = _tf(tmp_path, template + _tf_env(f"template_name = {reference}\n"))
    assert set(found) == {"CF-BEANSTALK-002"}


@pytest.mark.parametrize("body", [
    f'dynamic "setting" {{\n for_each = var.s\n content {{\n namespace = "{_LOGS}"\n name = "StreamLogs"\n value = "false"\n}}\n}}\n',
    "environment_id = var.e\n",
])
def test_beanstalk_terraform_template_the_scan_cannot_read_is_not_judged(tmp_path: Path, body: str) -> None:
    found = _tf(tmp_path, _TF_TEMPLATE % body + _tf_env("template_name = aws_elastic_beanstalk_configuration_template.t.name\n"))
    assert found == {}


# --- every check ---


@pytest.mark.parametrize("check", IDS)
def test_each_check_has_a_fix_in_both_languages(check: str) -> None:
    assert check in SNIPPETS["cloudformation"]
    assert check in SNIPPETS["terraform"]
