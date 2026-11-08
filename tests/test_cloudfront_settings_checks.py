"""CloudFront logging, price class, compression, origins, certificates, caching: CF-CF-005..013."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.report.doc_topics import RULE_TOPICS
from aws_arch_agent.rules.cf_template import (
    CF_COVERS_STATIC,
    CF_THEMES,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = tuple(f"CF-CF-{n:03d}" for n in range(5, 14))
_PARAM = {"Ref": "Param"}
_IF = {"Fn::If": ["C", "a", "b"]}
_VAR = 'variable "x" {}\n'
_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_S3 = {"Id": "s3", "DomainName": "b.s3.amazonaws.com", "S3OriginConfig": {}, "OriginAccessControlId": "o"}


def _findings(found: list[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, []).append(f)
    return out


def _cf(tmp_path: Path, resources: dict) -> dict[str, list[Finding]]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _findings(found)


def _tf(tmp_path: Path, text: str) -> dict[str, list[Finding]]:
    path = tmp_path / "main.tf"
    path.write_text(_VAR + text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _findings(run_resource_checks(resources, path))


def _custom(policy: Any = "https-only", name: str = "app", **settings: Any) -> dict:
    return {"Id": name, "DomainName": "app.example.com",
            "CustomOriginConfig": {"OriginProtocolPolicy": policy, **settings}}


def _dist(*origins: Any, default: dict | None = None, behaviors: list | None = None, **config: Any) -> dict:
    body: dict = {
        "Origins": list(origins) or [_custom()],
        "DefaultCacheBehavior": {"TargetOriginId": "app", "ViewerProtocolPolicy": "https-only",
                                 **(default or {})},
        **config,
    }
    if behaviors is not None:
        body["CacheBehaviors"] = behaviors
    return {"Type": "AWS::CloudFront::Distribution", "Properties": {"DistributionConfig": body}}


def _behavior(path: Any = "/x/*", **props: Any) -> dict:
    return {"PathPattern": path, "TargetOriginId": "app", "ViewerProtocolPolicy": "https-only", **props}


def _tf_dist(*blocks: str, default: str = "") -> str:
    body = "\n".join(blocks) or _tf_custom()
    return f"""
resource "aws_cloudfront_distribution" "d" {{
  {body}
  default_cache_behavior {{
    target_origin_id = "app"
    viewer_protocol_policy = "https-only"
    {default}
  }}
}}
"""


def _tf_custom(policy: str = '"https-only"', protocols: str = '["TLSv1.2"]', origin_id: str = "app") -> str:
    return f"""
  origin {{
    origin_id   = "{origin_id}"
    domain_name = "app.example.com"
    custom_origin_config {{
      http_port = 80
      https_port = 443
      origin_protocol_policy = {policy}
      origin_ssl_protocols = {protocols}
    }}
  }}"""


_TF_S3 = """
  origin {
    origin_id   = "s3"
    domain_name = "b.s3.amazonaws.com"
    origin_access_control_id = "o"
    s3_origin_config {
      origin_access_identity = ""
    }
  }"""


# --- CF-CF-005: logging ---


def test_cf_no_logging_reports(tmp_path: Path) -> None:
    assert "CF-CF-005" in _cf(tmp_path, {"D": _dist()})


@pytest.mark.parametrize("config", [
    {"Logging": {"Bucket": "b.s3.amazonaws.com"}},
    {"Logging": {"Bucket": _PARAM}},
    {"Logging": _IF},
    {"default": {"RealtimeLogConfigArn": "arn:aws:cloudfront::1:realtime-log-config/x"}},
    {"behaviors": [_behavior(RealtimeLogConfigArn=_PARAM)]},
    {"behaviors": _IF},
    {"behaviors": [_IF]},
])
def test_cf_logging_set_is_quiet(tmp_path: Path, config: dict) -> None:
    assert "CF-CF-005" not in _cf(tmp_path, {"D": _dist(**config)})


def _source(arn: Any) -> dict:
    return {"Type": "AWS::Logs::DeliverySource",
            "Properties": {"Name": "s", "LogType": "ACCESS_LOGS", "ResourceArn": arn}}


@pytest.mark.parametrize("arn", [
    {"Fn::Sub": "arn:aws:cloudfront::${AWS::AccountId}:distribution/${D}"},
    {"Fn::Sub": "arn:aws:cloudfront::1:distribution/${Param}"},  # cannot be tied: counts for all
    _PARAM,
    "arn:aws:cloudfront::111122223333:distribution/E123",
])
def test_cf_delivery_source_counts_as_logging(tmp_path: Path, arn: Any) -> None:
    assert "CF-CF-005" not in _cf(tmp_path, {"D": _dist(), "S": _source(arn)})


def test_cf_delivery_source_only_covers_its_own_distribution(tmp_path: Path) -> None:
    arn = {"Fn::Sub": "arn:aws:cloudfront::1:distribution/${D}"}
    found = _cf(tmp_path, {"D": _dist(), "E": _dist(), "S": _source(arn)})
    assert [f.evidence for f in found["CF-CF-005"]] == ["E (AWS::CloudFront::Distribution)"]


@pytest.mark.parametrize("arn", [
    "arn:aws:lambda:eu-north-1:111122223333:function:f",
    {"Fn::GetAtt": ["Fn", "Arn"]},
])
def test_cf_delivery_source_of_another_service_does_not_count(tmp_path: Path, arn: Any) -> None:
    fn = {"Type": "AWS::Lambda::Function", "Properties": {
        "Role": "arn:aws:iam::1:role/r", "Handler": "i.h", "Runtime": "nodejs22.x", "Code": {"ZipFile": "x"}}}
    assert "CF-CF-005" in _cf(tmp_path, {"D": _dist(), "Fn": fn, "S": _source(arn)})


def test_tf_no_logging_reports(tmp_path: Path) -> None:
    assert "CF-CF-005" in _tf(tmp_path, _tf_dist())


@pytest.mark.parametrize("block", [
    'logging_config {\n bucket = "b.s3.amazonaws.com"\n}',
    "logging_config {\n bucket = var.x\n}",
    'dynamic "logging_config" {\n for_each = var.x\n content {\n bucket = "b"\n }\n}',
    'dynamic "ordered_cache_behavior" {\n for_each = var.x\n content {\n path_pattern = "/a"\n }\n}',
])
def test_tf_logging_set_or_unknown_is_quiet(tmp_path: Path, block: str) -> None:
    assert "CF-CF-005" not in _tf(tmp_path, _tf_dist(_tf_custom(), block))


@pytest.mark.parametrize("arn", ["var.x", '"arn:aws:cloudfront::1:distribution/${var.x}"'])
def test_tf_realtime_log_is_logging(tmp_path: Path, arn: str) -> None:
    found = _tf(tmp_path, _tf_dist(default=f"realtime_log_config_arn = {arn}"))
    assert "CF-CF-005" not in found


def _tf_source(arn: str) -> str:
    return f"""
resource "aws_cloudwatch_log_delivery_source" "s" {{
  name = "s"
  log_type = "ACCESS_LOGS"
  resource_arn = {arn}
}}
"""


@pytest.mark.parametrize("arn", ["aws_cloudfront_distribution.d.arn", "var.x", "module.cdn.arn"])
def test_tf_delivery_source_counts_as_logging(tmp_path: Path, arn: str) -> None:
    assert "CF-CF-005" not in _tf(tmp_path, _tf_dist() + _tf_source(arn))


def test_tf_delivery_source_of_another_distribution_does_not_count(tmp_path: Path) -> None:
    other = _tf_dist().replace('"d"', '"other"')
    found = _tf(tmp_path, _tf_dist() + other + _tf_source("aws_cloudfront_distribution.other.arn"))
    assert [f.evidence for f in found["CF-CF-005"]] == ["aws_cloudfront_distribution.d (aws_cloudfront_distribution)"]


# --- CF-CF-006: price class ---


@pytest.mark.parametrize("config", [{}, {"PriceClass": "PriceClass_All"}])
def test_cf_price_class_reports(tmp_path: Path, config: dict) -> None:
    assert "CF-CF-006" in _cf(tmp_path, {"D": _dist(**config)})


@pytest.mark.parametrize("config", [
    {"PriceClass": "PriceClass_100"}, {"PriceClass": "PriceClass_200"}, {"PriceClass": _PARAM}, {"PriceClass": _IF},
    {"ConnectionMode": "tenant-only"}, {"ConnectionMode": _PARAM},
])
def test_cf_price_class_quiet(tmp_path: Path, config: dict) -> None:
    assert "CF-CF-006" not in _cf(tmp_path, {"D": _dist(**config)})


@pytest.mark.parametrize("line", ["", 'price_class = "PriceClass_All"'])
def test_tf_price_class_reports(tmp_path: Path, line: str) -> None:
    assert "CF-CF-006" in _tf(tmp_path, _tf_dist(_tf_custom(), line))


@pytest.mark.parametrize("line", ['price_class = "PriceClass_100"', "price_class = var.x"])
def test_tf_price_class_quiet(tmp_path: Path, line: str) -> None:
    assert "CF-CF-006" not in _tf(tmp_path, _tf_dist(_tf_custom(), line))


# --- CF-CF-007: compression ---


def test_cf_compress_reports_once_with_the_paths(tmp_path: Path) -> None:
    behaviors = [_behavior("/a/*"), _behavior("/b/*", Compress=False), _behavior("/c/*", Compress=True)]
    found = _cf(tmp_path, {"D": _dist(behaviors=behaviors)})["CF-CF-007"]
    assert len(found) == 1
    assert "default, /a/*, /b/*" in found[0].recommendation
    assert "/c/*" not in found[0].recommendation


@pytest.mark.parametrize("default", [
    {"Compress": True},
    {"Compress": "true"},
    {"Compress": _PARAM},
    {"Compress": _IF},
    {"CachePolicyId": _DISABLED},  # compression does not work without caching
    {"CachePolicyId": _PARAM},  # may be CachingDisabled
])
def test_cf_compress_quiet(tmp_path: Path, default: dict) -> None:
    assert "CF-CF-007" not in _cf(tmp_path, {"D": _dist(default=default)})


def test_cf_compress_reports_with_a_caching_policy(tmp_path: Path) -> None:
    assert "CF-CF-007" in _cf(tmp_path, {"D": _dist(default={"CachePolicyId": _OPTIMIZED})})


def test_cf_compress_unknown_behavior_does_not_hide_a_known_one(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"D": _dist(default={"Compress": True}, behaviors=[_IF, _behavior("/a/*")])})
    assert "/a/*" in found["CF-CF-007"][0].recommendation


def test_tf_compress_reports(tmp_path: Path) -> None:
    ordered = 'ordered_cache_behavior {\n path_pattern = "/a/*"\n target_origin_id = "app"\n compress = false\n}'
    found = _tf(tmp_path, _tf_dist(_tf_custom(), ordered, default="compress = true"))["CF-CF-007"]
    assert len(found) == 1
    assert "/a/*" in found[0].recommendation
    assert "default" not in found[0].recommendation


@pytest.mark.parametrize("line", [
    "compress = true",
    "compress = var.x",
    f'cache_policy_id = "{_DISABLED}"',
    "cache_policy_id = var.x",
    "cache_policy_id = data.aws_cloudfront_cache_policy.p.id",
])
def test_tf_compress_quiet(tmp_path: Path, line: str) -> None:
    assert "CF-CF-007" not in _tf(tmp_path, _tf_dist(default=line))


# --- CF-CF-008: default root object ---


def test_cf_root_object_reports_on_s3_target(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"D": _dist(_S3, _custom(), default={"TargetOriginId": "s3"})})
    assert "CF-CF-008" in found


@pytest.mark.parametrize("target", [_PARAM, None])
def test_cf_root_object_reports_when_all_origins_are_s3_and_target_is_unclear(tmp_path: Path, target: Any) -> None:
    other = {**_S3, "Id": "s3b"}
    found = _cf(tmp_path, {"D": _dist(_S3, other, default={"TargetOriginId": target})})
    assert "CF-CF-008" in found


def test_cf_root_object_reports_through_an_origin_group(tmp_path: Path) -> None:
    other = {**_S3, "Id": "s3b"}
    groups = {"Quantity": 1, "Items": [{"Id": "g", "Members": {
        "Quantity": 2, "Items": [{"OriginId": "s3"}, {"OriginId": "s3b"}]}}]}
    found = _cf(tmp_path, {"D": _dist(_S3, other, default={"TargetOriginId": "g"}, OriginGroups=groups)})
    assert "CF-CF-008" in found


@pytest.mark.parametrize(("origins", "config"), [
    ([_custom()], {}),  # an API has no root object
    ([_S3, _custom()], {"default": {"TargetOriginId": "app"}}),  # the S3 origin serves a path
    ([_S3, _custom()], {"default": {"TargetOriginId": _PARAM}}),  # cannot be tied, and not all S3
    ([_S3], {"DefaultRootObject": "index.html"}),
    ([_S3], {"DefaultRootObject": _PARAM}),
    ([_S3], {"default": {"FunctionAssociations": [{"EventType": "viewer-request", "FunctionARN": "a"}]}}),
    ([_S3], {"default": {"LambdaFunctionAssociations": [{"EventType": "origin-request", "LambdaFunctionARN": "a"}]}}),
    ([_S3], {"default": {"FunctionAssociations": _IF}}),
    ([{"Id": "w", "DomainName": "b.s3-website-eu-north-1.amazonaws.com"}], {}),  # has its own index document
    ([{**_S3, "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"}, "S3OriginConfig": None}], {}),
    ([_IF, _S3], {"default": {"TargetOriginId": _PARAM}}),
])
def test_cf_root_object_quiet(tmp_path: Path, origins: list, config: dict) -> None:
    assert "CF-CF-008" not in _cf(tmp_path, {"D": _dist(*origins, **config)})


def test_cf_root_object_ignores_a_response_function(tmp_path: Path) -> None:
    default = {"FunctionAssociations": [{"EventType": "viewer-response", "FunctionARN": "a"}]}
    assert "CF-CF-008" in _cf(tmp_path, {"D": _dist(_S3, default=default)})


def test_tf_root_object_reports(tmp_path: Path) -> None:
    assert "CF-CF-008" in _tf(tmp_path, _tf_dist(_TF_S3))


@pytest.mark.parametrize("blocks", [
    (_TF_S3, 'default_root_object = "index.html"'),
    (_TF_S3, "default_root_object = var.x"),
    (_tf_custom(),),
    (_TF_S3, _tf_custom()),  # target_origin_id is app, the custom origin
    (_TF_S3, 'dynamic "origin" {\n for_each = var.x\n content {\n origin_id = "y"\n domain_name = "z"\n }\n}'),
])
def test_tf_root_object_quiet(tmp_path: Path, blocks: tuple) -> None:
    assert "CF-CF-008" not in _tf(tmp_path, _tf_dist(*blocks))


def test_tf_root_object_quiet_with_request_function(tmp_path: Path) -> None:
    line = 'function_association {\n event_type = "viewer-request"\n function_arn = "a"\n}'
    assert "CF-CF-008" not in _tf(tmp_path, _tf_dist(_TF_S3, default=line))


def test_tf_root_object_unknown_ids_are_not_the_same_origin(tmp_path: Path) -> None:
    # Both ids are unknown, so the target is not tied, and not every origin is an S3 origin.
    s3 = _TF_S3.replace('"s3"', "var.x")
    text = _tf_dist(s3, _tf_custom()).replace('target_origin_id = "app"', "target_origin_id = var.x")
    assert "CF-CF-008" not in _tf(tmp_path, text)


# --- CF-CF-009: origin failover ---


def _groups(*members: Any) -> dict:
    return {"Quantity": 1, "Items": [{"Id": "g", "Members": {"Quantity": len(members), "Items": list(members)}}]}


@pytest.mark.parametrize("config", [
    {},
    {"OriginGroups": {"Quantity": 0}},
    {"OriginGroups": {"Quantity": 0, "Items": []}},
    {"OriginGroups": _groups({"OriginId": "app"})},
])
def test_cf_origin_group_reports(tmp_path: Path, config: dict) -> None:
    found = _cf(tmp_path, {"D": _dist(**config)})["CF-CF-009"]
    assert "one origin" in found[0].recommendation


@pytest.mark.parametrize("groups", [
    _groups({"OriginId": "a"}, {"OriginId": "b"}),
    _PARAM,
    _IF,
    {"Quantity": 1, "Items": _IF},
    {"Quantity": 1, "Items": [_IF]},
    {"Quantity": 1, "Items": [{"Id": "g", "Members": _IF}]},
])
def test_cf_origin_group_quiet(tmp_path: Path, groups: Any) -> None:
    assert "CF-CF-009" not in _cf(tmp_path, {"D": _dist(OriginGroups=groups)})


def test_tf_origin_group_reports(tmp_path: Path) -> None:
    assert "CF-CF-009" in _tf(tmp_path, _tf_dist())


@pytest.mark.parametrize("block", [
    'origin_group {\n origin_id = "g"\n member {\n origin_id = "a"\n }\n member {\n origin_id = var.x\n }\n}',
    'dynamic "origin_group" {\n for_each = var.x\n content {\n origin_id = "g"\n }\n}',
    'origin_group {\n origin_id = "g"\n dynamic "member" {\n for_each = var.x\n content {\n'
    ' origin_id = "a"\n }\n }\n}',
])
def test_tf_origin_group_quiet(tmp_path: Path, block: str) -> None:
    assert "CF-CF-009" not in _tf(tmp_path, _tf_dist(_tf_custom(), block))


# --- CF-CF-010: plain HTTP to a custom origin ---


def test_cf_http_only_reports(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"D": _dist(_custom("http-only"))})["CF-CF-010"]
    assert found[0].severity == "Medium"


def test_cf_match_viewer_behind_allow_all_reports(tmp_path: Path) -> None:
    origin = _custom("match-viewer")
    assert "CF-CF-010" in _cf(tmp_path, {"D": _dist(origin, default={"ViewerProtocolPolicy": "allow-all"})})


def test_cf_match_viewer_behind_allow_all_reports_through_a_group(tmp_path: Path) -> None:
    groups = {"Quantity": 1, "Items": [{"Id": "g", "Members": {"Quantity": 2, "Items": [
        {"OriginId": "app"}, {"OriginId": "other"}]}}]}
    found = _cf(tmp_path, {"D": _dist(
        _custom("match-viewer"), _custom(name="other"), OriginGroups=groups,
        default={"TargetOriginId": "g", "ViewerProtocolPolicy": "allow-all"},
    )})
    assert "OriginProtocolPolicy is match-viewer on origins: app," in found["CF-CF-010"][0].recommendation


@pytest.mark.parametrize(("origins", "config"), [
    ([_custom("https-only")], {}),
    ([_custom(_PARAM)], {}),
    ([_custom("match-viewer")], {}),  # viewers are on HTTPS only
    ([_custom("match-viewer")], {"default": {"ViewerProtocolPolicy": _PARAM}}),
    ([_custom("match-viewer"), _custom(name="b")],  # allow-all goes to the other origin
     {"default": {"TargetOriginId": "b", "ViewerProtocolPolicy": "allow-all"}}),
    ([_custom("match-viewer"), _custom(name="b")],  # cannot be tied
     {"default": {"TargetOriginId": _PARAM, "ViewerProtocolPolicy": "allow-all"}}),
    ([{**_S3, "CustomOriginConfig": {"OriginProtocolPolicy": "http-only"}}], {}),  # S3OriginConfig
    ([{"Id": "w", "DomainName": "b.s3-website-eu-north-1.amazonaws.com",
       "CustomOriginConfig": {"OriginProtocolPolicy": "http-only"}}], {}),
    ([{"Id": "w", "DomainName": {"Fn::Sub": "${B}.s3-website-${AWS::Region}.amazonaws.com"},
       "CustomOriginConfig": {"OriginProtocolPolicy": "http-only"}}], {}),
    ([{"Id": "w", "DomainName": {"Fn::Select": [2, {"Fn::Split": ["/", {"Fn::GetAtt": ["B", "WebsiteURL"]}]}]},
       "CustomOriginConfig": {"OriginProtocolPolicy": "http-only"}}], {}),
    ([{"Id": "c", "DomainName": "a", "CustomOriginConfig": _IF}], {}),
])
def test_cf_origin_http_quiet(tmp_path: Path, origins: list, config: dict) -> None:
    assert "CF-CF-010" not in _cf(tmp_path, {"D": _dist(*origins, **config)})


def test_tf_http_only_reports(tmp_path: Path) -> None:
    assert "CF-CF-010" in _tf(tmp_path, _tf_dist(_tf_custom('"http-only"')))


def test_tf_match_viewer_behind_allow_all_reports(tmp_path: Path) -> None:
    text = _tf_dist(_tf_custom('"match-viewer"')).replace(
        'viewer_protocol_policy = "https-only"', 'viewer_protocol_policy = "allow-all"')
    assert "CF-CF-010" in _tf(tmp_path, text)


@pytest.mark.parametrize("text", [
    _tf_dist(_tf_custom('"https-only"')),
    _tf_dist(_tf_custom("var.x")),
    _tf_dist(_tf_custom('"match-viewer"')),
    _tf_dist(_tf_custom('"match-viewer"')).replace(
        'viewer_protocol_policy = "https-only"', "viewer_protocol_policy = var.x"),
    _tf_dist(_tf_custom('"http-only"')).replace(
        '"app.example.com"', "aws_s3_bucket_website_configuration.w.website_endpoint"),
    _tf_dist('origin {\n origin_id = "app"\n domain_name = "a"\n dynamic "custom_origin_config" {\n'
             ' for_each = var.x\n content {\n origin_protocol_policy = "http-only"\n }\n }\n}'),
])
def test_tf_origin_http_quiet(tmp_path: Path, text: str) -> None:
    assert "CF-CF-010" not in _tf(tmp_path, text)


def test_tf_unknown_value_does_not_hide_the_rest(tmp_path: Path) -> None:
    # Unknown nested values must not drop DistributionConfig, or every check here goes quiet.
    text = _tf_dist(_tf_custom('"http-only"', "var.x"), "price_class = var.x", "web_acl_id = var.x",
                    default="compress = var.x")
    found = _tf(tmp_path, text)
    assert "CF-CF-010" in found
    assert "CF-CF-005" in found
    assert "CF-CF-006" not in found
    assert "CF-CF-007" not in found


# --- CF-CF-011: SSLv3 to a custom origin ---


def test_cf_sslv3_reports(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"D": _dist(_custom(OriginSSLProtocols=["SSLv3", "TLSv1.2"]))})
    assert found["CF-CF-011"][0].severity == "Medium"


@pytest.mark.parametrize("origin", [
    _custom(OriginSSLProtocols=["TLSv1.2"]),
    _custom(),
    _custom(OriginSSLProtocols=_PARAM),
    _custom(OriginSSLProtocols=_IF),
    _custom(OriginSSLProtocols=[_PARAM]),
    {**_S3, "CustomOriginConfig": {"OriginSSLProtocols": ["SSLv3"]}},  # S3OriginConfig
])
def test_cf_sslv3_quiet(tmp_path: Path, origin: dict) -> None:
    assert "CF-CF-011" not in _cf(tmp_path, {"D": _dist(origin)})


@pytest.mark.parametrize("protocols", ['["SSLv3", "TLSv1.2"]', '["SSLv3", var.x]'])
def test_tf_sslv3_reports(tmp_path: Path, protocols: str) -> None:
    assert "CF-CF-011" in _tf(tmp_path, _tf_dist(_tf_custom(protocols=protocols)))


@pytest.mark.parametrize("protocols", ['["TLSv1.2"]', "var.x", "[var.x]", "local.protocols"])
def test_tf_sslv3_quiet(tmp_path: Path, protocols: str) -> None:
    assert "CF-CF-011" not in _tf(tmp_path, _tf_dist(_tf_custom(protocols=protocols)))


# --- CF-CF-012: dedicated IP certificate ---


def test_cf_vip_reports(tmp_path: Path) -> None:
    cert = {"AcmCertificateArn": "arn", "SslSupportMethod": "vip"}
    assert "CF-CF-012" in _cf(tmp_path, {"D": _dist(ViewerCertificate=cert)})


@pytest.mark.parametrize("cert", [
    {"AcmCertificateArn": "arn", "SslSupportMethod": "sni-only"},
    {"AcmCertificateArn": "arn", "SslSupportMethod": _PARAM},
    {"CloudFrontDefaultCertificate": True},
    _IF,
])
def test_cf_vip_quiet(tmp_path: Path, cert: Any) -> None:
    assert "CF-CF-012" not in _cf(tmp_path, {"D": _dist(ViewerCertificate=cert)})


def test_tf_vip_reports(tmp_path: Path) -> None:
    block = 'viewer_certificate {\n acm_certificate_arn = "a"\n ssl_support_method = "vip"\n}'
    assert "CF-CF-012" in _tf(tmp_path, _tf_dist(_tf_custom(), block))


@pytest.mark.parametrize("value", ['"sni-only"', "var.x"])
def test_tf_vip_quiet(tmp_path: Path, value: str) -> None:
    block = f'viewer_certificate {{\n acm_certificate_arn = "a"\n ssl_support_method = {value}\n}}'
    assert "CF-CF-012" not in _tf(tmp_path, _tf_dist(_tf_custom(), block))


# --- CF-CF-013: caching on static paths ---


@pytest.mark.parametrize("path", [
    "*.js", "*.css", "*.png", "/img/*.JPG", "/static/*", "/assets/*", "assets/*", "/_next/static/*", "*.woff2",
])
def test_cf_static_path_without_caching_reports(tmp_path: Path, path: str) -> None:
    found = _cf(tmp_path, {"D": _dist(behaviors=[_behavior(path, CachePolicyId=_DISABLED)])})
    assert path in found["CF-CF-013"][0].recommendation


@pytest.mark.parametrize("behavior", [
    _behavior("/api/*", CachePolicyId=_DISABLED),
    _behavior("/api/assets/*", CachePolicyId=_DISABLED),
    _behavior("*.json", CachePolicyId=_DISABLED),
    _behavior(_PARAM, CachePolicyId=_DISABLED),
    _behavior("*.js", CachePolicyId=_OPTIMIZED),
    _behavior("*.js", CachePolicyId=_PARAM),
    _behavior("*.js", ForwardedValues={"QueryString": False}),
])
def test_cf_static_path_quiet(tmp_path: Path, behavior: dict) -> None:
    assert "CF-CF-013" not in _cf(tmp_path, {"D": _dist(behaviors=[behavior])})


def test_cf_default_behavior_is_not_a_static_path(tmp_path: Path) -> None:
    assert "CF-CF-013" not in _cf(tmp_path, {"D": _dist(default={"CachePolicyId": _DISABLED})})


def _tf_ordered(path: str, policy: str) -> str:
    return (f'ordered_cache_behavior {{\n path_pattern = {path}\n target_origin_id = "app"\n'
            f' cache_policy_id = {policy}\n}}')


def test_tf_static_path_without_caching_reports(tmp_path: Path) -> None:
    found = _tf(tmp_path, _tf_dist(_tf_custom(), _tf_ordered('"*.js"', f'"{_DISABLED}"')))
    assert "*.js" in found["CF-CF-013"][0].recommendation


@pytest.mark.parametrize(("path", "policy"), [
    ('"*.js"', f'"{_OPTIMIZED}"'),
    ('"*.js"', "var.x"),
    ('"*.js"', "data.aws_cloudfront_cache_policy.p.id"),
    ("var.x", f'"{_DISABLED}"'),
    ('"/api/*"', f'"{_DISABLED}"'),
])
def test_tf_static_path_quiet(tmp_path: Path, path: str, policy: str) -> None:
    assert "CF-CF-013" not in _tf(tmp_path, _tf_dist(_tf_custom(), _tf_ordered(path, policy)))


# --- what CF-CF-001..004 report does not change, and the rest of the project wiring ---


def _all_ids(tmp_path: Path, text: str) -> set[str]:
    path = tmp_path / "main.tf"
    path.write_text(_VAR + text, encoding="utf-8")
    warnings: list[str] = []
    found = run_resource_checks(resources_from_terraform(tmp_path, warnings), path)
    assert warnings == []
    return {f.id for f in found}


@pytest.mark.parametrize("name", ["origin", "ordered_cache_behavior"])
def test_tf_dynamic_list_block_still_leaves_the_whole_distribution_unjudged(tmp_path: Path, name: str) -> None:
    block = f'dynamic "{name}" {{\n for_each = var.x\n content {{\n origin_id = "y"\n }}\n}}'
    found = _all_ids(tmp_path, _tf_dist(_TF_S3, block))
    assert not {i for i in found if i.startswith("CF-CF-")}


def test_tf_older_checks_read_the_same_values(tmp_path: Path) -> None:
    text = _tf_dist(_TF_S3.replace('    origin_access_control_id = "o"\n', "")).replace(
        'viewer_protocol_policy = "https-only"', 'viewer_protocol_policy = "allow-all"')
    assert {"CF-CF-001", "CF-CF-003", "CF-CF-004"} <= _all_ids(tmp_path, text)


@pytest.mark.parametrize("check_id", IDS)
def test_wiring(check_id: str) -> None:
    assert check_id in RULE_TOPICS
    assert check_id in CF_THEMES
    assert check_id in SNIPPETS["cloudformation"]
    assert check_id in SNIPPETS["terraform"]


@pytest.mark.parametrize(("check_id", "rule_id"), [
    ("CF-CF-005", "OPS-007"), ("CF-CF-006", "COST-011"), ("CF-CF-007", "SUST-006"), ("CF-CF-013", "PERF-006"),
])
def test_covers_static(check_id: str, rule_id: str) -> None:
    assert rule_id in CF_COVERS_STATIC[check_id]
