"""Route 53, ACM and Global Accelerator: CF-R53-*, CF-ACM-* and CF-GA-001."""
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
    *(f"CF-R53-00{n}" for n in range(1, 4)),
    *(f"CF-ACM-00{n}" for n in range(1, 4)),
    "CF-GA-001",
)
_PARAM = {"Ref": "Param"}
_IF = {"Fn::If": ["C", "a", {"Ref": "AWS::NoValue"}]}
_ZONE = "aws_route53_zone"


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


def _zone(**props: Any) -> dict:
    return {"Type": "AWS::Route53::HostedZone", "Properties": {"Name": "example.com", **props}}


def _dnssec(zone: Any) -> dict:
    return {"Type": "AWS::Route53::DNSSEC", "Properties": {"HostedZoneId": zone}}


def _ksk(zone: Any) -> dict:
    return {"Type": "AWS::Route53::KeySigningKey", "Properties": {
        "HostedZoneId": zone, "KeyManagementServiceArn": "arn:k", "Name": "k", "Status": "ACTIVE"}}


def _record(**props: Any) -> dict:
    return {"Type": "AWS::Route53::RecordSet", "Properties": {"Name": "a.example.com", "Type": "A", **props}}


def _cert(**props: Any) -> dict:
    return {"Type": "AWS::CertificateManager::Certificate", "Properties": {
        "DomainName": "example.com", "ValidationMethod": "DNS", **props}}


def _group(*endpoints: Any, **props: Any) -> dict:
    return {"Type": "AWS::GlobalAccelerator::EndpointGroup", "Properties": {
        "ListenerArn": "arn:l", "EndpointGroupRegion": "us-east-1",
        "EndpointConfigurations": [{"EndpointId": e} for e in endpoints], **props}}


_LOG = {"CloudWatchLogsLogGroupArn": "arn:log"}
_LB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/a/1"


# --- Hosted zones: public or private ---


def test_public_zone_is_reported_for_logging_and_dnssec(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"Z": _zone()})
    assert found == {"CF-R53-001": {"Z"}, "CF-R53-002": {"Z"}}


@pytest.mark.parametrize("vpcs", [[{"VPCId": "vpc-1", "VPCRegion": "us-east-1"}], _PARAM, _IF])
def test_private_or_unknown_zone_is_not_judged(tmp_path: Path, vpcs: Any) -> None:
    assert _cf(tmp_path, {"Z": _zone(VPCs=vpcs)}) == {}


@pytest.mark.parametrize("vpc", [
    'vpc { vpc_id = "vpc-1" }',
    "vpc { vpc_id = var.vpc }",
    'dynamic "vpc" {\n for_each = var.vpcs\n content { vpc_id = vpc.value }\n}',
])
def test_private_or_unknown_zone_in_terraform_is_not_judged(tmp_path: Path, vpc: str) -> None:
    assert _tf(tmp_path, f'resource "{_ZONE}" "z" {{\n name = "example.com"\n {vpc}\n}}\n') == {}


# --- CF-R53-001 ---


@pytest.mark.parametrize(("value", "fires"), [(_LOG, False), (_PARAM, False), (_IF, False)])
def test_query_logging_config_is_read_from_the_zone(tmp_path: Path, value: Any, fires: bool) -> None:
    assert ("CF-R53-001" in _cf(tmp_path, {"Z": _zone(QueryLoggingConfig=value)})) is fires


@pytest.mark.parametrize(("zone_id", "fires"), [
    ("aws_route53_zone.z.zone_id", False),
    ("var.zone_id", False),
    ('"Z123"', False),
    ("data.aws_route53_zone.shared.zone_id", False),
])
def test_query_log_in_terraform(tmp_path: Path, zone_id: str, fires: bool) -> None:
    found = _tf(tmp_path, f'''
resource "{_ZONE}" "z" {{ name = "example.com" }}
resource "aws_route53_query_log" "l" {{
  zone_id                  = {zone_id}
  cloudwatch_log_group_arn = "arn:log"
}}''')
    assert ("CF-R53-001" in found) is fires


def test_terraform_public_zone_without_query_log_is_reported(tmp_path: Path) -> None:
    found = _tf(tmp_path, f'resource "{_ZONE}" "z" {{ name = "example.com" }}\n')
    assert found == {"CF-R53-001": {f"{_ZONE}.z"}, "CF-R53-002": {f"{_ZONE}.z"}}


def test_query_log_covers_only_its_zone_in_terraform(tmp_path: Path) -> None:
    found = _tf(tmp_path, f'''
resource "{_ZONE}" "z" {{ name = "example.com" }}
resource "{_ZONE}" "other" {{ name = "example.org" }}
resource "aws_route53_query_log" "l" {{
  zone_id                  = aws_route53_zone.z.zone_id
  cloudwatch_log_group_arn = "arn:log"
}}''')
    assert found["CF-R53-001"] == {f"{_ZONE}.other"}


def test_a_query_log_with_each_key_counts_for_all_zones(tmp_path: Path) -> None:
    found = _tf(tmp_path, f'''
resource "{_ZONE}" "z" {{
  for_each = var.names
  name     = each.key
}}
resource "aws_route53_query_log" "l" {{
  for_each                 = var.names
  zone_id                  = aws_route53_zone.z[each.key].zone_id
  cloudwatch_log_group_arn = "arn:log"
}}''')
    assert "CF-R53-001" not in found


def test_a_depends_on_does_not_tie_a_query_log_to_a_zone(tmp_path: Path) -> None:
    found = _tf(tmp_path, f'''
resource "{_ZONE}" "z" {{ name = "example.com" }}
resource "{_ZONE}" "other" {{ name = "example.org" }}
resource "aws_route53_query_log" "l" {{
  zone_id                  = var.zone_id
  cloudwatch_log_group_arn = "arn:log"
  depends_on               = [aws_route53_zone.other]
}}''')
    assert "CF-R53-001" not in found


# --- CF-R53-002 ---


@pytest.mark.parametrize("extra", [
    _dnssec({"Ref": "Z"}),
    _ksk({"Ref": "Z"}),
    _dnssec(_PARAM),
    _dnssec("Z123"),
    _dnssec({"Fn::ImportValue": "zone"}),
])
def test_dnssec_or_key_counts_for_the_zone(tmp_path: Path, extra: dict) -> None:
    assert "CF-R53-002" not in _cf(tmp_path, {"Z": _zone(), "D": extra})


def test_dnssec_covers_only_its_zone(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"Z": _zone(), "Other": _zone(), "D": _dnssec({"Ref": "Z"})})
    assert found["CF-R53-002"] == {"Other"}


def test_a_malformed_dnssec_counts_for_all_zones(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"Z": _zone(), "D": {
        "Type": "AWS::Route53::DNSSEC", "Properties": "not a map"}}}), encoding="utf-8")
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[])
    assert "CF-R53-002" not in _by_id(found)


@pytest.mark.parametrize(("extra", "fires"), [
    ('resource "aws_route53_hosted_zone_dnssec" "d" { hosted_zone_id = aws_route53_zone.z.id }', False),
    ('resource "aws_route53_hosted_zone_dnssec" "d" { hosted_zone_id = var.zone }', False),
    ('resource "aws_route53_key_signing_key" "k" {\n hosted_zone_id = aws_route53_zone.z.id\n'
     ' name = "k"\n key_management_service_arn = "arn:k"\n}', False),
    ('resource "aws_route53_hosted_zone_dnssec" "d" { hosted_zone_id = aws_route53_zone.other.id }', True),
])
def test_dnssec_in_terraform(tmp_path: Path, extra: str, fires: bool) -> None:
    found = _tf(tmp_path, f'''
resource "{_ZONE}" "z" {{ name = "example.com" }}
resource "{_ZONE}" "other" {{
  name = "example.org"
  vpc {{ vpc_id = "vpc-1" }}
}}
{extra}''')
    assert ("CF-R53-002" in found) is fires


# --- CF-R53-003 ---


@pytest.mark.parametrize(("props", "fires"), [
    ({"Failover": "PRIMARY", "SetIdentifier": "a"}, True),
    ({"Weight": 10, "SetIdentifier": "a"}, True),
    ({"Weight": 0, "SetIdentifier": "a"}, True),
    ({"Weight": "10", "SetIdentifier": "a"}, True),
    ({"Weight": 10, "SetIdentifier": "a", "AliasTarget": {"DNSName": "d", "HostedZoneId": "z"}}, True),
    ({"Weight": 10, "SetIdentifier": "a", "AliasTarget": {"EvaluateTargetHealth": False}}, True),
    ({"Failover": "PRIMARY", "SetIdentifier": "a", "HealthCheckId": "hc"}, False),
    ({"Failover": "PRIMARY", "SetIdentifier": "a", "HealthCheckId": _PARAM}, False),
    ({"Weight": 10, "SetIdentifier": "a", "HealthCheckId": _IF}, False),
    ({"Weight": 10, "SetIdentifier": "a", "AliasTarget": {"EvaluateTargetHealth": True}}, False),
    ({"Weight": 10, "SetIdentifier": "a", "AliasTarget": {"EvaluateTargetHealth": _PARAM}}, False),
    ({"Weight": 10, "SetIdentifier": "a", "AliasTarget": _PARAM}, False),
    ({"Failover": "SECONDARY", "SetIdentifier": "a"}, False),
    ({"Failover": _PARAM, "SetIdentifier": "a"}, False),
    ({"Weight": _PARAM, "SetIdentifier": "a"}, False),
    ({"Weight": _IF, "SetIdentifier": "a"}, False),
    ({"SetIdentifier": "a", "Region": "us-east-1"}, False),
    ({"SetIdentifier": "a", "MultiValueAnswer": True}, False),
    ({}, False),
])
def test_record_health_signal(tmp_path: Path, props: dict, fires: bool) -> None:
    assert ("CF-R53-003" in _cf(tmp_path, {"R": _record(**props)})) is fires


@pytest.mark.parametrize(("records", "fires"), [
    ([{"Name": "a", "Type": "A"}, {"Name": "b", "Type": "A", "Weight": 0, "SetIdentifier": "b"}], True),
    ([{"Name": "a", "Type": "A", "Failover": "PRIMARY", "SetIdentifier": "a"}], True),
    ([{"Name": "a", "Type": "A", "Weight": 1, "SetIdentifier": "a", "HealthCheckId": "hc"}], False),
    ([{"Name": "a", "Type": "A"}], False),
    ([_IF], False),
    (_PARAM, False),
])
def test_record_set_group_reads_each_record(tmp_path: Path, records: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"G": {"Type": "AWS::Route53::RecordSetGroup", "Properties": {"RecordSets": records}}})
    assert ("CF-R53-003" in found) is fires


def test_record_set_group_reports_once(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    records = [{"Name": n, "Type": "A", "Weight": 1, "SetIdentifier": n} for n in "ab"]
    path.write_text(json.dumps({"Resources": {"G": {
        "Type": "AWS::Route53::RecordSetGroup", "Properties": {"RecordSets": records}}}}), encoding="utf-8")
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[])
    assert [f.id for f in found if f.id == "CF-R53-003"] == ["CF-R53-003"]


_TF_DYNAMIC = 'dynamic "{0}" {{\n for_each = var.xs\n content {{\n {1}\n }}\n}}'
@pytest.mark.parametrize(("attrs", "fires"), [
    ('failover_routing_policy { type = "PRIMARY" }', True),
    ("weighted_routing_policy { weight = 10 }", True),
    ("weighted_routing_policy { weight = 0 }", True),
    ('weighted_routing_policy { weight = 10 }\n alias {\n name = "d"\n zone_id = "z"\n'
     ' evaluate_target_health = false\n}', True),
    ('failover_routing_policy { type = "SECONDARY" }', False),
    ("failover_routing_policy { type = var.kind }", False),
    ("weighted_routing_policy { weight = var.weight }", False),
    ('weighted_routing_policy { weight = 10 }\n health_check_id = "hc"', False),
    ("weighted_routing_policy { weight = 10 }\n health_check_id = var.hc", False),
    ("weighted_routing_policy { weight = 10 }\n health_check_id = aws_route53_health_check.h.id", False),
    ('weighted_routing_policy { weight = 10 }\n alias {\n name = "d"\n zone_id = "z"\n'
     ' evaluate_target_health = true\n}', False),
    ('weighted_routing_policy { weight = 10 }\n alias {\n name = "d"\n zone_id = "z"\n'
     ' evaluate_target_health = var.eval\n}', False),
    ("weighted_routing_policy { weight = 10 }\n"
     + _TF_DYNAMIC.format("alias", 'name = "d"\n zone_id = "z"\n evaluate_target_health = false'), False),
    (_TF_DYNAMIC.format("failover_routing_policy", 'type = "PRIMARY"'), False),
    (_TF_DYNAMIC.format("weighted_routing_policy", "weight = 1"), False),
    ('latency_routing_policy { region = "us-east-1" }', False),
    ("", False),
])
def test_record_health_signal_in_terraform(tmp_path: Path, attrs: str, fires: bool) -> None:
    found = _tf(tmp_path, f'''
resource "aws_route53_record" "r" {{
  zone_id        = "Z1"
  name           = "a"
  type           = "A"
  set_identifier = "a"
  {attrs}
}}''')
    assert ("CF-R53-003" in found) is fires


# --- ACM ---


@pytest.mark.parametrize(("props", "fires"), [
    ({"ValidationMethod": None}, True),
    ({"ValidationMethod": "EMAIL"}, True),
    ({"ValidationMethod": "email"}, True),
    ({"ValidationMethod": "EMAIL", "DomainValidationOptions": [{"DomainName": "a", "HostedZoneId": "z"}]}, True),
    ({"ValidationMethod": "DNS"}, False),
    ({"ValidationMethod": _PARAM}, False),
    ({"ValidationMethod": _IF}, False),
    ({"ValidationMethod": "EMAIL", "CertificateAuthorityArn": "arn:ca"}, False),
    ({"ValidationMethod": None, "CertificateAuthorityArn": "arn:ca"}, False),
    ({"ValidationMethod": None, "CertificateAuthorityArn": _PARAM}, False),
])
def test_validation_method(tmp_path: Path, props: dict, fires: bool) -> None:
    resource = _cert(**props)
    resource["Properties"] = {k: v for k, v in resource["Properties"].items() if v is not None}
    assert ("CF-ACM-001" in _cf(tmp_path, {"C": resource})) is fires


@pytest.mark.parametrize(("algorithm", "fires"), [
    ("RSA_1024", True),
    ("RSA_2048", False),
    ("RSA_4096", False),
    ("EC_prime256v1", False),
    ("EC_secp384r1", False),
    (_PARAM, False),
])
def test_key_algorithm(tmp_path: Path, algorithm: Any, fires: bool) -> None:
    assert ("CF-ACM-002" in _cf(tmp_path, {"C": _cert(KeyAlgorithm=algorithm)})) is fires


def test_a_private_ca_certificate_is_still_read_for_key_length(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"C": _cert(KeyAlgorithm="RSA_1024", CertificateAuthorityArn="arn:ca")})
    assert "CF-ACM-002" in found


@pytest.mark.parametrize(("value", "fires"), [
    ("DISABLED", True),
    ("ENABLED", False),
    (_PARAM, False),
])
def test_transparency_logging(tmp_path: Path, value: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"C": _cert(CertificateTransparencyLoggingPreference=value)})
    assert ("CF-ACM-003" in found) is fires


def test_transparency_logging_unset_is_not_reported(tmp_path: Path) -> None:
    assert "CF-ACM-003" not in _cf(tmp_path, {"C": _cert()})


def test_transparency_logging_on_a_private_ca_certificate_is_not_judged(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"C": _cert(CertificateTransparencyLoggingPreference="DISABLED",
                                      CertificateAuthorityArn="arn:ca")})
    assert "CF-ACM-003" not in found


_TF_CERT = 'resource "aws_acm_certificate" "c" {\n %s\n}\n'
@pytest.mark.parametrize(("attrs", "expected"), [
    ('domain_name = "a"\n validation_method = "EMAIL"', {"CF-ACM-001"}),
    ('domain_name = "a"\n validation_method = "DNS"', set()),
    ('domain_name = "a"\n validation_method = var.method', set()),
    ('domain_name = "a"', set()),  # the argument is required: not a CloudFormation default
    ('domain_name = "a"\n validation_method = "DNS"\n key_algorithm = "RSA_1024"', {"CF-ACM-002"}),
    ('domain_name = "a"\n validation_method = "DNS"\n key_algorithm = "RSA_2048"', set()),
    ('domain_name = "a"\n validation_method = "DNS"\n key_algorithm = "EC_prime256v1"', set()),
    ('domain_name = "a"\n validation_method = "DNS"\n key_algorithm = var.algorithm', set()),
    ('domain_name = "a"\n validation_method = "DNS"\n'
     ' options { certificate_transparency_logging_preference = "DISABLED" }', {"CF-ACM-003"}),
    ('domain_name = "a"\n validation_method = "DNS"\n'
     ' options { certificate_transparency_logging_preference = "ENABLED" }', set()),
    ('domain_name = "a"\n validation_method = "DNS"\n'
     ' options { certificate_transparency_logging_preference = var.ct }', set()),
    ('domain_name = "a"\n validation_method = "DNS"\n'
     ' dynamic "options" {\n for_each = var.xs\n content {\n'
     ' certificate_transparency_logging_preference = "DISABLED"\n }\n}', set()),
    ('domain_name = "a"\n certificate_authority_arn = "arn:ca"', set()),
    ('domain_name = "a"\n certificate_authority_arn = var.ca\n validation_method = "EMAIL"', set()),
    ('domain_name = "a"\n certificate_authority_arn = aws_acmpca_certificate_authority.ca.arn\n'
     ' key_algorithm = "RSA_1024"', {"CF-ACM-002"}),
    ('private_key = "secret"\n certificate_body = "body"', set()),
    ('private_key = var.key\n certificate_body = var.body\n key_algorithm = "RSA_1024"', set()),
    ('certificate_body = "body"\n validation_method = "EMAIL"', set()),
    ('private_key = "secret"\n options { certificate_transparency_logging_preference = "DISABLED" }', set()),
])
def test_certificate_in_terraform(tmp_path: Path, attrs: str, expected: set[str]) -> None:
    assert set(_tf(tmp_path, _TF_CERT % attrs)) == expected


def test_a_literal_private_key_is_not_kept(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(_TF_CERT % 'private_key = "s3cret"\n certificate_body = "body"', encoding="utf-8")
    resource = next(r for r in resources_from_terraform(tmp_path, []) if r.type == "acm_certificate")
    assert "s3cret" not in json.dumps(resource.properties)


# --- Global Accelerator ---


@pytest.mark.parametrize(("endpoints", "props", "fires"), [
    (["i-0123456789abcdef0"], {}, True),
    (["eipalloc-0123"], {}, True),
    ([_LB, "i-0123456789abcdef0"], {}, True),
    ([{"Ref": "Inst"}], {}, True),
    ([{"Fn::GetAtt": ["Ip", "AllocationId"]}], {}, True),
    (["i-1"], {"HealthCheckProtocol": "HTTP"}, False),
    (["i-1"], {"HealthCheckPath": "/health"}, False),
    (["i-1"], {"HealthCheckPort": 443}, False),
    (["i-1"], {"HealthCheckProtocol": _PARAM}, False),
    (["i-1"], {"HealthCheckPort": _IF}, False),
    ([_LB], {}, False),
    ([{"Ref": "Lb"}], {}, False),
    ([_PARAM], {}, False),
    ([], {}, False),
])
def test_endpoint_group_health_settings(tmp_path: Path, endpoints: list, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {
        "G": _group(*endpoints, **props),
        "Inst": {"Type": "AWS::EC2::Instance", "Properties": {"ImageId": "ami-1", "InstanceType": "t3.micro"}},
        "Ip": {"Type": "AWS::EC2::EIP", "Properties": {"Domain": "vpc"}},
        "Lb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {"Scheme": "internal"}},
    })
    assert ("CF-GA-001" in found) is fires


def test_endpoint_group_with_no_endpoints_is_not_judged(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"G": {"Type": "AWS::GlobalAccelerator::EndpointGroup", "Properties": {
        "ListenerArn": "arn:l", "EndpointGroupRegion": "us-east-1"}}})
    assert "CF-GA-001" not in found


def test_endpoint_configurations_from_a_parameter_is_not_judged(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"G": {"Type": "AWS::GlobalAccelerator::EndpointGroup", "Properties": {
        "ListenerArn": "arn:l", "EndpointGroupRegion": "us-east-1", "EndpointConfigurations": _PARAM}}})
    assert "CF-GA-001" not in found


@pytest.mark.parametrize(("attrs", "fires"), [
    ('endpoint_configuration { endpoint_id = "i-0123" }', True),
    ('endpoint_configuration { endpoint_id = "eipalloc-0123" }', True),
    ("endpoint_configuration { endpoint_id = aws_eip.ip.allocation_id }", True),
    ("endpoint_configuration { endpoint_id = aws_instance.i.id }", True),
    ('endpoint_configuration { endpoint_id = "i-0123" }\n health_check_protocol = "HTTP"', False),
    ('endpoint_configuration { endpoint_id = "i-0123" }\n health_check_path = "/health"', False),
    ('endpoint_configuration { endpoint_id = "i-0123" }\n health_check_port = 443', False),
    ('endpoint_configuration { endpoint_id = "i-0123" }\n health_check_protocol = var.protocol', False),
    ("endpoint_configuration { endpoint_id = aws_lb.lb.arn }", False),
    ("endpoint_configuration { endpoint_id = var.endpoint }", False),
    (_TF_DYNAMIC.format("endpoint_configuration", 'endpoint_id = "i-0123"'), False),
    ("", False),
])
def test_endpoint_group_in_terraform(tmp_path: Path, attrs: str, fires: bool) -> None:
    found = _tf(tmp_path, f'''
resource "aws_eip" "ip" {{ domain = "vpc" }}
resource "aws_instance" "i" {{
  ami           = "ami-1"
  instance_type = "t3.micro"
}}
resource "aws_lb" "lb" {{ internal = true }}
resource "aws_globalaccelerator_endpoint_group" "g" {{
  listener_arn = "arn:l"
  {attrs}
}}''')
    assert ("CF-GA-001" in found) is fires


# --- Fixes ---


@pytest.mark.parametrize("check", IDS)
def test_each_check_has_a_fix_in_both_languages(check: str) -> None:
    assert check in SNIPPETS["cloudformation"]
    assert check in SNIPPETS["terraform"]
