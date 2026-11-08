"""EMR and DMS: CF-EMR-001..003, CF-DMS-001..004."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.report.doc_topics import RULE_TOPICS
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = ("CF-EMR-001", "CF-EMR-002", "CF-EMR-003", "CF-DMS-001", "CF-DMS-002", "CF-DMS-003", "CF-DMS-004")
_PARAM = {"Ref": "Param"}
_IF = {"Fn::If": ["C", "a", "b"]}
_VAR = 'variable "x" {}\n'
_SECRET = "arn:aws:secretsmanager:eu-west-1:111111111111:secret:db"


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict, name: str = "t.json") -> dict[str, set[str]]:
    path = tmp_path / name
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _by_id(found)


def _tf(tmp_path: Path, text: str, name: str = "main.tf") -> dict[str, set[str]]:
    (tmp_path / name).write_text(_VAR + text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / name))


def _subnet(public: Any = True) -> dict:
    return {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/24",
                                                       "MapPublicIpOnLaunch": public}}


def _cluster(subnet: Any = None, security: Any = "sc") -> dict:
    props: dict = {"Name": "c", "JobFlowRole": "r", "ServiceRole": "s", "ReleaseLabel": "emr-7.0.0",
                   "Instances": {} if subnet is None else {"Ec2SubnetId": subnet}}
    if security is not None:
        props["SecurityConfiguration"] = security
    return {"Type": "AWS::EMR::Cluster", "Properties": props}


def _security(document: Any) -> dict:
    return {"Type": "AWS::EMR::SecurityConfiguration", "Properties": {"SecurityConfiguration": document}}


def _encryption(at_rest: Any = True, in_transit: Any = True) -> dict:
    return {"EncryptionConfiguration": {"EnableAtRestEncryption": at_rest, "EnableInTransitEncryption": in_transit}}


def _instance(**props: Any) -> dict:
    return {"Type": "AWS::DMS::ReplicationInstance", "Properties": {
        "ReplicationInstanceClass": "dms.t3.micro", "PubliclyAccessible": False, **props}}


def _endpoint(**props: Any) -> dict:
    return {"Type": "AWS::DMS::Endpoint", "Properties": {"EndpointType": "source", **props}}


def _tf_instance(extra: str = "") -> str:
    return f'''resource "aws_dms_replication_instance" "r" {{
  replication_instance_id    = "r"
  replication_instance_class = "dms.t3.micro"
  {extra}
}}
'''


@pytest.mark.parametrize(("subnet", "public", "fires"), [
    ({"Ref": "Net"}, True, True),
    ({"Fn::GetAtt": ["Net", "SubnetId"]}, True, True),
    ({"Ref": "Net"}, "true", True),
    ({"Ref": "Net"}, False, False),
    ({"Ref": "Net"}, _PARAM, False),
    ({"Ref": "Other"}, True, False),
    (_PARAM, True, False),
    ({"Fn::If": ["C", {"Ref": "Net"}, "subnet-1"]}, True, False),
    ("subnet-123", True, False),
    ("Net", True, False),
])
def test_emr_public_subnet_cf(tmp_path: Path, subnet: Any, public: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"C": _cluster(subnet), "Net": _subnet(public)})
    assert found.get("CF-EMR-001", set()) == ({"C"} if fires else set())


def test_emr_subnet_outside_the_template_and_parameter_are_not_judged(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"C": _cluster(_PARAM)}).get("CF-EMR-001") is None
    assert _cf(tmp_path, {"C": _cluster("subnet-123")}).get("CF-EMR-001") is None


def test_emr_cdk_public_subnet_is_still_reported(tmp_path: Path) -> None:
    subnet = _subnet()
    subnet["Properties"]["Tags"] = [{"Key": "aws-cdk:subnet-type", "Value": "Public"}]
    assert _cf(tmp_path, {"C": _cluster({"Ref": "Net"}), "Net": subnet})["CF-EMR-001"] == {"C"}


@pytest.mark.parametrize(("subnet_id", "map_public", "fires"), [
    ("aws_subnet.net.id", "true", True),
    ('"${aws_subnet.net.id}"', "true", True),
    ("aws_subnet.net[0].id", "true", True),
    ("aws_subnet.net.id", "false", False),
    ("aws_subnet.net.id", "var.x", False),
    ("aws_subnet.other.id", "true", False),
    ("var.x", "true", False),
    ("var.x ? aws_subnet.net.id : aws_subnet.other.id", "true", False),
    ('"subnet-1"', "true", False),
    ("data.aws_subnet.net.id", "true", False),
])
def test_emr_public_subnet_tf(tmp_path: Path, subnet_id: str, map_public: str, fires: bool) -> None:
    found = _tf(tmp_path, f'''
resource "aws_subnet" "net" {{
  vpc_id                  = "vpc-1"
  cidr_block              = "10.0.0.0/24"
  map_public_ip_on_launch = {map_public}
}}
resource "aws_emr_cluster" "c" {{
  name                   = "c"
  security_configuration = "sc"
  ec2_attributes {{
    subnet_id = {subnet_id}
  }}
}}
''')
    assert found.get("CF-EMR-001", set()) == ({"aws_emr_cluster.c"} if fires else set())


def test_emr_dynamic_ec2_attributes_are_not_judged(tmp_path: Path) -> None:
    found = _tf(tmp_path, '''
resource "aws_subnet" "net" {
  map_public_ip_on_launch = true
}
resource "aws_emr_cluster" "c" {
  security_configuration = "sc"
  dynamic "ec2_attributes" {
    for_each = var.x
    content {
      subnet_id = aws_subnet.net.id
    }
  }
}
''')
    assert "CF-EMR-001" not in found


@pytest.mark.parametrize(("security", "fires"), [
    (None, True),
    ("", True),
    ("sc", False),
    (_PARAM, False),
    (_IF, False),
])
def test_emr_cluster_security_configuration_cf(tmp_path: Path, security: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"C": _cluster(security=security)})
    assert found.get("CF-EMR-002", set()) == ({"C"} if fires else set())
    assert "CF-EMR-003" not in found


def test_emr_cluster_with_no_configuration_says_in_transit_is_off(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"C": _cluster(security=None)}}), encoding="utf-8")
    found = [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[]) if f.id == "CF-EMR-002"]
    assert len(found) == 1
    assert "in transit is off too" in found[0].recommendation


@pytest.mark.parametrize(("arguments", "fires"), [
    ("", True),
    ('security_configuration = "sc"', False),
    ("security_configuration = aws_emr_security_configuration.s.name", False),
    ("security_configuration = var.x", False),
])
def test_emr_cluster_security_configuration_tf(tmp_path: Path, arguments: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_emr_cluster" "c" {{\n  {arguments}\n}}\n')
    assert found.get("CF-EMR-002", set()) == ({"aws_emr_cluster.c"} if fires else set())


@pytest.mark.parametrize(("document", "at_rest", "in_transit"), [
    (_encryption(), False, False),
    (_encryption(False, True), True, False),
    (_encryption(True, False), False, True),
    (_encryption(False, False), True, True),
    (_encryption("false", "true"), True, False),
    ({"EncryptionConfiguration": {"EnableInTransitEncryption": True}}, True, False),
    ({"EncryptionConfiguration": {}}, True, True),
    ({"AuthenticationConfiguration": {}}, True, True),
    ({}, True, True),
    (json.dumps(_encryption(False, True)), True, False),
    (json.dumps(_encryption()), False, False),
    (_encryption(_PARAM, False), False, True),
    (_encryption(False, _IF), True, False),
    (_encryption(_PARAM, _PARAM), False, False),
    ({"EncryptionConfiguration": _PARAM}, False, False),
    (_PARAM, False, False),
    ({"Fn::Sub": "{}"}, False, False),
    ("not json", False, False),
])
def test_emr_security_configuration_cf(tmp_path: Path, document: Any, at_rest: bool, in_transit: bool) -> None:
    found = _cf(tmp_path, {"S": _security(document)})
    assert found.get("CF-EMR-002", set()) == ({"S"} if at_rest else set())
    assert found.get("CF-EMR-003", set()) == ({"S"} if in_transit else set())


@pytest.mark.parametrize(("configuration", "at_rest", "in_transit"), [
    ('''jsonencode({
    EncryptionConfiguration = {
      EnableAtRestEncryption    = false
      EnableInTransitEncryption = true
    }
  })''', True, False),
    ('''jsonencode({
    EncryptionConfiguration = {
      EnableAtRestEncryption    = true
      EnableInTransitEncryption = false
    }
  })''', False, True),
    ('''jsonencode({
    EncryptionConfiguration = {
      EnableAtRestEncryption    = true
      EnableInTransitEncryption = true
    }
  })''', False, False),
    ('''jsonencode({
    EncryptionConfiguration = {
      EnableAtRestEncryption    = var.x
      EnableInTransitEncryption = false
    }
  })''', False, True),
    ("jsonencode({ EncryptionConfiguration = var.x })", False, False),
    ("jsonencode(var.x)", False, False),
    ("var.x", False, False),
    ('file("config.json")', False, False),
    ('''<<EOF
{"EncryptionConfiguration": {"EnableAtRestEncryption": false, "EnableInTransitEncryption": true}}
EOF''', True, False),
    ('''<<EOF
{"EncryptionConfiguration": {"EnableAtRestEncryption": ${var.x}, "EnableInTransitEncryption": ${var.x}}}
EOF''', False, False),
    ('''"{\\"EncryptionConfiguration\\": {\\"EnableAtRestEncryption\\": true, \\"EnableInTransitEncryption\\": false}}"''',
     False, True),
])
def test_emr_security_configuration_tf(tmp_path: Path, configuration: str, at_rest: bool, in_transit: bool) -> None:
    found = _tf(tmp_path, f'''resource "aws_emr_security_configuration" "s" {{
  configuration = {configuration}
}}
''')
    name = {"aws_emr_security_configuration.s"}
    assert found.get("CF-EMR-002", set()) == (name if at_rest else set())
    assert found.get("CF-EMR-003", set()) == (name if in_transit else set())


def test_emr_each_problem_is_reported_once_on_its_own_resource(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"C": _cluster(security={"Ref": "S"}), "S": _security(_encryption(False, False))})
    assert found == {"CF-EMR-002": {"S"}, "CF-EMR-003": {"S"}}


@pytest.mark.parametrize(("props", "fires"), [
    ({"PubliclyAccessible": True}, True),
    ({"PubliclyAccessible": "true"}, True),
    ({"PubliclyAccessible": False}, False),
    ({"PubliclyAccessible": _PARAM}, False),
    ({"PubliclyAccessible": _IF}, False),
])
def test_dms_public_cf(tmp_path: Path, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"R": _instance(**props)})
    assert found.get("CF-DMS-001", set()) == ({"R"} if fires else set())


def test_dms_public_unset_in_cf_defaults_to_true(tmp_path: Path) -> None:
    instance = _instance()
    del instance["Properties"]["PubliclyAccessible"]
    assert _cf(tmp_path, {"R": instance})["CF-DMS-001"] == {"R"}


@pytest.mark.parametrize(("arguments", "fires"), [
    ("publicly_accessible = true", True),
    ("publicly_accessible = false", False),
    ("publicly_accessible = var.x", False),
    ("", False),
])
def test_dms_public_tf(tmp_path: Path, arguments: str, fires: bool) -> None:
    found = _tf(tmp_path, _tf_instance(arguments))
    assert found.get("CF-DMS-001", set()) == ({"aws_dms_replication_instance.r"} if fires else set())


@pytest.mark.parametrize(("props", "fires"), [
    ({"AutoMinorVersionUpgrade": False}, True),
    ({"AutoMinorVersionUpgrade": "false"}, True),
    ({"AutoMinorVersionUpgrade": True}, False),
    ({"AutoMinorVersionUpgrade": _PARAM}, False),
    ({"AutoMinorVersionUpgrade": _IF}, False),
    ({}, False),
])
def test_dms_minor_upgrade_cf(tmp_path: Path, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"R": _instance(**props)})
    assert found.get("CF-DMS-002", set()) == ({"R"} if fires else set())


@pytest.mark.parametrize(("arguments", "fires"), [
    ("auto_minor_version_upgrade = false", True),
    ("", True),
    ("auto_minor_version_upgrade = true", False),
    ("auto_minor_version_upgrade = var.x", False),
])
def test_dms_minor_upgrade_tf(tmp_path: Path, arguments: str, fires: bool) -> None:
    found = _tf(tmp_path, _tf_instance(arguments))
    assert found.get("CF-DMS-002", set()) == ({"aws_dms_replication_instance.r"} if fires else set())


@pytest.mark.parametrize(("props", "fires"), [
    ({"EngineName": "mysql"}, True),
    ({"EngineName": "postgres", "SslMode": "none"}, True),
    ({"EngineName": "ORACLE", "SslMode": "NONE"}, True),
    ({"EngineName": "aurora-postgresql"}, True),
    ({"EngineName": "docdb", "SslMode": "none", "SecretsManagerSecretId": _SECRET}, True),
    ({"EngineName": "mysql", "MySqlSettings": {"ServerName": "db"}}, True),
    ({"EngineName": "mysql", "SslMode": "require"}, False),
    ({"EngineName": "mysql", "SslMode": "verify-full"}, False),
    ({"EngineName": "mysql", "SslMode": _PARAM}, False),
    ({"EngineName": "mysql", "SslMode": _IF}, False),
    ({"EngineName": _PARAM, "SslMode": "none"}, False),
    ({"EngineName": "s3", "SslMode": "none"}, False),
    ({"EngineName": "dynamodb"}, False),
    ({"EngineName": "kinesis"}, False),
    ({"EngineName": "kafka"}, False),
    ({"EngineName": "redshift", "SslMode": "none"}, False),
    ({"EngineName": "mongodb"}, False),
    ({"EngineName": "sybase"}, False),
    ({"EngineName": "mysql", "CertificateArn": "arn:aws:dms:::cert:c"}, False),
    ({"EngineName": "mysql", "ExtraConnectionAttributes": "a=b"}, False),
    ({"EngineName": "mysql", "MySqlSettings": {"SecretsManagerSecretId": _SECRET}}, False),
    ({"EngineName": "mysql", "MySqlSettings": _PARAM}, False),
])
def test_dms_ssl_cf(tmp_path: Path, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"E": _endpoint(**props)})
    assert found.get("CF-DMS-003", set()) == ({"E"} if fires else set())


@pytest.mark.parametrize(("arguments", "fires"), [
    ('engine_name = "mysql"', True),
    ('engine_name = "mysql"\n  ssl_mode = "none"', True),
    (f'engine_name = "mysql"\n  ssl_mode = "none"\n  secrets_manager_arn = "{_SECRET}"', True),
    ('engine_name = "mysql"\n  ssl_mode = "require"', False),
    ('engine_name = "mysql"\n  ssl_mode = var.x', False),
    ('engine_name = var.x\n  ssl_mode = "none"', False),
    ('engine_name = "s3"\n  ssl_mode = "none"', False),
    ('engine_name = "dynamodb"', False),
    ('engine_name = "kinesis"', False),
    (f'engine_name = "mysql"\n  secrets_manager_arn = "{_SECRET}"', False),
    ('engine_name = "mysql"\n  secrets_manager_arn = var.x', False),
    ('engine_name = "mysql"\n  certificate_arn = var.x', False),
    ('engine_name = "mysql"\n  extra_connection_attributes = "a=b"', False),
    ('engine_name = "mysql"\n  extra_connection_attributes = var.x', False),
])
def test_dms_ssl_tf(tmp_path: Path, arguments: str, fires: bool) -> None:
    found = _tf(tmp_path, f'resource "aws_dms_endpoint" "e" {{\n  {arguments}\n}}\n')
    assert found.get("CF-DMS-003", set()) == ({"aws_dms_endpoint.e"} if fires else set())


@pytest.mark.parametrize(("name", "props", "fires"), [
    ("prod-stack.json", {}, True),
    ("prod-stack.json", {"MultiAZ": False}, True),
    ("prod-stack.json", {"MultiAZ": "false"}, True),
    ("prod-stack.json", {"MultiAZ": True}, False),
    ("prod-stack.json", {"MultiAZ": _PARAM}, False),
    ("prod-stack.json", {"MultiAZ": _IF}, False),
    ("t.json", {"MultiAZ": False}, False),
    ("dev-stack.json", {"MultiAZ": False}, False),
    ("staging-stack.json", {}, False),
])
def test_dms_multi_az_cf(tmp_path: Path, name: str, props: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"R": _instance(**props)}, name)
    assert found.get("CF-DMS-004", set()) == ({"R"} if fires else set())


@pytest.mark.parametrize(("arguments", "fires"), [
    ("", True),
    ("multi_az = false", True),
    ("multi_az = true", False),
    ("multi_az = var.x", False),
])
def test_dms_multi_az_tf(tmp_path: Path, arguments: str, fires: bool) -> None:
    found = _tf(tmp_path, _tf_instance(arguments), "prod.tf")
    assert found.get("CF-DMS-004", set()) == ({"aws_dms_replication_instance.r"} if fires else set())


def test_dms_multi_az_tf_outside_prod_is_not_reported(tmp_path: Path) -> None:
    assert "CF-DMS-004" not in _tf(tmp_path, _tf_instance("multi_az = false"))


def test_literal_secret_in_terraform_endpoint_is_not_copied(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('''resource "aws_dms_endpoint" "e" {
  engine_name                 = "mysql"
  password                    = "hunter2-secret"
  extra_connection_attributes = "password=hunter2-secret"
}
''', encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    endpoint = next(r for r in resources if r.type == "dms_endpoint")
    assert "hunter2" not in json.dumps(endpoint.properties, default=str)


@pytest.mark.parametrize("check_id", IDS)
def test_every_check_has_snippets_and_a_topic(check_id: str) -> None:
    assert check_id in SNIPPETS["cloudformation"]
    assert check_id in SNIPPETS["terraform"]
    assert check_id in RULE_TOPICS
