"""V2 reports a problem once when a template check covers the CDK rule for that control."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.rules.cf_template import (
    CF_COVERS_STATIC,
    CF_PARTLY_COVERS_STATIC,
    drop_static_covered_by_cf,
    run_cf_rules_from_paths,
)
from aws_arch_agent.rules.registry import ALL_RULES

RULE_BY_ID = {r.id: r for r in ALL_RULES}
RULES_DIR = Path(__file__).parents[1] / "src" / "aws_arch_agent" / "rules"


def _lambda(**extra: Any) -> dict:
    props = {"Role": "arn:aws:iam::111122223333:role/r", "Handler": "index.handler",
             "Runtime": "nodejs22.x", "Code": {"ZipFile": "x"}}
    return {"Type": "AWS::Lambda::Function", "Properties": {**props, **extra}}


def _db(**extra: Any) -> dict:
    return {"Type": "AWS::RDS::DBInstance",
            "Properties": {"Engine": "postgres", "DBInstanceClass": "db.t4g.micro", **extra}}


_TABLE = {"Type": "AWS::DynamoDB::Table", "Properties": {
    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
    "BillingMode": "PAY_PER_REQUEST",
}}
_LOG_GROUP = {"Type": "AWS::Logs::LogGroup", "Properties": {}}
_REST_STAGE = {"Type": "AWS::ApiGateway::Stage",
               "Properties": {"RestApiId": {"Ref": "Api"}, "StageName": "prod"}}
_HTTP_STAGE = {"Type": "AWS::ApiGatewayV2::Stage",
               "Properties": {"ApiId": {"Ref": "Api"}, "StageName": "$default"}}


def _open_sg(port: int) -> dict:
    return {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": "sg",
        "SecurityGroupIngress": [
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "CidrIp": "0.0.0.0/0"},
        ],
    }}


_PUBLIC_KEY = {"Type": "AWS::KMS::Key", "Properties": {"KeyPolicy": {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:*", "Resource": "*"}],
}}}

def _ref(name: str) -> dict:
    return {"Ref": name}


def _az(i: int) -> dict:
    return {"Fn::Select": [i, {"Fn::GetAZs": ""}]}


# One NAT gateway that private subnets in two AZs route through, as CDK natGateways: 1.
_ONE_NAT_TWO_AZS: dict = {
    "Public": {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": "vpc-1", "AvailabilityZone": _az(0)}},
    "Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": _ref("Public")}},
    **{f"Private{i}": {"Type": "AWS::EC2::Subnet",
                       "Properties": {"VpcId": "vpc-1", "AvailabilityZone": _az(i)}} for i in (0, 1)},
    **{f"Table{i}": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": "vpc-1"}} for i in (0, 1)},
    **{f"Assoc{i}": {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {
        "RouteTableId": _ref(f"Table{i}"), "SubnetId": _ref(f"Private{i}")}} for i in (0, 1)},
    **{f"Route{i}": {"Type": "AWS::EC2::Route", "Properties": {
        "RouteTableId": _ref(f"Table{i}"), "DestinationCidrBlock": "0.0.0.0/0",
        "NatGatewayId": _ref("Nat")}} for i in (0, 1)},
}

_DB_ENGINE = "engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_16 })"
_FN = (
    'new lambda.Function(this, "Fn", { runtime: lambda.Runtime.NODEJS_22_X, '
    'handler: "index.handler", code: lambda.Code.fromInline("x") });'
)

# (template check, CDK rule, synthesised resource, CDK source that fires the CDK rule)
PAIRS: list[tuple[str, str, dict, str]] = [
    ("CF-SQS-001", "SEC-013", {"Type": "AWS::SQS::Queue", "Properties": {}},
     "new sqs.Queue(this, 'Q');"),
    ("CF-SQS-002", "REL-008", {"Type": "AWS::SQS::Queue", "Properties": {}},
     "new sqs.Queue(this, 'Q');"),
    ("CF-SG-001", "SEC-003", _open_sg(22),
     "sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));"),
    ("CF-SG-001", "SEC-004", _open_sg(5432),
     "sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(5432));"),
    ("CF-DDB-001", "REL-004", _TABLE,
     "new dynamodb.Table(this, 'T', { partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING } });"),
    ("CF-DDB-002", "SEC-008", _TABLE,
     "new dynamodb.Table(this, 'T', { partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING } });"),
    ("CF-CW-001", "COST-001", _LOG_GROUP,
     "new logs.LogGroup(this, 'LG', { retention: logs.RetentionDays.INFINITE });"),
    ("CF-CW-002", "SEC-062", _LOG_GROUP, "new logs.LogGroup(this, 'LG');"),
    ("CF-APIGW-001", "OPS-005", _REST_STAGE, "new apigateway.RestApi(this, 'Api');"),
    ("CF-APIGW-V2-001", "OPS-005", _HTTP_STAGE, "new HttpApi(this, 'Api');"),
    ("CF-APIGW-002", "OPS-003", _REST_STAGE, "new apigateway.RestApi(this, 'Api');"),
    ("CF-APIGW-V2-002", "OPS-003", _HTTP_STAGE, "new apigateway.HttpApi(this, 'Api');"),
    ("CF-LAM-002", "OPS-003", _lambda(DeadLetterConfig={"TargetArn": "arn:aws:sqs:::dlq"}), _FN),
    ("CF-LAM-001", "REL-003", _lambda(TracingConfig={"Mode": "Active"}), _FN),
    ("CF-RDS-002", "REL-002", _db(BackupRetentionPeriod=0),
     f'new rds.DatabaseInstance(this, "DB", {{ {_DB_ENGINE} }});'),
    ("CF-RDS-004", "SEC-064", _db(PubliclyAccessible=True),
     f"new rds.DatabaseInstance(this, 'DB', {{ publiclyAccessible: true, {_DB_ENGINE} }});"),
    ("CF-RDS-005", "REL-030", _db(),
     f"new rds.DatabaseInstance(this, 'DB', {{ {_DB_ENGINE}, vpc }});"),
    ("CF-S3-003", "REL-031", {"Type": "AWS::S3::Bucket", "Properties": {}},
     'new s3.Bucket(this, "B");'),
    ("CF-KMS-001", "SEC-007", _PUBLIC_KEY,
     "const key = new kms.Key(this, 'Key');\n"
     "key.addToResourcePolicy(new iam.PolicyStatement({ Principal: '*', Action: 'kms:*' }));"),
    ("CF-ALB-001", "OPS-006",
     {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {"Type": "network"}},
     "new elbv2.NetworkLoadBalancer(this, 'Nlb', { vpc });"),
    ("CF-SG-002", "SEC-003", {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": "sg",
        "SecurityGroupIngress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}],
        "SecurityGroupEgress": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                 "CidrIp": "10.0.0.0/16"}],
    }}, "sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));"),
    ("CF-SG-003", "SEC-054", {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": "sg",
        "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}],
    }}, "new ec2.SecurityGroup(this, 'Sg', { vpc, allowAllOutbound: true });"),
    ("CF-NAT-001", "REL-012", _ONE_NAT_TWO_AZS, "new ec2.Vpc(this, 'Vpc', { natGateways: 1 });"),
    ("CF-TGW-002", "OPS-016", {"Type": "AWS::EC2::TransitGateway", "Properties": {}},
     "new ec2.CfnTransitGateway(this, 'Tgw', {});"),
    ("CF-ALB-002", "SEC-011", {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
        "Protocol": "HTTP", "Port": 80,
        "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn"}]}},
     "new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });"),
    ("CF-ALB-003", "SEC-012", {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
        "Protocol": "HTTPS", "Port": 443,
        "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn"}]}},
     "new elbv2.ApplicationLoadBalancer(this, 'Alb', { vpc });"),
    ("CF-ALB-007", "REL-007", {"Type": "AWS::ElasticLoadBalancingV2::TargetGroup", "Properties": {
        "Protocol": "HTTP", "Port": 80}},
     "new elbv2.ApplicationTargetGroup(this, 'Tg', { vpc, port: 80 });"),
    ("CF-RDS-006", "SEC-021", _db(Engine="mysql", DBParameterGroupName="default.mysql8.0"),
     f'new rds.DatabaseInstance(this, "DB", {{ {_DB_ENGINE} }});'),
    ("CF-RDS-007", "OPS-009", _db(Engine="mysql"),
     f'new rds.DatabaseInstance(this, "DB", {{ {_DB_ENGINE} }});'),
    ("CF-RDS-014", "COST-010", _db(Engine="postgres", DBInstanceClass="db.m5.large"),
     f'new rds.DatabaseInstance(this, "DB", {{ {_DB_ENGINE} }});'),
    ("CF-LAM-004", "SEC-057", {"Type": "AWS::Lambda::Url", "Properties": {
        "TargetFunctionArn": "arn", "AuthType": "NONE"}}, "fn.addFunctionUrl();"),
    ("CF-LAM-005", "SEC-017", _lambda(Environment={"Variables": {"DB_PASSWORD": "literal-value"}}),
     "new lambda.Function(this, 'Fn', { environment: { PASSWORD: 'secret123456789' } });"),
    ("CF-LAM-005", "BP-002", _lambda(Environment={"Variables": {"DB_PASSWORD": "literal-value"}}),
     "new lambda.Function(this, 'Fn', { environment: { PASSWORD: 'secret123456789' } });"),
    ("CF-LAM-006", "REL-027", _lambda(), _FN),
    ("CF-LAM-007", "REL-009", {
        "Fn": _lambda(),
        "Map": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
            "FunctionName": {"Ref": "Fn"}, "EventSourceArn": "arn:aws:sqs:eu-west-1:1:q"}},
    }, _FN),
    ("CF-COST-002", "COST-006",
     {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": {"Ref": "Public"}}},
     "new ec2.Vpc(this, 'Vpc', { natGateways: 1 });"),
]


def _scan(tmp_path: Path, rule_id: str, resource: dict, source: str) -> list:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "stack.ts").write_text(source + "\n", encoding="utf-8")
    template = tmp_path / "cdk.out" / "Stack.template.json"
    template.parent.mkdir()
    resources = resource if "Type" not in resource else {"Res": resource}  # or several
    template.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    static = RULE_BY_ID[rule_id].run(tmp_path, "typescript")
    cf = run_cf_rules_from_paths([template], repo_path=tmp_path)
    return static + cf


@pytest.mark.parametrize(
    ("cf_id", "rule_id", "resource", "source"),
    PAIRS,
    ids=[f"{cf_id}-{rule_id}" for cf_id, rule_id, _r, _s in PAIRS],
)
def test_v2_reports_only_the_template_finding(
    tmp_path: Path, cf_id: str, rule_id: str, resource: dict, source: str
) -> None:
    findings = _scan(tmp_path, rule_id, resource, source)
    ids = {f.id for f in findings}
    assert {cf_id, rule_id} <= ids, f"fixture does not fire both checks: {sorted(ids)}"
    kept = {f.id for f in drop_static_covered_by_cf(findings)}
    assert cf_id in kept
    assert rule_id not in kept


def test_every_pair_is_in_the_map() -> None:
    for cf_id, rule_id, _resource, _source in PAIRS:
        assert rule_id in CF_COVERS_STATIC[cf_id]


def test_partial_pairs_keep_the_cdk_finding() -> None:
    from aws_arch_agent.models import Finding

    for cf_id, (rule_ids, _why) in CF_PARTLY_COVERS_STATIC.items():
        assert cf_id not in CF_COVERS_STATIC
        findings = [Finding(id=cf_id, title="t", recommendation="r")]
        findings += [Finding(id=r, title="t", recommendation="r") for r in rule_ids]
        kept = {f.id for f in drop_static_covered_by_cf(findings)}
        assert set(rule_ids) <= kept


# Template checks known to name the same control as a CDK rule. Each must be tied in
# CF_COVERS_STATIC or explained in CF_PARTLY_COVERS_STATIC.
KNOWN_SAME_CONTROL: list[tuple[str, str]] = [
    *[(cf_id, rule_id) for cf_id, rule_id, _r, _s in PAIRS],
    ("CF-RDS-003", "REL-001"),
    ("CF-PERF-001", "PERF-001"),
    ("CF-CT-001", "OPS-001"),
    ("CF-CT-002", "OPS-001"),
    ("CF-CT-003", "OPS-001"),
    ("CF-TAG-001", "BP-001"),
    ("CF-NACL-001", "SEC-055"),
]

# Title words that do not name a control.
_FILLER = frozenset({
    "a", "an", "the", "is", "be", "may", "not", "no", "has", "miss", "missing", "enabled",
    "set", "configured", "explicitly", "with", "or", "to", "of", "on", "for", "template",
    "level",
})


def _title_words(title: str) -> frozenset[str]:
    return frozenset(w for w in re.findall(r"[a-z0-9]+", title.lower()) if w not in _FILLER)


def _template_check_titles() -> dict[str, str]:
    """First literal title per template check id, read from the rule sources."""
    pattern = re.compile(r'id="(CF-[A-Z0-9-]+)",\s*title=\(?\s*"([^"]+)"')
    titles: dict[str, str] = {}
    for path in sorted(RULES_DIR.glob("*.py")):
        for cf_id, title in pattern.findall(path.read_text(encoding="utf-8")):
            titles.setdefault(cf_id, title)
    return titles


def _accounted_for(cf_id: str, rule_id: str) -> bool:
    if rule_id in CF_COVERS_STATIC.get(cf_id, ()):
        return True
    return rule_id in CF_PARTLY_COVERS_STATIC.get(cf_id, ((), ""))[0]


def test_known_same_control_pairs_are_accounted_for() -> None:
    missing = [p for p in KNOWN_SAME_CONTROL if not _accounted_for(*p)]
    assert not missing, f"tie in CF_COVERS_STATIC or explain in CF_PARTLY_COVERS_STATIC: {missing}"


def test_template_check_with_a_cdk_rule_title_is_accounted_for() -> None:
    titles = _template_check_titles()
    assert len(titles) > 40  # the title pattern still reads the sources
    missing = [
        (cf_id, rule.id, title, rule.title)
        for cf_id, title in titles.items()
        for rule in ALL_RULES
        if _title_words(title) == _title_words(rule.title) and not _accounted_for(cf_id, rule.id)
    ]
    assert not missing, f"same control, not in either map: {missing}"
