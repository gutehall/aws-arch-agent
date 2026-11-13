"""REL 5: stateless compute (REPO-042), an emergency lever (REPO-043), and a fallback when a
dependency fails (REPO-044)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    EmergencyLeverMissing,
    FallbackMissing,
    LocalStateOnCompute,
    emergency_levers,
    fallbacks,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / _PATHS[source], body)


LAMBDA = {
    "cdk": "const fn = new lambda.Function(this, 'Fn', props);\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}
INSTANCE = {
    "cdk": "const host = new ec2.Instance(this, 'Host', props);\n",
    "cloudformation": {"Host": {"Type": "AWS::EC2::Instance", "Properties": {}}},
    "terraform": 'resource "aws_instance" "host" {\n  ami = "ami-1"\n}\n',
}
TABLE = {
    "cdk": "const table = new dynamodb.Table(this, 'Orders', props);\n",
    "cloudformation": {"Orders": {"Type": "AWS::DynamoDB::Table", "Properties": {}}},
    "terraform": 'resource "aws_dynamodb_table" "orders" {\n  name = "orders"\n}\n',
}

# --- REPO-042: state on local disk ---

ATTACHED_VOLUME = {
    "cdk": "const data = new ec2.Volume(this, 'Data', props);\n"
           "data.grantAttachVolume(host.role, [host]);\n",
    "cloudformation": {
        "Data": {"Type": "AWS::EC2::Volume", "Properties": {"Size": 100}},
        "Attach": {"Type": "AWS::EC2::VolumeAttachment",
                   "Properties": {"Device": "/dev/sdf", "InstanceId": {"Ref": "Host"},
                                  "VolumeId": {"Ref": "Data"}}},
    },
    "terraform": 'resource "aws_ebs_volume" "data" {\n  size = 100\n}\n'
                 'resource "aws_volume_attachment" "data" {\n  device_name = "/dev/sdf"\n}\n',
}
HOST_VOLUME = {
    "cdk": "const svc = new ecs.FargateService(this, 'Svc', props);\n"
           "task.addVolume({ name: 'data', host: { sourcePath: '/data' } });\n",
    "cloudformation": {
        "Svc": {"Type": "AWS::ECS::Service", "Properties": {}},
        "Task": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
            "Volumes": [{"Name": "data", "Host": {"SourcePath": "/data"}}]}},
    },
    "terraform": 'resource "aws_ecs_service" "svc" {\n  name = "svc"\n}\n'
                 'resource "aws_ecs_task_definition" "task" {\n  volume {\n    name = "data"\n'
                 '    host_path = "/data"\n  }\n}\n',
}
STATELESS = {
    "cdk": "const host = new ec2.Instance(this, 'Host', { blockDevices: [{ deviceName: "
           "'/dev/xvda', volume: ec2.BlockDeviceVolume.ebs(30) }] });\n"
           "const fs = new efs.FileSystem(this, 'Shared', { vpc });\n",
    "cloudformation": {"Host": {"Type": "AWS::EC2::Instance", "Properties": {
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 30}}]}},
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}},
    "terraform": 'resource "aws_instance" "host" {\n  root_block_device {\n'
                 '    volume_size = 30\n  }\n}\n'
                 'resource "aws_dynamodb_table" "state" {\n  name = "state"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_attached_data_volume_fails_repo_042(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, INSTANCE[source], ATTACHED_VOLUME[source])
    (finding,) = LocalStateOnCompute().run(tmp_path)
    assert finding.id == "REPO-042"
    assert finding.file == _PATHS[source] and finding.line
    assert f"{_PATHS[source]}:" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_ecs_host_volume_fails_repo_042(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, HOST_VOLUME[source])
    (finding,) = LocalStateOnCompute().run(tmp_path)
    assert "ECS host volume" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_root_volume_and_external_state_pass_repo_042(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, STATELESS[source])
    assert LocalStateOnCompute().run(tmp_path) == []


def test_extra_block_device_and_hostpath_fail(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"],
           'resource "aws_launch_template" "lt" {\n  block_device_mappings {\n'
           '    device_name = "/dev/sdb"\n  }\n}\n')
    _write(tmp_path / "k8s" / "deploy.yaml",
           "volumes:\n  - name: cache\n    hostPath:\n      path: /var/data\n")
    (finding,) = LocalStateOnCompute().run(tmp_path)
    assert "non-root device at main.tf:" in finding.evidence
    assert "Kubernetes hostPath volume at k8s/deploy.yaml:3" in finding.evidence


def test_shared_docker_volume_fails(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {
        "Svc": {"Type": "AWS::ECS::Service", "Properties": {}},
        "Task": {"Type": "AWS::ECS::TaskDefinition", "Properties": {"Volumes": [{
            "Name": "d", "DockerVolumeConfiguration": {"Scope": "shared",
                                                      "Autoprovision": True}}]}}})
    (finding,) = LocalStateOnCompute().run(tmp_path)
    assert "Docker volume" in finding.evidence


def test_local_state_without_compute_is_not_judged(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", ATTACHED_VOLUME["terraform"])
    assert LocalStateOnCompute().run(tmp_path) == []


# --- REPO-043: emergency lever ---

RESERVED = {
    "cdk": "const fn = new lambda.Function(this, 'Fn', { ...props, "
           "reservedConcurrentExecutions: 20 });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function",
                              "Properties": {"ReservedConcurrentExecutions": 20}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n'
                 '  reserved_concurrent_executions = 20\n}\n',
}
THROTTLE = {
    "cdk": "const api = new apigw.RestApi(this, 'Api', { deployOptions: "
           "{ throttlingRateLimit: 100, throttlingBurstLimit: 50 } });\n",
    "cloudformation": {"Plan": {"Type": "AWS::ApiGateway::UsagePlan", "Properties": {
        "Throttle": {"BurstLimit": 50, "RateLimit": 100}}}},
    "terraform": 'resource "aws_api_gateway_method_settings" "all" {\n  settings {\n'
                 '    throttling_burst_limit = 50\n    throttling_rate_limit = 100\n  }\n}\n',
}
RATE_RULE = {
    "cdk": "new wafv2.CfnWebACL(this, 'Acl', { rules: [{ name: 'rate', statement: "
           "{ rateBasedStatement: { limit: 1000, aggregateKeyType: 'IP' } } }] });\n",
    "cloudformation": {"Acl": {"Type": "AWS::WAFv2::WebACL", "Properties": {"Rules": [{
        "Statement": {"RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP"}}}]}}},
    "terraform": 'resource "aws_wafv2_web_acl" "acl" {\n  rule {\n    statement {\n'
                 '      rate_based_statement {\n        limit = 1000\n      }\n    }\n  }\n}\n',
}
FLAGS = {
    "cdk": "new appconfig.HostedConfiguration(this, 'Flags', { application, "
           "type: appconfig.ConfigurationType.FEATURE_FLAGS, content });\n",
    "cloudformation": {"Flags": {"Type": "AWS::AppConfig::ConfigurationProfile", "Properties": {
        "Type": "AWS.AppConfig.FeatureFlags", "LocationUri": "hosted"}}},
    "terraform": 'resource "aws_appconfig_configuration_profile" "flags" {\n'
                 '  type = "AWS.AppConfig.FeatureFlags"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_compute_without_lever_fails_repo_043(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source])
    (finding,) = EmergencyLeverMissing().run(tmp_path)
    assert finding.id == "REPO-043"
    assert "Lambda" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize(
    "lever", [RESERVED, THROTTLE, RATE_RULE, FLAGS], ids=["reserved", "throttle", "waf", "flags"]
)
def test_lever_passes_repo_043(tmp_path: Path, source: str, lever: dict) -> None:
    _stack(tmp_path, source, LAMBDA[source], lever[source])
    assert EmergencyLeverMissing().run(tmp_path) == []


@pytest.mark.parametrize(("rel", "text"), [
    ("src/handler.py", "from aws_lambda_powertools.utilities.feature_flags import FeatureFlags\n"),
    ("src/handler.ts", "import { OpenFeature } from '@openfeature/server-sdk';\n"),
    ("src/package.json", '{"dependencies": {"@launchdarkly/node-server-sdk": "9"}}'),
    ("src/flags.py", "requests.get('http://localhost:2772/applications/a/environments/e')\n"),
])
def test_feature_flag_sdk_in_code_passes(tmp_path: Path, rel: str, text: str) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"])
    _write(tmp_path / rel, text)
    assert emergency_levers(tmp_path)
    assert EmergencyLeverMissing().run(tmp_path) == []


def test_unreserved_concurrency_is_no_lever(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_lambda_function" "fn" {\n'
           '  reserved_concurrent_executions = -1\n}\n')
    assert EmergencyLeverMissing().run(tmp_path)


def test_no_compute_gets_no_repo_043(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", TABLE["terraform"])
    assert EmergencyLeverMissing().run(tmp_path) == []


# --- REPO-044: fallback when a dependency fails ---

SQS_BUFFER = {
    "cdk": "const queue = new sqs.Queue(this, 'Work');\nfn.addEventSource(new SqsEventSource(queue));\n",
    "cloudformation": {
        "Work": {"Type": "AWS::SQS::Queue", "Properties": {}},
        "Map": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
            "EventSourceArn": {"Fn::GetAtt": ["Work", "Arn"]}, "FunctionName": {"Ref": "Fn"}}},
    },
    "terraform": 'resource "aws_sqs_queue" "work" {\n  name = "work"\n}\n'
                 'resource "aws_lambda_event_source_mapping" "m" {\n'
                 '  event_source_arn = aws_sqs_queue.work.arn\n}\n',
}
ON_FAILURE = {
    "cdk": "new lambda.EventInvokeConfig(this, 'Async', { function: fn, "
           "onFailure: new destinations.SqsDestination(dlq) });\n",
    "cloudformation": {"Async": {"Type": "AWS::Lambda::EventInvokeConfig", "Properties": {
        "DestinationConfig": {"OnFailure": {"Destination": "arn:aws:sqs:eu-west-1:1:dlq"}}}}},
    "terraform": 'resource "aws_lambda_function_event_invoke_config" "a" {\n'
                 '  destination_config {\n    on_failure {\n      destination = "arn"\n'
                 '    }\n  }\n}\n',
}
CATCH = {
    "cdk": "const call = new tasks.DynamoGetItem(this, 'Get', props);\n"
           "call.addCatch(fallbackState);\n",
    "cloudformation": {"Flow": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {
        "DefinitionString": json.dumps({"States": {"Get": {
            "Type": "Task", "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "Cached"}]}}})}}},
    "terraform": 'resource "aws_sfn_state_machine" "flow" {\n  definition = jsonencode({\n'
                 '    States = { Get = { Type = "Task", Catch = [{ Next = "Cached" }] } }\n'
                 '  })\n}\n',
}
FAILOVER = {
    "cdk": "new cloudfront.Distribution(this, 'Cdn', { defaultBehavior: { origin: "
           "new origins.OriginGroup({ primaryOrigin, fallbackOrigin }) } });\n",
    "cloudformation": {"Primary": {"Type": "AWS::Route53::RecordSet", "Properties": {
        "Failover": "PRIMARY", "SetIdentifier": "a"}}},
    "terraform": 'resource "aws_route53_record" "primary" {\n'
                 '  failover_routing_policy {\n    type = "PRIMARY"\n  }\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_dependency_without_fallback_fails_repo_044(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], TABLE[source])
    (finding,) = FallbackMissing().run(tmp_path)
    assert finding.id == "REPO-044"
    assert f"DynamoDB ({_PATHS[source]})" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize(
    "fallback", [SQS_BUFFER, ON_FAILURE, CATCH, FAILOVER],
    ids=["sqs", "on-failure", "catch", "failover"],
)
def test_fallback_passes_repo_044(tmp_path: Path, source: str, fallback: dict) -> None:
    _stack(tmp_path, source, LAMBDA[source], TABLE[source], fallback[source])
    assert FallbackMissing().run(tmp_path) == []


def test_mock_integration_and_circuit_breaker_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", LAMBDA["cdk"], TABLE["cdk"],
           "resource.addMethod('GET', new apigw.MockIntegration(degraded));\n")
    assert fallbacks(tmp_path) == {"fixed response or mock integration": "lib/stack.ts"}
    other = tmp_path / "other"
    _stack(other, "terraform", LAMBDA["terraform"], TABLE["terraform"])
    _write(other / "src" / "handler.py", "import pybreaker\nbreaker = pybreaker.CircuitBreaker()\n")
    assert FallbackMissing().run(other) == []


def test_edge_counts_as_a_dependency(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"],
           'resource "aws_apigatewayv2_api" "api" {\n  name = "api"\n}\n')
    (finding,) = FallbackMissing().run(tmp_path)
    assert "API Gateway" in finding.evidence


def test_compute_alone_or_no_compute_gets_no_repo_044(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"])
    assert FallbackMissing().run(tmp_path) == []
    other = tmp_path / "other"
    _stack(other, "terraform", TABLE["terraform"])
    assert FallbackMissing().run(other) == []


def test_ecs_deployment_circuit_breaker_is_no_fallback(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_ecs_service" "svc" {\n'
           '  deployment_circuit_breaker {\n    enable = true\n  }\n}\n', TABLE["terraform"])
    assert FallbackMissing().run(tmp_path)


# --- self-match, mapping, and the REL 5 answer ---

_RULES = (LocalStateOnCompute, EmergencyLeverMissing, FallbackMissing)


def test_saved_reports_quoting_the_findings_neither_pass_nor_fire(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"], ATTACHED_VOLUME["terraform"],
           TABLE["terraform"])
    hits = [f for rule in _RULES for f in rule().run(tmp_path)]
    assert sorted(f.id for f in hits) == ["REPO-042", "REPO-043", "REPO-044"]
    # Evidence and recommendations name every control; a saved report must not pass them.
    report = json.dumps({"findings": [h.model_dump() for h in hits]})
    markdown = "\n".join(f"- {h.title}: {h.evidence}. {h.recommendation}" for h in hits)
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", markdown)
    assert sorted(f.id for rule in _RULES for f in rule().run(tmp_path)) == [
        "REPO-042", "REPO-043", "REPO-044"]
    # Nor does a saved report on its own, with no compute, fire anything.
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", markdown)
    assert [f for rule in _RULES for f in rule().run(empty)] == []


def test_rule_text_matches_no_control() -> None:
    """The rules' own words are not IaC: no evidence or recommendation names a control in
    the syntax the patterns read."""
    from aws_arch_agent.rules import repo_practices as rp

    kinds = (*rp._LOCAL_STATE, *rp._LEVERS, *rp._FLAG_CODE, *rp._FALLBACKS)
    for rule in _RULES:
        for name, pattern in kinds:
            assert not pattern.search(rule.recommendation), (rule.id, name)
            assert not pattern.search(rule.title), (rule.id, name)
        assert not rp._FALLBACK_CODE.search(rule.recommendation), rule.id


def test_rules_map_to_rel5_and_run_by_default() -> None:
    assert well_architected.best_practices_of("REPO-042") == ("REL05-BP06",)
    assert well_architected.best_practices_of("REPO-043") == ("REL05-BP07",)
    assert well_architected.best_practices_of("REPO-044") == ("REL05-BP01",)
    assert not {"REPO-042", "REPO-043", "REPO-044"} & set(ORG_RULE_IDS)


def test_rel5_is_fully_checked_and_reads_met_without_findings() -> None:
    (rel5,) = [a for a in well_architected.answers([]) if a.question.id == "REL 5"]
    assert rel5.not_checked == ()
    assert rel5.met
