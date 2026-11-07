"""Positive and negative cases for template checks that had no direct test."""
import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.rules.cf_template import run_cf_rules


def _ids(tmp_path: Path, rtype: str, props: dict[str, Any]) -> list[str]:
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir(parents=True)
    template = {"Resources": {"Res": {"Type": rtype, "Properties": props}}}
    (cdk_out / "stack.template.json").write_text(json.dumps(template), encoding="utf-8")
    warnings: list[str] = []
    ids = [f.id for f in run_cf_rules(cdk_out, warnings=warnings)]
    # run_cf_rules turns a crashing check into a warning; a crash must not pass as "no finding".
    assert warnings == []
    return ids


CASES = [
    # (rule id, resource type, failing props, passing props)
    (
        "CF-APIGW-001",
        "AWS::ApiGateway::Stage",
        {},
        {"AccessLogSetting": {"DestinationArn": "arn:aws:logs:eu-west-1:111122223333:log-group:api"}},
    ),
    (
        "CF-APIGW-V2-001",
        "AWS::ApiGatewayV2::Stage",
        {"AccessLogSettings": {}},
        {"AccessLogSettings": {"DestinationArn": "arn:aws:logs:eu-west-1:111122223333:log-group:api"}},
    ),
    (
        "CF-CW-002",
        "AWS::Logs::LogGroup",
        {"RetentionInDays": 30},
        {"RetentionInDays": 30, "KmsKeyId": "arn:aws:kms:eu-west-1:111122223333:key/abc"},
    ),
    (
        "CF-DDB-002",
        "AWS::DynamoDB::Table",
        {"SSESpecification": {"SSEEnabled": False}},
        {"SSESpecification": {"SSEEnabled": True}},
    ),
    (
        "CF-SQS-001",
        "AWS::SQS::Queue",
        {},
        {"SqsManagedSseEnabled": True},
    ),
    (
        "CF-SUST-001",
        "AWS::AutoScaling::AutoScalingGroup",
        {"MinSize": "1", "MaxSize": "2"},
        {
            "MinSize": "1",
            "MaxSize": "2",
            "MixedInstancesPolicy": {"InstancesDistribution": {"SpotAllocationStrategy": "price-capacity-optimized"}},
        },
    ),
    (
        "CF-SUST-002",
        "AWS::ECS::Service",
        {"LaunchType": "FARGATE"},
        {
            "CapacityProviderStrategy": [
                {"CapacityProvider": "FARGATE", "Weight": 1},
                {"CapacityProvider": "FARGATE_SPOT", "Weight": 3},
            ]
        },
    ),
]


@pytest.mark.parametrize(("rule_id", "rtype", "bad", "good"), CASES, ids=[c[0] for c in CASES])
def test_check_flags_bad_and_passes_good(
    tmp_path: Path, rule_id: str, rtype: str, bad: dict[str, Any], good: dict[str, Any]
) -> None:
    assert rule_id in _ids(tmp_path / "bad", rtype, bad)
    assert rule_id not in _ids(tmp_path / "good", rtype, good)


def test_sqs_kms_key_also_counts_as_encrypted(tmp_path: Path) -> None:
    assert "CF-SQS-001" not in _ids(tmp_path, "AWS::SQS::Queue", {"KmsMasterKeyId": "alias/aws/sqs"})


def test_dynamodb_sse_type_alone_counts_as_encrypted(tmp_path: Path) -> None:
    ids = _ids(tmp_path, "AWS::DynamoDB::Table", {"SSESpecification": {"SSEType": "KMS"}})
    assert "CF-DDB-002" not in ids


def test_ecs_service_on_ec2_is_not_asked_for_fargate_spot(tmp_path: Path) -> None:
    assert "CF-SUST-002" not in _ids(tmp_path, "AWS::ECS::Service", {"LaunchType": "EC2"})
