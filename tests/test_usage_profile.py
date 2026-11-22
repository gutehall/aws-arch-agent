"""The optional usage profile: validation, precedence, and usage-based cost."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aws_arch_agent import pricing
from aws_arch_agent.config import ConfigError
from aws_arch_agent.pricing.usage import DEFAULT_FILE, UsageError, find, load, parse
from aws_arch_agent.rules import estimates, stack_cost
from aws_arch_agent.rules.resource_model import Resource, resources_from_cf_template

PRICES = {
    "s3:standard": [0.023, "GB-Mo"], "s3:standard-ia": [0.0125, "GB-Mo"],
    "lambda:request": [0.0000002, "Requests"], "lambda:gb-second": [0.0000166667, "Lambda-GB-Second"],
    "lambda:gb-second-arm": [0.0000133334, "Lambda-GB-Second"],
    "nat:hour": [0.045, "Hrs"], "nat:gb": [0.045, "GB"],
    "dynamodb:read-request": [0.000000125, "ReadRequestUnits"],
    "dynamodb:write-request": [0.000000625, "WriteRequestUnits"], "dynamodb:storage-gb": [0.25, "GB-Mo"],
    "logs:ingest-gb": [0.5, "GB"], "logs:storage-gb": [0.03, "GB-Mo"],
    "apigw:rest-request": [0.0000035, "Requests"], "apigw:http-request": [0.000001, "Requests"],
    "elb:alb-hour": [0.0225, "Hrs"], "elb:alb-lcu": [0.008, "LCU-Hrs"], "elb:nlb-lcu": [0.006, "LCU-Hrs"],
    "vpce:gb": [0.01, "GB"], "sqs:standard-request": [0.0000004, "Requests"],
    "sqs:fifo-request": [0.0000005, "Requests"], "sns:request": [0.0000005, "Requests"],
}


@pytest.fixture(autouse=True)
def _prices() -> object:
    with pricing.use_provider(pricing.InMemoryPriceProvider({"us-east-1": PRICES}, {"us-east-1": "2026-11-05"})) as p:
        yield p


def _res(rtype: str, props: dict | None = None, name: str = "R", count: int = 1) -> Resource:
    return Resource(type=rtype, name=name, properties=props or {}, count=count)


@pytest.mark.parametrize("data, message", [
    ({"defaults": {"s3_bucket": {"storage_gb": -1}}}, "must not be negative"),
    ({"defaults": {"s3_bucket": {"monthly_requests": 5}}}, "unknown key"),
    ({"defaults": {"ec2_instance": {"storage_gb": 5}}}, "unknown resource type"),
    ({"resources": {"aws_s3_bucket.b": {"storage_gb": "lots"}}}, "must be a number"),
    ({"resources": {"aws_s3_bucket.b": {"storage_gb": True}}}, "must be a number"),
    ({"resources": {"B": {"storage_class": "tape"}}}, "storage_class"),
    ({"resources": {"B": {"what": 1}}}, "unknown key"),
    ({"budget": 1}, "unknown top-level key"),
    ({"defaults": []}, "must be mappings"),
    ([1, 2], "must be a mapping"),
])
def test_invalid_profiles_are_config_errors(data: object, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse(data)


def test_load_and_find(tmp_path: Path) -> None:
    assert find(tmp_path) is None
    (tmp_path / DEFAULT_FILE).write_text("defaults:\n  s3_bucket:\n    storage_gb: 10\n", encoding="utf-8")
    assert find(tmp_path) == tmp_path / DEFAULT_FILE
    assert find(tmp_path, tmp_path / "other.yaml") == tmp_path / "other.yaml"
    profile = load(tmp_path / DEFAULT_FILE)
    assert profile.defaults == {"s3_bucket": {"storage_gb": 10}} and profile.path.endswith(DEFAULT_FILE)
    assert parse(None).for_resource("s3_bucket", "B") is None
    with pytest.raises(UsageError, match="cannot read"):
        load(tmp_path / "missing.yaml")
    (tmp_path / "bad.yaml").write_text("defaults: [\n", encoding="utf-8")
    with pytest.raises(UsageError, match="not valid YAML"):
        load(tmp_path / "bad.yaml")


def test_resource_entry_wins_over_type_defaults() -> None:
    profile = parse({
        "defaults": {"s3_bucket": {"storage_gb": 10, "storage_class": "standard"}},
        "resources": {"aws_s3_bucket.uploads": {"storage_gb": 2000}, "Other": {"monthly_requests": 5}},
    })
    assert profile.for_resource("s3_bucket", "aws_s3_bucket.uploads") == {"storage_gb": 2000, "storage_class": "standard"}
    assert profile.for_resource("s3_bucket", "aws_s3_bucket.logs") == {"storage_gb": 10, "storage_class": "standard"}
    assert profile.for_resource("sqs_queue", "Other") == {"monthly_requests": 5}
    assert profile.for_resource("instance", "Other") is None and profile.for_resource(None, "Other") is None


@pytest.mark.parametrize("rtype, props, usage, usd", [
    ("s3_bucket", {}, {"storage_gb": 100}, 100 * 0.023),
    ("s3_bucket", {}, {"storage_gb": 100, "storage_class": "standard-ia"}, 100 * 0.0125),
    ("lambda_function", {"MemorySize": 512}, {"monthly_requests": 1_000_000, "avg_duration_ms": 200},
     1_000_000 * 0.0000002 + 1_000_000 * 0.2 * 0.5 * 0.0000166667),
    ("lambda_function", {"Architectures": ["arm64"]}, {"monthly_requests": 1_000_000, "avg_duration_ms": 100},
     1_000_000 * 0.0000002 + 1_000_000 * 0.1 * 0.125 * 0.0000133334),
    ("lambda_function", {}, {"monthly_requests": 3_000_000}, 3_000_000 * 0.0000002),
    ("nat_gateway", {}, {"monthly_data_processed_gb": 500}, 500 * 0.045),
    ("dynamodb_table", {"BillingMode": "PAY_PER_REQUEST"},
     {"monthly_read_request_units": 10_000_000, "monthly_write_request_units": 1_000_000, "storage_gb": 20},
     10_000_000 * 0.000000125 + 1_000_000 * 0.000000625 + 20 * 0.25),
    ("dynamodb_table", {"BillingMode": "PROVISIONED"}, {"monthly_read_request_units": 1e9, "storage_gb": 20}, 5.0),
    ("cloudwatch_log_group", {}, {"monthly_ingest_gb": 30, "storage_gb": 200}, 30 * 0.5 + 200 * 0.03),
    ("api_gateway_rest_api", {}, {"monthly_requests": 10_000_000}, 35.0),
    ("apigatewayv2_api", {"ProtocolType": "HTTP"}, {"monthly_requests": 10_000_000}, 10.0),
    ("lb", {}, {"monthly_lcu_hours": 1460}, 1460 * 0.008),
    ("lb", {"Type": "network"}, {"monthly_lcu_hours": 730}, 730 * 0.006),
    ("vpc_endpoint", {"VpcEndpointType": "Interface"}, {"monthly_data_processed_gb": 100}, 1.0),
    ("sqs_queue", {}, {"monthly_requests": 5_000_000}, 2.0),
    ("sqs_queue", {"FifoQueue": True}, {"monthly_requests": 5_000_000}, 2.5),
    ("sns_topic", {}, {"monthly_requests": 2_000_000}, 1.0),
])
def test_usage_calculators(rtype: str, props: dict, usage: dict, usd: float) -> None:
    est = estimates.usage_cost(_res(rtype, props), usage)
    assert est is not None and est.monthly_cost_usd == round(usd, 2), est
    assert est.basis.startswith("Usage assumed (") and "free tier not deducted" in est.basis
    assert "us-east-1, AWS prices of 2026-11-05" in est.basis


@pytest.mark.parametrize("rtype, props, usage", [
    ("apigatewayv2_api", {"ProtocolType": "WEBSOCKET"}, {"monthly_requests": 5}),
    ("lb", {"Type": "gateway"}, {"monthly_lcu_hours": 5}),
    ("vpc_endpoint", {}, {"monthly_data_processed_gb": 5}),  # a gateway endpoint
    ("lambda_function", {"MemorySize": {"Ref": "Mem"}}, {"monthly_requests": 5}),
    ("lambda_function", {}, {"avg_duration_ms": 5}),
    ("s3_bucket", {}, {"storage_class": "standard"}),
])
def test_usage_that_cannot_be_priced(rtype: str, props: dict, usage: dict) -> None:
    assert estimates.usage_cost(_res(rtype, props), usage) is None


def test_count_multiplies_usage() -> None:
    est = estimates.usage_cost(_res("sqs_queue", count=3), {"monthly_requests": 5_000_000})
    assert est is not None and est.monthly_cost_usd == 6.0 and est.basis.startswith("count = 3 × (Usage assumed")


TEMPLATE = {"Resources": {
    "Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": "s"}},
    "Uploads": {"Type": "AWS::S3::Bucket", "Properties": {}},
    "Fn": {"Type": "AWS::Lambda::Function", "Properties": {"Runtime": "python3.13", "Handler": "a", "Role": "r"}},
    "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
}}


def _summary(tmp_path: Path, profile: object) -> dict:
    path = tmp_path / "t.json"
    path.write_text(json.dumps(TEMPLATE), encoding="utf-8")
    with stack_cost.collect(stack_cost.FinOps(usage=profile)):  # type: ignore[arg-type]
        stack_cost.record(path, resources_from_cf_template(path, TEMPLATE))
        cost = stack_cost.summary([], tmp_path)
    assert cost is not None
    return cost


def test_without_a_profile_usage_resources_stay_not_priced(tmp_path: Path) -> None:
    cost = _summary(tmp_path, None)
    assert cost["usage_monthly_usd"] == 0.0 and cost["fixed_monthly_usd"] == cost["total_monthly_usd"] == 32.85
    assert cost["not_priced"] == {"AWS::Lambda::Function": 1, "AWS::S3::Bucket": 1, "AWS::SQS::Queue": 1}
    assert all("usage_assumed" not in r for r in cost["top_resources"]) and "usage_file" not in cost


def test_fixed_and_usage_cost_are_kept_apart(tmp_path: Path) -> None:
    profile = parse({"defaults": {"nat_gateway": {"monthly_data_processed_gb": 1000}},
                     "resources": {"Uploads": {"storage_gb": 1000}}}, "usage.yaml")
    cost = _summary(tmp_path, profile)
    assert cost["fixed_monthly_usd"] == 32.85
    assert cost["usage_monthly_usd"] == round(1000 * 0.045 + 1000 * 0.023, 2)
    assert cost["total_monthly_usd"] == round(32.85 + 45 + 23, 2)
    assert cost["stacks"][0]["fixed_monthly_usd"] == 32.85 and cost["stacks"][0]["resources_priced"] == 2
    assert cost["not_priced"] == {"AWS::Lambda::Function": 1, "AWS::SQS::Queue": 1}
    flagged = {(r["name"], r.get("usage_assumed", False)) for r in cost["top_resources"]}
    assert flagged == {("Nat", True), ("Nat", False), ("Uploads", True)}
    assert cost["usage_file"] == "usage.yaml" and "usage profile (usage.yaml)" in cost["basis"]


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(ConfigError, match="must be a number"):
        parse({"defaults": {"s3_bucket": {"storage_gb": value}}})
