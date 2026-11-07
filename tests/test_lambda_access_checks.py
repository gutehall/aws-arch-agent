"""Lambda access, secrets and limits in templates: CF-LAM-004..008."""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.secret_names import is_literal_secret, is_secret_name
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = tuple(f"CF-LAM-00{n}" for n in range(4, 9))


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


def _fn(**props: object) -> dict:
    base = {"Role": "arn:aws:iam::111122223333:role/r", "Handler": "index.handler",
            "Runtime": "nodejs22.x", "Code": {"ZipFile": "x"}, "ReservedConcurrentExecutions": 10}
    return {"Type": "AWS::Lambda::Function", "Properties": {**base, **props}}


def test_secret_names_and_values() -> None:
    assert is_secret_name("DB_PASSWORD") and is_secret_name("ApiKey") and is_secret_name("GITHUB_TOKEN")
    assert is_secret_name("MINIO_SECRET_KEY") and is_secret_name("MINT_API_KEY")
    assert not is_secret_name("MAX_TOKENS") and not is_secret_name("MIN_PASSWORD_LENGTH")
    assert not is_secret_name("DB_SECRET_ARN") and not is_secret_name("TOKEN_URL")
    assert not is_secret_name("TABLE_NAME") and not is_secret_name("MaxTokens")
    assert is_literal_secret("hunter2-but-longer")
    for value in ("", "true", "12", "arn:aws:secretsmanager:eu-west-1:1:secret:x",
                  "{{resolve:secretsmanager:db}}", {"Ref": "Secret"}):
        assert not is_literal_secret(value)


def test_function_url_and_environment(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "PublicUrl": {"Type": "AWS::Lambda::Url", "Properties": {
            "TargetFunctionArn": {"Fn::GetAtt": ["Fn", "Arn"]}, "AuthType": "NONE"}},
        "IamUrl": {"Type": "AWS::Lambda::Url", "Properties": {
            "TargetFunctionArn": {"Fn::GetAtt": ["Fn", "Arn"]}, "AuthType": "AWS_IAM"}},
        "Leaky": _fn(Environment={"Variables": {"DB_PASSWORD": "s3cr3t-value", "STAGE": "prod"}}),
        "Safe": _fn(Environment={"Variables": {
            "DB_SECRET_ARN": {"Ref": "Secret"}, "API_KEY": "{{resolve:ssm-secure:/app/key}}",
            "TOKEN_CACHE_ENABLED": "true", "PASSWORD": {"Ref": "PasswordParam"}}}),
        "Unreserved": _fn(ReservedConcurrentExecutions=None),
    })
    assert found == {"CF-LAM-004": {"PublicUrl"}, "CF-LAM-005": {"Leaky"}, "CF-LAM-006": {"Unreserved"}}


def test_timeouts_against_triggers(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Consumer": _fn(),  # default 3 s, polled by a mapping
        "SlowConsumer": _fn(Timeout=60),
        "Api": _fn(Timeout=900),
        "Batch": _fn(Timeout=900),  # no API Gateway in front
        "Mapping": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
            "FunctionName": {"Ref": "Consumer"}, "EventSourceArn": "arn:aws:sqs:eu-west-1:1:q"}},
        "SlowMapping": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
            "FunctionName": {"Ref": "SlowConsumer"}, "EventSourceArn": "arn:aws:sqs:eu-west-1:1:q"}},
        "ApiInvoke": {"Type": "AWS::Lambda::Permission", "Properties": {
            "Action": "lambda:InvokeFunction", "FunctionName": {"Fn::GetAtt": ["Api", "Arn"]},
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": "arn:aws:execute-api:eu-west-1:1:abc/*"}},
    })
    assert found == {"CF-LAM-007": {"Consumer", "Api"}}


def _subnet(az: int | None) -> dict:
    props: dict = {"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/24"}
    if az is not None:
        props["AvailabilityZone"] = {"Fn::Select": [az, {"Fn::GetAZs": ""}]}
    return {"Type": "AWS::EC2::Subnet", "Properties": props}


def test_vpc_function_in_one_az(tmp_path: Path) -> None:
    def vpc(*subnets: object) -> dict:
        return {"SubnetIds": list(subnets), "SecurityGroupIds": ["sg-1"]}

    found = _cf(tmp_path, {
        "A1": _subnet(0), "A2": _subnet(0), "B": _subnet(1), "Unknown": _subnet(None),
        "OneAz": _fn(VpcConfig=vpc({"Ref": "A1"}, {"Ref": "A2"})),
        "TwoAz": _fn(VpcConfig=vpc({"Ref": "A1"}, {"Ref": "B"})),
        "Imported": _fn(VpcConfig=vpc("subnet-123")),
        "NoAz": _fn(VpcConfig=vpc({"Ref": "Unknown"})),
    })
    assert found == {"CF-LAM-008": {"OneAz"}}


def test_terraform_lambda(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("""\
variable "stage" { type = string }
resource "aws_subnet" "a" {
  vpc_id            = "vpc-1"
  cidr_block        = "10.0.0.0/24"
  availability_zone = "eu-west-1a"
}
resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::1:role/r"
  runtime       = "python3.13"
  handler       = "app.handler"
  environment {
    variables = {
      API_KEY = "abc123-literal"
      STAGE   = var.stage
    }
  }
  vpc_config {
    subnet_ids         = [aws_subnet.a.id]
    security_group_ids = ["sg-1"]
  }
}
resource "aws_lambda_function" "reserved" {
  function_name                  = "reserved"
  role                           = "arn:aws:iam::1:role/r"
  runtime                        = "python3.13"
  handler                        = "app.handler"
  timeout                        = 30
  reserved_concurrent_executions = 5
}
resource "aws_lambda_event_source_mapping" "queue" {
  function_name    = aws_lambda_function.worker.arn
  event_source_arn = "arn:aws:sqs:eu-west-1:1:q"
}
resource "aws_lambda_function_url" "public" {
  function_name      = aws_lambda_function.worker.function_name
  authorization_type = "NONE"
}
""", encoding="utf-8")
    warnings: list[str] = []
    found = _by_id(run_resource_checks(resources_from_terraform(tmp_path, warnings), tmp_path / "main.tf", warnings))
    assert warnings == []
    assert found == {
        "CF-LAM-004": {"aws_lambda_function_url.public"},
        "CF-LAM-005": {"aws_lambda_function.worker"},
        "CF-LAM-006": {"aws_lambda_function.worker"},
        "CF-LAM-007": {"aws_lambda_function.worker"},
        "CF-LAM-008": {"aws_lambda_function.worker"},
    }
