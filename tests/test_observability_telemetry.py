"""OPS 4: the workload publishes an application KPI (REPO-018), measures user experience on
the edge (REPO-019), and has telemetry on the datastores and queues it calls (REPO-020)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    DependencyTelemetryMissing,
    EdgeTelemetryMissing,
    KpiMetricMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

RULES = ("REPO-018", "REPO-019", "REPO-020")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _cf_alarm(namespace: str, metric: str) -> dict:
    return {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": namespace, "MetricName": metric, "Statistic": "Sum", "Period": 60,
        "EvaluationPeriods": 1, "Threshold": 1,
        "ComparisonOperator": "GreaterThanOrEqualToThreshold"}}


# A Lambda function behind an API, writing to a queue: compute, an edge and a dependency.
_CF_BASE = {
    "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
        "Runtime": "python3.12", "Handler": "app.handler", "Role": "arn:aws:iam::1:role/r",
        "Code": {"ZipFile": "def handler(e, c): pass"}}},
    "Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": "shop"}},
    "Jobs": {"Type": "AWS::SQS::Queue", "Properties": {}},
}
_CF_CONTROLS = {
    "REPO-018": {
        "alarm": {"Orders": _cf_alarm("Shop", "OrdersPlaced")},
        "metric filter": {"Orders": {"Type": "AWS::Logs::MetricFilter", "Properties": {
            "LogGroupName": "/shop/app", "FilterPattern": "ORDER_PLACED",
            "MetricTransformations": [{"MetricNamespace": "Shop", "MetricName": "Orders",
                                       "MetricValue": "1"}]}}},
    },
    "REPO-019": {
        "canary": {"Checkout": {"Type": "AWS::Synthetics::Canary", "Properties": {
            "Name": "checkout", "RuntimeVersion": "syn-nodejs-puppeteer-9.1"}}},
        "rum": {"Web": {"Type": "AWS::RUM::AppMonitor", "Properties": {
            "Name": "web", "Domain": "shop.example.com"}}},
        "health check": {"Health": {"Type": "AWS::Route53::HealthCheck", "Properties": {
            "HealthCheckConfig": {"Type": "HTTPS", "FullyQualifiedDomainName": "api.shop"}}}},
        "edge alarm": {"Errors": _cf_alarm("AWS/ApiGateway", "5XXError")},
    },
    "REPO-020": {
        "dependency alarm": {"Age": _cf_alarm("AWS/SQS", "ApproximateAgeOfOldestMessage")},
        "adot layer": {"Traced": {"Type": "AWS::Lambda::Function", "Properties": {
            "Runtime": "python3.12", "Handler": "app.handler", "Role": "arn:aws:iam::1:role/r",
            "Layers": ["arn:aws:lambda:eu-west-1:901920570463:layer:"
                       "aws-otel-python-amd64-ver-1-25-0:1"],
            "Code": {"ZipFile": "def handler(e, c): pass"}}}},
        "application signals": {"Slo": {
            "Type": "AWS::ApplicationSignals::ServiceLevelObjective",
            "Properties": {"Name": "checkout-latency"}}},
    },
}

_TF_BASE = '''
resource "aws_lambda_function" "fn" {
  function_name = "shop"
  runtime       = "python3.12"
  handler       = "app.handler"
  role          = aws_iam_role.fn.arn
}
resource "aws_apigatewayv2_api" "api" {
  name          = "shop"
  protocol_type = "HTTP"
}
resource "aws_sqs_queue" "jobs" {
  name = "jobs"
}
'''


def _tf_alarm(namespace: str, metric: str) -> str:
    return (
        f'resource "aws_cloudwatch_metric_alarm" "a" {{\n  namespace = "{namespace}"\n'
        f'  metric_name = "{metric}"\n  statistic = "Sum"\n  period = 60\n'
        '  evaluation_periods = 1\n  threshold = 1\n'
        '  comparison_operator = "GreaterThanOrEqualToThreshold"\n}\n'
    )


_TF_CONTROLS = {
    "REPO-018": {
        "alarm": _tf_alarm("Shop", "OrdersPlaced"),
        "metric filter": (
            'resource "aws_cloudwatch_log_metric_filter" "orders" {\n'
            '  name = "orders"\n  log_group_name = "/shop/app"\n  pattern = "ORDER_PLACED"\n'
            '  metric_transformation {\n    name = "Orders"\n    namespace = "Shop"\n'
            '    value = "1"\n  }\n}\n'),
    },
    "REPO-019": {
        "canary": 'resource "aws_synthetics_canary" "checkout" {\n  name = "checkout"\n}\n',
        "rum": 'resource "aws_rum_app_monitor" "web" {\n  name = "web"\n}\n',
        "health check": (
            'resource "aws_route53_health_check" "api" {\n  fqdn = "api.shop.example.com"\n'
            '  type = "HTTPS"\n}\n'),
        "edge alarm": _tf_alarm("AWS/ApiGateway", "Latency"),
    },
    "REPO-020": {
        "dependency alarm": _tf_alarm("AWS/SQS", "ApproximateAgeOfOldestMessage"),
        "adot layer": (
            'resource "aws_lambda_function" "traced" {\n  function_name = "traced"\n'
            '  layers = ["arn:aws:lambda:eu-west-1:901920570463:layer:'
            'aws-otel-python-amd64-ver-1-25-0:1"]\n'
            '  environment {\n    variables = {\n'
            '      AWS_LAMBDA_EXEC_WRAPPER = "/opt/otel-instrument"\n    }\n  }\n}\n'),
    },
}

_CDK_BASE = (
    "const fn = new lambda.Function(this, 'Fn', { runtime, handler: 'app.handler', code });\n"
    "const api = new apigateway.LambdaRestApi(this, 'Api', { handler: fn });\n"
    "const queue = new sqs.Queue(this, 'Jobs');\n"
)
_CDK_CONTROLS = {
    "REPO-018": {
        "alarm": (
            "new cloudwatch.Alarm(this, 'Orders', { metric: new cloudwatch.Metric({\n"
            "  namespace: 'Shop', metricName: 'OrdersPlaced' }), threshold: 1,\n"
            "  evaluationPeriods: 1 });\n"),
        "metric filter": (
            "new logs.MetricFilter(this, 'Orders', { logGroup, metricNamespace: 'Shop',\n"
            "  metricName: 'Orders', filterPattern: logs.FilterPattern.literal('ORDER') });\n"),
    },
    "REPO-019": {
        "canary": "new synthetics.Canary(this, 'Checkout', { schedule, test, runtime });\n",
        "rum": "new rum.CfnAppMonitor(this, 'Web', { name: 'web', domain: 'shop.com' });\n",
        "health check": (
            "new route53.CfnHealthCheck(this, 'Health', { healthCheckConfig: {\n"
            "  type: 'HTTPS', fullyQualifiedDomainName: 'api.shop.example.com' } });\n"),
        "edge alarm": "api.metricLatency().createAlarm(this, 'Slow', { threshold: 1000, "
                      "evaluationPeriods: 3 });\n",
    },
    "REPO-020": {
        "dependency alarm": (
            "new cloudwatch.Alarm(this, 'Age', {\n"
            "  metric: queue.metricApproximateAgeOfOldestMessage(), threshold: 300,\n"
            "  evaluationPeriods: 1 });\n"),
        "adot layer": (
            "new lambda.Function(this, 'Traced', { runtime, handler, code,\n"
            "  adotInstrumentation: { layerVersion, execWrapper } });\n"),
        "application signals": (
            "new appsignals.ApplicationSignalsIntegration(this, 'Signals', {\n"
            "  taskDefinition, instrumentation });\n"),
    },
}


def _cfn_iac(controls: dict | None = None) -> dict[str, str]:
    return {"t.json": _cfn({**_CF_BASE, **(controls or {})})}


def _tf_iac(controls: str = "") -> dict[str, str]:
    return {"main.tf": _TF_BASE + controls}


def _cdk_iac(controls: str = "") -> dict[str, str]:
    return {"lib/stack.ts": _CDK_BASE + controls, "package.json": "{}"}


_BUILDERS = {"cdk": _cdk_iac, "cloudformation": _cfn_iac, "terraform": _tf_iac}
_CONTROLS = {"cdk": _CDK_CONTROLS, "cloudformation": _CF_CONTROLS, "terraform": _TF_CONTROLS}
_SOURCE_IDS = list(_BUILDERS)
_CASES = [
    (source, rule_id, kind)
    for source in _SOURCE_IDS
    for rule_id in RULES
    for kind in _CONTROLS[source][rule_id]
]


def _scan(root: Path, iac: dict[str, str], code: dict[str, str] | None = None) -> tuple:
    # IaC under prod/: the pytest directory name says "test", which reads as a dev stack.
    for rel, text in {**iac, **(code or {})}.items():
        _write(root / "prod" / rel, text)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return ctx, findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops4() -> None:
    assert RULE_BEST_PRACTICES["REPO-018"] == ("OPS04-BP01",)
    assert RULE_BEST_PRACTICES["REPO-019"] == ("OPS04-BP03",)
    assert RULE_BEST_PRACTICES["REPO-020"] == ("OPS04-BP04",)
    assert {"OPS04-BP01", "OPS04-BP03", "OPS04-BP04"}.isdisjoint(NOT_CHECKED)


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_no_telemetry_fails_ops4(tmp_path: Path, source: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source]())
    assert ctx.source == source
    (kpi,) = _found(findings, "REPO-018")
    (edge,) = _found(findings, "REPO-019")
    (deps,) = _found(findings, "REPO-020")
    for hit in (kpi, edge, deps):
        assert hit.question == "OPS 4"
        assert hit.category == "Operational Excellence"
        assert hit.evidence.endswith("found none")
        assert hit.file is None  # repo-level: the evidence names the files
    assert (kpi.severity, edge.severity, deps.severity) == ("Low", "Medium", "Low")
    assert kpi.evidence.startswith("Runs Lambda (prod/")
    assert edge.evidence.startswith("Serves users through API Gateway (prod/")
    assert deps.evidence.startswith("Calls SQS (prod/")
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    assert not answer["OPS 4"].met


@pytest.mark.parametrize(("source", "rule_id", "kind"), _CASES)
def test_iac_control_passes(tmp_path: Path, source: str, rule_id: str, kind: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source](_CONTROLS[source][rule_id][kind]))
    assert ctx.source == source
    assert not _found(findings, rule_id)
    # One control answers one practice; the others still fire.
    for other in RULES:
        if other != rule_id:
            assert _found(findings, other), f"{kind} passed {other}"


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_all_controls_answer_ops4(tmp_path: Path, source: str) -> None:
    controls = _CONTROLS[source]
    picked = [controls["REPO-018"]["alarm"], controls["REPO-019"]["canary"],
              controls["REPO-020"]["dependency alarm"]]
    if source == "cloudformation":
        merged: dict = {}
        for part in picked:
            merged.update(part)
        iac = _cfn_iac(merged)
    else:
        iac = _BUILDERS[source]("".join(picked))
    ctx, findings = _scan(tmp_path, iac)
    # Other OPS 4 rules (X-Ray active tracing, OPS04-BP05) may still fire.
    assert not [f for f in findings if f.id in RULES]
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    assert {"OPS04-BP01", "OPS04-BP03", "OPS04-BP04"}.isdisjoint(answer["OPS 4"].not_checked)


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_aws_service_metric_alarm_is_not_a_kpi(tmp_path: Path, source: str) -> None:
    # An alarm on a default Lambda metric is neither a KPI, an edge metric, nor a dependency.
    alarm = {
        "cdk": "fn.metricErrors().createAlarm(this, 'Errors', { threshold: 1, "
               "evaluationPeriods: 1 });\n",
        "cloudformation": {"Errors": _cf_alarm("AWS/Lambda", "Errors")},
        "terraform": _tf_alarm("AWS/Lambda", "Errors"),
    }[source]
    _ctx, findings = _scan(tmp_path, _BUILDERS[source](alarm))  # type: ignore[operator]
    for rule_id in RULES:
        assert _found(findings, rule_id)


@pytest.mark.parametrize(
    ("rule_id", "path", "code"),
    [
        ("REPO-018", "src/app.py",
         "from aws_embedded_metrics import metric_scope\n@metric_scope\ndef handler(m): pass\n"),
        ("REPO-018", "src/index.ts",
         "import { createMetricsLogger } from 'aws-embedded-metrics';\n"),
        ("REPO-018", "src/app.py",
         "boto3.client('cloudwatch').put_metric_data(Namespace='Shop', MetricData=[])\n"),
        ("REPO-018", "src/index.ts",
         "await cw.send(new PutMetricDataCommand({ Namespace: 'Shop', MetricData }));\n"),
        ("REPO-018", "src/app.py",
         "from aws_lambda_powertools import Metrics\nmetrics = Metrics(namespace='Shop')\n"),
        ("REPO-018", "src/index.ts",
         "import { Metrics } from '@aws-lambda-powertools/metrics';\n"),
        ("REPO-020", "src/index.js",
         "const AWSXRay = require('aws-xray-sdk-core');\n"
         "const sqs = AWSXRay.captureAWSv3Client(new SQSClient({}));\n"),
        ("REPO-020", "src/app.py",
         "from aws_xray_sdk.core import patch_all\npatch_all()\n"),
        ("REPO-020", "src/app.py",
         "from aws_xray_sdk.core import patch\npatch(['boto3'])\n"),
        ("REPO-020", "src/app.py",
         "from aws_lambda_powertools import Tracer\ntracer = Tracer()\n"),
        ("REPO-020", "src/index.ts",
         "const client = tracer.captureAWSv3Client(new DynamoDBClient({}));\n"),
        ("REPO-020", "src/tracing.ts",
         "import { AwsInstrumentation } from '@opentelemetry/instrumentation-aws-sdk';\n"),
        ("REPO-020", "src/package.json",
         json.dumps({"dependencies": {"@opentelemetry/instrumentation-aws-sdk": "^0.44.0"}})),
        ("REPO-020", "src/requirements.txt", "opentelemetry-instrumentation-botocore==0.48b0\n"),
    ],
    ids=["emf-py", "emf-ts", "put-metric-data-py", "put-metric-data-ts", "powertools-py",
         "powertools-ts", "xray-js", "xray-patch-all", "xray-patch-boto3", "tracer-py",
         "tracer-ts", "otel-code", "otel-package", "otel-requirements"],
)
def test_code_control_passes(tmp_path: Path, rule_id: str, path: str, code: str) -> None:
    rule = {"REPO-018": KpiMetricMissing(), "REPO-020": DependencyTelemetryMissing()}[rule_id]
    _write(tmp_path / "prod" / "main.tf", _TF_BASE)
    assert rule.run(tmp_path)
    _write(tmp_path / path, code)
    assert not rule.run(tmp_path)


def test_powertools_tracer_without_auto_patch_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF_BASE)
    _write(tmp_path / "src" / "app.py",
           "from aws_lambda_powertools import Tracer\ntracer = Tracer(auto_patch=False)\n")
    assert DependencyTelemetryMissing().run(tmp_path)


def test_put_metric_data_permission_is_not_a_metric(tmp_path: Path) -> None:
    # Granting cloudwatch:PutMetricData in a policy does not publish a metric.
    _write(tmp_path / "prod" / "main.tf", _TF_BASE + (
        'data "aws_iam_policy_document" "fn" {\n  statement {\n'
        '    actions = ["cloudwatch:PutMetricData"]\n    resources = ["*"]\n  }\n}\n'))
    assert KpiMetricMissing().run(tmp_path)


def test_kubernetes_namespace_is_not_a_metric_namespace(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF_BASE + _tf_alarm("AWS/Lambda", "Errors") + (
        'resource "helm_release" "app" {\n  name = "app"\n  namespace = "shop"\n}\n'))
    assert KpiMetricMissing().run(tmp_path)


def test_ecs_service_connect_namespace_is_not_a_metric_namespace(tmp_path: Path) -> None:
    service = {"Svc": {"Type": "AWS::ECS::Service", "Properties": {
        "ServiceConnectConfiguration": {"Enabled": True, "Namespace": "shop"}}},
        "Errors": _cf_alarm("AWS/ECS", "CPUUtilization")}
    _write(tmp_path / "prod" / "t.json", _cfn(service))
    (hit,) = KpiMetricMissing().run(tmp_path)
    assert hit.evidence.startswith("Runs ECS service (prod/t.json)")


@pytest.mark.parametrize(
    ("resources", "rule"),
    [
        ({"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}, KpiMetricMissing()),
        ({"Jobs": _CF_BASE["Jobs"]}, EdgeTelemetryMissing()),
        ({"Api": _CF_BASE["Api"]}, DependencyTelemetryMissing()),
    ],
    ids=["no-compute", "no-edge", "no-dependency"],
)
def test_no_finding_without_the_precondition(
    tmp_path: Path, resources: dict, rule: object
) -> None:
    _write(tmp_path / "prod" / "t.json", _cfn(resources))
    assert not rule.run(tmp_path)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("rule_id", "text", "kind"),
    [
        ("REPO-019", "Events:\n  Get:\n    Type: Api\n", "API Gateway"),
        ("REPO-019", 'resource "aws_lb" "web" {\n  internal = false\n}\n', "load balancer"),
        ("REPO-019", "new cloudfront.Distribution(this, 'Cdn', { defaultBehavior });\n",
         "CloudFront"),
        ("REPO-020", 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n', "RDS"),
        ("REPO-020", "new dynamodb.TableV2(this, 'Orders', { partitionKey });\n", "DynamoDB"),
        ("REPO-020", 'resource "aws_elasticache_replication_group" "c" {\n}\n', "ElastiCache"),
        ("REPO-020", "sns.Topic(self, 'Events')\n", "SNS"),
        ("REPO-020", 'resource "aws_kinesis_stream" "s" {\n  shard_count = 1\n}\n', "Kinesis"),
        ("REPO-020", "new opensearch.Domain(this, 'Search', { version });\n", "OpenSearch"),
    ],
    ids=["sam-api", "alb", "cloudfront", "rds", "dynamodb", "elasticache", "sns", "kinesis",
         "opensearch"],
)
def test_evidence_lists_what_it_found(tmp_path: Path, rule_id: str, text: str, kind: str) -> None:
    if text.startswith("Events"):
        text = (
            "Transform: AWS::Serverless-2016-10-31\nResources:\n  Fn:\n"
            "    Type: AWS::Serverless::Function\n    Properties:\n      "
            + text.replace("\n", "\n      ")
        )
        name = "template.yaml"
    elif text.startswith("resource"):
        name = "main.tf"
    else:
        name = "stack.py" if "self" in text else "stack.ts"
    _write(tmp_path / "prod" / name, text)
    rule = {"REPO-019": EdgeTelemetryMissing(), "REPO-020": DependencyTelemetryMissing()}[rule_id]
    (hit,) = rule.run(tmp_path)
    assert f"{kind} (prod/{name})" in hit.evidence


def test_controls_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF_BASE)
    _write(tmp_path / "tests" / "monitoring.tf",
           _TF_CONTROLS["REPO-018"]["alarm"] + _TF_CONTROLS["REPO-019"]["canary"])
    _write(tmp_path / "tests" / "test_app.py", "from aws_xray_sdk.core import patch_all\n")
    assert KpiMetricMissing().run(tmp_path)
    assert EdgeTelemetryMissing().run(tmp_path)
    assert DependencyTelemetryMissing().run(tmp_path)


def test_report_quoting_a_metric_namespace_does_not_pass(tmp_path: Path) -> None:
    # A JSON report saved in the repo quotes the findings, their recommendations, and an
    # alarm on a custom namespace and on the edge and queue namespaces; none of it is IaC.
    _write(tmp_path / "prod" / "main.tf", _TF_BASE)
    rules = (KpiMetricMissing(), EdgeTelemetryMissing(), DependencyTelemetryMissing())
    hits = [hit for rule in rules for hit in rule.run(tmp_path)]
    assert len(hits) == 3
    quoted = [
        'Alarm (AWS::CloudWatch::Alarm) "Namespace": "Shop", MetricName OrdersPlaced',
        'resource "aws_cloudwatch_metric_alarm" namespace = "AWS/ApiGateway" Latency',
        "AWS::CloudWatch::Alarm on AWS/SQS ApproximateAgeOfOldestMessage",
    ]
    report = {"findings": [
        {"evidence": hit.evidence, "recommendation": hit.recommendation} for hit in hits
    ] + [{"evidence": text} for text in quoted]}
    _write(tmp_path / "report.json", json.dumps(report, indent=2))
    for rule in rules:
        assert rule.run(tmp_path)
