"""COST 9: demand management. Demand analysis (REPO-096) and a buffer or throttle on what
takes demand (REPO-097)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import DemandNotAnalysed, DemandUnbuffered

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}
RULES = (DemandNotAnalysed(), DemandUnbuffered())


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object, env: str = "prod") -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / env / _PATHS[source], body)


# REPO-096: demand analysis.

FN = {
    "cdk": "new lambda.Function(this, 'Fn', { runtime, handler, code });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}
SCHEDULE = {
    "cdk": "target.scaleOnSchedule('Peak', { schedule: autoscaling.Schedule.cron({ hour: '8' }) });\n",
    "cloudformation": {"Peak": {"Type": "AWS::AutoScaling::ScheduledAction", "Properties": {
        "Recurrence": "0 8 * * *"}}},
    "terraform": 'resource "aws_autoscaling_schedule" "peak" {\n  recurrence = "0 8 * * *"\n}\n',
}
QUEUE_DEPTH = {
    "cdk": "new cloudwatch.Metric({ namespace: 'AWS/SQS', "
           "metricName: 'ApproximateNumberOfMessagesVisible' });\n",
    "cloudformation": {"A": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "MetricName": "ApproximateNumberOfMessagesVisible", "Namespace": "AWS/SQS"}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "a" {\n'
                 '  metric_name = "ApproximateNumberOfMessagesVisible"\n}\n',
}
REQUEST_TRACKING = {
    "cdk": "svc.scaleOnRequestCount('Req', { requestsPerTarget: 500 });\n",
    "cloudformation": {"P": {"Type": "AWS::ApplicationAutoScaling::ScalingPolicy", "Properties": {
        "TargetTrackingScalingPolicyConfiguration": {"PredefinedMetricSpecification": {
            "PredefinedMetricType": "ALBRequestCountPerTarget"}}}}},
    "terraform": 'resource "aws_appautoscaling_policy" "p" {\n  predefined_metric_type = '
                 '"ALBRequestCountPerTarget"\n}\n',
}
CPU_ALARM = {
    "cdk": "new cloudwatch.Metric({ namespace: 'AWS/EC2', metricName: 'CPUUtilization' });\n"
           "svc.scaleOnCpuUtilization('Cpu', { targetUtilizationPercent: 60 });\n",
    "cloudformation": {"A": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "MetricName": "CPUUtilization", "Namespace": "AWS/EC2"}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "a" {\n'
                 '  metric_name = "CPUUtilization"\n}\n',
}
SIGNALS = {"schedule": SCHEDULE, "queue depth": QUEUE_DEPTH, "request rate": REQUEST_TRACKING}


@pytest.mark.parametrize("source", SOURCES)
def test_compute_with_no_demand_signal_fires_repo_096(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FN[source])
    (hit,) = DemandNotAnalysed().run(tmp_path)
    assert "Lambda" in hit.evidence and "found none" in hit.evidence


@pytest.mark.parametrize("signal", SIGNALS)
@pytest.mark.parametrize("source", SOURCES)
def test_demand_signal_passes_repo_096(tmp_path: Path, source: str, signal: str) -> None:
    _stack(tmp_path, source, FN[source], SIGNALS[signal][source])
    assert DemandNotAnalysed().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_cpu_only_is_not_a_demand_signal_repo_096(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FN[source], CPU_ALARM[source])
    assert len(DemandNotAnalysed().run(tmp_path)) == 1


@pytest.mark.parametrize("path,text", (
    ("docs/demand.md", "Peak 400 requests per second on weekdays."),
    ("docs/notes.md", "# Load profile\n\nAbout 2 000 users per day, busiest at month-end.\n"),
    ("docs/capacity-plan.md", "Business hours carry most traffic."),
))
def test_demand_note_passes_repo_096(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", FN["terraform"])
    _write(tmp_path / path, text)
    assert DemandNotAnalysed().run(tmp_path) == []


def test_note_without_a_number_or_calendar_does_not_pass_repo_096(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FN["terraform"])
    _write(tmp_path / "docs/demand.md", "We should think about demand some day.")
    assert len(DemandNotAnalysed().run(tmp_path)) == 1
    _write(tmp_path / "docs/other.md", "# Setup\n\nPeak 400 requests per second.")
    assert len(DemandNotAnalysed().run(tmp_path)) == 1


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_096(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", FN["terraform"], env=env)
    assert DemandNotAnalysed().run(tmp_path) == []
    _stack(tmp_path, "terraform", FN["terraform"])
    _stack(tmp_path, "terraform", SCHEDULE["terraform"], env=env)
    assert len(DemandNotAnalysed().run(tmp_path)) == 1


def test_no_compute_is_silent_repo_096(tmp_path: Path) -> None:
    _write(tmp_path / "prod/main.tf", 'resource "aws_s3_bucket" "b" {}\n')
    assert DemandNotAnalysed().run(tmp_path) == []


def test_python_cdk_repo_096(tmp_path: Path) -> None:
    code = "_lambda.Function(self, 'Fn', runtime=r, handler='h', code=c)\n"
    _write(tmp_path / "app.py", code)
    assert len(DemandNotAnalysed().run(tmp_path)) == 1
    _write(tmp_path / "app.py", code + "t.scale_on_schedule('Peak', "
           "schedule=appscaling.Schedule.cron(hour='8'))\n")
    assert DemandNotAnalysed().run(tmp_path) == []


# REPO-097: buffer or throttle.

API = {
    "cdk": "new apigateway.RestApi(this, 'Api');\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n}\n',
}
STAGE_THROTTLE = {
    "cdk": "new apigateway.RestApi(this, 'Api', { deployOptions: { throttlingRateLimit: 100 } });\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                       "S": {"Type": "AWS::ApiGateway::Stage", "Properties": {
                           "MethodSettings": [{"ThrottlingRateLimit": 100}]}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {}\n'
                 'resource "aws_api_gateway_method_settings" "m" {\n  settings {\n'
                 '    throttling_rate_limit = 100\n  }\n}\n',
}
USAGE_PLAN = {
    "cdk": "const api = new apigateway.RestApi(this, 'Api');\napi.addUsagePlan('P');\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                       "P": {"Type": "AWS::ApiGateway::UsagePlan", "Properties": {}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {}\n'
                 'resource "aws_api_gateway_usage_plan" "p" {\n  name = "p"\n}\n',
}
WAF_RATE = {
    "cdk": "new Api(this, 'Api');\nconst r = { statement: { rateBasedStatement: { limit: 100 } } };\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                       "W": {"Type": "AWS::WAFv2::WebACL", "Properties": {"Rules": [
                           {"Statement": {"RateBasedStatement": {"Limit": 100}}}]}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {}\n'
                 'resource "aws_wafv2_web_acl" "w" {\n  rule {\n    statement {\n'
                 '      rate_based_statement {\n        limit = 100\n      }\n    }\n  }\n}\n',
}
RESERVED = {
    "cdk": "new apigateway.RestApi(this, 'Api');\n"
           "new lambda.Function(this, 'Fn', { reservedConcurrentExecutions: 20 });\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                       "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                           "ReservedConcurrentExecutions": 20}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {}\n'
                 'resource "aws_lambda_function" "fn" {\n  reserved_concurrent_executions = 20\n}\n',
}
LIMITS = {"stage throttle": STAGE_THROTTLE, "usage plan": USAGE_PLAN,
          "waf rate rule": WAF_RATE, "reserved concurrency": RESERVED}


@pytest.mark.parametrize("source", SOURCES)
def test_bare_api_fires_repo_097(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, API[source])
    (hit,) = DemandUnbuffered().run(tmp_path)
    assert "API Gateway API in prod/" in hit.evidence and "found none" in hit.evidence


@pytest.mark.parametrize("limit", LIMITS)
@pytest.mark.parametrize("source", SOURCES)
def test_throttled_api_passes_repo_097(tmp_path: Path, source: str, limit: str) -> None:
    _stack(tmp_path, source, LIMITS[limit][source])
    assert DemandUnbuffered().run(tmp_path) == []


SNS_LAMBDA = {
    "cdk": "topic.addSubscription(new subs.LambdaSubscription(fn));\n",
    "cloudformation": {"Sub": {"Type": "AWS::SNS::Subscription", "Properties": {
        "Protocol": "lambda", "Endpoint": "arn"}}},
    "terraform": 'resource "aws_sns_topic_subscription" "s" {\n  protocol = "lambda"\n}\n',
}
QUEUE = {
    "cdk": "new sqs.Queue(this, 'Q');\n",
    "cloudformation": {"Q": {"Type": "AWS::SQS::Queue", "Properties": {}}},
    "terraform": 'resource "aws_sqs_queue" "q" {}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_sns_straight_to_lambda_fires_repo_097(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SNS_LAMBDA[source])
    (hit,) = DemandUnbuffered().run(tmp_path)
    assert "SNS subscription to Lambda in prod/" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_queue_between_sns_and_lambda_passes_repo_097(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, SNS_LAMBDA[source], QUEUE[source])
    assert DemandUnbuffered().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_reserved_concurrency_passes_sns_trigger_repo_097(tmp_path: Path, source: str) -> None:
    extra = {"cdk": RESERVED["cdk"], "terraform": RESERVED["terraform"],
             "cloudformation": {"Fn": RESERVED["cloudformation"]["Fn"]}}
    _stack(tmp_path, source, SNS_LAMBDA[source], extra[source])
    assert DemandUnbuffered().run(tmp_path) == []


def test_s3_notification_to_lambda_fires_repo_097(tmp_path: Path) -> None:
    _write(tmp_path / "prod/lib/stack.ts",
           "bucket.addEventNotification(s3.EventType.OBJECT_CREATED, "
           "new s3n.LambdaDestination(fn));\n")
    assert len(DemandUnbuffered().run(tmp_path)) == 1


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_097(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", API["terraform"], env=env)
    assert DemandUnbuffered().run(tmp_path) == []


def test_no_edge_and_no_worker_is_silent_repo_097(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FN["terraform"], QUEUE["terraform"])
    assert DemandUnbuffered().run(tmp_path) == []
    (tmp_path / "prod/main.tf").unlink()
    _stack(tmp_path, "terraform", FN["terraform"])
    assert DemandUnbuffered().run(tmp_path) == []


def test_python_cdk_repo_097(tmp_path: Path) -> None:
    code = "apigateway.RestApi(self, 'Api')\n"
    _write(tmp_path / "app.py", code)
    assert len(DemandUnbuffered().run(tmp_path)) == 1
    _write(tmp_path / "app.py", "apigateway.RestApi(self, 'Api', deploy_options="
           "apigateway.StageOptions(throttling_rate_limit=100))\n")
    assert DemandUnbuffered().run(tmp_path) == []


def test_silent_on_this_repo() -> None:
    root = Path(__file__).resolve().parent.parent
    assert DemandNotAnalysed().run(root) == []
    assert DemandUnbuffered().run(root) == []


# Both rules.

def _firing(rule_id: str, root: Path) -> None:
    if rule_id == "REPO-096":
        _stack(root, "terraform", FN["terraform"])
    else:
        _stack(root, "terraform", API["terraform"])


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _firing(rule.id, tmp_path)
    (hit,) = rule.run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", text)
    assert len(rule.run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", text)
    assert rule.run(empty) == []


@pytest.mark.parametrize("rule_id,practice", (
    ("REPO-096", "COST09-BP01"), ("REPO-097", "COST09-BP02"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 9"


def test_rules_run_by_default() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == set()
    assert {r.category for r in RULES} == {"Cost"}
    assert {r.severity for r in RULES} == {"Low"}
    assert {t for r in RULES for t in r.themes} == {"finops"}


def test_cost9_is_fully_checked() -> None:
    (cost9,) = [a for a in well_architected.answers([]) if a.question.id == "COST 9"]
    assert cost9.not_checked == ()


def test_cost9_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _firing("REPO-096", tmp_path)
    findings = DemandNotAnalysed().run(tmp_path)
    (cost9,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 9"]
    assert not cost9.met
