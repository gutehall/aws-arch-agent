"""REL 6: alarms defined on workload metrics (REPO-045), logs analyzed for errors (REPO-046),
an automated response to alarms (REPO-047), and end to end tracing (REPO-048)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    AlarmMetricUndefined,
    AlarmResponseMissing,
    EndToEndTracingMissing,
    LogErrorAnalysisMissing,
    automated_responses,
    compute_tracing,
    error_log_analysis,
    incomplete_alarms,
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


def _ids(rule: object, root: Path) -> list[str]:
    return [f.id for f in rule.run(root)]  # type: ignore[attr-defined]


LAMBDA = {
    "cdk": "const fn = new lambda.Function(this, 'Fn', props);\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}

# --- REPO-045: alarms defined on workload metrics ---

CPU_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Cpu', { metric: new cloudwatch.Metric({ namespace: "
           "'AWS/EC2', metricName: 'CPUUtilization' }), threshold: 80, evaluationPeriods: 3 });\n",
    "cloudformation": {"Cpu": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/EC2", "MetricName": "CPUUtilization", "Statistic": "Average",
        "Period": 60, "EvaluationPeriods": 3, "Threshold": 80,
        "ComparisonOperator": "GreaterThanThreshold"}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "cpu" {\n  namespace = "AWS/EC2"\n'
                 '  metric_name = "CPUUtilization"\n  period = 60\n  threshold = 80\n}\n',
}
ORDERS_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Orders', { metric: new cloudwatch.Metric({ namespace: "
           "'Shop', metricName: 'OrdersFailed' }), threshold: 1, evaluationPeriods: 1 });\n",
    "cloudformation": {"Orders": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "Shop", "MetricName": "OrdersFailed", "Statistic": "Sum", "Period": 60,
        "EvaluationPeriods": 1, "Threshold": 1,
        "ComparisonOperator": "GreaterThanOrEqualToThreshold"}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "orders" {\n  namespace = "Shop"\n'
                 '  metric_name = "OrdersFailed"\n  period = 60\n  threshold = 1\n}\n',
}
EMPTY_ALARM = {
    "cloudformation": {"Empty": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "AlarmActions": [{"Ref": "Topic"}], "EvaluationPeriods": 1}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "empty" {\n  alarm_name = "empty"\n'
                 '  evaluation_periods = 1\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_host_only_alarms_fail_repo_045(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], CPU_ALARM[source])
    (finding,) = AlarmMetricUndefined().run(tmp_path)
    assert "CPUUtilization" in finding.evidence and "host metric" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_workload_metric_alarm_passes_repo_045(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], CPU_ALARM[source], ORDERS_ALARM[source])
    assert _ids(AlarmMetricUndefined(), tmp_path) == []


@pytest.mark.parametrize("source", ("cloudformation", "terraform"))
def test_empty_alarm_fails_repo_045_with_its_place(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], ORDERS_ALARM[source], EMPTY_ALARM[source])
    (finding,) = AlarmMetricUndefined().run(tmp_path)
    assert finding.file == _PATHS[source] and finding.line
    assert "no metric or threshold" in finding.evidence
    assert ("Empty" if source == "cloudformation" else "empty") in finding.evidence


def test_metric_math_and_threshold_metric_count_as_defined(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf",
           'resource "aws_cloudwatch_metric_alarm" "band" {\n'
           '  threshold_metric_id = "e1"\n  metric_query {\n    id = "e1"\n  }\n}\n')
    _write(tmp_path / "stack.yaml",
           "Resources:\n  Math:\n    Type: AWS::CloudWatch::Alarm\n    Properties:\n"
           "      Metrics: []\n      ThresholdMetricId: e1\n")
    assert incomplete_alarms(tmp_path) == []


def test_alarm_missing_only_a_threshold_is_named(tmp_path: Path) -> None:
    _write(tmp_path / "stack.yaml",
           "Resources:\n  Fn:\n    Type: AWS::Lambda::Function\n  NoLimit:\n"
           "    Type: AWS::CloudWatch::Alarm\n    Properties:\n      MetricName: Errors\n")
    ((name, rel, line, missing),) = incomplete_alarms(tmp_path)
    assert (name, rel, line, missing) == ("NoLimit", "stack.yaml", 4, "threshold")


def test_no_alarm_or_no_compute_gets_no_repo_045(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"])
    assert _ids(AlarmMetricUndefined(), tmp_path) == []
    bare = tmp_path / "bare"
    _stack(bare, "terraform", CPU_ALARM["terraform"], EMPTY_ALARM["terraform"])
    assert _ids(AlarmMetricUndefined(), bare) == []


# --- REPO-046: logs analyzed for errors ---

ERROR_FILTER = {
    "cdk": "new logs.MetricFilter(this, 'Errors', { logGroup, metricNamespace: 'App', "
           "metricName: 'Errors', filterPattern: logs.FilterPattern.anyTerm('ERROR', "
           "'Exception') });\n",
    "cloudformation": {"Errors": {"Type": "AWS::Logs::MetricFilter", "Properties": {
        "LogGroupName": "app", "FilterPattern": '{ $.level = "ERROR" }',
        "MetricTransformations": [{"MetricNamespace": "App", "MetricName": "Errors",
                                   "MetricValue": "1"}]}}},
    "terraform": 'resource "aws_cloudwatch_log_metric_filter" "errors" {\n'
                 '  name = "errors"\n  pattern = "?ERROR ?FATAL"\n'
                 '  log_group_name = "app"\n}\n',
}
ORDER_FILTER = {
    "cdk": "new logs.MetricFilter(this, 'Errors', { logGroup, metricNamespace: 'Errors', "
           "metricName: 'Orders', filterPattern: logs.FilterPattern.literal('OrderPlaced') });\n",
    "cloudformation": {"Orders": {"Type": "AWS::Logs::MetricFilter", "Properties": {
        "LogGroupName": "errors", "FilterPattern": '{ $.event = "OrderPlaced" }',
        "MetricTransformations": [{"MetricNamespace": "Errors", "MetricName": "Orders",
                                   "MetricValue": "1"}]}}},
    "terraform": 'resource "aws_cloudwatch_log_metric_filter" "orders" {\n'
                 '  name = "errors"\n  pattern = "OrderPlaced"\n'
                 '  log_group_name = "errors"\n}\n',
}
LOG_ANOMALY = {
    "cdk": "new logs.CfnLogAnomalyDetector(this, 'Anomalies', { logGroupArnList: [arn] });\n",
    "cloudformation": {"Anomalies": {"Type": "AWS::Logs::LogAnomalyDetector",
                                     "Properties": {"LogGroupArnList": ["arn"]}}},
    "terraform": 'resource "aws_cloudwatch_log_anomaly_detector" "a" {\n'
                 '  log_group_arn_list = ["arn"]\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_no_log_analysis_fails_repo_046(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source])
    (finding,) = LogErrorAnalysisMissing().run(tmp_path)
    assert finding.evidence.endswith("found none")


@pytest.mark.parametrize("source", SOURCES)
def test_error_metric_filter_passes_repo_046(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], ERROR_FILTER[source])
    assert _ids(LogErrorAnalysisMissing(), tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_non_error_metric_filter_fails_repo_046(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], ORDER_FILTER[source])
    (finding,) = LogErrorAnalysisMissing().run(tmp_path)
    assert "count no error" in finding.evidence
    assert error_log_analysis(tmp_path) == {}


@pytest.mark.parametrize("source", SOURCES)
def test_log_anomaly_detector_passes_repo_046(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], LOG_ANOMALY[source])
    assert _ids(LogErrorAnalysisMissing(), tmp_path) == []


@pytest.mark.parametrize("pattern", ['"?Exception"', '"[ip, user, status=5*, size]"',
                                     '"{ $.statusCode = 503 }"', '"level=\\"error\\""'])
def test_error_patterns_pass(tmp_path: Path, pattern: str) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"],
           'resource "aws_cloudwatch_log_metric_filter" "f" {\n'
           f'  pattern = {pattern}\n}}\n')
    assert _ids(LogErrorAnalysisMissing(), tmp_path) == []


def test_python_cdk_error_filter_passes(tmp_path: Path) -> None:
    _write(tmp_path / "app.py",
           "fn = _lambda.Function(self, 'Fn', **props)\n"
           "group.add_metric_filter('Errors', metric_namespace='App', metric_name='Errors',\n"
           "    filter_pattern=logs.FilterPattern.string_value('$.level', '=', 'ERROR'))\n")
    assert _ids(LogErrorAnalysisMissing(), tmp_path) == []


# --- REPO-047: automated response ---

SCALING = {
    "cdk": "svc.autoScaleTaskCount({ maxCapacity: 4 }).scaleOnCpuUtilization('Cpu', "
           "{ targetUtilizationPercent: 60 });\n",
    "cloudformation": {"Scale": {"Type": "AWS::ApplicationAutoScaling::ScalingPolicy",
                                 "Properties": {"PolicyType": "TargetTrackingScaling"}}},
    "terraform": 'resource "aws_appautoscaling_policy" "scale" {\n'
                 '  policy_type = "TargetTrackingScaling"\n}\n',
}
AUTOMATION_ACTION = {
    "cdk": "alarm.addAlarmAction(new actions.SsmAction(actions.OpsItemSeverity.HIGH));\n",
    "cloudformation": {"Alarm": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "MetricName": "Errors", "Threshold": 1,
        "AlarmActions": ["arn:aws:automate:eu-west-1:ec2:reboot"]}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "errors" {\n'
                 '  metric_name = "Errors"\n  threshold = 1\n'
                 '  alarm_actions = [aws_lambda_function.responder.arn]\n}\n',
}
NOTIFY_ONLY = {
    "cdk": "alarm.addAlarmAction(new actions.SnsAction(topic));\n",
    "cloudformation": {"Alarm": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "MetricName": "Errors", "Threshold": 1, "AlarmActions": [{"Ref": "Topic"}]}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "errors" {\n'
                 '  metric_name = "Errors"\n  threshold = 1\n'
                 '  alarm_actions = [aws_sns_topic.alerts.arn]\n}\n',
}
STATE_CHANGE_RULE = {
    "cdk": "new events.Rule(this, 'OnAlarm', { eventPattern: { source: ['aws.cloudwatch'], "
           "detailType: ['CloudWatch Alarm State Change'] }, targets: [new LambdaFunction(fn)] "
           "});\n",
    "cloudformation": {"OnAlarm": {"Type": "AWS::Events::Rule", "Properties": {
        "EventPattern": {"source": ["aws.cloudwatch"],
                         "detail-type": ["CloudWatch Alarm State Change"]},
        "Targets": [{"Id": "fn", "Arn": {"Fn::GetAtt": ["Fn", "Arn"]}}]}}},
    "terraform": 'resource "aws_cloudwatch_event_rule" "on_alarm" {\n'
                 '  event_pattern = jsonencode({ "detail-type" = ["CloudWatch Alarm State '
                 'Change"] })\n}\nresource "aws_cloudwatch_event_target" "fn" {\n'
                 '  rule = aws_cloudwatch_event_rule.on_alarm.name\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_notification_only_fails_repo_047(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source], NOTIFY_ONLY[source])
    assert _ids(AlarmResponseMissing(), tmp_path) == ["REPO-047"]


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("control", [SCALING, AUTOMATION_ACTION, STATE_CHANGE_RULE],
                         ids=["scaling", "action", "eventbridge"])
def test_automated_response_passes_repo_047(tmp_path: Path, source: str, control: dict) -> None:
    _stack(tmp_path, source, LAMBDA[source], control[source])
    assert automated_responses(tmp_path)
    assert _ids(AlarmResponseMissing(), tmp_path) == []


def test_state_change_rule_without_target_is_no_response(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"],
           'resource "aws_cloudwatch_event_rule" "on_alarm" {\n'
           '  event_pattern = jsonencode({ "detail-type" = ["CloudWatch Alarm State '
           'Change"] })\n}\n')
    assert _ids(AlarmResponseMissing(), tmp_path) == ["REPO-047"]


def test_no_compute_gets_no_repo_047(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", NOTIFY_ONLY["terraform"])
    assert _ids(AlarmResponseMissing(), tmp_path) == []


# --- REPO-048: end to end tracing ---

TRACED_LAMBDA = {
    "cdk": "const fn = new lambda.Function(this, 'Fn', { ...props, tracing: "
           "lambda.Tracing.ACTIVE });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function",
                              "Properties": {"TracingConfig": {"Mode": "Active"}}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n'
                 '  tracing_config {\n    mode = "Active"\n  }\n}\n',
}
REST_API = {
    "cdk": "const api = new apigateway.RestApi(this, 'Api', props);\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                       "Stage": {"Type": "AWS::ApiGateway::Stage",
                                 "Properties": {"StageName": "prod"}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n}\n'
                 'resource "aws_api_gateway_stage" "prod" {\n  stage_name = "prod"\n}\n',
}
TRACED_REST_API = {
    "cdk": "const api = new apigateway.RestApi(this, 'Api', { deployOptions: "
           "{ tracingEnabled: true } });\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
                       "Stage": {"Type": "AWS::ApiGateway::Stage",
                                 "Properties": {"StageName": "prod", "TracingEnabled": True}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n}\n'
                 'resource "aws_api_gateway_stage" "prod" {\n  stage_name = "prod"\n'
                 '  xray_tracing_enabled = true\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_untraced_compute_fails_repo_048(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LAMBDA[source])
    (finding,) = EndToEndTracingMissing().run(tmp_path)
    assert "no compute is traced" in finding.evidence
    assert "REST API" not in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_traced_compute_passes_repo_048(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, TRACED_LAMBDA[source])
    assert _ids(EndToEndTracingMissing(), tmp_path) == []


def test_cloudformation_tracing_config_passes_repo_048(tmp_path: Path) -> None:
    _write(tmp_path / "template.yaml",
           "Transform: AWS::Serverless-2016-10-31\nGlobals:\n  Function:\n    Tracing: Active\n"
           "Resources:\n  Fn:\n    Type: AWS::Serverless::Function\n")
    assert _ids(EndToEndTracingMissing(), tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_untraced_rest_stage_fails_repo_048(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, TRACED_LAMBDA[source], REST_API[source])
    (finding,) = EndToEndTracingMissing().run(tmp_path)
    assert "REST API" in finding.evidence and "no compute is traced" not in finding.evidence
    assert finding.file == _PATHS[source]


@pytest.mark.parametrize("source", SOURCES)
def test_traced_rest_stage_passes_repo_048(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, TRACED_LAMBDA[source], TRACED_REST_API[source])
    assert _ids(EndToEndTracingMissing(), tmp_path) == []


def test_http_api_is_not_judged_and_both_gaps_are_named(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", TRACED_LAMBDA["terraform"],
           'resource "aws_apigatewayv2_api" "http" {\n  protocol_type = "HTTP"\n}\n')
    assert _ids(EndToEndTracingMissing(), tmp_path) == []
    both = tmp_path / "both"
    _stack(both, "terraform", LAMBDA["terraform"], REST_API["terraform"])
    (finding,) = EndToEndTracingMissing().run(both)
    assert "no compute is traced" in finding.evidence and "REST API" in finding.evidence


@pytest.mark.parametrize(("rel", "text"), [
    ("task.tf", 'resource "aws_ecs_service" "svc" {}\nimage = "amazon/aws-xray-daemon:3.3.12"\n'),
    ("src/handler.py", "from aws_lambda_powertools import Tracer\n"),
    ("package.json", '{"dependencies": {"@opentelemetry/auto-instrumentations-node": "1"}}'),
])
def test_collector_and_sdk_count_as_tracing(tmp_path: Path, rel: str, text: str) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"])
    _write(tmp_path / rel, text)
    assert compute_tracing(tmp_path)
    assert _ids(EndToEndTracingMissing(), tmp_path) == []


# --- self-match, mapping, and the REL 6 answer ---

_RULES = (AlarmMetricUndefined, LogErrorAnalysisMissing, AlarmResponseMissing,
          EndToEndTracingMissing)
_ALL = ["REPO-045", "REPO-046", "REPO-047", "REPO-048"]


def test_saved_reports_quoting_the_findings_neither_pass_nor_fire(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", LAMBDA["terraform"], CPU_ALARM["terraform"],
           ORDER_FILTER["terraform"], REST_API["terraform"])
    hits = [f for rule in _RULES for f in rule().run(tmp_path)]
    assert sorted(f.id for f in hits) == _ALL
    # Evidence and recommendations name every control; a saved report must not pass them.
    report = json.dumps({"findings": [h.model_dump() for h in hits]})
    markdown = "\n".join(f"- {h.title}: {h.evidence}. {h.recommendation}" for h in hits)
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", markdown)
    assert sorted(f.id for rule in _RULES for f in rule().run(tmp_path)) == _ALL
    # Nor does a saved report on its own, with no compute, fire anything.
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", markdown)
    assert [f for rule in _RULES for f in rule().run(empty)] == []


def test_rule_text_matches_no_control(tmp_path: Path) -> None:
    """The rules' own words, saved as code, pass no control and declare nothing."""
    words = "\n".join(f"{r.title}\n{r.recommendation}" for r in (rule() for rule in _RULES))
    _stack(tmp_path, "terraform", LAMBDA["terraform"])
    _write(tmp_path / "notes.ts", words)
    assert sorted(f.id for rule in _RULES for f in rule().run(tmp_path)) == [
        "REPO-046", "REPO-047", "REPO-048"]
    assert error_log_analysis(tmp_path) == {}
    assert automated_responses(tmp_path) == {}
    assert compute_tracing(tmp_path) == {}


def test_rules_map_to_rel6_and_run_by_default() -> None:
    assert well_architected.best_practices_of("REPO-045") == ("REL06-BP02",)
    assert well_architected.best_practices_of("REPO-046") == ("REL06-BP05",)
    assert well_architected.best_practices_of("REPO-047") == ("REL06-BP04",)
    assert well_architected.best_practices_of("REPO-048") == ("REL06-BP07",)
    assert not set(_ALL) & set(ORG_RULE_IDS)
    for rule in _RULES:
        assert rule.category == "Reliability" and rule.themes == ("observability",)


def test_rel6_reads_one_answer_with_every_best_practice_checked() -> None:
    (rel6,) = [a for a in well_architected.answers([]) if a.question.id == "REL 6"]
    # One answer: with no finding every best practice is checked and the answer is met.
    assert rel6.not_checked == () and rel6.met
    hit = AlarmResponseMissing()._finding("no automated response")
    (failing,) = [a for a in well_architected.answers([hit]) if a.question.id == "REL 6"]
    assert not failing.met and [f.id for f in failing.findings] == ["REPO-047"]
