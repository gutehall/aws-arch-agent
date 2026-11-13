"""OPS 8: alarms watch workload metrics (REPO-027), logs are analyzed (REPO-028), traces are
analyzed (REPO-029), and dashboards show workload metrics (REPO-030)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    DashboardWorkloadMetricMissing,
    LogAnalysisMissing,
    TraceAnalysisMissing,
    WorkloadAlarmMissing,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

RULES = ("REPO-027", "REPO-028", "REPO-029")
OPS8 = {"OPS08-BP01", "OPS08-BP02", "OPS08-BP03", "OPS08-BP04", "OPS08-BP05"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _cf_alarm(namespace: str, metric: str, dimensions: list | None = None) -> dict:
    props = {"Namespace": namespace, "MetricName": metric, "Statistic": "Sum", "Period": 60,
             "EvaluationPeriods": 1, "Threshold": 1,
             "ComparisonOperator": "GreaterThanOrEqualToThreshold"}
    if dimensions:
        props["Dimensions"] = dimensions
    return {"Type": "AWS::CloudWatch::Alarm", "Properties": props}


def _cf_dashboard(*metrics: list) -> dict:
    body = {"widgets": [{"type": "metric", "properties": {"metrics": list(metrics)}}]}
    return {"Type": "AWS::CloudWatch::Dashboard",
            "Properties": {"DashboardBody": json.dumps(body)}}


_CF_BASE = {
    "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
        "Runtime": "python3.12", "Handler": "app.handler", "Role": "arn:aws:iam::1:role/r",
        "TracingConfig": {"Mode": "Active"},
        "Code": {"ZipFile": "def handler(e, c): pass"}}},
}
_CF_CONTROLS = {
    "REPO-027": {
        "kpi alarm": {"Orders": _cf_alarm("Shop", "OrdersPlaced")},
        "edge alarm": {"Errors": _cf_alarm("AWS/ApiGateway", "5XXError")},
        "dependency alarm": {"Age": _cf_alarm("AWS/SQS", "ApproximateAgeOfOldestMessage")},
        "anomaly detector": {"Band": {"Type": "AWS::CloudWatch::AnomalyDetector", "Properties": {
            "Namespace": "AWS/Lambda", "MetricName": "Invocations", "Stat": "Sum"}}},
    },
    "REPO-028": {
        "metric filter": {"Errors": {"Type": "AWS::Logs::MetricFilter", "Properties": {
            "LogGroupName": "/shop/app", "FilterPattern": "ERROR",
            "MetricTransformations": [{"MetricNamespace": "Shop",
                                       "MetricName": "Errors", "MetricValue": "1"}]}}},
        "contributor insights": {"Top": {"Type": "AWS::CloudWatch::InsightRule", "Properties": {
            "RuleName": "top-callers", "RuleState": "ENABLED", "RuleBody": "{}"}}},
        "saved query": {"Q": {"Type": "AWS::Logs::QueryDefinition", "Properties": {
            "Name": "errors", "QueryString": "fields @message | filter level = 'ERROR'"}}},
        "log anomaly detector": {"A": {"Type": "AWS::Logs::LogAnomalyDetector",
                                       "Properties": {"LogGroupArnList": ["arn"]}}},
        "subscription filter": {"S": {"Type": "AWS::Logs::SubscriptionFilter", "Properties": {
            "LogGroupName": "/shop/app", "FilterPattern": "", "DestinationArn": "arn"}}},
    },
    "REPO-029": {
        "xray group": {"G": {"Type": "AWS::XRay::Group", "Properties": {
            "GroupName": "checkout", "FilterExpression": "service(\"checkout\")"}}},
        "sampling rule": {"R": {"Type": "AWS::XRay::SamplingRule", "Properties": {}}},
        "slo": {"Slo": {"Type": "AWS::ApplicationSignals::ServiceLevelObjective",
                        "Properties": {"Name": "checkout-latency"}}},
        "discovery": {"D": {"Type": "AWS::ApplicationSignals::Discovery", "Properties": {}}},
        "signals alarm": {"Fault": _cf_alarm("ApplicationSignals", "Fault")},
    },
}

_TF_BASE = '''
resource "aws_lambda_function" "fn" {
  function_name = "shop"
  runtime       = "python3.12"
  handler       = "app.handler"
  role          = aws_iam_role.fn.arn
  tracing_config {
    mode = "Active"
  }
}
'''


def _tf_alarm(namespace: str, metric: str) -> str:
    return (
        f'resource "aws_cloudwatch_metric_alarm" "a" {{\n  namespace = "{namespace}"\n'
        f'  metric_name = "{metric}"\n  statistic = "Sum"\n  period = 60\n'
        '  evaluation_periods = 1\n  threshold = 1\n'
        '  comparison_operator = "GreaterThanOrEqualToThreshold"\n}\n'
    )


def _tf_dashboard(*metrics: str) -> str:
    rows = ", ".join(metrics)
    return (
        'resource "aws_cloudwatch_dashboard" "ops" {\n  dashboard_name = "ops"\n'
        '  dashboard_body = jsonencode({\n    widgets = [{\n      type = "metric"\n'
        f'      properties = {{\n        metrics = [{rows}]\n      }}\n    }}]\n  }})\n}}\n'
    )


_TF_CONTROLS = {
    "REPO-027": {
        "kpi alarm": _tf_alarm("Shop", "OrdersPlaced"),
        "edge alarm": _tf_alarm("AWS/ApplicationELB", "TargetResponseTime"),
        "dependency alarm": _tf_alarm("AWS/DynamoDB", "ThrottledRequests"),
        "anomaly band": (
            'resource "aws_cloudwatch_metric_alarm" "band" {\n'
            '  comparison_operator = "GreaterThanUpperThreshold"\n'
            '  threshold_metric_id = "e1"\n  evaluation_periods = 2\n'
            '  metric_query {\n    id = "e1"\n'
            '    expression = "ANOMALY_DETECTION_BAND(m1)"\n  }\n'
            '  metric_query {\n    id = "m1"\n    return_data = true\n    metric {\n'
            '      namespace = "AWS/Lambda"\n      metric_name = "Invocations"\n'
            '      period = 60\n      stat = "Sum"\n    }\n  }\n}\n'),
    },
    "REPO-028": {
        "metric filter": (
            'resource "aws_cloudwatch_log_metric_filter" "errors" {\n  name = "errors"\n'
            '  log_group_name = "/shop/app"\n  pattern = "ERROR"\n'
            '  metric_transformation {\n    name = "Errors"\n    namespace = "Shop"\n'
            '    value = "1"\n  }\n}\n'),
        "contributor insights": (
            'resource "aws_cloudwatch_contributor_insight_rule" "top" {\n'
            '  rule_name = "top"\n  rule_state = "ENABLED"\n  rule_definition = "{}"\n}\n'),
        "saved query": (
            'resource "aws_cloudwatch_query_definition" "errors" {\n  name = "errors"\n'
            '  query_string = "fields @message"\n}\n'),
        "log anomaly detector": (
            'resource "aws_cloudwatch_log_anomaly_detector" "a" {\n'
            '  log_group_arn_list = [aws_cloudwatch_log_group.app.arn]\n}\n'),
        "subscription filter": (
            'resource "aws_cloudwatch_log_subscription_filter" "ship" {\n  name = "ship"\n'
            '  log_group_name = "/shop/app"\n  filter_pattern = ""\n'
            '  destination_arn = aws_kinesis_firehose_delivery_stream.logs.arn\n}\n'),
    },
    "REPO-029": {
        "xray group": (
            'resource "aws_xray_group" "checkout" {\n  group_name = "checkout"\n'
            '  filter_expression = "responsetime > 5"\n'
            '  insights_configuration {\n    insights_enabled = true\n  }\n}\n'),
        "sampling rule": (
            'resource "aws_xray_sampling_rule" "checkout" {\n  rule_name = "checkout"\n'
            '  priority = 1\n  fixed_rate = 0.1\n}\n'),
        "slo": (
            'resource "aws_applicationsignals_service_level_objective" "latency" {\n'
            '  name = "checkout-latency"\n}\n'),
        "xray alarm": _tf_alarm("AWS/X-Ray", "ApproximateTraceCount"),
    },
}

_CDK_BASE = (
    "const fn = new lambda.Function(this, 'Fn', { runtime, handler: 'app.handler', code,\n"
    "  tracing: lambda.Tracing.ACTIVE });\n"
)
_CDK_CONTROLS = {
    "REPO-027": {
        "kpi alarm": (
            "new cloudwatch.Alarm(this, 'Orders', { metric: new cloudwatch.Metric({\n"
            "  namespace: 'Shop', metricName: 'OrdersPlaced' }), threshold: 1,\n"
            "  evaluationPeriods: 1 });\n"),
        "edge alarm": "api.metricLatency().createAlarm(this, 'Slow', { threshold: 1000, "
                      "evaluationPeriods: 3 });\n",
        "dependency alarm": (
            "queue.metricApproximateAgeOfOldestMessage().createAlarm(this, 'Age', {\n"
            "  threshold: 300, evaluationPeriods: 1 });\n"),
        "anomaly band": (
            "new cloudwatch.Alarm(this, 'Band', { metric: new cloudwatch.MathExpression({\n"
            "  expression: 'ANOMALY_DETECTION_BAND(m1, 2)', usingMetrics: { m1 } }),\n"
            "  threshold: 0, evaluationPeriods: 2 });\n"),
    },
    "REPO-028": {
        "metric filter": (
            "logGroup.addMetricFilter('Errors', { metricNamespace: 'Shop',\n"
            "  metricName: 'Errors', filterPattern: logs.FilterPattern.literal('ERROR') });\n"),
        "contributor insights": (
            "new cloudwatch.CfnInsightRule(this, 'Top', { ruleName: 'top',\n"
            "  ruleState: 'ENABLED', ruleBody });\n"),
        "saved query": (
            "new logs.QueryDefinition(this, 'Errors', { queryDefinitionName: 'errors',\n"
            "  queryString });\n"),
        "subscription filter": (
            "new logs.SubscriptionFilter(this, 'Ship', { logGroup, destination,\n"
            "  filterPattern: logs.FilterPattern.allEvents() });\n"),
    },
    "REPO-029": {
        "xray group": (
            "new xray.CfnGroup(this, 'Checkout', { groupName: 'checkout',\n"
            "  insightsConfiguration: { insightsEnabled: true } });\n"),
        "sampling rule": "new xray.CfnSamplingRule(this, 'Rule', { samplingRule });\n",
        "slo": (
            "new applicationsignals.CfnServiceLevelObjective(this, 'Slo', {\n"
            "  name: 'checkout-latency', sli });\n"),
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


def _scan(root: Path, iac: dict[str, str]) -> tuple:
    # IaC under prod/: the pytest directory name says "test", which reads as a dev stack.
    for rel, text in iac.items():
        _write(root / "prod" / rel, text)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return ctx, findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_ops8() -> None:
    assert RULE_BEST_PRACTICES["REPO-027"] == ("OPS08-BP01", "OPS08-BP04")
    assert RULE_BEST_PRACTICES["REPO-028"] == ("OPS08-BP02",)
    assert RULE_BEST_PRACTICES["REPO-029"] == ("OPS08-BP03",)
    assert RULE_BEST_PRACTICES["REPO-030"] == ("OPS08-BP05",)
    assert OPS8.isdisjoint(NOT_CHECKED)


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_no_analysis_fails_ops8(tmp_path: Path, source: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source]())
    assert ctx.source == source
    hits = [_found(findings, rule_id) for rule_id in RULES]
    assert all(len(hit) == 1 for hit in hits)
    alarms, logs, traces = (hit[0] for hit in hits)
    for hit in (alarms, logs, traces):
        assert hit.question == "OPS 8"
        assert hit.category == "Operational Excellence"
        assert hit.file is None
        assert hit.evidence.startswith("Runs Lambda (prod/")
    assert (alarms.severity, logs.severity, traces.severity) == ("Medium", "Low", "Low")
    assert alarms.evidence.endswith("found no CloudWatch alarm")
    assert logs.evidence.endswith("found none")
    assert traces.evidence.endswith("found none")  # active tracing alone is not analysis
    assert not _found(findings, "REPO-030")  # no dashboard: OPS-021 and CF-DASH-001
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    assert not answer["OPS 8"].met


@pytest.mark.parametrize(("source", "rule_id", "kind"), _CASES)
def test_iac_control_passes(tmp_path: Path, source: str, rule_id: str, kind: str) -> None:
    ctx, findings = _scan(tmp_path, _BUILDERS[source](_CONTROLS[source][rule_id][kind]))
    assert ctx.source == source
    assert not _found(findings, rule_id)


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_cpu_only_alarms_fire(tmp_path: Path, source: str) -> None:
    alarm = {
        "cdk": "service.metricCpuUtilization().createAlarm(this, 'Cpu', { threshold: 80, "
               "evaluationPeriods: 3 });\n",
        "cloudformation": {"Cpu": _cf_alarm("AWS/EC2", "CPUUtilization")},
        "terraform": _tf_alarm("AWS/EC2", "CPUUtilization"),
    }[source]
    _ctx, findings = _scan(tmp_path, _BUILDERS[source](alarm))  # type: ignore[operator]
    (hit,) = _found(findings, "REPO-027")
    name = "metricCpuUtilization" if source == "cdk" else "CPUUtilization"
    assert f"watch only infrastructure metrics ({name})" in hit.evidence


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_lambda_metric_alarm_is_not_a_workload_metric(tmp_path: Path, source: str) -> None:
    alarm = {
        "cdk": "fn.metricErrors().createAlarm(this, 'Errors', { threshold: 1, "
               "evaluationPeriods: 1 });\n",
        "cloudformation": {"Errors": _cf_alarm("AWS/Lambda", "Errors")},
        "terraform": _tf_alarm("AWS/Lambda", "Errors"),
    }[source]
    _ctx, findings = _scan(tmp_path, _BUILDERS[source](alarm))  # type: ignore[operator]
    (hit,) = _found(findings, "REPO-027")
    assert "watch no workload metric" in hit.evidence


_CPU = '["AWS/EC2", "CPUUtilization", "InstanceId", "i-1"]'
_DASHBOARDS = {
    "cloudformation": (
        lambda *rows: {"Ops": _cf_dashboard(*[json.loads(r) for r in rows])}),
    "terraform": lambda *rows: _tf_dashboard(*rows),
    "cdk": lambda *rows: (
        "new cloudwatch.Dashboard(this, 'Ops', { widgets: [[new cloudwatch.GraphWidget({\n"
        f"  left: [{', '.join(rows)}] }})]] }});\n"),
}
_WORKLOAD_ROWS = {
    "cloudformation": ['["Shop", "OrdersPlaced"]', '["AWS/SQS", "ApproximateAgeOfOldestMessage"]',
                       '["AWS/ApiGateway", "5XXError", "ApiName", "shop"]',
                       '["ApplicationSignals", "Latency"]'],
    "terraform": ['["Shop", "OrdersPlaced"]', '["AWS/DynamoDB", "ThrottledRequests"]',
                  '["AWS/ApplicationELB", "TargetResponseTime"]'],
    "cdk": ["new cloudwatch.Metric({ namespace: 'Shop', metricName: 'OrdersPlaced' })",
            "queue.metricApproximateAgeOfOldestMessage()", "api.metricLatency()"],
}
_CDK_CPU = "service.metricCpuUtilization()"
_DASH_CASES = [(s, row) for s in _SOURCE_IDS for row in _WORKLOAD_ROWS[s]]


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_cpu_only_dashboard_fires(tmp_path: Path, source: str) -> None:
    cpu = _CDK_CPU if source == "cdk" else _CPU
    _ctx, findings = _scan(tmp_path, _BUILDERS[source](_DASHBOARDS[source](cpu)))
    (hit,) = _found(findings, "REPO-030")
    assert hit.question == "OPS 8"
    assert hit.severity == "Low"
    assert hit.evidence.startswith("The CloudWatch dashboards in prod/")
    assert "show only infrastructure metrics" in hit.evidence


@pytest.mark.parametrize(("source", "row"), _DASH_CASES)
def test_dashboard_with_workload_metric_passes(tmp_path: Path, source: str, row: str) -> None:
    cpu = _CDK_CPU if source == "cdk" else _CPU
    _ctx, findings = _scan(tmp_path, _BUILDERS[source](_DASHBOARDS[source](cpu, row)))
    assert not _found(findings, "REPO-030")


def test_cfn_yaml_sub_dashboard_body(tmp_path: Path) -> None:
    template = (
        "Resources:\n  Fn:\n    Type: AWS::Lambda::Function\n    Properties:\n"
        "      Handler: app.handler\n  Ops:\n    Type: AWS::CloudWatch::Dashboard\n"
        "    Properties:\n      DashboardBody: !Sub |\n"
        '        {"widgets": [{"type": "metric", "properties": {"region": "${AWS::Region}",\n'
        '          "metrics": [["AWS/EC2", "CPUUtilization", "InstanceId", "i-1"]]}}]}\n'
    )
    _write(tmp_path / "prod" / "template.yaml", template)
    assert DashboardWorkloadMetricMissing().run(tmp_path)
    _write(tmp_path / "prod" / "template.yaml", template.replace(
        '["AWS/EC2", "CPUUtilization", "InstanceId", "i-1"]', '["Shop", "OrdersPlaced"]'))
    assert not DashboardWorkloadMetricMissing().run(tmp_path)


def test_unreadable_dashboard_is_not_judged(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF_BASE + (
        'resource "aws_cloudwatch_dashboard" "ops" {\n  dashboard_name = "ops"\n'
        '  dashboard_body = file("${path.module}/dashboard.json")\n}\n'))
    assert not DashboardWorkloadMetricMissing().run(tmp_path)


def test_no_compute_no_finding(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "t.json",
           _cfn({"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}))
    for rule in (WorkloadAlarmMissing(), LogAnalysisMissing(), TraceAnalysisMissing(),
                 DashboardWorkloadMetricMissing()):
        assert not rule.run(tmp_path)


def test_controls_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF_BASE)
    _write(tmp_path / "tests" / "monitoring.tf",
           _TF_CONTROLS["REPO-027"]["kpi alarm"] + _TF_CONTROLS["REPO-028"]["metric filter"]
           + _TF_CONTROLS["REPO-029"]["xray group"])
    assert WorkloadAlarmMissing().run(tmp_path)
    assert LogAnalysisMissing().run(tmp_path)
    assert TraceAnalysisMissing().run(tmp_path)


def test_saved_report_neither_passes_nor_fires(tmp_path: Path) -> None:
    # A report saved in the repo quotes the findings and the controls; it is not IaC.
    _write(tmp_path / "prod" / "main.tf", _TF_BASE + _tf_alarm("AWS/EC2", "CPUUtilization")
           + _tf_dashboard(_CPU))
    rules = (WorkloadAlarmMissing(), LogAnalysisMissing(), TraceAnalysisMissing(),
             DashboardWorkloadMetricMissing())
    hits = [hit for rule in rules for hit in rule.run(tmp_path)]
    assert len(hits) == 4
    quoted = [
        'resource "aws_cloudwatch_metric_alarm" namespace = "Shop" OrdersPlaced',
        "AWS::Logs::MetricFilter AWS::CloudWatch::InsightRule AWS::Logs::SubscriptionFilter",
        "AWS::XRay::Group aws_xray_sampling_rule AWS::ApplicationSignals::Discovery",
        'AWS::CloudWatch::Dashboard metrics: [["Shop", "OrdersPlaced"]]',
    ]
    report = {"findings": [
        {"title": hit.title, "evidence": hit.evidence, "recommendation": hit.recommendation}
        for hit in hits
    ] + [{"evidence": text} for text in quoted]}
    _write(tmp_path / "report.json", json.dumps(report, indent=2))
    for rule in rules:
        assert rule.run(tmp_path), f"{rule.id} passed on a saved report"
    # The report alone, with no IaC, fires nothing.
    (tmp_path / "prod" / "main.tf").unlink()
    for rule in rules:
        assert not rule.run(tmp_path), f"{rule.id} fired on a saved report"


def test_all_controls_answer_ops8(tmp_path: Path) -> None:
    # CDK: OPS-010 and OPS-021 read the CDK code for an alarm and a dashboard, so OPS 8 is met
    # when every OPS 8 rule passes.
    controls = _CDK_CONTROLS
    stack = _CDK_BASE + "".join([
        controls["REPO-027"]["kpi alarm"], controls["REPO-028"]["metric filter"],
        controls["REPO-029"]["xray group"],
        _DASHBOARDS["cdk"](_CDK_CPU, _WORKLOAD_ROWS["cdk"][0]),
    ])
    ctx, findings = _scan(tmp_path, {"lib/stack.ts": stack, "package.json": "{}"})
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    ops8 = answer["OPS 8"]
    assert not [f for f in findings if f.question == "OPS 8"], [
        f.id for f in findings if f.question == "OPS 8"]
    assert not OPS8 & set(ops8.not_checked)
    assert ops8.met
