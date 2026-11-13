"""COST 3: monitoring cost and usage. A detailed cost source (REPO-069), cost attribution
tags or categories (REPO-070), a unit-cost organization metric (REPO-071), and costs
allocated through workload metrics (REPO-072)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    CostAttributionTagMissing,
    CostNotAllocatedByWorkload,
    CostReportMissing,
    UnitCostMetricMissing,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


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


FUNCTION = {
    "cdk": "const fn = new lambda.Function(this, 'Fn', { runtime, handler, code });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}
BUCKET = {
    "cdk": "new s3.Bucket(this, 'Data');\n",
    "cloudformation": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}},
    "terraform": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n',
}

# REPO-069: a Cost and Usage Report or data export.

CUR = {
    "cdk": "new cur.CfnReportDefinition(this, 'Cur', { reportName: 'cur', timeUnit: 'HOURLY' });\n",
    "cloudformation": {"Cur": {"Type": "AWS::CUR::ReportDefinition", "Properties": {
        "ReportName": "cur", "TimeUnit": "HOURLY"}}},
    "terraform": 'resource "aws_cur_report_definition" "cur" {\n  report_name = "cur"\n'
                 '  time_unit   = "HOURLY"\n}\n',
}
EXPORT = {
    "cdk": "new bcmdataexports.CfnExport(this, 'Export', { export: exportProps });\n",
    "cloudformation": {"Export": {"Type": "AWS::BCMDataExports::Export", "Properties": {}}},
    "terraform": 'resource "aws_bcmdataexports_export" "cur2" {\n  export {\n'
                 '    name = "cur2"\n  }\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_workload_with_no_cost_report_fires_repo_069(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    (hit,) = CostReportMissing().run(tmp_path)
    assert hit.id == "REPO-069"
    assert "S3 bucket" in hit.evidence


@pytest.mark.parametrize("report", (CUR, EXPORT), ids=("cur", "data-export"))
@pytest.mark.parametrize("source", SOURCES)
def test_cost_report_passes_repo_069(tmp_path: Path, source: str, report: dict) -> None:
    _stack(tmp_path, source, BUCKET[source], report[source])
    assert CostReportMissing().run(tmp_path) == []


def test_cost_report_in_another_stack_passes_repo_069(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FUNCTION["terraform"])
    _write(tmp_path / "billing" / "cur.tf", CUR["terraform"])
    assert CostReportMissing().run(tmp_path) == []


def test_no_workload_passes_repo_069(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", 'variable "region" {}\n')
    assert CostReportMissing().run(tmp_path) == []


def test_python_cdk_cost_report_repo_069(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py", "s3.Bucket(self, 'Data')\n")
    assert CostReportMissing().run(tmp_path)
    _write(tmp_path / "prod" / "billing.py",
           "aws_cur.CfnReportDefinition(self, 'Cur', report_name='cur', time_unit='HOURLY')\n")
    assert CostReportMissing().run(tmp_path) == []


# REPO-070: a cost attribution tag or a cost category.

COST_TAG = {
    "cdk": "Tags.of(app).add('CostCenter', 'cc-1234');\n",
    "cloudformation": {"Tagged": {"Type": "AWS::SQS::Queue", "Properties": {
        "Tags": [{"Key": "CostCenter", "Value": "cc-1234"}]}}},
    "terraform": 'provider "aws" {\n  default_tags {\n    tags = {\n'
                 '      cost-center = "cc-1234"\n    }\n  }\n}\n',
}
OTHER_TAGS = {
    "cdk": "Tags.of(app).add('Owner', 'team-a');\nTags.of(app).add('Environment', 'prod');\n",
    "cloudformation": {"Tagged": {"Type": "AWS::SQS::Queue", "Properties": {
        "Tags": [{"Key": "Owner", "Value": "team-a"}, {"Key": "Name", "Value": "q"}]}}},
    "terraform": 'provider "aws" {\n  default_tags {\n    tags = {\n'
                 '      Owner       = "team-a"\n      Environment = "prod"\n    }\n  }\n}\n',
}
COST_CATEGORY = {
    "cdk": "new ce.CfnCostCategory(this, 'Teams', { name: 'teams', ruleVersion, rules });\n",
    "cloudformation": {"Teams": {"Type": "AWS::CE::CostCategory", "Properties": {
        "Name": "teams"}}},
    "terraform": 'resource "aws_ce_cost_category" "teams" {\n  name = "teams"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_no_cost_tag_fires_repo_070(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source], OTHER_TAGS[source])
    (hit,) = CostAttributionTagMissing().run(tmp_path)
    assert hit.id == "REPO-070"
    assert "CostCenter" in hit.evidence


@pytest.mark.parametrize("extra", (COST_TAG, COST_CATEGORY), ids=("tag", "cost-category"))
@pytest.mark.parametrize("source", SOURCES)
def test_cost_tag_or_category_passes_repo_070(tmp_path: Path, source: str, extra: dict) -> None:
    _stack(tmp_path, source, BUCKET[source], extra[source])
    assert CostAttributionTagMissing().run(tmp_path) == []


@pytest.mark.parametrize("key", ("cost_center", "CostCentre", "business-unit", "PROJECT",
                                 "Product", "CostCategory"))
def test_cost_tag_keys_ignore_case_repo_070(tmp_path: Path, key: str) -> None:
    _stack(tmp_path, "cloudformation", BUCKET["cloudformation"], {"Q": {
        "Type": "AWS::SQS::Queue", "Properties": {"Tags": [{"Key": key, "Value": "x"}]}}})
    assert CostAttributionTagMissing().run(tmp_path) == []


def test_cfn_yaml_cost_tag_repo_070(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.yaml",
           "Resources:\n  Data:\n    Type: AWS::S3::Bucket\n    Properties:\n"
           "      Tags:\n        - Key: Owner\n          Value: team-a\n")
    assert CostAttributionTagMissing().run(tmp_path)
    _write(tmp_path / "prod" / "stack.yaml",
           "Resources:\n  Data:\n    Type: AWS::S3::Bucket\n    Properties:\n"
           "      Tags:\n        - Key: BusinessUnit\n          Value: retail\n")
    assert CostAttributionTagMissing().run(tmp_path) == []


def test_python_cdk_cost_tag_repo_070(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "s3.Bucket(self, 'Data')\nTags.of(app).add('Owner', 'team-a')\n")
    assert CostAttributionTagMissing().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py",
           "s3.Bucket(self, 'Data')\nTags.of(app).add('CostCenter', 'cc-1234')\n")
    assert CostAttributionTagMissing().run(tmp_path) == []


# REPO-071: a unit-cost metric named in a metric-name position.

UNIT_COST_METRIC = {
    "cdk": "new cloudwatch.Metric({ namespace: 'Shop', metricName: 'CostPerOrder' });\n",
    "cloudformation": {"Unit": {"Type": "AWS::Logs::MetricFilter", "Properties": {
        "FilterPattern": "{ $.cost = * }", "LogGroupName": "app",
        "MetricTransformations": [{"MetricName": "cost_per_request",
                                   "MetricNamespace": "Shop", "MetricValue": "$.cost"}]}}},
    "terraform": 'resource "aws_cloudwatch_log_metric_filter" "unit" {\n'
                 '  name    = "unit"\n  pattern = "{ $.cost = * }"\n'
                 '  metric_transformation {\n    name      = "UnitCost"\n'
                 '    namespace = "Shop"\n    value     = "$.cost"\n  }\n}\n',
}
COST_WORDS_ELSEWHERE = {
    "cdk": "// TODO: publish CostPerRequest\nconst label = 'cost per request';\n",
    "cloudformation": {"Q": {"Type": "AWS::SQS::Queue", "Properties": {
        "QueueName": "CostPerRequest"}}},
    "terraform": '# metric_name = "CostPerRequest" later\nlocals {\n'
                 '  doc = "CostPerRequest"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_no_unit_cost_metric_fires_repo_071(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FUNCTION[source], COST_WORDS_ELSEWHERE[source])
    _write(tmp_path / "README.md", "We track CostPerRequest: MetricName: CostPerRequest\n")
    (hit,) = UnitCostMetricMissing().run(tmp_path)
    assert hit.id == "REPO-071"
    assert "Lambda" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_unit_cost_metric_passes_repo_071(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FUNCTION[source], UNIT_COST_METRIC[source])
    assert UnitCostMetricMissing().run(tmp_path) == []


def test_no_compute_passes_repo_071(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    assert UnitCostMetricMissing().run(tmp_path) == []


@pytest.mark.parametrize("code", (
    "metrics.add_metric(name='CostPerTenant', unit=MetricUnit.Count, value=cost)\n",
    "cloudwatch.MathExpression(expression='c / r', label='CostPerRequest', using_metrics=m)\n",
    '{"_aws": {"CloudWatchMetrics": [{"Namespace": "Shop", '
    '"Metrics": [{"Name": "CostPerOrder"}]}]}}\n',
), ids=("powertools", "math-label", "emf"))
def test_python_unit_cost_metric_repo_071(tmp_path: Path, code: str) -> None:
    _write(tmp_path / "prod" / "stack.py", "_lambda.Function(self, 'Fn', runtime=r)\n")
    assert UnitCostMetricMissing().run(tmp_path)
    _write(tmp_path / "prod" / "metrics.py", code)
    assert UnitCostMetricMissing().run(tmp_path) == []


# REPO-072: metric math over a cost metric and a workload metric.

COST_MATH = {
    "cdk": "new cloudwatch.MathExpression({ expression: 'cost / requests', usingMetrics: {\n"
           "  cost: new cloudwatch.Metric({ namespace: 'AWS/Billing', "
           "metricName: 'EstimatedCharges' }),\n  requests: fn.metricInvocations() } });\n",
    "cloudformation": {"PerCall": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Threshold": 1, "Metrics": [
            {"Id": "e1", "Expression": "cost / calls", "ReturnData": True},
            {"Id": "cost", "ReturnData": False, "MetricStat": {"Metric": {
                "Namespace": "AWS/Billing", "MetricName": "EstimatedCharges"},
                "Period": 21600, "Stat": "Maximum"}},
            {"Id": "calls", "ReturnData": False, "MetricStat": {"Metric": {
                "Namespace": "AWS/Lambda", "MetricName": "Invocations"},
                "Period": 21600, "Stat": "Sum"}}]}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "per_call" {\n'
                 '  alarm_name = "per-call"\n  threshold  = 1\n'
                 '  metric_query {\n    id          = "e1"\n'
                 '    expression  = "cost / calls"\n    return_data = true\n  }\n'
                 '  metric_query {\n    id = "cost"\n    metric {\n'
                 '      namespace   = "AWS/Billing"\n      metric_name = "EstimatedCharges"\n'
                 '    }\n  }\n'
                 '  metric_query {\n    id = "calls"\n    metric {\n'
                 '      namespace   = "AWS/Lambda"\n      metric_name = "Invocations"\n'
                 '    }\n  }\n}\n',
}
COST_ALARM_ONLY = {
    "cdk": "new cloudwatch.Alarm(this, 'Bill', { metric: new cloudwatch.Metric({ "
           "namespace: 'AWS/Billing', metricName: 'EstimatedCharges' }), threshold: 100, "
           "evaluationPeriods: 1 });\n",
    "cloudformation": {"Bill": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/Billing", "MetricName": "EstimatedCharges", "Threshold": 100}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "bill" {\n'
                 '  namespace   = "AWS/Billing"\n  metric_name = "EstimatedCharges"\n'
                 '  threshold   = 100\n}\n',
}
WORKLOAD_MATH_ONLY = {
    "cdk": "new cloudwatch.MathExpression({ expression: 'e / i', usingMetrics: {\n"
           "  e: fn.metricErrors(), i: fn.metricInvocations() } });\n",
    "cloudformation": {"Rate": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Threshold": 1, "Metrics": [
            {"Id": "e1", "Expression": "e / i", "ReturnData": True},
            {"Id": "e", "MetricStat": {"Metric": {
                "Namespace": "AWS/Lambda", "MetricName": "Errors"}}},
            {"Id": "i", "MetricStat": {"Metric": {
                "Namespace": "AWS/Lambda", "MetricName": "Invocations"}}}]}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "rate" {\n'
                 '  metric_query {\n    id         = "e1"\n    expression = "e / i"\n  }\n'
                 '  metric_query {\n    id = "e"\n    metric {\n'
                 '      metric_name = "Errors"\n    }\n  }\n'
                 '  metric_query {\n    id = "i"\n    metric {\n'
                 '      metric_name = "Invocations"\n    }\n  }\n}\n',
}


@pytest.mark.parametrize("extra", (COST_ALARM_ONLY, WORKLOAD_MATH_ONLY),
                         ids=("cost-alarm-only", "workload-math-only"))
@pytest.mark.parametrize("source", SOURCES)
def test_no_cost_allocation_math_fires_repo_072(tmp_path: Path, source: str,
                                                extra: dict) -> None:
    _stack(tmp_path, source, FUNCTION[source], extra[source])
    (hit,) = CostNotAllocatedByWorkload().run(tmp_path)
    assert hit.id == "REPO-072"


@pytest.mark.parametrize("source", SOURCES)
def test_cost_allocation_math_passes_repo_072(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FUNCTION[source], COST_MATH[source])
    assert CostNotAllocatedByWorkload().run(tmp_path) == []


def test_dashboard_math_passes_repo_072(tmp_path: Path) -> None:
    body = json.dumps({"widgets": [{"type": "metric", "properties": {"metrics": [
        [{"expression": "cost / req", "label": "CostPerRequest"}],
        ["AWS/Billing", "EstimatedCharges", {"id": "cost"}],
        ["AWS/ApplicationELB", "RequestCount", {"id": "req"}]]}}]})
    _stack(tmp_path, "cloudformation", FUNCTION["cloudformation"], {"Board": {
        "Type": "AWS::CloudWatch::Dashboard", "Properties": {"DashboardBody": body}}})
    assert CostNotAllocatedByWorkload().run(tmp_path) == []


def test_python_cdk_cost_allocation_repo_072(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py", "fn = _lambda.Function(self, 'Fn', runtime=r)\n")
    assert CostNotAllocatedByWorkload().run(tmp_path)
    _write(tmp_path / "prod" / "metrics.py",
           "cloudwatch.MathExpression(expression='cost / calls', using_metrics={\n"
           "    'cost': cloudwatch.Metric(namespace='AWS/Billing', "
           "metric_name='EstimatedCharges'),\n"
           "    'calls': fn.metric_invocations()})\n")
    assert CostNotAllocatedByWorkload().run(tmp_path) == []


# Shared: dev paths, saved reports, mapping.

RULES = (CostReportMissing(), CostAttributionTagMissing(), UnitCostMetricMissing(),
         CostNotAllocatedByWorkload())
FIRING = {"REPO-069": BUCKET, "REPO-070": BUCKET, "REPO-071": FUNCTION, "REPO-072": FUNCTION}


@pytest.mark.parametrize("env", ("dev", "staging"))
@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_dev_paths_are_skipped(tmp_path: Path, rule, env: str) -> None:
    _stack(tmp_path, "terraform", FIRING[rule.id]["terraform"], env=env)
    assert rule.run(tmp_path) == []
    _stack(tmp_path, "terraform", FIRING[rule.id]["terraform"])
    assert rule.run(tmp_path)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _stack(tmp_path, "terraform", FIRING[rule.id]["terraform"])
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
    ("REPO-069", "COST03-BP01"), ("REPO-070", "COST03-BP03"), ("REPO-071", "COST03-BP04"),
    ("REPO-072", "COST03-BP06"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 3"


def test_only_the_cost_report_rule_is_account_level() -> None:
    assert "REPO-069" in ORG_RULE_IDS
    assert not {"REPO-070", "REPO-071", "REPO-072"} & ORG_RULE_IDS


def test_cost3_is_fully_checked() -> None:
    (cost3,) = [a for a in well_architected.answers([]) if a.question.id == "COST 3"]
    assert cost3.not_checked == ()


def test_cost3_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FUNCTION["terraform"])
    findings = UnitCostMetricMissing().run(tmp_path)
    (cost3,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 3"]
    assert not cost3.met
