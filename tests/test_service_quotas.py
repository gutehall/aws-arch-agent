"""REL 1: quota usage alarms (REPO-012) and failover headroom under quotas (REPO-013)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import declared_limits, quota_usage

SOURCES = ("cdk", "cloudformation", "terraform")
_FILE = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json", "terraform": "main.tf"}
_ALARM_FILE = {
    "cdk": "lib/quotas.ts", "cloudformation": "quotas.template.json", "terraform": "quotas.tf",
}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict[str, tuple[str, dict]]) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }})


def _workload(root: Path, source: str, reserved: tuple[int, ...] = (10,), eips: int = 1) -> None:
    """Lambda functions with reserved concurrency and Elastic IPs, per source."""
    if source == "cdk":
        _write(root / "package.json", "{}")
        lines = [
            f"new lambda.Function(this, 'Fn{i}', {{ reservedConcurrentExecutions: {n} }});"
            for i, n in enumerate(reserved)
        ]
        lines += [f"new ec2.CfnEIP(this, 'Eip{i}', {{}});" for i in range(eips)]
        _write(root / _FILE[source], "\n".join(lines) + "\n")
    elif source == "cloudformation":
        resources: dict[str, tuple[str, dict]] = {
            f"Fn{i}": ("AWS::Lambda::Function", {"ReservedConcurrentExecutions": n})
            for i, n in enumerate(reserved)
        }
        resources.update({f"Eip{i}": ("AWS::EC2::EIP", {}) for i in range(eips)})
        _write(root / _FILE[source], _cfn(resources))
    else:
        blocks = [
            f'resource "aws_lambda_function" "fn{i}" {{\n'
            f"  reserved_concurrent_executions = {n}\n}}\n"
            for i, n in enumerate(reserved)
        ]
        blocks += [f'resource "aws_eip" "eip{i}" {{\n}}\n' for i in range(eips)]
        _write(root / _FILE[source], "".join(blocks))


def _scan(root: Path, **kwargs):
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False, **kwargs)
    return ctx, findings


def _rel1(findings, ran):
    return {a.question.id: a for a in well_architected.answers(findings, ran)}["REL 1"]


USAGE_ALARM = {
    "cdk": (
        "new cloudwatch.Alarm(this, 'LambdaQuota', { metric: new cloudwatch.Metric({ "
        "namespace: 'AWS/Usage', metricName: 'ResourceCount' }), threshold: 800 });\n"
    ),
    "cloudformation": _cfn({"LambdaQuota": ("AWS::CloudWatch::Alarm", {
        "Namespace": "AWS/Usage", "MetricName": "ResourceCount", "Threshold": 800})}),
    "terraform": (
        'resource "aws_cloudwatch_metric_alarm" "lambda_quota" {\n'
        '  namespace   = "AWS/Usage"\n  metric_name = "ResourceCount"\n}\n'
    ),
}
QUOTA_MATH = {
    "cdk": "new cloudwatch.MathExpression({ expression: '(m1 / SERVICE_QUOTA(m1)) * 100' });\n",
    "cloudformation": _cfn({"Pct": ("AWS::CloudWatch::Alarm", {"Metrics": [
        {"Id": "pct", "Expression": "(m1/SERVICE_QUOTA(m1))*100"}]})}),
    "terraform": (
        'resource "aws_cloudwatch_metric_alarm" "pct" {\n  metric_query {\n'
        '    expression = "(m1/SERVICE_QUOTA(m1))*100"\n  }\n}\n'
    ),
}


@pytest.mark.parametrize("source", SOURCES)
def test_quota_alarm_rule_is_off_by_default(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    assert "REPO-012" not in {f.id for f in findings}
    assert "REPO-012" not in ctx.rules_run
    assert "REPO-013" in ctx.rules_run
    rel1 = _rel1(findings, ctx.rules_run)
    assert "REL01-BP04" in rel1.not_checked
    assert not rel1.met


@pytest.mark.parametrize("source", SOURCES)
def test_no_quota_alarm_fails_with_rules_org(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    ctx, findings = _scan(tmp_path, rules_org=True)
    assert ctx.source == source
    (f,) = [f for f in findings if f.id == "REPO-012"]
    assert f.question == "REL 1"
    assert f.best_practices == ["REL01-BP04"]
    assert f.severity == "Medium"
    assert f.category == "Reliability"
    assert f.evidence.startswith(
        f"Uses Lambda ({_FILE[source]}), Elastic IPs ({_FILE[source]}); searched"
    )
    rel1 = _rel1(findings, ctx.rules_run)
    assert not rel1.met
    assert "REL01-BP04" not in rel1.not_checked


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("control", ["usage_alarm", "quota_math"])
def test_quota_alarm_passes(tmp_path: Path, source: str, control: str) -> None:
    _workload(tmp_path, source)
    text = (USAGE_ALARM if control == "usage_alarm" else QUOTA_MATH)[source]
    _write(tmp_path / _ALARM_FILE[source], text)
    ctx, findings = _scan(tmp_path, rules_org=True)
    assert ctx.source == source
    ids = {f.id for f in findings}
    assert not ids & {"REPO-012", "REPO-013"}
    rel1 = _rel1(findings, ctx.rules_run)
    assert not {"REL01-BP04", "REL01-BP06"} & set(rel1.not_checked)


def test_quota_alarm_needs_an_alarm_or_quota_math(tmp_path: Path) -> None:
    _workload(tmp_path, "cdk")
    # A dashboard metric on AWS/Usage alarms on nothing.
    _write(tmp_path / "lib" / "dash.ts", "new cloudwatch.Metric({ namespace: 'AWS/Usage' });\n")
    assert quota_usage(tmp_path)[1] == {}
    _write(tmp_path / "lib" / "ta.ts", (
        "new events.Rule(this, 'Limits', { eventPattern: { source: ['aws.trustedadvisor'] } });\n"
    ))
    assert quota_usage(tmp_path)[1] == {"Trusted Advisor service limit events": "lib/ta.ts"}


def test_no_quota_heavy_service_no_finding(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", 'resource "aws_s3_bucket" "b" {\n}\n')
    _ctx, findings = _scan(tmp_path, rules_org=True)
    assert not {"REPO-012", "REPO-013"} & {f.id for f in findings}


@pytest.mark.parametrize("source", SOURCES)
def test_reserved_concurrency_over_half_fails(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source, reserved=(300, 200))
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    (f,) = [f for f in findings if f.id == "REPO-013"]
    assert f.question == "REL 1"
    assert f.best_practices == ["REL01-BP06"]
    assert f.severity == "Medium"
    assert f.category == "Reliability"
    assert f.evidence.startswith(
        f"Lambda reserved concurrency sums to 500 ({_FILE[source]} 500); the default quota "
        "is 1,000 per Region with 100 unreserved, so 900 can be reserved"
    )
    assert not _rel1(findings, ctx.rules_run).met


@pytest.mark.parametrize("source", SOURCES)
def test_elastic_ips_over_half_fail(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source, eips=3)
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    (f,) = [f for f in findings if f.id == "REPO-013"]
    assert f.question == "REL 1"
    assert f.evidence.startswith(
        f"Elastic IPs (EIP resources and CDK NAT gateways) number 3 ({_FILE[source]} 3)"
    )


@pytest.mark.parametrize("source", SOURCES)
def test_limits_under_half_pass(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source, reserved=(250, 200), eips=2)
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    assert "REPO-013" not in {f.id for f in findings}
    assert "REL01-BP06" not in _rel1(findings, ctx.rules_run).not_checked


def test_cdk_nat_gateways_count_as_elastic_ips(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", "{}")
    _write(tmp_path / "lib" / "a.ts", "new ec2.Vpc(this, 'A', { natGateways: 2 });\n")
    _write(tmp_path / "app.py", "ec2.Vpc(self, 'B', nat_gateways=1)\n")
    assert declared_limits(tmp_path)["elastic_ips"] == [("app.py", 1), ("lib/a.ts", 2)]
    ids = [f.id for f in _scan(tmp_path)[1]]
    assert ids.count("REPO-013") == 1


def test_variable_limits_are_not_summed(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", (
        'resource "aws_lambda_function" "fn" {\n'
        "  reserved_concurrent_executions = var.reserved\n}\n"
        'resource "aws_lambda_function" "open" {\n'
        "  reserved_concurrent_executions = -1\n}\n"
    ))
    assert declared_limits(tmp_path)["lambda_concurrency"] == []
