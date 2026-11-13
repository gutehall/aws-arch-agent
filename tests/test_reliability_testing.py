"""REL 12: the repo injects faults into the workload (REPO-016) and load tests it in the
pipeline (REPO-017)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import FaultInjectionMissing, LoadTestMissing
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


_QUEUE = {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {}}}
_FIS_CFN = {"Experiment": {"Type": "AWS::FIS::ExperimentTemplate", "Properties": {
    "Description": "stop the web tier", "RoleArn": "arn:aws:iam::111122223333:role/fis",
    "StopConditions": [{"Source": "aws:cloudwatch:alarm",
                        "Value": "arn:aws:cloudwatch:eu-west-1:111122223333:alarm:errors"}],
    "Targets": {}, "Actions": {}, "Tags": {"Name": "web"}}}}

_TF = 'resource "aws_sqs_queue" "jobs" {\n  name = "jobs"\n}\n'
_TF_FIS = '''
resource "aws_fis_experiment_template" "web" {
  description = "stop the web tier"
  role_arn    = aws_iam_role.fis.arn
  stop_condition {
    source = "aws:cloudwatch:alarm"
    value  = aws_cloudwatch_metric_alarm.errors.arn
  }
  action {
    name      = "stop"
    action_id = "aws:ec2:stop-instances"
  }
}
'''
_CDK = "new sqs.Queue(this, 'Jobs');\n"
_CDK_FIS = (
    "new fis.CfnExperimentTemplate(this, 'StopWeb', { description: 'stop the web tier', "
    "roleArn: role.roleArn, stopConditions: [{ source: 'aws:cloudwatch:alarm', "
    "value: alarm.alarmArn }], targets: {}, actions: {}, tags: { Name: 'web' } });\n"
)

# (IaC files without a control, the same IaC with a FIS experiment template), per source.
_SOURCES = {
    "cdk": ({"lib/stack.ts": _CDK, "package.json": "{}"},
            {"lib/stack.ts": _CDK + _CDK_FIS, "package.json": "{}"}),
    "cloudformation": ({"t.json": _cfn(_QUEUE)}, {"t.json": _cfn({**_QUEUE, **_FIS_CFN})}),
    "terraform": ({"main.tf": _TF}, {"main.tf": _TF + _TF_FIS}),
}
_SOURCE_IDS = list(_SOURCES)


def _scan(root: Path, iac: dict[str, str], ci: dict[str, str] | None = None) -> tuple:
    # IaC under prod/: the pytest directory name says "test", which reads as a dev stack.
    # CI configs sit at the repo root, where REPO-002 looks for them.
    for rel, text in iac.items():
        _write(root / "prod" / rel, text)
    for rel, text in (ci or {}).items():
        _write(root / rel, text)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return ctx, findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def _workflow(*commands: str) -> dict[str, str]:
    steps = "".join(f"      - run: {c}\n" for c in commands)
    return {".github/workflows/ci.yml": f"jobs:\n  build:\n    steps:\n{steps}"}


def test_rules_answer_rel12() -> None:
    assert RULE_BEST_PRACTICES["REPO-016"] == ("REL12-BP04",)
    assert RULE_BEST_PRACTICES["REPO-017"] == ("REL12-BP03",)
    assert {"REL12-BP03", "REL12-BP04"}.isdisjoint(NOT_CHECKED)


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_no_experiment_and_no_load_test_fails_rel12(tmp_path: Path, source: str) -> None:
    bare, _with_fis = _SOURCES[source]
    ctx, findings = _scan(tmp_path, bare, _workflow("npm ci", "npm test"))
    assert ctx.source == source
    (chaos,) = _found(findings, "REPO-016")
    (load,) = _found(findings, "REPO-017")
    for hit in (chaos, load):
        assert hit.question == "REL 12"
        assert hit.severity == "Low" and hit.category == "Reliability"
        assert hit.evidence.endswith("found none")
    assert "AWS::FIS::ExperimentTemplate" in chaos.evidence
    assert ".github/workflows/ci.yml" in load.evidence and "k6 run" in load.evidence
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    assert not answer["REL 12"].met


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_fis_experiment_template_passes(tmp_path: Path, source: str) -> None:
    _bare, with_fis = _SOURCES[source]
    ctx, findings = _scan(tmp_path, with_fis)
    assert ctx.source == source
    assert not _found(findings, "REPO-016")
    assert _found(findings, "REPO-017")  # an experiment is not a load test


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_load_test_in_ci_passes(tmp_path: Path, source: str) -> None:
    bare, _with_fis = _SOURCES[source]
    ctx, findings = _scan(tmp_path, bare, _workflow("k6 run load/checkout.js"))
    assert ctx.source == source
    assert not _found(findings, "REPO-017")
    assert _found(findings, "REPO-016")  # a load test is not fault injection


@pytest.mark.parametrize("source", _SOURCE_IDS)
def test_both_controls_answer_rel12(tmp_path: Path, source: str) -> None:
    _bare, with_fis = _SOURCES[source]
    ctx, findings = _scan(tmp_path, with_fis, _workflow("artillery run load/artillery.yml"))
    assert not _found(findings, "REPO-016") and not _found(findings, "REPO-017")
    answer = {a.question.id: a for a in well_architected.answers(findings, ctx.rules_run)}
    assert not [f for f in findings if f.question == "REL 12"]
    # Both practices are checked and pass; REL 12 stays not met only for the practices no
    # rule checks (playbooks, post-incident analysis, game days).
    assert not answer["REL 12"].findings
    assert answer["REL 12"].not_checked == ("REL12-BP01", "REL12-BP02", "REL12-BP05")


@pytest.mark.parametrize(
    "command",
    [
        "aws fis start-experiment --experiment-template-id EXT1a2b3c",
        "litmusctl run chaos-experiment --project-id p",
        "kubectl apply -f https://mirrors.chaos-mesh.org/latest/crd.yaml # chaos-mesh",
        "gremlin attack cpu -l 60",
        "chaos run experiments/az-outage.json",
    ],
    ids=["fis-cli", "litmus", "chaos-mesh", "gremlin", "chaostoolkit"],
)
def test_chaos_run_from_ci_passes(tmp_path: Path, command: str) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF)
    for rel, text in _workflow(command).items():
        _write(tmp_path / rel, text)
    assert not FaultInjectionMissing().run(tmp_path)


@pytest.mark.parametrize(
    "command",
    [
        "docker run -i grafana/k6 run - < load/script.js",
        "artillery run-fargate load/artillery.yml",
        "locust -f load/locustfile.py --headless -u 100 -r 10 --run-time 5m",
        "jmeter -n -t load/plan.jmx -l results.jtl",
        "mvn gatling:test",
        "echo 'GET https://staging.example.com/' | vegeta attack -duration=60s",
        "hey -n 10000 -c 50 https://staging.example.com/",
        "ab -n 5000 -c 20 https://staging.example.com/",
        "bzt load/taurus.yml",
        "aws cloudformation deploy --stack-name distributed-load-testing --template-file t",
    ],
    ids=["k6-docker", "artillery", "locust", "jmeter", "gatling", "vegeta", "hey", "ab",
         "taurus", "dlt"],
)
def test_load_tool_in_ci_passes(tmp_path: Path, command: str) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF)
    for rel, text in _workflow(command).items():
        _write(tmp_path / rel, text)
    assert not LoadTestMissing().run(tmp_path)


def test_load_test_in_inline_buildspec_passes(tmp_path: Path) -> None:
    buildspec = json.dumps({"version": "0.2", "phases": {"build": {
        "commands": ["k6 run load/checkout.js"]}}})
    project = {"LoadTest": {"Type": "AWS::CodeBuild::Project", "Properties": {
        "Source": {"Type": "CODEPIPELINE", "BuildSpec": buildspec}}}}
    _write(tmp_path / "prod" / "t.json", _cfn({**_QUEUE, **project}))
    assert not LoadTestMissing().run(tmp_path)


def test_load_test_from_a_package_script_ci_runs_passes(tmp_path: Path) -> None:
    _write(tmp_path / "package.json",
           json.dumps({"scripts": {"load": "k6 run load/checkout.js"}}))
    for rel, text in _workflow("npm run load").items():
        _write(tmp_path / rel, text)
    assert not LoadTestMissing().run(tmp_path)


def test_load_test_script_ci_never_runs_fails(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF)
    _write(tmp_path / "load" / "checkout.js",
           "import http from 'k6/http';\nexport default function () { http.get(url); }\n")
    _write(tmp_path / "load" / "artillery.yml", "config:\n  target: https://example.com\n")
    _write(tmp_path / "load" / "locustfile.py", "from locust import HttpUser\n")
    # A package.json script that would run it, but no build calls the script.
    _write(tmp_path / "package.json",
           json.dumps({"scripts": {"load": "k6 run load/checkout.js"}}))
    for rel, text in _workflow("npm ci", "npm test").items():
        _write(tmp_path / rel, text)
    (hit,) = LoadTestMissing().run(tmp_path)
    assert hit.evidence.startswith("Searched the build configs (.github/workflows/ci.yml)")


def test_no_build_says_so(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF)
    (hit,) = LoadTestMissing().run(tmp_path)
    assert hit.evidence.startswith("Searched the repo for a build to run a load test")


def test_fis_template_in_tests_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF)
    _write(tmp_path / "tests" / "fis.tf", _TF_FIS)
    assert FaultInjectionMissing().run(tmp_path)


def test_fis_template_in_yaml_passes(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "template.yaml", (
        "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Experiment:\n"
        "    Type: AWS::FIS::ExperimentTemplate\n    Properties:\n      Description: stop\n"))
    assert not FaultInjectionMissing().run(tmp_path)


def test_report_naming_the_type_is_not_a_template(tmp_path: Path) -> None:
    # A JSON report saved in the repo quotes REPO-016's evidence; it is not an experiment.
    _write(tmp_path / "prod" / "main.tf", _TF)
    (hit,) = FaultInjectionMissing().run(tmp_path)
    _write(tmp_path / "report.json", json.dumps({"findings": [{"evidence": hit.evidence}]}))
    assert FaultInjectionMissing().run(tmp_path)
