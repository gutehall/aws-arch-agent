"""REL 1: quotas managed as code (REPO-133), quota increases automated (REPO-134) and fixed
quotas designed around (REPO-135)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import (
    FixedQuotaNotDesignedAround,
    QuotaIncreaseNotAutomated,
    QuotasNotManaged,
)
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_FN = {
    "main.tf": 'resource "aws_lambda_function" "f" {\n  function_name = "f"\n}\n',
}
_COMPUTE = [
    {"main.tf": _FN["main.tf"]},
    {"t.json": '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"F": {"Type": '
               '"AWS::Lambda::Function", "Properties": {}}}}'},
    {"lib/stack.ts": "new lambda.Function(this, 'F', { runtime, handler, code });\n"},
]
_IDS = ["terraform", "cloudformation", "cdk"]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_rel1() -> None:
    for rule_id, bp in (("REPO-133", "REL01-BP02"), ("REPO-134", "REL01-BP05"),
                        ("REPO-135", "REL01-BP03")):
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


@pytest.mark.parametrize("rule_id", ["REPO-133", "REPO-134"])
@pytest.mark.parametrize("files", _COMPUTE, ids=_IDS)
def test_compute_without_quota_management_fails(tmp_path: Path, rule_id: str, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), rule_id)
    assert hit.question == "REL 1"
    assert hit.severity == "Low" and hit.category == "Reliability"
    assert hit.evidence.endswith("found none")


@pytest.mark.parametrize("rule_id", ["REPO-133", "REPO-134"])
def test_no_compute_does_not_fire(tmp_path: Path, rule_id: str) -> None:
    assert not _found(_scan(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}), rule_id)


@pytest.mark.parametrize(
    "extra",
    [
        {"q.tf": 'resource "aws_servicequotas_service_quota" "q" {\n  value = 200\n}\n'},
        {"q.tf": 'resource "aws_servicequotas_template" "t" {\n  value = 200\n}\n'},
        {"lib/q.ts": "new servicequotas.CfnTemplate(this, 'T', {});\n"},
    ],
    ids=["service-quota", "template", "cdk"],
)
def test_service_quotas_resource_passes_both(tmp_path: Path, extra: dict) -> None:
    findings = _scan(tmp_path, {**_FN, **extra})
    assert not _found(findings, "REPO-133")
    assert not _found(findings, "REPO-134")


def test_quotas_module_passes_management_but_not_automation(tmp_path: Path) -> None:
    files = {**_FN, "mod.tf": 'module "quotas" {\n  source = "./modules/quotas"\n}\n'}
    findings = _scan(tmp_path, files)
    assert not _found(findings, "REPO-133")
    assert _found(findings, "REPO-134")


def test_increase_request_in_function_code_passes(tmp_path: Path) -> None:
    files = {**_FN, "src/handler.py": "client.request_service_quota_increase(ServiceCode='lambda')\n"}
    assert not _found(_scan(tmp_path, files), "REPO-134")


def test_increase_permission_in_a_policy_passes(tmp_path: Path) -> None:
    files = {**_FN, "iam.tf": 'actions = ["servicequotas:RequestServiceQuotaIncrease"]\n'}
    assert not _found(_scan(tmp_path, files), "REPO-134")


_FIFO = {
    "q.tf": 'resource "aws_sqs_queue" "q" {\n  name = "q.fifo"\n  fifo_queue = true\n}\n',
    "q.json": '{"Resources": {"Q": {"Type": "AWS::SQS::Queue", "Properties": '
              '{"FifoQueue": true}}}}',
    "lib/q.ts": "new sqs.Queue(this, 'Q', { fifo: true });\n",
}


@pytest.mark.parametrize("name", list(_FIFO), ids=["terraform", "cloudformation", "cdk"])
def test_fifo_queue_without_high_throughput_fails(tmp_path: Path, name: str) -> None:
    (hit,) = _found(_scan(tmp_path, {name: _FIFO[name]}), "REPO-135")
    assert hit.question == "REL 1"
    assert "FIFO queue without high-throughput mode" in hit.evidence


@pytest.mark.parametrize(
    "files",
    [
        {"q.tf": 'resource "aws_sqs_queue" "q" {\n  fifo_queue = true\n'
                 '  deduplication_scope = "messageGroup"\n'
                 '  fifo_throughput_limit = "perMessageGroupId"\n}\n'},
        {"lib/q.ts": "new sqs.Queue(this, 'Q', { fifo: true, deduplicationScope: "
                     "sqs.DeduplicationScope.MESSAGE_GROUP, fifoThroughputLimit: "
                     "sqs.FifoThroughputLimit.PER_MESSAGE_GROUP_ID });\n"},
        {"q.tf": 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n'},
    ],
    ids=["terraform-high-throughput", "cdk-high-throughput", "standard-queue"],
)
def test_high_throughput_or_standard_queue_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-135")


def test_one_shard_provisioned_stream_fails(tmp_path: Path) -> None:
    files = {"k.tf": 'resource "aws_kinesis_stream" "s" {\n  name = "s"\n  shard_count = 1\n}\n'}
    (hit,) = _found(_scan(tmp_path, files), "REPO-135")
    assert "one-shard provisioned Kinesis stream" in hit.evidence


@pytest.mark.parametrize(
    "files",
    [
        {"k.tf": 'resource "aws_kinesis_stream" "s" {\n  name = "s"\n  shard_count = 4\n}\n'},
        {"k.tf": 'resource "aws_kinesis_stream" "s" {\n  name = "s"\n  stream_mode_details {\n'
                 '    stream_mode = "ON_DEMAND"\n  }\n}\n'},
    ],
    ids=["four-shards", "on-demand"],
)
def test_wider_stream_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-135")


def test_quota_code_in_tests_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", _FN["main.tf"])
    _write(tmp_path / "tests" / "q.tf", 'resource "aws_servicequotas_service_quota" "q" {}\n')
    _write(tmp_path / "tests" / "test_q.py", "client.request_service_quota_increase()\n")
    assert QuotasNotManaged().run(tmp_path)
    assert QuotaIncreaseNotAutomated().run(tmp_path)
    _write(tmp_path / "tests" / "fifo.tf", _FIFO["q.tf"])
    assert not FixedQuotaNotDesignedAround().run(tmp_path)
