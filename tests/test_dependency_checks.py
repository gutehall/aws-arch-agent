"""REL 4: calls name their dependencies (REPO-107) and a synchronous call has a timeout or
a queue behind it (REPO-108)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.repo_practices import DependencyUrlHardcoded, SyncCallNoTimeoutOrQueue
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TF_QUEUE = 'resource "aws_sqs_queue" "jobs" {\n  name = "jobs"\n}\n'
_CFN_QUEUE = (
    '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": '
    '{"Jobs": {"Type": "AWS::SQS::Queue"}}}'
)
_CDK_QUEUE = "const q = new sqs.Queue(this, 'Jobs');\n"
_CALL = "const r = await fetch(process.env.DEP_URL!);\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str]) -> list:
    # Under prod/: the pytest directory name says "test", which reads as a dev stack.
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_rel4() -> None:
    assert RULE_BEST_PRACTICES["REPO-107"] == ("REL04-BP01",)
    assert RULE_BEST_PRACTICES["REPO-108"] == ("REL04-BP03",)
    assert {"REL04-BP01", "REL04-BP03"}.isdisjoint(NOT_CHECKED)


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("src/handler.ts", "const r = await fetch('https://api.vendor.com/v1/x');\n"),
        ("src/handler.js", "axios.get(`https://api.vendor.com/v1/${id}`);\n"),
        ("src/handler.py", "resp = requests.get('https://api.vendor.com/v1/x', timeout=3)\n"),
        ("src/handler.py", "urllib.request.urlopen(\"https://api.vendor.com/v1/x\")\n"),
    ],
    ids=["ts-fetch", "js-axios", "py-requests", "py-urlopen"],
)
def test_hardcoded_url_fails(tmp_path: Path, name: str, code: str) -> None:
    (hit,) = _found(_scan(tmp_path, {name: code}), "REPO-107")
    assert hit.question == "REL 4"
    assert hit.severity == "Low" and hit.category == "Reliability"
    assert "api.vendor.com" in hit.evidence


@pytest.mark.parametrize(
    "code",
    [
        "const r = await fetch(process.env.VENDOR_URL!);\n",
        "requests.get(os.environ['VENDOR_URL'], timeout=3)\n",
        "requests.get(f'{base_url}/v1/x', timeout=3)\n",
        "fetch('http://localhost:3000/health');\n",
        "fetch('https://dynamodb.eu-west-1.amazonaws.com/');\n",
        "fetch('http://169.254.169.254/latest/meta-data/');\n",
        "// see https://docs.vendor.com/api\nconst x = 1;\n",
    ],
    ids=["env-ts", "env-py", "base-url", "localhost", "aws-endpoint", "metadata", "comment"],
)
def test_named_or_local_dependency_passes(tmp_path: Path, code: str) -> None:
    assert not _found(_scan(tmp_path, {"src/handler.ts": code}), "REPO-107")


def test_url_in_tests_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "test_client.py", "requests.get('https://api.vendor.com/x')\n")
    assert not DependencyUrlHardcoded().run(tmp_path)


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("src/handler.ts", _CALL),
        ("src/handler.js", "const r = await axios.post(url, body);\n"),
        ("src/handler.py", "resp = requests.get(url)\n"),
        ("src/handler.py", "data = urlopen(url).read()\n"),
    ],
    ids=["ts-fetch", "js-axios", "py-requests", "py-urlopen"],
)
def test_sync_call_without_timeout_or_queue_fails(tmp_path: Path, name: str, code: str) -> None:
    (hit,) = _found(_scan(tmp_path, {name: code, "main.tf": "# nothing here\n"}), "REPO-108")
    assert hit.question == "REL 4"
    assert hit.severity == "Medium" and hit.category == "Reliability"
    assert name in hit.evidence and "no queue" in hit.evidence


@pytest.mark.parametrize(
    "files",
    [
        {"src/handler.ts": "await fetch(url, { signal: AbortSignal.timeout(3000) });\n"},
        {"src/handler.py": "requests.get(url, timeout=3)\n"},
        {"src/handler.ts": "const c = new AbortController();\nawait fetch(url, { signal: c.signal });\n"},
        {"src/handler.ts": _CALL, "main.tf": _TF_QUEUE},
        {"src/handler.ts": _CALL, "t.json": _CFN_QUEUE},
        {"src/handler.ts": _CALL, "lib/stack.ts": _CDK_QUEUE},
        {"src/handler.ts": _CALL,
         "main.tf": 'resource "aws_scheduler_schedule" "s" {\n  schedule_expression = '
                    '"rate(5 minutes)"\n}\n'},
        {"src/handler.ts": _CALL,
         "main.tf": 'resource "aws_lambda_event_source_mapping" "m" {\n'
                    '  event_source_arn = aws_sqs_queue.q.arn\n}\n'},
        {"src/handler.ts": "const x = 1;\n"},
    ],
    ids=["abort-signal", "py-timeout", "abort-controller", "terraform-queue",
         "cloudformation-queue", "cdk-queue", "schedule", "event-source", "no-call"],
)
def test_timeout_or_queue_passes(tmp_path: Path, files: dict) -> None:
    assert not _found(_scan(tmp_path, files), "REPO-108")


def test_call_in_tests_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "test_client.py", "requests.get(url)\n")
    assert not SyncCallNoTimeoutOrQueue().run(tmp_path)
